//! NTFS v3: MFT records, update sequences, attribute lists, runlists and $I30.
use super::{
    DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, StreamInfo, TimeBasis, Times, Timestamp,
};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{BTreeMap, HashMap, HashSet};

const REFERENCE_MASK: u64 = 0x0000_ffff_ffff_ffff;
#[derive(Clone, Debug)]
struct Run {
    vcn: u64,
    count: u64,
    lcn: Option<u64>,
}
#[derive(Clone)]
enum Value {
    Resident(Vec<u8>),
    Nonresident {
        first: u64,
        compression_unit: u16,
        size: u64,
        initialized: u64,
        runs: Vec<Run>,
    },
}
#[derive(Clone)]
struct Attribute {
    kind: u32,
    name: String,
    instance: u16,
    flags: u16,
    value: Value,
}
struct Record {
    sequence: u16,
    links: u16,
    flags: u16,
    base: u64,
    attributes: Vec<Attribute>,
}
#[derive(Clone)]
struct Stream {
    resident: Option<Vec<u8>>,
    runs: Vec<Run>,
    size: u64,
    initialized: u64,
    flags: u16,
    compression_unit: u16,
}

pub struct Ntfs<'a> {
    image: &'a mut dyn DiskImage,
    info: FsInfo,
    limits: Limits,
    cluster_size: u64,
    sectors: usize,
    record_size: usize,
    index_size: usize,
    total_clusters: u64,
    mft: Stream,
    upcase: Vec<u16>,
    cached_stream: Option<(u64, String, Stream)>,
}

impl<'a> Ntfs<'a> {
    pub fn open(image: &'a mut dyn DiskImage, limits: Limits) -> Result<Self> {
        let boot = read_vec(image, 0, 512)?;
        if &boot[3..11] != b"NTFS    " || boot[510..] != [0x55, 0xaa] {
            return Err(corrupt("NTFS", 0, "invalid volume boot record"));
        }
        let sectors = u16le(&boot, 11)? as usize;
        let spc = boot[13] as u64;
        if !sectors.is_power_of_two()
            || !(512..=4096).contains(&sectors)
            || !spc.is_power_of_two()
            || spc > 128
        {
            return Err(corrupt("NTFS", 11, "invalid sector/cluster geometry"));
        }
        let cluster_size = sectors as u64 * spc;
        let total_sectors = u64le(&boot, 40)?;
        let total_bytes = total_sectors
            .checked_mul(sectors as u64)
            .ok_or_else(|| corrupt("NTFS", 40, "volume size overflow"))?;
        checked_region(0, total_bytes, image.len(), "NTFS")?;
        let total_clusters = total_sectors / spc;
        if total_clusters == 0 {
            return Err(corrupt("NTFS", 40, "empty volume"));
        }
        let record_size =
            decode_record_size(boot[64] as i8, cluster_size, limits.max_metadata_bytes)?;
        let index_size =
            decode_record_size(boot[68] as i8, cluster_size, limits.max_metadata_bytes)?;
        if !record_size.is_multiple_of(512) || !index_size.is_multiple_of(512) {
            return Err(corrupt("NTFS", 64, "record size is not sector aligned"));
        }
        let mft_cluster = u64le(&boot, 48)?;
        if mft_cluster >= total_clusters {
            return Err(corrupt("NTFS", 48, "$MFT starts outside the volume"));
        }
        let mut first = read_vec(image, mft_cluster * cluster_size, record_size)?;
        fixup(&mut first, b"FILE", sectors)?;
        let first = parse_record(&first, total_clusters, &limits)?;
        let mft = stream(&first.attributes, 0x80, "", cluster_size, true)?
            .ok_or_else(|| corrupt("NTFS", 0, "$MFT has no data stream"))?;
        if mft.flags & 0x4001 != 0 || mft.resident.is_some() {
            return Err(corrupt("NTFS", 0, "invalid $MFT data stream"));
        }
        let mut fs = Self {
            image,
            info: FsInfo {
                filesystem: FsType::Ntfs,
                label: String::new(),
                block_size: cluster_size as u32,
                total_bytes,
                root_id: 5,
                needs_journal_recovery: false,
            },
            limits,
            cluster_size,
            sectors,
            record_size,
            index_size,
            total_clusters,
            mft,
            upcase: Vec::new(),
            cached_stream: None,
        };
        let attrs = fs.attributes(0)?;
        fs.mft = stream(&attrs, 0x80, "", cluster_size, false)?
            .ok_or_else(|| corrupt("NTFS", 0, "missing complete $MFT stream"))?;
        if !fs.mft.size.is_multiple_of(record_size as u64) {
            return Err(corrupt("NTFS", 0, "$MFT length is not record aligned"));
        }
        let volume = fs.attributes(3)?;
        if let Some(data) = resident(&volume, 0x60, "") {
            fs.info.label = utf16(data)?;
        }
        if let Some(data) = resident(&volume, 0x70, "") {
            if data.len() < 12 || data[8] != 3 || data[9] > 1 {
                return Err(Error::Unsupported(
                    "NTFS versions other than 3.0/3.1".into(),
                ));
            }
            fs.info.needs_journal_recovery = u16le(data, 10)? & 1 != 0;
        }
        let case_attrs = fs.attributes(10)?;
        let case_stream = stream(&case_attrs, 0x80, "", cluster_size, false)?
            .ok_or_else(|| corrupt("NTFS", 10, "missing $UpCase stream"))?;
        if case_stream.size != 131072 {
            return Err(corrupt("NTFS", 10, "invalid $UpCase length"));
        }
        if case_stream.size > fs.limits.max_metadata_bytes as u64 {
            return Err(Error::ResourceLimit("NTFS $UpCase table"));
        }
        let mut case_bytes = vec![0; 131072];
        read_stream(fs.image, cluster_size, &case_stream, 0, &mut case_bytes)?;
        fs.upcase = case_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        let root = fs.metadata(5)?;
        if root.kind != FileKind::Directory || !root.allocated {
            return Err(corrupt(
                "NTFS",
                5,
                "root MFT record is not an allocated directory",
            ));
        }
        Ok(fs)
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    pub fn security(&mut self, id: u64) -> Result<Option<super::security::SecurityDescriptor>> {
        let attrs = self.attributes(id)?;
        if let Some(raw) = resident(&attrs, 0x50, "") {
            return super::security::parse(raw).map(Some);
        }
        let Some(si) = resident(&attrs, 0x10, "") else {
            return Ok(None);
        };
        if si.len() < 56 {
            return Ok(None);
        }
        let security_id = u32le(si, 52)?;
        let secure = self.attributes(9)?;
        let data = stream(&secure, 0x80, "$SDS", self.cluster_size, false)?
            .ok_or_else(|| corrupt("NTFS security", 9, "missing $Secure:$SDS"))?;
        let mut at = 0u64;
        let mut scanned = 0usize;
        while at < data.size {
            if at >= self.limits.max_metadata_bytes as u64
                || scanned >= self.limits.max_chain_length
            {
                return Err(Error::ResourceLimit("NTFS security descriptor scan"));
            }
            let mut h = [0; 20];
            if read_stream(self.image, self.cluster_size, &data, at, &mut h)? != 20 {
                return Err(corrupt("NTFS security", at, "short SDS header"));
            }
            if h.iter().all(|b| *b == 0) {
                at = (at / 0x80000 + 1) * 0x80000;
                continue;
            }
            let length = u32le(&h, 16)? as usize;
            if length < 40
                || length > self.limits.max_metadata_bytes
                || (at % 0x40000) + length as u64 > 0x40000
                || u64le(&h, 8)? != at
            {
                return Err(corrupt(
                    "NTFS security",
                    at,
                    "invalid SDS entry bounds/offset",
                ));
            }
            if u32le(&h, 4)? == security_id {
                let mut raw = vec![0; length - 20];
                if read_stream(self.image, self.cluster_size, &data, at + 20, &mut raw)?
                    != raw.len()
                {
                    return Err(corrupt("NTFS security", at, "short descriptor"));
                }
                if super::security::ntfs_hash(&raw) != u32le(&h, 0)? {
                    return Err(corrupt("NTFS security", at, "descriptor hash mismatch"));
                }
                return super::security::parse(&raw).map(Some);
            }
            at = (at + length as u64).div_ceil(16) * 16;
            if at % 0x80000 >= 0x40000 {
                at = (at / 0x80000 + 1) * 0x80000;
            }
            scanned += 1;
        }
        Err(Error::NotFound(format!("NTFS security ID {security_id}")))
    }
    pub fn details(&mut self, id: u64) -> Result<super::forensics::NtfsDetails> {
        use super::forensics::*;
        let metadata = self.metadata(id)?;
        let attrs = self.attributes(id)?;
        let mut names = vec![];
        for a in attrs.iter().filter(|a| a.kind == 0x30) {
            let Value::Resident(data) = &a.value else {
                return Err(corrupt("NTFS FILE_NAME", id, "nonresident filename"));
            };
            let parent = u64le(data, 0)?;
            let length = *bytes(data, 64, 1)?.first().unwrap() as usize;
            names.push(FileName {
                name: utf16(bytes(data, 66, length * 2)?)?,
                namespace: *bytes(data, 65, 1)?.first().unwrap(),
                parent_id: parent & REFERENCE_MASK,
                parent_sequence: (parent >> 48) as u16,
                times: Times {
                    created: Some(filetime(u64le(data, 8)?)),
                    modified: Some(filetime(u64le(data, 16)?)),
                    changed: Some(filetime(u64le(data, 24)?)),
                    accessed: Some(filetime(u64le(data, 32)?)),
                },
                allocated_size: u64le(data, 40)?,
                logical_size: u64le(data, 48)?,
                flags: u32le(data, 56)?,
            });
        }
        let si = resident(&attrs, 0x10, "");
        Ok(NtfsDetails {
            metadata,
            names,
            security_id: si
                .filter(|d| d.len() >= 56)
                .map(|d| u32le(d, 52))
                .transpose()?,
            file_attributes: si
                .filter(|d| d.len() >= 36)
                .map(|d| u32le(d, 32))
                .transpose()?,
        })
    }
    fn recovery_status(
        &mut self,
        id: u64,
        name: Option<&str>,
    ) -> Result<super::forensics::RecoveryStatus> {
        use super::forensics::RecoveryStatus::*;
        let record = self.record(id)?;
        if record.flags & 1 != 0 || record.base != 0 {
            return Err(Error::Unsupported(
                "recovery requires a deleted base MFT record".into(),
            ));
        }
        let mft_attrs = self.attributes(0)?;
        let bitmap = stream(&mft_attrs, 0xb0, "", self.cluster_size, false)?
            .ok_or_else(|| corrupt("NTFS recovery", 0, "missing $MFT bitmap"))?;
        let mut bit = [0];
        if read_stream(self.image, self.cluster_size, &bitmap, id / 8, &mut bit)? != 1 {
            return Err(corrupt("NTFS recovery", id, "missing MFT bitmap bit"));
        }
        if bit[0] & (1 << (id % 8)) != 0 {
            return Ok(MftBitmapConflict);
        }
        let attrs = self.attributes(id)?;
        let Some(data) = stream(&attrs, 0x80, name.unwrap_or(""), self.cluster_size, false)? else {
            return Ok(Unsupported);
        };
        if data.flags & 0x4000 != 0
            || data.flags & 0xff > 1
            || data.flags & 1 != 0 && (data.compression_unit != 4 || self.cluster_size > 4096)
        {
            return Ok(Unsupported);
        }
        if data.resident.is_some() {
            return Ok(Resident);
        }
        let volume = self.attributes(6)?;
        let bitmap = stream(&volume, 0x80, "", self.cluster_size, false)?
            .ok_or_else(|| corrupt("NTFS recovery", 6, "missing volume bitmap"))?;
        let mut checked = 0u64;
        let mut last = None;
        for run in &data.runs {
            if let Some(lcn) = run.lcn {
                checked = checked
                    .checked_add(run.count)
                    .ok_or(Error::ResourceLimit("recovery cluster count"))?;
                if checked > self.limits.max_chain_length as u64 {
                    return Err(Error::ResourceLimit("recovery cluster count"));
                }
                for cluster in lcn..lcn + run.count {
                    let byte = cluster / 8;
                    if last != Some(byte) {
                        if read_stream(self.image, self.cluster_size, &bitmap, byte, &mut bit)? != 1
                        {
                            return Err(corrupt(
                                "NTFS recovery",
                                cluster,
                                "missing allocation bitmap bit",
                            ));
                        }
                        last = Some(byte);
                    }
                    if bit[0] & (1 << (cluster % 8)) != 0 {
                        return Ok(ReallocatedClusters);
                    }
                }
            }
        }
        Ok(UnallocatedClusters)
    }
    pub fn check_recovery(&mut self, id: u64, name: Option<&str>) -> Result<()> {
        use super::forensics::RecoveryStatus::*;
        match self.recovery_status(id, name)? {
            Resident | UnallocatedClusters => Ok(()),
            status => Err(Error::Unsupported(format!(
                "deleted stream recovery refused: {status:?}"
            ))),
        }
    }
    pub fn deleted_records(
        &mut self,
        start: u64,
        count: usize,
        name: Option<&str>,
    ) -> Result<super::forensics::DeletedScan> {
        use super::forensics::*;
        if count == 0 || count > self.limits.max_directory_entries {
            return Err(Error::ResourceLimit("deleted MFT scan batch"));
        }
        let total = self.mft.size / self.record_size as u64;
        let end = start.saturating_add(count as u64).min(total);
        let mut report = DeletedScan {
            records: vec![],
            issues: vec![],
            next_record: if end < total { Some(end) } else { None },
            records_scanned: end.saturating_sub(start),
        };
        let mut budget = 0usize;
        for id in start..end {
            // Empty/uninitialized MFT slots are not corrupt deleted files.
            let mut signature = [0; 4];
            read_stream(
                self.image,
                self.cluster_size,
                &self.mft,
                id * self.record_size as u64,
                &mut signature,
            )?;
            if signature == [0; 4] {
                continue;
            }
            let result = (|| -> Result<Option<DeletedRecord>> {
                let record = self.record(id)?;
                if record.flags & 1 != 0 || record.base != 0 {
                    return Ok(None);
                }
                if !record
                    .attributes
                    .iter()
                    .any(|a| a.kind == 0x30 || a.kind == 0x80)
                {
                    return Ok(None);
                }
                let details = self.details(id)?;
                let status = self.recovery_status(id, name)?;
                Ok(Some(DeletedRecord{details,status,assessed_stream:name.map(str::to_owned),explanation:"Current allocation checks do not prove original deleted content survives overwriting, TRIM, or reuse followed by deallocation.".into()}))
            })();
            match result {
                Ok(Some(record)) => {
                    budget = budget.saturating_add(
                        serde_json::to_vec(&record)
                            .map_err(|e| corrupt("NTFS recovery", id, e.to_string()))?
                            .len(),
                    );
                    if budget > self.limits.max_metadata_bytes {
                        return Err(Error::ResourceLimit("deleted MFT scan metadata"));
                    }
                    report.records.push(record);
                }
                Ok(None) => {}
                Err(error) => {
                    let message = error.to_string();
                    budget = budget.saturating_add(message.len() + 32);
                    if budget > self.limits.max_metadata_bytes {
                        return Err(Error::ResourceLimit("deleted scan issues"));
                    }
                    report.issues.push(ScanIssue {
                        record_id: id,
                        message,
                    });
                }
            }
        }
        Ok(report)
    }
    pub fn usn_journal(
        &mut self,
        id: u64,
        start: u64,
        byte_limit: usize,
        count: usize,
    ) -> Result<super::journal::UsnScan> {
        if byte_limit < 8
            || byte_limit > self.limits.max_directory_bytes as usize
            || count == 0
            || count > self.limits.max_directory_entries
            || !start.is_multiple_of(8)
        {
            return Err(Error::ResourceLimit("USN scan size/count/alignment"));
        }
        let attrs = self.attributes(id)?;
        let journal = stream(&attrs, 0x80, "$J", self.cluster_size, false)?
            .ok_or_else(|| Error::NotFound("$UsnJrnl:$J".into()))?;
        let mut report = super::journal::UsnScan {
            records: vec![],
            next_offset: None,
            bytes_scanned: 0,
            journal_id: None,
            lowest_valid_usn: None,
        };
        if let Some(max) = stream(&attrs, 0x80, "$Max", self.cluster_size, false)? {
            let mut data = [0; 32];
            if read_stream(self.image, self.cluster_size, &max, 0, &mut data)? != 32 {
                return Err(corrupt("USN $Max", 0, "short metadata"));
            }
            report.journal_id = Some(u64le(&data, 16)?);
            report.lowest_valid_usn = Some(u64le(&data, 24)? as i64);
        }
        let end = start.saturating_add(byte_limit as u64).min(journal.size);
        let mut at = start;
        let mut budget = 0usize;
        while at < end && report.records.len() < count {
            // Skip sparse journal holes without reading gigabytes of synthetic zeroes.
            if journal.resident.is_none() && journal.flags & 1 == 0 {
                let vcn = at / self.cluster_size;
                if let Some(index) = journal
                    .runs
                    .partition_point(|r| r.vcn <= vcn)
                    .checked_sub(1)
                    && let Some(run) = journal.runs.get(index)
                    && vcn < run.vcn + run.count
                    && run.lcn.is_none()
                {
                    at = ((run.vcn + run.count) * self.cluster_size).min(end);
                    continue;
                }
            }
            if end - at < 8 {
                break;
            }
            let mut h = [0; 8];
            if read_stream(self.image, self.cluster_size, &journal, at, &mut h)? != 8 {
                return Err(corrupt("USN", at, "short header"));
            }
            if h == [0; 8] {
                at += 8;
                continue;
            }
            let length = u32le(&h, 0)? as usize;
            if length < 8 || !length.is_multiple_of(8) || length > self.limits.max_metadata_bytes {
                return Err(corrupt("USN", at, "invalid record length"));
            }
            if at + length as u64 > journal.size {
                return Err(corrupt("USN", at, "truncated journal record"));
            }
            if at + length as u64 > end {
                break;
            }
            budget = budget.saturating_add(length + 256);
            if budget > self.limits.max_metadata_bytes {
                return Err(Error::ResourceLimit("USN result metadata"));
            }
            let mut data = vec![0; length];
            read_stream(self.image, self.cluster_size, &journal, at, &mut data)?;
            report
                .records
                .push(super::journal::parse_record(&data, at)?);
            at += length as u64;
        }
        if at == start && at < journal.size {
            return Err(Error::ResourceLimit(
                "USN scan window cannot hold next record",
            ));
        }
        report.bytes_scanned = at.saturating_sub(start);
        report.next_offset = (at < journal.size).then_some(at);
        Ok(report)
    }
    pub fn logfile_info(&mut self) -> Result<super::journal::LogFileInfo> {
        use super::journal::*;
        let attrs = self.attributes(2)?;
        let data = stream(&attrs, 0x80, "", self.cluster_size, false)?
            .ok_or_else(|| Error::NotFound("$LogFile".into()))?;
        let mut result = LogFileInfo {
            restart_areas: vec![],
            initialized: false,
            issues: vec![],
            replay_performed: false,
        };
        // Restart pages occupy the beginning of the log. Scan a bounded prefix
        // for both copies, including an independently recoverable second copy.
        let end = data.size.min(131072).min(self.limits.max_directory_bytes);
        for at in (0..end).step_by(512) {
            let mut h = [0; 32];
            if read_stream(self.image, self.cluster_size, &data, at, &mut h)? != 32 {
                break;
            }
            if &h[..4] != b"RSTR" {
                continue;
            }
            result.initialized = true;
            let parsed = (|| -> Result<RestartArea> {
                let system = u32le(&h, 16)?;
                let log = u32le(&h, 20)?;
                if !system.is_power_of_two()
                    || !(512..=65536).contains(&system)
                    || !log.is_power_of_two()
                    || !(512..=65536).contains(&log)
                    || system as usize > self.limits.max_metadata_bytes
                {
                    return Err(corrupt("$LogFile", at, "invalid page sizes"));
                }
                let mut page = vec![0; system as usize];
                if read_stream(self.image, self.cluster_size, &data, at, &mut page)? != page.len() {
                    return Err(corrupt("$LogFile", at, "short restart page"));
                }
                fixup(&mut page, b"RSTR", self.sectors)?;
                let major = u16le(&page, 28)?;
                let minor = u16le(&page, 26)?;
                if ![(1, 1), (2, 0)].contains(&(major, minor)) {
                    return Err(Error::Unsupported(format!(
                        "NTFS log version {major}.{minor}"
                    )));
                }
                let area = usize::from(u16le(&page, 24)?);
                let usa_end = usize::from(u16le(&page, 4)?) + usize::from(u16le(&page, 6)?) * 2;
                if area < usa_end || !area.is_multiple_of(8) {
                    return Err(corrupt("$LogFile", at, "restart area overlaps header/USA"));
                }
                let area = bytes(&page, area, 48)?;
                let clients = u16le(area, 8)?;
                let size = u16le(area, 20)?;
                let client_offset = u16le(area, 22)?;
                if size < 48
                    || client_offset < 48
                    || usize::from(client_offset) + usize::from(clients) * 160 > usize::from(size)
                    || usize::from(u16le(&page, 24)?) + usize::from(size) > page.len()
                {
                    return Err(corrupt(
                        "$LogFile",
                        at,
                        "invalid restart area/client bounds",
                    ));
                }
                let file_size = u64le(area, 24)?;
                if file_size > data.size || file_size < u64::from(system) * 2 {
                    return Err(corrupt("$LogFile", at, "invalid log size"));
                }
                let flags = u16le(area, 14)?;
                Ok(RestartArea {
                    page_offset: at,
                    major,
                    minor,
                    system_page_size: system,
                    log_page_size: log,
                    current_lsn: u64le(area, 0)?,
                    flags,
                    clean_shutdown: flags & 2 != 0,
                    log_clients: clients,
                    file_size,
                    record_header_size: u16le(area, 36)?,
                    log_page_data_offset: u16le(area, 38)?,
                })
            })();
            match parsed {
                Ok(area) => result.restart_areas.push(area),
                Err(error) => result.issues.push(format!("page {at:#x}: {error}")),
            }
            if result.restart_areas.len() + result.issues.len() > 16 {
                return Err(Error::ResourceLimit("NTFS log restart page count"));
            }
        }
        Ok(result)
    }
    pub fn name_eq(&self, left: &str, right: &str) -> bool {
        left.encode_utf16()
            .map(|u| self.upcase[u as usize])
            .eq(right.encode_utf16().map(|u| self.upcase[u as usize]))
    }
    fn record(&mut self, id: u64) -> Result<Record> {
        let offset = id
            .checked_mul(self.record_size as u64)
            .ok_or_else(|| corrupt("NTFS", id, "MFT record offset overflow"))?;
        checked_region(offset, self.record_size as u64, self.mft.size, "MFT")?;
        let mut data = vec![0; self.record_size];
        if read_stream(self.image, self.cluster_size, &self.mft, offset, &mut data)? != data.len() {
            return Err(corrupt("MFT", id, "short MFT record read"));
        }
        fixup(&mut data, b"FILE", self.sectors)?;
        parse_record(&data, self.total_clusters, &self.limits)
    }
    fn attributes(&mut self, id: u64) -> Result<Vec<Attribute>> {
        let record = self.record(id)?;
        if record.base != 0 {
            return Err(corrupt("MFT", id, "extension record used as a base file"));
        }
        let sequence = record.sequence;
        let mut attributes = record.attributes;
        let Some(list) = stream(&attributes, 0x20, "", self.cluster_size, false)? else {
            return Ok(attributes);
        };
        if list.size > self.limits.max_metadata_bytes as u64 {
            return Err(Error::ResourceLimit("NTFS attribute list size"));
        }
        let mut data = vec![0; list.size as usize];
        read_stream(self.image, self.cluster_size, &list, 0, &mut data)?;
        let mut position = 0;
        let mut seen = HashSet::new();
        let mut extensions = HashMap::new();
        while position < data.len() {
            if data[position..].iter().all(|&b| b == 0) {
                break;
            }
            let tail = &data[position..];
            let kind = u32le(tail, 0)?;
            let length = u16le(tail, 4)? as usize;
            if length < 26 || !length.is_multiple_of(8) {
                return Err(corrupt(
                    "NTFS attribute list",
                    position as u64,
                    "invalid entry length",
                ));
            }
            let item = bytes(tail, 0, length)?;
            let name = utf16(bytes(
                item,
                *item
                    .get(7)
                    .ok_or_else(|| corrupt("NTFS", 0, "short attribute name"))?
                    as usize,
                item[6] as usize * 2,
            )?)?;
            let first_vcn = u64le(item, 8)?;
            let reference = u64le(item, 16)?;
            let record_id = reference & REFERENCE_MASK;
            let instance = u16le(item, 24)?;
            if !seen.insert((record_id, instance)) {
                return Err(corrupt(
                    "NTFS attribute list",
                    position as u64,
                    "duplicate attribute reference",
                ));
            }
            if seen.len() > 4096 {
                return Err(Error::ResourceLimit("NTFS attribute list entries"));
            }
            if record_id != id {
                if extensions.len() >= 256 {
                    return Err(Error::ResourceLimit("NTFS extension records"));
                }
                if !extensions.contains_key(&record_id) {
                    if (extensions.len() + 2).saturating_mul(self.record_size)
                        > self.limits.max_metadata_bytes
                    {
                        return Err(Error::ResourceLimit("NTFS attribute extension metadata"));
                    }
                    extensions.insert(record_id, self.record(record_id)?);
                }
                let extension = &extensions[&record_id];
                if extension.sequence != (reference >> 48) as u16
                    || extension.base != (id | (u64::from(sequence) << 48))
                {
                    return Err(corrupt(
                        "NTFS attribute list",
                        record_id,
                        "stale or foreign extension record reference",
                    ));
                }
                let attribute = extension
                    .attributes
                    .iter()
                    .find(|a| {
                        a.instance == instance
                            && a.kind == kind
                            && a.name == name
                            && match &a.value {
                                Value::Resident(_) => first_vcn == 0,
                                Value::Nonresident { first, .. } => *first == first_vcn,
                            }
                    })
                    .ok_or_else(|| {
                        corrupt(
                            "NTFS attribute list",
                            record_id,
                            "referenced attribute is missing",
                        )
                    })?;
                attributes.push(attribute.clone());
            } else if reference >> 48 != u64::from(sequence) {
                return Err(corrupt(
                    "NTFS attribute list",
                    id,
                    "stale base record reference",
                ));
            }
            position += length;
        }
        Ok(attributes)
    }
    pub fn metadata(&mut self, id: u64) -> Result<Metadata> {
        let record = self.record(id)?;
        let attributes = self.attributes(id)?;
        let mut times = Times::default();
        if let Some(si) = resident(&attributes, 0x10, "") {
            times.created = Some(filetime(u64le(si, 0)?));
            times.modified = Some(filetime(u64le(si, 8)?));
            times.changed = Some(filetime(u64le(si, 16)?));
            times.accessed = Some(filetime(u64le(si, 24)?));
        }
        let mut streams = Vec::new();
        let names: HashSet<_> = attributes
            .iter()
            .filter(|a| a.kind == 0x80)
            .map(|a| a.name.clone())
            .collect();
        for name in names {
            if let Some(data) = stream(&attributes, 0x80, &name, self.cluster_size, false)? {
                streams.push(StreamInfo {
                    name,
                    size: data.size,
                    resident: data.resident.is_some(),
                    compressed: data.flags & 0xff != 0,
                    encrypted: data.flags & 0x4000 != 0,
                });
            }
        }
        streams.sort_by(|a, b| a.name.cmp(&b.name));
        let size = if record.flags & 2 != 0 {
            resident(&attributes, 0x90, "$I30").map_or(0, |value| value.len() as u64)
        } else {
            streams
                .iter()
                .find(|a| a.name.is_empty())
                .map_or(0, |a| a.size)
        };
        let mut kind = if record.flags & 2 != 0 {
            FileKind::Directory
        } else {
            FileKind::File
        };
        if attributes.iter().any(|a| a.kind == 0xc0) {
            kind = FileKind::Symlink;
        }
        Ok(Metadata {
            id,
            kind,
            size,
            allocated: record.flags & 1 != 0,
            links: u32::from(record.links),
            mode: None,
            uid: None,
            gid: None,
            sequence: Some(record.sequence),
            times,
            streams,
        })
    }
    pub fn read_file(
        &mut self,
        id: u64,
        name: Option<&str>,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let name = name.unwrap_or("");
        if self
            .cached_stream
            .as_ref()
            .is_none_or(|(cached, stream, _)| *cached != id || stream != name)
        {
            let record = self.record(id)?;
            if record.flags & 2 != 0 {
                return Err(Error::Unsupported(
                    "NTFS directory content as a data file".into(),
                ));
            }
            let attributes = self.attributes(id)?;
            if attributes.iter().any(|a| a.kind == 0xc0) {
                return Err(Error::Unsupported(
                    "NTFS reparse point content/traversal".into(),
                ));
            }
            let data = stream(&attributes, 0x80, name, self.cluster_size, false)?;
            let data = if let Some(data) = data {
                data
            } else if name.is_empty() {
                Stream {
                    resident: Some(Vec::new()),
                    runs: Vec::new(),
                    size: 0,
                    initialized: 0,
                    flags: 0,
                    compression_unit: 0,
                }
            } else {
                return Err(Error::NotFound(format!("NTFS stream {name}")));
            };
            self.cached_stream = Some((id, name.into(), data));
        }
        read_stream(
            self.image,
            self.cluster_size,
            &self.cached_stream.as_ref().unwrap().2,
            offset,
            buffer,
        )
    }
    pub fn read_dir(&mut self, id: u64) -> Result<Vec<DirEntry>> {
        let record = self.record(id)?;
        if record.flags & 2 == 0 {
            return Err(Error::NotDirectory(id.to_string()));
        }
        let attributes = self.attributes(id)?;
        let root = resident(&attributes, 0x90, "$I30")
            .ok_or_else(|| corrupt("NTFS index", id, "missing $I30 index root"))?;
        if u32le(root, 0)? != 0x30 || u32le(root, 8)? as usize != self.index_size {
            return Err(corrupt("NTFS index", id, "invalid filename index geometry"));
        }
        let allocation = stream(&attributes, 0xa0, "$I30", self.cluster_size, false)?;
        let bitmap = stream(&attributes, 0xb0, "$I30", self.cluster_size, false)?;
        let (mut keys, children) = index_entries(root, 16, self.limits.max_directory_entries)?;
        let mut queue: Vec<_> = children.into_iter().map(|vcn| (vcn, 1)).collect();
        let mut visited = HashSet::new();
        while let Some((vcn, depth)) = queue.pop() {
            if depth > self.limits.max_tree_depth
                || visited.len() as u64 * self.index_size as u64 >= self.limits.max_directory_bytes
            {
                return Err(Error::ResourceLimit("NTFS directory index traversal"));
            }
            if !visited.insert(vcn) {
                return Err(corrupt(
                    "NTFS index",
                    vcn,
                    "cycle or duplicate child in index tree",
                ));
            }
            let unit = if self.cluster_size <= self.index_size as u64 {
                self.cluster_size
            } else {
                self.sectors as u64
            };
            let offset = vcn
                .checked_mul(unit)
                .ok_or_else(|| corrupt("NTFS index", vcn, "index offset overflow"))?;
            if !offset.is_multiple_of(self.index_size as u64) {
                return Err(corrupt("NTFS index", vcn, "unaligned index child"));
            }
            let allocation = allocation
                .as_ref()
                .ok_or_else(|| corrupt("NTFS index", id, "missing index allocation stream"))?;
            let bitmap = bitmap
                .as_ref()
                .ok_or_else(|| corrupt("NTFS index", id, "missing index bitmap"))?;
            let bit = offset / self.index_size as u64;
            let mut flag = [0];
            if read_stream(self.image, self.cluster_size, bitmap, bit / 8, &mut flag)? != 1
                || flag[0] & (1 << (bit % 8)) == 0
            {
                return Err(corrupt(
                    "NTFS index",
                    vcn,
                    "tree points to an unallocated index record",
                ));
            }
            let mut data = vec![0; self.index_size];
            if read_stream(self.image, self.cluster_size, allocation, offset, &mut data)?
                != data.len()
            {
                return Err(corrupt("NTFS index", vcn, "short index record"));
            }
            fixup(&mut data, b"INDX", self.sectors)?;
            if u64le(&data, 16)? != vcn {
                return Err(corrupt("NTFS index", vcn, "index record VCN mismatch"));
            }
            let (entries, children) = index_entries(&data, 24, self.limits.max_directory_entries)?;
            if keys.len().saturating_add(entries.len()) > self.limits.max_directory_entries {
                return Err(Error::ResourceLimit("NTFS directory entries"));
            }
            keys.extend(entries);
            queue.extend(children.into_iter().map(|child| (child, depth + 1)));
        }
        let mut result = Vec::new();
        let mut aliases: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        let mut names = HashSet::new();
        for key in &keys {
            if key.namespace == 2 {
                aliases
                    .entry(key.reference & REFERENCE_MASK)
                    .or_default()
                    .push(key.name.clone());
            }
        }
        for key in keys {
            if key.name == "." || key.name == ".." {
                continue;
            }
            let file_id = key.reference & REFERENCE_MASK;
            if key.namespace == 2 {
                continue;
            }
            if !names.insert(key.name.clone()) {
                return Err(corrupt("NTFS index", id, "duplicate directory filename"));
            }
            let file = self.record(file_id)?;
            if file.sequence != (key.reference >> 48) as u16 || file.flags & 1 == 0 {
                return Err(corrupt(
                    "NTFS index",
                    file_id,
                    "stale or unallocated file reference",
                ));
            }
            let kind = if file.flags & 2 != 0 {
                FileKind::Directory
            } else if file.attributes.iter().any(|a| a.kind == 0xc0) {
                FileKind::Symlink
            } else {
                FileKind::File
            };
            let size = if kind == FileKind::Directory {
                resident(&file.attributes, 0x90, "$I30").map_or(0, |value| value.len() as u64)
            } else {
                stream(&file.attributes, 0x80, "", self.cluster_size, true)?
                    .map_or(key.size, |data| data.size)
            };
            result.push(DirEntry {
                id: file_id,
                name: key.name,
                kind,
                size,
                allocated: true,
                aliases: aliases.get(&file_id).cloned().unwrap_or_default(),
                raw_name: None,
            });
        }
        Ok(result)
    }
}

fn decode_record_size(value: i8, cluster_size: u64, limit: usize) -> Result<usize> {
    let size = if value < 0 {
        1_u64.checked_shl(u32::from(value.unsigned_abs()))
    } else {
        cluster_size.checked_mul(value as u64)
    }
    .ok_or_else(|| corrupt("NTFS", 64, "record size overflow"))?;
    if size < 512 || size > limit as u64 || size > 1024 * 1024 {
        return Err(Error::ResourceLimit("NTFS record size"));
    }
    Ok(size as usize)
}
fn fixup(data: &mut [u8], magic: &[u8; 4], sector_size: usize) -> Result<()> {
    if data.get(..4) != Some(magic) {
        return Err(corrupt("NTFS record", 0, "invalid record signature"));
    }
    let offset = u16le(data, 4)? as usize;
    let count = u16le(data, 6)? as usize;
    let stride = if count == data.len() / 512 + 1 {
        512
    } else {
        sector_size
    };
    if count < 2
        || !data.len().is_multiple_of(stride)
        || count != data.len() / stride + 1
        || offset < 8
        || offset + count * 2 > stride - 2
    {
        return Err(corrupt(
            "NTFS update sequence",
            offset as u64,
            "invalid update sequence array",
        ));
    }
    let sequence = bytes(data, offset, 2)?.to_vec();
    for index in 1..count {
        let end = index * stride - 2;
        if bytes(data, end, 2)? != sequence {
            return Err(corrupt(
                "NTFS update sequence",
                end as u64,
                "torn sector or bad update sequence",
            ));
        }
    }
    for index in 1..count {
        let original: [u8; 2] = bytes(data, offset + index * 2, 2)?.try_into().unwrap();
        data[index * stride - 2..index * stride].copy_from_slice(&original);
    }
    Ok(())
}
fn parse_record(data: &[u8], total_clusters: u64, limits: &Limits) -> Result<Record> {
    let used = u32le(data, 24)? as usize;
    let allocated = u32le(data, 28)? as usize;
    let mut offset = u16le(data, 20)? as usize;
    if allocated != data.len()
        || used > allocated
        || offset < 48
        || !offset.is_multiple_of(8)
        || offset + 4 > used
    {
        return Err(corrupt("MFT", 0, "invalid file record bounds"));
    }
    let mut attributes = Vec::new();
    loop {
        let kind = u32le(bytes(data, 0, used)?, offset)?;
        if kind == 0xffff_ffff {
            break;
        }
        if attributes.len() >= 1024 {
            return Err(Error::ResourceLimit("NTFS attributes per record"));
        }
        let length = u32le(data, offset + 4)? as usize;
        if length < 24 || !length.is_multiple_of(8) || kind == 0 {
            return Err(corrupt(
                "MFT attribute",
                offset as u64,
                "invalid attribute length or type",
            ));
        }
        let attr = bytes(bytes(data, 0, used)?, offset, length)?;
        let name_length = attr[9] as usize * 2;
        let name_offset = u16le(attr, 10)? as usize;
        if name_length != 0 && name_offset < 24 {
            return Err(corrupt(
                "MFT attribute",
                offset as u64,
                "attribute name overlaps header",
            ));
        }
        let name = if name_length == 0 {
            String::new()
        } else {
            utf16(bytes(attr, name_offset, name_length)?)?
        };
        let flags = u16le(attr, 12)?;
        let value = match attr[8] {
            0 => {
                let value_offset = u16le(attr, 20)? as usize;
                if value_offset < 24 {
                    return Err(corrupt(
                        "MFT attribute",
                        offset as u64,
                        "resident value overlaps header",
                    ));
                }
                Value::Resident(bytes(attr, value_offset, u32le(attr, 16)? as usize)?.to_vec())
            }
            1 => {
                let first = u64le(attr, 16)?;
                let last = u64le(attr, 24)?;
                let run_offset = u16le(attr, 32)? as usize;
                if run_offset < 64 || run_offset >= attr.len() {
                    return Err(corrupt(
                        "MFT attribute",
                        offset as u64,
                        "invalid mapping pairs offset",
                    ));
                }
                let size = u64le(attr, 48)?;
                let initialized = u64le(attr, 56)?;
                if first == 0 && initialized > size {
                    return Err(corrupt(
                        "MFT attribute",
                        offset as u64,
                        "initialized data exceeds stream size",
                    ));
                }
                let runs = runlist(
                    &attr[run_offset..],
                    first,
                    last,
                    total_clusters,
                    limits.max_chain_length,
                )?;
                Value::Nonresident {
                    first,
                    compression_unit: u16le(attr, 34)?,
                    size,
                    initialized,
                    runs,
                }
            }
            _ => {
                return Err(corrupt(
                    "MFT attribute",
                    offset as u64,
                    "invalid resident flag",
                ));
            }
        };
        attributes.push(Attribute {
            kind,
            name,
            instance: u16le(attr, 14)?,
            flags,
            value,
        });
        offset += length;
    }
    Ok(Record {
        sequence: u16le(data, 16)?,
        links: u16le(data, 18)?,
        flags: u16le(data, 22)?,
        base: u64le(data, 32)?,
        attributes,
    })
}
fn runlist(
    data: &[u8],
    first: u64,
    last: u64,
    total_clusters: u64,
    limit: usize,
) -> Result<Vec<Run>> {
    let mut position = 0;
    let mut vcn = first;
    let mut lcn = 0_i128;
    let mut runs = Vec::new();
    loop {
        let header = *data.get(position).ok_or_else(|| {
            corrupt(
                "NTFS runlist",
                position as u64,
                "unterminated mapping pairs",
            )
        })?;
        position += 1;
        if header == 0 {
            break;
        }
        let length_size = (header & 15) as usize;
        let offset_size = (header >> 4) as usize;
        if length_size == 0 || length_size > 8 || offset_size > 8 {
            return Err(corrupt(
                "NTFS runlist",
                position as u64,
                "invalid mapping pair widths",
            ));
        }
        let mut integer = [0; 8];
        integer[..length_size].copy_from_slice(bytes(data, position, length_size)?);
        let count = u64::from_le_bytes(integer);
        position += length_size;
        if count == 0 {
            return Err(corrupt("NTFS runlist", position as u64, "empty run"));
        }
        let physical = if offset_size == 0 {
            None
        } else {
            let value = bytes(data, position, offset_size)?;
            let mut integer = if value[offset_size - 1] & 0x80 != 0 {
                [0xff; 8]
            } else {
                [0; 8]
            };
            integer[..offset_size].copy_from_slice(value);
            lcn += i128::from(i64::from_le_bytes(integer));
            if lcn < 0 || lcn > i128::from(u64::MAX) {
                return Err(corrupt(
                    "NTFS runlist",
                    position as u64,
                    "negative or overflowing physical cluster",
                ));
            }
            checked_region(lcn as u64, count, total_clusters, "NTFS runlist")?;
            Some(lcn as u64)
        };
        position += offset_size;
        if runs.len() >= limit {
            return Err(Error::ResourceLimit("NTFS run count"));
        }
        runs.push(Run {
            vcn,
            count,
            lcn: physical,
        });
        vcn = vcn
            .checked_add(count)
            .ok_or_else(|| corrupt("NTFS runlist", position as u64, "virtual cluster overflow"))?;
    }
    if !runs.is_empty() && last.checked_add(1) != Some(vcn) {
        return Err(corrupt(
            "NTFS runlist",
            position as u64,
            "mapping pairs do not match highest VCN",
        ));
    }
    Ok(runs)
}
fn resident<'a>(attributes: &'a [Attribute], kind: u32, name: &str) -> Option<&'a [u8]> {
    attributes.iter().find_map(|a| {
        if a.kind == kind && a.name == name {
            if let Value::Resident(value) = &a.value {
                Some(value.as_slice())
            } else {
                None
            }
        } else {
            None
        }
    })
}
fn stream(
    attributes: &[Attribute],
    kind: u32,
    name: &str,
    cluster_size: u64,
    partial: bool,
) -> Result<Option<Stream>> {
    let mut pieces: Vec<_> = attributes
        .iter()
        .filter(|a| a.kind == kind && a.name == name)
        .collect();
    if pieces.is_empty() {
        return Ok(None);
    }
    pieces.sort_by_key(|a| match a.value {
        Value::Resident(_) => 0,
        Value::Nonresident { first, .. } => first,
    });
    if let Value::Resident(data) = &pieces[0].value {
        if pieces.len() != 1 {
            return Err(corrupt(
                "NTFS stream",
                0,
                "duplicate resident stream attributes",
            ));
        }
        return Ok(Some(Stream {
            resident: Some(data.clone()),
            runs: Vec::new(),
            size: data.len() as u64,
            initialized: data.len() as u64,
            flags: pieces[0].flags,
            compression_unit: 0,
        }));
    }
    let mut result = Stream {
        resident: None,
        runs: Vec::new(),
        size: 0,
        initialized: 0,
        flags: pieces[0].flags,
        compression_unit: 0,
    };
    let mut expected = 0;
    for piece in pieces {
        let Value::Nonresident {
            first,
            compression_unit,
            size,
            initialized,
            runs,
        } = &piece.value
        else {
            return Err(corrupt(
                "NTFS stream",
                0,
                "mixed resident/nonresident stream",
            ));
        };
        if *first != expected {
            return Err(corrupt(
                "NTFS stream",
                *first,
                "gap or overlap in attribute extents",
            ));
        }
        if *first == 0 {
            result.size = *size;
            result.initialized = *initialized;
            result.compression_unit = *compression_unit;
        } else if *compression_unit != result.compression_unit || piece.flags != result.flags {
            return Err(corrupt(
                "NTFS stream",
                *first,
                "extent compression flags/unit disagree",
            ));
        }
        result.flags |= piece.flags;
        for run in runs {
            expected = run
                .vcn
                .checked_add(run.count)
                .ok_or_else(|| corrupt("NTFS stream", run.vcn, "extent overflow"))?;
            result.runs.push(run.clone());
        }
    }
    let covered = expected
        .checked_mul(cluster_size)
        .ok_or_else(|| corrupt("NTFS stream", 0, "stream length overflow"))?;
    if !partial && covered < result.size {
        return Err(Error::Unsupported(
            "NTFS stream mapping is incomplete (fragmented attribute-list bootstrap)".into(),
        ));
    }
    Ok(Some(result))
}
fn read_stream(
    image: &mut dyn DiskImage,
    cluster_size: u64,
    stream: &Stream,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize> {
    if stream.flags & 0x4000 != 0 {
        return Err(Error::Unsupported("NTFS EFS-encrypted data streams".into()));
    }
    if stream.flags & 0xff != 0 && stream.resident.is_none() {
        if stream.flags & 0xff != 1 || stream.compression_unit != 4 || cluster_size > 4096 {
            return Err(Error::Unsupported(
                "NTFS compression algorithm/unit geometry".into(),
            ));
        }
        return read_compressed(image, cluster_size, stream, offset, buffer);
    }
    let amount = stream.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
    if let Some(data) = &stream.resident {
        if amount > 0 {
            buffer[..amount].copy_from_slice(&data[offset as usize..offset as usize + amount]);
        }
        return Ok(amount);
    }
    let mut done = 0;
    while done < amount {
        let position = offset + done as u64;
        if position >= stream.initialized {
            buffer[done..amount].fill(0);
            break;
        }
        let vcn = position / cluster_size;
        let index = stream
            .runs
            .partition_point(|r| r.vcn <= vcn)
            .checked_sub(1)
            .ok_or_else(|| corrupt("NTFS stream", position, "unmapped virtual cluster"))?;
        let run = &stream.runs[index];
        if vcn - run.vcn >= run.count {
            return Err(corrupt("NTFS stream", position, "gap in virtual mapping"));
        }
        let run_start = run.vcn * cluster_size;
        let within = position - run_start;
        let count = (run.count * cluster_size - within)
            .min((amount - done) as u64)
            .min(stream.initialized - position) as usize;
        if let Some(lcn) = run.lcn {
            image.read_exact_at(lcn * cluster_size + within, &mut buffer[done..done + count])?;
        } else {
            buffer[done..done + count].fill(0);
        }
        done += count;
    }
    Ok(amount)
}
fn read_compressed(
    image: &mut dyn DiskImage,
    cluster: u64,
    stream: &Stream,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize> {
    let amount = stream.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
    let unit = cluster * 16;
    let mut done = 0;
    while done < amount {
        let at = offset + done as u64;
        if at >= stream.initialized {
            buffer[done..amount].fill(0);
            break;
        }
        let start = at / unit * unit;
        let first = start / cluster;
        let end = (first + 16).min(stream.runs.last().map_or(0, |r| r.vcn + r.count));
        let mut physical = Vec::with_capacity(unit as usize);
        let mut sparse = false;
        let mut vcn = first;
        while vcn < end {
            let i = stream
                .runs
                .partition_point(|r| r.vcn <= vcn)
                .checked_sub(1)
                .ok_or_else(|| corrupt("NTFS compression", vcn, "unmapped unit"))?;
            let run = &stream.runs[i];
            if vcn >= run.vcn + run.count {
                return Err(corrupt("NTFS compression", vcn, "unmapped cluster"));
            }
            let count = (run.vcn + run.count - vcn).min(end - vcn);
            if let Some(lcn) = run.lcn {
                if sparse {
                    return Err(corrupt(
                        "NTFS compression",
                        vcn,
                        "allocated cluster follows sparse unit tail",
                    ));
                }
                let n = (count * cluster) as usize;
                let old = physical.len();
                physical.resize(old + n, 0);
                image.read_exact_at((lcn + vcn - run.vcn) * cluster, &mut physical[old..])?;
            } else {
                sparse = true;
            }
            vcn += count;
        }
        let required = (stream.initialized - start).min(unit) as usize;
        let data = if physical.is_empty() {
            vec![0; unit as usize]
        } else if !sparse {
            physical
        } else {
            super::lznt1::decompress(&physical, unit as usize)?
        };
        if data.len() < required {
            return Err(corrupt(
                "NTFS compression",
                start,
                "decoded unit is shorter than initialized data",
            ));
        }
        let within = (at - start) as usize;
        let count = (amount - done)
            .min((unit - (at - start)) as usize)
            .min((stream.initialized - at) as usize);
        buffer[done..done + count].copy_from_slice(&data[within..within + count]);
        done += count;
    }
    Ok(amount)
}
fn filetime(value: u64) -> Timestamp {
    Timestamp {
        seconds: (value / 10_000_000) as i64 - 11_644_473_600,
        nanos: ((value % 10_000_000) * 100) as u32,
        basis: TimeBasis::Utc,
    }
}

struct IndexKey {
    reference: u64,
    name: String,
    namespace: u8,
    size: u64,
}
fn index_entries(data: &[u8], header: usize, limit: usize) -> Result<(Vec<IndexKey>, Vec<u64>)> {
    let entries_offset = u32le(data, header)? as usize;
    let used = u32le(data, header + 4)? as usize;
    let allocated = u32le(data, header + 8)? as usize;
    if entries_offset < 16 || used < entries_offset || allocated < used {
        return Err(corrupt(
            "NTFS index",
            header as u64,
            "invalid index header bounds",
        ));
    }
    let block = bytes(data, header, used)?;
    let mut offset = entries_offset;
    let mut keys = Vec::new();
    let mut children = Vec::new();
    loop {
        let length = u16le(block, offset + 8)? as usize;
        let key_length = u16le(block, offset + 10)? as usize;
        let flags = u16le(block, offset + 12)?;
        if length < 16 || !length.is_multiple_of(8) || flags & !3 != 0 {
            return Err(corrupt("NTFS index", offset as u64, "invalid index entry"));
        }
        let entry = bytes(block, offset, length)?;
        let child_bytes = if flags & 1 != 0 { 8 } else { 0 };
        if length < 16 + child_bytes || key_length > length - 16 - child_bytes {
            return Err(corrupt(
                "NTFS index",
                offset as u64,
                "key exceeds entry bounds",
            ));
        }
        if child_bytes != 0 {
            children.push(u64le(entry, length - 8)?);
        }
        if flags & 2 != 0 {
            if key_length != 0 {
                return Err(corrupt(
                    "NTFS index",
                    offset as u64,
                    "terminal entry has a key",
                ));
            }
            break;
        }
        let key = bytes(entry, 16, key_length)?;
        let name_length = *key
            .get(64)
            .ok_or_else(|| corrupt("NTFS index", offset as u64, "truncated filename key"))?
            as usize;
        let namespace = *key
            .get(65)
            .ok_or_else(|| corrupt("NTFS index", offset as u64, "truncated filename namespace"))?;
        if namespace > 3 || name_length == 0 {
            return Err(corrupt(
                "NTFS index",
                offset as u64,
                "invalid filename namespace or length",
            ));
        }
        let name = utf16(bytes(key, 66, name_length * 2)?)?;
        if name.contains(['\0', '/']) {
            return Err(corrupt("NTFS index", offset as u64, "invalid filename"));
        }
        if keys.len() >= limit {
            return Err(Error::ResourceLimit("NTFS directory entries"));
        }
        keys.push(IndexKey {
            reference: u64le(entry, 0)?,
            name,
            namespace,
            size: u64le(key, 48)?,
        });
        offset += length;
    }
    Ok((keys, children))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_mapping_deltas_and_sparse_runs_are_preserved() {
        let runs = runlist(&[0x11, 3, 5, 0x11, 2, 0xfe, 0x01, 4, 0], 0, 8, 100, 10).unwrap();
        assert_eq!((runs[0].vcn, runs[0].count, runs[0].lcn), (0, 3, Some(5)));
        assert_eq!((runs[1].vcn, runs[1].count, runs[1].lcn), (3, 2, Some(3)));
        assert_eq!((runs[2].vcn, runs[2].count, runs[2].lcn), (5, 4, None));
    }
    #[test]
    fn invalid_or_overflowing_mapping_pairs_are_errors() {
        for data in [
            &[0x90, 1, 0][..],
            &[0x11, 0, 1, 0],
            &[0x11, 1, 0xff, 0],
            &[0x11, 2, 99, 0],
            &[0x11, 1],
            &[0x11, 1, 1],
        ] {
            assert!(runlist(data, 0, 0, 100, 10).is_err(), "{data:?}");
        }
        assert!(runlist(&[0x01, 1, 0], u64::MAX, u64::MAX, 100, 10).is_err());
    }
    #[test]
    fn update_sequences_restore_sector_tails_and_detect_torn_writes() {
        let mut data = vec![0; 1024];
        data[..4].copy_from_slice(b"FILE");
        data[4..6].copy_from_slice(&48_u16.to_le_bytes());
        data[6..8].copy_from_slice(&3_u16.to_le_bytes());
        data[48..54].copy_from_slice(&[0xaa, 0x55, 1, 2, 3, 4]);
        data[510..512].copy_from_slice(&[0xaa, 0x55]);
        data[1022..1024].copy_from_slice(&[0xaa, 0x55]);
        let mut torn = data.clone();
        torn[1023] ^= 1;
        assert!(fixup(&mut torn, b"FILE", 512).is_err());
        fixup(&mut data, b"FILE", 512).unwrap();
        assert_eq!(&data[510..512], &[1, 2]);
        assert_eq!(&data[1022..1024], &[3, 4]);
    }
    #[test]
    fn truncated_index_children_cannot_underflow_entry_bounds() {
        let mut data = vec![0; 32];
        data[..4].copy_from_slice(&16_u32.to_le_bytes());
        data[4..8].copy_from_slice(&32_u32.to_le_bytes());
        data[8..12].copy_from_slice(&32_u32.to_le_bytes());
        data[24..26].copy_from_slice(&16_u16.to_le_bytes());
        data[28..30].copy_from_slice(&3_u16.to_le_bytes());
        assert!(index_entries(&data, 0, 100).is_err());
    }
    #[test]
    fn filetime_epoch_and_subsecond_precision_are_explicit() {
        assert_eq!(filetime(0).seconds, -11_644_473_600);
        assert_eq!(
            filetime(116_444_736_000_000_123),
            Timestamp {
                seconds: 0,
                nanos: 12300,
                basis: TimeBasis::Utc
            }
        );
    }
}
