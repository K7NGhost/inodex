//! Read-only exFAT v1; checks boot regions, entry sets, upcase and allocation.
use super::{DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, TimeBasis, Times};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
struct Record {
    first: u32,
    size: u64,
    valid: u64,
    contiguous: bool,
    directory: bool,
    times: Times,
}

pub struct Exfat<'a> {
    image: &'a mut dyn DiskImage,
    info: FsInfo,
    limits: Limits,
    fat: u64,
    heap: u64,
    clusters: u32,
    cluster_size: u64,
    bitmap: Vec<u8>,
    upcase: Vec<u16>,
    records: HashMap<u64, Record>,
}

fn bad(reason: &str) -> Error {
    corrupt("exFAT", 0, reason)
}
fn checksum32(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |s, b| s.rotate_right(1).wrapping_add(u32::from(*b)))
}
fn set_checksum(data: &[u8]) -> u16 {
    data.iter()
        .enumerate()
        .filter(|(i, _)| *i != 2 && *i != 3)
        .fold(0u16, |s, (_, b)| {
            s.rotate_right(1).wrapping_add(u16::from(*b))
        })
}
impl<'a> Exfat<'a> {
    pub fn open(image: &'a mut dyn DiskImage, limits: Limits) -> Result<Self> {
        let b = read_vec(image, 0, 512)?;
        if &b[3..11] != b"EXFAT   "
            || b[..3] != [0xeb, 0x76, 0x90]
            || b[11..64].iter().any(|b| *b != 0)
            || b[510..] != [0x55, 0xaa]
            || !(9..=12).contains(&b[108])
            || b[109] > 25 - b[108]
        {
            return Err(bad("invalid boot record"));
        }
        if u16le(&b, 104)? != 0x100 || b[110] != 1 {
            return Err(Error::Unsupported(
                "exFAT revision or TexFAT/two-FAT volume".into(),
            ));
        }
        let sector = 1u64 << b[108];
        let cluster_size = sector << b[109];
        let total = u64le(&b, 72)?
            .checked_mul(sector)
            .ok_or_else(|| bad("volume size overflow"))?;
        checked_region(0, total, image.len(), "exFAT")?;
        let fat = u64::from(u32le(&b, 80)?) * sector;
        let fat_size = u64::from(u32le(&b, 84)?) * sector;
        let heap = u64::from(u32le(&b, 88)?) * sector;
        let clusters = u32le(&b, 92)?;
        let flags = u16le(&b, 106)?;
        if clusters == 0
            || clusters > 0xffff_fff5
            || fat < 24 * sector
            || fat + fat_size > heap
            || fat_size < (u64::from(clusters) + 2) * 4
            || flags & 1 != 0
            || (b[112] > 100 && b[112] != 255)
        {
            return Err(bad("invalid volume geometry or active FAT"));
        }
        checked_region(heap, u64::from(clusters) * cluster_size, total, "exFAT")?;
        let header = read_vec(image, fat, 8)?;
        if u32le(&header, 0)? != 0xffff_fff8 || u32le(&header, 4)? != 0xffff_ffff {
            return Err(bad("invalid reserved FAT entries"));
        }
        // Validate both boot regions. Mutable flags/percent are excluded by spec.
        for base in [0, 12 * sector] {
            let boot = read_vec(image, base, (12 * sector) as usize)?;
            let mut sum = 0u32;
            for (i, byte) in boot[..(11 * sector) as usize].iter().enumerate() {
                if ![106, 107, 112].contains(&i) {
                    sum = sum.rotate_right(1).wrapping_add(u32::from(*byte));
                }
            }
            if boot[(11 * sector) as usize..]
                .as_chunks::<4>()
                .0
                .iter()
                .any(|v| u32::from_le_bytes(*v) != sum)
            {
                return Err(bad("boot checksum mismatch"));
            }
            for i in 1..=8 {
                if u32le(&boot, (i * sector) as usize + sector as usize - 4)? != 0xaa55_0000 {
                    return Err(bad("extended boot signature"));
                }
            }
            if boot[..106] != b[..106] || boot[108..112] != b[108..112] {
                return Err(bad("backup boot geometry disagrees"));
            }
        }
        let root = u32le(&b, 96)?;
        let mut fs = Self {
            image,
            limits,
            fat,
            heap,
            clusters,
            cluster_size,
            bitmap: vec![],
            upcase: vec![],
            records: HashMap::new(),
            info: FsInfo {
                filesystem: FsType::Exfat,
                label: String::new(),
                block_size: cluster_size as u32,
                total_bytes: total,
                root_id: 0,
                needs_journal_recovery: flags & 6 != 0,
            },
        };
        let chain = fs.chain(root, None, false)?;
        let size = chain.len() as u64 * cluster_size;
        fs.records.insert(
            0,
            Record {
                first: root,
                size,
                valid: size,
                contiguous: false,
                directory: true,
                times: Times::default(),
            },
        );
        let (data, _) = fs.directory_data(0)?;
        let mut bitmap = None;
        let mut upcase = None;
        let mut label_seen = false;
        for e in data.as_chunks::<32>().0 {
            if e[0] == 0 {
                break;
            }
            match e[0] {
                0x81 => {
                    if bitmap.is_some() || e[1] != 0 {
                        return Err(bad("duplicate/invalid bitmap"));
                    }
                    bitmap = Some((u32le(e, 20)?, u64le(e, 24)?));
                }
                0x82 => {
                    if upcase.is_some() {
                        return Err(bad("duplicate upcase"));
                    }
                    upcase = Some((u32le(e, 20)?, u64le(e, 24)?, u32le(e, 4)?));
                }
                0x83 => {
                    if label_seen || e[1] > 11 {
                        return Err(bad("invalid volume label"));
                    }
                    label_seen = true;
                    fs.info.label = utf16(&e[2..2 + usize::from(e[1]) * 2])?;
                }
                _ => {}
            }
        }
        let (first, len) = bitmap.ok_or_else(|| bad("missing allocation bitmap"))?;
        if len != u64::from(clusters).div_ceil(8) {
            return Err(bad("bitmap size"));
        }
        fs.bitmap = fs.system_data(first, len)?;
        let bitmap_chain = fs.chain(first, Some(len), false)?;
        let (first, len, expected) = upcase.ok_or_else(|| bad("missing upcase table"))?;
        let data = fs.system_data(first, len)?;
        if fs.limits.max_metadata_bytes < 65536 * 2 {
            return Err(Error::ResourceLimit("exFAT decoded upcase table"));
        }
        if checksum32(&data) != expected || !data.len().is_multiple_of(2) {
            return Err(bad("upcase checksum/size"));
        }
        let mut words = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes(*v));
        while let Some(w) = words.next() {
            if w == 0xffff && fs.upcase.len() != 65535 {
                let n = words.next().ok_or_else(|| bad("truncated upcase run"))? as usize;
                if n == 0 || fs.upcase.len() + n > 65536 {
                    return Err(bad("upcase run bounds"));
                }
                for _ in 0..n {
                    fs.upcase.push(fs.upcase.len() as u16);
                }
            } else {
                fs.upcase.push(w);
            }
            if fs.upcase.len() > 65536 {
                return Err(bad("upcase table too large"));
            }
        }
        if fs.upcase.len() != 65536
            || (0..128).any(|i| fs.upcase[i] != (i as u8).to_ascii_uppercase() as u16)
        {
            return Err(bad("invalid upcase mapping"));
        }
        for c in chain.into_iter().chain(bitmap_chain) {
            fs.allocated(c)?;
        }
        fs.read_dir(0)?;
        Ok(fs)
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    fn cluster_offset(&self, c: u32) -> Result<u64> {
        if c < 2 || u64::from(c) >= u64::from(self.clusters) + 2 {
            return Err(bad("cluster outside heap"));
        }
        Ok(self.heap + u64::from(c - 2) * self.cluster_size)
    }
    fn allocated(&self, c: u32) -> Result<()> {
        self.cluster_offset(c)?;
        if !self.bitmap.is_empty() && self.bitmap[(c as usize - 2) / 8] & (1 << ((c - 2) % 8)) == 0
        {
            return Err(bad("stream references free cluster"));
        }
        Ok(())
    }
    fn chain(&mut self, first: u32, len: Option<u64>, contiguous: bool) -> Result<Vec<u32>> {
        let count = len.map(|n| n.div_ceil(self.cluster_size));
        if count == Some(0) {
            if first != 0 {
                return Err(bad("empty stream cluster"));
            }
            return Ok(vec![]);
        }
        if count.is_some_and(|n| {
            n > self.limits.max_chain_length as u64 || n > u64::from(self.clusters)
        }) {
            return Err(Error::ResourceLimit("exFAT cluster chain"));
        }
        let mut out = vec![];
        let mut seen = HashSet::new();
        let mut c = first;
        loop {
            self.allocated(c)?;
            if out.len() >= self.limits.max_chain_length {
                return Err(Error::ResourceLimit("exFAT cluster chain"));
            }
            if !seen.insert(c) {
                return Err(bad("cyclic cluster chain"));
            }
            out.push(c);
            if contiguous {
                if Some(out.len() as u64) == count {
                    break;
                }
                c = c.checked_add(1).ok_or_else(|| bad("cluster overflow"))?;
            } else {
                let next = u32le(&read_vec(self.image, self.fat + u64::from(c) * 4, 4)?, 0)?;
                if next >= 0xffff_fff8 {
                    if count.is_some_and(|n| n != out.len() as u64) {
                        return Err(bad("short cluster chain"));
                    }
                    break;
                }
                if count.is_some_and(|n| out.len() as u64 >= n) {
                    return Err(bad("overlong cluster chain"));
                }
                c = next;
            }
        }
        Ok(out)
    }
    fn system_data(&mut self, first: u32, len: u64) -> Result<Vec<u8>> {
        if len > self.limits.max_metadata_bytes as u64 {
            return Err(Error::ResourceLimit("exFAT system metadata"));
        }
        let chain = self.chain(first, Some(len), false)?;
        let mut data = vec![0; len as usize];
        for (i, c) in chain.iter().enumerate() {
            let start = i * self.cluster_size as usize;
            let n = (data.len() - start).min(self.cluster_size as usize);
            let at = self.cluster_offset(*c)?;
            self.image.read_exact_at(at, &mut data[start..start + n])?;
        }
        Ok(data)
    }
    fn record(&self, id: u64) -> Result<Record> {
        self.records
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("exFAT entry {id}; enumerate its parent first")))
    }
    pub fn metadata(&mut self, id: u64) -> Result<Metadata> {
        let r = self.record(id)?;
        Ok(Metadata {
            id,
            kind: if r.directory {
                FileKind::Directory
            } else {
                FileKind::File
            },
            size: r.size,
            allocated: true,
            links: 1,
            mode: None,
            uid: None,
            gid: None,
            sequence: None,
            times: r.times,
            streams: vec![],
        })
    }
    fn directory_data(&mut self, id: u64) -> Result<(Vec<u8>, Vec<u32>)> {
        let r = self.record(id)?;
        if !r.directory {
            return Err(Error::NotDirectory(id.to_string()));
        }
        if r.size > self.limits.max_directory_bytes || r.valid != r.size {
            return Err(Error::ResourceLimit("exFAT directory bytes"));
        }
        let chain = self.chain(r.first, Some(r.size), r.contiguous)?;
        let mut data = vec![0; r.size as usize];
        for (i, c) in chain.iter().enumerate() {
            let start = i * self.cluster_size as usize;
            let at = self.cluster_offset(*c)?;
            self.image
                .read_exact_at(at, &mut data[start..start + self.cluster_size as usize])?;
        }
        Ok((data, chain))
    }
    pub fn name_eq(&self, a: &str, b: &str) -> bool {
        a.encode_utf16()
            .map(|v| self.upcase[v as usize])
            .eq(b.encode_utf16().map(|v| self.upcase[v as usize]))
    }
    pub fn read_dir(&mut self, id: u64) -> Result<Vec<DirEntry>> {
        let (data, chain) = self.directory_data(id)?;
        let mut out = vec![];
        let mut pos = 0;
        while pos + 32 <= data.len() {
            let typ = data[pos];
            if typ == 0 {
                break;
            }
            if typ & 0x80 == 0 {
                pos += 32;
                continue;
            }
            if typ != 0x85 {
                if ![0x81, 0x82, 0x83].contains(&typ) && typ & 0x20 == 0 {
                    return Err(Error::Unsupported(format!(
                        "exFAT critical directory entry {typ:#x}"
                    )));
                }
                pos += 32;
                continue;
            }
            let n = data[pos + 1] as usize;
            let set = bytes(&data, pos, (n + 1) * 32)?;
            if n < 2 || set[32] != 0xc0 || set_checksum(set) != u16le(set, 2)? {
                return Err(bad("entry-set structure/checksum"));
            }
            let s = &set[32..64];
            let flags = s[1];
            let name_len = s[3] as usize;
            if flags & 1 == 0 || flags & !3 != 0 || name_len == 0 {
                return Err(bad("stream flags/name length"));
            }
            let mut name = vec![];
            for e in set[64..].as_chunks::<32>().0 {
                if e[0] == 0xc1 {
                    name.extend_from_slice(&e[2..32]);
                } else if e[0] & 0xe0 != 0xe0 {
                    return Err(Error::Unsupported("exFAT critical secondary entry".into()));
                }
            }
            if name.len() != name_len.div_ceil(15) * 30 {
                return Err(bad("filename entry count"));
            }
            let name = utf16(bytes(&name, 0, name_len * 2)?)?;
            if name.chars().any(|c| c < ' ' || "\"*/:<>?\\|".contains(c))
                || name == "."
                || name == ".."
            {
                return Err(bad("invalid filename"));
            }
            let hash = name
                .encode_utf16()
                .map(|v| self.upcase[v as usize])
                .flat_map(u16::to_le_bytes)
                .fold(0u16, |h, b| h.rotate_right(1).wrapping_add(u16::from(b)));
            if hash != u16le(s, 4)? {
                return Err(bad("filename hash"));
            }
            let attrs = u16le(set, 4)?;
            let size = u64le(s, 24)?;
            let valid = u64le(s, 8)?;
            let first = u32le(s, 20)?;
            if valid > size
                || size > u64::from(self.clusters) * self.cluster_size
                || (size == 0 && first != 0)
                || (size == 0 && flags & 2 != 0)
                || (attrs & 0x10 != 0 && (size == 0 || !size.is_multiple_of(self.cluster_size)))
            {
                return Err(bad("invalid stream size"));
            }
            if size != 0 {
                self.allocated(first)?;
            }
            let entry_id = self.cluster_offset(chain[pos / self.cluster_size as usize])?
                + (pos as u64 % self.cluster_size);
            let r = Record {
                first,
                size,
                valid,
                contiguous: flags & 2 != 0,
                directory: attrs & 0x10 != 0,
                times: Times {
                    created: time(set, 8, set[20], set[22])?,
                    modified: time(set, 12, set[21], set[23])?,
                    accessed: time(set, 16, 0, set[24])?,
                    changed: None,
                },
            };
            if out.len() >= self.limits.max_directory_entries
                || (!self.records.contains_key(&entry_id)
                    && self.records.len() >= self.limits.max_directory_entries)
            {
                return Err(Error::ResourceLimit("exFAT directory entries"));
            }
            out.push(DirEntry {
                id: entry_id,
                name,
                kind: if r.directory {
                    FileKind::Directory
                } else {
                    FileKind::File
                },
                size,
                allocated: true,
                aliases: vec![],
                raw_name: None,
            });
            self.records.insert(entry_id, r);
            pos += set.len();
        }
        Ok(out)
    }
    pub fn read_file(&mut self, id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let r = self.record(id)?;
        if r.directory {
            return Err(Error::Unsupported("exFAT directory as file".into()));
        }
        let chain = self.chain(r.first, Some(r.size), r.contiguous)?;
        let n = r.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        buffer[..n].fill(0);
        let initialized = r.valid.saturating_sub(offset).min(n as u64) as usize;
        let mut done = 0;
        while done < initialized {
            let at = offset + done as u64;
            let c = chain[(at / self.cluster_size) as usize];
            let within = at % self.cluster_size;
            let count = (initialized - done).min((self.cluster_size - within) as usize);
            let physical = self.cluster_offset(c)? + within;
            self.image
                .read_exact_at(physical, &mut buffer[done..done + count])?;
            done += count;
        }
        Ok(n)
    }
}
fn time(data: &[u8], at: usize, increment: u8, zone: u8) -> Result<Option<super::Timestamp>> {
    let packed = u32le(data, at)?;
    let mut value = super::fat::dos_time((packed >> 16) as u16, packed as u16, increment);
    if let Some(t) = value.as_mut()
        && zone & 0x80 != 0
    {
        let quarters = ((zone << 1) as i8) >> 1;
        t.seconds -= i64::from(quarters) * 15 * 60;
        t.basis = TimeBasis::Utc;
    }
    Ok(value)
}
