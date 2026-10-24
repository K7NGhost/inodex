//! Read-only MBR/EBR and GPT partition discovery over any decoded disk image.
use crate::{
    Error, Result,
    image::{DiskImage, Volume, read_vec},
    wire::*,
};
use serde::Serialize;
use std::collections::HashSet;

const MAX_PARTITIONS: usize = 16384;
const MAX_GPT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Mbr,
    Gpt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionType {
    Mbr(u8),
    Gpt([u8; 16]),
}

#[derive(Debug, Clone, Serialize)]
pub struct Partition {
    /// MBR slot 1..4, logical partition 5+, or GPT entry slot 1+.
    pub index: u32,
    pub start_lba: u64,
    pub sectors: u64,
    pub partition_type: PartitionType,
    pub name: String,
    pub unique_id: Option<[u8; 16]>,
    pub attributes: u64,
    pub bootable: bool,
    pub is_container: bool,
    pub is_logical: bool,
}
impl Partition {
    pub fn volume<'a>(&self, image: &'a mut dyn DiskImage) -> Result<Volume<'a>> {
        if self.is_container {
            return Err(Error::Unsupported(
                "open a logical partition inside the extended container".into(),
            ));
        }
        let sector = u64::from(image.sector_size());
        let offset = self
            .start_lba
            .checked_mul(sector)
            .ok_or_else(|| corrupt("partition", self.start_lba, "byte offset overflow"))?;
        let size = self
            .sectors
            .checked_mul(sector)
            .ok_or_else(|| corrupt("partition", self.start_lba, "byte size overflow"))?;
        Volume::new(image, offset, size)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PartitionTable {
    pub scheme: Scheme,
    pub sector_size: u32,
    pub disk_guid: Option<[u8; 16]>,
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    /// No signature/table returns None, allowing whole-volume filesystem images.
    /// Recognized but corrupt partition tables return an error, never a fallback.
    pub fn read(image: &mut dyn DiskImage) -> Result<Option<Self>> {
        let sector_size = image.sector_size();
        if !sector_size.is_power_of_two() || !(512..=65536).contains(&sector_size) {
            return Err(corrupt("partition", 0, "invalid logical sector size"));
        }
        if image.len() < 512 {
            return Ok(None);
        }
        let mbr = read_vec(image, 0, 512)?;
        let gpt_signature = if image.len() >= u64::from(sector_size) + 8 {
            read_vec(image, u64::from(sector_size), 8)? == b"EFI PART"
        } else {
            false
        };
        if gpt_signature
            || (mbr[510..] == [0x55, 0xaa] && (0..4).any(|i| mbr[450 + 16 * i] == 0xee))
        {
            if mbr[510..] != [0x55, 0xaa] {
                return Err(corrupt("GPT", 0, "missing protective MBR signature"));
            }
            let protective: Vec<_> = (0..4).filter(|&i| mbr[450 + i * 16] != 0).collect();
            if protective.len() != 1 || mbr[450 + protective[0] * 16] != 0xee {
                return Err(Error::Unsupported("hybrid GPT/MBR partition tables".into()));
            }
            let entry = mbr_entry(&mbr, protective[0])?;
            let expected = (image.len() / u64::from(sector_size))
                .saturating_sub(1)
                .min(u64::from(u32::MAX));
            if entry.start != 1 || entry.count != expected {
                return Err(corrupt("GPT", 446, "invalid protective MBR coverage"));
            }
            return read_gpt(image).map(Some);
        }
        if mbr[510..] != [0x55, 0xaa] {
            return Ok(None);
        }
        // Known volume boot records also end in 55aa and are not MBRs.
        if &mbr[3..11] == b"NTFS    "
            || &mbr[3..11] == b"EXFAT   "
            || &mbr[54..59] == b"FAT12"
            || &mbr[54..59] == b"FAT16"
            || &mbr[82..87] == b"FAT32"
        {
            return Ok(None);
        }
        if (0..4).all(|i| mbr[450 + i * 16] == 0) {
            return Ok(None);
        }
        read_mbr(image, &mbr).map(Some)
    }
    pub fn get(&self, index: u32) -> Result<&Partition> {
        self.partitions
            .iter()
            .find(|p| p.index == index)
            .ok_or_else(|| Error::NotFound(format!("partition {index}")))
    }
}

#[derive(Clone, Copy)]
struct MbrEntry {
    kind: u8,
    start: u64,
    count: u64,
    bootable: bool,
}
fn extended(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0f | 0x85)
}
fn mbr_entry(bytes: &[u8], slot: usize) -> Result<MbrEntry> {
    let offset = 446 + slot * 16;
    let flags = bytes[offset];
    let entry = MbrEntry {
        kind: bytes[offset + 4],
        start: u64::from(u32le(bytes, offset + 8)?),
        count: u64::from(u32le(bytes, offset + 12)?),
        bootable: flags == 0x80,
    };
    if flags != 0 && flags != 0x80 {
        return Err(corrupt("MBR", offset as u64, "invalid boot flag"));
    }
    if entry.kind == 0 && (entry.start != 0 || entry.count != 0) {
        return Err(corrupt(
            "MBR",
            offset as u64,
            "unused entry has a nonempty range",
        ));
    }
    if entry.kind != 0 && (entry.start == 0 || entry.count == 0) {
        return Err(corrupt(
            "MBR",
            offset as u64,
            "partition has a zero start or size",
        ));
    }
    Ok(entry)
}
fn check_lbas(start: u64, count: u64, total: u64, layer: &'static str) -> Result<()> {
    if count == 0 {
        return Err(corrupt(layer, start, "empty partition"));
    }
    checked_region(start, count, total, layer)
}
fn from_mbr(entry: MbrEntry, index: u32, logical: bool) -> Partition {
    Partition {
        index,
        start_lba: entry.start,
        sectors: entry.count,
        partition_type: PartitionType::Mbr(entry.kind),
        name: String::new(),
        unique_id: None,
        attributes: 0,
        bootable: entry.bootable,
        is_container: extended(entry.kind),
        is_logical: logical,
    }
}
fn overlaps(a: &Partition, b: &Partition) -> bool {
    a.start_lba < b.start_lba + b.sectors && b.start_lba < a.start_lba + a.sectors
}
fn read_mbr(image: &mut dyn DiskImage, mbr: &[u8]) -> Result<PartitionTable> {
    let total = image.len() / u64::from(image.sector_size());
    let mut partitions = Vec::new();
    for slot in 0..4 {
        let entry = mbr_entry(mbr, slot)?;
        if entry.kind == 0 {
            continue;
        }
        if entry.kind == 0xee {
            return Err(corrupt("MBR", 446, "protective MBR requires GPT"));
        }
        check_lbas(entry.start, entry.count, total, "MBR")?;
        partitions.push(from_mbr(entry, slot as u32 + 1, false));
    }
    for (i, a) in partitions.iter().enumerate() {
        if partitions[i + 1..].iter().any(|b| overlaps(a, b)) {
            return Err(corrupt(
                "MBR",
                a.start_lba,
                "overlapping primary partitions",
            ));
        }
    }
    let containers: Vec<_> = partitions
        .iter()
        .filter(|p| p.is_container)
        .cloned()
        .collect();
    let mut logical_index = 5;
    for container in containers {
        let mut current = container.start_lba;
        let end = current + container.sectors;
        let mut visited = HashSet::new();
        loop {
            if visited.len() >= 4096 {
                return Err(Error::ResourceLimit("EBR chain length"));
            }
            if !visited.insert(current) {
                return Err(corrupt("EBR", current, "cycle in extended partition chain"));
            }
            if current < container.start_lba || current >= end {
                return Err(corrupt(
                    "EBR",
                    current,
                    "EBR is outside its extended container",
                ));
            }
            let byte_offset = current * u64::from(image.sector_size());
            let record = read_vec(image, byte_offset, 512)?;
            if record[510..] != [0x55, 0xaa] {
                return Err(corrupt("EBR", current, "missing EBR signature"));
            }
            let mut first = mbr_entry(&record, 0)?;
            if first.kind != 0 {
                if extended(first.kind) || first.kind == 0xee {
                    return Err(corrupt("EBR", current, "invalid logical partition type"));
                }
                first.start = current
                    .checked_add(first.start)
                    .ok_or_else(|| corrupt("EBR", current, "logical offset overflow"))?;
                check_lbas(first.start, first.count, end, "EBR")?;
                if first.start < container.start_lba {
                    return Err(corrupt(
                        "EBR",
                        current,
                        "logical partition precedes its container",
                    ));
                }
                partitions.push(from_mbr(first, logical_index, true));
                logical_index += 1;
            }
            if mbr_entry(&record, 2)?.kind != 0 || mbr_entry(&record, 3)?.kind != 0 {
                return Err(corrupt("EBR", current, "unexpected extra EBR entries"));
            }
            let next = mbr_entry(&record, 1)?;
            if next.kind == 0 {
                break;
            }
            if !extended(next.kind) {
                return Err(corrupt("EBR", current, "invalid chain link type"));
            }
            current = container
                .start_lba
                .checked_add(next.start)
                .ok_or_else(|| corrupt("EBR", current, "link offset overflow"))?;
            check_lbas(current, next.count, end, "EBR")?;
        }
        for part in partitions
            .iter()
            .filter(|p| p.is_logical && p.start_lba >= container.start_lba && p.start_lba < end)
        {
            if visited
                .iter()
                .any(|&lba| lba >= part.start_lba && lba < part.start_lba + part.sectors)
            {
                return Err(corrupt(
                    "EBR",
                    part.start_lba,
                    "logical data overlaps an EBR",
                ));
            }
        }
    }
    let data: Vec<_> = partitions.iter().filter(|p| !p.is_container).collect();
    for (index, a) in data.iter().enumerate() {
        if data[index + 1..].iter().any(|b| overlaps(a, b)) {
            return Err(corrupt("MBR", a.start_lba, "overlapping data partitions"));
        }
    }
    Ok(PartitionTable {
        scheme: Scheme::Mbr,
        sector_size: image.sector_size(),
        disk_guid: None,
        partitions,
    })
}

#[derive(PartialEq, Eq)]
struct Gpt {
    alternate: u64,
    first: u64,
    last: u64,
    guid: [u8; 16],
    count: u32,
    entry_size: u32,
    entries: Vec<u8>,
}
fn crc(data: &[u8], stored: u32, offset: u64, context: &'static str) -> Result<()> {
    let calculated = crc32fast::hash(data);
    if stored != calculated {
        return Err(Error::Checksum {
            context,
            offset,
            stored,
            calculated,
        });
    }
    Ok(())
}
fn gpt_header(image: &mut dyn DiskImage, lba: u64, backup: bool) -> Result<Gpt> {
    let sector = u64::from(image.sector_size());
    let total = image.len() / sector;
    let mut header = read_vec(image, lba * sector, sector as usize)?;
    if &header[..8] != b"EFI PART" {
        return Err(corrupt("GPT", lba * sector, "missing GPT signature"));
    }
    if u32le(&header, 8)? != 0x10000 || u32le(&header, 20)? != 0 {
        return Err(corrupt(
            "GPT",
            lba * sector,
            "unsupported revision or nonzero reserved field",
        ));
    }
    let size = u32le(&header, 12)? as usize;
    if !(92..=sector as usize).contains(&size) {
        return Err(corrupt("GPT", lba * sector, "invalid header size"));
    }
    let stored = u32le(&header, 16)?;
    header[16..20].fill(0);
    crc(&header[..size], stored, lba * sector, "GPT header CRC32")?;
    let alternate = u64le(&header, 32)?;
    if u64le(&header, 24)? != lba || alternate != if backup { 1 } else { total - 1 } {
        return Err(corrupt(
            "GPT",
            lba * sector,
            "invalid primary/backup header locations",
        ));
    }
    let first = u64le(&header, 40)?;
    let last = u64le(&header, 48)?;
    if first < 2 || first > last || last >= total - 1 {
        return Err(corrupt("GPT", lba * sector, "invalid usable LBA range"));
    }
    let array_lba = u64le(&header, 72)?;
    let count = u32le(&header, 80)?;
    let entry_size = u32le(&header, 84)?;
    if count == 0 || count as usize > MAX_PARTITIONS {
        return Err(Error::ResourceLimit("GPT partition entries"));
    }
    if entry_size < 128 || !entry_size.is_power_of_two() || entry_size > 4096 {
        return Err(corrupt("GPT", lba * sector, "invalid entry size"));
    }
    let array_size = u64::from(count) * u64::from(entry_size);
    if array_size > MAX_GPT_BYTES {
        return Err(Error::ResourceLimit("GPT entry array size"));
    }
    let array_offset = array_lba
        .checked_mul(sector)
        .ok_or_else(|| corrupt("GPT", array_lba, "array byte offset overflow"))?;
    checked_region(array_offset, array_size, image.len(), "GPT entry array")?;
    let array_end = array_lba
        .checked_add(array_size.div_ceil(sector))
        .ok_or_else(|| corrupt("GPT", array_lba, "array offset overflow"))?;
    if (!backup && (array_lba <= 1 || array_end > first))
        || (backup && (array_lba <= last || array_end > lba))
    {
        return Err(corrupt(
            "GPT",
            array_offset,
            "partition entry array overlaps usable space or header",
        ));
    }
    let entries = read_vec(image, array_offset, array_size as usize)?;
    crc(
        &entries,
        u32le(&header, 88)?,
        array_offset,
        "GPT entry array CRC32",
    )?;
    let guid = bytes(&header, 56, 16)?.try_into().unwrap();
    if guid == [0; 16] {
        return Err(corrupt("GPT", lba * sector, "zero disk GUID"));
    }
    Ok(Gpt {
        alternate,
        first,
        last,
        guid,
        count,
        entry_size,
        entries,
    })
}
fn read_gpt(image: &mut dyn DiskImage) -> Result<PartitionTable> {
    let primary = gpt_header(image, 1, false)?;
    let mut backup = gpt_header(image, primary.alternate, true)?;
    backup.alternate = primary.alternate;
    if primary != backup {
        return Err(corrupt("GPT", 0, "primary and backup GPT disagree"));
    }
    let mut partitions = Vec::new();
    let mut identifiers = HashSet::new();
    for (slot, entry) in primary
        .entries
        .chunks_exact(primary.entry_size as usize)
        .enumerate()
    {
        let kind: [u8; 16] = entry[..16].try_into().unwrap();
        if kind == [0; 16] {
            continue;
        }
        let unique: [u8; 16] = entry[16..32].try_into().unwrap();
        if unique == [0; 16] || !identifiers.insert(unique) {
            return Err(corrupt(
                "GPT",
                slot as u64,
                "zero or duplicate partition GUID",
            ));
        }
        let start = u64le(entry, 32)?;
        let end = u64le(entry, 40)?;
        if start < primary.first || end > primary.last || start > end {
            return Err(corrupt("GPT", start, "partition outside usable LBA range"));
        }
        let name_end = entry[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .position(|x| *x == [0, 0])
            .unwrap_or(36);
        let name = utf16(&entry[56..56 + name_end * 2])?;
        partitions.push(Partition {
            index: slot as u32 + 1,
            start_lba: start,
            sectors: end - start + 1,
            partition_type: PartitionType::Gpt(kind),
            name,
            unique_id: Some(unique),
            attributes: u64le(entry, 48)?,
            bootable: false,
            is_container: false,
            is_logical: false,
        });
    }
    let mut ranges: Vec<_> = partitions.iter().collect();
    ranges.sort_by_key(|p| p.start_lba);
    for pair in ranges.windows(2) {
        if overlaps(pair[0], pair[1]) {
            return Err(corrupt("GPT", pair[1].start_lba, "overlapping partitions"));
        }
    }
    Ok(PartitionTable {
        scheme: Scheme::Gpt,
        sector_size: image.sector_size(),
        disk_guid: Some(primary.guid),
        partitions,
    })
}

/// Format a GPT GUID using its mixed-endian on-disk representation.
pub fn guid(bytes: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8],
        bytes[9],
        crate::ewf::hex(&bytes[10..])
    )
}
