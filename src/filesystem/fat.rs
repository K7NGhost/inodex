//! FAT12/16/32 allocation chains, short names and VFAT long filenames.
use super::{DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, TimeBasis, Times, Timestamp};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{HashMap, HashSet};

// Only one directory is indexed per handle. The index accounts for names and
// hash-table overhead against max_metadata_bytes; larger directories use scans.
type NameIndex = HashMap<String, Option<u64>>;

pub struct Fat<'a> {
    image: &'a mut dyn DiskImage,
    info: FsInfo,
    limits: Limits,
    fat_offset: u64,
    fat_size: u64,
    data_offset: u64,
    root_offset: u64,
    root_entries: usize,
    root_cluster: u32,
    clusters: u32,
    cluster_size: u64,
    cached_chain: Option<(u32, Vec<u32>)>,
    cached_directory: Option<(u64, NameIndex)>,
}
impl<'a> Fat<'a> {
    pub fn open(image: &'a mut dyn DiskImage, limits: Limits) -> Result<Self> {
        let boot = read_vec(image, 0, 512)?;
        if boot[510..] != [0x55, 0xaa] || (boot[0] != 0xeb && boot[0] != 0xe9) {
            return Err(corrupt("FAT", 0, "invalid boot record"));
        }
        let sector = u64::from(u16le(&boot, 11)?);
        let spc = u64::from(boot[13]);
        let reserved = u64::from(u16le(&boot, 14)?);
        let fats = u64::from(boot[16]);
        if !sector.is_power_of_two()
            || !(512..=4096).contains(&sector)
            || !spc.is_power_of_two()
            || spc > 128
            || reserved == 0
            || !(1..=4).contains(&fats)
        {
            return Err(corrupt("FAT", 11, "invalid BIOS parameter block geometry"));
        }
        let small_total = u64::from(u16le(&boot, 19)?);
        let big_total = u64::from(u32le(&boot, 32)?);
        let total = if small_total != 0 {
            small_total
        } else {
            big_total
        };
        if total == 0 || (small_total != 0 && big_total != 0 && small_total != big_total) {
            return Err(corrupt("FAT", 19, "invalid sector count"));
        }
        checked_region(0, total * sector, image.len(), "FAT")?;
        let small_fat = u16le(&boot, 22)?;
        let sectors_per_fat = if small_fat != 0 {
            u64::from(small_fat)
        } else {
            u64::from(u32le(&boot, 36)?)
        };
        let root_entries = u16le(&boot, 17)? as usize;
        let root_sectors = (root_entries as u64 * 32).div_ceil(sector);
        let overhead = reserved + fats * sectors_per_fat + root_sectors;
        if sectors_per_fat == 0 || overhead >= total {
            return Err(corrupt("FAT", 22, "FAT/root area exceeds volume"));
        }
        let clusters = (total - overhead) / spc;
        let (filesystem, bits) = if clusters < 4085 {
            (FsType::Fat12, 12)
        } else if clusters < 65525 {
            (FsType::Fat16, 16)
        } else {
            (FsType::Fat32, 32)
        };
        if clusters > 0x0fff_ffed {
            return Err(corrupt("FAT", 0, "too many FAT clusters"));
        }
        if (filesystem == FsType::Fat32
            && (small_fat != 0 || root_entries != 0 || u16le(&boot, 42)? != 0))
            || (filesystem != FsType::Fat32 && (small_fat == 0 || root_entries == 0))
        {
            return Err(corrupt("FAT", 17, "FAT variant and root geometry disagree"));
        }
        let fat_size = sectors_per_fat * sector;
        if fat_size * 8 / bits < clusters + 2 {
            return Err(corrupt(
                "FAT",
                22,
                "allocation table cannot address all clusters",
            ));
        }
        let active = if filesystem == FsType::Fat32 {
            let flags = u16le(&boot, 40)?;
            if flags & 0x80 != 0 {
                u64::from(flags & 0xf)
            } else {
                0
            }
        } else {
            0
        };
        if active >= fats {
            return Err(corrupt(
                "FAT",
                40,
                "active FAT index exceeds number of FATs",
            ));
        }
        let root_cluster = if filesystem == FsType::Fat32 {
            u32le(&boot, 44)? & 0x0fff_ffff
        } else {
            0
        };
        if filesystem == FsType::Fat32
            && (root_cluster < 2 || u64::from(root_cluster) >= clusters + 2)
        {
            return Err(corrupt("FAT", 44, "invalid root directory cluster"));
        }
        let label_offset = if filesystem == FsType::Fat32 { 71 } else { 43 };
        let label = oem(&boot[label_offset..label_offset + 11])
            .trim_end()
            .to_owned();
        let fat_offset = (reserved + active * sectors_per_fat) * sector;
        let header = read_vec(image, fat_offset, 4)?;
        if header[0] != boot[21] || boot[21] < 0xf0 {
            return Err(corrupt("FAT", fat_offset, "FAT media descriptor mismatch"));
        }
        Ok(Self {
            image,
            info: FsInfo {
                filesystem,
                label,
                block_size: (sector * spc) as u32,
                total_bytes: total * sector,
                root_id: 0,
                needs_journal_recovery: false,
            },
            limits,
            fat_offset,
            fat_size,
            data_offset: overhead * sector,
            root_offset: (reserved + fats * sectors_per_fat) * sector,
            root_entries,
            root_cluster,
            clusters: clusters as u32,
            cluster_size: sector * spc,
            cached_chain: None,
            cached_directory: None,
        })
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < 2 || cluster - 2 >= self.clusters {
            return Err(corrupt(
                "FAT chain",
                u64::from(cluster),
                "cluster outside data area",
            ));
        }
        Ok(self.data_offset + u64::from(cluster - 2) * self.cluster_size)
    }
    fn next(&mut self, cluster: u32) -> Result<Option<u32>> {
        self.cluster_offset(cluster)?;
        let (offset, size) = match self.info.filesystem {
            FsType::Fat12 => (u64::from(cluster) + u64::from(cluster) / 2, 2),
            FsType::Fat16 => (u64::from(cluster) * 2, 2),
            _ => (u64::from(cluster) * 4, 4),
        };
        checked_region(offset, size as u64, self.fat_size, "FAT entry")?;
        let value = read_vec(self.image, self.fat_offset + offset, size)?;
        let (next, reserved, bad, eoc) = match self.info.filesystem {
            FsType::Fat12 => {
                let value = u32::from(u16le(&value, 0)?);
                (
                    if cluster & 1 != 0 {
                        value >> 4
                    } else {
                        value & 0xfff
                    },
                    0xff0,
                    0xff7,
                    0xff8,
                )
            }
            FsType::Fat16 => (u32::from(u16le(&value, 0)?), 0xfff0, 0xfff7, 0xfff8),
            _ => (
                u32le(&value, 0)? & 0x0fff_ffff,
                0x0fff_fff0,
                0x0fff_fff7,
                0x0fff_fff8,
            ),
        };
        if next >= eoc {
            return Ok(None);
        }
        if next < 2 || next >= reserved || next == bad {
            return Err(corrupt(
                "FAT chain",
                u64::from(cluster),
                "free, reserved or bad cluster in live chain",
            ));
        }
        self.cluster_offset(next)?;
        Ok(Some(next))
    }
    fn chain(&mut self, first: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = Some(first);
        while let Some(cluster) = current {
            if chain.len() >= self.limits.max_chain_length {
                return Err(Error::ResourceLimit("FAT chain length"));
            }
            if !visited.insert(cluster) {
                return Err(corrupt(
                    "FAT chain",
                    u64::from(cluster),
                    "cycle in allocation chain",
                ));
            }
            self.cluster_offset(cluster)?;
            chain.push(cluster);
            current = self.next(cluster)?;
        }
        Ok(chain)
    }
    fn record(&mut self, id: u64) -> Result<Vec<u8>> {
        if id == 0 {
            return Err(corrupt(
                "FAT directory",
                0,
                "root has no physical directory entry",
            ));
        }
        let offset = id - 1;
        if !offset.is_multiple_of(32) || offset < self.root_offset {
            return Err(corrupt("FAT directory", offset, "invalid entry identifier"));
        }
        checked_region(offset, 32, self.info.total_bytes, "FAT directory")?;
        if offset < self.data_offset && offset >= self.root_offset + self.root_entries as u64 * 32 {
            return Err(corrupt("FAT directory", offset, "entry is in root padding"));
        }
        let entry = read_vec(self.image, offset, 32)?;
        if entry[0] == 0 || entry[11] & 8 != 0 || entry[11] & 0xc0 != 0 {
            return Err(corrupt(
                "FAT directory",
                offset,
                "not a file directory entry",
            ));
        }
        Ok(entry)
    }
    fn first_cluster(&self, entry: &[u8]) -> Result<u32> {
        let lo = u32::from(u16le(entry, 26)?);
        Ok(if self.info.filesystem == FsType::Fat32 {
            (u32::from(u16le(entry, 20)?) << 16 | lo) & 0x0fff_ffff
        } else {
            lo
        })
    }
    pub fn metadata(&mut self, id: u64) -> Result<Metadata> {
        if id == 0 {
            return Ok(Metadata {
                id,
                kind: FileKind::Directory,
                size: 0,
                allocated: true,
                links: 1,
                mode: None,
                uid: None,
                gid: None,
                sequence: None,
                times: Times::default(),
                streams: Vec::new(),
            });
        }
        let entry = self.record(id)?;
        let kind = if entry[11] & 0x10 != 0 {
            FileKind::Directory
        } else {
            FileKind::File
        };
        let times = Times {
            created: dos_time(u16le(&entry, 16)?, u16le(&entry, 14)?, entry[13]),
            modified: dos_time(u16le(&entry, 24)?, u16le(&entry, 22)?, 0),
            accessed: dos_time(u16le(&entry, 18)?, 0, 0),
            changed: None,
        };
        let size = if kind == FileKind::Directory && entry[0] != 0xe5 {
            let first = self.first_cluster(&entry)?;
            self.chain(first)?.len() as u64 * self.cluster_size
        } else {
            u64::from(u32le(&entry, 28)?)
        };
        Ok(Metadata {
            id,
            kind,
            size,
            allocated: entry[0] != 0xe5,
            links: 1,
            mode: None,
            uid: None,
            gid: None,
            sequence: None,
            times,
            streams: Vec::new(),
        })
    }
    pub(super) fn lookup(&mut self, id: u64, name: &str) -> Result<Option<u64>> {
        let key = name.to_ascii_lowercase();
        if let Some((cached, names)) = &self.cached_directory {
            if *cached == id {
                return match names.get(&key) {
                    Some(Some(found)) => Ok(Some(*found)),
                    Some(None) => Err(corrupt("directory", id, "ambiguous filename")),
                    None => Ok(None),
                };
            }
        }
        let entries = self.read_dir(id)?;
        let accounted = entries
            .iter()
            .flat_map(|e| std::iter::once(&e.name).chain(e.aliases.iter()))
            .fold(0usize, |total, n| {
                total.saturating_add(n.len().saturating_add(128))
            });
        if accounted > self.limits.max_metadata_bytes {
            let mut found = None;
            for entry in entries {
                if entry.name.eq_ignore_ascii_case(name)
                    || entry
                        .aliases
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(name))
                {
                    if found.is_some_and(|old| old != entry.id) {
                        return Err(corrupt("directory", id, "ambiguous filename"));
                    }
                    found = Some(entry.id);
                }
            }
            return Ok(found);
        }
        let mut names = HashMap::new();
        for entry in entries {
            for name in std::iter::once(entry.name).chain(entry.aliases) {
                let slot = names
                    .entry(name.to_ascii_lowercase())
                    .or_insert(Some(entry.id));
                if *slot != Some(entry.id) {
                    *slot = None; // Preserve alias/name ambiguity rather than choosing a file.
                }
            }
        }
        let result = match names.get(&key) {
            Some(Some(found)) => Ok(Some(*found)),
            Some(None) => Err(corrupt("directory", id, "ambiguous filename")),
            None => Ok(None),
        };
        self.cached_directory = Some((id, names));
        result
    }
    pub fn read_dir(&mut self, id: u64) -> Result<Vec<DirEntry>> {
        let metadata = self.metadata(id)?;
        if metadata.kind != FileKind::Directory {
            return Err(Error::NotDirectory(id.to_string()));
        }
        if !metadata.allocated {
            return Err(Error::Unsupported("deleted FAT directories".into()));
        }
        let mut locations = Vec::new();
        if id == 0 && self.info.filesystem != FsType::Fat32 {
            if self.root_entries as u64 * 32 > self.limits.max_directory_bytes {
                return Err(Error::ResourceLimit("FAT root directory size"));
            }
            locations.push((self.root_offset, self.root_entries * 32));
        } else {
            let first = if id == 0 {
                self.root_cluster
            } else {
                let entry = self.record(id)?;
                self.first_cluster(&entry)?
            };
            let chain = self.chain(first)?;
            if chain.len() as u64 * self.cluster_size > self.limits.max_directory_bytes {
                return Err(Error::ResourceLimit("FAT directory size"));
            }
            for cluster in chain {
                locations.push((self.cluster_offset(cluster)?, self.cluster_size as usize));
            }
        }
        let mut entries = Vec::new();
        let mut long = LongName::default();
        let mut names = HashSet::new();
        for (location, size) in locations {
            let data = read_vec(self.image, location, size)?;
            for (slot, entry) in data.as_chunks::<32>().0.iter().enumerate() {
                if entry[0] == 0 {
                    return Ok(entries);
                }
                if entry[0] == 0xe5 {
                    long = LongName::default();
                    continue;
                }
                if entry[11] == 0x0f {
                    long.add(entry);
                    continue;
                }
                if entry[11] & 8 != 0 {
                    long = LongName::default();
                    continue;
                }
                if entry[11] & 0xc0 != 0 {
                    return Err(corrupt(
                        "FAT directory",
                        location,
                        "reserved entry attribute bits",
                    ));
                }
                let short = short_name(entry);
                let name = long.finish(entry).unwrap_or_else(|| short.clone());
                if name == "." || name == ".." {
                    continue;
                }
                if name.is_empty() || name.contains(['\0', '/']) {
                    return Err(corrupt("FAT directory", location, "invalid filename"));
                }
                if !names.insert(name.to_ascii_lowercase()) {
                    return Err(corrupt(
                        "FAT directory",
                        location,
                        "duplicate directory name",
                    ));
                }
                if entries.len() >= self.limits.max_directory_entries {
                    return Err(Error::ResourceLimit("FAT directory entries"));
                }
                let id = location + slot as u64 * 32 + 1;
                let size = if entry[11] & 0x10 != 0 {
                    self.metadata(id)?.size
                } else {
                    u64::from(u32le(entry, 28)?)
                };
                entries.push(DirEntry {
                    id,
                    aliases: if name == short {
                        Vec::new()
                    } else {
                        vec![short]
                    },
                    name,
                    kind: if entry[11] & 0x10 != 0 {
                        FileKind::Directory
                    } else {
                        FileKind::File
                    },
                    size,
                    allocated: true,
                    raw_name: None,
                });
            }
        }
        Ok(entries)
    }
    pub fn read_file(&mut self, id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let metadata = self.metadata(id)?;
        if metadata.kind != FileKind::File {
            return Err(Error::Unsupported("FAT directory read as a file".into()));
        }
        if !metadata.allocated {
            return Err(Error::Unsupported("deleted FAT file recovery".into()));
        }
        let count = metadata
            .size
            .saturating_sub(offset)
            .min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        let record = self.record(id)?;
        let first = self.first_cluster(&record)?;
        if self
            .cached_chain
            .as_ref()
            .is_none_or(|(cached, _)| *cached != first)
        {
            let chain = self.chain(first)?;
            if (chain.len() as u64) * self.cluster_size < metadata.size {
                return Err(corrupt(
                    "FAT file",
                    id,
                    "allocation chain is shorter than file size",
                ));
            }
            self.cached_chain = Some((first, chain));
        }
        let mut done = 0;
        while done < count {
            let position = offset + done as u64;
            let index = (position / self.cluster_size) as usize;
            let within = position % self.cluster_size;
            let cluster = *self
                .cached_chain
                .as_ref()
                .unwrap()
                .1
                .get(index)
                .ok_or_else(|| corrupt("FAT file", id, "truncated cluster chain"))?;
            let size = (self.cluster_size - within).min((count - done) as u64) as usize;
            let physical = self.cluster_offset(cluster)? + within;
            self.image
                .read_exact_at(physical, &mut buffer[done..done + size])?;
            done += size;
        }
        Ok(count)
    }
}

#[derive(Default)]
struct LongName {
    units: Vec<u16>,
    next: u8,
    checksum: u8,
    valid: bool,
}
impl LongName {
    fn add(&mut self, entry: &[u8; 32]) {
        let ordinal = entry[0] & 0x1f;
        if entry[0] & 0x40 != 0 {
            *self = Self {
                units: vec![0xffff; ordinal as usize * 13],
                next: ordinal,
                checksum: entry[13],
                valid: (1..=20).contains(&ordinal),
            };
        }
        if !self.valid
            || ordinal == 0
            || ordinal != self.next
            || entry[13] != self.checksum
            || entry[12] != 0
            || entry[26..28] != [0, 0]
            || entry[0] & 0xa0 != 0
        {
            self.valid = false;
            return;
        }
        for (index, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            self.units[(ordinal as usize - 1) * 13 + index] =
                u16::from_le_bytes([entry[offset], entry[offset + 1]]);
        }
        self.next -= 1;
    }
    fn finish(&mut self, short: &[u8]) -> Option<String> {
        let old = std::mem::take(self);
        let checksum = short[..11]
            .iter()
            .fold(0_u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte));
        if !old.valid || old.next != 0 || checksum != old.checksum {
            return None;
        }
        let length = old
            .units
            .iter()
            .position(|&u| u == 0)
            .unwrap_or(old.units.len());
        if length > 255
            || old.units[..length].contains(&0xffff)
            || old.units[length..].iter().any(|&u| u != 0 && u != 0xffff)
        {
            return None;
        }
        String::from_utf16(&old.units[..length]).ok()
    }
}
fn short_name(entry: &[u8]) -> String {
    let mut base = entry[..8].to_vec();
    if base[0] == 5 {
        base[0] = 0xe5;
    }
    let mut base = oem(&base).trim_end().to_owned();
    let mut extension = oem(&entry[8..11]).trim_end().to_owned();
    if entry[12] & 8 != 0 {
        base.make_ascii_lowercase();
    }
    if entry[12] & 16 != 0 {
        extension.make_ascii_lowercase();
    }
    if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    }
}
fn oem(bytes: &[u8]) -> String {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";
    bytes
        .iter()
        .map(|&b| {
            if b < 128 {
                char::from(b)
            } else {
                HIGH.chars().nth((b - 128) as usize).unwrap()
            }
        })
        .collect()
}
// FAT wall-clock timestamps have no time zone. Return their civil value as
// seconds from 1970 with no timezone conversion; callers must retain that fact.
pub(super) fn dos_time(date: u16, time: u16, hundredths: u8) -> Option<Timestamp> {
    if date == 0 || hundredths > 199 {
        return None;
    }
    let year = i64::from(1980 + (date >> 9));
    let month = ((date >> 5) & 15) as usize;
    let day = i64::from(date & 31);
    let hour = i64::from(time >> 11);
    let minute = i64::from((time >> 5) & 63);
    let second = i64::from(time & 31) * 2 + i64::from(hundredths / 100);
    let leap = |year: i64| year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > lengths[month - 1]
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return None;
    }
    let mut days = 0;
    for year in 1970..year {
        days += if leap(year) { 366 } else { 365 };
    }
    days += lengths[..month - 1].iter().sum::<i64>() + day - 1;
    Some(Timestamp {
        seconds: days * 86400 + hour * 3600 + minute * 60 + second,
        nanos: u32::from(hundredths % 100) * 10_000_000,
        basis: TimeBasis::LocalCivil,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_zero_long_name_ordinal_is_discarded() {
        let mut name = LongName {
            units: vec![0; 13],
            next: 0,
            checksum: 0,
            valid: true,
        };
        let mut entry = [0; 32];
        entry[11] = 0x0f;
        name.add(&entry);
        assert!(!name.valid);
    }
    #[test]
    fn oem_names_use_cp437_instead_of_latin1() {
        assert_eq!(oem(&[0x80, 0x82, 0xe0, 0xff]), "Çéα ");
    }
    #[test]
    fn fat_dates_retain_civil_time_and_validate_leap_days() {
        let date = (44 << 9) | (2 << 5) | 29;
        let time = (2 << 11) | (4 << 5) | 3;
        assert_eq!(
            dos_time(date, time, 123),
            Some(Timestamp {
                seconds: 1709172247,
                nanos: 230_000_000,
                basis: TimeBasis::LocalCivil
            })
        );
        assert!(dos_time((43 << 9) | (2 << 5) | 29, 0, 0).is_none());
    }
}
