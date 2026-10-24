//! Read-only VHDX v1, following Microsoft's MS-VHDX specification.
use super::{DiskImage, Limits, common::*};
use crate::{Error, Result, wire::*};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const MB: u64 = 1024 * 1024;
const BAT: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 8,
];
const META: [u8; 16] = [
    6, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 5, 0x0f, 0x88, 0x6e,
];
fn guid(s: &str) -> Result<[u8; 16]> {
    let s = s.trim_matches(['{', '}']).replace('-', "");
    if s.len() != 32 || !s.is_ascii() {
        return Err(bad("VHDX", "invalid GUID"));
    }
    let mut d = [0; 16];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| bad("VHDX", "invalid GUID"))?;
    }
    d[..4].reverse();
    d[4..6].reverse();
    d[6..8].reverse();
    Ok(d)
}
fn crc(d: &[u8]) -> u32 {
    let mut c = !0u32;
    for (i, &b) in d.iter().enumerate() {
        c ^= if (4..8).contains(&i) { 0 } else { u32::from(b) };
        for _ in 0..8 {
            c = (c >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}
fn check(d: &[u8], sig: &[u8]) -> Result<()> {
    if !d.starts_with(sig) || u32le(d, 4)? != crc(d) {
        return Err(bad("VHDX", "signature or CRC32C mismatch"));
    }
    Ok(())
}
#[derive(Debug)]
pub struct VhdxImage {
    source: Source,
    size: u64,
    sector: u32,
    block: u64,
    ratio: u64,
    bat: Vec<u64>,
    parent: Option<Box<Self>>,
    data_write_id: [u8; 16],
    bitmap_cache: Option<(u64, Vec<u8>)>,
}
impl VhdxImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_limits(path, Limits::default())
    }
    pub fn with_limits(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        Self::load(path.as_ref(), &limits, None, &mut vec![])
    }
    pub fn with_parent(path: impl AsRef<Path>, parent: impl AsRef<Path>) -> Result<Self> {
        Self::load(
            path.as_ref(),
            &Limits::default(),
            Some(parent.as_ref()),
            &mut vec![],
        )
    }
    fn load(
        path: &Path,
        limits: &Limits,
        explicit: Option<&Path>,
        chain: &mut Vec<PathBuf>,
    ) -> Result<Self> {
        let canonical = path.canonicalize()?;
        if chain.contains(&canonical) {
            return Err(bad("VHDX", "parent cycle"));
        }
        if chain.len() >= limits.max_parent_depth {
            return Err(Error::ResourceLimit("VHDX parent depth"));
        }
        chain.push(canonical);
        let mut source = Source::open(path)?;
        if source.read(0, 8)? != b"vhdxfile" {
            return Err(bad("VHDX", "file identifier"));
        }
        let mut headers = vec![];
        for at in [65536, 131072] {
            let d = source.read(at, 4096)?;
            if check(&d, b"head").is_ok() && u16le(&d, 66)? == 1 {
                headers.push(d);
            }
        }
        headers.sort_by_key(|d| u64le(d, 8).unwrap());
        if headers.len() == 2 && headers[0][8..16] == headers[1][8..16] && headers[0] != headers[1]
        {
            return Err(bad("VHDX", "conflicting equal-sequence headers"));
        }
        let h = headers
            .last()
            .ok_or_else(|| bad("VHDX", "no valid header"))?;
        if u16le(h, 64)? != 0 || h[48..64].iter().any(|&b| b != 0) {
            return Err(Error::Unsupported("VHDX active log requires replay".into()));
        }
        let data_write_id = h[32..48].try_into().unwrap();
        let log_at = u64le(h, 72)?;
        let log_len = u64::from(u32le(h, 68)?);
        if log_len < MB || !log_len.is_multiple_of(MB) || log_at < MB || !log_at.is_multiple_of(MB)
        {
            return Err(bad("VHDX", "log geometry"));
        }
        checked_region(log_at, log_len, source.len, "VHDX log")?;
        let mut regions = None;
        for at in [196608, 262144] {
            let d = source.read(at, 65536)?;
            if check(&d, b"regi").is_err() {
                continue;
            }
            let count = u32le(&d, 8)? as usize;
            if count > 2047 || u32le(&d, 12)? != 0 {
                return Err(bad("VHDX", "region count/reserved"));
            }
            let mut table = BTreeMap::new();
            for i in 0..count {
                let e = bytes(&d, 16 + i * 32, 32)?;
                let id: [u8; 16] = e[..16].try_into().unwrap();
                let pos = u64le(e, 16)?;
                let len = u64::from(u32le(e, 24)?);
                let flags = u32le(e, 28)?;
                if pos < MB
                    || !pos.is_multiple_of(MB)
                    || len == 0
                    || !len.is_multiple_of(MB)
                    || flags > 1
                {
                    return Err(bad("VHDX", "region geometry/flags"));
                }
                checked_region(pos, len, source.len, "VHDX region")?;
                if id != BAT && id != META && flags == 1 {
                    return Err(Error::Unsupported("required VHDX region".into()));
                }
                if table.insert(id, (pos, len)).is_some() {
                    return Err(bad("VHDX", "duplicate region"));
                }
            }
            if regions.as_ref().is_some_and(|old| old != &table) {
                return Err(bad("VHDX", "region tables disagree"));
            }
            regions = Some(table);
        }
        let regions = regions.ok_or_else(|| bad("VHDX", "no valid region table"))?;
        let mut occupied = vec![(0, MB), (log_at, log_at + log_len)];
        for &(pos, len) in regions.values() {
            occupied.push((pos, pos + len));
        }
        overlaps(&mut occupied)?;
        let &(meta_at, meta_len) = regions
            .get(&META)
            .ok_or_else(|| bad("VHDX", "missing metadata"))?;
        let table = source.read(meta_at, 65536)?;
        if &table[..8] != b"metadata"
            || u16le(&table, 8)? != 0
            || table[12..32].iter().any(|&b| b != 0)
        {
            return Err(bad("VHDX", "metadata header"));
        }
        let count = u16le(&table, 10)? as usize;
        if count > 2047 {
            return Err(bad("VHDX", "metadata count"));
        }
        let known = [
            "caa16737-fa36-4d43-b3b6-33f0aa44e76b",
            "2fa54224-cd1b-4876-b211-5dbed83bf4b8",
            "8141bf1d-a96f-4709-ba47-f233a8faab5f",
            "cda348c7-445d-4471-9cc9-e9885251c556",
            "beca12ab-b2e6-4523-93ef-c309e000c746",
            "a8d35f2d-b30b-454d-abf7-d3d84834ab0c",
        ]
        .map(|s| guid(s).unwrap());
        let mut items = BTreeMap::new();
        let mut ranges = vec![];
        let mut budget = 65536usize;
        for i in 0..count {
            let e = bytes(&table, 32 + i * 32, 32)?;
            let id: [u8; 16] = e[..16].try_into().unwrap();
            let offset = u64::from(u32le(e, 16)?);
            let len = u32le(e, 20)? as usize;
            let flags = u32le(e, 24)?;
            if offset < 65536 || flags & !7 != 0 || u32le(e, 28)? != 0 {
                return Err(bad("VHDX", "metadata offset/flags"));
            }
            checked_region(offset, len as u64, meta_len, "VHDX metadata item")?;
            ranges.push((offset, offset + len as u64));
            if !known.contains(&id) && flags & 4 != 0 {
                return Err(Error::Unsupported("required VHDX metadata item".into()));
            }
            budget = budget
                .checked_add(len)
                .ok_or(Error::ResourceLimit("VHDX metadata"))?;
            if budget > limits.max_metadata_bytes {
                return Err(Error::ResourceLimit("VHDX metadata"));
            }
            if items
                .insert(id, source.read(meta_at + offset, len)?)
                .is_some()
            {
                return Err(bad("VHDX", "duplicate metadata item"));
            }
        }
        overlaps(&mut ranges)?;
        let item = |n: usize, len: usize| -> Result<&[u8]> {
            let d = items
                .get(&known[n])
                .ok_or_else(|| bad("VHDX", "missing required metadata"))?;
            if d.len() != len {
                return Err(bad("VHDX", "metadata size"));
            }
            Ok(d)
        };
        let params = item(0, 8)?;
        let block = u64::from(u32le(params, 0)?);
        let flags = u32le(params, 4)?;
        let size = u64le(item(1, 8)?, 0)?;
        let sector = u32le(item(2, 4)?, 0)?;
        let physical = u32le(item(3, 4)?, 0)?;
        item(4, 16)?;
        if flags & !3 != 0
            || !block.is_power_of_two()
            || !(MB..=256 * MB).contains(&block)
            || ![512, 4096].contains(&sector)
            || ![512, 4096].contains(&physical)
            || size == 0
            || size > 64 * 1024 * 1024 * MB
            || !size.is_multiple_of(u64::from(sector))
        {
            return Err(bad("VHDX", "virtual geometry"));
        }
        let has_parent = flags & 2 != 0;
        let ratio = (1 << 23) * u64::from(sector) / block;
        let blocks = size.div_ceil(block);
        let entries = if has_parent {
            blocks.div_ceil(ratio) * (ratio + 1)
        } else {
            blocks + (blocks - 1) / ratio
        };
        let bat_bytes = entries
            .checked_mul(8)
            .ok_or(Error::ResourceLimit("VHDX BAT"))?;
        if bat_bytes > limits.max_metadata_bytes.saturating_sub(budget) as u64 {
            return Err(Error::ResourceLimit("VHDX BAT"));
        }
        let &(bat_at, bat_len) = regions
            .get(&BAT)
            .ok_or_else(|| bad("VHDX", "missing BAT"))?;
        checked_region(0, bat_bytes, bat_len, "VHDX BAT")?;
        let raw = source.read(bat_at, bat_bytes as usize)?;
        let bat: Vec<u64> = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|e| u64::from_le_bytes(*e))
            .collect();
        for b in 0..blocks {
            let entry = bat[(b + b / ratio) as usize];
            if entry & 7 == 7 && limits.max_decoded_block < MB as usize {
                return Err(Error::ResourceLimit("VHDX sector bitmap"));
            }
            if entry & 0xffff8 != 0
                || ![0, 1, 2, 3, 6, 7].contains(&(entry & 7))
                || (entry & 7 == 7 && !has_parent)
            {
                return Err(bad("VHDX", "payload BAT state/reserved"));
            }
            if entry & 7 >= 6 {
                let pos = entry & !0xfffff;
                checked_region(pos, block, source.len, "VHDX payload")?;
                occupied.push((pos, pos + block));
            }
        }
        if has_parent {
            for c in 0..blocks.div_ceil(ratio) {
                let entry = bat[(c * (ratio + 1) + ratio) as usize];
                if entry & 0xffff8 != 0 || ![0, 6].contains(&(entry & 7)) {
                    return Err(bad("VHDX", "bitmap BAT state/reserved"));
                }
                let partial = (c * ratio..((c + 1) * ratio).min(blocks))
                    .any(|b| bat[(b + b / ratio) as usize] & 7 == 7);
                if partial && entry & 7 != 6 {
                    return Err(bad("VHDX", "partial payload without bitmap"));
                }
                if entry & 7 == 6 {
                    let pos = entry & !0xfffff;
                    checked_region(pos, MB, source.len, "VHDX bitmap")?;
                    occupied.push((pos, pos + MB));
                }
            }
        }
        overlaps(&mut occupied)?;
        let parent = if has_parent {
            let d = items
                .get(&known[5])
                .ok_or_else(|| bad("VHDX", "missing parent locator"))?;
            if bytes(d, 0, 16)? != guid("b04aefb7-d19e-4a81-b789-25b8e9445913")?
                || u16le(d, 16)? != 0
            {
                return Err(Error::Unsupported("VHDX parent locator type".into()));
            }
            let count = u16le(d, 18)? as usize;
            let mut values = BTreeMap::new();
            for i in 0..count {
                let e = bytes(d, 20 + i * 12, 12)?;
                let k = utf16(bytes(d, u32le(e, 0)? as usize, u16le(e, 8)? as usize)?)?;
                let v = utf16(bytes(d, u32le(e, 4)? as usize, u16le(e, 10)? as usize)?)?;
                if values.insert(k, v).is_some() {
                    return Err(bad("VHDX", "duplicate parent locator key"));
                }
            }
            let id = guid(
                values
                    .get("parent_linkage")
                    .ok_or_else(|| bad("VHDX", "missing parent linkage"))?,
            )?;
            let p = if let Some(p) = explicit {
                p.to_path_buf()
            } else {
                let name = values.get("relative_path").ok_or_else(|| {
                    Error::Unsupported(
                        "VHDX needs a local relative parent or explicit parent".into(),
                    )
                })?;
                companion(path, name)?
            };
            let parent = Self::load(&p, limits, None, chain)?;
            if parent.size != size || parent.sector != sector || parent.data_write_id != id {
                return Err(bad("VHDX", "parent linkage/geometry mismatch"));
            }
            Some(Box::new(parent))
        } else {
            if explicit.is_some() {
                return Err(bad("VHDX", "parent supplied for base image"));
            }
            None
        };
        chain.pop();
        Ok(Self {
            source,
            size,
            sector,
            block,
            ratio,
            bat,
            parent,
            data_write_id,
            bitmap_cache: None,
        })
    }
}
fn overlaps(ranges: &mut [(u64, u64)]) -> Result<()> {
    ranges.sort_unstable();
    if ranges.windows(2).any(|p| p[0].1 > p[1].0) {
        return Err(bad("VHDX", "overlapping allocated regions"));
    }
    Ok(())
}
impl DiskImage for VhdxImage {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let count = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        let mut done = 0;
        while done < count {
            let at = offset + done as u64;
            let b = at / self.block;
            let inside = at % self.block;
            let entry = self.bat[(b + b / self.ratio) as usize];
            let state = entry & 7;
            let mut n = (self.block - inside).min((count - done) as u64) as usize;
            let local = if state == 7 {
                n = n.min((u64::from(self.sector) - at % u64::from(self.sector)) as usize);
                let bit = (b % self.ratio) * self.block / u64::from(self.sector)
                    + inside / u64::from(self.sector);
                let bitmap =
                    self.bat[(b / self.ratio * (self.ratio + 1) + self.ratio) as usize] & !0xfffff;
                if self
                    .bitmap_cache
                    .as_ref()
                    .is_none_or(|(at, _)| *at != bitmap)
                {
                    self.bitmap_cache = Some((bitmap, self.source.read(bitmap, MB as usize)?));
                }
                self.bitmap_cache.as_ref().unwrap().1[(bit / 8) as usize] & (1 << (bit % 8)) != 0
            } else {
                state == 6
            };
            let dst = &mut buffer[done..done + n];
            if local {
                self.source.exact((entry & !0xfffff) + inside, dst)?;
            } else if (state == 0 || state == 3 || state == 7) && self.parent.is_some() {
                self.parent.as_mut().unwrap().read_exact_at(at, dst)?;
            } else {
                dst.fill(0);
            }
            done += n;
        }
        Ok(count)
    }
}
