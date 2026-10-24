//! Fixed, dynamic and differencing VHD with bitmap-based parent inheritance.
use super::{DiskImage, common::*};
use crate::{Error, Result, wire::*};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};
#[derive(Debug)]
pub struct VhdImage {
    source: Source,
    size: u64,
    kind: u32,
    uuid: [u8; 16],
    block: u64,
    bitmap_size: u64,
    bat: Vec<u32>,
    parent: Option<Box<VhdImage>>,
    bitmap: Option<(usize, Vec<u8>)>,
}
fn check(d: &[u8], field: usize) -> Result<()> {
    let sum = d
        .iter()
        .enumerate()
        .filter(|(i, _)| !(*i >= field && *i < field + 4))
        .fold(0u32, |s, (_, b)| s.wrapping_add(u32::from(*b)));
    if u32be(d, field)? != !sum {
        return Err(bad("VHD", "checksum mismatch"));
    }
    Ok(())
}
fn text(d: &[u8], little: bool) -> Result<String> {
    if !d.len().is_multiple_of(2) {
        return Err(bad("VHD", "odd parent name size"));
    }
    let units: Vec<_> = d
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| {
            if little {
                u16::from_le_bytes(*v)
            } else {
                u16::from_be_bytes(*v)
            }
        })
        .take_while(|v| *v != 0)
        .collect();
    String::from_utf16(&units).map_err(|_| bad("VHD", "invalid parent-name UTF-16"))
}
impl VhdImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_limits(path, Limits::default())
    }
    pub fn with_limits(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        Self::inner(path.as_ref(), None, &limits, &mut HashSet::new())
    }
    pub fn with_parent(path: impl AsRef<Path>, parent: impl AsRef<Path>) -> Result<Self> {
        Self::inner(
            path.as_ref(),
            Some(parent.as_ref()),
            &Limits::default(),
            &mut HashSet::new(),
        )
    }
    fn inner(
        path: &Path,
        explicit: Option<&Path>,
        limits: &Limits,
        seen: &mut HashSet<PathBuf>,
    ) -> Result<Self> {
        if seen.len() >= limits.max_parent_depth {
            return Err(Error::ResourceLimit("VHD parent depth"));
        }
        if !seen.insert(path.canonicalize()?) {
            return Err(bad("VHD", "parent chain cycle"));
        }
        let mut source = Source::open(path)?;
        if source.len < 512 || !source.len.is_multiple_of(512) {
            return Err(bad("VHD", "truncated/alignment-invalid footer"));
        }
        let footer = source.read(source.len - 512, 512)?;
        if &footer[..8] != b"conectix" || u32be(&footer, 12)? != 0x10000 {
            return Err(bad("VHD", "footer signature/version"));
        }
        check(&footer, 64)?;
        let size = u64be(&footer, 48)?;
        let kind = u32be(&footer, 60)?;
        let uuid = bytes(&footer, 68, 16)?.try_into().unwrap();
        if size == 0 || !size.is_multiple_of(512) || ![2, 3, 4].contains(&kind) {
            return Err(Error::Unsupported("VHD disk type or geometry".into()));
        }
        let mut result = Self {
            source,
            size,
            kind,
            uuid,
            block: 0,
            bitmap_size: 0,
            bat: vec![],
            parent: None,
            bitmap: None,
        };
        if kind == 2 {
            if u64be(&footer, 16)? != u64::MAX
                || result.source.len
                    != size
                        .checked_add(512)
                        .ok_or_else(|| bad("VHD", "size overflow"))?
            {
                return Err(bad("VHD", "fixed image size/offset"));
            }
            return Ok(result);
        }
        let leading = result.source.read(0, 512)?;
        if &leading[..8] != b"conectix" {
            return Err(bad("VHD", "missing leading footer"));
        }
        check(&leading, 64)?;
        if leading[48..84] != footer[48..84] || leading[16..24] != footer[16..24] {
            return Err(bad("VHD", "footer copies disagree"));
        }
        let header_at = u64be(&footer, 16)?;
        checked_region(header_at, 1024, result.source.len - 512, "VHD header")?;
        let h = result.source.read(header_at, 1024)?;
        if &h[..8] != b"cxsparse" || u64be(&h, 8)? != u64::MAX || u32be(&h, 24)? != 0x10000 {
            return Err(bad("VHD", "dynamic header signature/version"));
        }
        check(&h, 36)?;
        result.block = u64::from(u32be(&h, 32)?);
        if !result.block.is_power_of_two()
            || result.block < 512
            || result.block > limits.max_decoded_block as u64
        {
            return Err(bad("VHD", "block size"));
        }
        result.bitmap_size = (result.block / 512).div_ceil(8).div_ceil(512) * 512;
        let entries = u32be(&h, 28)? as usize;
        if entries > limits.max_metadata_bytes / 4 || (entries as u64) < size.div_ceil(result.block)
        {
            return Err(Error::ResourceLimit("VHD BAT entries"));
        }
        let table = u64be(&h, 16)?;
        if !table.is_multiple_of(512) {
            return Err(bad("VHD", "BAT alignment"));
        }
        checked_region(
            table,
            entries as u64 * 4,
            result.source.len - 512,
            "VHD BAT",
        )?;
        let d = result.source.read(table, entries * 4)?;
        result.bat = d
            .as_chunks::<4>()
            .0
            .iter()
            .map(|v| u32::from_be_bytes(*v))
            .collect();
        let mut reserved = vec![
            (0, 512),
            (header_at, header_at + 1024),
            (table, table + (entries as u64 * 4).div_ceil(512) * 512),
        ];
        let mut candidates = vec![];
        for i in 0..8 {
            let loc = &h[576 + i * 24..600 + i * 24];
            let len = u32be(loc, 8)? as usize;
            if len == 0 {
                continue;
            }
            if len > limits.max_metadata_bytes {
                return Err(Error::ResourceLimit("VHD parent locator"));
            }
            let at = u64be(loc, 16)?;
            checked_region(
                at,
                len as u64,
                result.source.len - 512,
                "VHD parent locator",
            )?;
            reserved.push((at, at + len as u64));
            if &loc[..4] == b"W2ru" || &loc[..4] == b"W2ku" {
                let raw = result.source.read(at, len)?;
                let name = text(&raw, true)?;
                if let Ok(p) = companion(path, &name) {
                    candidates.push(p);
                }
            }
        }
        for &entry in &result.bat {
            if entry != u32::MAX {
                let at = sector(u64::from(entry))?;
                let length = result.bitmap_size + result.block;
                checked_region(at, length, result.source.len - 512, "VHD block")?;
                reserved.push((at, at + length));
            }
        }
        reserved.sort_unstable();
        for pair in reserved.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(bad("VHD", "overlapping blocks/metadata"));
            }
        }
        if kind == 4 {
            let name = text(&h[64..576], false)?;
            if let Ok(p) = companion(path, &name) {
                candidates.push(p);
            }
            if let Some(base) = name.replace('\\', "/").rsplit('/').next()
                && let Ok(p) = companion(path, base)
            {
                candidates.push(p);
            }
            let parent_path = if let Some(p) = explicit {
                p.to_path_buf()
            } else {
                candidates
                    .into_iter()
                    .find(|p| p.is_file())
                    .ok_or_else(|| Error::NotFound(format!("VHD parent {name}")))?
            };
            let parent = Self::inner(&parent_path, None, limits, seen)?;
            if parent.uuid != h[40..56] || parent.size != size {
                return Err(bad("VHD", "parent UUID/virtual size mismatch"));
            }
            result.parent = Some(Box::new(parent));
        }
        Ok(result)
    }
    pub fn disk_type(&self) -> u32 {
        self.kind
    }
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }
}
impl DiskImage for VhdImage {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let n = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        if self.kind == 2 {
            self.source.exact(offset.min(self.size), &mut buffer[..n])?;
            return Ok(n);
        }
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let index = (at / self.block) as usize;
            let within = at % self.block;
            let bit = (within / 512) as usize;
            let count = (n - done).min((512 - within % 512) as usize);
            let entry = self.bat[index];
            let mut present = false;
            if entry != u32::MAX {
                if self.bitmap.as_ref().is_none_or(|(i, _)| *i != index) {
                    self.bitmap = Some((
                        index,
                        self.source
                            .read(sector(u64::from(entry))?, self.bitmap_size as usize)?,
                    ));
                }
                present = self.bitmap.as_ref().unwrap().1[bit / 8] & (0x80 >> (bit % 8)) != 0;
            }
            let out = &mut buffer[done..done + count];
            if present {
                self.source
                    .exact(sector(u64::from(entry))? + self.bitmap_size + within, out)?;
            } else if let Some(parent) = self.parent.as_mut() {
                parent.read_exact_at(at, out)?;
            } else {
                out.fill(0);
            }
            done += count;
        }
        Ok(n)
    }
}
