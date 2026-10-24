use super::{DiskImage, common::*};
use crate::{Error, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Debug)]
struct Part {
    path: PathBuf,
    start: u64,
    len: u64,
}
/// An ordered raw segment set. Only one segment handle is cached.
#[derive(Debug)]
pub struct SplitRawImage {
    parts: Vec<Part>,
    len: u64,
    sector: u32,
    cache: Option<(usize, Source)>,
}
impl SplitRawImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_segments(discover(path.as_ref(), &Limits::default())?, 512)
    }
    pub fn open_segments(
        paths: impl IntoIterator<Item = PathBuf>,
        sector_size: u32,
    ) -> Result<Self> {
        Self::with_limits(paths, sector_size, Limits::default())
    }
    pub fn with_limits(
        paths: impl IntoIterator<Item = PathBuf>,
        sector_size: u32,
        limits: Limits,
    ) -> Result<Self> {
        if !sector_size.is_power_of_two() || !(512..=65536).contains(&sector_size) {
            return Err(bad("split raw", "invalid sector size"));
        }
        let mut parts = vec![];
        let mut len = 0u64;
        let mut seen = std::collections::HashSet::new();
        for path in paths {
            if parts.len() >= limits.max_segments {
                return Err(Error::ResourceLimit("raw segments"));
            }
            let canonical = path.canonicalize()?;
            if !seen.insert(canonical) {
                return Err(bad("split raw", "duplicate segment"));
            }
            let source = Source::open(&path)?;
            if source.len == 0 {
                return Err(bad("split raw", "empty segment"));
            }
            parts.push(Part {
                path,
                start: len,
                len: source.len,
            });
            len = len
                .checked_add(source.len)
                .ok_or_else(|| bad("split raw", "media size overflow"))?;
        }
        if parts.is_empty() {
            return Err(bad("split raw", "no segments"));
        }
        Ok(Self {
            parts,
            len,
            sector: sector_size,
            cache: None,
        })
    }
    pub fn segment_paths(&self) -> Vec<&Path> {
        self.parts.iter().map(|p| p.path.as_path()).collect()
    }
    pub fn set_sector_size(&mut self, n: u32) -> Result<()> {
        if !n.is_power_of_two() || !(512..=65536).contains(&n) {
            return Err(bad("split raw", "invalid sector size"));
        }
        self.sector = n;
        Ok(())
    }
}
pub(super) fn discover(path: &Path, limits: &Limits) -> Result<Vec<PathBuf>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let alphabetic = ext.len() == 2 && ext.bytes().all(|b| b.is_ascii_alphabetic());
    if !alphabetic && (ext.len() < 3 || !ext.bytes().all(|b| b.is_ascii_digit())) {
        return Ok(vec![path.to_path_buf()]);
    }
    let number = |s: &str| -> Result<usize> {
        if alphabetic {
            Ok(s.bytes().fold(0, |n, b| {
                n * 26 + usize::from(b.to_ascii_lowercase() - b'a')
            }))
        } else {
            s.parse()
                .map_err(|_| bad("split raw", "segment number overflow"))
        }
    };
    let first = number(ext)?;
    if first > if alphabetic { 0 } else { 1 } {
        return Err(bad(
            "split raw",
            "open the first .000, .001 or .aa segment, or supply an explicit list",
        ));
    }
    let stem = path
        .file_stem()
        .ok_or_else(|| bad("split raw", "segment filename"))?;
    let mut found = BTreeMap::new();
    for entry in std::fs::read_dir(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )? {
        let p = entry?.path();
        if p.file_stem() != Some(stem) {
            continue;
        }
        let e = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if (alphabetic && e.len() == 2 && e.bytes().all(|b| b.is_ascii_alphabetic()))
            || (!alphabetic && e.len() >= ext.len() && e.bytes().all(|b| b.is_ascii_digit()))
        {
            let number = number(e)?;
            if found.len() >= limits.max_segments {
                return Err(Error::ResourceLimit("raw segments"));
            }
            if found.insert(number, p).is_some() {
                return Err(bad("split raw", "ambiguous segment number"));
            }
        }
    }
    let mut out = vec![];
    for (expected, (n, p)) in (first..).zip(found) {
        if n != expected {
            return Err(bad("split raw", format!("missing segment {expected}")));
        }
        out.push(p);
    }
    if out.is_empty() {
        return Err(bad("split raw", "no segments found"));
    }
    Ok(out)
}
impl DiskImage for SplitRawImage {
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let n = self.len.saturating_sub(offset).min(buffer.len() as u64) as usize;
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let index = self.parts.partition_point(|p| p.start <= at) - 1;
            let p = &self.parts[index];
            let within = at - p.start;
            let count = (n - done).min((p.len - within) as usize);
            if self.cache.as_ref().is_none_or(|(i, _)| *i != index) {
                let source = Source::open(&p.path)?;
                if source.len != p.len {
                    return Err(bad("split raw", "segment size changed"));
                }
                self.cache = Some((index, source));
            }
            self.cache
                .as_mut()
                .unwrap()
                .1
                .exact(within, &mut buffer[done..done + count])?;
            done += count;
        }
        Ok(n)
    }
}
