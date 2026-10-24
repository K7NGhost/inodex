//! Descriptor, flat/split sparse and stream-optimized VMDK readers.
use super::{DiskImage, common::*};
use crate::{Error, Result, wire::*};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::{Path, PathBuf},
};
#[derive(Debug)]
struct Sparse {
    source: Source,
    capacity: u64,
    grain: u64,
    flags: u32,
    compressed: bool,
    entries: Vec<u32>,
    reserved: Vec<(u64, u64)>,
}
impl Sparse {
    fn open(path: &Path, limits: &Limits) -> Result<Self> {
        let mut source = Source::open(path)?;
        let mut h = source.read(0, 512)?;
        if &h[..4] != b"KDMV" || !(1..=3).contains(&u32le(&h, 4)?) {
            return Err(Error::Unsupported("VMDK sparse format version".into()));
        }
        let flags = u32le(&h, 8)?;
        let capacity = sector(u64le(&h, 12)?)?;
        let grain = sector(u64le(&h, 20)?)?;
        let gtes = u32le(&h, 44)? as usize;
        if flags & !0x30007 != 0 {
            return Err(Error::Unsupported("VMDK sparse flags".into()));
        }
        if capacity == 0
            || grain < 4096
            || !grain.is_power_of_two()
            || grain > limits.max_decoded_block as u64
            || !gtes.is_power_of_two()
            || !(128..=65536).contains(&gtes)
        {
            return Err(bad("VMDK", "sparse geometry"));
        }
        if flags & 1 != 0 && h[73..77] != [10, 32, 13, 10] {
            return Err(bad("VMDK", "newline sentinel mismatch"));
        }
        let compression = u16le(&h, 77)?;
        let compressed = flags & 0x10000 != 0;
        if compression > 1
            || compressed != (compression == 1)
            || (compressed && flags & 0x20000 == 0)
        {
            return Err(Error::Unsupported("VMDK compression layout".into()));
        }
        let footer_at = if u64le(&h, 56)? == u64::MAX {
            if source.len < 1536 || !compressed {
                return Err(bad("VMDK", "missing stream footer"));
            }
            let eos = source.read(source.len - 512, 512)?;
            let footer = source.read(source.len - 1024, 512)?;
            let marker = source.read(source.len - 1536, 512)?;
            if eos.iter().any(|b| *b != 0)
                || &footer[..4] != b"KDMV"
                || u32le(&marker, 8)? != 0
                || u32le(&marker, 12)? != 3
                || u64le(&marker, 0)? != 0
                || marker[16..].iter().any(|b| *b != 0)
                || footer[..56] != h[..56]
                || footer[64..79] != h[64..79]
            {
                return Err(bad("VMDK", "invalid stream footer"));
            }
            h[56..64].copy_from_slice(&footer[56..64]);
            Some(source.len - 1536)
        } else {
            None
        };
        let grains = capacity.div_ceil(grain);
        if grains > limits.max_metadata_bytes as u64 / 4 {
            return Err(Error::ResourceLimit("VMDK grain index"));
        }
        let directories = grains.div_ceil(gtes as u64) as usize;
        let mut reserved = BTreeSet::from([(0, 512)]);
        if let Some(at) = footer_at {
            reserved.insert((at, source.len));
        }
        let desc = sector(u64le(&h, 28)?)?;
        let desc_len = sector(u64le(&h, 36)?)?;
        if desc_len != 0 {
            checked_region(desc, desc_len, source.len, "VMDK descriptor")?;
            reserved.insert((desc, desc + desc_len));
        }
        let mut load = |location: u64| -> Result<Vec<u32>> {
            let at = sector(location)?;
            checked_region(
                at,
                directories as u64 * 4,
                source.len,
                "VMDK grain directory",
            )?;
            reserved.insert((at, at + directories as u64 * 4));
            let gd = source.read(at, directories * 4)?;
            let mut out = Vec::with_capacity(grains as usize);
            for (i, v) in gd.as_chunks::<4>().0.iter().enumerate() {
                let table = u32::from_le_bytes(*v);
                let count = (grains as usize - out.len()).min(gtes);
                if table == 0 {
                    out.resize(out.len() + count, 0);
                    continue;
                }
                if table == 1 && flags & 4 != 0 && u32le(&h, 4)? >= 2 {
                    out.resize(out.len() + count, 1);
                    continue;
                }
                let at = sector(u64::from(table))?;
                checked_region(at, gtes as u64 * 4, source.len, "VMDK grain table")?;
                reserved.insert((at, at + gtes as u64 * 4));
                let gt = source.read(at, gtes * 4)?;
                out.extend(
                    gt.as_chunks::<4>().0[..count]
                        .iter()
                        .map(|v| u32::from_le_bytes(*v)),
                );
                if i >= directories {
                    return Err(bad("VMDK", "grain directory length"));
                }
            }
            Ok(out)
        };
        let gd = u64le(&h, 56)?;
        let backup = u64le(&h, 48)?;
        if gd == 0 && (flags & 2 == 0 || backup == 0) {
            return Err(bad("VMDK", "missing grain directory"));
        }
        let entries = load(if gd == 0 && flags & 2 != 0 {
            backup
        } else {
            gd
        })?;
        if flags & 2 != 0 && backup != 0 && gd != 0 && backup != gd && load(backup)? != entries {
            return Err(bad("VMDK", "redundant grain tables disagree"));
        }
        let reserved: Vec<_> = reserved.into_iter().collect();
        if reserved.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(bad("VMDK", "overlapping metadata"));
        }
        Ok(Self {
            source,
            capacity,
            grain,
            flags,
            compressed,
            entries,
            reserved,
        })
    }
    fn region(&self, at: u64, len: u64) -> Result<()> {
        checked_region(at, len, self.source.len, "VMDK grain")?;
        let end = at + len;
        if self.reserved.iter().any(|&(s, e)| at < e && s < end) {
            return Err(bad("VMDK", "grain overlaps metadata"));
        }
        Ok(())
    }
}
#[derive(Debug)]
enum Storage {
    Sparse(Sparse),
    Flat(Source, u64),
    Zero,
}
#[derive(Debug)]
struct Extent {
    start: u64,
    size: u64,
    storage: Storage,
}
#[derive(Debug)]
pub struct VmdkImage {
    size: u64,
    extents: Vec<Extent>,
    cid: Option<u32>,
    parent: Option<Box<VmdkImage>>,
    cache: Option<(usize, u64, Vec<u8>)>,
}
fn tokens(line: &str) -> Result<Vec<String>> {
    let mut out = vec![];
    let mut value = String::new();
    let mut quoted = false;
    for c in line.chars() {
        if c == '"' {
            quoted = !quoted;
        } else if c == '#' && !quoted {
            break;
        } else if c.is_whitespace() && !quoted {
            if !value.is_empty() {
                out.push(std::mem::take(&mut value));
            }
        } else {
            value.push(c);
        }
    }
    if quoted {
        return Err(bad("VMDK", "unterminated descriptor quote"));
    }
    if !value.is_empty() {
        out.push(value);
    }
    Ok(out)
}
impl VmdkImage {
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
            return Err(Error::ResourceLimit("VMDK parent depth"));
        }
        if !seen.insert(path.canonicalize()?) {
            return Err(bad("VMDK", "parent chain cycle"));
        }
        let mut source = Source::open(path)?;
        let signature = source.read(0, source.len.min(512) as usize)?;
        let embedded = signature.starts_with(b"KDMV");
        let mut fields = BTreeMap::new();
        let mut lines = vec![];
        let descriptor = if embedded {
            let at = sector(u64le(&signature, 28)?)?;
            let size = sector(u64le(&signature, 36)?)?;
            if size > limits.max_metadata_bytes as u64 {
                return Err(Error::ResourceLimit("VMDK descriptor"));
            }
            if size == 0 {
                vec![]
            } else {
                source.read(at, size as usize)?
            }
        } else {
            if source.len > limits.max_metadata_bytes as u64 {
                return Err(Error::ResourceLimit("VMDK descriptor"));
            }
            source.read(0, source.len as usize)?
        };
        let text = std::str::from_utf8(&descriptor)
            .map_err(|_| Error::Unsupported("VMDK descriptor encoding/legacy format".into()))?
            .trim_end_matches('\0');
        for line in text.lines() {
            let t = tokens(line)?;
            if t.is_empty() {
                continue;
            }
            if ["RW", "RDONLY", "NOACCESS"].contains(&t[0].as_str()) {
                lines.push(t);
            } else if let Some((key, value)) = line.split_once('=') {
                let value = tokens(value)?.join(" ");
                if fields.insert(key.trim().to_owned(), value).is_some() {
                    return Err(bad("VMDK", "duplicate descriptor setting"));
                }
            }
        }
        if !embedded && fields.get("version").map(String::as_str) != Some("1") {
            return Err(Error::Unsupported("VMDK descriptor version".into()));
        }
        let mut extents = vec![];
        let mut total = 0u64;
        let mut budget = descriptor.len();
        let self_extent = embedded && lines.len() == 1;
        if embedded && lines.is_empty() {
            let sparse = Sparse::open(path, limits)?;
            total = sparse.capacity;
            extents.push(Extent {
                start: 0,
                size: total,
                storage: Storage::Sparse(sparse),
            });
        }
        for row in lines {
            if extents.len() >= limits.max_segments {
                return Err(Error::ResourceLimit("VMDK extents"));
            }
            if row.len() < 3 || row[0] == "NOACCESS" {
                return Err(Error::Unsupported("VMDK inaccessible extent".into()));
            }
            let size = sector(
                row[1]
                    .parse()
                    .map_err(|_| bad("VMDK", "extent sector count"))?,
            )?;
            if size == 0 {
                return Err(bad("VMDK", "empty extent"));
            }
            let storage = match row[2].as_str() {
                "ZERO" => Storage::Zero,
                "SPARSE" => {
                    let extent_path = if self_extent {
                        path.to_path_buf()
                    } else {
                        companion(
                            path,
                            row.get(3)
                                .ok_or_else(|| bad("VMDK", "missing extent filename"))?,
                        )?
                    };
                    let sparse = Sparse::open(&extent_path, limits)?;
                    if sparse.capacity != size {
                        return Err(bad("VMDK", "descriptor/sparse capacity mismatch"));
                    }
                    budget = budget
                        .checked_add(sparse.entries.len() * 4)
                        .ok_or(Error::ResourceLimit("VMDK metadata"))?;
                    if budget > limits.max_metadata_bytes {
                        return Err(Error::ResourceLimit("VMDK metadata"));
                    }
                    Storage::Sparse(sparse)
                }
                "FLAT" => {
                    let filename = row
                        .get(3)
                        .ok_or_else(|| bad("VMDK", "missing flat filename"))?;
                    let p = companion(path, filename)?;
                    let flat = Source::open(&p)?;
                    let offset = sector(
                        row.get(4)
                            .map_or(Ok(0), |v| v.parse())
                            .map_err(|_| bad("VMDK", "flat sector offset"))?,
                    )?;
                    checked_region(offset, size, flat.len, "VMDK flat extent")?;
                    Storage::Flat(flat, offset)
                }
                _ => return Err(Error::Unsupported(format!("VMDK extent type {}", row[2]))),
            };
            extents.push(Extent {
                start: total,
                size,
                storage,
            });
            total = total
                .checked_add(size)
                .ok_or_else(|| bad("VMDK", "virtual size overflow"))?;
        }
        if extents.is_empty() {
            return Err(bad("VMDK", "descriptor has no extents"));
        }
        let cid = fields
            .get("CID")
            .map(|v| u32::from_str_radix(v, 16).map_err(|_| bad("VMDK", "CID")))
            .transpose()?;
        let parent_cid = fields
            .get("parentCID")
            .map(|v| u32::from_str_radix(v, 16).map_err(|_| bad("VMDK", "parent CID")))
            .transpose()?;
        let mut parent = None;
        if let Some(expected) = parent_cid.filter(|n| *n != u32::MAX) {
            let p = if let Some(p) = explicit {
                p.to_path_buf()
            } else {
                companion(
                    path,
                    fields
                        .get("parentFileNameHint")
                        .ok_or_else(|| bad("VMDK", "missing parent filename"))?,
                )?
            };
            let disk = Self::inner(&p, None, limits, seen)?;
            if disk.cid != Some(expected) || disk.size != total {
                return Err(bad("VMDK", "parent CID/capacity mismatch"));
            }
            parent = Some(Box::new(disk));
        }
        Ok(Self {
            size: total,
            extents,
            cid,
            parent,
            cache: None,
        })
    }
}
impl DiskImage for VmdkImage {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let n = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let index = self.extents.partition_point(|e| e.start <= at) - 1;
            let extent = &mut self.extents[index];
            let local = at - extent.start;
            let mut count = (n - done).min((extent.size - local) as usize);
            match &mut extent.storage {
                Storage::Zero => buffer[done..done + count].fill(0),
                Storage::Flat(source, start) => {
                    source.exact(*start + local, &mut buffer[done..done + count])?
                }
                Storage::Sparse(s) => {
                    let grain = local / s.grain;
                    let within = local % s.grain;
                    count = count.min((s.grain - within) as usize);
                    let entry = s.entries[grain as usize];
                    let out = &mut buffer[done..done + count];
                    if entry == 0 {
                        if let Some(parent) = self.parent.as_mut() {
                            parent.read_exact_at(at, out)?;
                        } else {
                            out.fill(0);
                        }
                    } else if entry == 1 && s.flags & 4 != 0 {
                        out.fill(0);
                    } else {
                        let physical = sector(u64::from(entry))?;
                        if s.compressed {
                            if self
                                .cache
                                .as_ref()
                                .is_none_or(|(i, g, _)| *i != index || *g != grain)
                            {
                                s.region(physical, 12)?;
                                let marker = s.source.read(physical, 12)?;
                                let len = u32le(&marker, 8)? as usize;
                                if u64le(&marker, 0)? != grain * (s.grain / 512)
                                    || len == 0
                                    || len > s.grain as usize + s.grain as usize / 100 + 1024
                                {
                                    return Err(bad("VMDK", "compressed grain marker"));
                                }
                                s.region(physical, len as u64 + 12)?;
                                let compressed = s.source.read(physical + 12, len)?;
                                let minimum = (s.capacity - grain * s.grain).min(s.grain) as usize;
                                let data = inflate(&compressed, minimum, s.grain as usize)?;
                                self.cache = Some((index, grain, data));
                            }
                            out.copy_from_slice(
                                &self.cache.as_ref().unwrap().2
                                    [within as usize..within as usize + count],
                            );
                        } else {
                            s.region(physical + within, count as u64)?;
                            s.source.exact(physical + within, out)?;
                        }
                    }
                }
            }
            done += count;
        }
        Ok(n)
    }
}
