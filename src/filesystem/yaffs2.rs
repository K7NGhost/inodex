//! YAFFS2 NAND pages with packed tags, object versions and logical data chunks.
use super::{FileKind, FsInfo, FsType, Limits, Times, indexed::*};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{BTreeMap, HashSet, VecDeque};
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub page_size: u32,
    pub spare_size: u32,
    pub pages_per_block: u32,
    pub tags_offset: u32,
}
impl Default for Geometry {
    fn default() -> Self {
        Self {
            page_size: 2048,
            spare_size: 64,
            pages_per_block: 64,
            tags_offset: 0,
        }
    }
}
#[derive(Clone)]
struct Header {
    version: (u32, u64),
    parent: u64,
    meta: super::Metadata,
    data: Data,
    name: String,
    equivalent: u64,
}
type Version = (u32, u64);
type ShrinkMap = BTreeMap<u64, Vec<(Version, u64)>>;
pub(super) fn detect(image: &mut dyn DiskImage) -> Result<Option<Geometry>> {
    for (page, spare) in [(2048, 64), (4096, 128), (1024, 32), (8192, 256)] {
        for offset in [0, 2] {
            let g = Geometry {
                page_size: page,
                spare_size: spare,
                pages_per_block: 64,
                tags_offset: offset,
            };
            let stride = u64::from(page + spare);
            if image.len() < stride || !image.len().is_multiple_of(stride) {
                continue;
            }
            let mut found = false;
            for i in 0..(image.len() / stride).min(128) {
                let d = read_vec(image, i * stride + u64::from(page + offset), 16)?;
                let seq = u32le(&d, 0)?;
                let chunk = u32le(&d, 8)?;
                if (0x1000..=0xefffff00).contains(&seq) && (chunk == 0 || chunk & 0x80000000 != 0) {
                    let head = read_vec(image, i * stride, 8)?;
                    if (1..=5).contains(&u32le(&head, 0)?) {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                return Ok(Some(g));
            }
        }
    }
    Ok(None)
}
pub fn open(image: &mut dyn DiskImage, limits: Limits, g: Geometry) -> Result<IndexedFs<'_>> {
    if !g.page_size.is_power_of_two()
        || !(512..=16384).contains(&g.page_size)
        || g.spare_size < 16
        || g.spare_size > 1024
        || g.tags_offset
            .checked_add(16)
            .is_none_or(|n| n > g.spare_size)
        || !g.pages_per_block.is_power_of_two()
    {
        return Err(bad("YAFFS2 geometry"));
    }
    let stride = u64::from(g.page_size) + u64::from(g.spare_size);
    if !image.len().is_multiple_of(stride) {
        return Err(bad("YAFFS2 truncated page/spare"));
    }
    let pages = image.len() / stride;
    if pages > limits.max_chain_length as u64 {
        return Err(Error::ResourceLimit("YAFFS2 pages"));
    }
    let mut headers: BTreeMap<u64, Header> = BTreeMap::new();
    let mut chunks: BTreeMap<(u64, u32), ((u32, u64), u32)> = BTreeMap::new();
    let mut shrink = ShrinkMap::new();
    let mut shadow = HashSet::new();
    let mut budget = 0usize;
    for page in 0..pages {
        let at = page * stride;
        let tag = read_vec(image, at + u64::from(g.page_size + g.tags_offset), 16)?;
        if tag.iter().all(|b| *b == 255) {
            continue;
        }
        let seq = u32le(&tag, 0)?;
        if !(0x1000..=0xefffff00).contains(&seq) {
            return Err(bad("YAFFS2 invalid sequence/ECC tags"));
        }
        let packed = u32le(&tag, 4)?;
        let extra = u32le(&tag, 8)?;
        let id = u64::from(if extra & 0x80000000 != 0 {
            packed & 0x0fffffff
        } else {
            packed
        });
        if id == 0 {
            return Err(bad("YAFFS2 zero object id"));
        }
        let chunk = if extra & 0x80000000 != 0 { 0 } else { extra };
        let version = (seq, at);
        budget += 80;
        if budget > limits.max_metadata_bytes {
            return Err(Error::ResourceLimit("YAFFS2 page index"));
        }
        if chunk == 0 {
            let d = read_vec(image, at, 512)?;
            let typ = u32le(&d, 0)?;
            if !(1..=5).contains(&typ) {
                return Err(bad("YAFFS2 object type"));
            }
            let parent = u64::from(u32le(&d, 4)?);
            let name_bytes = &d[10..266];
            let end = name_bytes
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| bad("YAFFS2 unterminated object name"))?;
            let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
            let mode = u32le(&d, 268)? as u16;
            let mut size = u64::from(u32le(&d, 292)?);
            let high = u32le(&d, 496)?;
            if high != u32::MAX {
                size |= u64::from(high) << 32;
            }
            let mut m = metadata(id, mode, size);
            m.kind = match typ {
                1 | 4 => FileKind::File,
                2 => FileKind::Symlink,
                3 => FileKind::Directory,
                _ => FileKind::Other,
            };
            m.uid = Some(u32le(&d, 272)?);
            m.gid = Some(u32le(&d, 276)?);
            m.times = Times {
                created: None,
                accessed: Some(utc(i64::from(u32le(&d, 280)?), 0)?),
                modified: Some(utc(i64::from(u32le(&d, 284)?), 0)?),
                changed: Some(utc(i64::from(u32le(&d, 288)?), 0)?),
            };
            let mut data = Data {
                size,
                ..Data::default()
            };
            if typ == 2 {
                let alias = &d[300..460];
                let end = alias
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| bad("YAFFS2 unterminated symlink"))?;
                data.inline = Some(alias[..end].to_vec());
                data.size = end as u64;
                m.size = data.size;
            }
            if typ == 3 {
                m.size = 0;
                data = Data::default();
            }
            if u32le(&d, 508)? == 1 {
                shrink.entry(id).or_default().push((version, size));
            }
            let shadows = u32le(&d, 504)?;
            if shadows != 0 && shadows != u32::MAX {
                shadow.insert(u64::from(shadows));
            }
            let h = Header {
                version,
                parent,
                meta: m,
                data,
                name,
                equivalent: if typ == 4 {
                    u64::from(u32le(&d, 296)?)
                } else {
                    0
                },
            };
            if headers.get(&id).is_none_or(|old| old.version < version) {
                headers.insert(id, h);
            }
        } else {
            let count = u32le(&tag, 12)?;
            if count == 0 || count > g.page_size {
                return Err(bad("YAFFS2 data byte count"));
            }
            let key = (id, chunk);
            if chunks.get(&key).is_none_or(|(old, _)| *old < version) {
                chunks.insert(key, (version, count));
            }
        }
    }
    let total = image.len();
    let mut fs = IndexedFs::new(
        image,
        FsInfo {
            filesystem: FsType::Yaffs2,
            label: String::new(),
            block_size: g.page_size,
            total_bytes: total,
            root_id: 1,
            needs_journal_recovery: false,
        },
        limits,
    );
    headers.entry(1).or_insert_with(|| Header {
        version: (0, 0),
        parent: 1,
        meta: metadata(1, 0x4000, 0),
        data: Data::default(),
        name: String::new(),
        equivalent: 0,
    });
    for ((id, chunk), (version, count)) in chunks {
        if let Some(h) = headers.get_mut(&id) {
            let logical = u64::from(chunk - 1) * u64::from(g.page_size);
            let mut length = u64::from(count).min(h.meta.size.saturating_sub(logical));
            if let Some(barriers) = shrink.get(&id) {
                for &(v, size) in barriers {
                    if version < v {
                        length = length.min(size.saturating_sub(logical));
                    }
                }
            }
            if length != 0 && h.meta.kind == FileKind::File {
                h.data.runs.push(Run {
                    logical,
                    physical: Some(version.1),
                    length,
                });
            }
        }
    }
    let mut queue = VecDeque::from([(1, 0)]);
    let mut seen = HashSet::new();
    let mut edges = vec![];
    while let Some((id, depth)) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        if depth > fs.limits.max_tree_depth {
            return Err(Error::ResourceLimit("YAFFS2 directory depth"));
        }
        let mut h = headers
            .get(&id)
            .cloned()
            .ok_or_else(|| bad("YAFFS2 missing header"))?;
        if h.equivalent != 0 {
            let mut equivalent = h.equivalent;
            let mut visited = HashSet::new();
            while equivalent != 0 {
                if !visited.insert(equivalent) || visited.len() > fs.limits.max_tree_depth {
                    return Err(bad("YAFFS2 hard-link cycle"));
                }
                let target = headers
                    .get(&equivalent)
                    .ok_or_else(|| bad("YAFFS2 missing hard-link target"))?;
                h.meta = target.meta.clone();
                h.meta.id = id;
                h.data = target.data.clone();
                equivalent = target.equivalent;
            }
        }
        if h.meta.kind == FileKind::Directory {
            for (&child, c) in &headers {
                if child != id
                    && c.parent == id
                    && !shadow.contains(&child)
                    && child != 3
                    && child != 4
                {
                    edges.push((id, child, c.name.clone()));
                    queue.push_back((child, depth + 1));
                }
            }
        }
        fs.insert(node(h.meta, h.data))?;
    }
    for (p, id, name) in edges {
        fs.link(p, id, name, None)?;
    }
    fs.validate()?;
    Ok(fs)
}
