//! Bounded file index and extent reads shared by the additional native parsers.
use super::{DirEntry, FileKind, FsInfo, Limits, Metadata, TimeBasis, Times, Timestamp};
use crate::{Error, Result, image::DiskImage, wire::*};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(super) struct Run {
    pub logical: u64,
    pub physical: Option<u64>,
    pub length: u64,
}
#[derive(Clone, Default)]
pub(super) struct Data {
    pub size: u64,
    pub runs: Vec<Run>,
    pub inline: Option<Vec<u8>>,
    pub unsupported: Option<String>,
    pub compressed: Option<Box<super::decmpfs::Compressed>>,
}
#[derive(Clone)]
pub(super) struct Node {
    pub meta: Metadata,
    pub children: Vec<DirEntry>,
    pub data: BTreeMap<String, Data>,
}
pub struct IndexedFs<'a> {
    pub(super) image: &'a mut dyn DiskImage,
    pub(super) info: FsInfo,
    pub(super) limits: Limits,
    pub(super) nodes: BTreeMap<u64, Node>,
    pub(super) ascii_fold: bool,
    pub(super) budget: usize,
    pub(super) base_offset: u64,
    data_budget: usize,
}
pub(super) fn bad(reason: impl Into<String>) -> Error {
    corrupt("filesystem", 0, reason)
}
pub(super) fn kind(mode: u16) -> FileKind {
    match mode & 0xf000 {
        0x4000 => FileKind::Directory,
        0x8000 => FileKind::File,
        0xa000 => FileKind::Symlink,
        _ => FileKind::Other,
    }
}
pub(super) fn utc(seconds: i64, nanos: u32) -> Result<Timestamp> {
    if nanos >= 1_000_000_000 {
        return Err(bad("timestamp nanoseconds"));
    }
    Ok(Timestamp {
        seconds,
        nanos,
        basis: TimeBasis::Utc,
    })
}
pub(super) fn metadata(id: u64, mode: u16, size: u64) -> Metadata {
    Metadata {
        id,
        kind: kind(mode),
        size,
        allocated: true,
        links: 1,
        mode: Some(mode),
        uid: None,
        gid: None,
        sequence: None,
        times: Times::default(),
        streams: vec![],
    }
}
pub(super) fn node(meta: Metadata, data: Data) -> Node {
    Node {
        meta,
        children: vec![],
        data: BTreeMap::from([(String::new(), data)]),
    }
}
impl<'a> IndexedFs<'a> {
    pub(super) fn new(image: &'a mut dyn DiskImage, info: FsInfo, limits: Limits) -> Self {
        Self {
            image,
            info,
            limits,
            nodes: BTreeMap::new(),
            ascii_fold: false,
            budget: 0,
            base_offset: 0,
            data_budget: 0,
        }
    }
    pub(super) fn charge(&mut self, n: usize) -> Result<()> {
        self.budget = self
            .budget
            .checked_add(n)
            .ok_or(Error::ResourceLimit("filesystem index"))?;
        if self.budget > self.limits.max_metadata_bytes {
            return Err(Error::ResourceLimit("filesystem index"));
        }
        Ok(())
    }
    pub(super) fn insert(&mut self, n: Node) -> Result<()> {
        if self.nodes.len() >= self.limits.max_directory_entries {
            return Err(Error::ResourceLimit("filesystem records"));
        }
        let data_bytes = n
            .data
            .values()
            .map(|d| d.runs.len() * 32 + d.inline.as_ref().map_or(0, Vec::len))
            .sum::<usize>();
        self.reserve_data(data_bytes)?;
        self.charge(256)?;
        if self.nodes.insert(n.meta.id, n).is_some() {
            return Err(bad("duplicate file identifier"));
        }
        Ok(())
    }
    pub(super) fn reserve_data(&mut self, n: usize) -> Result<()> {
        self.charge(n)?;
        self.data_budget = self
            .data_budget
            .checked_add(n)
            .ok_or(Error::ResourceLimit("filesystem data index"))?;
        Ok(())
    }
    pub(super) fn link(
        &mut self,
        parent: u64,
        id: u64,
        name: String,
        raw: Option<Vec<u8>>,
    ) -> Result<()> {
        if name.is_empty() || name.contains(['\0', '/']) {
            return Err(bad(format!("invalid directory name {name:?}")));
        }
        let m = self.metadata(id)?;
        self.charge(name.len() + raw.as_ref().map_or(0, Vec::len) + 96)?;
        let p = self
            .nodes
            .get_mut(&parent)
            .ok_or_else(|| bad(format!("missing parent directory {parent} for {name:?}")))?;
        if p.meta.kind != FileKind::Directory || p.children.iter().any(|e| e.name == name) {
            return Err(bad("invalid/duplicate directory entry"));
        }
        if p.children.len() >= self.limits.max_directory_entries {
            return Err(Error::ResourceLimit("directory entries"));
        }
        p.children.push(DirEntry {
            id,
            name,
            kind: m.kind,
            size: m.size,
            allocated: m.allocated,
            aliases: vec![],
            raw_name: raw,
        });
        Ok(())
    }
    pub(super) fn validate(&mut self) -> Result<()> {
        let mut bytes = 0usize;
        for n in self.nodes.values_mut() {
            for d in n.data.values_mut() {
                if d.runs.len() > self.limits.max_chain_length {
                    return Err(Error::ResourceLimit("file extents"));
                }
                d.runs.sort_by_key(|r| r.logical);
                let mut end = 0;
                for r in &d.runs {
                    if r.length == 0 || r.logical < end {
                        return Err(bad("overlapping/empty extents"));
                    }
                    end = r
                        .logical
                        .checked_add(r.length)
                        .ok_or_else(|| bad("extent overflow"))?;
                    if let Some(p) = r.physical {
                        if p < self.base_offset {
                            return Err(bad("extent before embedded filesystem"));
                        }
                        checked_region(
                            p - self.base_offset,
                            r.length,
                            self.info.total_bytes,
                            "filesystem extent",
                        )?;
                    }
                }
                if d.inline.as_ref().is_some_and(|v| v.len() as u64 != d.size) {
                    return Err(bad("inline data size"));
                }
                bytes = bytes
                    .checked_add(d.runs.len() * 32 + d.inline.as_ref().map_or(0, Vec::len))
                    .ok_or(Error::ResourceLimit("filesystem index"))?;
            }
        }
        self.charge(bytes.saturating_sub(self.data_budget))?;
        let mut colors = BTreeMap::new();
        for (&root, n) in &self.nodes {
            if n.meta.kind != FileKind::Directory || colors.get(&root) == Some(&2u8) {
                continue;
            }
            let mut todo = vec![(root, false, 0usize)];
            while let Some((id, exit, depth)) = todo.pop() {
                if exit {
                    colors.insert(id, 2u8);
                    continue;
                }
                match colors.get(&id) {
                    Some(1) => return Err(bad("directory graph cycle")),
                    Some(2) => continue,
                    _ => {}
                }
                if depth > self.limits.max_tree_depth {
                    return Err(Error::ResourceLimit("directory graph depth"));
                }
                colors.insert(id, 1u8);
                todo.push((id, true, depth));
                for child in &self.nodes[&id].children {
                    if child.kind == FileKind::Directory {
                        todo.push((child.id, false, depth + 1));
                    }
                }
            }
        }
        Ok(())
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    pub fn metadata(&self, id: u64) -> Result<Metadata> {
        self.nodes
            .get(&id)
            .map(|n| n.meta.clone())
            .ok_or_else(|| Error::NotFound(format!("file id {id}")))
    }
    pub fn read_dir(&self, id: u64) -> Result<Vec<DirEntry>> {
        let n = self
            .nodes
            .get(&id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if n.meta.kind != FileKind::Directory {
            return Err(Error::NotDirectory(id.to_string()));
        }
        Ok(n.children.clone())
    }
    pub fn read_file(
        &mut self,
        id: u64,
        stream: Option<&str>,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let n = self
            .nodes
            .get(&id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if !matches!(n.meta.kind, FileKind::File | FileKind::Symlink) {
            return Err(Error::Unsupported("directory/special file data".into()));
        }
        let d = n
            .data
            .get(stream.unwrap_or(""))
            .ok_or_else(|| Error::NotFound("file stream".into()))?;
        if let Some(reason) = &d.unsupported {
            return Err(Error::Unsupported(reason.clone()));
        }
        let amount = d.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        if let Some(compressed) = &d.compressed {
            return compressed.read_at(self.image, offset, buffer);
        }
        buffer[..amount].fill(0);
        if let Some(data) = &d.inline {
            if amount != 0 {
                buffer[..amount].copy_from_slice(&data[offset as usize..offset as usize + amount]);
            }
            return Ok(amount);
        }
        for r in &d.runs {
            let start = offset.max(r.logical);
            let end = (offset + amount as u64).min(r.logical + r.length);
            if start < end
                && let Some(p) = r.physical
            {
                self.image.read_exact_at(
                    p + (start - r.logical),
                    &mut buffer[(start - offset) as usize..(end - offset) as usize],
                )?;
            }
        }
        Ok(amount)
    }
}
pub(super) fn read_data(
    image: &mut dyn DiskImage,
    data: &Data,
    offset: u64,
    buf: &mut [u8],
) -> Result<()> {
    checked_region(offset, buf.len() as u64, data.size, "metadata stream")?;
    if let Some(inline) = &data.inline {
        buf.copy_from_slice(bytes(inline, offset as usize, buf.len())?);
        return Ok(());
    }
    buf.fill(0);
    for r in &data.runs {
        let s = offset.max(r.logical);
        let end = r
            .logical
            .checked_add(r.length)
            .ok_or_else(|| bad("metadata extent overflow"))?;
        let e = (offset + buf.len() as u64).min(end);
        if s < e
            && let Some(p) = r.physical
        {
            checked_region(p, r.length, image.len(), "metadata extent")?;
            image.read_exact_at(
                p + (s - r.logical),
                &mut buf[(s - offset) as usize..(e - offset) as usize],
            )?;
        }
    }
    Ok(())
}
