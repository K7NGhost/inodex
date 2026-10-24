//! Self-contained logical acquisition with preserved metadata and SHA-256 chunks.
use crate::{
    Error, Result,
    filesystem::{DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, logical::LogicalFs},
    wire::*,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
pub const MAGIC: &[u8; 8] = b"INODEX1\0";
const HEADER: u64 = 56;
const CHUNK: usize = 65536;
#[derive(Serialize, Deserialize)]
struct Entry {
    metadata: Metadata,
    children: Vec<DirEntry>,
    offset: u64,
    chunks: Vec<[u8; 32]>,
    sha256: [u8; 32],
}
#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    source_label: String,
    started_unix_seconds: u64,
    completed_unix_seconds: u64,
    entries: Vec<Entry>,
    source_root: String,
    source_root_encoded: Vec<u8>,
    source_os: String,
    writer_version: String,
}
#[derive(Debug, Serialize)]
pub struct AcquisitionReport {
    pub files: u64,
    pub bytes: u64,
    pub sha256: String,
    pub source_consistency: String,
    pub source_root: String,
    pub source_os: String,
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
pub fn acquire(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    limits: Limits,
) -> Result<AcquisitionReport> {
    let started = now();
    let destination = destination.as_ref();
    let mut logical = LogicalFs::open(source, limits.clone())?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    if parent.starts_with(logical.root()) {
        return Err(Error::Unsupported(
            "acquisition output must be outside source tree".into(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    let result = (|| -> Result<AcquisitionReport> {
        file.write_all(&[0; HEADER as usize])?;
        let mut entries = vec![];
        let mut total = 0;
        let mut files = 0;
        let mut budget = 0usize;
        for (metadata, children) in logical.entries_for_acquisition() {
            let offset = file.stream_position()?;
            let mut hasher = Sha256::new();
            let mut chunks = vec![];
            if matches!(metadata.kind, FileKind::File | FileKind::Symlink) {
                files += 1;
                let mut at = 0;
                let mut buffer = [0; CHUNK];
                // Validate empty files too.
                logical.read_file(metadata.id, None, 0, &mut [])?;
                while at < metadata.size {
                    let size = (metadata.size - at).min(CHUNK as u64) as usize;
                    let mut read = 0;
                    while read < size {
                        let n = logical.read_file(
                            metadata.id,
                            None,
                            at + read as u64,
                            &mut buffer[read..size],
                        )?;
                        if n == 0 {
                            return Err(corrupt("acquisition", at, "short source read"));
                        }
                        read += n;
                    }
                    file.write_all(&buffer[..size])?;
                    hasher.update(&buffer[..size]);
                    chunks.push(Sha256::digest(&buffer[..size]).into());
                    at += size as u64;
                    budget = budget.saturating_add(160);
                    if budget > limits.max_metadata_bytes {
                        return Err(Error::ResourceLimit("acquisition chunk index"));
                    }
                }
                total += metadata.size;
            } else if metadata.kind == FileKind::Other {
                return Err(Error::Unsupported(
                    "logical acquisition of special/reparse data without a recorded target".into(),
                ));
            }
            entries.push(Entry {
                metadata,
                children,
                offset,
                chunks,
                sha256: hasher.finalize().into(),
            });
        }
        let after = LogicalFs::open(logical.root(), limits.clone())?;
        if after.acquisition_signature() != logical.acquisition_signature() {
            return Err(corrupt(
                "acquisition",
                0,
                "source tree changed during capture",
            ));
        }
        let manifest = Manifest {
            version: 1,
            source_label: logical.info().label.clone(),
            started_unix_seconds: started,
            completed_unix_seconds: now(),
            entries,
            source_root: logical.root().display().to_string(),
            source_root_encoded: logical.root().as_os_str().as_encoded_bytes().to_vec(),
            source_os: std::env::consts::OS.into(),
            writer_version: env!("CARGO_PKG_VERSION").into(),
        };
        let data =
            serde_json::to_vec(&manifest).map_err(|e| corrupt("acquisition", 0, e.to_string()))?;
        if data.len() > limits.max_metadata_bytes {
            return Err(Error::ResourceLimit("acquisition manifest"));
        }
        let offset = file.stream_position()?;
        file.write_all(&data)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(MAGIC)?;
        file.write_all(&offset.to_le_bytes())?;
        file.write_all(&(data.len() as u64).to_le_bytes())?;
        file.write_all(&Sha256::digest(&data))?;
        file.flush()?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0; CHUNK];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok(AcquisitionReport{files,bytes:total,sha256:crate::ewf::hex(&hash.finalize()),source_consistency:"Live collection checked before/after; not an atomic volume snapshot. Preserve the reported SHA-256 separately.".into(),source_root:manifest.source_root,source_os:manifest.source_os})
    })();
    drop(file);
    if result.is_err() {
        fs::remove_file(destination)?;
    }
    result
}
pub struct SnapshotFs {
    file: File,
    entries: BTreeMap<u64, Entry>,
    info: FsInfo,
    cache: Option<(u64, u64, Vec<u8>)>,
}
impl SnapshotFs {
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        let mut header = [0; HEADER as usize];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(corrupt("acquisition", 0, "signature mismatch"));
        }
        let at = u64le(&header, 8)?;
        let length = u64le(&header, 16)?;
        if at < HEADER || length > limits.max_metadata_bytes as u64 {
            return Err(Error::ResourceLimit("acquisition manifest bounds"));
        }
        checked_region(at, length, size, "acquisition")?;
        if at + length != size {
            return Err(corrupt("acquisition", at, "trailing/missing data"));
        }
        let mut data = vec![0; length as usize];
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut data)?;
        if Sha256::digest(&data).as_slice() != &header[24..56] {
            return Err(corrupt("acquisition", at, "manifest SHA-256 mismatch"));
        }
        let manifest: Manifest =
            serde_json::from_slice(&data).map_err(|e| corrupt("acquisition", at, e.to_string()))?;
        if manifest.version != 1 || manifest.entries.len() > limits.max_directory_entries {
            return Err(Error::Unsupported("acquisition version/entry count".into()));
        }
        let mut entries = BTreeMap::new();
        let mut expected = HEADER;
        let mut total = 0u64;
        for entry in manifest.entries {
            if entry.offset != expected || entry.metadata.id == 0 {
                return Err(corrupt(
                    "acquisition",
                    entry.offset,
                    "noncontiguous blob or invalid ID",
                ));
            }
            let has_data = matches!(entry.metadata.kind, FileKind::File | FileKind::Symlink);
            let size = if has_data { entry.metadata.size } else { 0 };
            checked_region(expected, size, at, "acquisition blob")?;
            expected += size;
            total = total
                .checked_add(size)
                .ok_or_else(|| corrupt("acquisition", expected, "size overflow"))?;
            if entry.chunks.len() as u64 != size.div_ceil(CHUNK as u64)
                || !entry.children.is_empty() && entry.metadata.kind != FileKind::Directory
            {
                return Err(corrupt(
                    "acquisition",
                    entry.offset,
                    "invalid chunks/children",
                ));
            }
            if entries.insert(entry.metadata.id, entry).is_some() {
                return Err(corrupt("acquisition", 0, "duplicate entry ID"));
            }
        }
        if expected != at
            || entries
                .get(&1)
                .is_none_or(|e| e.metadata.kind != FileKind::Directory)
        {
            return Err(corrupt("acquisition", at, "invalid root/blob end"));
        }
        let mut seen = HashSet::from([1]);
        let mut queue = vec![(1, 0)];
        while let Some((id, depth)) = queue.pop() {
            if depth > limits.max_tree_depth {
                return Err(Error::ResourceLimit("acquisition tree depth"));
            }
            let e = &entries[&id];
            let mut names = HashSet::new();
            for child in &e.children {
                let Some(target) = entries.get(&child.id) else {
                    return Err(corrupt("acquisition", id, "missing child"));
                };
                if !seen.insert(child.id)
                    || !names.insert(&child.name)
                    || target.metadata.kind != child.kind
                    || target.metadata.size != child.size
                {
                    return Err(corrupt(
                        "acquisition",
                        id,
                        "duplicate/cyclic/inconsistent child",
                    ));
                }
                queue.push((child.id, depth + 1));
            }
        }
        if seen.len() != entries.len() {
            return Err(corrupt("acquisition", 0, "orphan entries"));
        }
        Ok(Self {
            file,
            entries,
            info: FsInfo {
                filesystem: FsType::Logical,
                label: manifest.source_label,
                block_size: 1,
                total_bytes: total,
                root_id: 1,
                needs_journal_recovery: false,
            },
            cache: None,
        })
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    pub fn metadata(&self, id: u64) -> Result<Metadata> {
        Ok(self.entry(id)?.metadata.clone())
    }
    fn entry(&self, id: u64) -> Result<&Entry> {
        self.entries
            .get(&id)
            .ok_or_else(|| Error::NotFound(id.to_string()))
    }
    pub fn read_dir(&self, id: u64) -> Result<Vec<DirEntry>> {
        let e = self.entry(id)?;
        if e.metadata.kind != FileKind::Directory {
            return Err(Error::NotDirectory(id.to_string()));
        }
        Ok(e.children.clone())
    }
    pub fn read_file(
        &mut self,
        id: u64,
        stream: Option<&str>,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        if stream.is_some_and(|s| !s.is_empty()) {
            return Err(Error::Unsupported("acquisition named streams".into()));
        }
        let e = self.entry(id)?;
        if !matches!(e.metadata.kind, FileKind::File | FileKind::Symlink) {
            return Err(Error::Unsupported("acquisition directory data".into()));
        }
        let size = e.metadata.size;
        let n = size.saturating_sub(offset).min(out.len() as u64) as usize;
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let index = at / CHUNK as u64;
            let within = (at % CHUNK as u64) as usize;
            if self
                .cache
                .as_ref()
                .is_none_or(|(file, chunk, _)| *file != id || *chunk != index)
            {
                let e = self.entry(id)?;
                let start = e.offset + index * CHUNK as u64;
                let expected = e.chunks[index as usize];
                let len = (size - index * CHUNK as u64).min(CHUNK as u64) as usize;
                let mut data = vec![0; len];
                self.file.seek(SeekFrom::Start(start))?;
                self.file.read_exact(&mut data)?;
                if Sha256::digest(&data).as_slice() != expected {
                    return Err(corrupt(
                        "acquisition",
                        start,
                        "content chunk SHA-256 mismatch",
                    ));
                }
                self.cache = Some((id, index, data));
            }
            let data = &self.cache.as_ref().unwrap().2;
            let count = (n - done).min(data.len() - within);
            out[done..done + count].copy_from_slice(&data[within..within + count]);
            done += count;
        }
        Ok(n)
    }
    pub fn verify(&mut self) -> Result<u64> {
        self.cache = None;
        let ids: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| matches!(e.metadata.kind, FileKind::File | FileKind::Symlink))
            .map(|(&id, _)| id)
            .collect();
        let mut total = 0;
        for id in ids {
            let e = self.entry(id)?;
            let expected = e.sha256;
            let size = e.metadata.size;
            let mut hash = Sha256::new();
            let mut at = 0;
            let mut data = [0; CHUNK];
            while at < size {
                let n = self.read_file(id, None, at, &mut data)?;
                hash.update(&data[..n]);
                at += n as u64;
            }
            if hash.finalize().as_slice() != expected {
                return Err(corrupt("acquisition", id, "whole-file SHA-256 mismatch"));
            }
            total += size;
        }
        Ok(total)
    }
}
