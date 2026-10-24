//! Live logical-directory evidence without following child links/reparse points.
use super::{DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, TimeBasis, Times, Timestamp};
use crate::{Error, Result, wire::corrupt};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
struct Entry {
    path: PathBuf,
    meta: Metadata,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    link: Option<Vec<u8>>,
    children: Vec<DirEntry>,
    #[cfg(unix)]
    identity: (u64, u64),
}
pub struct LogicalFs {
    root: PathBuf,
    info: FsInfo,
    entries: BTreeMap<u64, Entry>,
}
#[derive(PartialEq, Eq)]
pub(crate) struct AcquisitionIdentity {
    id: u64,
    path: PathBuf,
    size: u64,
    kind: FileKind,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    link: Option<Vec<u8>>,
    #[cfg(unix)]
    identity: (u64, u64),
}
fn bad(reason: &str) -> Error {
    corrupt("logical directory", 0, reason)
}
fn timestamp(t: SystemTime) -> Option<Timestamp> {
    let (seconds, nanos) = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (i64::try_from(d.as_secs()).ok()?, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let sec = i64::try_from(d.as_secs()).ok()?;
            if d.subsec_nanos() == 0 {
                (-sec, 0)
            } else {
                (-sec - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    };
    Some(Timestamp {
        seconds,
        nanos,
        basis: TimeBasis::Utc,
    })
}
fn reparse(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        m.file_type().is_symlink()
    }
}
fn open_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20000);
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x100);
    }
    #[cfg(all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))
    ))]
    {
        return Err(Error::Unsupported(
            "logical no-follow opens on this platform".into(),
        ));
    }
    Ok(options.open(path)?)
}
impl LogicalFs {
    pub(crate) fn entries_for_acquisition(&self) -> Vec<(Metadata, Vec<DirEntry>)> {
        self.entries
            .values()
            .map(|e| (e.meta.clone(), e.children.clone()))
            .collect()
    }
    pub(crate) fn acquisition_signature(&self) -> Vec<AcquisitionIdentity> {
        self.entries
            .iter()
            .map(|(&id, e)| AcquisitionIdentity {
                id,
                path: e.path.clone(),
                size: e.meta.size,
                kind: e.meta.kind,
                modified: e.modified,
                created: e.created,
                link: e.link.clone(),
                #[cfg(unix)]
                identity: e.identity,
            })
            .collect()
    }
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        let root = path.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(Error::NotDirectory(root.display().to_string()));
        }
        let mut entries: BTreeMap<u64, Entry> = BTreeMap::new();
        let mut queue = VecDeque::from([(1, root.clone(), 0)]);
        let mut next = 2u64;
        let mut budget = root.as_os_str().as_encoded_bytes().len() + 256;
        if limits.max_directory_entries == 0 || budget > limits.max_metadata_bytes {
            return Err(Error::ResourceLimit("logical root metadata"));
        }
        let mut total = 0u64;
        while let Some((id, path, depth)) = queue.pop_front() {
            if depth > limits.max_tree_depth {
                return Err(Error::ResourceLimit("logical directory depth"));
            }
            let m = fs::symlink_metadata(&path)?;
            let is_link = m.file_type().is_symlink() || reparse(&m);
            let target = if is_link {
                fs::read_link(&path)
                    .ok()
                    .map(|p| p.as_os_str().as_encoded_bytes().to_vec())
            } else {
                None
            };
            if let Some(target) = &target {
                budget = budget
                    .checked_add(target.len())
                    .ok_or(Error::ResourceLimit("logical link metadata"))?;
                if budget > limits.max_metadata_bytes {
                    return Err(Error::ResourceLimit("logical link metadata"));
                }
            }
            let kind = if target.is_some() {
                FileKind::Symlink
            } else if is_link {
                FileKind::Other
            } else if m.is_dir() {
                FileKind::Directory
            } else if m.is_file() {
                FileKind::File
            } else {
                FileKind::Other
            };
            let size = if let Some(t) = &target {
                t.len() as u64
            } else if kind == FileKind::File {
                m.len()
            } else {
                0
            };
            let mut meta = Metadata {
                id,
                kind,
                size,
                allocated: true,
                links: 1,
                mode: None,
                uid: None,
                gid: None,
                sequence: None,
                times: Times {
                    created: m.created().ok().and_then(timestamp),
                    modified: m.modified().ok().and_then(timestamp),
                    accessed: m.accessed().ok().and_then(timestamp),
                    changed: None,
                },
                streams: vec![],
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                meta.mode = Some(m.mode() as u16);
                meta.uid = Some(m.uid());
                meta.gid = Some(m.gid());
                meta.links = m
                    .nlink()
                    .try_into()
                    .map_err(|_| bad("host link count overflow"))?;
                if m.ctime_nsec() >= 0 && m.ctime_nsec() < 1_000_000_000 {
                    meta.times.changed = Some(Timestamp {
                        seconds: m.ctime(),
                        nanos: m.ctime_nsec() as u32,
                        basis: TimeBasis::Utc,
                    });
                }
            }
            #[cfg(windows)]
            {
                let _ = &mut meta;
            }
            let mut children = vec![];
            if kind == FileKind::Directory {
                let mut paths = vec![];
                let mut path_bytes = 0usize;
                for child in fs::read_dir(&path)? {
                    let child = child?.path();
                    path_bytes = path_bytes
                        .checked_add(child.as_os_str().as_encoded_bytes().len())
                        .ok_or(Error::ResourceLimit("logical directory paths"))?;
                    if paths.len() >= limits.max_directory_entries
                        || path_bytes > limits.max_metadata_bytes.saturating_sub(budget)
                    {
                        return Err(Error::ResourceLimit("logical directory entries/paths"));
                    }
                    paths.push(child);
                }
                paths.sort();
                for child in paths {
                    let raw = child
                        .file_name()
                        .ok_or_else(|| bad("host filename"))?
                        .as_encoded_bytes()
                        .to_vec();
                    let name = child.file_name().unwrap().to_string_lossy().into_owned();
                    budget = budget
                        .checked_add(
                            name.len()
                                + raw.len()
                                + child.as_os_str().as_encoded_bytes().len()
                                + 256,
                        )
                        .ok_or(Error::ResourceLimit("logical metadata"))?;
                    if budget > limits.max_metadata_bytes
                        || next > limits.max_directory_entries as u64
                    {
                        return Err(Error::ResourceLimit("logical metadata/records"));
                    }
                    let child_id = next;
                    next += 1;
                    children.push(DirEntry {
                        id: child_id,
                        name,
                        kind: FileKind::Other,
                        size: 0,
                        allocated: true,
                        aliases: vec![],
                        raw_name: Some(raw),
                    });
                    queue.push_back((child_id, child, depth + 1));
                }
            }
            total = total
                .checked_add(size)
                .ok_or_else(|| bad("logical byte count overflow"))?;
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                (m.dev(), m.ino())
            };
            entries.insert(
                id,
                Entry {
                    path,
                    meta,
                    modified: m.modified().ok(),
                    created: m.created().ok(),
                    link: target,
                    children,
                    #[cfg(unix)]
                    identity,
                },
            );
        }
        let types: BTreeMap<_, _> = entries
            .iter()
            .map(|(&id, e)| (id, (e.meta.kind, e.meta.size)))
            .collect();
        for e in entries.values_mut() {
            for child in &mut e.children {
                (child.kind, child.size) = types[&child.id];
            }
        }
        Ok(Self {
            info: FsInfo {
                filesystem: FsType::Logical,
                label: root.file_name().map_or_else(
                    || root.display().to_string(),
                    |s| s.to_string_lossy().into_owned(),
                ),
                block_size: 1,
                total_bytes: total,
                root_id: 1,
                needs_journal_recovery: false,
            },
            root,
            entries,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    pub fn metadata(&self, id: u64) -> Result<Metadata> {
        self.entries
            .get(&id)
            .map(|e| e.meta.clone())
            .ok_or_else(|| Error::NotFound(id.to_string()))
    }
    pub fn read_dir(&self, id: u64) -> Result<Vec<DirEntry>> {
        let e = self
            .entries
            .get(&id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if e.meta.kind != FileKind::Directory {
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
            return Err(Error::Unsupported("logical host named streams".into()));
        }
        let e = self
            .entries
            .get(&id)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        let n = e.meta.size.saturating_sub(offset).min(out.len() as u64) as usize;
        if let Some(target) = &e.link {
            if n != 0 {
                out[..n].copy_from_slice(&target[offset as usize..offset as usize + n]);
            }
            return Ok(n);
        }
        if e.meta.kind != FileKind::File {
            return Err(Error::Unsupported(
                "logical directory/special file data".into(),
            ));
        }
        if e.path.canonicalize()?.strip_prefix(&self.root).is_err() {
            return Err(bad("host file moved outside evidence root"));
        }
        let mut file = open_file(&e.path)?;
        let m = file.metadata()?;
        if !m.is_file()
            || reparse(&m)
            || m.len() != e.meta.size
            || m.modified().ok() != e.modified
            || m.created().ok() != e.created
        {
            return Err(bad("host file changed since enumeration"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (m.dev(), m.ino()) != e.identity {
                return Err(bad("host file identity changed"));
            }
        }
        if n == 0 {
            return Ok(0);
        }
        file.seek(SeekFrom::Start(offset))?;
        Ok(file.read(&mut out[..n])?)
    }
}
