//! A shared read-only interface for native forensic filesystem readers.
//!
//! ```no_run
//! use inodex::{filesystem::FileSystem, image::Image, partition::PartitionTable};
//! let mut image = Image::open("disk.E01")?;
//! let table = PartitionTable::read(&mut image)?.ok_or("no partition table")?;
//! let mut volume = table.get(1)?.volume(&mut image)?;
//! let mut fs = FileSystem::open(&mut volume)?;
//! let id = fs.resolve("/documents/report.txt")?;
//! fs.copy_file(id, None, &mut std::io::sink())?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
pub mod apfs;
mod decmpfs;
mod exfat;
mod ext;
mod fat;
pub mod forensics;
mod hfs;
mod indexed;
mod iso9660;
pub mod journal;
pub mod lef;
pub mod logical;
pub mod lznt1;
mod ntfs;
pub mod security;
mod ufs;
pub mod yaffs2;

use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::corrupt,
};
pub use exfat::Exfat;
pub use ext::Ext;
pub use fat::Fat;
pub use indexed::IndexedFs;
pub use ntfs::Ntfs;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_metadata_bytes: usize,
    pub max_directory_bytes: u64,
    pub max_directory_entries: usize,
    pub max_chain_length: usize,
    pub max_tree_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_metadata_bytes: 16 * 1024 * 1024,
            max_directory_bytes: 64 * 1024 * 1024,
            max_directory_entries: 100_000,
            max_chain_length: 1_048_576,
            max_tree_depth: 32,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsType {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    Exfat,
    Ext2,
    Ext3,
    Ext4,
    Apfs,
    HfsPlus,
    HfsX,
    Ufs1,
    Ufs1b,
    Ufs2,
    Iso9660,
    Yaffs2,
    Logical,
    LogicalEvidence,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeBasis {
    Utc,
    LocalCivil,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
    pub basis: TimeBasis,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Times {
    pub created: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub accessed: Option<Timestamp>,
    pub changed: Option<Timestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    pub name: String,
    pub size: u64,
    pub resident: bool,
    pub compressed: bool,
    pub encrypted: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub id: u64,
    pub kind: FileKind,
    pub size: u64,
    pub allocated: bool,
    pub links: u32,
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub sequence: Option<u16>,
    pub times: Times,
    pub streams: Vec<StreamInfo>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub id: u64,
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
    pub allocated: bool,
    pub aliases: Vec<String>,
    /// Original name bytes for ext filesystems; display names may be lossy UTF-8.
    pub raw_name: Option<Vec<u8>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsInfo {
    pub filesystem: FsType,
    pub label: String,
    pub block_size: u32,
    pub total_bytes: u64,
    pub root_id: u64,
    pub needs_journal_recovery: bool,
}

pub enum FileSystem<'a> {
    Ntfs(Ntfs<'a>),
    Fat(Fat<'a>),
    Ext(Ext<'a>),
    Exfat(Exfat<'a>),
    Indexed(IndexedFs<'a>),
    Logical(logical::LogicalFs),
    Snapshot(crate::acquisition::SnapshotFs),
    LogicalEvidence(lef::LogicalEvidenceFs),
}
impl<'a> FileSystem<'a> {
    pub fn open(image: &'a mut dyn DiskImage) -> Result<Self> {
        Self::with_limits(image, Limits::default())
    }
    pub fn with_limits(image: &'a mut dyn DiskImage, limits: Limits) -> Result<Self> {
        if let Some(path) = image.logical_evidence_path() {
            return lef::LogicalEvidenceFs::open(path, limits).map(Self::LogicalEvidence);
        }
        if let Some(path) = image.snapshot_path() {
            return crate::acquisition::SnapshotFs::open(path, limits).map(Self::Snapshot);
        }
        if let Some(root) = image.logical_root() {
            return logical::LogicalFs::open(root, limits).map(Self::Logical);
        }
        if image.len() >= 512 {
            let boot = read_vec(image, 0, 512)?;
            if &boot[3..11] == b"-FVE-FS-"
                || boot[424..440]
                    == [
                        0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3,
                        0x39, 0xe3, 0xd0, 0x01,
                    ]
            {
                return Err(Error::Unsupported(
                    "BitLocker volume requires an explicit credential/decrypted view".into(),
                ));
            }
            if &boot[3..11] == b"NTFS    " {
                return Ntfs::open(image, limits).map(Self::Ntfs);
            }
            if &boot[3..11] == b"EXFAT   " {
                return Exfat::open(image, limits).map(Self::Exfat);
            }
            if boot[510..] == [0x55, 0xaa] && (boot[0] == 0xeb || boot[0] == 0xe9) {
                return Fat::open(image, limits).map(Self::Fat);
            }
        }
        if image.len() >= 2048 && read_vec(image, 1024 + 56, 2)? == [0x53, 0xef] {
            return Ext::open(image, limits).map(Self::Ext);
        }
        if image.len() >= 4096 && read_vec(image, 32, 4)? == b"NXSB" {
            return apfs::open(image, limits).map(Self::Indexed);
        }
        if image.len() >= 1536
            && matches!(read_vec(image, 1024, 2)?.as_slice(), b"H+" | b"HX" | b"BD")
        {
            return hfs::open(image, limits).map(Self::Indexed);
        }
        if iso9660::detect(image)? {
            return iso9660::open(image, limits).map(Self::Indexed);
        }
        if ufs::detect(image)? {
            return ufs::open(image, limits).map(Self::Indexed);
        }
        if let Some(geometry) = yaffs2::detect(image)? {
            return yaffs2::open(image, limits, geometry).map(Self::Indexed);
        }
        Err(Error::Unsupported(
            "unrecognized filesystem; choose a partition or volume offset".into(),
        ))
    }
    pub fn info(&self) -> &FsInfo {
        match self {
            Self::Ntfs(fs) => fs.info(),
            Self::Fat(fs) => fs.info(),
            Self::Ext(fs) => fs.info(),
            Self::Exfat(fs) => fs.info(),
            Self::Indexed(fs) => fs.info(),
            Self::Logical(fs) => fs.info(),
            Self::Snapshot(fs) => fs.info(),
            Self::LogicalEvidence(fs) => fs.info(),
        }
    }
    pub fn metadata(&mut self, id: u64) -> Result<Metadata> {
        match self {
            Self::Ntfs(fs) => fs.metadata(id),
            Self::Fat(fs) => fs.metadata(id),
            Self::Ext(fs) => fs.metadata(id),
            Self::Exfat(fs) => fs.metadata(id),
            Self::Indexed(fs) => fs.metadata(id),
            Self::Logical(fs) => fs.metadata(id),
            Self::Snapshot(fs) => fs.metadata(id),
            Self::LogicalEvidence(fs) => fs.metadata(id),
        }
    }
    pub fn security(&mut self, id: u64) -> Result<Option<security::SecurityDescriptor>> {
        match self {
            Self::Ntfs(fs) => fs.security(id),
            _ => Err(Error::Unsupported(
                "security descriptors for this filesystem".into(),
            )),
        }
    }
    pub fn ntfs_details(&mut self, id: u64) -> Result<forensics::NtfsDetails> {
        match self {
            Self::Ntfs(fs) => fs.details(id),
            _ => Err(Error::Unsupported(
                "NTFS record details on this filesystem".into(),
            )),
        }
    }
    pub fn deleted_records(
        &mut self,
        start: u64,
        count: usize,
        stream: Option<&str>,
    ) -> Result<forensics::DeletedScan> {
        match self {
            Self::Ntfs(fs) => fs.deleted_records(start, count, stream),
            _ => Err(Error::Unsupported(
                "deleted-record scanning for this filesystem".into(),
            )),
        }
    }
    pub fn recover_file(
        &mut self,
        id: u64,
        stream: Option<&str>,
        output: &mut impl Write,
    ) -> Result<u64> {
        match self {
            Self::Ntfs(fs) => fs.check_recovery(id, stream)?,
            _ => {
                return Err(Error::Unsupported(
                    "deleted-file recovery for this filesystem".into(),
                ));
            }
        }
        self.copy_file(id, stream, output)
    }
    pub fn usn_journal(
        &mut self,
        start: u64,
        bytes: usize,
        count: usize,
    ) -> Result<journal::UsnScan> {
        if !matches!(self, Self::Ntfs(_)) {
            return Err(Error::Unsupported("USN journals require NTFS".into()));
        }
        let id = self.resolve("/$Extend/$UsnJrnl")?;
        match self {
            Self::Ntfs(fs) => fs.usn_journal(id, start, bytes, count),
            _ => Err(Error::Unsupported("USN journals require NTFS".into())),
        }
    }
    pub fn logfile_info(&mut self) -> Result<journal::LogFileInfo> {
        match self {
            Self::Ntfs(fs) => fs.logfile_info(),
            _ => Err(Error::Unsupported(
                "$LogFile inspection requires NTFS".into(),
            )),
        }
    }
    pub fn read_dir(&mut self, id: u64) -> Result<Vec<DirEntry>> {
        let mut entries = match self {
            Self::Ntfs(fs) => fs.read_dir(id),
            Self::Fat(fs) => fs.read_dir(id),
            Self::Ext(fs) => fs.read_dir(id),
            Self::Exfat(fs) => fs.read_dir(id),
            Self::Indexed(fs) => fs.read_dir(id),
            Self::Logical(fs) => fs.read_dir(id),
            Self::Snapshot(fs) => fs.read_dir(id),
            Self::LogicalEvidence(fs) => fs.read_dir(id),
        }?;
        entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        Ok(entries)
    }
    pub fn read_file(
        &mut self,
        id: u64,
        stream: Option<&str>,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        match self {
            Self::Ntfs(fs) => fs.read_file(id, stream, offset, buffer),
            Self::Indexed(fs) => fs.read_file(id, stream, offset, buffer),
            Self::Logical(fs) => fs.read_file(id, stream, offset, buffer),
            Self::Snapshot(fs) => fs.read_file(id, stream, offset, buffer),
            Self::LogicalEvidence(fs) => fs.read_file(id, stream, offset, buffer),
            Self::Exfat(fs) => {
                if stream.is_some_and(|s| !s.is_empty()) {
                    return Err(Error::Unsupported("exFAT named streams".into()));
                }
                fs.read_file(id, offset, buffer)
            }
            Self::Fat(fs) => {
                if stream.is_some_and(|s| !s.is_empty()) {
                    return Err(Error::Unsupported("FAT named streams".into()));
                }
                fs.read_file(id, offset, buffer)
            }
            Self::Ext(fs) => {
                if stream.is_some_and(|s| !s.is_empty()) {
                    return Err(Error::Unsupported("ext named streams".into()));
                }
                fs.read_file(id, offset, buffer)
            }
        }
    }
    /// Resolve a UTF-8 path without following symlinks or reparse points.
    pub fn resolve(&mut self, path: &str) -> Result<u64> {
        if path.len() > 32768 || path.contains('\0') {
            return Err(Error::Unsupported(
                "invalid or excessively long path".into(),
            ));
        }
        let mut stack = vec![self.info().root_id];
        for (count, component) in path.split('/').filter(|s| !s.is_empty()).enumerate() {
            if count >= 1024 {
                return Err(Error::ResourceLimit("path component count"));
            }
            let current = *stack.last().unwrap();
            if self.metadata(current)?.kind != FileKind::Directory {
                return Err(Error::NotDirectory(component.into()));
            }
            if component == "." {
                continue;
            }
            if component == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            if let Self::Fat(fs) = self {
                let found = fs.lookup(current, component)?;
                stack.push(found.ok_or_else(|| Error::NotFound(path.into()))?);
                continue;
            }
            let entries = self.read_dir(current)?;
            let mut found = None;
            for entry in entries {
                let matches = match self {
                    Self::Ntfs(fs) => {
                        fs.name_eq(&entry.name, component)
                            || entry.aliases.iter().any(|s| fs.name_eq(s, component))
                    }
                    Self::Fat(_) => {
                        entry.name.eq_ignore_ascii_case(component)
                            || entry
                                .aliases
                                .iter()
                                .any(|s| s.eq_ignore_ascii_case(component))
                    }
                    Self::Ext(_) => entry.raw_name.as_deref() == Some(component.as_bytes()),
                    Self::Exfat(fs) => fs.name_eq(&entry.name, component),
                    Self::Logical(_) | Self::Snapshot(_) => {
                        entry.raw_name.as_deref() == Some(component.as_bytes())
                            || (cfg!(windows) && entry.name.eq_ignore_ascii_case(component))
                    }
                    Self::LogicalEvidence(_) => entry.name == component,
                    Self::Indexed(fs) => match fs.info().filesystem {
                        FsType::Ufs1 | FsType::Ufs1b | FsType::Ufs2 => {
                            entry.raw_name.as_deref() == Some(component.as_bytes())
                        }
                        _ => {
                            entry.name == component
                                || (fs.ascii_fold && entry.name.eq_ignore_ascii_case(component))
                        }
                    },
                };
                if matches {
                    if found.is_some_and(|id| id != entry.id) {
                        return Err(corrupt("directory", current, "ambiguous filename"));
                    }
                    found = Some(entry.id);
                }
            }
            stack.push(found.ok_or_else(|| Error::NotFound(path.into()))?);
        }
        let result = *stack.last().unwrap();
        if path.ends_with('/') && self.metadata(result)?.kind != FileKind::Directory {
            return Err(Error::NotDirectory(path.into()));
        }
        Ok(result)
    }
    /// Bounded-memory extraction. Discard partial output if an error occurs.
    pub fn copy_file(
        &mut self,
        id: u64,
        stream: Option<&str>,
        output: &mut impl Write,
    ) -> Result<u64> {
        let metadata = self.metadata(id)?;
        if !matches!(metadata.kind, FileKind::File | FileKind::Symlink)
            && !(matches!(self, Self::LogicalEvidence(_)) && stream == Some("L01.data"))
        {
            return Err(Error::Unsupported(
                "extracting a directory or special file as a data file".into(),
            ));
        }
        let size = if let Some(name) = stream.filter(|s| !s.is_empty()) {
            metadata
                .streams
                .iter()
                .find(|s| s.name == name)
                .ok_or_else(|| Error::NotFound(format!("stream {name}")))?
                .size
        } else {
            metadata.size
        };
        // Validate stream support even for empty files, before claiming success.
        self.read_file(id, stream, 0, &mut [])?;
        let mut buffer = vec![0; 65536];
        let mut position = 0;
        while position < size {
            let amount = (size - position).min(buffer.len() as u64) as usize;
            let count = self.read_file(id, stream, position, &mut buffer[..amount])?;
            if count == 0 || count > amount {
                return Err(corrupt(
                    "file",
                    position,
                    "unexpected short read during extraction",
                ));
            }
            output.write_all(&buffer[..count])?;
            position += count as u64;
        }
        Ok(position)
    }
}
