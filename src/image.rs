//! Image interface shared by disk containers, partition views and filesystems.

use crate::{
    Error, Result,
    ewf::EwfImage,
    wire::{checked_region, corrupt},
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
mod aff;
mod common;
mod split_raw;
mod vhd;
mod vhdx;
mod vmdk;
pub use aff::AffImage;
pub use common::Limits;
pub use split_raw::SplitRawImage;
pub use vhd::VhdImage;
pub use vhdx::VhdxImage;
pub use vmdk::VmdkImage;
#[derive(Debug)]
pub struct LogicalImage {
    root: std::path::PathBuf,
    snapshot: bool,
    evidence: bool,
}
impl LogicalImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(Error::NotDirectory(root.display().to_string()));
        }
        Ok(Self {
            root,
            snapshot: false,
            evidence: false,
        })
    }
    fn snapshot(path: &Path) -> Result<Self> {
        Ok(Self {
            root: path.canonicalize()?,
            snapshot: true,
            evidence: false,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}
impl DiskImage for LogicalImage {
    fn logical_evidence_path(&self) -> Option<&Path> {
        self.evidence.then_some(self.root.as_path())
    }
    fn len(&self) -> u64 {
        0
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn logical_root(&self) -> Option<&Path> {
        Some(&self.root)
    }
    fn snapshot_path(&self) -> Option<&Path> {
        self.snapshot.then_some(self.root.as_path())
    }
    fn read_at(&mut self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::Unsupported(
            "logical directories have no disk byte stream".into(),
        ))
    }
}

pub trait DiskImage {
    fn logical_evidence_path(&self) -> Option<&Path> {
        None
    }
    fn snapshot_path(&self) -> Option<&Path> {
        None
    }
    fn logical_root(&self) -> Option<&Path> {
        None
    }
    /// Decoded media size, independent of the container's compressed size.
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn sector_size(&self) -> u32;
    /// Read decoded media without changing the sequential stream position.
    /// Returns a short read at the end of the media and zero beyond it.
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize>;

    fn read_exact_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        checked_region(offset, buffer.len() as u64, self.len(), "image read")?;
        let mut count = 0;
        while count < buffer.len() {
            let read = self.read_at(offset + count as u64, &mut buffer[count..])?;
            if read == 0 || read > buffer.len() - count {
                return Err(corrupt("image read", offset, "unexpected short read"));
            }
            count += read;
        }
        Ok(())
    }
}

/// A read-only single raw image. Files are never opened with write permission.
#[derive(Debug)]
pub struct RawImage {
    file: File,
    size: u64,
    sector_size: u32,
}
impl RawImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_sector_size(path, 512)
    }
    pub fn with_sector_size(path: impl AsRef<Path>, sector_size: u32) -> Result<Self> {
        if !sector_size.is_power_of_two() || !(512..=65536).contains(&sector_size) {
            return Err(corrupt("raw image", 0, "invalid sector size"));
        }
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file,
            size,
            sector_size,
        })
    }
}
impl DiskImage for RawImage {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let size = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        if size == 0 {
            return Ok(0);
        }
        self.file.seek(SeekFrom::Start(offset))?;
        Ok(self.file.read(&mut buffer[..size])?)
    }
}

/// Automatic disk-container or logical-directory selection.
#[derive(Debug)]
pub enum Image {
    Ewf(Box<EwfImage>),
    Raw(RawImage),
    SplitRaw(SplitRawImage),
    Aff(AffImage),
    Vmdk(VmdkImage),
    Vhd(VhdImage),
    Vhdx(VhdxImage),
    Logical(LogicalImage),
}
impl Image {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_limits(path, Limits::default())
    }
    pub fn with_limits(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        let path = path.as_ref();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if path.is_dir() {
            return if ext == "afd" {
                AffImage::with_limits(path, limits).map(Self::Aff)
            } else {
                LogicalImage::open(path).map(Self::Logical)
            };
        }
        let mut raw = RawImage::open(path)?;
        let mut signature = [0; 8];
        let count = raw.read_at(0, &mut signature)?;
        if signature == *b"LVF\x09\x0d\x0a\xff\x00" || ext == "l01" {
            crate::filesystem::lef::LogicalEvidenceFs::open(
                path,
                crate::filesystem::Limits::default(),
            )?;
            return Ok(Self::Logical(LogicalImage {
                root: path.canonicalize()?,
                snapshot: false,
                evidence: true,
            }));
        }
        if signature == *crate::acquisition::MAGIC || ext == "inodex" {
            crate::acquisition::SnapshotFs::open(path, crate::filesystem::Limits::default())?;
            return LogicalImage::snapshot(path).map(Self::Logical);
        }
        if signature == *b"AFF10\r\n\0" || ["aff", "afm"].contains(&ext.as_str()) {
            return AffImage::with_limits(path, limits).map(Self::Aff);
        }
        if &signature[..4] == b"KDMV" || &signature[..4] == b"COWD" || ext == "vmdk" {
            return VmdkImage::with_limits(path, limits).map(Self::Vmdk);
        }
        if ext == "vhd"
            || signature == *b"conectix"
            || (raw.len() >= 512 && {
                let mut cookie = [0; 8];
                raw.read_at(raw.len() - 512, &mut cookie)?;
                cookie == *b"conectix"
            })
        {
            return VhdImage::with_limits(path, limits).map(Self::Vhd);
        }
        if signature == *b"vhdxfile" || ext == "vhdx" {
            return VhdxImage::with_limits(path, limits).map(Self::Vhdx);
        }
        if ext == "aff4" {
            return Err(Error::Unsupported(
                "AFF4 is a separate, unsupported image format".into(),
            ));
        }
        let ewf_extension = path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|ext| {
                let ext = ext.to_ascii_uppercase();
                ext.len() == 3
                    && ext.starts_with('E')
                    && ext[1..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
            });
        if (count >= 3
            && (&signature[..3] == b"EVF"
                || &signature[..3] == b"LVF"
                || &signature[..3] == b"LEF"))
            || ewf_extension
        {
            drop(raw);
            Ok(Self::Ewf(Box::new(EwfImage::open(path)?)))
        } else {
            if (ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit())) || ext == "aa" {
                let paths = split_raw::discover(path, &limits)?;
                return SplitRawImage::with_limits(paths, 512, limits).map(Self::SplitRaw);
            }
            Ok(Self::Raw(raw))
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ewf(_) => "EWF v1 (E01)",
            Self::Raw(_) => "Raw",
            Self::SplitRaw(_) => "Split raw",
            Self::Aff(a) => a.kind(),
            Self::Vmdk(_) => "VMDK",
            Self::Vhd(_) => "VHD",
            Self::Vhdx(_) => "VHDX",
            Self::Logical(l) => {
                if l.evidence {
                    "L01 logical evidence"
                } else if l.snapshot {
                    "Logical acquisition"
                } else {
                    "Logical directory"
                }
            }
        }
    }
    pub fn set_sector_size(&mut self, n: u32) -> Result<()> {
        if !n.is_power_of_two() || !(512..=65536).contains(&n) {
            return Err(corrupt("image", 0, "invalid sector size"));
        }
        match self {
            Self::Raw(r) => {
                r.sector_size = n;
                Ok(())
            }
            Self::SplitRaw(r) => r.set_sector_size(n),
            Self::Logical(_) => Err(Error::Unsupported("logical directory sector size".into())),
            _ if self.sector_size() == n => Ok(()),
            _ => Err(Error::Unsupported(
                "sector-size override disagrees with container geometry".into(),
            )),
        }
    }
    pub fn verify(&mut self) -> Result<crate::ewf::Verification> {
        if let Some(path) = self.logical_evidence_path() {
            return crate::filesystem::lef::LogicalEvidenceFs::open(
                path,
                crate::filesystem::Limits::default(),
            )?
            .verify();
        }
        if let Some(path) = self.snapshot_path().map(Path::to_path_buf) {
            crate::acquisition::SnapshotFs::open(&path, crate::filesystem::Limits::default())?
                .verify()?;
            return Image::Raw(RawImage::open(path)?).verify();
        }
        self.export_to(&mut std::io::sink())
    }
    pub fn export_to(
        &mut self,
        output: &mut impl std::io::Write,
    ) -> Result<crate::ewf::Verification> {
        if let Self::Ewf(image) = self {
            return image.export_to(output);
        }
        if matches!(self, Self::Logical(_)) {
            return Err(Error::Unsupported(
                "logical directories have no disk stream; extract individual files".into(),
            ));
        }
        use md5::{Digest, Md5};
        use sha1::Sha1;
        use sha2::Sha256;
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut buffer = vec![0; 65536];
        let mut at = 0;
        while at < self.len() {
            let size = (self.len() - at).min(buffer.len() as u64) as usize;
            self.read_exact_at(at, &mut buffer[..size])?;
            output.write_all(&buffer[..size])?;
            md5.update(&buffer[..size]);
            sha1.update(&buffer[..size]);
            sha256.update(&buffer[..size]);
            at += size as u64;
        }
        let md5: [u8; 16] = md5.finalize().into();
        let sha1: [u8; 20] = sha1.finalize().into();
        let sha256: [u8; 32] = sha256.finalize().into();
        let mut md5_verified = false;
        let mut sha1_verified = false;
        if let Self::Aff(a) = self {
            for (name, stored, actual) in [
                ("md5", a.stored_md5()?.map(|h| h.to_vec()), md5.to_vec()),
                ("sha1", a.stored_sha1()?.map(|h| h.to_vec()), sha1.to_vec()),
                (
                    "sha256",
                    a.stored_sha256()?.map(|h| h.to_vec()),
                    sha256.to_vec(),
                ),
            ] {
                if let Some(stored) = stored {
                    if stored != actual {
                        return Err(Error::DigestMismatch {
                            algorithm: name,
                            stored: crate::ewf::hex(&stored),
                            calculated: crate::ewf::hex(&actual),
                        });
                    }
                    match name {
                        "md5" => md5_verified = true,
                        "sha1" => sha1_verified = true,
                        _ => {}
                    }
                }
            }
        }
        Ok(crate::ewf::Verification {
            bytes_read: at,
            md5,
            sha1,
            md5_verified,
            sha1_verified,
        })
    }
}
impl DiskImage for Image {
    fn logical_evidence_path(&self) -> Option<&Path> {
        match self {
            Self::Logical(l) => l.logical_evidence_path(),
            _ => None,
        }
    }
    fn snapshot_path(&self) -> Option<&Path> {
        match self {
            Self::Logical(l) => l.snapshot_path(),
            _ => None,
        }
    }
    fn len(&self) -> u64 {
        match self {
            Self::Ewf(image) => image.len(),
            Self::Raw(image) => image.len(),
            Self::SplitRaw(image) => image.len(),
            Self::Aff(image) => image.len(),
            Self::Vmdk(image) => image.len(),
            Self::Vhd(image) => image.len(),
            Self::Vhdx(image) => image.len(),
            Self::Logical(image) => image.len(),
        }
    }
    fn sector_size(&self) -> u32 {
        match self {
            Self::Ewf(image) => image.sector_size(),
            Self::Raw(image) => image.sector_size(),
            Self::SplitRaw(image) => image.sector_size(),
            Self::Aff(image) => image.sector_size(),
            Self::Vmdk(image) => image.sector_size(),
            Self::Vhd(image) => image.sector_size(),
            Self::Vhdx(image) => image.sector_size(),
            Self::Logical(image) => image.sector_size(),
        }
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        match self {
            Self::Ewf(image) => image.read_at(offset, buffer),
            Self::Raw(image) => image.read_at(offset, buffer),
            Self::SplitRaw(image) => image.read_at(offset, buffer),
            Self::Aff(image) => image.read_at(offset, buffer),
            Self::Vmdk(image) => image.read_at(offset, buffer),
            Self::Vhd(image) => image.read_at(offset, buffer),
            Self::Vhdx(image) => image.read_at(offset, buffer),
            Self::Logical(image) => image.read_at(offset, buffer),
        }
    }
    fn logical_root(&self) -> Option<&Path> {
        if let Self::Logical(l) = self {
            Some(l.root())
        } else {
            None
        }
    }
}

/// A bounded view. Reads cannot escape into a neighboring partition.
pub struct Volume<'a> {
    image: &'a mut dyn DiskImage,
    offset: u64,
    size: u64,
}
impl<'a> Volume<'a> {
    pub fn new(image: &'a mut dyn DiskImage, offset: u64, size: u64) -> Result<Self> {
        if image.logical_root().is_some() && (offset != 0 || size != 0) {
            return Err(Error::Unsupported(
                "logical directory has no partition offsets".into(),
            ));
        }
        checked_region(offset, size, image.len(), "volume")?;
        Ok(Self {
            image,
            offset,
            size,
        })
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
}
impl DiskImage for Volume<'_> {
    fn logical_evidence_path(&self) -> Option<&Path> {
        self.image.logical_evidence_path()
    }
    fn snapshot_path(&self) -> Option<&Path> {
        self.image.snapshot_path()
    }
    fn logical_root(&self) -> Option<&Path> {
        self.image.logical_root()
    }
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.image.sector_size()
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let count = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        self.image
            .read_at(self.offset + offset, &mut buffer[..count])
    }
}

pub(crate) fn read_vec(image: &mut dyn DiskImage, offset: u64, size: usize) -> Result<Vec<u8>> {
    checked_region(offset, size as u64, image.len(), "image read")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::ResourceLimit("image read allocation"))?;
    bytes.resize(size, 0);
    image.read_exact_at(offset, &mut bytes)?;
    Ok(bytes)
}
