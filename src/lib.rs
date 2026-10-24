//! Native Rust forensic image, partition, and filesystem readers.
//!
//! [`ewf::EwfImage`] exposes decoded media through [`std::io::Read`] and
//! [`std::io::Seek`], as well as the offset-based [`image::DiskImage`] interface.
//! [`partition::PartitionTable`] discovers MBR/GPT volumes;
//! [`filesystem::FileSystem`] reads NTFS, FAT, exFAT, ext, APFS, HFS+, HFSX,
//! UFS1/UFS2, ISO9660 and YAFFS2 directories and files.
//!
//! Start with [`image::Image::open`], select an optional partition using
//! [`partition::PartitionTable::read`], and call [`filesystem::FileSystem::open`].
//! Readers are read-only; the application owns case storage and processing.
//! See `docs/api.md` and the `library_ingest` Cargo example for integration.
#![forbid(unsafe_code)]
#![doc = include_str!("../docs/api.md")]

pub mod acquisition;
pub mod bitlocker;
pub mod error;
pub mod ewf;
pub mod filesystem;
pub mod image;
pub mod partition;
mod wire;

pub use error::{Error, Result};
