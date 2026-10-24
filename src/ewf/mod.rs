//! Read-only Expert Witness Format v1 (E01) disk images, without TSK/libewf FFI.
//!
//! ```no_run
//! use inodex::{ewf::EwfImage, image::DiskImage};
//! let mut image = EwfImage::open("evidence.E01")?;
//! let mut sector = vec![0; image.sector_size() as usize];
//! image.read_at(0, &mut sector)?;
//! let verification = image.verify()?;
//! # Ok::<(), inodex::Error>(())
//! ```

mod format;

use crate::{Error, Result, error::invalid, image::DiskImage};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Allocation and traversal limits applied before trusting on-disk counts.
/// Increase these explicitly for images outside the defaults.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    pub max_chunk_size: usize,
    pub max_metadata_size: usize,
    pub max_chunks: usize,
    pub max_table_entries: usize,
    pub max_sections: usize,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            max_chunk_size: 64 * 1024 * 1024,
            max_metadata_size: 16 * 1024 * 1024,
            max_chunks: 16 * 1024 * 1024,
            max_table_entries: 1024 * 1024,
            max_sections: 1024 * 1024,
        }
    }
}

impl OpenOptions {
    /// Discover subsequent segment filenames starting from segment 1.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<EwfImage> {
        format::open(self, vec![path.as_ref().to_owned()], true)
    }

    /// Open a complete set with arbitrary filenames, sorted by header number.
    pub fn open_segments<I, P>(&self, paths: I) -> Result<EwfImage>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        format::open(
            self,
            paths.into_iter().map(|p| p.as_ref().to_owned()).collect(),
            false,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Metadata {
    pub media_size: u64,
    pub sector_count: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_chunk: u32,
    pub chunk_count: u32,
    pub media_type: u8,
    pub media_flags: u8,
    pub compression_level: u8,
    pub set_identifier: [u8; 16],
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    /// Main acquisition fields keyed by their EWF identifiers (c, n, a, e, ...).
    /// Unicode header2 values take precedence over legacy header values.
    pub acquisition: BTreeMap<String, String>,
    /// Sector ranges reported unreadable by the acquisition tool.
    pub acquisition_errors: Vec<SectorRange>,
}

impl Metadata {
    pub fn chunk_size(&self) -> u64 {
        u64::from(self.bytes_per_sector) * u64::from(self.sectors_per_chunk)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectorRange {
    pub start: u64,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub segment: u16,
    pub kind: String,
    pub offset: u64,
    /// Descriptor plus payload; terminal descriptors are normalized to 76.
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct Verification {
    pub bytes_read: u64,
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub md5_verified: bool,
    pub sha1_verified: bool,
}

#[derive(Debug)]
struct Segment {
    file: File,
    path: PathBuf,
    number: u16,
    size: u64,
}

#[derive(Clone, Copy, Debug)]
struct Chunk {
    offset: u64,
    stored_size: u32,
    segment: u16,
    compressed: bool,
}

/// An indexed image with a bounded least-recently-used decoded-chunk cache.
/// Reads require mutable access; use independent handles for concurrent readers.
#[derive(Debug)]
pub struct EwfImage {
    segments: Vec<Segment>,
    metadata: Metadata,
    sections: Vec<SectionInfo>,
    chunks: Vec<Chunk>,
    position: u64,
    cached: VecDeque<(usize, Vec<u8>)>,
    cached_bytes: usize,
    pub(crate) logical_tree: Option<Vec<u8>>,
}

impl EwfImage {
    pub(crate) fn open_logical_with_options(path: &Path, options: &OpenOptions) -> Result<Self> {
        format::open_mode(options, vec![path.to_path_buf()], true, true)
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        OpenOptions::default().open(path)
    }

    pub fn open_segments<I, P>(paths: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        OpenOptions::default().open_segments(paths)
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub fn sections(&self) -> &[SectionInfo] {
        &self.sections
    }
    pub fn segment_paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.segments.iter().map(|segment| segment.path.as_path())
    }

    fn chunk(&mut self, index: usize) -> Result<&[u8]> {
        // Metadata and file reads alternate between distant chunks. A single
        // cached chunk repeatedly reinflates both sides of those reads.
        if let Some(position) = self.cached.iter().position(|(i, _)| *i == index) {
            if position != 0 {
                let hit = self.cached.remove(position).unwrap();
                self.cached.push_front(hit);
            }
        } else {
            let chunk = self.chunks[index];
            let segment = &mut self.segments[usize::from(chunk.segment) - 1];
            let stored =
                format::read_bytes(&mut segment.file, chunk.offset, chunk.stored_size as usize)?;
            let chunk_size = self.metadata.chunk_size() as usize;
            let data = if chunk.compressed {
                format::inflate(&stored, chunk_size, chunk.offset)?
            } else {
                format::checksum(&stored, chunk.offset, "uncompressed chunk")?;
                stored[..stored.len() - 4].to_vec()
            };
            let logical_size =
                (self.len() - index as u64 * chunk_size as u64).min(chunk_size as u64) as usize;
            // Some writers pad the final chunk to the full chunk size.
            if data.len() != logical_size
                && !(index + 1 == self.chunks.len() && data.len() == chunk_size)
                && !(self.metadata.media_type == 0x0e
                    && index + 1 == self.chunks.len()
                    && data.len()
                        == logical_size.div_ceil(self.metadata.bytes_per_sector as usize)
                            * self.metadata.bytes_per_sector as usize)
            {
                return Err(invalid(
                    chunk.offset,
                    format!(
                        "decoded chunk has {} bytes, expected {logical_size}",
                        data.len()
                    ),
                ));
            }
            // Keep at most 256 chunks / 8 MiB of decoded bytes. A chunk larger
            // than the budget is retained alone, as in the old one-chunk cache;
            // its size is still checked against OpenOptions::max_chunk_size.
            while !self.cached.is_empty()
                && (self.cached.len() >= 256
                    || self.cached_bytes.saturating_add(data.len()) > 8 * 1024 * 1024)
            {
                let (_, evicted) = self.cached.pop_back().unwrap();
                self.cached_bytes -= evicted.len();
            }
            self.cached_bytes += data.len();
            self.cached.push_front((index, data));
        }
        Ok(&self.cached.front().expect("chunk cache was populated").1)
    }

    /// Read every chunk, check its checksum, and compare available acquisition
    /// MD5/SHA1 digests. Does not change the stream position. If neither digest
    /// is stored, the report still contains computed hashes and checksum results.
    pub fn verify(&mut self) -> Result<Verification> {
        self.export_to(&mut io::sink())
    }

    /// Export all decoded media while checking chunk checksums and available
    /// acquisition digests in the same pass. Leaves the stream position intact.
    /// On error, the caller must discard the partial output.
    pub fn export_to(&mut self, output: &mut impl Write) -> Result<Verification> {
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut bytes_read = 0;
        for index in 0..self.chunks.len() {
            let remaining = self.len() - bytes_read;
            // Re-read even a cached chunk so verification covers current bytes.
            self.cached.clear();
            self.cached_bytes = 0;
            let data = self.chunk(index)?;
            let count = remaining.min(data.len() as u64) as usize;
            md5.update(&data[..count]);
            sha1.update(&data[..count]);
            output.write_all(&data[..count])?;
            bytes_read += count as u64;
        }
        let md5: [u8; 16] = md5.finalize().into();
        let sha1: [u8; 20] = sha1.finalize().into();
        if let Some(stored) = self.metadata.md5 {
            compare_digest("MD5", &stored, &md5)?;
        }
        if let Some(stored) = self.metadata.sha1 {
            compare_digest("SHA1", &stored, &sha1)?;
        }
        Ok(Verification {
            bytes_read,
            md5,
            sha1,
            md5_verified: self.metadata.md5.is_some(),
            sha1_verified: self.metadata.sha1.is_some(),
        })
    }
}

/// Lowercase hexadecimal representation of a binary digest or identifier.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String");
    }
    output
}

fn compare_digest(algorithm: &'static str, stored: &[u8], calculated: &[u8]) -> Result<()> {
    if stored != calculated {
        return Err(Error::DigestMismatch {
            algorithm,
            stored: hex(stored),
            calculated: hex(calculated),
        });
    }
    Ok(())
}

impl DiskImage for EwfImage {
    fn len(&self) -> u64 {
        self.metadata.media_size
    }
    fn sector_size(&self) -> u32 {
        self.metadata.bytes_per_sector
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let total = self.len().saturating_sub(offset).min(buffer.len() as u64) as usize;
        let chunk_size = self.metadata.chunk_size();
        let mut count = 0;
        while count < total {
            let current = offset + count as u64;
            let index = (current / chunk_size) as usize;
            let within = (current % chunk_size) as usize;
            let data = self.chunk(index)?;
            let size = (data.len() - within).min(total - count);
            buffer[count..count + size].copy_from_slice(&data[within..within + size]);
            count += size;
        }
        Ok(total)
    }
}

impl Read for EwfImage {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Return at most one chunk so a later chunk error never consumes bytes
        // without advancing the sequential position (the Read contract).
        let remaining_in_chunk =
            self.metadata.chunk_size() - self.position % self.metadata.chunk_size();
        let limit = buffer.len().min(remaining_in_chunk as usize);
        let count = self.read_at(self.position, &mut buffer[..limit])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for EwfImage {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => Some(value),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.len().checked_add_signed(delta),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before zero or beyond u64",
            )
        })?;
        self.position = next;
        Ok(next)
    }
}
