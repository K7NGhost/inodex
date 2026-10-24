use crate::{Error, Result, wire::*};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_metadata_bytes: usize,
    pub max_segments: usize,
    pub max_decoded_block: usize,
    pub max_parent_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_metadata_bytes: 16 * 1024 * 1024,
            max_segments: 4096,
            max_decoded_block: 64 * 1024 * 1024,
            max_parent_depth: 32,
        }
    }
}
pub(super) fn bad(layer: &'static str, reason: impl Into<String>) -> Error {
    corrupt(layer, 0, reason)
}
#[derive(Debug)]
pub(super) struct Source {
    pub file: File,
    pub len: u64,
}
impl Source {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(bad("image", "source is not a regular file"));
        }
        Ok(Self {
            file,
            len: meta.len(),
        })
    }
    pub fn read(&mut self, at: u64, len: usize) -> Result<Vec<u8>> {
        checked_region(at, len as u64, self.len, "container")?;
        let mut d = vec![0; len];
        self.exact(at, &mut d)?;
        Ok(d)
    }
    pub fn exact(&mut self, at: u64, data: &mut [u8]) -> Result<()> {
        checked_region(at, data.len() as u64, self.len, "container")?;
        self.file.seek(SeekFrom::Start(at))?;
        self.file.read_exact(data)?;
        Ok(())
    }
}
pub(super) fn sector(n: u64) -> Result<u64> {
    n.checked_mul(512)
        .ok_or_else(|| bad("image", "sector offset overflow"))
}
pub(super) fn companion(base: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains(['\0', ':']) || name.starts_with(['/', '\\']) {
        return Err(Error::Unsupported(
            "absolute/remote container companion path; provide a local relative reference".into(),
        ));
    }
    let name = name.replace('\\', "/");
    let mut p = base
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(Error::Unsupported(
                    "container companion escapes its directory".into(),
                ));
            }
            _ => p.push(part),
        }
    }
    Ok(p)
}
pub(super) fn inflate(data: &[u8], minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; maximum];
    let mut decoder = flate2::Decompress::new(true);
    let status = decoder
        .decompress(data, &mut output, flate2::FlushDecompress::Finish)
        .map_err(|e| bad("compressed image", e.to_string()))?;
    if status != flate2::Status::StreamEnd
        || decoder.total_in() != data.len() as u64
        || decoder.total_out() < minimum as u64
        || decoder.total_out() > maximum as u64
    {
        return Err(bad(
            "compressed image",
            "invalid compressed block length/termination",
        ));
    }
    output.truncate(decoder.total_out() as usize);
    Ok(output)
}
