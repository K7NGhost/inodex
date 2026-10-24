//! AFF segment framing, AFD sets and AFM external raw data, without AFFLIB FFI.
use super::{DiskImage, SplitRawImage, common::*};
use crate::{Error, Result, wire::*};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::{collections::BTreeMap, path::Path};
#[derive(Clone, Copy, Debug)]
struct Page {
    source: usize,
    offset: u64,
    len: usize,
    flags: u32,
}
#[derive(Debug)]
pub struct AffImage {
    sources: Vec<Source>,
    size: u64,
    sector: u32,
    page_size: usize,
    pages: BTreeMap<u64, Page>,
    metadata: BTreeMap<String, (u32, Vec<u8>)>,
    raw: Option<SplitRawImage>,
    cache: Option<(u64, Vec<u8>)>,
    kind: &'static str,
    decode_limit: usize,
}
impl AffImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_limits(path, Limits::default())
    }
    pub fn with_limits(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        let path = path.as_ref();
        let is_afm = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("afm"));
        let mut paths = vec![];
        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let p = entry?.path();
                if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("aff")) {
                    if paths.len() >= limits.max_segments {
                        return Err(Error::ResourceLimit("AFF members"));
                    }
                    paths.push(p);
                }
            }
            paths.sort();
            if paths.is_empty() {
                return Err(bad("AFD", "no AFF members"));
            }
            let numbered: Option<Vec<usize>> = paths
                .iter()
                .map(|p| p.file_stem()?.to_str()?.strip_prefix("file_")?.parse().ok())
                .collect();
            if let Some(mut numbers) = numbered {
                numbers.sort_unstable();
                if numbers.iter().enumerate().any(|(i, n)| i != *n) {
                    return Err(bad("AFD", "missing/duplicate numbered member"));
                }
            }
        } else {
            paths.push(path.to_path_buf());
        }
        if paths.len() > limits.max_segments {
            return Err(Error::ResourceLimit("AFF members"));
        }
        let mut sources = vec![];
        let mut pages = BTreeMap::new();
        let mut metadata: BTreeMap<String, (u32, Vec<u8>)> = BTreeMap::new();
        let mut budget = 0usize;
        for p in &paths {
            let mut source = Source::open(p)?;
            if source.read(0, 8)? != b"AFF10\r\n\0" {
                return Err(bad("AFF", "file signature"));
            }
            let index = sources.len();
            let mut at = 8u64;
            while at < source.len {
                let h = source.read(at, 16)?;
                if &h[..4] != b"AFF\0" {
                    return Err(bad("AFF", "segment signature"));
                }
                let name_len = u32be(&h, 4)? as usize;
                let len = u32be(&h, 8)? as usize;
                let flags = u32be(&h, 12)?;
                if name_len > 1024 {
                    return Err(Error::ResourceLimit("AFF segment name"));
                }
                let end = at
                    .checked_add(24 + name_len as u64 + len as u64)
                    .ok_or_else(|| bad("AFF", "segment size overflow"))?;
                checked_region(at, end - at, source.len, "AFF segment")?;
                let tail = source.read(end - 8, 8)?;
                if &tail[..4] != b"ATT\0" || u64::from(u32be(&tail, 4)?) != end - at {
                    return Err(bad("AFF", "segment trailer length/signature"));
                }
                let name = String::from_utf8(source.read(at + 16, name_len)?)
                    .map_err(|_| bad("AFF", "invalid segment name"))?;
                if name.contains('\0') {
                    return Err(bad("AFF", "NUL in segment name"));
                }
                if name.ends_with("/aes256") || name == "affkey_aes256" {
                    return Err(Error::Unsupported("encrypted AFF segments".into()));
                }
                let data_at = at + 16 + name_len as u64;
                let number = name
                    .strip_prefix("page")
                    .or_else(|| name.strip_prefix("seg"))
                    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    .map(|s| {
                        s.parse::<u64>()
                            .map_err(|_| bad("AFF", "page number overflow"))
                    })
                    .transpose()?;
                if let Some(number) = number {
                    if len
                        > limits
                            .max_decoded_block
                            .saturating_add(limits.max_decoded_block / 100)
                            .saturating_add(1024)
                    {
                        return Err(Error::ResourceLimit("AFF encoded page"));
                    }
                    budget = budget
                        .checked_add(40)
                        .ok_or(Error::ResourceLimit("AFF index"))?;
                    if let Some(old) = pages.insert(
                        number,
                        Page {
                            source: index,
                            offset: data_at,
                            len,
                            flags,
                        },
                    ) && old.source != index
                    {
                        return Err(bad("AFD", "duplicate data page across members"));
                    }
                } else if !name.is_empty() {
                    budget = budget
                        .checked_add(name.len() + len + 32)
                        .ok_or(Error::ResourceLimit("AFF metadata"))?;
                    if budget > limits.max_metadata_bytes {
                        return Err(Error::ResourceLimit("AFF metadata"));
                    }
                    let data = source.read(data_at, len)?;
                    if ["pagesize", "sectorsize", "imagesize"].contains(&name.as_str())
                        && let Some(old) = metadata.get(&name)
                        && old != &(flags, data.clone())
                    {
                        return Err(bad("AFD", "member geometry disagrees"));
                    }
                    metadata.insert(name, (flags, data));
                }
                if budget > limits.max_metadata_bytes {
                    return Err(Error::ResourceLimit("AFF index/metadata"));
                }
                at = end;
            }
            sources.push(source);
        }
        let page_size = metadata
            .get("pagesize")
            .or_else(|| metadata.get("segsize"))
            .ok_or_else(|| bad("AFF", "missing page size"))?
            .0 as usize;
        let sector = metadata.get("sectorsize").map_or(512, |v| v.0);
        let (flag, quad) = metadata
            .get("imagesize")
            .ok_or_else(|| bad("AFF", "missing image size"))?;
        if *flag != 2 || quad.len() != 8 {
            return Err(bad("AFF", "image-size quadword"));
        }
        let size = u64::from(u32be(quad, 0)?) | (u64::from(u32be(quad, 4)?) << 32);
        if !page_size.is_power_of_two()
            || page_size < 512
            || page_size > limits.max_decoded_block
            || !sector.is_power_of_two()
            || !(512..=65536).contains(&sector)
            || page_size < sector as usize
        {
            return Err(bad("AFF", "page/sector geometry"));
        }
        if pages
            .last_key_value()
            .is_some_and(|(number, _)| *number >= size.div_ceil(page_size as u64))
        {
            return Err(bad("AFF", "page outside media"));
        }
        let raw = if is_afm {
            if !pages.is_empty() {
                return Err(bad("AFM", "metadata file contains data pages"));
            }
            let ext = std::str::from_utf8(
                &metadata
                    .get("raw_image_file_extension")
                    .ok_or_else(|| bad("AFM", "missing raw extension"))?
                    .1,
            )
            .map_err(|_| bad("AFM", "raw extension encoding"))?;
            if ext.is_empty() || ext.len() > 8 || !ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(bad("AFM", "invalid raw extension"));
            }
            let first = path.with_extension(ext);
            let parts = super::split_raw::discover(&first, &limits)?;
            let raw = SplitRawImage::with_limits(parts, sector, limits.clone())?;
            if raw.len() != size {
                return Err(bad("AFM", "raw data/image size mismatch"));
            }
            Some(raw)
        } else {
            None
        };
        Ok(Self {
            sources,
            size,
            sector,
            page_size,
            pages,
            metadata,
            raw,
            cache: None,
            kind: if is_afm {
                "AFM"
            } else if path.is_dir() {
                "AFD"
            } else {
                "AFF"
            },
            decode_limit: limits.max_decoded_block,
        })
    }
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn metadata(&self) -> &BTreeMap<String, (u32, Vec<u8>)> {
        &self.metadata
    }
    pub fn stored_md5(&self) -> Result<Option<[u8; 16]>> {
        self.hash("md5")
    }
    pub fn stored_sha1(&self) -> Result<Option<[u8; 20]>> {
        self.hash("sha1")
    }
    pub fn stored_sha256(&self) -> Result<Option<[u8; 32]>> {
        self.hash("sha256")
    }
    fn hash<const N: usize>(&self, name: &str) -> Result<Option<[u8; N]>> {
        self.metadata
            .get(name)
            .map(|(_, d)| {
                d.as_slice()
                    .try_into()
                    .map_err(|_| bad("AFF", "digest size"))
            })
            .transpose()
    }
    fn verify_page(&self, n: u64, data: &[u8]) -> Result<()> {
        for (suffix, actual) in [
            ("md5", Md5::digest(data).to_vec()),
            ("sha1", Sha1::digest(data).to_vec()),
            ("sha256", Sha256::digest(data).to_vec()),
        ] {
            if let Some((_, expected)) = self.metadata.get(&format!("page{n}_{suffix}"))
                && expected != &actual
            {
                return Err(Error::DigestMismatch {
                    algorithm: suffix,
                    stored: super::super::ewf::hex(expected),
                    calculated: super::super::ewf::hex(&actual),
                });
            }
        }
        Ok(())
    }
}
impl DiskImage for AffImage {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let n = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let number = at / self.page_size as u64;
            let within = (at % self.page_size as u64) as usize;
            let count = (n - done).min(self.page_size - within);
            if self.cache.as_ref().is_none_or(|(p, _)| *p != number) {
                let minimum = (self.size - number * self.page_size as u64)
                    .min(self.page_size as u64) as usize;
                let data = if let Some(raw) = self.raw.as_mut() {
                    let mut data = vec![0; minimum];
                    raw.read_exact_at(number * self.page_size as u64, &mut data)?;
                    data
                } else if let Some(page) = self.pages.get(&number) {
                    let encoded = self.sources[page.source].read(page.offset, page.len)?;
                    if page.flags & 1 == 0 {
                        if encoded.len() < minimum || encoded.len() > self.page_size {
                            return Err(bad("AFF", "plain page length"));
                        }
                        encoded
                    } else {
                        match page.flags & 0xf0 {
                            0 => inflate(&encoded, minimum, self.page_size)?,
                            0x20 => {
                                let size = u64le(&encoded, 5)?;
                                if size < minimum as u64 || size > self.page_size as u64 {
                                    return Err(bad("AFF", "LZMA decoded page size"));
                                }
                                let mut output = vec![0; size as usize];
                                let mut writer = std::io::Cursor::new(output.as_mut_slice());
                                lzma_rs::lzma_decompress_with_options(
                                    &mut std::io::Cursor::new(&encoded),
                                    &mut writer,
                                    &lzma_rs::decompress::Options {
                                        memlimit: Some(self.decode_limit),
                                        ..Default::default()
                                    },
                                )
                                .map_err(|e| bad("AFF", format!("LZMA: {e}")))?;
                                if writer.position() != size {
                                    return Err(bad("AFF", "LZMA decoded length mismatch"));
                                }
                                output
                            }
                            0x30 => {
                                if encoded.len() != 4 {
                                    return Err(bad("AFF", "zero-page length"));
                                }
                                let zeros = u32be(&encoded, 0)? as usize;
                                if zeros < minimum || zeros > self.page_size {
                                    return Err(bad("AFF", "zero-page decoded size"));
                                }
                                vec![0; zeros]
                            }
                            _ => {
                                return Err(Error::Unsupported(
                                    "AFF page compression algorithm".into(),
                                ));
                            }
                        }
                    }
                } else {
                    vec![0; minimum]
                };
                self.verify_page(number, &data)?;
                self.cache = Some((number, data));
            }
            buffer[done..done + count]
                .copy_from_slice(&self.cache.as_ref().unwrap().1[within..within + count]);
            done += count;
        }
        Ok(n)
    }
}
