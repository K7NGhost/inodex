//! EWF-L01 logical evidence: immutable recorded tree and chunk-backed content.
use super::{
    DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, StreamInfo, Times,
    indexed::{metadata, utc},
};
use crate::{
    Error, Result,
    ewf::{EwfImage, Verification},
    image::DiskImage,
    wire::*,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
#[derive(Clone)]
struct Extent {
    at: u64,
    size: u64,
    fill: Option<u8>,
}
struct Entry {
    meta: Metadata,
    children: Vec<DirEntry>,
    extents: Vec<Extent>,
    values: Vec<String>,
}
pub struct LogicalEvidenceFs {
    image: EwfImage,
    info: FsInfo,
    entries: BTreeMap<u64, Entry>,
    columns: Vec<String>,
}
fn bad(s: impl Into<String>) -> Error {
    corrupt("L01", 0, s)
}
fn number(s: &str) -> Result<u64> {
    s.parse().map_err(|_| bad("invalid decimal field"))
}
fn hex(s: &str) -> Result<u64> {
    u64::from_str_radix(s, 16).map_err(|_| bad("invalid extent field"))
}
impl LogicalEvidenceFs {
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        Self::with_options(path, limits, crate::ewf::OpenOptions::default())
    }
    /// Configure both the EWF chunk/tree bounds and the retained filesystem index.
    pub fn with_options(
        path: impl AsRef<Path>,
        limits: Limits,
        options: crate::ewf::OpenOptions,
    ) -> Result<Self> {
        let mut image = EwfImage::open_logical_with_options(path.as_ref(), &options)?;
        let raw = image
            .logical_tree
            .take()
            .ok_or_else(|| bad("missing tree"))?;
        if raw.len() > limits.max_metadata_bytes {
            return Err(Error::ResourceLimit("L01 tree bytes"));
        }
        if !raw.len().is_multiple_of(2) {
            return Err(bad("odd UTF-16 tree byte count"));
        }
        let units: Vec<_> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        let text = String::from_utf16(&units)
            .map_err(|_| Error::Unsupported("L01 unpaired UTF-16 surrogates".into()))?;
        let mut lines = text.lines().map(|s| s.trim_end_matches('\r'));
        lines
            .find(|s| *s == "entry")
            .ok_or_else(|| bad("missing entry category"))?;
        lines
            .next()
            .ok_or_else(|| bad("missing entry category counts"))?;
        let keys: Vec<_> = lines
            .next()
            .ok_or_else(|| bad("missing entry keys"))?
            .split('\t')
            .take(257)
            .collect();
        if !["p", "n", "ls", "be"].iter().all(|k| keys.contains(k)) {
            return Err(Error::Unsupported("L01 entry schema".into()));
        }
        if keys.len() > 256 || keys.iter().any(|k| k.is_empty() || k.len() > 64) {
            return Err(Error::ResourceLimit("L01 field schema"));
        }
        if keys.iter().copied().collect::<BTreeSet<_>>().len() != keys.len() {
            return Err(bad("duplicate entry key"));
        }
        let mut entries: BTreeMap<u64, Entry> = BTreeMap::new();
        let mut stack: Vec<(u64, u64)> = vec![];
        let mut budget = keys
            .iter()
            .map(|k| k.len() + std::mem::size_of::<String>())
            .sum::<usize>();
        while let Some(count_line) = lines.next().filter(|s| !s.is_empty()) {
            if entries.len() >= limits.max_directory_entries {
                return Err(Error::ResourceLimit("L01 entries"));
            }
            let counts: Vec<_> = count_line.split('\t').take(3).collect();
            if counts.len() != 2 {
                return Err(bad("invalid tree counts"));
            }
            let children = number(counts[1])?;
            if children > limits.max_directory_entries as u64 {
                return Err(Error::ResourceLimit("L01 child count"));
            }
            let value_line = lines.next().ok_or_else(|| bad("truncated entry"))?;
            let values: Vec<_> = value_line.split('\t').take(keys.len() + 1).collect();
            if values.len() != keys.len() {
                return Err(bad("entry key/value count mismatch"));
            }
            budget = budget
                .checked_add(value_line.len() + values.len() * std::mem::size_of::<String>() + 512)
                .ok_or(Error::ResourceLimit("L01 metadata"))?;
            if budget > limits.max_metadata_bytes {
                return Err(Error::ResourceLimit("L01 metadata"));
            }
            let get = |k: &str| keys.iter().position(|v| *v == k).map_or("", |i| values[i]);
            let flags = if get("opr").is_empty() {
                0
            } else {
                number(get("opr"))?
            };
            let directory = get("p") == "1" || flags & 0x02000000 != 0;
            if children > 0 && !directory {
                return Err(bad("file has children"));
            }
            let size = if get("ls").is_empty() {
                0
            } else {
                number(get("ls"))?
            };
            let id = entries.len() as u64;
            let mut meta = metadata(
                id,
                if directory { 0x4000 } else { 0x8000 },
                if directory { 0 } else { size },
            );
            meta.mode = None;
            meta.allocated = flags & 0x80 == 0;
            let timestamp = |key| -> Result<_> {
                let s = get(key);
                if s.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(utc(
                        s.parse().map_err(|_| bad("invalid timestamp"))?,
                        0,
                    )?))
                }
            };
            meta.times = Times {
                created: timestamp("cr")?,
                accessed: timestamp("ac")?,
                modified: timestamp("wr")?,
                changed: timestamp("mo")?,
            };
            let mut extents = vec![];
            let mut covered = 0u64;
            if size > 0 {
                let mut parts = get("be").split_whitespace();
                let count = number(parts.next().ok_or_else(|| bad("missing binary extents"))?)?;
                if count > limits.max_chain_length as u64 {
                    return Err(Error::ResourceLimit("L01 extents"));
                }
                budget = budget
                    .checked_add(count as usize * std::mem::size_of::<Extent>())
                    .ok_or(Error::ResourceLimit("L01 extents"))?;
                if budget > limits.max_metadata_bytes {
                    return Err(Error::ResourceLimit("L01 extents"));
                }
                for _ in 0..count {
                    let first = parts.next().ok_or_else(|| bad("truncated binary extent"))?;
                    if first == "S" {
                        return Err(Error::Unsupported(
                            "L01 explicit sparse extent encoding".into(),
                        ));
                    }
                    let mut pos = hex(first)?;
                    let mut n = hex(parts.next().ok_or_else(|| bad("missing extent size"))?)?;
                    let duplicate = get("du");
                    if !duplicate.is_empty() && duplicate != "-1" {
                        if count != 1 {
                            return Err(Error::Unsupported(
                                "multi-extent L01 duplicate data".into(),
                            ));
                        }
                        pos = number(duplicate)?;
                        n = size;
                    }
                    let fill = if flags & 0x04000000 != 0
                        && n == 1
                        && (duplicate.is_empty() || duplicate == "-1")
                    {
                        let mut byte = [0];
                        image.read_exact_at(pos, &mut byte)?;
                        n = size;
                        Some(byte[0])
                    } else {
                        None
                    };
                    if fill.is_none() {
                        checked_region(pos, n, image.len(), "L01 extent")?;
                    }
                    covered = covered
                        .checked_add(n)
                        .ok_or_else(|| bad("extent length overflow"))?;
                    extents.push(Extent {
                        at: pos,
                        size: n,
                        fill,
                    });
                }
                if parts.next().is_some() || covered < size {
                    return Err(bad("invalid extent coverage"));
                }
                if covered != size && !(size == 0 && covered == 1) {
                    return Err(bad("extent/file size mismatch"));
                }
            }
            if directory && size > 0 {
                meta.streams.push(StreamInfo {
                    name: "L01.data".into(),
                    size,
                    resident: false,
                    compressed: false,
                    encrypted: false,
                });
            }
            while stack.last().is_some_and(|(_, n)| *n == 0) {
                stack.pop();
            }
            if let Some((parent, left)) = stack.last_mut() {
                *left -= 1;
                let original = get("n");
                budget = budget
                    .checked_add(original.len().saturating_mul(4) + 96)
                    .ok_or(Error::ResourceLimit("L01 names"))?;
                if budget > limits.max_metadata_bytes {
                    return Err(Error::ResourceLimit("L01 names"));
                }
                let name = original
                    .replace('%', "%25")
                    .replace('/', "%2F")
                    .replace('\0', "%00");
                let name = if name.is_empty() {
                    "%EMPTY".to_owned()
                } else if name == "." {
                    "%2E".to_owned()
                } else if name == ".." {
                    "%2E%2E".to_owned()
                } else {
                    name
                };
                let p = entries.get_mut(parent).unwrap();
                if p.children.iter().any(|e| e.name == name) {
                    return Err(bad("duplicate child name"));
                }
                p.children.push(DirEntry {
                    id,
                    name,
                    kind: meta.kind,
                    size: meta.size,
                    allocated: meta.allocated,
                    aliases: vec![],
                    raw_name: Some(original.as_bytes().to_vec()),
                });
            } else if id != 0 {
                return Err(bad("extra tree root"));
            }
            entries.insert(
                id,
                Entry {
                    meta,
                    children: vec![],
                    extents,
                    values: values.into_iter().map(str::to_owned).collect(),
                },
            );
            if children > 0 {
                stack.push((id, children));
            }
            if stack.len() > limits.max_tree_depth {
                return Err(Error::ResourceLimit("L01 tree depth"));
            }
        }
        if entries
            .get(&0)
            .is_none_or(|e| e.meta.kind != FileKind::Directory)
            || stack.iter().any(|(_, n)| *n != 0)
        {
            return Err(bad("incomplete logical tree"));
        }
        let info = FsInfo {
            filesystem: FsType::LogicalEvidence,
            label: String::new(),
            block_size: 0,
            total_bytes: image.len(),
            root_id: 0,
            needs_journal_recovery: false,
        };
        Ok(Self {
            image,
            info,
            entries,
            columns: keys.into_iter().map(str::to_owned).collect(),
        })
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    pub fn metadata(&self, id: u64) -> Result<Metadata> {
        Ok(self.entry(id)?.meta.clone())
    }
    /// Return owned copies of the original schema fields for one recorded entry.
    pub fn entry_fields(&self, id: u64) -> Result<BTreeMap<String, String>> {
        Ok(self
            .columns
            .iter()
            .cloned()
            .zip(self.entry(id)?.values.iter().cloned())
            .collect())
    }
    fn entry(&self, id: u64) -> Result<&Entry> {
        self.entries
            .get(&id)
            .ok_or_else(|| Error::NotFound(format!("L01 entry {id}")))
    }
    pub fn read_dir(&self, id: u64) -> Result<Vec<DirEntry>> {
        let e = self.entry(id)?;
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
        buffer: &mut [u8],
    ) -> Result<usize> {
        let e = self.entry(id)?;
        let size = if e.meta.kind == FileKind::Directory {
            if stream != Some("L01.data") {
                return Err(Error::NotDirectory(
                    "select L01.data to read directory-associated content".into(),
                ));
            }
            e.meta
                .streams
                .first()
                .ok_or_else(|| Error::NotFound("L01.data".into()))?
                .size
        } else {
            if stream.is_some_and(|s| !s.is_empty()) {
                return Err(Error::NotFound("L01 named stream".into()));
            }
            e.meta.size
        };
        let count = size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        let runs = e.extents.clone();
        let mut logical = 0;
        let mut done = 0;
        for run in runs {
            let pos = offset + done as u64;
            if pos >= logical && pos < logical + run.size && done < count {
                let inside = pos - logical;
                let n = (run.size - inside).min((count - done) as u64) as usize;
                if let Some(byte) = run.fill {
                    buffer[done..done + n].fill(byte);
                } else {
                    self.image
                        .read_exact_at(run.at + inside, &mut buffer[done..done + n])?;
                }
                done += n;
            }
            logical += run.size;
        }
        if done != count {
            return Err(bad("short file mapping"));
        }
        Ok(count)
    }
    pub fn verify(&mut self) -> Result<Verification> {
        use md5::{Digest, Md5};
        use sha1::Sha1;
        let report = self.image.verify()?;
        let ids: Vec<_> = self.entries.keys().copied().collect();
        let mut buffer = vec![0; 65536];
        for id in ids {
            let e = self.entry(id)?;
            let md5 = self
                .columns
                .iter()
                .position(|k| k == "ha")
                .map(|i| e.values[i].clone());
            let sha1 = self
                .columns
                .iter()
                .position(|k| k == "sha")
                .map(|i| e.values[i].clone());
            let stream = (e.meta.kind == FileKind::Directory).then_some("L01.data");
            if stream.is_some() && e.meta.streams.is_empty() {
                continue;
            }
            let mut m = Md5::new();
            let mut s = Sha1::new();
            let mut at = 0;
            loop {
                let n = self.read_file(id, stream, at, &mut buffer)?;
                if n == 0 {
                    break;
                }
                m.update(&buffer[..n]);
                s.update(&buffer[..n]);
                at += n as u64;
            }
            for (algorithm, stored, calculated) in [
                ("md5", md5, crate::ewf::hex(&m.finalize())),
                ("sha1", sha1, crate::ewf::hex(&s.finalize())),
            ] {
                if let Some(stored) =
                    stored.filter(|v| !v.is_empty() && v.bytes().any(|b| b != b'0'))
                    && !stored.eq_ignore_ascii_case(&calculated)
                {
                    return Err(Error::DigestMismatch {
                        algorithm,
                        stored,
                        calculated,
                    });
                }
            }
        }
        Ok(report)
    }
}
