//! Apple decmpfs transparent compression with bounded, lazy resource-fork reads.
use super::indexed::{Data, IndexedFs, bad, read_data};
use crate::{Error, Result, image::DiskImage, wire::*};
use std::io::{self, Write};
#[derive(Clone)]
pub(super) struct Compressed {
    method: u32,
    source: Data,
    chunks: Vec<(u64, usize)>,
    size: u64,
}
struct Limited {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for Limited {
    fn write(&mut self, d: &[u8]) -> io::Result<usize> {
        if d.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("decoded data exceeds declared size"));
        }
        self.bytes.extend_from_slice(d);
        Ok(d.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn decode(method: u32, encoded: &[u8], size: usize) -> Result<Vec<u8>> {
    let marker = match method {
        3 | 4 | 11 | 12 => 0xff,
        7 | 8 => 6,
        9 | 10 => 0xcc,
        _ => 0,
    };
    let out = if encoded.first() == Some(&marker) {
        encoded[1..].to_vec()
    } else if method == 3 || method == 4 {
        let mut out = vec![0; size + 1];
        let mut d = flate2::Decompress::new(true);
        let status = d
            .decompress(encoded, &mut out, flate2::FlushDecompress::Finish)
            .map_err(|e| bad(format!("decmpfs zlib: {e}")))?;
        if status != flate2::Status::StreamEnd
            || d.total_in() != encoded.len() as u64
            || d.total_out() != size as u64
        {
            return Err(bad("decmpfs zlib size/termination"));
        }
        out.truncate(size);
        out
    } else if [7, 8, 11, 12].contains(&method) {
        let wrapped;
        let mut input = if method == 7 || method == 8 {
            let mut d = b"bvxn".to_vec();
            d.extend_from_slice(&(size as u32).to_le_bytes());
            d.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            d.extend_from_slice(encoded);
            d.extend_from_slice(b"bvx$");
            wrapped = d;
            wrapped.as_slice()
        } else {
            encoded
        };
        let mut output = Limited {
            bytes: Vec::with_capacity(size),
            limit: size,
        };
        let input_len = input.len();
        let (consumed, written) = lzfse_rust::LzfseRingDecoder::default()
            .decode(&mut input, &mut output)
            .map_err(|e| bad(format!("decmpfs LZFSE/LZVN: {e}")))?;
        if consumed != input_len as u64 || written != size as u64 {
            return Err(bad("decmpfs LZFSE/LZVN size/termination"));
        }
        output.bytes
    } else {
        return Err(bad("decmpfs raw data marker"));
    };
    if out.len() != size {
        return Err(bad("decmpfs decoded length mismatch"));
    }
    Ok(out)
}
fn read(image: &mut dyn DiskImage, d: &Data, at: u64, size: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; size];
    read_data(image, d, at, &mut out)?;
    Ok(out)
}
impl Compressed {
    pub(super) fn read_at(
        &self,
        image: &mut dyn DiskImage,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let count = self.size.saturating_sub(offset).min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        let mut done = 0;
        while done < count {
            let at = offset + done as u64;
            let block = at / 65536;
            let inside = (at % 65536) as usize;
            let &(pos, n) = self
                .chunks
                .get(block as usize)
                .ok_or_else(|| bad("decmpfs missing chunk"))?;
            let expected = (self.size - block * 65536).min(65536) as usize;
            let encoded = read(image, &self.source, pos, n)?;
            let decoded = decode(self.method, &encoded, expected)?;
            let n = (expected - inside).min(count - done);
            buffer[done..done + n].copy_from_slice(&decoded[inside..inside + n]);
            done += n;
        }
        Ok(count)
    }
}
pub(super) fn apply(fs: &mut IndexedFs<'_>) -> Result<()> {
    let ids: Vec<_> = fs
        .nodes
        .iter()
        .filter(|(_, n)| {
            n.data.contains_key("com.apple.decmpfs")
                && matches!(
                    n.data[""].unsupported.as_deref(),
                    Some("APFS compressed file" | "HFS compressed file")
                )
        })
        .map(|(&id, _)| id)
        .collect();
    for id in ids {
        let attr = fs.nodes[&id].data["com.apple.decmpfs"].clone();
        if attr.size > fs.limits.max_metadata_bytes as u64 || attr.size < 16 {
            return Err(bad("decmpfs attribute size"));
        }
        let header = read(fs.image, &attr, 0, attr.size as usize)?;
        if &header[..4] != b"fpmc" {
            return Err(bad("decmpfs magic"));
        }
        let method = u32le(&header, 4)?;
        let size = u64le(&header, 8)?;
        let data = if [3, 7, 9, 11].contains(&method) {
            if size > fs.limits.max_metadata_bytes as u64 {
                return Err(Error::ResourceLimit("decmpfs inline decoded size"));
            }
            let inline = decode(method, &header[16..], size as usize)?;
            fs.reserve_data(inline.len())?;
            Data {
                size,
                inline: Some(inline),
                ..Data::default()
            }
        } else if [4, 8, 10, 12].contains(&method) {
            let source = fs.nodes[&id]
                .data
                .get("com.apple.ResourceFork")
                .ok_or_else(|| bad("decmpfs resource fork missing"))?
                .clone();
            let count = size.div_ceil(65536);
            if count > fs.limits.max_chain_length as u64
                || count > fs.limits.max_metadata_bytes as u64 / 32
            {
                return Err(Error::ResourceLimit("decmpfs resource chunks"));
            }
            let mut chunks = vec![];
            let table_end;
            if method == 4 {
                let resource_header = read(fs.image, &source, 0, 16)?;
                let base = u64::from(u32be(&resource_header, 0)?) + 4;
                let n = u32le(&read(fs.image, &source, base, 4)?, 0)? as u64;
                if n != count {
                    return Err(bad("decmpfs zlib chunk count"));
                }
                let table = read(fs.image, &source, base + 4, count as usize * 8)?;
                table_end = base + 4 + count * 8;
                for e in table.as_chunks::<8>().0 {
                    chunks.push((base + u64::from(u32le(e, 0)?), u32le(e, 4)? as usize));
                }
            } else {
                let table = read(fs.image, &source, 0, (count as usize + 1) * 4)?;
                table_end = (count + 1) * 4;
                if u32le(&table, 0)? as u64 != table_end {
                    return Err(bad("decmpfs resource table size"));
                }
                for i in 0..count as usize {
                    let at = u64::from(u32le(&table, i * 4)?);
                    let end = u64::from(u32le(&table, (i + 1) * 4)?);
                    let n = end
                        .checked_sub(at)
                        .ok_or_else(|| bad("decmpfs decreasing chunk offsets"))?;
                    chunks.push((at, n as usize));
                }
            }
            let mut end = table_end;
            for &(at, n) in &chunks {
                if at < end || n == 0 || n > 65536 + 4096 {
                    return Err(bad("decmpfs overlapping or oversized chunk"));
                }
                checked_region(at, n as u64, source.size, "decmpfs resource chunk")?;
                end = at + n as u64;
            }
            fs.reserve_data(chunks.len() * 32 + source.runs.len() * 32)?;
            Data {
                size,
                compressed: Some(Box::new(Compressed {
                    method,
                    source,
                    chunks,
                    size,
                })),
                ..Data::default()
            }
        } else {
            Data {
                size,
                unsupported: Some(format!("decmpfs compression method {method}")),
                ..Data::default()
            }
        };
        let node = fs.nodes.get_mut(&id).unwrap();
        node.meta.size = size;
        node.data.insert(String::new(), data);
    }
    Ok(())
}
