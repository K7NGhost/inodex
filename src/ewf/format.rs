//! EWF v1 wire format. All offsets here are relative to a segment file.
//! Format reference: libyal/libewf's Expert Witness Compression Format document.

use super::{Chunk, EwfImage, Metadata, OpenOptions, SectionInfo, SectorRange, Segment};
use crate::{Error, Result, error::invalid};
use flate2::{Decompress, FlushDecompress, Status};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    ops::Range,
    path::{Path, PathBuf},
};

const SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
const DESCRIPTOR_SIZE: u64 = 76;

pub(super) fn open(options: &OpenOptions, paths: Vec<PathBuf>, discover: bool) -> Result<EwfImage> {
    open_mode(options, paths, discover, false)
}

pub(super) fn open_mode(
    options: &OpenOptions,
    paths: Vec<PathBuf>,
    discover: bool,
    logical: bool,
) -> Result<EwfImage> {
    if paths.is_empty() || paths.len() > u16::MAX as usize {
        return Err(invalid(0, "expected between 1 and 65535 segments"));
    }
    let mut segments = paths
        .into_iter()
        .map(|p| open_segment(p, logical))
        .collect::<Result<Vec<_>>>()?;
    segments.sort_by_key(|s| s.number);
    let first_path = segments[0].path.clone();
    let mut image = EwfImage {
        segments,
        metadata: Metadata::default(),
        sections: Vec::new(),
        chunks: Vec::new(),
        position: 0,
        cached: std::collections::VecDeque::new(),
        cached_bytes: 0,
        logical_tree: None,
    };
    let mut index = 0;
    loop {
        let expected =
            u16::try_from(index + 1).map_err(|_| Error::ResourceLimit("segment count"))?;
        if image.segments[index].number != expected {
            return Err(invalid(
                9,
                format!(
                    "expected segment {expected}, found {} (missing or duplicate segment)",
                    image.segments[index].number
                ),
            ));
        }
        let done = parse_segment(&mut image, index, options, logical)?;
        if done {
            if index + 1 != image.segments.len() {
                return Err(invalid(0, "extra segments supplied after the done marker"));
            }
            break;
        }
        if index + 1 == image.segments.len() {
            let number = expected
                .checked_add(1)
                .ok_or(Error::ResourceLimit("segment count"))?;
            let mut path = next_segment_path(&first_path, number)?;
            if !discover {
                return Err(Error::MissingSegment { number, path });
            }
            if !path.exists() {
                // Permit mixed upper/lowercase extensions on case-sensitive hosts.
                let alternate = path.with_extension(
                    path.extension()
                        .unwrap()
                        .to_string_lossy()
                        .to_ascii_lowercase(),
                );
                if alternate.exists() {
                    path = alternate;
                } else {
                    let alternate = path.with_extension(
                        path.extension()
                            .unwrap()
                            .to_string_lossy()
                            .to_ascii_uppercase(),
                    );
                    if alternate.exists() {
                        path = alternate;
                    } else {
                        return Err(Error::MissingSegment { number, path });
                    }
                }
            }
            image.segments.push(open_segment(path, logical)?);
        }
        index += 1;
    }
    if image.metadata.bytes_per_sector == 0 {
        return Err(invalid(13, "missing volume geometry"));
    }
    if logical {
        let tree = image
            .logical_tree
            .as_ref()
            .ok_or_else(|| invalid(0, "missing logical file tree"))?;
        let text = crate::wire::utf16(tree)?;
        let mut lines = text.lines();
        lines
            .find(|s| *s == "rec")
            .ok_or_else(|| invalid(0, "missing logical record category"))?;
        let keys: Vec<_> = lines
            .next()
            .ok_or_else(|| invalid(0, "missing logical record keys"))?
            .split('\t')
            .take(257)
            .collect();
        let value = lines
            .next()
            .ok_or_else(|| invalid(0, "missing logical record values"))?;
        let tb = keys
            .iter()
            .position(|s| *s == "tb")
            .ok_or_else(|| invalid(0, "missing logical media size"))?;
        image.metadata.media_size = value
            .split('\t')
            .nth(tb)
            .ok_or_else(|| invalid(0, "missing logical media size"))?
            .parse()
            .map_err(|_| invalid(0, "invalid logical media size"))?;
        image.metadata.chunk_count = u32::try_from(
            image
                .metadata
                .media_size
                .div_ceil(image.metadata.chunk_size()),
        )
        .map_err(|_| Error::ResourceLimit("logical chunk count"))?;
    }
    if image.chunks.len() as u64 != u64::from(image.metadata.chunk_count) {
        return Err(invalid(
            0,
            format!(
                "chunk count mismatch: indexed {}, declared {}",
                image.chunks.len(),
                image.metadata.chunk_count
            ),
        ));
    }
    for range in &image.metadata.acquisition_errors {
        if range.count == 0
            || range
                .start
                .checked_add(range.count)
                .is_none_or(|end| end > image.metadata.sector_count)
        {
            return Err(invalid(0, "acquisition error range is outside the media"));
        }
    }
    Ok(image)
}

fn open_segment(path: PathBuf, logical: bool) -> Result<Segment> {
    let mut file = File::open(&path)?;
    let size = file.metadata()?.len();
    if size < 13 {
        return Err(invalid(0, "truncated file header"));
    }
    let header = read_bytes(&mut file, 0, 13)?;
    if header.starts_with(b"EVF2")
        || (!logical && header.starts_with(b"LVF"))
        || header.starts_with(b"LEF")
    {
        return Err(Error::Unsupported(
            "only physical EWF v1 (E01) images are supported".into(),
        ));
    }
    let signature = if logical {
        b"LVF\x09\x0d\x0a\xff\x00"
    } else {
        SIGNATURE
    };
    if &header[..8] != signature || header[8] != 1 || header[11..13] != [0, 0] {
        return Err(invalid(0, "invalid E01 file header"));
    }
    let number = u16::from_le_bytes([header[9], header[10]]);
    if number == 0 {
        return Err(invalid(9, "segment numbers start at 1"));
    }
    Ok(Segment {
        file,
        path,
        number,
        size,
    })
}

fn next_segment_path(first: &Path, number: u16) -> Result<PathBuf> {
    let extension = first.extension().and_then(|e| e.to_str()).unwrap_or("E01");
    let letter = if extension.to_ascii_uppercase().starts_with('L') {
        b'L'
    } else {
        b'E'
    };
    let lower = extension
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_lowercase);
    let mut next = if number <= 99 {
        format!("{}{number:02}", char::from(letter))
    } else {
        let value = usize::from(number) - 100;
        let a = letter as usize + value / (26 * 26);
        if a > b'Z' as usize {
            return Err(Error::Unsupported(
                "segment discovery beyond .ZZZ; supply explicit paths".into(),
            ));
        }
        String::from_utf8(vec![
            a as u8,
            b'A' + ((value / 26) % 26) as u8,
            b'A' + (value % 26) as u8,
        ])
        .unwrap()
    };
    if lower {
        next.make_ascii_lowercase();
    }
    Ok(first.with_extension(next))
}

fn parse_segment(
    image: &mut EwfImage,
    index: usize,
    options: &OpenOptions,
    logical: bool,
) -> Result<bool> {
    let segment = &mut image.segments[index];
    let mut offset = 13_u64;
    let mut sectors: Option<Range<u64>> = None;
    let mut last_table: Option<Table> = None;
    let mut previous = String::new();
    loop {
        if image.sections.len() >= options.max_sections {
            return Err(Error::ResourceLimit("section count"));
        }
        if offset
            .checked_add(DESCRIPTOR_SIZE)
            .is_none_or(|end| end > segment.size)
        {
            return Err(invalid(
                offset,
                "truncated section descriptor or missing terminal marker",
            ));
        }
        let descriptor = read_bytes(&mut segment.file, offset, DESCRIPTOR_SIZE as usize)?;
        checksum(&descriptor, offset, "section descriptor")?;
        let terminator = descriptor[..16]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| invalid(offset, "unterminated section type"))?;
        let kind = std::str::from_utf8(&descriptor[..terminator])
            .map_err(|_| invalid(offset, "non-ASCII section type"))?;
        if kind.is_empty() || !kind.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(invalid(offset, "invalid section type"));
        }
        let next = u64_at(&descriptor, 16);
        let size = u64_at(&descriptor, 24);
        let terminal = kind == "done" || kind == "next";
        if terminal {
            if next != offset
                || (size != 0 && size != DESCRIPTOR_SIZE)
                || offset + DESCRIPTOR_SIZE != segment.size
            {
                return Err(invalid(
                    offset,
                    "invalid terminal section or trailing bytes",
                ));
            }
        } else if next < offset + DESCRIPTOR_SIZE
            || next > segment.size
            || (size != 0 && offset.checked_add(size) != Some(next))
        {
            return Err(invalid(
                offset,
                "section size/next offset is out of bounds or inconsistent",
            ));
        }
        let actual_size = if terminal {
            DESCRIPTOR_SIZE
        } else {
            next - offset
        };
        image.sections.push(SectionInfo {
            segment: segment.number,
            kind: kind.into(),
            offset,
            size: actual_size,
        });
        let payload = offset + DESCRIPTOR_SIZE..offset + actual_size;
        match kind {
            "volume" | "disk" | "data" => {
                let data = read_payload(segment, &payload, options.max_metadata_size)?;
                let geometry = geometry(&data, payload.start, options, logical)?;
                merge_geometry(&mut image.metadata, geometry, payload.start)?;
            }
            "header" | "header2" => {
                let data = read_payload(segment, &payload, options.max_metadata_size)?;
                let decoded = inflate(&data, options.max_metadata_size, payload.start)?;
                let text = if kind == "header2" {
                    decode_utf16(&decoded, payload.start)?
                } else {
                    decoded.iter().map(|&b| char::from(b)).collect()
                };
                parse_acquisition(
                    &mut image.metadata,
                    &text,
                    kind == "header2",
                    options.max_metadata_size,
                )?;
            }
            "sectors" => {
                if sectors.is_some() {
                    return Err(invalid(offset, "sectors section has no chunk table"));
                }
                sectors = Some(payload.clone());
            }
            "table" => {
                if image.metadata.bytes_per_sector == 0 {
                    return Err(invalid(offset, "chunk table precedes volume geometry"));
                }
                let table = read_table(segment, &payload, options)?;
                let inline_start = payload.start + 28 + table.entries.len() as u64 * 4;
                let range = if inline_start < payload.end {
                    if sectors.is_some() {
                        return Err(invalid(offset, "both inline and sectors chunk data"));
                    }
                    inline_start..payload.end
                } else {
                    sectors
                        .take()
                        .ok_or_else(|| invalid(offset, "chunk table has no sectors data"))?
                };
                append_chunks(
                    &mut image.chunks,
                    &table,
                    range,
                    segment.number,
                    &image.metadata,
                    options,
                    offset,
                )?;
                last_table = Some(table);
            }
            "table2" => {
                let table = read_table(segment, &payload, options)?;
                if previous != "table"
                    || last_table.as_ref() != Some(&table)
                    || payload.end - payload.start != 28 + table.entries.len() as u64 * 4
                {
                    return Err(invalid(
                        offset,
                        "backup table2 does not match the preceding table",
                    ));
                }
            }
            "hash" | "digest" => {
                let data = read_payload(segment, &payload, options.max_metadata_size)?;
                let expected = if kind == "hash" { 36 } else { 80 };
                if data.len() != expected {
                    return Err(invalid(offset, "invalid hash/digest section size"));
                }
                checksum(&data, payload.start, "media hash section")?;
                merge_hash(&mut image.metadata.md5, &data[..16], payload.start)?;
                if kind == "digest" {
                    merge_hash(&mut image.metadata.sha1, &data[16..36], payload.start + 16)?;
                }
            }
            "error2" => {
                let data = read_payload(segment, &payload, options.max_metadata_size)?;
                if data.len() < 524 {
                    return Err(invalid(offset, "truncated error2 section"));
                }
                checksum(&data[..520], payload.start, "acquisition errors header")?;
                let count = u32_at(&data, 0) as usize;
                if (data.len() - 524) / 8 != count || (data.len() - 524) % 8 != 0 {
                    return Err(invalid(offset, "invalid acquisition error count"));
                }
                checksum(
                    &data[520..],
                    payload.start + 520,
                    "acquisition errors array",
                )?;
                if image
                    .metadata
                    .acquisition_errors
                    .len()
                    .saturating_add(count)
                    > options.max_metadata_size / std::mem::size_of::<SectorRange>()
                {
                    return Err(Error::ResourceLimit("total acquisition error ranges"));
                }
                image
                    .metadata
                    .acquisition_errors
                    .try_reserve(count)
                    .map_err(|_| Error::ResourceLimit("acquisition errors"))?;
                for entry in data[520..data.len() - 4].as_chunks::<8>().0 {
                    image.metadata.acquisition_errors.push(SectorRange {
                        start: u64::from(u32_at(entry, 0)),
                        count: u64::from(u32_at(entry, 4)),
                    });
                }
            }
            "incomplete" => return Err(invalid(offset, "image acquisition is incomplete")),
            "ltree" if logical => {
                use md5::{Digest, Md5};
                let data = read_payload(segment, &payload, options.max_metadata_size)?;
                if data.len() < 48 {
                    return Err(invalid(offset, "truncated logical tree header"));
                }
                let size = u64_at(&data, 16);
                if size != data.len() as u64 - 48 {
                    return Err(invalid(offset, "logical tree length mismatch"));
                }
                let mut header = data[..48].to_vec();
                let stored = u32_at(&header, 24);
                header[24..28].fill(0);
                if adler2::adler32_slice(&header) != stored
                    || Md5::digest(&data[48..]).as_slice() != &data[..16]
                {
                    return Err(invalid(offset, "logical tree checksum mismatch"));
                }
                if image.logical_tree.replace(data[48..].to_vec()).is_some() {
                    return Err(invalid(offset, "duplicate logical tree"));
                }
            }
            "ltypes" if logical => {}
            "ltree" | "ltypes" => {
                return Err(Error::Unsupported(
                    "logical evidence sections in a physical image".into(),
                ));
            }
            // Other optional sections remain discoverable in the inventory.
            _ => {}
        }
        if terminal {
            if sectors.is_some() {
                return Err(invalid(offset, "unindexed sectors data"));
            }
            return Ok(kind == "done");
        }
        previous = kind.to_owned();
        offset = next;
    }
}

fn read_payload(segment: &mut Segment, range: &Range<u64>, limit: usize) -> Result<Vec<u8>> {
    let size = range.end - range.start;
    if size > limit as u64 {
        return Err(Error::ResourceLimit("metadata section size"));
    }
    read_bytes(&mut segment.file, range.start, size as usize)
}

#[derive(Debug, PartialEq, Eq)]
struct Table {
    base: u64,
    entries: Vec<u32>,
}

fn read_table(segment: &mut Segment, payload: &Range<u64>, options: &OpenOptions) -> Result<Table> {
    if payload.end - payload.start < 28 {
        return Err(invalid(payload.start, "truncated chunk table"));
    }
    let header = read_bytes(&mut segment.file, payload.start, 24)?;
    checksum(&header, payload.start, "chunk table header")?;
    let count = u32_at(&header, 0) as usize;
    if count > options.max_table_entries || count > options.max_chunks {
        return Err(Error::ResourceLimit("table entries"));
    }
    let array_size = (count as u64)
        .checked_mul(4)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(|| invalid(payload.start, "table size overflow"))?;
    if array_size > payload.end - payload.start - 24 {
        return Err(invalid(payload.start, "table count exceeds section bounds"));
    }
    let data = read_bytes(&mut segment.file, payload.start + 24, array_size as usize)?;
    checksum(&data, payload.start + 24, "chunk table entries")?;
    let entries = data[..data.len() - 4]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32_at(b, 0))
        .collect();
    Ok(Table {
        base: u64_at(&header, 8),
        entries,
    })
}

fn append_chunks(
    chunks: &mut Vec<Chunk>,
    table: &Table,
    range: Range<u64>,
    segment: u16,
    metadata: &Metadata,
    options: &OpenOptions,
    offset: u64,
) -> Result<()> {
    let count = chunks
        .len()
        .checked_add(table.entries.len())
        .ok_or(Error::ResourceLimit("chunk index"))?;
    if count > options.max_chunks {
        return Err(Error::ResourceLimit("chunk count"));
    }
    if metadata.media_type != 0x0e && count as u64 > u64::from(metadata.chunk_count) {
        return Err(invalid(
            offset,
            "chunk tables exceed declared media chunk count",
        ));
    }
    chunks
        .try_reserve(table.entries.len())
        .map_err(|_| Error::ResourceLimit("chunk index allocation"))?;
    for (index, &entry) in table.entries.iter().enumerate() {
        let start = table
            .base
            .checked_add(u64::from(entry & 0x7fff_ffff))
            .ok_or_else(|| invalid(offset, "chunk offset overflow"))?;
        let end = if let Some(&next) = table.entries.get(index + 1) {
            table
                .base
                .checked_add(u64::from(next & 0x7fff_ffff))
                .ok_or_else(|| invalid(offset, "chunk offset overflow"))?
        } else {
            range.end
        };
        if start < range.start || end > range.end || end <= start {
            return Err(invalid(
                offset,
                "chunk offsets are out of bounds or not strictly increasing",
            ));
        }
        // zlib can slightly expand incompressible input.
        let max_stored = metadata
            .chunk_size()
            .checked_add(metadata.chunk_size() / 1000)
            .and_then(|size| size.checked_add(1024))
            .ok_or(Error::ResourceLimit("stored chunk size"))?;
        let size = end - start;
        if size > max_stored || size > u64::from(u32::MAX) {
            return Err(invalid(offset, "stored chunk exceeds chunk size bound"));
        }
        chunks.push(Chunk {
            offset: start,
            stored_size: size as u32,
            segment,
            compressed: entry & 0x8000_0000 != 0,
        });
    }
    Ok(())
}

fn geometry(data: &[u8], offset: u64, options: &OpenOptions, logical: bool) -> Result<Metadata> {
    if data.len() != 1052 && data.len() != 94 {
        return Err(invalid(offset, "unsupported volume/data section size"));
    }
    checksum(data, offset, "volume geometry")?;
    let mut metadata = Metadata {
        chunk_count: u32_at(data, 4),
        sectors_per_chunk: u32_at(data, 8),
        bytes_per_sector: u32_at(data, 12),
        sector_count: if data.len() == 94 {
            u64::from(u32_at(data, 16))
        } else {
            u64_at(data, 16)
        },
        media_type: data[0],
        ..Metadata::default()
    };
    if metadata.media_type == 0x0e && !logical {
        return Err(Error::Unsupported("logical evidence volume".into()));
    }
    if logical && metadata.media_type != 0x0e {
        return Err(invalid(offset, "physical geometry in logical evidence"));
    }
    if metadata.bytes_per_sector == 0 || metadata.sectors_per_chunk == 0 {
        return Err(invalid(offset, "zero sector or chunk size"));
    }
    if metadata.chunk_size() > options.max_chunk_size as u64 {
        return Err(Error::ResourceLimit("decoded chunk size"));
    }
    if u64::from(metadata.chunk_count) > options.max_chunks as u64 {
        return Err(Error::ResourceLimit("declared chunk count"));
    }
    metadata.media_size = metadata
        .sector_count
        .checked_mul(u64::from(metadata.bytes_per_sector))
        .ok_or_else(|| invalid(offset, "media size overflow"))?;
    if !logical
        && metadata.media_size.div_ceil(metadata.chunk_size()) != u64::from(metadata.chunk_count)
    {
        return Err(invalid(
            offset,
            "geometry chunk count is inconsistent with media size",
        ));
    }
    if data.len() == 1052 {
        metadata.media_flags = data[36];
        metadata.compression_level = data[52];
        metadata.set_identifier.copy_from_slice(&data[64..80]);
    }
    Ok(metadata)
}

fn merge_geometry(metadata: &mut Metadata, incoming: Metadata, offset: u64) -> Result<()> {
    if metadata.bytes_per_sector == 0 {
        metadata.media_size = incoming.media_size;
        metadata.sector_count = incoming.sector_count;
        metadata.bytes_per_sector = incoming.bytes_per_sector;
        metadata.sectors_per_chunk = incoming.sectors_per_chunk;
        metadata.chunk_count = incoming.chunk_count;
        metadata.media_type = incoming.media_type;
        metadata.media_flags = incoming.media_flags;
        metadata.compression_level = incoming.compression_level;
        metadata.set_identifier = incoming.set_identifier;
    } else if metadata.media_size != incoming.media_size
        || metadata.bytes_per_sector != incoming.bytes_per_sector
        || metadata.sectors_per_chunk != incoming.sectors_per_chunk
        || metadata.chunk_count != incoming.chunk_count
        || metadata.set_identifier != incoming.set_identifier
        || metadata.media_type != incoming.media_type
    {
        return Err(invalid(
            offset,
            "inconsistent volume/data geometry or segment set identifier",
        ));
    }
    Ok(())
}

fn merge_hash<const N: usize>(
    target: &mut Option<[u8; N]>,
    value: &[u8],
    offset: u64,
) -> Result<()> {
    let value: [u8; N] = value
        .try_into()
        .map_err(|_| invalid(offset, "invalid digest length"))?;
    if value == [0; N] {
        return Ok(());
    }
    if target.is_some_and(|existing| existing != value) {
        return Err(invalid(offset, "conflicting stored media digests"));
    }
    *target = Some(value);
    Ok(())
}

fn decode_utf16(data: &[u8], offset: u64) -> Result<String> {
    if data.len() < 2 || !data.len().is_multiple_of(2) {
        return Err(invalid(offset, "invalid UTF-16 header2 size"));
    }
    let big_endian = match &data[..2] {
        [0xff, 0xfe] => false,
        [0xfe, 0xff] => true,
        _ => return Err(invalid(offset, "missing header2 byte order mark")),
    };
    let units: Vec<_> = data[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| {
            if big_endian {
                u16::from_be_bytes([b[0], b[1]])
            } else {
                u16::from_le_bytes([b[0], b[1]])
            }
        })
        .collect();
    String::from_utf16(&units).map_err(|_| invalid(offset, "invalid UTF-16 header2 text"))
}

fn parse_acquisition(
    metadata: &mut Metadata,
    text: &str,
    prefer: bool,
    limit: usize,
) -> Result<()> {
    let mut size: usize = metadata
        .acquisition
        .iter()
        .map(|(key, value)| key.len() + value.len() + 64)
        .sum();
    let mut lines = text.lines().skip_while(|line| *line != "main");
    lines.next();
    if let (Some(keys), Some(values)) = (lines.next(), lines.next()) {
        for (key, value) in keys.split('\t').zip(values.split('\t')) {
            let existing = metadata.acquisition.get(key);
            if existing.is_some() && !prefer {
                continue;
            }
            let previous_size = existing.map_or(0, |value| key.len() + value.len() + 64);
            size = size
                .saturating_sub(previous_size)
                .saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(64);
            if size > limit {
                return Err(Error::ResourceLimit("total acquisition metadata"));
            }
            if prefer {
                metadata
                    .acquisition
                    .insert(key.to_owned(), value.to_owned());
            } else {
                metadata
                    .acquisition
                    .entry(key.to_owned())
                    .or_insert_with(|| value.to_owned());
            }
        }
    }
    Ok(())
}

pub(super) fn read_bytes(file: &mut File, offset: u64, size: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(size)
        .map_err(|_| Error::ResourceLimit("read buffer allocation"))?;
    data.resize(size, 0);
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut data)?;
    Ok(data)
}

pub(super) fn checksum(data: &[u8], offset: u64, context: &'static str) -> Result<()> {
    if data.len() < 4 {
        return Err(invalid(offset, "truncated checksum"));
    }
    let split = data.len() - 4;
    let stored = u32_at(data, split);
    let calculated = adler2::adler32_slice(&data[..split]);
    if stored != calculated {
        return Err(Error::Checksum {
            context,
            offset,
            stored,
            calculated,
        });
    }
    Ok(())
}

pub(super) fn inflate(data: &[u8], limit: usize, offset: u64) -> Result<Vec<u8>> {
    let capacity = limit
        .checked_add(1)
        .ok_or(Error::ResourceLimit("decompression limit"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::ResourceLimit("decompression buffer"))?;
    let mut decoder = Decompress::new(true);
    let status = decoder
        .decompress_vec(data, &mut output, FlushDecompress::Finish)
        .map_err(|error| invalid(offset, format!("invalid zlib stream: {error}")))?;
    if output.len() > limit {
        return Err(Error::ResourceLimit("decompressed data size"));
    }
    if status != Status::StreamEnd || decoder.total_in() != data.len() as u64 {
        return Err(invalid(
            offset,
            "truncated zlib stream or trailing compressed bytes",
        ));
    }
    Ok(output)
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_index_preserves_64_bit_table_base_offsets() {
        let base = 0x1_0000_0000;
        let mut chunks = Vec::new();
        let metadata = Metadata {
            chunk_count: 1,
            sectors_per_chunk: 64,
            bytes_per_sector: 512,
            ..Metadata::default()
        };
        let table = Table {
            base,
            entries: vec![0x8000_004c],
        };
        append_chunks(
            &mut chunks,
            &table,
            base + 76..base + 76 + 123,
            1,
            &metadata,
            &OpenOptions::default(),
            base,
        )
        .unwrap();
        assert_eq!(chunks[0].offset, 0x1_0000_004c);
        assert_eq!(chunks[0].stored_size, 123);
        assert!(chunks[0].compressed);
    }

    #[test]
    fn segment_extension_transitions() {
        for (number, name) in [
            (2, "disk.E02"),
            (99, "disk.E99"),
            (100, "disk.EAA"),
            (125, "disk.EAZ"),
            (126, "disk.EBA"),
            (775, "disk.EZZ"),
            (776, "disk.FAA"),
            (14971, "disk.ZZZ"),
        ] {
            assert_eq!(
                next_segment_path(Path::new("disk.E01"), number).unwrap(),
                Path::new(name)
            );
        }
        assert_eq!(
            next_segment_path(Path::new("disk.e01"), 100).unwrap(),
            Path::new("disk.eaa")
        );
        assert!(next_segment_path(Path::new("disk.E01"), 14972).is_err());
    }
}
