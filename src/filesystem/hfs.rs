//! HFS+/HFSX volume headers, catalog B-trees, forks and overflow extents.
use super::{FileKind, FsInfo, FsType, Limits, StreamInfo, Times, indexed::*};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{BTreeMap, HashSet};
type Overflow = BTreeMap<(u32, u8, u32), Vec<(u32, u32)>>;
type AttributeRecords = BTreeMap<(u32, String), Vec<(u32, Vec<u8>)>>;
fn unicode(d: &[u8]) -> Result<String> {
    if !d.len().is_multiple_of(2) {
        return Err(bad("HFS Unicode byte count"));
    }
    String::from_utf16(
        &d.as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_be_bytes(*v))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| bad("HFS invalid UTF-16"))
}
fn extents(d: &[u8]) -> Result<Vec<(u32, u32)>> {
    let mut out = vec![];
    for i in 0..8 {
        let start = u32be(d, i * 8)?;
        let count = u32be(d, i * 8 + 4)?;
        if count != 0 {
            out.push((start, count));
        }
    }
    Ok(out)
}
fn fork(
    d: &[u8],
    id: u32,
    which: u8,
    block: u64,
    base: u64,
    overflow: &Overflow,
    limit: usize,
) -> Result<Data> {
    let size = u64be(d, 0)?;
    let allocated = u32be(d, 12)?;
    let mut ext = extents(bytes(d, 16, 64)?)?;
    let mut blocks = ext.iter().try_fold(0u32, |s, (_, n)| {
        s.checked_add(*n)
            .ok_or_else(|| bad("HFS extent count overflow"))
    })?;
    while blocks < allocated {
        if ext.len() >= limit {
            return Err(Error::ResourceLimit("HFS extents"));
        }
        let more = overflow.get(&(id, which, blocks)).ok_or_else(|| {
            Error::Unsupported(format!("missing HFS overflow extents for CNID {id}"))
        })?;
        let n = more.iter().map(|(_, n)| u64::from(*n)).sum::<u64>();
        if n == 0 || n > u64::from(allocated - blocks) {
            return Err(bad("HFS overflow extent count"));
        }
        blocks += n as u32;
        ext.extend_from_slice(more);
    }
    if blocks != allocated || size > u64::from(blocks) * block {
        return Err(bad("HFS fork size/allocation mismatch"));
    }
    let mut data = Data {
        size,
        ..Data::default()
    };
    let mut logical = 0;
    for (start, n) in ext {
        let length = u64::from(n) * block;
        data.runs.push(Run {
            logical,
            physical: Some(base + u64::from(start) * block),
            length,
        });
        logical += length;
    }
    Ok(data)
}
fn leaves(image: &mut dyn DiskImage, data: &Data, limits: &Limits) -> Result<(Vec<Vec<u8>>, u8)> {
    if data.size == 0 {
        return Ok((vec![], 0));
    }
    let mut head = vec![0; 120];
    read_data(image, data, 0, &mut head)?;
    if head[8] != 1 {
        return Err(bad("HFS B-tree header node"));
    }
    let size = u16be(&head, 32)? as usize;
    let total = u32be(&head, 36)?;
    let mut leaf = u32be(&head, 24)?;
    let expected = u32be(&head, 20)? as usize;
    if !(512..=32768).contains(&size)
        || !size.is_power_of_two()
        || size > limits.max_metadata_bytes
        || u64::from(total) * size as u64 > data.size
        || expected > limits.max_directory_entries
    {
        return Err(bad("HFS B-tree geometry"));
    }
    let mut records = vec![];
    let mut seen = HashSet::new();
    let mut previous = 0;
    let mut budget = 0usize;
    while leaf != 0 {
        if leaf >= total || !seen.insert(leaf) {
            return Err(bad("HFS cyclic/out-of-range leaf"));
        }
        if seen.len() > limits.max_chain_length {
            return Err(Error::ResourceLimit("HFS B-tree leaves"));
        }
        let mut d = vec![0; size];
        read_data(image, data, u64::from(leaf) * size as u64, &mut d)?;
        if d[8] != 255 || u32be(&d, 4)? != previous || d[9] != 1 {
            return Err(bad("HFS leaf node type/backlink"));
        }
        let count = u16be(&d, 10)? as usize;
        if (count + 1) * 2 + 14 > size {
            return Err(bad("HFS record offsets"));
        }
        let table = size - (count + 1) * 2;
        for i in 0..count {
            let a = u16be(&d, size - (i + 1) * 2)? as usize;
            let b = u16be(&d, size - (i + 2) * 2)? as usize;
            if a < 14 || a >= b || b > table {
                return Err(bad("HFS record range"));
            }
            budget += b - a;
            if budget > limits.max_metadata_bytes || records.len() >= limits.max_directory_entries {
                return Err(Error::ResourceLimit("HFS B-tree records"));
            }
            records.push(d[a..b].to_vec());
        }
        previous = leaf;
        leaf = u32be(&d, 0)?;
    }
    if records.len() != expected {
        return Err(bad("HFS leaf record count"));
    }
    Ok((records, head[51]))
}
pub(super) fn open(image: &mut dyn DiskImage, limits: Limits) -> Result<IndexedFs<'_>> {
    let mut vh = read_vec(image, 1024, 512)?;
    let mut base = 0;
    let mut embedded_len = image.len();
    if u16be(&vh, 0)? == 0x4244 {
        let signature = u16be(&vh, 124)?;
        if ![0x482b, 0x4858].contains(&signature) {
            return Err(Error::Unsupported(
                "legacy HFS without an embedded HFS+ volume".into(),
            ));
        }
        let block = u64::from(u32be(&vh, 20)?);
        let allocation = u64::from(u16be(&vh, 28)?) * 512;
        let start = u64::from(u16be(&vh, 126)?);
        embedded_len = u64::from(u16be(&vh, 128)?) * block;
        base = allocation + start * block;
        if block == 0 || !block.is_multiple_of(512) || base < 1536 || embedded_len < 1536 {
            return Err(bad("HFS wrapper geometry"));
        }
        checked_region(
            allocation,
            u64::from(u16be(&vh, 18)?) * block,
            image.len(),
            "HFS wrapper allocation",
        )?;
        if start + u64::from(u16be(&vh, 128)?) > u64::from(u16be(&vh, 18)?) {
            return Err(bad("HFS embedded extent outside allocation"));
        }
        checked_region(base, embedded_len, image.len(), "HFS wrapper")?;
        vh = read_vec(image, base + 1024, 512)?;
        if u16be(&vh, 0)? != signature {
            return Err(bad("HFS embedded signature disagrees with wrapper"));
        }
    }
    let sig = u16be(&vh, 0)?;
    if ![0x482b, 0x4858].contains(&sig) || u16be(&vh, 2)? != if sig == 0x482b { 4 } else { 5 } {
        return Err(bad("HFS volume signature/version"));
    }
    let block = u64::from(u32be(&vh, 40)?);
    let total = u64::from(u32be(&vh, 44)?) * block;
    if !(512..=1024 * 1024).contains(&block) || !block.is_power_of_two() {
        return Err(bad("HFS allocation block size"));
    }
    checked_region(0, total, embedded_len, "HFS volume")?;
    let empty = Overflow::new();
    let ext = fork(
        &vh[192..272],
        3,
        0,
        block,
        base,
        &empty,
        limits.max_chain_length,
    )?;
    let (records, _) = leaves(image, &ext, &limits)?;
    let mut overflow = Overflow::new();
    for r in records {
        if u16be(&r, 0)? != 10 {
            return Err(bad("HFS overflow key length"));
        }
        let key = (u32be(&r, 4)?, r[2], u32be(&r, 8)?);
        if overflow.insert(key, extents(bytes(&r, 12, 64)?)?).is_some() {
            return Err(bad("HFS duplicate overflow key"));
        }
    }
    let catalog = fork(
        &vh[272..352],
        4,
        0,
        block,
        base,
        &overflow,
        limits.max_chain_length,
    )?;
    let (records, compare) = leaves(image, &catalog, &limits)?;
    let info = FsInfo {
        filesystem: if sig == 0x482b {
            FsType::HfsPlus
        } else {
            FsType::HfsX
        },
        label: String::new(),
        block_size: block as u32,
        total_bytes: total,
        root_id: 2,
        needs_journal_recovery: u32be(&vh, 4)? & 0x100 == 0,
    };
    let mut fs = IndexedFs::new(image, info, limits);
    fs.base_offset = base;
    fs.ascii_fold = sig == 0x482b || compare == 0xc7;
    let mut edges = vec![];
    for r in records {
        let keylen = u16be(&r, 0)? as usize;
        let parent = u64::from(u32be(&r, 2)?);
        let names = u16be(&r, 6)? as usize;
        if keylen != 6 + names * 2 || names > 255 {
            return Err(bad("HFS catalog key length"));
        }
        let name = unicode(bytes(&r, 8, names * 2)?)?
            .chars()
            .map(|c| {
                if c < ' ' {
                    '^'
                } else if c == '/' {
                    ':'
                } else {
                    c
                }
            })
            .collect::<String>();
        let v = bytes(
            &r,
            (keylen + 3) & !1,
            r.len()
                .checked_sub((keylen + 3) & !1)
                .ok_or_else(|| bad("HFS catalog record length"))?,
        )?;
        let typ = u16be(v, 0)?;
        if ![1, 2].contains(&typ) {
            continue;
        }
        bytes(v, 0, 88)?;
        let id = u64::from(u32be(v, 8)?);
        let mode = u16be(v, 42)?;
        let mut m = metadata(
            id,
            if typ == 1 {
                0x4000 | (mode & 0xfff)
            } else {
                mode
            },
            0,
        );
        if m.kind == FileKind::Other && typ == 2 {
            m.kind = FileKind::File;
        }
        m.uid = Some(u32be(v, 32)?);
        m.gid = Some(u32be(v, 36)?);
        let t = |at| -> Result<Option<super::Timestamp>> {
            Ok(Some(utc(i64::from(u32be(v, at)?) - 2_082_844_800, 0)?))
        };
        m.times = Times {
            created: t(12)?,
            modified: t(16)?,
            changed: t(20)?,
            accessed: t(24)?,
        };
        let data = if typ == 2 {
            fork(
                bytes(v, 88, 80)?,
                id as u32,
                0,
                block,
                base,
                &overflow,
                fs.limits.max_chain_length,
            )?
        } else {
            Data::default()
        };
        m.size = data.size;
        let mut entry = node(m, data);
        if typ == 2 {
            let resource = fork(
                bytes(v, 168, 80)?,
                id as u32,
                0xff,
                block,
                base,
                &overflow,
                fs.limits.max_chain_length,
            )?;
            if resource.size != 0 {
                entry.meta.streams.push(StreamInfo {
                    name: "com.apple.ResourceFork".into(),
                    size: resource.size,
                    resident: false,
                    compressed: false,
                    encrypted: false,
                });
                entry.data.insert("com.apple.ResourceFork".into(), resource);
            }
            if v[41] & 0x20 != 0 {
                entry.data.get_mut("").unwrap().unsupported = Some("HFS compressed file".into());
            }
            if &v[48..52] == b"hlnk" || &v[48..52] == b"fdrp" {
                entry.data.get_mut("").unwrap().unsupported =
                    Some("HFS indirect hard-link file".into());
            }
        }
        if id == 2 {
            fs.info.label = name;
        } else {
            edges.push((parent, id, name));
        }
        fs.insert(entry)?;
    }
    if !fs.nodes.contains_key(&2) {
        return Err(bad("HFS root CNID missing"));
    }
    let attributes = fork(
        &vh[352..432],
        8,
        0,
        block,
        base,
        &overflow,
        fs.limits.max_chain_length,
    )?;
    let (records, _) = leaves(fs.image, &attributes, &fs.limits)?;
    let mut attr_records = AttributeRecords::new();
    for record in records {
        let keylen = u16be(&record, 0)? as usize;
        let n = u16be(&record, 12)? as usize;
        if keylen != 12 + n * 2 || n > 255 || u16be(&record, 2)? != 0 {
            return Err(bad("HFS attribute key"));
        }
        let id = u32be(&record, 4)?;
        let start = u32be(&record, 8)?;
        let name = unicode(bytes(&record, 14, n * 2)?)?;
        let at = keylen + 2;
        let value = record
            .get(at..)
            .ok_or_else(|| bad("HFS attribute value"))?
            .to_vec();
        attr_records
            .entry((id, name))
            .or_default()
            .push((start, value));
    }
    for ((id, name), mut records) in attr_records {
        records.sort_by_key(|(start, _)| *start);
        if records[0].0 != 0 {
            return Err(bad("HFS attribute continuation without base"));
        }
        let mut extra = Overflow::new();
        for (start, v) in records.iter().skip(1) {
            if *start == 0
                || u32be(v, 0)? != 0x30
                || extra
                    .insert((id, 0, *start), extents(bytes(v, 8, 64)?)?)
                    .is_some()
            {
                return Err(bad("HFS attribute continuation"));
            }
        }
        let value = &records[0].1;
        let data = match u32be(value, 0)? {
            0x10 => {
                if records.len() != 1 {
                    return Err(bad("HFS inline attribute continuation"));
                }
                let size = u32be(value, 12)? as usize;
                Data {
                    size: size as u64,
                    inline: Some(bytes(value, 16, size)?.to_vec()),
                    ..Data::default()
                }
            }
            0x20 => fork(
                bytes(value, 8, 80)?,
                id,
                0,
                block,
                base,
                &extra,
                fs.limits.max_chain_length,
            )?,
            _ => return Err(Error::Unsupported("HFS attribute record type".into())),
        };
        fs.reserve_data(data.inline.as_ref().map_or(0, Vec::len) + data.runs.len() * 32)?;
        if let Some(entry) = fs.nodes.get_mut(&u64::from(id)) {
            if entry.data.contains_key(&name) {
                return Err(bad("HFS duplicate extended attribute"));
            }
            entry.meta.streams.push(StreamInfo {
                name: name.clone(),
                size: data.size,
                resident: data.inline.is_some(),
                compressed: false,
                encrypted: false,
            });
            entry.data.insert(name, data);
        }
    }
    super::decmpfs::apply(&mut fs)?;
    for (p, id, name) in edges {
        fs.link(p, id, name, None)?;
    }
    let allocation = fork(
        &vh[112..192],
        6,
        0,
        block,
        base,
        &overflow,
        fs.limits.max_chain_length,
    )?;
    let needed = u64::from(u32be(&vh, 44)?).div_ceil(8);
    if allocation.size < needed || needed > fs.limits.max_metadata_bytes as u64 {
        return Err(bad("HFS allocation bitmap size"));
    }
    let mut bitmap = vec![0; needed as usize];
    read_data(fs.image, &allocation, 0, &mut bitmap)?;
    for data in fs.nodes.values().flat_map(|n| n.data.values()).chain([
        &catalog,
        &ext,
        &allocation,
        &attributes,
    ]) {
        for run in &data.runs {
            if let Some(p) = run.physical {
                let relative = p
                    .checked_sub(base)
                    .ok_or_else(|| bad("HFS extent before wrapper"))?;
                checked_region(relative, run.length, total, "HFS extent")?;
                for cluster in relative / block..(relative + run.length).div_ceil(block) {
                    if bitmap[cluster as usize / 8] & (0x80 >> (cluster % 8)) == 0 {
                        return Err(bad("HFS extent references unallocated block"));
                    }
                }
            }
        }
    }
    fs.validate()?;
    Ok(fs)
}
