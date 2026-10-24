//! ISO9660 descriptors, Joliet names, Rock Ridge system-use records and extents.
use super::{FileKind, FsInfo, FsType, Limits, Times, indexed::*};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{HashSet, VecDeque};
fn both32(d: &[u8], o: usize) -> Result<u32> {
    let n = u32le(d, o)?;
    if n != u32be(d, o + 4)? {
        return Err(bad("ISO9660 endian copies disagree"));
    }
    Ok(n)
}
fn both16(d: &[u8], o: usize) -> Result<u16> {
    let n = u16le(d, o)?;
    if n != u16be(d, o + 2)? {
        return Err(bad("ISO9660 endian copies disagree"));
    }
    Ok(n)
}
fn unicode(d: &[u8]) -> Result<String> {
    if !d.len().is_multiple_of(2) {
        return Err(bad("Joliet odd name length"));
    }
    String::from_utf16(
        &d.as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_be_bytes(*v))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| bad("Joliet invalid UTF-16"))
}
pub(super) fn detect(image: &mut dyn DiskImage) -> Result<bool> {
    Ok(image.len() >= 32775 && read_vec(image, 32769, 5)? == b"CD001")
}
#[derive(Default)]
struct Rock {
    name: Vec<u8>,
    mode: Option<u16>,
    uid: Option<u32>,
    gid: Option<u32>,
    link: Vec<u8>,
}
fn rock(
    image: &mut dyn DiskImage,
    d: &[u8],
    block: u64,
    limit: usize,
    depth: usize,
    out: &mut Rock,
) -> Result<()> {
    if depth > 8 {
        return Err(Error::ResourceLimit("Rock Ridge continuation depth"));
    }
    let mut at = 0;
    while at + 4 <= d.len() {
        if d[at] == 0 {
            break;
        }
        let len = d[at + 2] as usize;
        if len < 4 {
            return Err(bad("Rock Ridge record length"));
        }
        let e = bytes(d, at, len)?;
        match &e[..2] {
            b"NM" => {
                if len < 5 || e[4] & !1 != 0 {
                    return Err(Error::Unsupported("Rock Ridge special name".into()));
                }
                out.name.extend_from_slice(&e[5..]);
            }
            b"PX" => {
                out.mode = Some(both32(e, 4)? as u16);
                out.uid = Some(both32(e, 20)?);
                out.gid = Some(both32(e, 28)?);
            }
            b"SL" => {
                if len < 5 {
                    return Err(bad("Rock Ridge link"));
                }
                let mut p = 5;
                while p + 2 <= e.len() {
                    let flags = e[p];
                    let size = e[p + 1] as usize;
                    let part = bytes(e, p + 2, size)?;
                    if !out.link.is_empty() && !out.link.ends_with(b"/") {
                        out.link.push(b'/');
                    }
                    match flags & !1 {
                        0 => out.link.extend_from_slice(part),
                        2 => out.link.extend_from_slice(b"."),
                        4 => out.link.extend_from_slice(b".."),
                        8 => {
                            out.link.clear();
                            out.link.push(b'/');
                        }
                        _ => return Err(Error::Unsupported("Rock Ridge link component".into())),
                    }
                    p += 2 + size;
                }
            }
            b"CE" => {
                let address = u64::from(both32(e, 4)?)
                    .checked_mul(block)
                    .and_then(|v| v.checked_add(u64::from(both32(e, 12).ok()?)))
                    .ok_or_else(|| bad("Rock Ridge continuation offset"))?;
                let size = both32(e, 20)? as usize;
                if size > limit {
                    return Err(Error::ResourceLimit("Rock Ridge continuation bytes"));
                }
                let next = read_vec(image, address, size)?;
                rock(image, &next, block, limit, depth + 1, out)?;
            }
            b"CL" | b"PL" | b"RE" => {
                return Err(Error::Unsupported("Rock Ridge relocated directory".into()));
            }
            b"ST" => break,
            _ => {}
        }
        if out.name.len() > limit || out.link.len() > limit {
            return Err(Error::ResourceLimit("Rock Ridge metadata"));
        }
        at += len;
    }
    Ok(())
}
fn date(d: &[u8]) -> Result<Option<super::Timestamp>> {
    if d.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let year = i64::from(d[0]) + 1900;
    let month = d[1] as usize;
    let day = i64::from(d[2]);
    let leap = |y: i64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let offset = d[6] as i8;
    if !(1..=12).contains(&month)
        || day < 1
        || day > months[month - 1]
        || d[3] > 23
        || d[4] > 59
        || d[5] > 59
        || !(-48..=52).contains(&offset)
    {
        return Err(bad("ISO9660 recording date"));
    }
    let mut days = 0;
    for y in 1970..year {
        days += if leap(y) { 366 } else { 365 };
    }
    for y in year..1970 {
        days -= if leap(y) { 366 } else { 365 };
    }
    days += months[..month - 1].iter().sum::<i64>() + day - 1;
    Ok(Some(utc(
        days * 86400 + i64::from(d[3]) * 3600 + i64::from(d[4]) * 60 + i64::from(d[5])
            - i64::from(offset) * 900,
        0,
    )?))
}
pub(super) fn open(image: &mut dyn DiskImage, limits: Limits) -> Result<IndexedFs<'_>> {
    let mut primary = None;
    let mut joliet = None;
    let mut ended = false;
    for i in 16..272 {
        let d = read_vec(image, i * 2048, 2048)?;
        if &d[1..6] != b"CD001" || d[6] != 1 {
            return Err(bad("ISO9660 volume descriptor"));
        }
        match d[0] {
            1 => {
                if primary.is_some() {
                    return Err(bad("duplicate ISO9660 primary descriptor"));
                }
                primary = Some(d);
            }
            2 if &d[88..91] == b"%/@" || &d[88..91] == b"%/C" || &d[88..91] == b"%/E" => {
                joliet = Some(d)
            }
            255 => {
                ended = true;
                break;
            }
            _ => {}
        }
    }
    if !ended || primary.is_none() {
        return Err(bad("ISO9660 descriptor terminator/primary missing"));
    }
    let is_joliet = joliet.is_some();
    let d = joliet.or(primary).unwrap();
    let block = u64::from(both16(&d, 128)?);
    if ![512, 1024, 2048].contains(&block) {
        return Err(bad("ISO9660 block size"));
    }
    let total = u64::from(both32(&d, 80)?) * block;
    checked_region(0, total, image.len(), "ISO9660")?;
    if both16(&d, 120)? != 1 || both16(&d, 124)? != 1 {
        return Err(Error::Unsupported("ISO9660 multi-volume set".into()));
    }
    let label = if is_joliet {
        unicode(&d[40..72])?
    } else {
        String::from_utf8_lossy(&d[40..72]).into_owned()
    }
    .trim_matches([' ', '\0'])
    .to_owned();
    let root = &d[156..190];
    let root_len = u64::from(both32(root, 10)?);
    let root_at = u64::from(both32(root, 2)?) * block;
    checked_region(root_at, root_len, total, "ISO9660 root directory")?;
    let mut fs = IndexedFs::new(
        image,
        FsInfo {
            filesystem: FsType::Iso9660,
            label,
            block_size: block as u32,
            total_bytes: total,
            root_id: 0,
            needs_journal_recovery: false,
        },
        limits,
    );
    fs.ascii_fold = true;
    fs.insert(node(
        metadata(0, 0x4000, root_len),
        Data {
            size: root_len,
            runs: vec![Run {
                logical: 0,
                physical: Some(root_at),
                length: root_len,
            }],
            ..Data::default()
        },
    ))?;
    let mut queue = VecDeque::from([(0, 0)]);
    let mut seen = HashSet::new();
    let mut visited_extents = HashSet::new();
    while let Some((id, depth)) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        if depth > fs.limits.max_tree_depth {
            return Err(Error::ResourceLimit("ISO9660 directory depth"));
        }
        let stream = fs.nodes[&id].data[""].clone();
        if stream.size > fs.limits.max_directory_bytes || stream.size > usize::MAX as u64 {
            return Err(Error::ResourceLimit("ISO9660 directory bytes"));
        }
        if !visited_extents.insert(stream.runs[0].physical) {
            return Err(bad("ISO9660 directory cycle"));
        }
        let mut data = vec![0; stream.size as usize];
        read_data(fs.image, &stream, 0, &mut data)?;
        let mut at = 0;
        let mut pending: Option<(u64, String)> = None;
        while at < data.len() {
            let len = data[at] as usize;
            if len == 0 {
                at = ((at / 2048) + 1) * 2048;
                continue;
            }
            if len < 34 || at % 2048 + len > 2048 {
                return Err(bad("ISO9660 directory record length"));
            }
            let r = bytes(&data, at, len)?;
            let n = r[32] as usize;
            let raw = bytes(r, 33, n)?;
            if raw == [0] || raw == [1] {
                at += len;
                continue;
            }
            if r[26] != 0 || r[27] != 0 {
                return Err(Error::Unsupported("ISO9660 interleaved file".into()));
            }
            if both16(r, 28)? != 1 {
                return Err(bad("ISO9660 volume sequence"));
            }
            let mut rr = Rock::default();
            let system = 33 + n + usize::from(n.is_multiple_of(2));
            if !is_joliet && system < r.len() {
                rock(
                    fs.image,
                    &r[system..],
                    block,
                    fs.limits.max_metadata_bytes,
                    0,
                    &mut rr,
                )?;
            }
            let name = if !rr.name.is_empty() {
                fs.ascii_fold = false;
                String::from_utf8(rr.name.clone()).map_err(|_| bad("Rock Ridge name encoding"))?
            } else {
                let s = if is_joliet {
                    unicode(raw)?
                } else {
                    String::from_utf8_lossy(raw).into_owned()
                };
                let base = s
                    .rsplit_once(';')
                    .filter(|(_, v)| v.bytes().all(|b| b.is_ascii_digit()))
                    .map_or(s.as_str(), |(b, _)| b);
                base.trim_end_matches('.').to_owned()
            };
            let size = u64::from(both32(r, 10)?);
            if r[25] & 128 != 0 && (size == 0 || !size.is_multiple_of(block)) {
                return Err(bad("ISO9660 non-final extent length"));
            }
            let physical = (u64::from(both32(r, 2)?) + u64::from(r[1])) * block;
            checked_region(physical, size, total, "ISO9660 file extent")?;
            let entry_id = stream.runs[0].physical.unwrap() + at as u64;
            let mode = rr
                .mode
                .unwrap_or(if r[25] & 2 != 0 { 0x4000 } else { 0x8000 });
            let mut m = metadata(entry_id, mode, size);
            m.uid = rr.uid;
            m.gid = rr.gid;
            m.times = Times {
                modified: date(&r[18..25])?,
                ..Times::default()
            };
            let mut file = Data {
                size,
                ..Data::default()
            };
            if m.kind == FileKind::Symlink {
                file.size = rr.link.len() as u64;
                m.size = file.size;
                file.inline = Some(rr.link);
            } else if size != 0 {
                file.runs.push(Run {
                    logical: 0,
                    physical: Some(physical),
                    length: size,
                });
            }
            if let Some((previous, previous_name)) = pending.take() {
                if name != previous_name || m.kind != FileKind::File {
                    return Err(bad("ISO9660 multi-extent continuation"));
                }
                let existing = fs.nodes.get_mut(&previous).unwrap();
                let d = existing.data.get_mut("").unwrap();
                d.runs.push(Run {
                    logical: d.size,
                    physical: Some(physical),
                    length: size,
                });
                d.size = d
                    .size
                    .checked_add(size)
                    .ok_or_else(|| bad("ISO9660 file size overflow"))?;
                existing.meta.size = d.size;
                if r[25] & 128 != 0 {
                    pending = Some((previous, name));
                } else {
                    fs.link(id, previous, name, None)?;
                }
            } else {
                let directory = m.kind == FileKind::Directory;
                fs.insert(node(m, file))?;
                if r[25] & 128 != 0 {
                    if directory {
                        return Err(bad("ISO9660 multi-extent directory"));
                    }
                    pending = Some((entry_id, name));
                } else {
                    fs.link(id, entry_id, name, None)?;
                }
                if directory {
                    queue.push_back((entry_id, depth + 1));
                }
            }
            at += len;
        }
        if pending.is_some() {
            return Err(bad("ISO9660 missing final extent"));
        }
    }
    fs.validate()?;
    Ok(fs)
}
