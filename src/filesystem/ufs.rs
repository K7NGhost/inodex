//! Native UFS1/UFS2 inode, cylinder-group, directory and indirect-block reader.
use super::{FileKind, FsInfo, FsType, Limits, Times, indexed::*};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{HashSet, VecDeque};
#[derive(Clone, Copy)]
struct Endian(bool);
impl Endian {
    fn u16(self, d: &[u8], o: usize) -> Result<u16> {
        if self.0 { u16be(d, o) } else { u16le(d, o) }
    }
    fn u32(self, d: &[u8], o: usize) -> Result<u32> {
        if self.0 { u32be(d, o) } else { u32le(d, o) }
    }
    fn u64(self, d: &[u8], o: usize) -> Result<u64> {
        if self.0 { u64be(d, o) } else { u64le(d, o) }
    }
}
pub(super) fn detect(image: &mut dyn DiskImage) -> Result<bool> {
    for at in [8192, 65536, 262144] {
        if image.len() >= at + 1536 {
            let d = read_vec(image, at + 1372, 4)?;
            if [u32le(&d, 0)?, u32be(&d, 0)?]
                .iter()
                .any(|v| [0x11954, 0x19540119].contains(v))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
pub(super) fn open(image: &mut dyn DiskImage, limits: Limits) -> Result<IndexedFs<'_>> {
    let mut found = None;
    for at in [8192, 65536, 262144] {
        if image.len() < at + 1536 {
            continue;
        }
        let sb = read_vec(image, at, 1536)?;
        for e in [Endian(false), Endian(true)] {
            let magic = e.u32(&sb, 1372)?;
            if [0x11954, 0x19540119].contains(&magic) {
                found = Some((sb, e, magic == 0x19540119));
                break;
            }
        }
        if found.is_some() {
            break;
        }
    }
    let (sb, e, v2) = found.ok_or_else(|| bad("UFS superblock not found"))?;
    let block = e.u32(&sb, 48)? as u64;
    let frag = e.u32(&sb, 52)? as u64;
    let ipg = e.u32(&sb, 184)? as u64;
    let fpg = e.u32(&sb, 188)? as u64;
    let groups = e.u32(&sb, 44)? as u64;
    let ino_size = if v2 { 256 } else { 128 };
    let fragments = if v2 {
        e.u64(&sb, 1080)?
    } else {
        u64::from(e.u32(&sb, 36)?)
    };
    if !(4096..=65536).contains(&block)
        || !block.is_power_of_two()
        || !(512..=block).contains(&frag)
        || !frag.is_power_of_two()
        || block / frag > 8
        || ipg == 0
        || fpg == 0
        || groups == 0
        || e.u32(&sb, 120)? as u64 != block / ino_size
        || u64::from(e.u32(&sb, 56)?) != block / frag
    {
        return Err(bad("UFS geometry"));
    }
    let total = fragments
        .checked_mul(frag)
        .ok_or_else(|| bad("UFS size overflow"))?;
    checked_region(0, total, image.len(), "UFS")?;
    // Solaris uses the old directory layout (u16 name length, no type byte).
    // Inspect the root's mandatory '.' record rather than guessing from endian.
    let solaris = if v2 {
        false
    } else {
        let root = u64::from(e.u32(&sb, 16)?) * frag + 2 * ino_size;
        let inode = read_vec(image, root, ino_size as usize)?;
        if e.u16(&inode, 0)? & 0xf000 != 0x4000 {
            return Err(bad("UFS root is not a directory"));
        }
        let data = read_vec(image, u64::from(e.u32(&inode, 40)?) * frag, 12)?;
        if e.u32(&data, 0)? != 2 || e.u16(&data, 4)? < 12 || &data[8..10] != b".\0" {
            return Err(bad("UFS root dot record"));
        }
        if data[6..8] == [4, 1] {
            false
        } else if e.u16(&data, 6)? == 1 {
            let state = e.u32(&sb, if e.0 { 1336 } else { 132 })?;
            if e.u32(&sb, 1320)? > 2
                || e.u32(&sb, 1356)? != 1
                || state.wrapping_add(e.u32(&sb, 32)?) != 0x7c269d38
            {
                return Err(Error::Unsupported("ambiguous old UFS directory layout; Solaris superblock state signature required".into()));
            }
            true
        } else {
            return Err(bad("UFS directory layout"));
        }
    };
    let info = FsInfo {
        filesystem: if v2 {
            FsType::Ufs2
        } else if solaris {
            FsType::Ufs1b
        } else {
            FsType::Ufs1
        },
        label: String::new(),
        block_size: block as u32,
        total_bytes: total,
        root_id: 2,
        needs_journal_recovery: sb[209] == 0,
    };
    let mut fs = IndexedFs::new(image, info, limits);
    let mut queue = VecDeque::from([(2, 0usize)]);
    let mut seen = HashSet::new();
    let mut edges = vec![];
    while let Some((id, depth)) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        if depth > fs.limits.max_tree_depth {
            return Err(Error::ResourceLimit("UFS directory depth"));
        }
        if id
            >= groups
                .checked_mul(ipg)
                .ok_or_else(|| bad("UFS inode count overflow"))?
        {
            return Err(bad("UFS inode outside groups"));
        }
        let cg = id / ipg;
        let delta = if v2 {
            0
        } else {
            u64::from(e.u32(&sb, 24)?) * (cg & !u64::from(e.u32(&sb, 28)?))
        };
        let base = (cg * fpg)
            .checked_add(delta)
            .ok_or_else(|| bad("UFS group offset overflow"))?;
        if base >= fragments {
            return Err(bad("UFS group outside volume"));
        }
        let descriptor = base
            .checked_add(u64::from(e.u32(&sb, 12)?))
            .and_then(|v| v.checked_mul(frag))
            .ok_or_else(|| bad("UFS group address overflow"))?;
        checked_region(descriptor, 100, total, "UFS cylinder group")?;
        let group = read_vec(fs.image, descriptor, 100)?;
        if e.u32(&group, 4)? != 0x90255 || u64::from(e.u32(&group, 12)?) != cg {
            return Err(bad("UFS cylinder group"));
        }
        let bitmap = u64::from(e.u32(&group, 92)?);
        let cgsize = u64::from(e.u32(&sb, 160)?);
        checked_region(descriptor, cgsize, total, "UFS cylinder group")?;
        checked_region(bitmap, ipg.div_ceil(8), cgsize, "UFS inode bitmap")?;
        let bit = id % ipg;
        let alloc =
            read_vec(fs.image, descriptor + bitmap + bit / 8, 1)?[0] & (1 << (bit % 8)) != 0;
        if !alloc {
            return Err(bad("UFS directory references unallocated inode"));
        }
        let address = base
            .checked_add(u64::from(e.u32(&sb, 16)?))
            .and_then(|v| v.checked_mul(frag))
            .and_then(|v| v.checked_add((id % ipg) * ino_size))
            .ok_or_else(|| bad("UFS inode address overflow"))?;
        checked_region(address, ino_size, total, "UFS inode")?;
        let inode = read_vec(fs.image, address, ino_size as usize)?;
        let size = e.u64(&inode, if v2 { 16 } else { 8 })?;
        let mode = e.u16(&inode, 0)?;
        let mut meta = metadata(id, mode, size);
        meta.links = u32::from(e.u16(&inode, 2)?);
        meta.uid = Some(e.u32(
            &inode,
            if v2 {
                4
            } else if solaris {
                116
            } else {
                112
            },
        )?);
        meta.gid = Some(e.u32(
            &inode,
            if v2 {
                8
            } else if solaris {
                120
            } else {
                116
            },
        )?);
        let timestamp = |sec: usize, ns: usize| -> Result<Option<super::Timestamp>> {
            let seconds = if v2 {
                e.u64(&inode, sec)? as i64
            } else {
                e.u32(&inode, sec)? as i32 as i64
            };
            let nanos = e.u32(&inode, ns)?;
            let nanos = if solaris {
                nanos
                    .checked_mul(1000)
                    .ok_or_else(|| bad("UFS microseconds overflow"))?
            } else {
                nanos
            };
            Ok(Some(utc(seconds, nanos)?))
        };
        meta.times = if v2 {
            Times {
                created: timestamp(56, 76)?,
                accessed: timestamp(32, 68)?,
                modified: timestamp(40, 64)?,
                changed: timestamp(48, 72)?,
            }
        } else {
            Times {
                created: None,
                accessed: timestamp(16, 20)?,
                modified: timestamp(24, 28)?,
                changed: timestamp(32, 36)?,
            }
        };
        let start = if v2 { 112 } else { 40 };
        let pointer_size = if v2 { 8 } else { 4 };
        let mut data = Data {
            size,
            ..Data::default()
        };
        let blocks = size.div_ceil(block);
        if meta.kind == FileKind::Symlink && size < (15 * pointer_size) as u64 {
            data.inline = Some(bytes(&inode, start, size as usize)?.to_vec());
        } else if matches!(
            meta.kind,
            FileKind::File | FileKind::Directory | FileKind::Symlink
        ) {
            if blocks > fs.limits.max_chain_length as u64
                || blocks > fs.limits.max_metadata_bytes as u64 / 32
            {
                return Err(Error::ResourceLimit("UFS file blocks"));
            }
            let ptr = |d: &[u8], at: usize| -> Result<u64> {
                if v2 {
                    e.u64(d, at)
                } else {
                    Ok(u64::from(e.u32(d, at)?))
                }
            };
            for logical in 0..blocks {
                let mut b;
                if logical < 12 {
                    b = ptr(&inode, start + logical as usize * pointer_size)?;
                } else {
                    let per = block / pointer_size as u64;
                    let mut relative = logical - 12;
                    let mut level = 1u32;
                    while level <= 3 && relative >= per.pow(level) {
                        relative -= per.pow(level);
                        level += 1;
                    }
                    if level > 3 {
                        return Err(bad("UFS file exceeds indirect addressing"));
                    }
                    b = ptr(&inode, start + (11 + level as usize) * pointer_size)?;
                    let mut visited = HashSet::new();
                    for depth in (0..level).rev() {
                        if b == 0 {
                            break;
                        }
                        if !visited.insert(b) {
                            return Err(bad("UFS cyclic indirect block"));
                        }
                        let physical = b
                            .checked_mul(frag)
                            .ok_or_else(|| bad("UFS block overflow"))?;
                        checked_region(physical, block, total, "UFS indirect block")?;
                        let d = read_vec(fs.image, physical, block as usize)?;
                        let index = relative / per.pow(depth);
                        relative %= per.pow(depth);
                        b = ptr(&d, index as usize * pointer_size)?;
                    }
                }
                let length = (size - logical * block).min(block);
                let physical = if b == 0 {
                    None
                } else {
                    Some(
                        b.checked_mul(frag)
                            .ok_or_else(|| bad("UFS fragment overflow"))?,
                    )
                };
                if let Some(p) = physical {
                    checked_region(p, length, total, "UFS file block")?;
                }
                data.runs.push(Run {
                    logical: logical * block,
                    physical,
                    length,
                });
            }
        }
        if meta.kind == FileKind::Directory {
            if size > fs.limits.max_directory_bytes || size > usize::MAX as u64 {
                return Err(Error::ResourceLimit("UFS directory bytes"));
            }
            let mut d = vec![0; size as usize];
            read_data(fs.image, &data, 0, &mut d)?;
            let mut at = 0;
            while at < d.len() {
                let child = u64::from(e.u32(&d, at)?);
                let reclen = e.u16(&d, at + 4)? as usize;
                let len = if solaris {
                    e.u16(&d, at + 6)? as usize
                } else {
                    *bytes(&d, at + 7, 1)?.first().unwrap() as usize
                };
                if reclen < 8 || !reclen.is_multiple_of(4) || at % 512 + reclen > 512 {
                    return Err(bad("UFS directory record length"));
                }
                bytes(&d, at, reclen)?;
                if len > 255 || len + 8 >= reclen || bytes(&d, at + 8 + len, 1)?[0] != 0 {
                    return Err(bad("UFS directory name length"));
                }
                if child != 0 {
                    let raw = bytes(&d, at + 8, len)?.to_vec();
                    if raw != b"." && raw != b".." {
                        let name = String::from_utf8_lossy(&raw).into_owned();
                        edges.push((id, child, name, raw));
                        queue.push_back((child, depth + 1));
                        if edges.len() > fs.limits.max_directory_entries {
                            return Err(Error::ResourceLimit("UFS directory entries"));
                        }
                    }
                }
                at += reclen;
            }
        }
        fs.insert(node(meta, data))?;
    }
    for (p, id, name, raw) in edges {
        fs.link(p, id, name, Some(raw))?;
    }
    fs.validate()?;
    Ok(fs)
}
