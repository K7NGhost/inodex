//! APFS containers, checkpoints, object maps and live filesystem B-trees.
use super::{FileKind, FsInfo, FsType, Limits, StreamInfo, Times, indexed::*};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::{BTreeMap, HashSet};
const MASK: u64 = 0x0fff_ffff_ffff_ffff;
#[derive(Clone, Debug, serde::Serialize)]
pub struct VolumeInfo {
    pub oid: u64,
    pub name: String,
    pub encrypted: bool,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct SnapshotInfo {
    pub xid: u64,
    pub name: String,
    pub superblock: u64,
    pub created: super::Timestamp,
    pub changed: super::Timestamp,
    pub flags: u32,
}
struct Reader<'a> {
    image: &'a mut dyn DiskImage,
    block: u64,
    total: u64,
    limits: Limits,
    xid: u64,
}
fn checksum(d: &[u8]) -> Result<()> {
    let mut a = 0u64;
    let mut b = 0u64;
    let m = 0xffff_ffff;
    for w in d[8..].as_chunks::<4>().0 {
        a = (a + u64::from(u32::from_le_bytes(*w))) % m;
        b = (b + a) % m;
    }
    let c = m - (a + b) % m;
    let e = m - (a + c) % m;
    if u64le(d, 0)? != c | (e << 32) {
        return Err(bad("APFS object checksum"));
    }
    Ok(())
}
type Mapping = BTreeMap<u64, (u64, u64, u32)>;
impl<'a> Reader<'a> {
    fn object(&mut self, p: u64) -> Result<Vec<u8>> {
        let at = p
            .checked_mul(self.block)
            .ok_or_else(|| bad("APFS block overflow"))?;
        checked_region(at, self.block, self.total, "APFS object")?;
        let d = read_vec(self.image, at, self.block as usize)?;
        checksum(&d)?;
        if u64le(&d, 16)? > self.xid {
            return Err(bad("APFS object newer than selected checkpoint"));
        }
        if u16le(&d, 26)? & 0x1000 != 0 {
            return Err(Error::Unsupported("APFS encrypted metadata".into()));
        }
        Ok(d)
    }
    fn tree(
        &mut self,
        root: u64,
        map: Option<&Mapping>,
        fixed: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut todo = vec![(root, 0usize, None)];
        let mut seen = HashSet::new();
        let mut out = vec![];
        let mut budget = 0usize;
        while let Some((id, depth, parent_level)) = todo.pop() {
            if depth > self.limits.max_tree_depth || seen.len() >= self.limits.max_chain_length {
                return Err(Error::ResourceLimit("APFS B-tree traversal"));
            }
            let physical = if let Some(m) = map {
                resolve(m, id, self.block)?
            } else {
                id
            };
            if !seen.insert(physical) {
                return Err(bad("APFS B-tree cycle"));
            }
            let d = self.object(physical)?;
            if map.is_some() && u64le(&d, 8)? != id {
                return Err(bad("APFS mapped object identity"));
            }
            let typ = u16le(&d, 24)?;
            if ![2, 3].contains(&typ) {
                return Err(bad("APFS B-tree object type"));
            }
            let flags = u16le(&d, 32)?;
            let level = u16le(&d, 34)?;
            if parent_level.is_some_and(|v: u16| level.checked_add(1) != Some(v))
                || ((flags & 2 != 0) != (level == 0))
                || ((flags & 4 != 0) != fixed)
            {
                return Err(bad("APFS B-tree level/flags"));
            }
            let count = u32le(&d, 36)? as usize;
            let ts = 56 + u16le(&d, 40)? as usize;
            let tl = u16le(&d, 42)? as usize;
            let width = if fixed { 4 } else { 8 };
            if count > self.limits.max_directory_entries
                || count.checked_mul(width).is_none_or(|n| n > tl)
            {
                return Err(bad("APFS B-tree table size"));
            }
            bytes(&d, ts, tl)?;
            let keybase = ts + tl;
            let end = d.len() - if flags & 1 != 0 { 40 } else { 0 };
            if keybase > end {
                return Err(bad("APFS B-tree key area"));
            }
            for i in 0..count {
                let entry = ts + i * width;
                let ko = u16le(&d, entry)? as usize;
                let kl = if fixed {
                    16
                } else {
                    u16le(&d, entry + 2)? as usize
                };
                let vo = u16le(&d, entry + if fixed { 2 } else { 4 })? as usize;
                let vl = if level > 0 {
                    8
                } else if fixed {
                    16
                } else {
                    u16le(&d, entry + 6)? as usize
                };
                let vs = end
                    .checked_sub(vo)
                    .ok_or_else(|| bad("APFS value offset"))?;
                let ks = keybase
                    .checked_add(ko)
                    .ok_or_else(|| bad("APFS key offset"))?;
                if ks + kl > vs || vs + vl > end || vs < keybase {
                    return Err(bad("APFS key/value bounds"));
                }
                let key = bytes(&d, ks, kl)?;
                let value = bytes(&d, vs, vl)?;
                if level > 0 {
                    todo.push((u64le(value, 0)?, depth + 1, Some(level)));
                } else {
                    budget = budget
                        .checked_add(kl + vl + 48)
                        .ok_or(Error::ResourceLimit("APFS tree records"))?;
                    if budget > self.limits.max_metadata_bytes
                        || out.len() >= self.limits.max_directory_entries
                    {
                        return Err(Error::ResourceLimit("APFS tree records"));
                    }
                    out.push((key.to_vec(), value.to_vec()));
                }
            }
        }
        Ok(out)
    }
    fn omap(&mut self, p: u64) -> Result<Mapping> {
        self.omap_at(p, self.xid)
    }
    fn omap_at(&mut self, p: u64, selected_xid: u64) -> Result<Mapping> {
        let d = self.object(p)?;
        if u16le(&d, 24)? != 11 {
            return Err(bad("APFS object-map type"));
        }
        let root = u64le(&d, 48)?;
        let records = self.tree(root, None, true)?;
        let mut map = Mapping::new();
        for (k, v) in records {
            let oid = u64le(&k, 0)?;
            let xid = u64le(&k, 8)?;
            if xid > selected_xid {
                continue;
            }
            let flags = u32le(&v, 0)?;
            let size = u32le(&v, 4)?;
            if flags & 1 == 0 && size != self.block as u32 {
                return Err(Error::Unsupported("APFS multi-block mapped object".into()));
            }
            let physical = u64le(&v, 8)?;
            if map.get(&oid).is_none_or(|(old, _, _)| xid > *old) {
                map.insert(oid, (xid, physical, flags));
            }
        }
        Ok(map)
    }
}
fn resolve(map: &Mapping, id: u64, block: u64) -> Result<u64> {
    let &(_, p, flags) = map
        .get(&id)
        .ok_or_else(|| bad(format!("APFS unmapped object {id}")))?;
    if flags & 1 != 0 {
        return Err(bad("APFS deleted object reference"));
    }
    if flags & 12 != 0 {
        return Err(Error::Unsupported(
            "APFS encrypted/headerless mapped object".into(),
        ));
    }
    if p > u64::MAX / block {
        return Err(bad("APFS object address overflow"));
    }
    Ok(p)
}
fn container(image: &mut dyn DiskImage, limits: Limits) -> Result<(Reader<'_>, Vec<u8>, Mapping)> {
    let head = read_vec(image, 0, 4096)?;
    if &head[32..36] != b"NXSB" {
        return Err(bad("APFS container magic"));
    }
    let block = u64::from(u32le(&head, 36)?);
    if !block.is_power_of_two()
        || !(4096..=65536).contains(&block)
        || block > limits.max_metadata_bytes as u64
    {
        return Err(bad("APFS block size"));
    }
    let total = u64le(&head, 40)?
        .checked_mul(block)
        .ok_or_else(|| bad("APFS container size overflow"))?;
    checked_region(0, total, image.len(), "APFS container")?;
    let mut reader = Reader {
        image,
        block,
        total,
        limits,
        xid: u64::MAX,
    };
    let mut nx = reader.object(0)?;
    if u64le(&nx, 64)? & !3 != 0 {
        return Err(Error::Unsupported(
            "APFS Fusion/new container features".into(),
        ));
    }
    let count = u32le(&nx, 104)?;
    if count & 0x8000_0000 != 0 {
        return Err(Error::Unsupported("APFS checkpoint descriptor tree".into()));
    }
    if count as usize > reader.limits.max_chain_length {
        return Err(Error::ResourceLimit("APFS checkpoint blocks"));
    }
    let base = u64le(&nx, 112)?;
    checked_region(
        base.checked_mul(block)
            .ok_or_else(|| bad("APFS checkpoint offset"))?,
        u64::from(count) * block,
        total,
        "APFS checkpoints",
    )?;
    for i in 0..u64::from(count) {
        let at = (base + i) * block;
        let d = read_vec(reader.image, at, block as usize)?;
        if &d[32..36] == b"NXSB" && checksum(&d).is_ok() && u64le(&d, 16)? > u64le(&nx, 16)? {
            if u64le(&d, 40)?.checked_mul(block) != Some(total) || u32le(&d, 36)? as u64 != block {
                return Err(bad("APFS checkpoint geometry disagreement"));
            }
            nx = d;
        }
    }
    reader.xid = u64le(&nx, 16)?;
    let map = reader.omap(u64le(&nx, 160)?)?;
    Ok((reader, nx, map))
}
fn text(d: &[u8]) -> Result<String> {
    let end = d.iter().position(|b| *b == 0).unwrap_or(d.len());
    String::from_utf8(d[..end].to_vec()).map_err(|_| bad("APFS invalid UTF-8"))
}
pub fn volumes(image: &mut dyn DiskImage, limits: Limits) -> Result<Vec<VolumeInfo>> {
    let (mut r, nx, map) = container(image, limits)?;
    let mut out = vec![];
    for i in 0..100 {
        let oid = u64le(&nx, 184 + i * 8)?;
        if oid == 0 {
            continue;
        }
        let d = r.object(resolve(&map, oid, r.block)?)?;
        if &d[32..36] != b"APSB" {
            return Err(bad("APFS volume magic"));
        }
        out.push(VolumeInfo {
            oid,
            name: text(bytes(&d, 704, 256)?)?,
            encrypted: u64le(&d, 264)? & 1 == 0,
        });
    }
    Ok(out)
}
pub(super) fn open(image: &mut dyn DiskImage, limits: Limits) -> Result<IndexedFs<'_>> {
    open_volume(image, limits, None)
}
fn volume_block(
    reader: &mut Reader<'_>,
    nx: &[u8],
    map: &Mapping,
    volume_oid: Option<u64>,
) -> Result<Vec<u8>> {
    let mut chosen = None;
    for i in 0..100 {
        let oid = u64le(nx, 184 + i * 8)?;
        if oid != 0 && volume_oid.is_none_or(|v| v == oid) {
            chosen = Some(oid);
            break;
        }
    }
    let oid = chosen.ok_or_else(|| Error::NotFound("APFS volume".into()))?;
    let sb = reader.object(resolve(map, oid, reader.block)?)?;
    if &sb[32..36] != b"APSB" || u16le(&sb, 24)? != 13 {
        return Err(bad("APFS volume superblock"));
    }
    if u64le(&sb, 264)? & 1 == 0 {
        return Err(Error::Unsupported("APFS encrypted volume".into()));
    }
    Ok(sb)
}
fn snapshot_records(reader: &mut Reader<'_>, sb: &[u8]) -> Result<Vec<SnapshotInfo>> {
    let root = u64le(sb, 152)?;
    if root == 0 {
        return Ok(vec![]);
    }
    if u32le(&reader.object(root)?, 28)? != 16 {
        return Err(bad("APFS snapshot metadata tree subtype"));
    }
    let rows = reader.tree(root, None, false)?;
    let mut out = BTreeMap::new();
    for (k, v) in rows {
        let key = u64le(&k, 0)?;
        if key >> 60 != 1 {
            continue;
        }
        let xid = key & MASK;
        let n = u16le(&v, 48)? as usize;
        let name = bytes(&v, 50, n)?;
        if xid == 0 || xid > reader.xid || n == 0 || name[n - 1] != 0 {
            return Err(bad("APFS snapshot key/name"));
        }
        let time = |at| -> Result<_> {
            let t = u64le(&v, at)? as i64;
            utc(
                t.div_euclid(1_000_000_000),
                t.rem_euclid(1_000_000_000) as u32,
            )
        };
        let entry = SnapshotInfo {
            xid,
            name: text(name)?,
            superblock: u64le(&v, 8)?,
            created: time(16)?,
            changed: time(24)?,
            flags: u32le(&v, 44)?,
        };
        if out.insert(xid, entry).is_some() {
            return Err(bad("duplicate APFS snapshot XID"));
        }
    }
    Ok(out.into_values().collect())
}
/// Enumerate recorded snapshots in an unencrypted APFS volume.
pub fn snapshots(
    image: &mut dyn DiskImage,
    limits: Limits,
    volume_oid: Option<u64>,
) -> Result<Vec<SnapshotInfo>> {
    let (mut reader, nx, map) = container(image, limits)?;
    let sb = volume_block(&mut reader, &nx, &map, volume_oid)?;
    snapshot_records(&mut reader, &sb)
}
/// Open the filesystem tree and object versions recorded at a snapshot's XID.
pub fn open_snapshot(
    image: &mut dyn DiskImage,
    limits: Limits,
    volume_oid: Option<u64>,
    xid: u64,
) -> Result<IndexedFs<'_>> {
    open_selected(image, limits, volume_oid, Some(xid))
}
pub fn open_volume(
    image: &mut dyn DiskImage,
    limits: Limits,
    volume_oid: Option<u64>,
) -> Result<IndexedFs<'_>> {
    open_selected(image, limits, volume_oid, None)
}
fn open_selected(
    image: &mut dyn DiskImage,
    limits: Limits,
    volume_oid: Option<u64>,
    snapshot_xid: Option<u64>,
) -> Result<IndexedFs<'_>> {
    let (mut reader, nx, container_map) = container(image, limits.clone())?;
    let mut sb = volume_block(&mut reader, &nx, &container_map, volume_oid)?;
    let omap = u64le(&sb, 128)?;
    let mut selected_map = None;
    if let Some(xid) = snapshot_xid {
        let snap = snapshot_records(&mut reader, &sb)?
            .into_iter()
            .find(|s| s.xid == xid)
            .ok_or_else(|| Error::NotFound(format!("APFS snapshot {xid}")))?;
        if snap.flags != 0 {
            return Err(Error::Unsupported("APFS pending/dataless snapshot".into()));
        }
        let saved = reader.object(snap.superblock)?;
        if &saved[32..36] != b"APSB"
            || u16le(&saved, 24)? != 13
            || saved[240..256] != sb[240..256]
            || u64le(&saved, 16)? > xid
            || u64le(&saved, 264)? & 1 == 0
        {
            return Err(bad("APFS snapshot superblock identity/transaction"));
        }
        selected_map = Some(reader.omap_at(omap, xid)?);
        reader.xid = xid;
        sb = saved;
    }
    let features = u64le(&sb, 56)?;
    if features & !0xb != 0 {
        return Err(Error::Unsupported(
            "APFS incompatible volume features".into(),
        ));
    }
    let map = if let Some(map) = selected_map {
        map
    } else {
        reader.omap(omap)?
    };
    let root = u64le(&sb, 136)?;
    let records = reader.tree(root, Some(&map), false)?;
    let block = reader.block;
    let total = reader.total;
    let mut fs = IndexedFs::new(
        reader.image,
        FsInfo {
            filesystem: FsType::Apfs,
            label: text(bytes(&sb, 704, 256)?)?,
            block_size: block as u32,
            total_bytes: total,
            root_id: 2,
            needs_journal_recovery: false,
        },
        limits,
    );
    fs.ascii_fold = features & 1 != 0;
    let mut streams: BTreeMap<u64, Vec<Run>> = BTreeMap::new();
    let mut private = BTreeMap::new();
    let mut sparse = HashSet::new();
    let mut edges = vec![];
    let mut attrs = vec![];
    for (k, v) in records {
        let key = u64le(&k, 0)?;
        let id = key & MASK;
        match key >> 60 {
            3 => {
                bytes(&v, 0, 92)?;
                let mut m = metadata(id, u16le(&v, 80)?, 0);
                m.uid = Some(u32le(&v, 72)?);
                m.gid = Some(u32le(&v, 76)?);
                if m.kind != FileKind::Directory {
                    m.links = u32le(&v, 56)?;
                }
                let time = |at| -> Result<Option<super::Timestamp>> {
                    let n = u64le(&v, at)? as i64;
                    Ok(Some(utc(
                        n.div_euclid(1_000_000_000),
                        n.rem_euclid(1_000_000_000) as u32,
                    )?))
                };
                m.times = Times {
                    created: time(16)?,
                    modified: time(24)?,
                    changed: time(32)?,
                    accessed: time(40)?,
                };
                if v.len() > 92 {
                    let n = u16le(&v, 92)? as usize;
                    let mut data_at = 96 + n * 4;
                    bytes(&v, 96, n * 4)?;
                    for i in 0..n {
                        let desc = 96 + i * 4;
                        let len = u16le(&v, desc + 2)? as usize;
                        let field = bytes(&v, data_at, len)?;
                        if v[desc] == 8 {
                            m.size = u64le(field, 0)?;
                        }
                        data_at = data_at
                            .checked_add(len.div_ceil(8) * 8)
                            .ok_or_else(|| bad("APFS extended field size"))?;
                    }
                }
                let mut d = Data {
                    size: m.size,
                    ..Data::default()
                };
                if u32le(&v, 68)? & 0x20 != 0 {
                    d.unsupported = Some("APFS compressed file".into());
                }
                private.insert(id, u64le(&v, 8)?);
                if u64le(&v, 48)? & 0x200 != 0 {
                    sparse.insert(id);
                }
                fs.insert(node(m, d))?;
            }
            8 => {
                let logical = u64le(&k, 8)?;
                let packed = u64le(&v, 0)?;
                let length = packed & 0x00ff_ffff_ffff_ffff;
                if packed >> 56 != 0 {
                    return Err(Error::Unsupported("APFS extent flags".into()));
                }
                let p = u64le(&v, 8)?;
                let physical = if p == 0 {
                    None
                } else {
                    Some(
                        p.checked_mul(block)
                            .ok_or_else(|| bad("APFS extent offset"))?,
                    )
                };
                let list = streams.entry(id).or_default();
                if list.len() >= fs.limits.max_chain_length {
                    return Err(Error::ResourceLimit("APFS extents"));
                }
                list.push(Run {
                    logical,
                    physical,
                    length,
                });
            }
            9 => {
                let (at, len) = if features & 9 != 0 {
                    (12, (u32le(&k, 8)? & 0x3ff) as usize)
                } else {
                    (10, u16le(&k, 8)? as usize)
                };
                let name = text(bytes(&k, at, len)?)?;
                edges.push((id, u64le(&v, 0)?, name));
            }
            4 => {
                let len = u16le(&k, 8)? as usize;
                let name = text(bytes(&k, 10, len)?)?;
                let flags = u16le(&v, 0)?;
                let length = u16le(&v, 2)? as usize;
                let payload = bytes(&v, 4, length)?.to_vec();
                attrs.push((id, name, flags, payload));
            }
            _ => {}
        }
    }
    for (id, stream) in private {
        if let Some(runs) = streams.get(&stream) {
            fs.reserve_data(runs.len() * 32)?;
            fs.nodes
                .get_mut(&id)
                .unwrap()
                .data
                .get_mut("")
                .unwrap()
                .runs = runs.clone();
        }
    }
    for (id, name, flags, payload) in attrs {
        let Some(n) = fs.nodes.get_mut(&id) else {
            continue;
        };
        let mut d = Data::default();
        if flags & 2 != 0 {
            d.size = payload.len() as u64;
            d.inline = Some(payload);
        } else if flags & 1 != 0 {
            let stream = u64le(&payload, 0)?;
            d.size = u64le(&payload, 8)?;
            d.runs = streams.get(&stream).cloned().unwrap_or_default();
        } else {
            continue;
        }
        if name == "com.apple.fs.symlink" {
            if d.inline.is_none() {
                if d.size > fs.limits.max_metadata_bytes as u64 {
                    return Err(Error::ResourceLimit("APFS symlink bytes"));
                }
                let mut value = vec![0; d.size as usize];
                read_data(fs.image, &d, 0, &mut value)?;
                d.inline = Some(value);
                d.runs.clear();
            }
            if let Some(inline) = d.inline.as_mut()
                && inline.last() == Some(&0)
            {
                inline.pop();
                d.size = inline.len() as u64;
            }
            n.meta.size = d.size;
            n.data.insert(String::new(), d);
        } else {
            n.meta.streams.push(StreamInfo {
                name: name.clone(),
                size: d.size,
                resident: d.inline.is_some(),
                compressed: false,
                encrypted: false,
            });
            n.data.insert(name, d);
        }
    }
    if !fs.nodes.contains_key(&2) {
        return Err(bad("APFS root inode missing"));
    }
    super::decmpfs::apply(&mut fs)?;
    for (&id, n) in &fs.nodes {
        let d = &n.data[""];
        if d.size != 0
            && d.inline.is_none()
            && d.compressed.is_none()
            && d.runs.is_empty()
            && d.unsupported.is_none()
            && !sparse.contains(&id)
        {
            return Err(bad("APFS file data stream has no extents"));
        }
    }
    if edges.iter().any(|(p, _, _)| *p == 1) && !fs.nodes.contains_key(&1) {
        fs.insert(node(metadata(1, 0x4000, 0), Data::default()))?;
    }
    for (p, id, name) in edges {
        if p == 1 && id == 2 {
            continue;
        }
        fs.link(p, id, name, None)?;
    }
    fs.validate()?;
    Ok(fs)
}
