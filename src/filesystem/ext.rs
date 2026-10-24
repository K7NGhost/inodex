//! ext2/3/4 inodes, indirect blocks, extents, directories and metadata checksums.
use super::{DirEntry, FileKind, FsInfo, FsType, Limits, Metadata, TimeBasis, Times, Timestamp};
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use std::collections::HashSet;

#[derive(Clone)]
struct Inode {
    data: Vec<u8>,
    metadata: Metadata,
    flags: u32,
    generation: u32,
}
pub struct Ext<'a> {
    image: &'a mut dyn DiskImage,
    info: FsInfo,
    limits: Limits,
    block_size: u64,
    blocks: u64,
    inodes: u32,
    inodes_per_group: u32,
    groups: u64,
    inode_size: usize,
    descriptor_size: usize,
    descriptor_offset: u64,
    incompat: u32,
    ro_compat: u32,
    seed: u32,
    uuid: [u8; 16],
    cached: Option<(u64, Inode)>,
}
impl<'a> Ext<'a> {
    pub fn open(image: &'a mut dyn DiskImage, limits: Limits) -> Result<Self> {
        let sb = read_vec(image, 1024, 1024)?;
        if u16le(&sb, 56)? != 0xef53 {
            return Err(corrupt("ext", 1024, "invalid superblock signature"));
        }
        let revision = u32le(&sb, 76)?;
        if revision > 1 {
            return Err(Error::Unsupported("unknown ext superblock revision".into()));
        }
        if u32le(&sb, 72)? != 0 {
            return Err(Error::Unsupported(
                "non-Linux ext creator OS metadata".into(),
            ));
        }
        let log_block = u32le(&sb, 24)?;
        if log_block > 6 {
            return Err(corrupt("ext", 1048, "invalid block size"));
        }
        let block_size = 1024_u64 << log_block;
        let compat = if revision == 0 { 0 } else { u32le(&sb, 92)? };
        let incompat = if revision == 0 { 0 } else { u32le(&sb, 96)? };
        let ro_compat = if revision == 0 { 0 } else { u32le(&sb, 100)? };
        // Unsupported layout-changing incompat features never fall back to ext2.
        let understood =
            0x2 | 0x4 | 0x40 | 0x80 | 0x200 | 0x400 | 0x2000 | 0x4000 | 0x8000 | 0x10000 | 0x20000;
        if incompat & !understood != 0 {
            return Err(Error::Unsupported(format!(
                "ext incompatible feature flags {:#x}",
                incompat & !understood
            )));
        }
        if ro_compat & 0x200 != 0 {
            return Err(Error::Unsupported("ext4 bigalloc".into()));
        }
        let uuid: [u8; 16] = sb[104..120].try_into().unwrap();
        if ro_compat & 0x400 != 0 {
            if sb[373] != 1 {
                return Err(Error::Unsupported("ext metadata checksum algorithm".into()));
            }
            check_checksum(
                crc32c(!0, &sb[..1020]),
                u32le(&sb, 1020)?,
                1024,
                "ext superblock CRC32C",
            )?;
        }
        let seed = if incompat & 0x2000 != 0 {
            u32le(&sb, 624)?
        } else {
            crc32c(!0, &uuid)
        };
        let blocks = u64::from(u32le(&sb, 4)?)
            | if incompat & 0x80 != 0 {
                u64::from(u32le(&sb, 336)?) << 32
            } else {
                0
            };
        let total_bytes = blocks
            .checked_mul(block_size)
            .ok_or_else(|| corrupt("ext", 1028, "volume size overflow"))?;
        checked_region(0, total_bytes, image.len(), "ext")?;
        let first = u64::from(u32le(&sb, 20)?);
        if first != if block_size == 1024 { 1 } else { 0 } || blocks <= first {
            return Err(corrupt("ext", 1044, "invalid first data block"));
        }
        let blocks_per_group = u32le(&sb, 32)?;
        let inodes_per_group = u32le(&sb, 40)?;
        let inodes = u32le(&sb, 0)?;
        if blocks_per_group == 0
            || u64::from(blocks_per_group) > block_size * 8
            || inodes_per_group == 0
            || u64::from(inodes_per_group) > block_size * 8
            || !inodes_per_group.is_multiple_of(8)
            || inodes < 2
        {
            return Err(corrupt("ext", 1056, "invalid block/inode group geometry"));
        }
        let groups = (blocks - first).div_ceil(u64::from(blocks_per_group));
        if u64::from(inodes).div_ceil(u64::from(inodes_per_group)) > groups {
            return Err(corrupt("ext", 1024, "inode groups exceed block groups"));
        }
        let inode_size = if revision == 0 {
            128
        } else {
            u16le(&sb, 88)? as usize
        };
        let descriptor_size = if incompat & 0x80 != 0 {
            u16le(&sb, 254)? as usize
        } else {
            32
        };
        if !inode_size.is_power_of_two()
            || inode_size < 128
            || inode_size as u64 > block_size
            || inode_size > limits.max_metadata_bytes
        {
            return Err(corrupt("ext", 1112, "invalid inode size"));
        }
        if descriptor_size < if incompat & 0x80 != 0 { 64 } else { 32 }
            || descriptor_size as u64 > block_size
            || !descriptor_size.is_multiple_of(8)
        {
            return Err(corrupt("ext", 1278, "invalid group descriptor size"));
        }
        let descriptor_offset = (first + 1) * block_size;
        checked_region(
            descriptor_offset,
            groups * descriptor_size as u64,
            total_bytes,
            "ext group descriptors",
        )?;
        let label_end = sb[120..136].iter().position(|&b| b == 0).unwrap_or(16);
        let filesystem = if incompat & (0x40 | 0x80) != 0 || ro_compat & (0x400 | 0x40) != 0 {
            FsType::Ext4
        } else if compat & 4 != 0 {
            FsType::Ext3
        } else {
            FsType::Ext2
        };
        let mut fs = Self {
            image,
            info: FsInfo {
                filesystem,
                label: String::from_utf8_lossy(&sb[120..120 + label_end]).into_owned(),
                block_size: block_size as u32,
                total_bytes,
                root_id: 2,
                needs_journal_recovery: incompat & 4 != 0,
            },
            limits,
            block_size,
            blocks,
            inodes,
            inodes_per_group,
            groups,
            inode_size,
            descriptor_size,
            descriptor_offset,
            incompat,
            ro_compat,
            seed,
            uuid,
            cached: None,
        };
        let root = fs.metadata(2)?;
        if root.kind != FileKind::Directory || !root.allocated {
            return Err(corrupt(
                "ext",
                2,
                "root inode is not an allocated directory",
            ));
        }
        Ok(fs)
    }
    pub fn info(&self) -> &FsInfo {
        &self.info
    }
    fn checksum_seed(&self, id: u64, generation: u32) -> u32 {
        crc32c(
            crc32c(self.seed, &(id as u32).to_le_bytes()),
            &generation.to_le_bytes(),
        )
    }
    fn block(&mut self, number: u64) -> Result<Vec<u8>> {
        if number == 0 || number >= self.blocks {
            return Err(corrupt("ext block", number, "block outside the filesystem"));
        }
        read_vec(
            self.image,
            number * self.block_size,
            self.block_size as usize,
        )
    }
    fn inode(&mut self, id: u64) -> Result<Inode> {
        if let Some((cached, inode)) = &self.cached
            && *cached == id
        {
            return Ok(inode.clone());
        }
        if id == 0 || id > u64::from(self.inodes) {
            return Err(corrupt("ext inode", id, "inode number out of range"));
        }
        let group = (id - 1) / u64::from(self.inodes_per_group);
        let within = (id - 1) % u64::from(self.inodes_per_group);
        if group >= self.groups {
            return Err(corrupt("ext inode", id, "inode group out of range"));
        }
        let mut descriptor = read_vec(
            self.image,
            self.descriptor_offset + group * self.descriptor_size as u64,
            self.descriptor_size,
        )?;
        let stored = u16le(&descriptor, 30)?;
        descriptor[30..32].fill(0);
        if self.ro_compat & 0x400 != 0 {
            let calculated = crc32c(
                crc32c(self.seed, &(group as u32).to_le_bytes()),
                &descriptor,
            ) as u16;
            check_checksum(
                u32::from(calculated),
                u32::from(stored),
                group,
                "ext group descriptor CRC32C",
            )?;
        } else if self.ro_compat & 0x10 != 0 {
            let mut calculated = crc16(crc16(0xffff, &self.uuid), &(group as u32).to_le_bytes());
            calculated = crc16(calculated, &descriptor[..30]);
            calculated = crc16(calculated, &descriptor[32..]);
            check_checksum(
                u32::from(calculated),
                u32::from(stored),
                group,
                "ext group descriptor CRC16",
            )?;
        }
        let bitmap_block = u64::from(u32le(&descriptor, 4)?)
            | if self.incompat & 0x80 != 0 {
                u64::from(u32le(&descriptor, 36)?) << 32
            } else {
                0
            };
        let table_block = u64::from(u32le(&descriptor, 8)?)
            | if self.incompat & 0x80 != 0 {
                u64::from(u32le(&descriptor, 40)?) << 32
            } else {
                0
            };
        if table_block == 0 || table_block >= self.blocks {
            return Err(corrupt("ext inode", id, "invalid inode table block"));
        }
        let bitmap = self.block(bitmap_block)?;
        if self.ro_compat & 0x400 != 0 && u16le(&descriptor, 18)? & 1 == 0 {
            let calculated = crc32c(self.seed, &bitmap[..self.inodes_per_group as usize / 8]);
            let stored = u32::from(u16le(&descriptor, 26)?)
                | if self.descriptor_size >= 64 {
                    u32::from(u16le(&descriptor, 58)?) << 16
                } else {
                    0
                };
            check_checksum(
                if self.descriptor_size >= 64 {
                    calculated
                } else {
                    calculated & 0xffff
                },
                stored,
                bitmap_block,
                "ext inode bitmap CRC32C",
            )?;
        }
        let allocated = u16le(&descriptor, 18)? & 1 == 0
            && bitmap[within as usize / 8] & (1 << (within % 8)) != 0;
        let location = table_block * self.block_size + within * self.inode_size as u64;
        checked_region(
            location,
            self.inode_size as u64,
            self.info.total_bytes,
            "ext inode table",
        )?;
        let mut data = read_vec(self.image, location, self.inode_size)?;
        let generation = u32le(&data, 100)?;
        let extra = if self.inode_size > 128 {
            u16le(&data, 128)? as usize
        } else {
            0
        };
        if extra > self.inode_size - 128 || !extra.is_multiple_of(4) {
            return Err(corrupt("ext inode", id, "invalid extra inode size"));
        }
        if self.ro_compat & 0x400 != 0 {
            let lo = u16le(&data, 124)?;
            let has_hi = extra >= 4 && self.inode_size >= 132;
            let hi = if has_hi { u16le(&data, 130)? } else { 0 };
            data[124..126].fill(0);
            if has_hi {
                data[130..132].fill(0);
            }
            let calculated = crc32c(self.checksum_seed(id, generation), &data);
            check_checksum(
                if has_hi {
                    calculated
                } else {
                    calculated & 0xffff
                },
                u32::from(lo) | u32::from(hi) << 16,
                location,
                "ext inode CRC32C",
            )?;
        }
        let mode = u16le(&data, 0)?;
        let kind = match mode & 0xf000 {
            0x8000 => FileKind::File,
            0x4000 => FileKind::Directory,
            0xa000 => FileKind::Symlink,
            _ => FileKind::Other,
        };
        let size = u64::from(u32le(&data, 4)?)
            | if matches!(kind, FileKind::File | FileKind::Directory) {
                u64::from(u32le(&data, 108)?) << 32
            } else {
                0
            };
        let flags = u32le(&data, 32)?;
        let time = |base, extra_offset| {
            ext_time(
                &data,
                base,
                if extra_offset + 4 <= 128 + extra {
                    Some(extra_offset)
                } else {
                    None
                },
            )
        };
        let times = Times {
            modified: Some(time(16, 136)?),
            accessed: Some(time(8, 140)?),
            changed: Some(time(12, 132)?),
            created: if extra >= 24 {
                Some(time(144, 148)?)
            } else {
                None
            },
        };
        let metadata = Metadata {
            id,
            kind,
            size,
            allocated,
            links: u32::from(u16le(&data, 26)?),
            mode: Some(mode),
            uid: Some(u32::from(u16le(&data, 2)?) | u32::from(u16le(&data, 120)?) << 16),
            gid: Some(u32::from(u16le(&data, 24)?) | u32::from(u16le(&data, 122)?) << 16),
            sequence: None,
            times,
            streams: Vec::new(),
        };
        let inode = Inode {
            data,
            metadata,
            flags,
            generation,
        };
        self.cached = Some((id, inode.clone()));
        Ok(inode)
    }
    pub fn metadata(&mut self, id: u64) -> Result<Metadata> {
        Ok(self.inode(id)?.metadata)
    }
    fn file_block(&mut self, inode: &Inode, logical: u64) -> Result<Option<u64>> {
        if inode.flags & 0x80000 != 0 {
            return self.extent_block(&inode.data[40..100], logical, None, inode, 0..0x1_0000_0000);
        }
        let width = self.block_size / 4;
        if logical < 12 {
            let physical = u64::from(u32le(&inode.data, 40 + logical as usize * 4)?);
            return self.validate_mapping(physical);
        }
        let mut logical = logical - 12;
        for depth in 1..=3_u32 {
            let capacity = width.pow(depth);
            if logical < capacity {
                let mut physical = u64::from(u32le(&inode.data, 40 + (11 + depth as usize) * 4)?);
                for level in (0..depth).rev() {
                    if physical == 0 {
                        return Ok(None);
                    }
                    let pointer_block = self.block(physical)?;
                    let stride = width.pow(level);
                    let index = logical / stride;
                    logical %= stride;
                    physical = u64::from(u32le(&pointer_block, index as usize * 4)?);
                }
                return self.validate_mapping(physical);
            }
            logical -= capacity;
        }
        Err(corrupt(
            "ext file",
            logical,
            "file exceeds indirect-block addressing capacity",
        ))
    }
    fn validate_mapping(&self, physical: u64) -> Result<Option<u64>> {
        if physical == 0 {
            return Ok(None);
        }
        if physical >= self.blocks {
            return Err(corrupt("ext file", physical, "data block is out of range"));
        }
        Ok(Some(physical))
    }
    fn extent_block(
        &mut self,
        data: &[u8],
        logical: u64,
        expected_depth: Option<u16>,
        inode: &Inode,
        bounds: std::ops::Range<u64>,
    ) -> Result<Option<u64>> {
        if u16le(data, 0)? != 0xf30a {
            return Err(corrupt(
                "ext extent",
                logical,
                "invalid extent header magic",
            ));
        }
        let count = u16le(data, 2)? as usize;
        let max = u16le(data, 4)? as usize;
        let depth = u16le(data, 6)?;
        if count > max
            || max == 0
            || 12 + max * 12 > data.len()
            || depth > 5
            || expected_depth.is_some_and(|expected| expected != depth)
        {
            return Err(corrupt(
                "ext extent",
                logical,
                "invalid extent header bounds/depth",
            ));
        }
        if usize::from(depth) > self.limits.max_tree_depth {
            return Err(Error::ResourceLimit("ext extent tree depth"));
        }
        let mut previous_end = bounds.start;
        let mut selected = None;
        for index in 0..count {
            let entry = bytes(data, 12 + index * 12, 12)?;
            let first = u64::from(u32le(entry, 0)?);
            if first < previous_end || first >= bounds.end {
                return Err(corrupt(
                    "ext extent",
                    first,
                    "unordered or overlapping extent entries",
                ));
            }
            if depth == 0 {
                let raw_length = u16le(entry, 4)?;
                let length = u64::from(if raw_length > 32768 {
                    raw_length - 32768
                } else {
                    raw_length
                });
                if length == 0 || first + length > bounds.end {
                    return Err(corrupt("ext extent", first, "invalid extent length"));
                }
                let physical = u64::from(u32le(entry, 8)?) | u64::from(u16le(entry, 6)?) << 32;
                if physical == 0 {
                    return Err(corrupt("ext extent", first, "extent points to block zero"));
                }
                checked_region(physical, length, self.blocks, "ext extent")?;
                previous_end = first + length;
                if logical >= first && logical < previous_end {
                    selected = Some(if raw_length > 32768 {
                        None
                    } else {
                        Some(physical + logical - first)
                    });
                }
            } else {
                previous_end = first + 1;
                let next = if index + 1 < count {
                    u64::from(u32le(data, 12 + (index + 1) * 12)?)
                } else {
                    bounds.end
                };
                if logical >= first && logical < next {
                    let physical = u64::from(u32le(entry, 4)?) | u64::from(u16le(entry, 8)?) << 32;
                    let child = self.block(physical)?;
                    if self.ro_compat & 0x400 != 0 {
                        let child_max = u16le(&child, 4)? as usize;
                        let tail = 12 + child_max * 12;
                        let stored = u32le(&child, tail)?;
                        check_checksum(
                            crc32c(
                                self.checksum_seed(inode.metadata.id, inode.generation),
                                bytes(&child, 0, tail)?,
                            ),
                            stored,
                            physical,
                            "ext extent block CRC32C",
                        )?;
                    }
                    return self.extent_block(&child, logical, Some(depth - 1), inode, first..next);
                }
            }
        }
        Ok(selected.flatten())
    }
    fn read_content(&mut self, inode: &Inode, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if inode.flags & (0x4 | 0x800 | 0x10000000) != 0 {
            return Err(Error::Unsupported(
                "compressed, encrypted, or inline ext inode data".into(),
            ));
        }
        let count = inode
            .metadata
            .size
            .saturating_sub(offset)
            .min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        let ea = u64::from(u32le(&inode.data, 104)?)
            | if self.incompat & 0x80 != 0 {
                u64::from(u16le(&inode.data, 118)?) << 32
            } else {
                0
            };
        let blocks = u64::from(u32le(&inode.data, 28)?) | u64::from(u16le(&inode.data, 116)?) << 32;
        if inode.metadata.kind == FileKind::Symlink
            && inode.metadata.size <= 60
            && inode.flags & 0x80000 == 0
            && blocks <= if ea == 0 { 0 } else { self.block_size / 512 }
        {
            buffer[..count].copy_from_slice(bytes(&inode.data, 40 + offset as usize, count)?);
            return Ok(count);
        }
        let mut done = 0;
        while done < count {
            let position = offset + done as u64;
            let within = position % self.block_size;
            let amount = (self.block_size - within).min((count - done) as u64) as usize;
            if let Some(physical) = self.file_block(inode, position / self.block_size)? {
                self.image.read_exact_at(
                    physical * self.block_size + within,
                    &mut buffer[done..done + amount],
                )?;
            } else {
                buffer[done..done + amount].fill(0);
            }
            done += amount;
        }
        Ok(count)
    }
    pub fn read_file(&mut self, id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let inode = self.inode(id)?;
        if !matches!(inode.metadata.kind, FileKind::File | FileKind::Symlink) {
            return Err(Error::Unsupported(
                "ext special file or directory content".into(),
            ));
        }
        if !inode.metadata.allocated {
            return Err(Error::Unsupported("deleted ext file recovery".into()));
        }
        self.read_content(&inode, offset, buffer)
    }
    pub fn read_dir(&mut self, id: u64) -> Result<Vec<DirEntry>> {
        let inode = self.inode(id)?;
        if inode.metadata.kind != FileKind::Directory {
            return Err(Error::NotDirectory(id.to_string()));
        }
        if inode.flags & (0x800 | 0x40000000 | 0x10000000) != 0 {
            return Err(Error::Unsupported(
                "encrypted, casefolded, or inline ext directory".into(),
            ));
        }
        if !inode.metadata.size.is_multiple_of(self.block_size) {
            return Err(corrupt(
                "ext directory",
                id,
                "directory size is not block aligned",
            ));
        }
        if inode.metadata.size > self.limits.max_directory_bytes {
            return Err(Error::ResourceLimit("ext directory size"));
        }
        let mut entries = Vec::new();
        let mut names = HashSet::new();
        for block in 0..inode.metadata.size / self.block_size {
            let mut data = vec![0; self.block_size as usize];
            self.read_content(&inode, block * self.block_size, &mut data)?;
            let mut limit = data.len();
            if self.ro_compat & 0x400 != 0 {
                let tail = data.len() - 12;
                if u32le(&data, tail)? == 0
                    && u16le(&data, tail + 4)? == 12
                    && data[tail + 6] == 0
                    && data[tail + 7] == 0xde
                {
                    check_checksum(
                        crc32c(self.checksum_seed(id, inode.generation), &data[..tail]),
                        u32le(&data, tail + 8)?,
                        block,
                        "ext directory CRC32C",
                    )?;
                    limit = tail;
                } else if inode.flags & 0x1000 != 0 {
                    self.check_htree(&data, &inode, block)?;
                } else {
                    return Err(corrupt(
                        "ext directory",
                        block,
                        "missing directory checksum tail",
                    ));
                }
            }
            let mut offset = 0;
            while offset < limit {
                let child = u32le(&data, offset)?;
                let encoded = u16le(&data, offset + 4)? as usize;
                let length = if self.block_size == 65536 && (encoded == 0 || encoded == 0xffff) {
                    65536
                } else {
                    encoded
                };
                if length < 8 || !length.is_multiple_of(4) || offset + length > limit {
                    return Err(corrupt(
                        "ext directory",
                        block * self.block_size + offset as u64,
                        "invalid directory record length",
                    ));
                }
                let name_length = if self.incompat & 2 != 0 {
                    usize::from(data[offset + 6])
                } else {
                    u16le(&data, offset + 6)? as usize
                };
                if name_length > 255 || name_length > length - 8 {
                    return Err(corrupt(
                        "ext directory",
                        offset as u64,
                        "invalid filename length",
                    ));
                }
                if child != 0 {
                    let raw = bytes(&data, offset + 8, name_length)?.to_vec();
                    if raw.is_empty() || raw.contains(&0) || raw.contains(&b'/') {
                        return Err(corrupt(
                            "ext directory",
                            offset as u64,
                            "invalid filename bytes",
                        ));
                    }
                    if raw != b"." && raw != b".." {
                        if !names.insert(raw.clone()) {
                            return Err(corrupt(
                                "ext directory",
                                id,
                                "duplicate directory filename",
                            ));
                        }
                        if entries.len() >= self.limits.max_directory_entries {
                            return Err(Error::ResourceLimit("ext directory entries"));
                        }
                        let metadata = self.metadata(u64::from(child))?;
                        if !metadata.allocated {
                            return Err(corrupt(
                                "ext directory",
                                u64::from(child),
                                "live directory references unallocated inode",
                            ));
                        }
                        entries.push(DirEntry {
                            id: u64::from(child),
                            name: String::from_utf8_lossy(&raw).into_owned(),
                            kind: metadata.kind,
                            size: metadata.size,
                            allocated: true,
                            aliases: Vec::new(),
                            raw_name: Some(raw),
                        });
                    }
                }
                offset += length;
            }
        }
        Ok(entries)
    }
    fn check_htree(&self, data: &[u8], inode: &Inode, block: u64) -> Result<()> {
        let offset = if block == 0 {
            if u16le(data, 4)? != 12 || data.get(29) != Some(&8) {
                return Err(corrupt("ext htree", block, "invalid htree root"));
            }
            32
        } else {
            if u32le(data, 0)? != 0 || data[6..8] != [0, 0] {
                return Err(corrupt("ext htree", block, "invalid htree node"));
            }
            8
        };
        let limit = u16le(data, offset)? as usize;
        let count = u16le(data, offset + 2)? as usize;
        if count == 0 || count > limit {
            return Err(corrupt("ext htree", block, "invalid htree entry count"));
        }
        let tail = offset + limit * 8;
        let used = bytes(data, 0, offset + count * 8)?;
        let tail_data = bytes(data, tail, 8)?;
        if u32le(tail_data, 0)? != 0 {
            return Err(corrupt(
                "ext htree",
                block,
                "nonzero htree tail reserved field",
            ));
        }
        let checksum = crc32c(
            crc32c(
                crc32c(
                    self.checksum_seed(inode.metadata.id, inode.generation),
                    used,
                ),
                &tail_data[..4],
            ),
            &[0; 4],
        );
        check_checksum(checksum, u32le(tail_data, 4)?, block, "ext htree CRC32C")
    }
}

fn ext_time(data: &[u8], base: usize, extra: Option<usize>) -> Result<Timestamp> {
    let lo = i64::from(u32le(data, base)? as i32);
    let extra = if let Some(offset) = extra {
        u32le(data, offset)?
    } else {
        0
    };
    let nanos = extra >> 2;
    if nanos >= 1_000_000_000 {
        return Err(corrupt(
            "ext timestamp",
            base as u64,
            "nanoseconds outside valid range",
        ));
    }
    Ok(Timestamp {
        seconds: lo + (i64::from(extra & 3) << 32),
        nanos,
        basis: TimeBasis::Utc,
    })
}
fn check_checksum(calculated: u32, stored: u32, offset: u64, context: &'static str) -> Result<()> {
    if calculated != stored {
        return Err(Error::Checksum {
            context,
            offset,
            stored,
            calculated,
        });
    }
    Ok(())
}
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f6_3b78 } else { 0 };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};
fn crc32c(mut state: u32, data: &[u8]) -> u32 {
    for &byte in data {
        state = (state >> 8) ^ CRC32C_TABLE[((state as u8) ^ byte) as usize];
    }
    state
}
fn crc16(mut state: u16, data: &[u8]) -> u16 {
    for &byte in data {
        state ^= u16::from(byte);
        for _ in 0..8 {
            state = state >> 1 ^ if state & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_algorithms_match_standard_vectors() {
        assert_eq!(!crc32c(!0, b"123456789"), 0xe3069283);
        assert_eq!(crc16(0, b"123456789"), 0xbb3d);
    }
}
