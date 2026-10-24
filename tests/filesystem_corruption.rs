mod layers_support;
use inodex::{
    Error,
    filesystem::{FileSystem, Limits},
};
use layers_support::*;

#[test]
fn ntfs_rejects_torn_mft_sectors_and_bad_record_bounds() {
    for field in [510, 20, 24] {
        let mut data = raw("ntfs.raw");
        let record = 4 * 4096;
        if field == 510 {
            data[record + field] ^= 1;
        } else if field == 20 {
            put16(&mut data, record + field, 0);
        } else {
            put32(&mut data, record + field, u32::MAX);
        }
        assert!(FileSystem::open(&mut Memory::new(data)).is_err());
    }
}

#[test]
fn ntfs_volume_geometry_and_mft_location_are_checked() {
    for case in 0..4 {
        let mut data = raw("ntfs.raw");
        match case {
            0 => data[13] = 0,
            1 => data[64] = 0,
            2 => put64(&mut data, 40, u64::MAX),
            _ => put64(&mut data, 48, u64::MAX),
        }
        assert!(FileSystem::open(&mut Memory::new(data)).is_err());
    }
}

#[test]
fn ntfs_malformed_mapping_pairs_never_return_media_data() {
    let mut data = raw("ntfs.raw");
    let record = 4 * 4096;
    let mut offset = record + u16at(&data, record + 20) as usize;
    while u32at(&data, offset) != 0x80 {
        offset += u32at(&data, offset + 4) as usize;
    }
    let run = offset + u16at(&data, offset + 32) as usize;
    data[run] = 0xff;
    assert!(FileSystem::open(&mut Memory::new(data)).is_err());
}

#[test]
fn ntfs_sparse_and_uninitialized_streams_return_zeroes() {
    let mut image = Memory::new(raw("ntfs.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/$BadClus").unwrap();
    let mut bytes = [0x55; 4097];
    assert_eq!(
        fs.read_file(id, Some("$Bad"), 511, &mut bytes).unwrap(),
        bytes.len()
    );
    assert!(bytes.iter().all(|&b| b == 0));
    assert!(
        fs.read_file(id, Some("missing-stream"), 0, &mut bytes)
            .is_err()
    );
}

#[test]
fn ntfs_compressed_or_encrypted_streams_fail_explicitly() {
    for flags in [1, 0x4000] {
        let mut data = raw("ntfs.raw");
        let record = 4 * 4096 + 2 * 1024; // $LogFile, a nonresident data stream.
        let mut offset = record + u16at(&data, record + 20) as usize;
        while u32at(&data, offset) != 0x80 {
            offset += u32at(&data, offset + 4) as usize;
        }
        put16(&mut data, offset + 12, flags);
        let mut image = Memory::new(data);
        let mut fs = FileSystem::open(&mut image).unwrap();
        assert!(matches!(
            fs.read_file(2, None, 0, &mut [0; 10]),
            Err(Error::Unsupported(_))
        ));
    }
}

#[test]
fn fat_boot_geometry_and_table_capacity_are_checked() {
    for field in [11, 13, 14, 16, 22] {
        let mut data = raw("fat12.raw");
        if field == 13 || field == 16 {
            data[field] = 0;
        } else {
            put16(&mut data, field, 0);
        }
        assert!(FileSystem::open(&mut Memory::new(data)).is_err());
    }
}

#[test]
fn fat_live_chain_cycles_and_bad_clusters_are_errors() {
    for next in [3, 0, 0xfff7] {
        let mut data = raw("fat16.raw");
        put16(&mut data, 512 + 5 * 2, next);
        let mut image = Memory::new(data);
        let mut fs = FileSystem::open(&mut image).unwrap();
        let id = fs.resolve("/RESUME~1.TXT").unwrap();
        assert!(fs.read_file(id, None, 0, &mut [0; 4096]).is_err());
    }
}

#[test]
fn invalid_vfat_checksums_fall_back_to_the_verified_short_name() {
    let mut data = raw("fat16.raw");
    let root = (1 + 2 * 64) * 512;
    data[root + 13] ^= 1;
    let mut image = Memory::new(data);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.resolve("/Résumé long filename.txt").is_err());
    let id = fs.resolve("/RESUME~1.TXT").unwrap();
    assert_eq!(fs.metadata(id).unwrap().size, 131113);
}

#[test]
fn fat32_free_root_cluster_is_rejected() {
    let mut data = raw("fat32.raw");
    put32(&mut data, 32 * 512 + 2 * 4, 0);
    let mut image = Memory::new(data);
    let mut fs = FileSystem::open(&mut image).unwrap();
    let root = fs.info().root_id;
    assert!(fs.read_dir(root).is_err());
}

#[test]
fn ext4_checksums_cover_superblock_group_bitmap_inode_and_directory() {
    let original = raw("ext4.raw");
    let table = u32at(&original, 2048 + 8) as usize * 1024;
    let inode_bitmap = u32at(&original, 2048 + 4) as usize * 1024;
    for offset in [1024 + 120, 2048 + 12, inode_bitmap, table + 256 + 4] {
        let mut data = original.clone();
        data[offset] ^= 1;
        assert!(
            matches!(
                FileSystem::open(&mut Memory::new(data)),
                Err(Error::Checksum { .. })
            ),
            "offset {offset}"
        );
    }
    let mut data = original;
    let root_inode = table + 256;
    let root_data = u32at(&data, root_inode + 60) as usize * 1024;
    data[root_data + 100] ^= 1;
    let mut image = Memory::new(data);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(matches!(fs.read_dir(2), Err(Error::Checksum { .. })));
}

#[test]
fn ext4_external_extent_blocks_have_their_own_checksum() {
    let mut data = raw("ext4-extent.raw");
    data[3000 * 1024 + 20] ^= 1;
    let mut image = Memory::new(data);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(matches!(
        fs.read_file(14, None, 0, &mut [0; 16]),
        Err(Error::Checksum { .. })
    ));
}

#[test]
fn ext2_bad_inode_pointers_and_directory_records_are_errors() {
    let original = raw("ext2.raw");
    let table = u32at(&original, 2048 + 8) as usize * 1024;
    let size = u16at(&original, 1024 + 88) as usize;
    let mut data = original.clone();
    put32(&mut data, table + 13 * size + 40, u32::MAX);
    let mut image = Memory::new(data);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.read_file(14, None, 0, &mut [0; 10]).is_err());
    let mut data = original;
    let root = u32at(&data, table + size + 40) as usize * 1024;
    put16(&mut data, root + 4, 0);
    let mut image = Memory::new(data);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.read_dir(2).is_err());
}

#[test]
fn unsupported_ext_inode_features_do_not_emit_ciphertext_or_inline_garbage() {
    for flags in [0x800, 0x10000000, 4] {
        let mut data = raw("ext2.raw");
        let table = u32at(&data, 2048 + 8) as usize * 1024;
        let size = u16at(&data, 1024 + 88) as usize;
        put32(&mut data, table + 13 * size + 32, flags);
        let mut image = Memory::new(data);
        let mut fs = FileSystem::open(&mut image).unwrap();
        assert!(matches!(
            fs.read_file(14, None, 0, &mut [0; 16]),
            Err(Error::Unsupported(_))
        ));
    }
}

#[test]
fn filesystem_traversal_and_allocation_limits_are_enforced() {
    for name in ["ntfs.raw", "fat12.raw", "ext2.raw", "ext4.raw"] {
        let mut image = Memory::new(raw(name));
        let mut fs = FileSystem::with_limits(
            &mut image,
            Limits {
                max_directory_entries: 1,
                ..Limits::default()
            },
        )
        .unwrap();
        let root = fs.info().root_id;
        assert!(
            matches!(fs.read_dir(root), Err(Error::ResourceLimit(_))),
            "{name}"
        );
    }
    let mut image = Memory::new(raw("ntfs.raw"));
    assert!(matches!(
        FileSystem::with_limits(
            &mut image,
            Limits {
                max_metadata_bytes: 1024,
                ..Limits::default()
            }
        ),
        Err(Error::ResourceLimit(_))
    ));
}

#[test]
fn symlinks_are_read_as_link_data_and_never_followed_by_path_resolution() {
    let mut image = Memory::new(raw("ext2.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/a_link").unwrap();
    let mut target = Vec::new();
    fs.copy_file(id, None, &mut target).unwrap();
    assert_eq!(target, b"a_directory/another_file");
    assert!(fs.resolve("/a_link/").is_err());
    assert!(fs.resolve("/a_link/child").is_err());
}

#[test]
fn truncation_and_deterministic_header_mutations_never_panic() {
    for name in ["ntfs.raw", "fat12.raw", "ext2.raw", "ext4.raw"] {
        let original = raw(name);
        for length in [0, 1, 511, 512, 1024, 2047, original.len() - 1] {
            let mut image = Memory::new(original[..length].to_vec());
            let _ = FileSystem::open(&mut image);
        }
        let mut seed = 0x715d_u64;
        for _ in 0..48 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut data = original.clone();
            let offset = seed as usize % 4096;
            data[offset] ^= 1 << ((seed >> 32) % 8);
            let mut image = Memory::new(data);
            if let Ok(mut fs) = FileSystem::open(&mut image) {
                let root = fs.info().root_id;
                let _ = fs.read_dir(root);
            }
        }
    }
}
