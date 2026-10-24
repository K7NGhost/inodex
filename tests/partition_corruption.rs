mod layers_support;
use inodex::{Error, partition::PartitionTable};
use layers_support::*;

#[test]
fn mbr_overlap_geometry_and_boot_flags_are_rejected() {
    for (offset, value) in [(446, 1), (454, 0), (458, u32::MAX), (470, 1)] {
        let mut data = raw("mbr.raw");
        if offset == 446 {
            data[offset] = value as u8;
        } else {
            put32(&mut data, offset, value);
        }
        assert!(
            PartitionTable::read(&mut Memory::new(data)).is_err(),
            "field {offset}"
        );
    }
}

#[test]
fn ebr_cycles_and_out_of_container_data_are_rejected() {
    let mut data = raw("mbr.raw");
    let first = 130 * 512;
    data[first + 466] = 5;
    put32(&mut data, first + 470, 130);
    put32(&mut data, first + 474, 7932);
    let second = 260 * 512;
    data[second + 510..second + 512].copy_from_slice(&[0x55, 0xaa]);
    data[second + 450] = 0x83;
    put32(&mut data, second + 454, 1);
    put32(&mut data, second + 458, 1);
    data[second + 466] = 5;
    put32(&mut data, second + 470, 130);
    put32(&mut data, second + 474, 7932);
    assert!(
        matches!(PartitionTable::read(&mut Memory::new(data)), Err(Error::Corrupt { reason, .. }) if reason.contains("cycle"))
    );
    let mut data = raw("mbr.raw");
    put32(&mut data, first + 458, 10000);
    assert!(PartitionTable::read(&mut Memory::new(data)).is_err());
}

#[test]
fn missing_ebr_signature_and_extra_ebr_entries_are_rejected() {
    for extra in [false, true] {
        let mut data = raw("mbr.raw");
        let ebr = 130 * 512;
        if extra {
            data[ebr + 482] = 0x83;
            put32(&mut data, ebr + 486, 1);
            put32(&mut data, ebr + 490, 1);
        } else {
            data[ebr + 510] = 0;
        }
        assert!(PartitionTable::read(&mut Memory::new(data)).is_err());
    }
}

#[test]
fn gpt_header_array_and_backup_checksums_are_enforced() {
    let original = raw("gpt.raw");
    for offset in [512 + 40, 1024 + 56, original.len() - 512 + 40] {
        let mut data = original.clone();
        data[offset] ^= 1;
        assert!(matches!(
            PartitionTable::read(&mut Memory::new(data)),
            Err(Error::Checksum { .. })
        ));
    }
}

#[test]
fn gpt_valid_checksums_do_not_hide_overlap_duplicate_guids_or_bad_names() {
    for kind in 0..4 {
        let mut data = raw("gpt.raw");
        match kind {
            0 => {
                let start = u64at(&data, 1024 + 32);
                put64(&mut data, 1024 + 128 + 32, start);
            }
            1 => {
                let id = data[1040..1056].to_vec();
                data[1168..1184].copy_from_slice(&id);
            }
            2 => data[1040..1056].fill(0),
            _ => {
                put16(&mut data, 1024 + 56, 0xd800);
                put16(&mut data, 1024 + 58, 0);
            }
        }
        fix_gpt(&mut data);
        assert!(
            PartitionTable::read(&mut Memory::new(data)).is_err(),
            "semantic case {kind}"
        );
    }
}

#[test]
fn gpt_counts_and_offsets_are_bounded_before_allocating() {
    for field in [72, 80, 84] {
        let mut data = raw("gpt.raw");
        if field == 72 {
            put64(&mut data, 512 + field, u64::MAX - 100);
        } else {
            put32(&mut data, 512 + field, u32::MAX);
        }
        fix_header(&mut data, 512);
        assert!(PartitionTable::read(&mut Memory::new(data)).is_err());
    }
}

#[test]
fn gpt_backup_must_agree_with_primary_even_with_valid_crc() {
    let mut data = raw("gpt.raw");
    let backup = data.len() - 512;
    data[backup + 56] ^= 1;
    fix_header(&mut data, backup);
    assert!(
        matches!(PartitionTable::read(&mut Memory::new(data)), Err(Error::Corrupt { reason, .. }) if reason.contains("disagree"))
    );
}

#[test]
fn malformed_protective_mbr_is_not_accepted_as_a_whole_volume() {
    let mut data = raw("gpt.raw");
    put32(&mut data, 454, 2);
    assert!(PartitionTable::read(&mut Memory::new(data)).is_err());
    // Upstream empty GPT intentionally omits its protective partition entry.
    assert!(PartitionTable::read(&mut Memory::new(raw("gpt_empty.raw"))).is_err());
}

#[test]
fn truncated_tables_and_invalid_sector_sizes_are_errors() {
    let original = raw("gpt.raw");
    for length in [511, 1023, 1024, 4096, original.len() - 1] {
        let mut image = Memory::new(original[..length].to_vec());
        let result = PartitionTable::read(&mut image);
        if length < 512 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.is_err());
        }
    }
    let mut image = Memory::new(original);
    image.sector_size = 513;
    assert!(PartitionTable::read(&mut image).is_err());
}

#[test]
fn filesystem_boot_sectors_are_not_misidentified_as_mbrs() {
    for name in [
        "ntfs.raw",
        "fat12.raw",
        "fat16.raw",
        "fat32.raw",
        "ext2.raw",
        "ext4.raw",
    ] {
        assert!(
            PartitionTable::read(&mut Memory::new(raw(name)))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn gpt_uses_the_image_logical_sector_size_including_4k_sectors() {
    let source = raw("gpt.raw");
    let mut data = vec![0; 8192 * 4096];
    data[..512].copy_from_slice(&source[..512]);
    for lba in [1, 8191] {
        data[lba * 4096..lba * 4096 + 512].copy_from_slice(&source[lba * 512..lba * 512 + 512]);
    }
    for lba in [2, 8159] {
        data[lba * 4096..lba * 4096 + 16384].copy_from_slice(&source[lba * 512..lba * 512 + 16384]);
    }
    let mut image = Memory {
        data,
        sector_size: 4096,
    };
    let table = PartitionTable::read(&mut image).unwrap().unwrap();
    assert_eq!(table.sector_size, 4096);
    assert_eq!(table.get(1).unwrap().start_lba, 2048);
    let volume = table.get(1).unwrap().volume(&mut image).unwrap();
    assert_eq!(volume.offset(), 2048 * 4096);
}
