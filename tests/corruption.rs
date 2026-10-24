mod support;

use inodex::{
    Error,
    ewf::{EwfImage, OpenOptions},
    image::DiskImage,
};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
};
use support::*;

fn open_bytes(data: &[u8]) -> inodex::Result<EwfImage> {
    let (_directory, path) = write_image(data);
    // Keep the directory until open completes; image owns its file handles.
    EwfImage::open(path)
}

#[test]
fn unsupported_signatures_are_explicit() {
    for signature in [b"EVF2", b"LVF\x09", b"LEF2"] {
        let mut data = fixture("ext2.E01");
        data[..4].copy_from_slice(signature);
        assert!(matches!(open_bytes(&data), Err(Error::Unsupported(_))));
    }
    let mut data = fixture("ext2.E01");
    data[8] = 2;
    assert!(matches!(
        open_bytes(&data),
        Err(Error::InvalidFormat { .. })
    ));
}

#[test]
fn checksums_cover_descriptor_volume_table_header_entries_and_backup() {
    for (kind, within) in [
        ("volume", 10),
        ("table", 0),
        ("table", 24),
        ("table2", 24),
        ("hash", 0),
    ] {
        let mut data = fixture("ext2.E01");
        let start = section(&data, kind);
        data[start + 76 + within] ^= 0x10;
        assert!(
            matches!(open_bytes(&data), Err(Error::Checksum { .. })),
            "{kind} + {within}"
        );
    }
    let mut data = fixture("ext2.E01");
    data[13 + 32] ^= 0x10;
    assert!(matches!(
        open_bytes(&data),
        Err(Error::Checksum {
            context: "section descriptor",
            ..
        })
    ));
}

#[test]
fn section_cycles_overflow_overlap_and_trailing_bytes_are_rejected() {
    let original = fixture("ext2.E01");
    for next in [0, 13, 14, 88, u64::MAX] {
        let mut data = original.clone();
        put64(&mut data, 13 + 16, next);
        fix_checksum(&mut data[13..13 + 76]);
        assert!(open_bytes(&data).is_err(), "next={next}");
    }
    let mut data = original.clone();
    put64(&mut data, 13 + 24, u64::MAX);
    fix_checksum(&mut data[13..13 + 76]);
    assert!(open_bytes(&data).is_err());
    let mut data = original;
    data.push(0);
    assert!(open_bytes(&data).is_err());
}

#[test]
fn terminal_markers_are_required_and_must_point_to_themselves() {
    let mut data = fixture("ext2.E01");
    let done = section(&data, "done");
    let truncated = data[..done].to_vec();
    assert!(open_bytes(&truncated).is_err());
    put64(&mut data, done + 16, 13);
    fix_checksum(&mut data[done..]);
    assert!(open_bytes(&data).is_err());
}

#[test]
fn consistent_checksums_do_not_hide_invalid_chunk_offsets() {
    let original = fixture("ext2.E01");
    for value in [0, 0x7fff_ffff, 0x8000_0000] {
        let mut data = original.clone();
        let table = section(&data, "table");
        put32(&mut data, table + 76 + 24, value);
        let end = u64_at(&data, table + 16) as usize;
        fix_checksum(&mut data[table + 100..end]);
        assert!(matches!(
            open_bytes(&data),
            Err(Error::InvalidFormat { .. })
        ));
    }
    let mut data = original;
    let table = section(&data, "table");
    put64(&mut data, table + 84, u64::MAX);
    fix_checksum(&mut data[table + 76..table + 100]);
    assert!(open_bytes(&data).is_err());
}

#[test]
fn oversized_table_count_is_rejected_before_allocation() {
    let mut data = fixture("ext2.E01");
    let table = section(&data, "table");
    put32(&mut data, table + 76, u32::MAX);
    fix_checksum(&mut data[table + 76..table + 100]);
    assert!(matches!(open_bytes(&data), Err(Error::ResourceLimit(_))));
    put32(&mut data, table + 76, 129);
    fix_checksum(&mut data[table + 76..table + 100]);
    assert!(matches!(
        open_bytes(&data),
        Err(Error::InvalidFormat { .. })
    ));
}

#[test]
fn valid_but_divergent_backup_table_is_rejected() {
    let mut data = fixture("ext2.E01");
    let table = section(&data, "table2");
    let end = u64_at(&data, table + 16) as usize;
    data[table + 100] ^= 1;
    fix_checksum(&mut data[table + 100..end]);
    assert!(matches!(
        open_bytes(&data),
        Err(Error::InvalidFormat { .. })
    ));
}

#[test]
fn compressed_chunk_payload_and_zlib_checksum_corruption_fail_when_read() {
    for at_end in [false, true] {
        let mut data = fixture("ext2.E01");
        let sectors = section(&data, "sectors");
        let table = section(&data, "table");
        let base = u64_at(&data, table + 84) as usize;
        let next_chunk = base + (u32_at(&data, table + 104) & 0x7fff_ffff) as usize;
        let index = if at_end { next_chunk - 1 } else { sectors + 78 };
        data[index] ^= 0x80;
        let mut image = open_bytes(&data).unwrap();
        assert!(image.read_at(0, &mut [0; 100]).is_err());
        assert!(image.verify().is_err());
    }
}

#[test]
fn uncompressed_chunk_checksum_is_enforced() {
    let mut data = fixture("libewf-encase6-c0.E01");
    let sectors = section(&data, "sectors");
    data[sectors + 76] ^= 0x10;
    let mut image = open_bytes(&data).unwrap();
    assert!(matches!(
        image.verify(),
        Err(Error::Checksum {
            context: "uncompressed chunk",
            ..
        })
    ));
}

#[test]
fn wrong_stored_md5_and_sha1_fail_full_verification() {
    let mut data = fixture("ext2.E01");
    let hash = section(&data, "hash");
    data[hash + 76] ^= 1;
    fix_section_payload(&mut data, hash);
    let mut image = open_bytes(&data).unwrap();
    assert!(matches!(
        image.verify(),
        Err(Error::DigestMismatch {
            algorithm: "MD5",
            ..
        })
    ));

    let mut data = fixture("libewf-encase6-c2.E01");
    let digest = section(&data, "digest");
    data[digest + 76 + 16] ^= 1;
    fix_section_payload(&mut data, digest);
    let mut image = open_bytes(&data).unwrap();
    assert!(matches!(
        image.verify(),
        Err(Error::DigestMismatch {
            algorithm: "SHA1",
            ..
        })
    ));
}

#[test]
fn conflicting_hash_sections_are_rejected_on_open() {
    let mut data = fixture("libewf-encase6-c2.E01");
    let digest = section(&data, "digest");
    data[digest + 76] ^= 1;
    fix_section_payload(&mut data, digest);
    assert!(matches!(
        open_bytes(&data),
        Err(Error::InvalidFormat { .. })
    ));
}

#[test]
fn bad_geometry_and_overflow_are_rejected() {
    for (field, value) in [(8, 0), (12, 0), (4, 127), (8, u32::MAX)] {
        let mut data = fixture("ext2.E01");
        let volume = section(&data, "volume");
        put32(&mut data, volume + 76 + field, value);
        fix_section_payload(&mut data, volume);
        assert!(open_bytes(&data).is_err());
    }
    let mut data = fixture("ext2.E01");
    let volume = section(&data, "volume");
    put64(&mut data, volume + 92, u64::MAX);
    fix_section_payload(&mut data, volume);
    assert!(open_bytes(&data).is_err());
}

#[test]
fn segment_set_identifier_and_geometry_must_match() {
    let mut data = fixture("ext2.E01");
    let data_section = section(&data, "data");
    data[data_section + 76 + 64] ^= 1;
    fix_section_payload(&mut data, data_section);
    assert!(matches!(
        open_bytes(&data),
        Err(Error::InvalidFormat { .. })
    ));
}

#[test]
fn custom_resource_limits_are_enforced() {
    let (_dir, path) = write_image(&fixture("ext2.E01"));
    for options in [
        OpenOptions {
            max_chunks: 127,
            ..OpenOptions::default()
        },
        OpenOptions {
            max_table_entries: 127,
            ..OpenOptions::default()
        },
        OpenOptions {
            max_chunk_size: 1024,
            ..OpenOptions::default()
        },
        OpenOptions {
            max_metadata_size: 50,
            ..OpenOptions::default()
        },
        OpenOptions {
            max_sections: 3,
            ..OpenOptions::default()
        },
    ] {
        assert!(matches!(options.open(&path), Err(Error::ResourceLimit(_))));
    }
}

#[test]
fn truncated_files_fail_without_panicking() {
    let data = fixture("ext2.E01");
    let (_dir, path) = write_image(&[]);
    let mut lengths: Vec<_> = (0..data.len()).step_by(89).collect();
    for kind in [
        "header2", "volume", "sectors", "table", "table2", "hash", "done",
    ] {
        let offset = section(&data, kind);
        lengths.extend([offset, offset + 1, offset + 75]);
    }
    lengths.push(data.len() - 1);
    for len in lengths {
        fs::write(&path, &data[..len]).unwrap();
        assert!(EwfImage::open(&path).is_err(), "truncation at {len}");
    }
}

#[test]
fn deterministic_mutations_do_not_panic_or_silently_verify_changed_media() {
    let original = fixture("ext2.E01");
    let (_dir, path) = write_image(&[]);
    let mut seed = 0x5eed_u64;
    for _ in 0..400 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let index = seed as usize % original.len();
        let mut data = original.clone();
        data[index] ^= 1 << ((seed >> 32) % 8);
        fs::write(&path, &data).unwrap();
        if let Ok(mut image) = EwfImage::open(&path) {
            // Certain padding/header fields legitimately do not change media.
            if let Ok(report) = image.verify() {
                assert_eq!(
                    inodex::ewf::hex(&report.md5),
                    "196066add11fb71c4c49cf1bb50d6d24"
                );
            }
        }
    }
}

#[test]
fn sequential_read_returns_successful_bytes_before_a_later_chunk_error() {
    let mut data = fixture("libewf-encase6-c0.E01");
    let sectors = section(&data, "sectors");
    data[sectors + 76 + 32768 + 4] ^= 1;
    let mut image = open_bytes(&data).unwrap();
    let mut buffer = vec![0; 65536];
    assert_eq!(image.read(&mut buffer).unwrap(), 32768);
    assert_eq!(image.stream_position().unwrap(), 32768);
    assert!(image.read(&mut buffer).is_err());
    assert_eq!(image.stream_position().unwrap(), 32768);
    image.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(image.read(&mut []).unwrap(), 0);
}
