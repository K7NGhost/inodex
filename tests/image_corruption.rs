mod image_support;
use image_support::*;
use inodex::{
    Error,
    image::{AffImage, DiskImage, Image, Limits, VhdImage, VmdkImage},
};
use std::{fs, path::Path};

fn try_vhd(p: &Path, bytes: &[u8]) {
    fs::write(p, bytes).unwrap();
    assert!(VhdImage::open(p).is_err());
}
#[test]
fn vhd_rejects_footer_header_checksums_and_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("disk.vhd");
    let original = fixture("ntfs-dynamic.vhd");
    for cut in [0, 511, 512, 1535, original.len() - 1, original.len() - 512] {
        try_vhd(&p, &original[..cut]);
    }
    for at in [0, 64, 512, 548, original.len() - 512, original.len() - 448] {
        let mut bytes = original.clone();
        bytes[at] ^= 1;
        try_vhd(&p, &bytes);
    }
    for name in ["image.vhd", "image-differential.vhd"] {
        corpus(dir.path());
        assert!(Image::open(dir.path().join(name)).is_err());
    }
}
#[test]
fn vhd_rejects_overlapping_blocks_impossible_geometry_and_outside_bat() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("disk.vhd");
    let original = fixture("ntfs-dynamic.vhd");
    let table = u64::from_be_bytes(original[528..536].try_into().unwrap()) as usize;
    let mut bytes = original.clone();
    be32(&mut bytes, table, 1);
    try_vhd(&p, &bytes);
    let mut bytes = original.clone();
    be32(&mut bytes, table, 0xfffffff0);
    try_vhd(&p, &bytes);
    for block in [0, 513, 0x80000000] {
        let mut bytes = original.clone();
        be32(&mut bytes[512..1536], 32, block);
        checksum(&mut bytes[512..1536], 36);
        try_vhd(&p, &bytes);
    }
    let mut bytes = original;
    let len = bytes.len();
    be64(&mut bytes[len - 512..], 48, u64::MAX - 511);
    checksum(&mut bytes[len - 512..], 64);
    try_vhd(&p, &bytes);
}
#[test]
fn vmdk_rejects_wrong_parent_cid_cycles_and_untrusted_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = sparse_child(dir.path());
    let descriptor = fs::read_to_string(&p).unwrap();
    for modified in [
        descriptor.replace("parentCID=12345678", "parentCID=00000000"),
        descriptor.replace("parent.vmdk", "child.vmdk"),
        descriptor.replace("parent.vmdk", "../outside.vmdk"),
        descriptor.replace("child-sparse.vmdk", "C:\\external.vmdk"),
    ] {
        fs::write(&p, modified).unwrap();
        assert!(VmdkImage::open(&p).is_err());
    }
}
#[test]
fn vmdk_rejects_truncated_indexes_bad_grains_and_metadata_overlaps() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = sparse_child(dir.path());
    let sparse = dir.path().join("child-sparse.vmdk");
    let original = fs::read(&sparse).unwrap();
    for cut in [0, 511, 512, 1023, 1535] {
        fs::write(&sparse, &original[..cut]).unwrap();
        assert!(VmdkImage::open(&p).is_err());
    }
    for grain in [2, 0xfffffff0] {
        let mut bytes = original.clone();
        le32(&mut bytes, 1032, grain);
        fs::write(&sparse, &bytes).unwrap();
        let mut disk = VmdkImage::open(&p).unwrap();
        assert!(disk.read_exact_at(8192, &mut [0; 10]).is_err());
    }
    let mut bytes = original;
    le64(&mut bytes, 56, 0);
    fs::write(sparse, bytes).unwrap();
    assert!(VmdkImage::open(p).is_err());
}
#[test]
fn vmdk_compressed_marker_and_deflate_corruption_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("stream.vmdk");
    let original = fixture("streamOptimized.vmdk");
    // Locate a real compressed-grain marker: first grain starts at overhead sectors.
    let at = u64::from_le_bytes(original[64..72].try_into().unwrap()) as usize * 512;
    for offset in [at, at + 8, at + 12] {
        let mut bytes = original.clone();
        bytes[offset] ^= 0x80;
        fs::write(&p, bytes).unwrap();
        let mut disk = Image::open(&p).unwrap();
        assert!(disk.verify().is_err());
    }
}
#[test]
fn aff_rejects_bad_framing_geometry_encryption_and_resource_exhaustion() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("test.aff");
    let mut original = aff_header(4096);
    aff_segment(&mut original, "page0", 0, &[3; 4096]);
    for cut in [0, 7, 8, 23, original.len() - 1] {
        fs::write(&p, &original[..cut]).unwrap();
        assert!(AffImage::open(&p).is_err());
    }
    let mut bytes = original.clone();
    let len = bytes.len();
    bytes[len - 1] ^= 1;
    fs::write(&p, bytes).unwrap();
    assert!(AffImage::open(&p).is_err());
    let mut bytes = original.clone();
    aff_segment(&mut bytes, "page1/aes256", 0, b"ciphertext");
    fs::write(&p, bytes).unwrap();
    assert!(matches!(AffImage::open(&p), Err(Error::Unsupported(_))));
    fs::write(&p, original).unwrap();
    assert!(matches!(
        AffImage::with_limits(
            &p,
            Limits {
                max_metadata_bytes: 1,
                ..Limits::default()
            }
        ),
        Err(Error::ResourceLimit(_))
    ));
}
#[test]
fn aff_rejects_bad_zlib_lzma_bombs_and_short_plain_pages() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("test.aff");
    for (flags, page) in [
        (1, b"broken zlib".to_vec()),
        (0, vec![3; 4095]),
        (0x31, 8192u32.to_be_bytes().to_vec()),
        (
            0x21,
            [
                vec![0x5d, 0, 0, 0, 1],
                u64::MAX.to_le_bytes().to_vec(),
                vec![0; 20],
            ]
            .concat(),
        ),
    ] {
        let mut bytes = aff_header(4096);
        aff_segment(&mut bytes, "page0", flags, &page);
        fs::write(&p, bytes).unwrap();
        let mut disk = AffImage::open(&p).unwrap();
        assert!(disk.read_exact_at(0, &mut [0; 4096]).is_err());
    }
}
#[test]
fn aff_page_and_media_digest_mismatches_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("test.aff");
    for digest in [
        "page0_md5",
        "page0_sha1",
        "page0_sha256",
        "md5",
        "sha1",
        "sha256",
    ] {
        let mut bytes = aff_header(4096);
        aff_segment(&mut bytes, "page0", 0, &[3; 4096]);
        let len = if digest.ends_with("md5") {
            16
        } else if digest.ends_with("sha1") {
            20
        } else {
            32
        };
        aff_segment(&mut bytes, digest, 0, &vec![0; len]);
        fs::write(&p, bytes).unwrap();
        let mut disk = Image::open(&p).unwrap();
        assert!(
            matches!(disk.verify(), Err(Error::DigestMismatch { .. })),
            "{digest}"
        );
    }
}
#[test]
fn afd_and_afm_reject_missing_members_and_duplicate_data_pages() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    fs::remove_file(dir.path().join("multi.afd/file_001.aff")).unwrap();
    assert!(AffImage::open(dir.path().join("multi.afd")).is_err());
    fs::remove_file(dir.path().join("native.001")).unwrap();
    assert!(AffImage::open(dir.path().join("native.afm")).is_err());
    let afd = dir.path().join("duplicate.afd");
    fs::create_dir(&afd).unwrap();
    let mut a = aff_header(4096);
    aff_segment(&mut a, "page0", 0, &[0; 4096]);
    fs::write(afd.join("a.aff"), &a).unwrap();
    fs::write(afd.join("b.aff"), a).unwrap();
    assert!(AffImage::open(afd).is_err());
}
#[test]
fn unsupported_disk_formats_fail_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("unsupported.aff4");
    fs::write(&p, b"unsupported").unwrap();
    assert!(matches!(Image::open(p), Err(Error::Unsupported(_))));
    let p = dir.path().join("invalid.vhdx");
    fs::write(&p, b"unsupported").unwrap();
    assert!(matches!(Image::open(p), Err(Error::Corrupt { .. })));
}

#[test]
fn footer_based_vmdk_rejects_bad_footer_marker_and_index() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("footer.vmdk");
    let original = fixture("streamFooter.vmdk");
    let len = original.len();
    for at in [
        len - 1536,
        len - 1536 + 12,
        len - 1024 + 4,
        len - 1024 + 12,
        len - 1024 + 56,
        len - 1,
    ] {
        let mut bytes = original.clone();
        bytes[at] ^= 0x80;
        fs::write(&p, bytes).unwrap();
        assert!(Image::open(&p).is_err(), "offset {at}");
    }
}

#[test]
fn deterministic_container_metadata_mutations_do_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        max_metadata_bytes: 256 * 1024,
        max_decoded_block: 4 * 1024 * 1024,
        ..Limits::default()
    };
    for name in ["native.aff", "ext2.vmdk", "ext2.vhd"] {
        let original = fixture(name);
        let p = dir.path().join(name);
        for i in 0..100usize {
            let mut bytes = original.clone();
            let at = if i < 80 { i } else { 512 + (i * 37) % 1024 };
            bytes[at] ^= 1 << (i % 8);
            fs::write(&p, bytes).unwrap();
            let result = std::panic::catch_unwind(|| {
                if let Ok(mut disk) = Image::with_limits(&p, limits.clone()) {
                    let mut out = [0; 1027];
                    let _ = disk.read_at(0, &mut out);
                    let _ = disk.read_at(disk.len().saturating_sub(1027), &mut out);
                }
            });
            assert!(result.is_ok(), "{name}: mutation at {at}");
        }
    }
}
