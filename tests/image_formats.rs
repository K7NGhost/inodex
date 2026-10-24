mod image_support;
use image_support::*;
use inodex::{
    Error,
    filesystem::{FileSystem, FsType},
    image::{AffImage, DiskImage, Image, Limits, SplitRawImage, VhdImage, VmdkImage},
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
fn independently_authored_public_containers_match_reference_bytes() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/images/tsk-image-reference.json")).unwrap();
    for (name, record) in reference.as_object().unwrap() {
        let expected = fixture(&format!("{name}.decoded"));
        assert_eq!(
            inodex::ewf::hex(&Sha256::digest(&expected)),
            record["sha256"].as_str().unwrap()
        );
        let mut image = Image::open(dir.path().join(name)).unwrap();
        check_reads(&mut image, &expected);
    }
}

#[test]
fn qemu_vmdk_variants_support_filesystem_extraction() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    let raw = fixture("ext2.vmdk.decoded");
    for name in [
        "monolithicSparse",
        "streamOptimized",
        "streamFooter",
        "twoGbMaxExtentSparse",
        "monolithicFlat",
        "twoGbMaxExtentFlat",
    ] {
        let mut image = Image::open(dir.path().join(format!("{name}.vmdk"))).unwrap();
        check_reads(&mut image, &raw);
        let mut fs = FileSystem::open(&mut image).unwrap();
        assert_eq!(fs.info().filesystem, FsType::Ext2);
        let id = fs.resolve("/passwords.txt").unwrap();
        let mut data = vec![];
        fs.copy_file(id, None, &mut data).unwrap();
        assert_eq!(
            inodex::ewf::hex(&Sha256::digest(&data)),
            "02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252"
        );
    }
}

#[test]
fn vhd_variants_and_parent_sector_inheritance() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    for (name, kind) in [
        ("ntfs-fixed.vhd", 2),
        ("ntfs-dynamic.vhd", 3),
        ("ntfs-differential.vhd", 4),
        ("fat-differential.vhd", 4),
    ] {
        let mut disk = VhdImage::open(dir.path().join(name)).unwrap();
        assert_eq!(disk.disk_type(), kind);
        check_reads(&mut disk, &fixture(&format!("{name}.decoded")));
    }
}

#[test]
fn split_raw_explicit_order_unequal_members_and_sector_override() {
    let dir = tempfile::tempdir().unwrap();
    let expected: Vec<u8> = (0..80000).map(|i| (i % 251) as u8).collect();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let c = dir.path().join("c");
    fs::write(&a, &expected[..1001]).unwrap();
    fs::write(&b, &expected[1001..67891]).unwrap();
    fs::write(&c, &expected[67891..]).unwrap();
    let mut disk = SplitRawImage::open_segments([a, b, c], 4096).unwrap();
    assert_eq!(disk.sector_size(), 4096);
    check_reads(&mut disk, &expected);
}

#[test]
fn split_raw_rejects_gaps_duplicates_missing_members_and_bad_sectors() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("disk.001");
    let c = dir.path().join("disk.003");
    fs::write(&a, b"abc").unwrap();
    fs::write(&c, b"xyz").unwrap();
    assert!(SplitRawImage::open(&a).is_err());
    assert!(SplitRawImage::open(&c).is_err());
    assert!(SplitRawImage::open_segments([a.clone(), a.clone()], 512).is_err());
    assert!(SplitRawImage::open_segments([a.clone()], 513).is_err());
    assert!(SplitRawImage::open_segments(Vec::<PathBuf>::new(), 512).is_err());
    fs::remove_file(c).unwrap();
    let b = dir.path().join("disk.002");
    fs::write(&b, b"xyz").unwrap();
    let mut disk = SplitRawImage::open(&a).unwrap();
    fs::remove_file(&b).unwrap();
    assert!(disk.read_exact_at(2, &mut [0; 4]).is_err());
}

#[test]
fn vmdk_snapshot_inherits_parent_and_distinguishes_explicit_zero_grains() {
    let dir = tempfile::tempdir().unwrap();
    let (path, expected) = sparse_child(dir.path());
    let mut disk = VmdkImage::open(&path).unwrap();
    check_reads(&mut disk, &expected);
    let other = dir.path().join("other.vmdk");
    fs::rename(dir.path().join("parent.vmdk"), &other).unwrap();
    assert!(VmdkImage::open(&path).is_err());
    check_reads(
        &mut VmdkImage::with_parent(&path, &other).unwrap(),
        &expected,
    );
}

#[test]
fn vmdk_flat_offset_zero_extents_and_multiple_extents() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("disk.vmdk");
    fs::write(
        dir.path().join("part.raw"),
        [vec![0x11; 512], vec![0x22; 512], vec![0x33; 512]].concat(),
    )
    .unwrap();
    fs::write(
        &p,
        "version=1\nRW 1 FLAT \"part.raw\" 1\nRW 1 ZERO\nRW 1 FLAT \"part.raw\" 2\n",
    )
    .unwrap();
    let mut disk = VmdkImage::open(p).unwrap();
    let expected = [vec![0x22; 512], vec![0; 512], vec![0x33; 512]].concat();
    let mut bytes = vec![0; 1536];
    disk.read_exact_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, expected);
}

#[test]
fn vhd_explicit_parent_wrong_uuid_missing_parent_and_cycles() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    let child = dir.path().join("ntfs-differential.vhd");
    let parent = dir.path().join("ntfs-parent.vhd");
    let moved = dir.path().join("moved.vhd");
    fs::rename(&parent, &moved).unwrap();
    assert!(VhdImage::open(&child).is_err());
    check_reads(
        &mut VhdImage::with_parent(&child, &moved).unwrap(),
        &fixture("ntfs-differential.vhd.decoded"),
    );
    assert!(VhdImage::with_parent(&child, dir.path().join("ntfs-fixed.vhd")).is_err());
    assert!(VhdImage::with_parent(&child, &child).is_err());
}

#[test]
fn generic_verify_and_export_match_known_bytes() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    for name in [
        "ext2.vmdk",
        "ext2.vhd",
        "ext2.splitraw.000",
        "ntfs-fixed.vhd",
    ] {
        let mut image = Image::open(dir.path().join(name)).unwrap();
        let result = image.verify().unwrap();
        let expected = fixture(&format!("{name}.decoded"));
        assert_eq!(result.bytes_read, expected.len() as u64);
        assert!(!result.md5_verified && !result.sha1_verified);
        let mut out = vec![];
        image.export_to(&mut out).unwrap();
        assert_eq!(out, expected);
    }
}

#[test]
fn image_resource_limits_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    let limits = Limits {
        max_metadata_bytes: 4,
        ..Limits::default()
    };
    for name in ["ext2.vmdk", "ntfs-dynamic.vhd"] {
        assert!(matches!(
            Image::with_limits(dir.path().join(name), limits.clone()),
            Err(Error::ResourceLimit(_))
        ));
    }
    assert!(
        SplitRawImage::with_limits(
            [
                dir.path().join("ext2.splitraw.000"),
                dir.path().join("ext2.splitraw.001")
            ],
            512,
            Limits {
                max_segments: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        VhdImage::with_limits(
            dir.path().join("fat-differential.vhd"),
            Limits {
                max_parent_depth: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn aff_sparse_zero_compressed_pages_and_page_digests() {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.aff");
    let mut data = aff_header(4 * 4096);
    aff_segment(&mut data, "page0", 0, &[0x7a; 4096]);
    let mut z = ZlibEncoder::new(vec![], Compression::default());
    z.write_all(&[0x5c; 4096]).unwrap();
    aff_segment(&mut data, "page1", 1, &z.finish().unwrap());
    aff_segment(&mut data, "page1_sha256", 0, &Sha256::digest([0x5c; 4096]));
    aff_segment(&mut data, "page2", 0x31, &4096u32.to_be_bytes());
    fs::write(&path, data).unwrap();
    let expected = [vec![0x7a; 4096], vec![0x5c; 4096], vec![0; 8192]].concat();
    check_reads(&mut AffImage::open(&path).unwrap(), &expected);
}

#[test]
fn afflib_authored_aff_afd_afm_and_lzma_match_stream_oracle() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    let expected = fixture("ext2.vmdk.decoded");
    for name in [
        "native.aff",
        "plain.aff",
        "lzma.aff",
        "multi.afd",
        "native.afm",
    ] {
        let mut disk = Image::open(dir.path().join(name)).unwrap();
        check_reads(&mut disk, &expected);
        let verified = disk.verify().unwrap();
        assert!(verified.md5_verified && verified.sha1_verified);
        let mut fs = FileSystem::open(&mut disk).unwrap();
        assert_eq!(fs.info().filesystem, FsType::Ext2);
        let id = fs.resolve("/passwords.txt").unwrap();
        let mut out = vec![];
        fs.copy_file(id, None, &mut out).unwrap();
        assert_eq!(out.len(), 116);
    }
}

#[test]
fn aff_final_partial_page_and_high_quadword_size() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("tail.aff");
    let mut bytes = aff_header(4099);
    aff_segment(&mut bytes, "page0", 0, &[0x51; 4096]);
    aff_segment(&mut bytes, "page1", 0, b"end");
    fs::write(&p, bytes).unwrap();
    let expected = [vec![0x51; 4096], b"end".to_vec()].concat();
    check_reads(&mut AffImage::open(&p).unwrap(), &expected);
    fs::write(&p, aff_header((1u64 << 32) + 17)).unwrap();
    let mut disk = AffImage::open(&p).unwrap();
    assert_eq!(disk.len(), (1 << 32) + 17);
    let mut out = [0xa5; 17];
    disk.read_exact_at(1 << 32, &mut out).unwrap();
    assert_eq!(out, [0; 17]);
}

#[test]
fn alphabetic_split_raw_discovery_and_gap_detection() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("disk.aa");
    fs::write(&first, [0x12; 4096]).unwrap();
    fs::write(dir.path().join("disk.ab"), [0x34; 4096]).unwrap();
    check_reads(
        &mut Image::open(&first).unwrap(),
        &[vec![0x12; 4096], vec![0x34; 4096]].concat(),
    );
    fs::rename(dir.path().join("disk.ab"), dir.path().join("disk.ac")).unwrap();
    assert!(Image::open(first).is_err());
}

#[test]
fn committed_container_checksums_match_provenance_manifests() {
    for manifest in [
        include_str!("fixtures/images/dfvfs-sources.json"),
        include_str!("fixtures/images/qemu-generated.json"),
        include_str!("fixtures/images/afflib-generated.json"),
    ] {
        let value: serde_json::Value = serde_json::from_str(manifest).unwrap();
        let rows: Vec<(String, &serde_json::Value)> = if let Some(rows) = value.as_array() {
            rows.iter()
                .map(|v| (v["name"].as_str().unwrap().to_owned(), v))
                .collect()
        } else {
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v))
                .collect()
        };
        for (name, record) in rows {
            let data = fixture(&name);
            assert_eq!(
                inodex::ewf::hex(&Sha256::digest(&data)),
                record["sha256"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}

#[test]
fn vmdk_version_two_zero_grain_directory_overrides_parent() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = sparse_child(dir.path());
    let sparse = dir.path().join("child-sparse.vmdk");
    let mut bytes = fs::read(&sparse).unwrap();
    le32(&mut bytes, 4, 2);
    le32(&mut bytes, 512, 1);
    fs::write(sparse, bytes).unwrap();
    check_reads(&mut VmdkImage::open(path).unwrap(), &[0; 12288]);
}
