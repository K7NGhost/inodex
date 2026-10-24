mod expansion_support;
mod layers_support;
use expansion_support::*;
use inodex::{
    filesystem::{FileKind, FileSystem, FsType, Limits, apfs},
    image::Image,
};
use layers_support::Memory;
use sha2::{Digest, Sha256};
#[test]
fn solaris_both_endians_inode_ownership_microseconds_and_content() {
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/layers/tsk-more-reference.json")).unwrap();
    for name in ["ufs1b", "ufs1b-be"] {
        let mut image = Memory::new(fixture(&format!("{name}.raw")));
        let mut fs = FileSystem::open(&mut image).unwrap();
        assert_eq!(fs.info().filesystem, FsType::Ufs1b);
        for row in oracle["filesystems"]["ufs1"].as_array().unwrap() {
            let path = row["path"].as_str().unwrap();
            let id = fs.resolve(path).unwrap();
            let m = fs.metadata(id).unwrap();
            assert_eq!(id, row["id"].as_u64().unwrap());
            assert_eq!(m.uid, Some(100000 + id as u32));
            assert_eq!(m.gid, Some(200000 + id as u32));
            assert_eq!(m.times.modified.unwrap().nanos, 123456000);
            if m.kind == FileKind::File || m.kind == FileKind::Symlink {
                let mut bytes = vec![];
                fs.copy_file(id, None, &mut bytes).unwrap();
                assert_eq!(
                    format!("{:x}", Sha256::digest(bytes)),
                    row["sha256"].as_str().unwrap()
                );
            }
        }
    }
}

#[test]
fn old_bsd_directories_are_not_silently_given_solaris_ownership() {
    let original = layers_support::raw("ufs1.raw");
    let mut bytes = original[8192..].to_vec();
    let frag = u32::from_le_bytes(bytes[8244..8248].try_into().unwrap()) as usize;
    let root = u32::from_le_bytes(bytes[8208..8212].try_into().unwrap()) as usize * frag + 256;
    let directory =
        u32::from_le_bytes(bytes[root + 40..root + 44].try_into().unwrap()) as usize * frag;
    bytes[directory + 6..directory + 8].copy_from_slice(&1u16.to_le_bytes());
    assert!(matches!(
        FileSystem::open(&mut Memory::new(bytes)),
        Err(inodex::Error::Unsupported(_))
    ));
}
#[test]
fn wrapped_hfsplus_hfsx_preserve_forks_and_metadata() {
    for (name, typ) in [
        ("hfs-wrapped", FsType::HfsPlus),
        ("hfsx-wrapped", FsType::HfsX),
    ] {
        let mut image = Memory::new(fixture(&format!("{name}.raw")));
        let mut fs = FileSystem::open(&mut image).unwrap();
        assert_eq!(fs.info().filesystem, typ);
        let base = layers_support::raw(if typ == FsType::HfsPlus {
            "hfsplus.raw"
        } else {
            "hfsx.raw"
        });
        let mut plain = Memory::new(base);
        let mut reference = FileSystem::open(&mut plain).unwrap();
        for path in [
            "/passwords.txt",
            "/a_directory/a_file",
            "/a_link",
            "/a_directory/a_resourcefork",
        ] {
            let id = fs.resolve(path).unwrap();
            let expected = reference.resolve(path).unwrap();
            assert_eq!(
                serde_json::to_value(fs.metadata(id).unwrap()).unwrap(),
                serde_json::to_value(reference.metadata(expected).unwrap()).unwrap()
            );
            let stream = (path.ends_with("a_resourcefork")).then_some("com.apple.ResourceFork");
            let (mut actual, mut golden) = (vec![], vec![]);
            fs.copy_file(id, stream, &mut actual).unwrap();
            reference.copy_file(expected, stream, &mut golden).unwrap();
            assert_eq!(actual, golden);
        }
    }
}
#[test]
fn apple_compression_independent_payloads_and_random_boundaries() {
    let source: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/expansion/compression-source.json")).unwrap();
    for family in ["hfs", "apfs"] {
        for method in [3, 4, 7, 8, 9, 10, 11, 12] {
            let name = format!("{family}-compressed-{method}.raw");
            let mut image = Memory::new(fixture(&name));
            let mut fs = FileSystem::open(&mut image).unwrap();
            let id = fs.resolve("/passwords.txt").unwrap();
            let m = fs.metadata(id).unwrap();
            let expected = &source[method.to_string()];
            let root = fs.info().root_id;
            assert_eq!(
                fs.read_dir(root)
                    .unwrap()
                    .into_iter()
                    .find(|e| e.id == id)
                    .unwrap()
                    .size,
                m.size
            );
            assert_eq!(m.size, expected["size"].as_u64().unwrap());
            assert!(m.streams.iter().any(|s| s.name == "com.apple.decmpfs"));
            let mut bytes = vec![];
            fs.copy_file(id, None, &mut bytes).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&bytes)),
                expected["sha256"].as_str().unwrap()
            );
            for offset in [0, 37, 65530, 65536, bytes.len() - 7] {
                let mut buffer = [0; 127];
                let n = fs.read_file(id, None, offset as u64, &mut buffer).unwrap();
                let at = offset.min(bytes.len());
                assert_eq!(&buffer[..n], &bytes[at..at + n]);
            }
            assert_eq!(fs.read_file(id, None, u64::MAX, &mut [0; 9]).unwrap(), 0);
        }
    }
}
#[test]
fn snapshot_tree_uses_historical_object_map_and_file_bytes() {
    let bytes = fixture("apfs-snapshot.raw");
    let mut image = Memory::new(bytes);
    let snapshots = apfs::snapshots(&mut image, Limits::default(), None).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, "before-edit");
    assert_eq!(snapshots[0].xid, 3);
    let mut live = FileSystem::open(&mut image).unwrap();
    let id = live.resolve("/passwords.txt").unwrap();
    let mut current = vec![];
    live.copy_file(id, None, &mut current).unwrap();
    drop(live);
    let mut snap = FileSystem::Indexed(
        apfs::open_snapshot(&mut image, Limits::default(), Some(1026), 3).unwrap(),
    );
    let id = snap.resolve("/passwords.txt").unwrap();
    let mut old = vec![];
    snap.copy_file(id, None, &mut old).unwrap();
    drop(snap);
    assert_ne!(current, old);
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/expansion/tsk-reference.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(current)),
        oracle["apfs-snapshot-False"]["sha256"]
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(old)),
        oracle["apfs-snapshot-True"]["sha256"]
    );
    assert!(matches!(
        apfs::open_snapshot(&mut image, Limits::default(), None, 99),
        Err(inodex::Error::NotFound(_))
    ));
}
#[test]
fn snapshot_checksum_identity_and_pending_flags_are_rejected() {
    let original = fixture("apfs-snapshot.raw");
    let mut pending = original.clone();
    let start = 140 * 4096;
    let count = u32::from_le_bytes(pending[start + 36..start + 40].try_into().unwrap()) as usize;
    let table_len =
        u16::from_le_bytes(pending[start + 42..start + 44].try_into().unwrap()) as usize;
    for i in 0..count {
        let entry = start + 56 + i * 8;
        let ko = u16::from_le_bytes(pending[entry..entry + 2].try_into().unwrap()) as usize;
        let key = start + 56 + table_len + ko;
        if u64::from_le_bytes(pending[key..key + 8].try_into().unwrap()) >> 60 == 1 {
            let vo = u16::from_le_bytes(pending[entry + 4..entry + 6].try_into().unwrap()) as usize;
            let value = start + 4056 - vo;
            pending[value + 44..value + 48].copy_from_slice(&1u32.to_le_bytes());
        }
    }
    apfs_crc(&mut pending, 140);
    assert!(matches!(
        apfs::open_snapshot(&mut Memory::new(pending), Limits::default(), None, 3),
        Err(inodex::Error::Unsupported(_))
    ));
    let mut bad = original.clone();
    bad[104 * 4096 + 240] ^= 1;
    apfs_crc(&mut bad, 104);
    assert!(apfs::open_snapshot(&mut Memory::new(bad), Limits::default(), None, 3).is_err());
    let mut bad = original.clone();
    bad[140 * 4096 + 8] ^= 1;
    assert!(apfs::snapshots(&mut Memory::new(bad), Limits::default(), None).is_err());
    let mut bad = original;
    bad[101 * 4096 + 16..101 * 4096 + 24].copy_from_slice(&4u64.to_le_bytes());
    apfs_crc(&mut bad, 101);
    assert!(apfs::open_snapshot(&mut Memory::new(bad), Limits::default(), None, 3).is_err());
}
#[test]
fn wrapper_bounds_and_signatures_fail_without_fallback() {
    for at in [1024, 1148, 1150, 1152] {
        let mut bytes = fixture("hfs-wrapped.raw");
        bytes[at] ^= 0xff;
        assert!(FileSystem::open(&mut Memory::new(bytes)).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = unpack("hfs-wrapped.raw", dir.path());
    let mut image = Image::open(path).unwrap();
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.resolve("/passwords.txt").is_ok());
}

#[test]
fn new_filesystem_layouts_compose_through_verified_e01() {
    let mut names = vec![
        "ufs1b".to_owned(),
        "ufs1b-be".to_owned(),
        "hfs-wrapped".to_owned(),
        "hfsx-wrapped".to_owned(),
        "apfs-snapshot".to_owned(),
    ];
    for family in ["hfs", "apfs"] {
        for method in [3, 4, 7, 8, 9, 10, 11, 12] {
            names.push(format!("{family}-compressed-{method}"));
        }
    }
    for name in names {
        let mut image = Image::open(root().join(format!("{name}.E01"))).unwrap();
        let verification = image.verify().unwrap();
        assert!(verification.md5_verified);
        assert!(verification.sha1_verified);
        let mut fs = FileSystem::open(&mut image).unwrap();
        let id = fs.resolve("/passwords.txt").unwrap();
        let mut content = vec![];
        fs.copy_file(id, None, &mut content).unwrap();
        assert!(!content.is_empty());
        drop(fs);
        if name == "apfs-snapshot" {
            let mut snap = FileSystem::Indexed(
                apfs::open_snapshot(&mut image, Limits::default(), None, 3).unwrap(),
            );
            let id = snap.resolve("/passwords.txt").unwrap();
            let mut saved = vec![];
            snap.copy_file(id, None, &mut saved).unwrap();
            assert_ne!(content, saved);
        }
    }
}

#[test]
fn compressed_headers_resource_tables_and_decoded_size_limits() {
    for family in ["hfs", "apfs"] {
        let original = fixture(&format!("{family}-compressed-3.raw"));
        let header = original.windows(4).position(|b| b == b"fpmc").unwrap();
        for at in [header, header + 16] {
            let mut d = original.clone();
            d[at] ^= 1;
            if family == "apfs" {
                apfs_crc(&mut d, header / 4096);
            }
            assert!(FileSystem::open(&mut Memory::new(d)).is_err());
        }
        let mut d = original.clone();
        d[header + 8..header + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        if family == "apfs" {
            apfs_crc(&mut d, header / 4096);
        }
        assert!(FileSystem::open(&mut Memory::new(d)).is_err());
        let mut d = original;
        d[header + 4..header + 8].copy_from_slice(&13u32.to_le_bytes());
        if family == "apfs" {
            apfs_crc(&mut d, header / 4096);
        }
        let mut image = Memory::new(d);
        let mut fs = FileSystem::open(&mut image).unwrap();
        let id = fs.resolve("/passwords.txt").unwrap();
        assert!(matches!(
            fs.read_file(id, None, 0, &mut [0; 10]),
            Err(inodex::Error::Unsupported(_))
        ));
    }
    let original = fixture("hfs-compressed-4.raw");
    let catalog = u32::from_be_bytes(original[1312..1316].try_into().unwrap()) as usize * 4096;
    let size =
        u16::from_be_bytes(original[catalog + 32..catalog + 34].try_into().unwrap()) as usize;
    let leaf = catalog + size;
    let count = u16::from_be_bytes(original[leaf + 10..leaf + 12].try_into().unwrap()) as usize;
    let mut resource = None;
    for i in 0..count {
        let at = leaf
            + u16::from_be_bytes(
                original[leaf + size - (i + 1) * 2..leaf + size - i * 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
        let value = at + 2 + u16::from_be_bytes(original[at..at + 2].try_into().unwrap()) as usize;
        if original[value..value + 2] == [0, 2]
            && u32::from_be_bytes(original[value + 8..value + 12].try_into().unwrap()) == 20
        {
            resource = Some(
                u32::from_be_bytes(original[value + 184..value + 188].try_into().unwrap()) as usize
                    * 4096,
            );
        }
    }
    let resource = resource.unwrap();
    for (at, value) in [(resource + 260, u32::MAX), (resource + 264, 0)] {
        let mut d = original.clone();
        d[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(FileSystem::open(&mut Memory::new(d)).is_err());
    }
}
