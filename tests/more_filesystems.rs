mod layers_support;
use inodex::{
    filesystem::{FileKind, FileSystem, FsType, Limits, apfs},
    image::{DiskImage, Volume},
};
use layers_support::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/layers/tsk-more-reference.json")).unwrap()
}
fn bytes(name: &str) -> Vec<u8> {
    let d = raw(&format!("{name}.raw"));
    if name == "ufs1" || name == "ufs2" {
        d[8192..].to_vec()
    } else {
        d
    }
}
fn walk(fs: &mut FileSystem<'_>, id: u64, path: &str, entries: &mut BTreeMap<String, u64>) {
    for e in fs.read_dir(id).unwrap() {
        let p = format!("{path}/{}", e.name);
        assert!(entries.insert(p.clone(), e.id).is_none());
        if e.kind == FileKind::Directory {
            walk(fs, e.id, &p, entries);
        }
    }
}
fn compare(name: &str, typ: FsType) {
    let mut image = Memory::new(bytes(name));
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.info().filesystem, typ);
    let mut entries = BTreeMap::new();
    let root = fs.info().root_id;
    walk(&mut fs, root, "", &mut entries);
    let expected = oracle();
    let expected = expected["filesystems"][name].as_array().unwrap();
    let expected: Vec<_> = expected
        .iter()
        .filter(|e| !e["path"].as_str().unwrap().starts_with("/<"))
        .collect();
    assert_eq!(entries.len(), expected.len(), "{name} {:?}", entries.keys());
    for e in expected {
        let path = e["source_path"]
            .as_str()
            .unwrap_or_else(|| e["path"].as_str().unwrap());
        let id = *entries
            .get(path)
            .unwrap_or_else(|| panic!("missing {name}:{path}"));
        assert_eq!(fs.resolve(path).unwrap(), id);
        let m = fs.metadata(id).unwrap();
        if let Some(target) = e["source_target"].as_str() {
            assert_eq!(m.kind, FileKind::Symlink);
            let mut data = vec![];
            fs.copy_file(id, None, &mut data).unwrap();
            assert_eq!(data, target.as_bytes());
            continue;
        }
        if name == "yaffs2" && path == "/hardlink" {
            assert_eq!(m.kind, FileKind::File);
            let mut data = vec![];
            fs.copy_file(id, None, &mut data).unwrap();
            assert_eq!(data, b"hello yaffs!");
            continue;
        }
        assert_eq!(
            serde_json::to_value(m.kind).unwrap(),
            e["kind"],
            "{name}:{path}"
        );
        assert_eq!(
            m.size,
            e[if m.kind == FileKind::Symlink {
                "logical_size"
            } else {
                "size"
            }]
            .as_u64()
            .unwrap(),
            "{name}:{path}"
        );
        if !name.starts_with("iso") {
            assert_eq!(id, e["id"].as_u64().unwrap());
        }
        if let Some(uid) = m.uid {
            assert_eq!(uid as u64, e["uid"].as_u64().unwrap());
        }
        if let Some(gid) = m.gid {
            assert_eq!(gid as u64, e["gid"].as_u64().unwrap());
        }
        if let Some(t) = m.times.modified {
            // TSK ignores ISO's +02:00 recording offset and calls mktime.
            let adjustment = oracle()["iso_recording_offsets"][name]
                .as_i64()
                .unwrap_or(0);
            assert_eq!(
                t.seconds,
                e[if name.starts_with("iso") {
                    "created"
                } else {
                    "modified"
                }]
                .as_i64()
                .unwrap()
                    - adjustment,
                "{name}:{path}"
            );
        }
        if matches!(m.kind, FileKind::File | FileKind::Symlink) {
            let mut data = vec![];
            fs.copy_file(id, None, &mut data).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&data)),
                e["sha256"].as_str().unwrap(),
                "{name}:{path}"
            );
            let mut buffer = [0; 17];
            for offset in [0, 1, m.size.saturating_sub(4), m.size, m.size + 10] {
                let n = fs.read_file(id, None, offset, &mut buffer).unwrap();
                let start = (offset as usize).min(data.len());
                assert_eq!(&buffer[..n], &data[start..start + n]);
            }
        }
    }
}
macro_rules! comparison {
    ($test:ident,$name:literal,$typ:ident) => {
        #[test]
        fn $test() {
            compare($name, FsType::$typ);
        }
    };
}
comparison!(apfs_against_current_tsk, "apfs", Apfs);
comparison!(
    apfs_internal_nodes_against_current_tsk,
    "apfs-internal",
    Apfs
);
comparison!(hfs_overflow_against_current_tsk, "hfs-overflow", HfsPlus);
comparison!(hfsplus_against_current_tsk, "hfsplus", HfsPlus);
comparison!(ufs1_against_current_tsk, "ufs1", Ufs1);
comparison!(ufs2_against_current_tsk, "ufs2", Ufs2);
comparison!(iso9660_against_current_tsk, "iso9660", Iso9660);
#[test]
fn iso_multi_extent_reads_one_logical_file() {
    let mut m = Memory::new(bytes("iso-multi"));
    let mut fs = FileSystem::open(&mut m).unwrap();
    let id = fs.resolve("/PASSWORDS.TXT").unwrap();
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(
        data,
        (0..2381)
            .map(|i| ((i * 13 + 7) % 251) as u8)
            .collect::<Vec<_>>()
    );
    let mut boundary = [0; 30];
    assert_eq!(fs.read_file(id, None, 2040, &mut boundary).unwrap(), 30);
    assert_eq!(&boundary, &data[2040..2070]);
}
comparison!(yaffs2_against_current_tsk, "yaffs2", Yaffs2);
comparison!(hfsx_against_current_tsk, "hfsx", HfsX);
comparison!(ufs1_indirect_against_current_tsk, "ufs1-indirect", Ufs1);
comparison!(ufs2_indirect_against_current_tsk, "ufs2-indirect", Ufs2);
comparison!(ufs1_big_endian_against_current_tsk, "ufs1-be", Ufs1);
comparison!(ufs2_big_endian_against_current_tsk, "ufs2-be", Ufs2);
comparison!(joliet_against_current_tsk, "iso-joliet", Iso9660);
comparison!(rockridge_against_current_tsk, "iso-rockridge", Iso9660);

#[test]
fn apple_resource_forks_match_independent_reader() {
    let reference = oracle();
    for name in ["apfs", "hfsplus"] {
        let mut image = Memory::new(bytes(name));
        let mut fs = FileSystem::open(&mut image).unwrap();
        let id = fs.resolve("/a_directory/a_resourcefork").unwrap();
        let mut data = vec![];
        fs.copy_file(id, Some("com.apple.ResourceFork"), &mut data)
            .unwrap();
        let expected = &reference["resource_forks"][name];
        assert_eq!(data.len() as u64, expected["size"].as_u64().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(&data)),
            expected["sha256"].as_str().unwrap()
        );
    }
}
#[test]
fn apfs_volumes_are_selectable_and_symlink_has_no_trailing_nul() {
    let mut image = Memory::new(bytes("apfs"));
    let v = apfs::volumes(&mut image, Limits::default()).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].oid, 1026);
    assert_eq!(v[0].name, "apfs_test");
    assert!(!v[0].encrypted);
    let mut fs = apfs::open_volume(&mut image, Limits::default(), Some(v[0].oid)).unwrap();
    let mut data = vec![0; 24];
    assert_eq!(fs.read_file(20, None, 0, &mut data).unwrap(), 24);
    assert_eq!(data, b"a_directory/another_file");
    assert!(apfs::open_volume(&mut image, Limits::default(), Some(999999)).is_err());
}
#[test]
fn yaffs_versions_fragmentation_holes_and_unlinks() {
    let mut image = Memory::new(bytes("yaffs2"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.resolve("/deleted").is_err());
    let id = fs.resolve("/fragmented.bin").unwrap();
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(
        data,
        (0..3000)
            .map(|i| ((i * 11 + 3) % 251) as u8)
            .collect::<Vec<_>>()
    );
    let id = fs.resolve("/sparse.bin").unwrap();
    data.clear();
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(&data[..2048], &[0; 2048]);
    assert_eq!(&data[2048..], &[b'Z'; 2048]);
}
#[test]
fn all_added_parsers_enforce_limits_and_volume_bounds() {
    for name in ["apfs", "hfsplus", "ufs1", "ufs2", "iso9660", "yaffs2"] {
        let mut image = Memory::new(bytes(name));
        assert!(
            FileSystem::with_limits(
                &mut image,
                Limits {
                    max_metadata_bytes: 100,
                    max_directory_entries: 1,
                    ..Limits::default()
                }
            )
            .is_err(),
            "{name}"
        );
        let len = image.len();
        let mut volume = Volume::new(&mut image, 0, len / 2 - 1).unwrap();
        assert!(FileSystem::open(&mut volume).is_err(), "{name}");
    }
}
#[test]
fn all_added_parsers_reject_truncated_metadata_without_panics() {
    for name in ["apfs", "hfsplus", "ufs1", "ufs2", "iso9660", "yaffs2"] {
        let source = bytes(name);
        for length in [0, 32, 511, 1024, 2047, source.len() / 2 - 1] {
            let mut image = Memory::new(source[..length.min(source.len())].to_vec());
            assert!(FileSystem::open(&mut image).is_err(), "{name}:{length}");
        }
    }
}
#[test]
fn hfsx_is_case_sensitive_and_hfsplus_accepts_ascii_case() {
    for (name, insensitive) in [("hfsx", false), ("hfsplus", true)] {
        let mut m = Memory::new(bytes(name));
        let mut fs = FileSystem::open(&mut m).unwrap();
        assert!(fs.resolve("/passwords.txt").is_ok());
        assert_eq!(fs.resolve("/PASSWORDS.TXT").is_ok(), insensitive);
    }
}
#[test]
fn indirect_ufs_files_match_constructed_source_patterns() {
    for name in ["ufs1-indirect", "ufs2-indirect"] {
        let mut m = Memory::new(bytes(name));
        let mut fs = FileSystem::open(&mut m).unwrap();
        let block = fs.info().block_size as usize;
        let id = fs.resolve("/passwords.txt").unwrap();
        let mut d = vec![];
        fs.copy_file(id, None, &mut d).unwrap();
        let expected: Vec<u8> = (0..12 * block + 321)
            .map(|i| {
                if i / block == 3 {
                    0
                } else {
                    (((i / block) * 19 + i % block) % 251) as u8
                }
            })
            .collect();
        assert_eq!(d, expected);
    }
}
#[test]
fn new_fixture_provenance_hashes_match() {
    for manifest in [
        include_str!("fixtures/layers/MORE_RAW_SHA256SUMS"),
        include_str!("fixtures/layers/MORE_GENERATED_SHA256SUMS"),
        include_str!("fixtures/layers/YAFFS_RAW_SHA256SUMS"),
    ] {
        for line in manifest.lines() {
            let (expected, name) = line.split_once("  ").unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(raw(name))),
                expected,
                "{name}"
            );
        }
    }
}
#[test]
fn rockridge_case_and_joliet_unicode_names_follow_the_selected_namespace() {
    let mut image = Memory::new(bytes("iso-rockridge"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.resolve("/docs/note.txt").is_ok());
    assert!(fs.resolve("/DOCS/NOTE.TXT").is_err());
    let mut image = Memory::new(bytes("iso-joliet"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.resolve("/Docs/Gräße.txt").is_ok());
}
