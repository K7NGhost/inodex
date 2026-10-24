use inodex::{
    filesystem::{FileKind, FileSystem, FsType, TimeBasis},
    image::{DiskImage, Image, RawImage, Volume},
    partition::{PartitionTable, Scheme},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn raw(name: &str) -> Vec<u8> {
    let path = if name == "ext2.raw" {
        root().join("tests/fixtures/ext2.raw.gz")
    } else {
        root()
            .join("tests/fixtures/layers")
            .join(format!("{name}.gz"))
    };
    let compressed = fs::read(path).unwrap();
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}
fn image_file(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    fs::write(&path, raw(name)).unwrap();
    (dir, path)
}
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/layers/tsk-reference.json")).unwrap()
}
fn walk(
    fs: &mut FileSystem<'_>,
    id: u64,
    parent: &str,
    entries: &mut BTreeMap<String, (u64, FileKind)>,
) {
    for entry in fs.read_dir(id).unwrap() {
        let path = format!("{parent}/{}", entry.name);
        assert!(
            entries
                .insert(path.clone(), (entry.id, entry.kind))
                .is_none()
        );
        if entry.kind == FileKind::Directory {
            walk(fs, entry.id, &path, entries);
        }
    }
}

fn compare_filesystem(name: &str, expected_type: FsType) {
    let (_dir, path) = image_file(name);
    let mut image = RawImage::open(path).unwrap();
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.info().filesystem, expected_type);
    let reference = oracle();
    let expected = &reference["filesystems"][name];
    let mut actual = BTreeMap::new();
    let root_id = fs.info().root_id;
    walk(&mut fs, root_id, "", &mut actual);
    let expected_entries: Vec<_> = expected["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            // TSK exposes FAT metadata and volume labels as synthetic entries.
            e["kind"] != "other"
                && !e["path"]
                    .as_str()
                    .unwrap()
                    .ends_with("(Volume Label Entry)")
        })
        .collect();
    assert_eq!(
        actual.len(),
        expected_entries.len(),
        "{name}: {:?}",
        actual.keys()
    );
    for entry in expected_entries {
        let path = entry["path"].as_str().unwrap();
        let (id, _) = actual
            .get(path)
            .unwrap_or_else(|| panic!("missing {name}:{path}"));
        assert_eq!(fs.resolve(path).unwrap(), *id);
        let metadata = fs.metadata(*id).unwrap();
        assert_eq!(
            serde_json::to_value(metadata.kind).unwrap(),
            entry["kind"],
            "{name}:{path}"
        );
        assert_eq!(
            metadata.size,
            entry["size"].as_u64().unwrap(),
            "{name}:{path}"
        );
        assert!(metadata.allocated);
        if expected_type != FsType::Fat12
            && expected_type != FsType::Fat16
            && expected_type != FsType::Fat32
        {
            assert_eq!(*id, entry["id"].as_u64().unwrap(), "{name}:{path}");
            if expected_type == FsType::Ntfs && path == "/$MFT" {
                // Its SI FILETIMEs are literally zero. This old TSK build
                // underflows that conversion; preserve the correct 1601 date.
                assert_eq!(metadata.times.modified.unwrap().seconds, -11_644_473_600);
            } else {
                assert_eq!(
                    metadata.times.modified.unwrap().seconds,
                    entry["modified"].as_i64().unwrap(),
                    "{name}:{path}"
                );
                assert_eq!(
                    metadata.times.accessed.unwrap().seconds,
                    entry["accessed"].as_i64().unwrap(),
                    "{name}:{path}"
                );
                assert_eq!(
                    metadata.times.changed.unwrap().seconds,
                    entry["changed"].as_i64().unwrap(),
                    "{name}:{path}"
                );
            }
        } else if let Some(time) = metadata.times.modified {
            assert_eq!(time.basis, TimeBasis::LocalCivil);
        }
        for stream in entry["streams"].as_array().unwrap() {
            if let Some(samples) = stream["samples"].as_array() {
                for sample in samples {
                    let mut bytes = vec![0xa5; sample["length"].as_u64().unwrap() as usize];
                    assert_eq!(
                        fs.read_file(*id, None, sample["offset"].as_u64().unwrap(), &mut bytes)
                            .unwrap(),
                        bytes.len()
                    );
                    assert_eq!(
                        inodex::ewf::hex(&Sha256::digest(&bytes)),
                        sample["sha256"].as_str().unwrap()
                    );
                }
                continue;
            }
            let Some(hash) = stream["sha256"].as_str() else {
                assert_eq!(path, "/$BadClus");
                continue;
            };
            let stream_name = stream["name"].as_str().unwrap();
            let mut output = Vec::new();
            assert_eq!(
                fs.copy_file(*id, Some(stream_name), &mut output).unwrap(),
                stream["size"].as_u64().unwrap()
            );
            if name == "ext4-extent.raw" && path == "/passwords.txt" {
                // pytsk3 20180225 reads the physical bytes of unwritten
                // extents. Current TSK source and the ext4 specification
                // require zeroes. The independently constructed source bytes
                // are A at block 0, B at block 12, and zero everywhere else.
                let mut source = vec![0; 269 * 1024];
                source[..1024].fill(b'A');
                source[12 * 1024..13 * 1024].fill(b'B');
                assert_eq!(
                    hash,
                    "a18d601cca4d1fdca40b02dca9ea448e2a4cdb9f4875268eb78406ef3177d111"
                );
                assert_eq!(output, source);
            } else {
                assert_eq!(
                    inodex::ewf::hex(&Sha256::digest(&output)),
                    hash,
                    "{name}:{path}:{stream_name}"
                );
            }
            for offset in [0, 1, 511, 4095, output.len() as u64, u64::MAX] {
                let mut bytes = [0xa5; 1027];
                let count = fs
                    .read_file(*id, Some(stream_name), offset, &mut bytes)
                    .unwrap();
                let start = offset.min(output.len() as u64) as usize;
                assert_eq!(
                    &bytes[..count],
                    &output[start..(start + bytes.len()).min(output.len())]
                );
                assert!(bytes[count..].iter().all(|&b| b == 0xa5));
            }
        }
    }
    assert!(fs.resolve("/missing-file").is_err());
    if matches!(expected_type, FsType::Fat16 | FsType::Fat32) {
        assert_eq!(
            fs.resolve("/resume~1.txt").unwrap(),
            fs.resolve("/Résumé long filename.txt").unwrap()
        );
        assert_eq!(
            fs.resolve("/nested").unwrap(),
            fs.resolve("/NESTED").unwrap()
        );
        assert_eq!(
            fs.resolve("/NESTED/../empty.txt").unwrap(),
            fs.resolve("/EMPTY.TXT").unwrap()
        );
    } else {
        assert!(fs.resolve("/passwords.txt/child").is_err());
        assert_eq!(
            fs.resolve("/a_directory/../passwords.txt").unwrap(),
            fs.resolve("/passwords.txt").unwrap()
        );
    }
}

#[test]
fn ntfs_directory_metadata_and_every_readable_stream_match_tsk() {
    compare_filesystem("ntfs.raw", FsType::Ntfs);
}

#[test]
fn ntfs_attribute_list_and_extension_record_streams_match_tsk() {
    compare_filesystem("ntfs-attrlist.raw", FsType::Ntfs);
}
#[test]
fn fat12_directory_metadata_and_file_contents_match_tsk() {
    compare_filesystem("fat12.raw", FsType::Fat12);
}
#[test]
fn fat16_fragmented_unicode_and_file_contents_match_tsk() {
    compare_filesystem("fat16.raw", FsType::Fat16);
}
#[test]
fn fat32_fragmented_unicode_and_file_contents_match_tsk() {
    compare_filesystem("fat32.raw", FsType::Fat32);
}
#[test]
fn ext2_directory_metadata_and_file_contents_match_tsk() {
    compare_filesystem("ext2.raw", FsType::Ext2);
}
#[test]
fn ext4_directory_metadata_and_file_contents_match_tsk() {
    compare_filesystem("ext4.raw", FsType::Ext4);
}
#[test]
fn ext2_single_double_triple_indirect_and_sparse_reads_match_tsk() {
    compare_filesystem("ext2-indirect.raw", FsType::Ext2);
}
#[test]
fn ext4_external_extent_node_holes_and_unwritten_data_match_tsk() {
    compare_filesystem("ext4-extent.raw", FsType::Ext4);
}

#[test]
fn partition_ranges_match_tsk_for_mbr_ebr_and_gpt() {
    let reference = oracle();
    for name in [
        "mbr.raw",
        "gpt.raw",
        "gpt_non_sequential.raw",
        "ntfs-mbr.raw",
        "ntfs-gpt.raw",
    ] {
        let (_dir, path) = image_file(name);
        let mut image = RawImage::open(path).unwrap();
        let table = PartitionTable::read(&mut image).unwrap().unwrap();
        assert_eq!(
            table.scheme,
            if name.contains("mbr") {
                Scheme::Mbr
            } else {
                Scheme::Gpt
            }
        );
        let mut actual: Vec<_> = table
            .partitions
            .iter()
            .filter(|p| !p.is_container)
            .map(|p| (p.start_lba, p.sectors))
            .collect();
        let mut expected: Vec<_> = reference["partitions"][name]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["flags"].as_u64().unwrap() & 1 != 0)
            .map(|p| (p["start"].as_u64().unwrap(), p["sectors"].as_u64().unwrap()))
            .collect();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
        if name == "mbr.raw" {
            assert_eq!(table.get(5).unwrap().start_lba, 131);
            assert!(table.get(2).unwrap().is_container);
        }
    }
}

#[test]
fn e01_partition_ntfs_listing_and_extraction_is_end_to_end() {
    for (name, index) in [("ntfs-mbr.E01", 1), ("ntfs-gpt.E01", 3)] {
        let mut image = Image::open(root().join("tests/fixtures/layers").join(name)).unwrap();
        if let Image::Ewf(ewf) = &mut image {
            assert!(ewf.verify().unwrap().md5_verified);
        } else {
            panic!("expected E01");
        }
        let table = PartitionTable::read(&mut image).unwrap().unwrap();
        assert_eq!(table.get(index).unwrap().start_lba, 2048);
        if index == 3 {
            assert_eq!(table.get(index).unwrap().name, "NTFS evidence ☃");
        }
        let mut volume = table.get(index).unwrap().volume(&mut image).unwrap();
        let mut fs = FileSystem::open(&mut volume).unwrap();
        assert_eq!(fs.info().filesystem, FsType::Ntfs);
        let id = fs.resolve("/A_DIRECTORY/ANOTHER_FILE").unwrap();
        assert_eq!(id, 67);
        let mut bytes = Vec::new();
        fs.copy_file(id, None, &mut bytes).unwrap();
        assert_eq!(
            inodex::ewf::hex(&Sha256::digest(&bytes)),
            "c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16"
        );
    }
}

#[test]
fn e01_to_ext2_listing_and_extraction_is_end_to_end() {
    let mut image = Image::open(root().join("tests/fixtures/ext2.E01")).unwrap();
    assert!(PartitionTable::read(&mut image).unwrap().is_none());
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/passwords.txt").unwrap();
    let mut bytes = Vec::new();
    assert_eq!(fs.copy_file(id, None, &mut bytes).unwrap(), 116);
    assert_eq!(
        inodex::ewf::hex(&Sha256::digest(&bytes)),
        "02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252"
    );
}

#[test]
fn volume_reads_are_clipped_and_cannot_escape() {
    let (_dir, path) = image_file("ntfs.raw");
    let mut image = RawImage::open(path).unwrap();
    let mut volume = Volume::new(&mut image, 100, 50).unwrap();
    let mut bytes = [0xcc; 100];
    assert_eq!(volume.read_at(40, &mut bytes).unwrap(), 10);
    assert!(bytes[10..].iter().all(|&b| b == 0xcc));
    assert_eq!(volume.read_at(u64::MAX, &mut bytes).unwrap(), 0);
    assert!(volume.read_exact_at(40, &mut [0; 11]).is_err());
    assert!(Volume::new(&mut image, u64::MAX, 1).is_err());
}
