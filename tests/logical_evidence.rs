mod expansion_support;
use expansion_support::*;
use inodex::{
    filesystem::{FileKind, FileSystem, FsType, Limits, lef::LogicalEvidenceFs},
    image::{DiskImage, Image},
};
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
#[test]
fn public_l01_every_entry_and_content_matches_libewf() {
    let reference: serde_json::Value =
        serde_json::from_slice(&fixture("l01-reference.json")).unwrap();
    let rows = reference.as_array().unwrap();
    assert_eq!(rows.len(), 9952);
    let path = root().join("tracy-phone.L01");
    let mut evidence = LogicalEvidenceFs::open(path, Limits::default()).unwrap();
    assert_eq!(evidence.info().filesystem, FsType::LogicalEvidence);
    for (id, row) in rows.iter().enumerate() {
        let meta = evidence.metadata(id as u64).unwrap();
        let fields = evidence.entry_fields(id as u64).unwrap();
        assert!(fields.contains_key("mid"));
        let stream = if meta.kind == FileKind::Directory {
            assert_eq!(
                evidence.read_dir(id as u64).unwrap().len() as u64,
                row["children"].as_u64().unwrap()
            );
            if row["size"] == 0 {
                continue;
            }
            Some("L01.data")
        } else {
            assert_eq!(meta.size, row["size"].as_u64().unwrap());
            None
        };
        let mut at = 0;
        let mut hash = Sha256::new();
        let mut buffer = [0; 32771];
        loop {
            let n = evidence
                .read_file(id as u64, stream, at, &mut buffer)
                .unwrap();
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
            at += n as u64;
        }
        assert_eq!(at, row["size"].as_u64().unwrap(), "id {id}");
        assert_eq!(
            format!("{:x}", hash.finalize()),
            row["sha256"].as_str().unwrap(),
            "id {id}"
        );
    }
    evidence.verify().unwrap();
}
#[test]
fn l01_auto_detection_path_resolution_cli_and_random_reads() {
    let path = root().join("tracy-phone.L01");
    let mut image = Image::open(&path).unwrap();
    assert_eq!(image.kind(), "L01 logical evidence");
    assert_eq!(image.len(), 0);
    assert!(image.export_to(&mut vec![]).is_err());
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/Phone Information/Device").unwrap();
    let mut all = vec![];
    fs.copy_file(id, None, &mut all).unwrap();
    assert_eq!(all.len(), 306);
    for at in [0, 1, 17, 300, 306, 900] {
        let mut b = [0; 23];
        let n = fs.read_file(id, None, at, &mut b).unwrap();
        let at = (at as usize).min(all.len());
        assert_eq!(&b[..n], &all[at..at + n]);
    }
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("device.bin");
    let result = Command::new(env!("CARGO_BIN_EXE_inodex"))
        .args([
            "extract",
            path.to_str().unwrap(),
            "/Phone Information/Device",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output).unwrap(), all);
    let result = Command::new(env!("CARGO_BIN_EXE_inodex"))
        .args(["partitions", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(!result.status.success());
}
#[test]
fn l01_tree_integrity_chunk_corruption_truncation_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.L01");
    let original = fs::read(root().join("tracy-phone.L01")).unwrap();
    for at in [0, 2404690 + 76 + 16, 2404690 + 76 + 24, 2404690 + 76 + 49] {
        let mut d = original.clone();
        d[at] ^= 1;
        fs::write(&path, d).unwrap();
        assert!(Image::open(&path).is_err());
    }
    for cut in [12, 2404690, original.len() - 1] {
        fs::write(&path, &original[..cut]).unwrap();
        assert!(Image::open(&path).is_err());
    }
    let mut d = original;
    d[2000] ^= 1;
    fs::write(&path, d).unwrap();
    let mut image = Image::open(&path).unwrap();
    assert!(image.verify().is_err());
    assert!(
        LogicalEvidenceFs::open(
            root().join("tracy-phone.L01"),
            Limits {
                max_directory_entries: 10,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn split_l01_multiextent_duplicate_fill_and_missing_members() {
    for prefix in ["logical-split", "logical-multi"] {
        let path = root().join(format!("{prefix}.L01"));
        let expected: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root().join(format!("{prefix}-source.json"))).unwrap(),
        )
        .unwrap();
        let mut image = Image::open(&path).unwrap();
        let report = image.verify().unwrap();
        assert_eq!(report.bytes_read, 66048);
        assert!(report.md5_verified);
        let mut fs = FileSystem::open(&mut image).unwrap();
        for (name, row) in expected.as_object().unwrap() {
            let id = fs.resolve(&format!("/{name}")).unwrap();
            let meta = fs.metadata(id).unwrap();
            assert_eq!(meta.times.modified.unwrap().seconds, 1600000002);
            let mut content = vec![];
            fs.copy_file(id, None, &mut content).unwrap();
            assert_eq!(content.len() as u64, row["size"].as_u64().unwrap());
            assert_eq!(
                format!("{:x}", Sha256::digest(content)),
                row["sha256"].as_str().unwrap()
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join(format!("{prefix}.L01"));
        std::fs::copy(path, &missing).unwrap();
        assert!(matches!(
            Image::open(&missing),
            Err(inodex::Error::MissingSegment { number: 2, .. })
        ));
    }
}
