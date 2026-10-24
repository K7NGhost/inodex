use inodex::{
    acquisition::{SnapshotFs, acquire},
    filesystem::{FileSystem, Limits},
    image::Image,
};
use std::{fs, path::Path, process::Command};
#[test]
fn acquired_tree_and_metadata_survive_source_removal() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("nested/日本語.txt"), b"fixed evidence").unwrap();
    fs::write(source.join("empty"), []).unwrap();
    fs::write(source.join("large"), vec![0x7a; 170003]).unwrap();
    let output = root.path().join("copy.inodex");
    let report = acquire(&source, &output, Limits::default()).unwrap();
    assert_eq!(report.files, 3);
    let mut snapshot = SnapshotFs::open(&output, Limits::default()).unwrap();
    assert_eq!(snapshot.verify().unwrap(), 170017);
    // Remove only this test's source; the acquisition must no longer depend on it.
    assert!(
        source
            .canonicalize()
            .unwrap()
            .starts_with(root.path().canonicalize().unwrap())
    );
    fs::remove_dir_all(&source).unwrap();
    let mut image = Image::open(&output).unwrap();
    image.verify().unwrap();
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/nested/日本語.txt").unwrap();
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(data, b"fixed evidence");
    assert!(acquire(root.path(), &output, Limits::default()).is_err());
}
#[test]
fn acquisition_manifest_and_chunk_tampering_are_detected() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), [0x6a; 100000]).unwrap();
    let output = root.path().join("capture.inodex");
    acquire(&source, &output, Limits::default()).unwrap();
    let original = fs::read(&output).unwrap();
    let mut changed = original.clone();
    changed[56] ^= 1;
    fs::write(&output, &changed).unwrap();
    assert!(
        SnapshotFs::open(&output, Limits::default())
            .unwrap()
            .verify()
            .is_err()
    );
    let mut changed = original;
    let end = changed.len() - 1;
    changed[end] ^= 1;
    fs::write(&output, &changed).unwrap();
    assert!(SnapshotFs::open(output, Limits::default()).is_err());
}
#[test]
fn acquisition_cli_round_trip_and_no_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"captured").unwrap();
    let output = root.path().join("capture.inodex");
    let run = |args: &[&Path]| {
        Command::new(env!("CARGO_BIN_EXE_inodex"))
            .args(args)
            .output()
            .unwrap()
    };
    let result = run(&[Path::new("acquire-logical"), &source, &output]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(run(&[Path::new("verify"), &output]).status.success());
    assert!(
        run(&[Path::new("ls"), &output, Path::new("--json")])
            .status
            .success()
    );
    assert!(
        !run(&[Path::new("acquire-logical"), &source, &output])
            .status
            .success()
    );
    let dest = root.path().join("extracted");
    assert!(
        run(&[Path::new("extract"), &output, Path::new("/file"), &dest])
            .status
            .success()
    );
    assert_eq!(fs::read(dest).unwrap(), b"captured");
}

#[test]
fn acquisition_limits_cleanup_and_existing_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("large"), vec![0x6b; 4 * 1024 * 1024]).unwrap();
    let output = dir.path().join("capture.inodex");
    assert!(
        acquire(
            &source,
            &output,
            Limits {
                max_metadata_bytes: 4096,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(!output.exists());
    fs::write(&output, b"existing evidence").unwrap();
    assert!(acquire(&source, &output, Limits::default()).is_err());
    assert_eq!(fs::read(output).unwrap(), b"existing evidence");
    assert!(acquire(&source, source.join("inside.inodex"), Limits::default()).is_err());
    assert!(!source.join("inside.inodex").exists());
}

#[test]
fn acquisition_rejects_cycles_oversized_blobs_and_truncation_even_with_rehashed_manifest() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"data").unwrap();
    let output = dir.path().join("copy.inodex");
    acquire(&source, &output, Limits::default()).unwrap();
    let original = fs::read(&output).unwrap();
    let at = u64::from_le_bytes(original[8..16].try_into().unwrap()) as usize;
    let value: serde_json::Value = serde_json::from_slice(&original[at..]).unwrap();
    for case in 0..3 {
        let mut value = value.clone();
        match case {
            0 => value["entries"][0]["children"][0]["id"] = 1.into(),
            1 => value["entries"][1]["metadata"]["size"] = u64::MAX.into(),
            _ => value["entries"][1]["metadata"]["id"] = 1.into(),
        };
        let manifest = serde_json::to_vec(&value).unwrap();
        let mut changed = original[..at].to_vec();
        changed[16..24].copy_from_slice(&(manifest.len() as u64).to_le_bytes());
        changed[24..56].copy_from_slice(&Sha256::digest(&manifest));
        changed.extend_from_slice(&manifest);
        fs::write(&output, changed).unwrap();
        assert!(SnapshotFs::open(&output, Limits::default()).is_err());
    }
    for length in [0, 55, original.len() - 1] {
        fs::write(&output, &original[..length]).unwrap();
        assert!(SnapshotFs::open(&output, Limits::default()).is_err());
    }
}
