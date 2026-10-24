mod layers_support;
use inodex::{ewf::EwfImage, image::DiskImage};
use layers_support::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/layers")
        .join(name)
}
#[test]
fn every_added_family_extracts_from_independently_encoded_e01() {
    let reference: Value =
        serde_json::from_str(include_str!("fixtures/layers/tsk-more-reference.json")).unwrap();
    for (name, typ, path) in [
        ("apfs", "apfs", "/passwords.txt"),
        ("hfsplus", "hfs_plus", "/passwords.txt"),
        ("hfsx", "hfs_x", "/passwords.txt"),
        ("ufs1", "ufs1", "/passwords.txt"),
        ("ufs2", "ufs2", "/passwords.txt"),
        ("iso9660", "iso9660", "/PASSWORDS.TXT"),
        ("yaffs2", "yaffs2", "/fragmented.bin"),
    ] {
        let source = fixture(&format!("{name}.E01"));
        let mut image = EwfImage::open(&source).unwrap();
        image.verify().unwrap();
        let mut data = vec![0; image.len() as usize];
        image.read_exact_at(0, &mut data).unwrap();
        assert_eq!(data, raw(&format!("{name}.raw")), "{name}");
        let offset = if name.starts_with("ufs") { 8192 } else { 0 };
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("extracted");
        let info = Command::new(env!("CARGO_BIN_EXE_inodex"))
            .arg("fs-info")
            .arg(&source)
            .args(["--offset", &offset.to_string(), "--json"])
            .output()
            .unwrap();
        assert!(
            info.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&info.stderr)
        );
        let info: Value = serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(info["filesystem"], typ);
        let run = Command::new(env!("CARGO_BIN_EXE_inodex"))
            .arg("extract")
            .arg(&source)
            .arg(path)
            .arg(&output)
            .args(["--offset", &offset.to_string()])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let expected = reference["filesystems"][name]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == path)
            .unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(&output).unwrap())),
            expected["sha256"].as_str().unwrap()
        );
        let run = Command::new(env!("CARGO_BIN_EXE_inodex"))
            .arg("extract")
            .arg(&source)
            .arg(path)
            .arg(&output)
            .args(["--offset", &offset.to_string()])
            .output()
            .unwrap();
        assert!(!run.status.success());
    }
}
#[test]
fn resource_forks_extract_via_cli_and_bad_stream_leaves_no_output() {
    for name in ["apfs", "hfsplus", "hfsx"] {
        let source = fixture(&format!("{name}.E01"));
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("resource");
        let run = Command::new(env!("CARGO_BIN_EXE_inodex"))
            .arg("extract")
            .arg(&source)
            .arg("/a_directory/a_resourcefork")
            .arg(&output)
            .args(["--stream", "com.apple.ResourceFork"])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(fs::read(&output).unwrap().len(), 17);
        let output = temp.path().join("bad");
        let run = Command::new(env!("CARGO_BIN_EXE_inodex"))
            .arg("extract")
            .arg(&source)
            .arg("/passwords.txt")
            .arg(&output)
            .args(["--stream", "missing"])
            .output()
            .unwrap();
        assert!(!run.status.success());
        assert!(!output.exists());
    }
}
#[test]
fn apfs_cli_lists_and_selects_volumes() {
    let source = fixture("apfs.E01");
    let output = Command::new(env!("CARGO_BIN_EXE_inodex"))
        .arg("apfs-volumes")
        .arg(&source)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success());
    let list: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(list[0]["oid"], 1026);
    for (oid, success) in [(1026, true), (99999, false)] {
        let output = Command::new(env!("CARGO_BIN_EXE_inodex"))
            .arg("ls")
            .arg(&source)
            .args(["/", "--json", "--apfs-volume", &oid.to_string()])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
