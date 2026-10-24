mod layers_support;
use layers_support::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/layers")
        .join(name)
}
fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inodex"))
        .args(args)
        .output()
        .unwrap()
}
fn json(args: &[&Path]) -> Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn discover_list_and_stat_ntfs_inside_a_partitioned_e01() {
    let image = fixture("ntfs-gpt.E01");
    let table = json(&[Path::new("partitions"), &image, Path::new("--json")]);
    assert_eq!(table["scheme"], "gpt");
    assert_eq!(table["partitions"][0]["index"], 3);
    let info = json(&[
        Path::new("fs-info"),
        &image,
        Path::new("--partition"),
        Path::new("3"),
        Path::new("--json"),
    ]);
    assert_eq!(info["filesystem"], "ntfs");
    let entries = json(&[
        Path::new("ls"),
        &image,
        Path::new("/a_directory"),
        Path::new("--partition"),
        Path::new("3"),
        Path::new("--json"),
    ]);
    assert_eq!(entries.as_array().unwrap().len(), 2);
    assert_eq!(entries[0]["name"], "a_file");
    let stat = json(&[
        Path::new("stat"),
        &image,
        Path::new("/passwords.txt"),
        Path::new("--partition"),
        Path::new("3"),
        Path::new("--json"),
    ]);
    assert_eq!(stat["size"], 116);
    assert_eq!(stat["times"]["modified"]["basis"], "utc");
}

#[test]
fn extract_by_partition_or_explicit_byte_offset_and_refuse_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let image = fixture("ntfs-mbr.E01");
    for offset_mode in [false, true] {
        let output = dir.path().join(if offset_mode {
            "offset.txt"
        } else {
            "partition.txt"
        });
        let selector = Path::new(if offset_mode {
            "--offset"
        } else {
            "--partition"
        });
        let value = Path::new(if offset_mode { "1048576" } else { "1" });
        let result = run(&[
            Path::new("extract"),
            &image,
            Path::new("/passwords.txt"),
            &output,
            selector,
            value,
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            inodex::ewf::hex(&Sha256::digest(fs::read(&output).unwrap())),
            "02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252"
        );
        fs::write(&output, b"keep this").unwrap();
        assert!(
            !run(&[
                Path::new("extract"),
                &image,
                Path::new("/passwords.txt"),
                &output,
                selector,
                value
            ])
            .status
            .success()
        );
        assert_eq!(fs::read(output).unwrap(), b"keep this");
    }
}

#[test]
fn named_stream_extraction_and_unicode_host_paths() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("証拠.E01");
    fs::copy(fixture("ntfs-mbr.E01"), &image).unwrap();
    let output = dir.path().join("結果.bin");
    let result = run(&[
        Path::new("extract"),
        &image,
        Path::new("/$UpCase"),
        &output,
        Path::new("--partition"),
        Path::new("1"),
        Path::new("--stream"),
        Path::new("$Info"),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::metadata(&output).unwrap().len(), 32);
    assert_eq!(
        inodex::ewf::hex(&Sha256::digest(fs::read(output).unwrap())),
        "ee502838f53f00c9444b311f4cdea74454a1e0c64e8cdec3d63eb5232fb61f82"
    );
}

#[test]
fn failed_extraction_removes_partial_output() {
    let dir = tempfile::tempdir().unwrap();
    let image = fixture("ntfs-mbr.E01");
    for (path, stream) in [("/", ""), ("/passwords.txt", "absent-stream")] {
        let output = dir.path().join("partial.bin");
        assert!(
            !run(&[
                Path::new("extract"),
                &image,
                Path::new(path),
                &output,
                Path::new("--partition"),
                Path::new("1"),
                Path::new("--stream"),
                Path::new(stream)
            ])
            .status
            .success()
        );
        assert!(!output.exists());
    }
}

#[test]
fn raw_fat_and_ext_cli_paths_use_the_same_interface() {
    let dir = tempfile::tempdir().unwrap();
    for (name, kind) in [
        ("fat12.raw", "fat12"),
        ("fat16.raw", "fat16"),
        ("fat32.raw", "fat32"),
        ("ext4.raw", "ext4"),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, raw(name)).unwrap();
        let info = json(&[Path::new("fs-info"), &path, Path::new("--json")]);
        assert_eq!(info["filesystem"], kind);
        let entries = json(&[Path::new("ls"), &path, Path::new("--json")]);
        assert!(!entries.as_array().unwrap().is_empty());
    }
}

#[test]
fn selectors_and_option_errors_fail_without_writing_files() {
    let image = fixture("ntfs-gpt.E01");
    for tail in [
        vec!["--partition", "99"],
        vec!["--partition", "3", "--offset", "0"],
        vec!["--offset", "18446744073709551615"],
        vec!["--sector-size", "4096"],
        vec!["--unknown", "1"],
    ] {
        let mut arguments = vec![Path::new("fs-info"), &image];
        arguments.extend(tail.iter().map(Path::new));
        assert!(!run(&arguments).status.success());
    }
}
