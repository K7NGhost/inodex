use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/forensics")
        .join(name)
}
fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inodex"))
        .args(args)
        .output()
        .unwrap()
}
fn good(args: &[&Path]) -> Output {
    let out = run(args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
#[test]
fn security_details_usn_and_logfile_work_through_e01() {
    let image = fixture("ntfs-forensics.E01");
    for command in ["security", "ntfs-details"] {
        let out = good(&[Path::new(command), &image, Path::new("/passwords.txt")]);
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(value.is_object());
    }
    let out = good(&[
        Path::new("usn"),
        &image,
        Path::new("--count"),
        Path::new("1"),
    ]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["records"][0]["name"], "created.txt");
    assert!(report["next_offset"].is_number());
    let out = good(&[Path::new("logfile-info"), &image]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["restart_areas"].as_array().unwrap().len(), 2);
    assert_eq!(report["replay_performed"], false);
}
#[test]
fn deleted_scanning_and_recovery_cli_refuse_reallocated_clusters_and_overwrites() {
    let image = fixture("ntfs-forensics.E01");
    let out = good(&[
        Path::new("deleted"),
        &image,
        Path::new("--start"),
        Path::new("27"),
        Path::new("--count"),
        Path::new("3"),
    ]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 3);
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("recovered");
    good(&[
        Path::new("recover"),
        &image,
        &output,
        Path::new("--id"),
        Path::new("27"),
    ]);
    assert_eq!(fs::read(&output).unwrap(), b"resident deleted evidence");
    assert!(
        !run(&[
            Path::new("recover"),
            &image,
            &output,
            Path::new("--id"),
            Path::new("27")
        ])
        .status
        .success()
    );
    assert_eq!(fs::read(&output).unwrap(), b"resident deleted evidence");
    let refused = dir.path().join("reused");
    assert!(
        !run(&[
            Path::new("recover"),
            &image,
            &refused,
            Path::new("--id"),
            Path::new("29")
        ])
        .status
        .success()
    );
    assert!(!refused.exists());
}
#[test]
fn e01_partition_bitlocker_unlock_extract_and_decrypt_cli() {
    let image = fixture("bitlocker-mbr.E01");
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("fvek.bin");
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/forensics/bitlocker-generated.json")).unwrap();
    let text = manifest["records"]["bitlocker-8004.raw"]["key"]
        .as_str()
        .unwrap();
    let bytes: Vec<_> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    fs::write(&key, bytes).unwrap();
    let file = dir.path().join("report");
    good(&[
        Path::new("extract"),
        &image,
        Path::new("/passwords.txt"),
        &file,
        Path::new("--partition"),
        Path::new("1"),
        Path::new("--bitlocker-fvek-file"),
        &key,
    ]);
    assert_eq!(fs::metadata(&file).unwrap().len(), 116);
    let plain = dir.path().join("decrypted.raw");
    good(&[
        Path::new("decrypt"),
        &image,
        &plain,
        Path::new("--partition"),
        Path::new("1"),
        Path::new("--bitlocker-fvek-file"),
        &key,
    ]);
    use sha2::{Digest, Sha256};
    assert_eq!(
        inodex::ewf::hex(&Sha256::digest(fs::read(&plain).unwrap())),
        manifest["records"]["bitlocker-8004.raw"]["decoded_sha256"]
            .as_str()
            .unwrap()
    );
    fs::write(&key, [0; 32]).unwrap();
    let bad = dir.path().join("bad-output");
    assert!(
        !run(&[
            Path::new("decrypt"),
            &image,
            &bad,
            Path::new("--partition"),
            Path::new("1"),
            Path::new("--bitlocker-fvek-file"),
            &key
        ])
        .status
        .success()
    );
    assert!(!bad.exists());
}
