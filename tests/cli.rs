mod support;
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Output},
};
use support::*;

fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inodex"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn info_and_verify_commands_report_real_metadata_and_hashes() {
    let (_dir, path) = write_image(&fixture("ext2.E01"));
    let info = run(&[Path::new("info"), &path]);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let info = String::from_utf8(info.stdout).unwrap();
    assert!(info.contains("Media size: 4194304 bytes"));
    assert!(info.contains("Case: case"));
    let verify = run(&[Path::new("verify"), &path]);
    assert!(verify.status.success());
    let report = String::from_utf8(verify.stdout).unwrap();
    assert!(report.contains("Verified 4194304 bytes"));
    assert!(report.contains("196066add11fb71c4c49cf1bb50d6d24 (matches acquisition digest)"));
}

#[test]
fn export_matches_source_bytes_and_refuses_overwrites() {
    let (dir, path) = write_image(&fixture("ext2.E01"));
    let output = dir.path().join("decoded.raw");
    let result = run(&[Path::new("export"), &path, &output]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut expected = Vec::new();
    flate2::read::GzDecoder::new(&include_bytes!("fixtures/ext2.raw.gz")[..])
        .read_to_end(&mut expected)
        .unwrap();
    assert_eq!(fs::read(&output).unwrap(), expected);
    fs::write(&output, b"preserve existing output").unwrap();
    assert!(!run(&[Path::new("export"), &path, &output]).status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve existing output");
    assert!(!run(&[Path::new("export"), &path, &path]).status.success());
    assert_eq!(fs::read(path).unwrap(), fixture("ext2.E01"));
}

#[test]
fn failed_verification_removes_partial_export_and_returns_failure() {
    for corrupt_hash in [false, true] {
        let mut data = fixture("ext2.E01");
        let offset = section(&data, if corrupt_hash { "hash" } else { "sectors" });
        data[offset + 76] ^= 0x40;
        if corrupt_hash {
            fix_section_payload(&mut data, offset);
        }
        let (dir, path) = write_image(&data);
        assert!(!run(&[Path::new("verify"), &path]).status.success());
        let output = dir.path().join("partial.raw");
        let result = run(&[Path::new("export"), &path, &output]);
        assert!(!result.status.success());
        assert!(!output.exists());
    }
}

#[test]
fn help_and_invalid_commands_have_correct_exit_status() {
    assert!(run(&[Path::new("--help")]).status.success());
    for args in [
        vec![],
        vec![Path::new("unknown")],
        vec![Path::new("info")],
        vec![Path::new("verify"), Path::new("missing.E01")],
    ] {
        assert!(!run(&args).status.success());
    }
}

#[test]
fn unicode_input_and_output_paths_are_supported() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("\u{8a3c}\u{62e0} \u{e9}.E01");
    let output = dir.path().join("\u{539f}\u{672c}.raw");
    fs::write(&image, fixture("libewf-encase6-c2.E01")).unwrap();
    let result = run(&[Path::new("export"), &image, &output]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::metadata(output).unwrap().len(), 131584);
}
