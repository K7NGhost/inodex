mod image_support;
use image_support::*;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inodex"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn image_info_verify_export_and_extract_across_container_families() {
    let dir = tempfile::tempdir().unwrap();
    corpus(dir.path());
    for name in [
        "ext2.splitraw.000",
        "ext2.vhd",
        "ext2.vmdk",
        "streamOptimized.vmdk",
        "native.aff",
        "multi.afd",
        "native.afm",
    ] {
        let path = dir.path().join(name);
        for command in ["info", "verify"] {
            let r = run(&[Path::new(command), &path]);
            assert!(
                r.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&r.stderr)
            );
        }
        let dest = dir.path().join(format!("{name}.raw"));
        let r = run(&[Path::new("export"), &path, &dest]);
        assert!(
            r.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        let expected = if name == "ext2.vhd" {
            fixture("ext2.vhd.decoded")
        } else {
            fixture("ext2.vmdk.decoded")
        };
        assert_eq!(fs::read(&dest).unwrap(), expected);
        fs::write(&dest, b"existing output").unwrap();
        assert!(!run(&[Path::new("export"), &path, &dest]).status.success());
        assert_eq!(fs::read(&dest).unwrap(), b"existing output");
        let file = dir.path().join(format!("{name}.file"));
        let r = run(&[
            Path::new("extract"),
            &path,
            Path::new("/passwords.txt"),
            &file,
        ]);
        assert!(
            r.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert_eq!(fs::metadata(file).unwrap().len(), 116);
    }
}
#[test]
fn failed_digest_export_removes_partial_output_and_preserves_input() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.aff");
    let out = dir.path().join("partial.raw");
    let mut bytes = aff_header(8192);
    aff_segment(&mut bytes, "page0", 0, &[0x23; 4096]);
    aff_segment(&mut bytes, "md5", 0, &[0; 16]);
    fs::write(&p, &bytes).unwrap();
    let result = run(&[Path::new("export"), &p, &out]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("digest"));
    assert!(!out.exists());
    assert_eq!(fs::read(p).unwrap(), bytes);
}
#[test]
fn partitioned_vmdk_and_split_raw_reach_existing_ntfs_parser() {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layers/ntfs-gpt.raw.gz");
    let mut raw = vec![];
    GzDecoder::new(fs::File::open(source).unwrap())
        .read_to_end(&mut raw)
        .unwrap();
    fs::write(dir.path().join("gpt.raw"), &raw).unwrap();
    let vmdk = dir.path().join("gpt.vmdk");
    fs::write(
        &vmdk,
        format!("version=1\nRW {} FLAT \"gpt.raw\" 0\n", raw.len() / 512),
    )
    .unwrap();
    let split = dir.path().join("gpt.001");
    fs::write(&split, &raw[..2000001]).unwrap();
    fs::write(dir.path().join("gpt.002"), &raw[2000001..]).unwrap();
    for path in [&vmdk, &split] {
        let output = dir.path().join(format!(
            "{}.file",
            path.file_name().unwrap().to_str().unwrap()
        ));
        let result = run(&[
            Path::new("extract"),
            path,
            Path::new("/passwords.txt"),
            &output,
            Path::new("--partition"),
            Path::new("3"),
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::metadata(output).unwrap().len(), 116);
    }
}
