use inodex::{
    filesystem::{FileKind, FileSystem, FsType, Limits, logical::LogicalFs},
    image::{DiskImage, Image, Volume},
};
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
fn tree(root: &Path) {
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/日本語.txt"), b"logical evidence\0payload").unwrap();
    fs::write(root.join("empty"), []).unwrap();
    fs::write(
        root.join("large.bin"),
        (0..200000).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    )
    .unwrap();
}
#[test]
fn logical_directory_metadata_unicode_nested_files_and_random_reads() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let mut image = Image::open(dir.path()).unwrap();
    assert!(image.logical_root().is_some());
    assert!(image.read_at(0, &mut [0]).is_err());
    assert!(image.verify().is_err());
    assert!(image.export_to(&mut vec![]).is_err());
    assert!(Volume::new(&mut image, 1, 0).is_err());
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.info().filesystem, FsType::Logical);
    let root = fs.info().root_id;
    assert_eq!(fs.read_dir(root).unwrap().len(), 3);
    let id = fs.resolve("/nested/日本語.txt").unwrap();
    let meta = fs.metadata(id).unwrap();
    assert_eq!(meta.kind, FileKind::File);
    assert_eq!(meta.size, 24);
    let mut out = vec![];
    fs.copy_file(id, None, &mut out).unwrap();
    assert_eq!(out, b"logical evidence\0payload");
    let id = fs.resolve("/large.bin").unwrap();
    let mut b = [0; 1027];
    for at in [0, 1, 511, 65535, 199999, 200000, u64::MAX] {
        let n = fs.read_file(id, None, at, &mut b).unwrap();
        assert_eq!(n, 200000u64.saturating_sub(at).min(1027) as usize);
        for (i, v) in b[..n].iter().enumerate() {
            assert_eq!(*v, ((at + i as u64) % 251) as u8);
        }
    }
    assert!(fs.read_file(id, Some("ads"), 0, &mut b).is_err());
    assert!(fs.read_dir(id).is_err());
    assert!(fs.resolve("/absent").is_err());
}

#[test]
fn logical_detects_files_modified_after_indexing() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let mut image = Image::open(dir.path()).unwrap();
    let mut logical = FileSystem::open(&mut image).unwrap();
    let id = logical.resolve("/empty").unwrap();
    fs::write(dir.path().join("empty"), b"changed").unwrap();
    assert!(logical.read_file(id, None, 0, &mut [0; 16]).is_err());
}

#[test]
fn logical_limits_bound_metadata_entries_and_depth() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    for limits in [
        Limits {
            max_metadata_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_directory_entries: 1,
            ..Limits::default()
        },
        Limits {
            max_tree_depth: 0,
            ..Limits::default()
        },
    ] {
        assert!(LogicalFs::open(dir.path(), limits).is_err());
    }
    let empty = tempfile::tempdir().unwrap();
    assert!(
        LogicalFs::open(
            empty.path(),
            Limits {
                max_directory_entries: 0,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn logical_cli_lists_stats_extracts_and_protects_evidence() {
    let evidence = tempfile::tempdir().unwrap();
    tree(evidence.path());
    let output = tempfile::tempdir().unwrap();
    for command in ["fs-info", "ls", "stat"] {
        let out = if command == "stat" {
            run(&[Path::new(command), evidence.path(), Path::new("/empty")])
        } else {
            run(&[Path::new(command), evidence.path(), Path::new("--json")])
        };
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
    }
    let dest = output.path().join("result");
    let out = run(&[
        Path::new("extract"),
        evidence.path(),
        Path::new("/nested/日本語.txt"),
        &dest,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&dest).unwrap(), b"logical evidence\0payload");
    assert!(
        !run(&[
            Path::new("extract"),
            evidence.path(),
            Path::new("/empty"),
            &dest
        ])
        .status
        .success()
    );
    let inside = evidence.path().join("new-output");
    assert!(
        !run(&[
            Path::new("extract"),
            evidence.path(),
            Path::new("/empty"),
            &inside
        ])
        .status
        .success()
    );
    assert!(!inside.exists());
    for command in ["partitions", "verify", "apfs-volumes"] {
        assert!(!run(&[Path::new(command), evidence.path()]).status.success());
    }
    assert!(
        !run(&[
            Path::new("ls"),
            evidence.path(),
            Path::new("--offset"),
            Path::new("1")
        ])
        .status
        .success()
    );
    assert!(
        !run(&[Path::new("export"), evidence.path(), &inside])
            .status
            .success()
    );
    assert!(!inside.exists());
}

#[test]
fn extraction_with_a_bare_relative_output_filename_works() {
    let evidence = tempfile::tempdir().unwrap();
    tree(evidence.path());
    let output = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_inodex"))
        .current_dir(output.path())
        .arg("extract")
        .arg(evidence.path())
        .arg("/empty")
        .arg("copy")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output.path().join("copy")).unwrap(), b"");
}

#[cfg(unix)]
#[test]
fn logical_symlinks_are_recorded_without_following_and_replaced_files_are_rejected() {
    use std::os::unix::fs::symlink;
    let evidence = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"outside").unwrap();
    symlink(outside.path(), evidence.path().join("link")).unwrap();
    fs::write(evidence.path().join("replace"), b"inside").unwrap();
    let mut image = Image::open(evidence.path()).unwrap();
    let mut logical = FileSystem::open(&mut image).unwrap();
    let link = logical.resolve("/link").unwrap();
    assert_eq!(logical.metadata(link).unwrap().kind, FileKind::Symlink);
    assert!(logical.resolve("/link/secret").is_err());
    let replace = logical.resolve("/replace").unwrap();
    fs::remove_file(evidence.path().join("replace")).unwrap();
    symlink(
        outside.path().join("secret"),
        evidence.path().join("replace"),
    )
    .unwrap();
    assert!(logical.read_file(replace, None, 0, &mut [0; 6]).is_err());
}

#[cfg(windows)]
#[test]
fn logical_windows_junctions_are_recorded_without_recursion() {
    let evidence = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"outside").unwrap();
    let junction = evidence.path().join("link");
    let result = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(outside.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut image = Image::open(evidence.path()).unwrap();
    let mut logical = FileSystem::open(&mut image).unwrap();
    let id = logical.resolve("/link").unwrap();
    assert_ne!(logical.metadata(id).unwrap().kind, FileKind::Directory);
    assert!(logical.resolve("/link/secret").is_err());
    fs::remove_dir(junction).unwrap();
    assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"outside");
}
