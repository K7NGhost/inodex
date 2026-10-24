mod expansion_support;
use expansion_support::*;
use inodex::{
    filesystem::FileSystem,
    image::{DiskImage, Image, Limits, VhdxImage, Volume},
    partition::PartitionTable,
};
use std::fs;
#[test]
fn independent_fixed_dynamic_and_differencing_bytes_and_filesystems() {
    let dir = tempfile::tempdir().unwrap();
    vhdx_corpus(dir.path());
    for name in [
        "ext2",
        "fat-parent",
        "fat-differential",
        "ntfs-fixed",
        "ntfs-dynamic",
        "ntfs-parent",
        "ntfs-differential",
    ] {
        let golden = fixture(&format!("{name}-decoded.raw"));
        let mut image = Image::open(dir.path().join(format!("{name}.vhdx"))).unwrap();
        assert_eq!(image.kind(), "VHDX");
        assert_eq!(image.len(), golden.len() as u64);
        let mut decoded = vec![];
        image.export_to(&mut decoded).unwrap();
        assert_eq!(decoded, golden, "{name}");
        for offset in [0, 511, 4095, 1048573, golden.len() - 37] {
            let mut buffer = vec![0; 10003];
            let count = image.read_at(offset as u64, &mut buffer).unwrap();
            assert_eq!(&buffer[..count], &golden[offset..offset + count]);
        }
        assert_eq!(image.read_at(u64::MAX, &mut [0; 5]).unwrap(), 0);
        let table = PartitionTable::read(&mut image).unwrap();
        let mut volume = if let Some(table) = table {
            table.get(1).unwrap().volume(&mut image).unwrap()
        } else {
            let len = image.len();
            Volume::new(&mut image, 0, len).unwrap()
        };
        let mut fs = FileSystem::open(&mut volume).unwrap();
        if name.ends_with("-parent") {
            assert!(fs.resolve("/passwords.txt").is_err());
            let root = fs.info().root_id;
            assert!(!fs.read_dir(root).unwrap().is_empty());
            continue;
        }
        let id = fs.resolve("/passwords.txt").unwrap();
        let meta = fs.metadata(id).unwrap();
        let mut bytes = vec![];
        assert_eq!(fs.copy_file(id, None, &mut bytes).unwrap(), meta.size);
        assert!(!bytes.is_empty());
    }
}
#[test]
fn redundant_headers_regions_crc_log_and_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk.vhdx");
    let original = fixture("ntfs-fixed.vhdx");
    for at in [65536, 131072, 196608, 262144] {
        let mut d = original.clone();
        d[at + 4] ^= 1;
        fs::write(&path, &d).unwrap();
        VhdxImage::open(&path).unwrap();
    }
    for pair in [[65536, 131072], [196608, 262144]] {
        let mut d = original.clone();
        for at in pair {
            d[at + 4] ^= 1;
        }
        fs::write(&path, d).unwrap();
        assert!(VhdxImage::open(&path).is_err());
    }
    for cut in [0, 7, 65536, 200000, original.len() - 1] {
        fs::write(&path, &original[..cut]).unwrap();
        assert!(VhdxImage::open(&path).is_err());
    }
    let mut d = original.clone();
    for at in [65536, 131072] {
        d[at + 48] = 1;
        crc32c(&mut d[at..at + 4096]);
    }
    fs::write(&path, d).unwrap();
    assert!(matches!(
        VhdxImage::open(&path),
        Err(inodex::Error::Unsupported(_))
    ));
    assert!(
        VhdxImage::with_limits(
            unpack("ntfs-fixed.vhdx", dir.path()),
            Limits {
                max_metadata_bytes: 32,
                ..Limits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn parents_missing_wrong_identity_cycles_and_explicit_selection() {
    let dir = tempfile::tempdir().unwrap();
    let child = unpack("ntfs-differential.vhdx", dir.path());
    assert!(VhdxImage::open(&child).is_err());
    let correct = unpack("ntfs-parent.vhdx", dir.path());
    fs::rename(&correct, dir.path().join("relocated.vhdx")).unwrap();
    let parent = dir.path().join("relocated.vhdx");
    let mut image = VhdxImage::with_parent(&child, &parent).unwrap();
    let mut bytes = vec![0; 4096];
    image.read_exact_at(0, &mut bytes).unwrap();
    assert_eq!(
        &bytes[..],
        &fixture("ntfs-differential-decoded.raw")[..4096]
    );
    assert!(VhdxImage::with_parent(&child, &child).is_err());
    let wrong = unpack("fat-parent.vhdx", dir.path());
    assert!(VhdxImage::with_parent(&child, wrong).is_err());
    let mut d = fs::read(&child).unwrap();
    let at = d
        .windows(26)
        .position(|s| {
            s == "relative_path"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        })
        .unwrap()
        + 26;
    // Same-length traversal path, without changing metadata lengths.
    d[at..at + 6].copy_from_slice(
        &['.' as u16, '.' as u16, '\\' as u16]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    fs::write(&child, d).unwrap();
    assert!(VhdxImage::open(&child).is_err());
}
