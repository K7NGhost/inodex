mod layers_support;
use inodex::{
    Error,
    filesystem::{FileSystem, FsType, Limits, TimeBasis},
};
use layers_support::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn cluster(c: usize) -> usize {
    (64 + c - 2) * 512
}
fn sum(data: &[u8], bits: u32, skip: &[usize]) -> u32 {
    data.iter()
        .enumerate()
        .filter(|(i, _)| !skip.contains(i))
        .fold(0u32, |s, (_, b)| {
            let rotated = if bits == 16 {
                (s as u16).rotate_right(1) as u32
            } else {
                s.rotate_right(1)
            };
            rotated.wrapping_add(*b as u32) & if bits == 16 { 65535 } else { u32::MAX }
        })
}
fn fix_set(data: &mut [u8], at: usize) {
    let len = (data[at + 1] as usize + 1) * 32;
    let s = sum(&data[at..at + len], 16, &[2, 3]);
    put16(data, at + 2, s as u16);
}
#[track_caller]
fn reject(data: Vec<u8>) {
    assert!(FileSystem::open(&mut Memory::new(data)).is_err());
}

#[test]
fn exfat_tree_unicode_timestamps_and_logical_bytes() {
    let mut image = Memory::new(raw("exfat.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.info().filesystem, FsType::Exfat);
    assert_eq!(fs.info().label, "TESTS");
    assert_eq!(fs.read_dir(0).unwrap().len(), 4);
    let id = fs.resolve("/GRÄßE.TXT").unwrap();
    let metadata = fs.metadata(id).unwrap();
    assert_eq!(metadata.size, 900);
    let t = metadata.times.created.unwrap();
    assert_eq!(t.basis, TimeBasis::Utc);
    assert_eq!(t.seconds, 1_718_447_696);
    assert_eq!(t.nanos, 230_000_000);
    let mut bytes = Vec::new();
    fs.copy_file(id, None, &mut bytes).unwrap();
    let expected: Vec<u8> = (0..900)
        .map(|i| if i < 700 { (i % 251) as u8 } else { 0 })
        .collect();
    assert_eq!(bytes, expected);
    let frag = fs.resolve("/fragmented.bin").unwrap();
    let expected: Vec<u8> = (0..800).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    for start in [0, 1, 500, 511, 512, 799, 800, 900] {
        let mut b = [99; 97];
        let n = fs.read_file(frag, None, start, &mut b).unwrap();
        assert_eq!(
            &b[..n],
            &expected[(start as usize).min(800)..(start as usize).min(800) + n]
        );
    }
    bytes.clear();
    fs.copy_file(frag, None, &mut bytes).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(
        fs.resolve("/subdir/../empty").unwrap(),
        fs.resolve("/empty").unwrap()
    );
    let child = fs.resolve("/subdir/CHILD.TXT").unwrap();
    bytes.clear();
    fs.copy_file(child, None, &mut bytes).unwrap();
    assert_eq!(bytes, b"hello exfat!");
    let empty = fs.resolve("/empty").unwrap();
    assert_eq!(fs.read_file(empty, None, 0, &mut [1; 1]).unwrap(), 0);
    assert!(fs.read_file(empty, Some("ads"), 0, &mut []).is_err());
}

#[test]
fn exfat_independent_tsk_names_sizes_and_initialized_payloads() {
    let oracle: Value =
        serde_json::from_str(include_str!("fixtures/layers/tsk-reference.json")).unwrap();
    let mut image = Memory::new(raw("exfat.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let expected = &oracle["filesystems"]["exfat.raw"]["entries"];
    for path in [
        "/Gräße.txt",
        "/fragmented.bin",
        "/subdir",
        "/empty",
        "/subdir/child.txt",
    ] {
        let entry = expected
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == path)
            .unwrap();
        let id = fs.resolve(path).unwrap();
        let m = fs.metadata(id).unwrap();
        assert_eq!(m.size, entry["size"].as_u64().unwrap());
        if path != "/Gräße.txt" && path != "/subdir" {
            let mut data = vec![];
            fs.copy_file(id, None, &mut data).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&data)),
                entry["streams"][0]["sha256"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn exfat_rejects_boot_upcase_bitmap_and_entry_corruption() {
    for at in [
        3,
        11,
        108,
        510,
        512 + 508,
        11 * 512,
        12 * 512 + 80,
        23 * 512,
        cluster(4) + 42,
        cluster(2) + 96 + 2,
    ] {
        let mut data = raw("exfat.raw");
        data[at] ^= 1;
        reject(data);
    }
    for bit in [0, 1, 2, 4] {
        let mut d = raw("exfat.raw");
        d[cluster(3)] &= !(1 << bit);
        reject(d);
    }
    let at = cluster(2) + 96;
    for (offset, value) in [(40, 901u64), (56, u64::MAX)] {
        let mut d = raw("exfat.raw");
        put64(&mut d, at + offset, value);
        fix_set(&mut d, at);
        reject(d);
    }
    let mut d = raw("exfat.raw");
    d[at + 36] ^= 1;
    fix_set(&mut d, at);
    reject(d);
    let mut d = raw("exfat.raw");
    put32(&mut d, 24 * 512 + 8, 2);
    reject(d);
    let mut d = raw("exfat.raw");
    put32(&mut d, 24 * 512, 0);
    reject(d);
    let mut d = raw("exfat.raw");
    let empty = cluster(2) + 384;
    d[empty + 33] = 3;
    fix_set(&mut d, empty);
    reject(d);
}

#[test]
fn exfat_file_chain_cycle_free_and_outside_heap_fail_on_read() {
    for next in [8, 0, 4034] {
        let mut d = raw("exfat.raw");
        put32(&mut d, 24 * 512 + 8 * 4, next);
        let mut image = Memory::new(d);
        let mut fs = FileSystem::open(&mut image).unwrap();
        let id = fs.resolve("/fragmented.bin").unwrap();
        assert!(fs.copy_file(id, None, &mut vec![]).is_err());
    }
    let mut d = raw("exfat.raw");
    d[cluster(3) + 1] &= !(1 << 1); // cluster 11
    let mut image = Memory::new(d);
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/fragmented.bin").unwrap();
    assert!(fs.copy_file(id, None, &mut vec![]).is_err());
}

#[test]
fn exfat_entry_set_crosses_directory_cluster_boundary() {
    let mut d = raw("exfat.raw");
    let record = d[cluster(2) + 384..cluster(2) + 480].to_vec();
    d[cluster(2) + 384..cluster(2) + 512].fill(0x05);
    d[cluster(2) + 480..cluster(2) + 512].copy_from_slice(&record[..32]);
    d[cluster(12)..cluster(12) + 64].copy_from_slice(&record[32..]);
    put32(&mut d, 24 * 512 + 2 * 4, 12);
    put32(&mut d, 24 * 512 + 12 * 4, 0xffffffff);
    d[cluster(3) + 1] |= 1 << 2;
    let mut image = Memory::new(d);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.read_dir(0).unwrap().len(), 4);
    let empty = fs.resolve("/empty").unwrap();
    assert_eq!(fs.metadata(empty).unwrap().size, 0);
}

#[test]
fn exfat_limits_are_enforced() {
    for limits in [
        Limits {
            max_metadata_bytes: 100,
            ..Limits::default()
        },
        Limits {
            max_directory_bytes: 100,
            ..Limits::default()
        },
        Limits {
            max_chain_length: 1,
            ..Limits::default()
        },
        Limits {
            max_directory_entries: 2,
            ..Limits::default()
        },
    ] {
        let mut image = Memory::new(raw("exfat.raw"));
        assert!(matches!(
            FileSystem::with_limits(&mut image, limits),
            Err(Error::ResourceLimit(_))
        ));
    }
}

#[test]
fn exfat_cli_extract_from_mbr_volume() {
    use std::{fs, process::Command};
    let raw = raw("exfat.raw");
    let mut disk = vec![0; raw.len() + 512];
    disk[512..].copy_from_slice(&raw);
    disk[510..512].copy_from_slice(&[0x55, 0xaa]);
    disk[450] = 7;
    put32(&mut disk, 454, 1);
    put32(&mut disk, 458, (raw.len() / 512) as u32);
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.raw");
    let output = dir.path().join("out");
    fs::write(&image, disk).unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_inodex"))
        .arg("extract")
        .arg(&image)
        .args(["/subdir/child.txt"])
        .arg(&output)
        .args(["--partition", "1"])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(fs::read(&output).unwrap(), b"hello exfat!");
}

#[test]
fn exfat_e01_container_verifies_and_extracts() {
    use inodex::{ewf::EwfImage, image::DiskImage};
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layers/exfat.E01");
    let mut image = EwfImage::open(path).unwrap();
    image.verify().unwrap();
    let mut decoded = vec![0; image.len() as usize];
    image.read_exact_at(0, &mut decoded).unwrap();
    assert_eq!(decoded, raw("exfat.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/fragmented.bin").unwrap();
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(
        data,
        (0..800)
            .map(|i| ((i * 7 + 13) % 256) as u8)
            .collect::<Vec<_>>()
    );
}

#[test]
fn exfat_4k_sectors_and_unknown_or_negative_timezone() {
    let source = raw("exfat.raw");
    let mut d = vec![0; 4096 * 4096];
    d[..512].copy_from_slice(&source[..512]);
    d[108] = 12;
    d[24 * 4096..24 * 4096 + 32 * 512].copy_from_slice(&source[24 * 512..56 * 512]);
    for c in 2..=11 {
        let dest = (64 + c - 2) * 4096;
        d[dest..dest + 512].copy_from_slice(&source[cluster(c)..cluster(c) + 512]);
    }
    put32(&mut d, 24 * 4096 + 4 * 4, 0xffffffff); // upcase now fits one cluster
    put32(&mut d, 24 * 4096 + 8 * 4, 0xffffffff); // file also fits one cluster
    d[(64 + 4 - 2) * 4096 + 512..(64 + 4 - 2) * 4096 + 518]
        .copy_from_slice(&source[cluster(5)..cluster(5) + 6]);
    let root = 64 * 4096;
    let dir = root + 96 + 192;
    put64(&mut d, dir + 40, 4096);
    put64(&mut d, dir + 56, 4096);
    fix_set(&mut d, dir);
    let file = root + 96;
    d[file + 22] = 0;
    d[file + 23] = 0xfc; // unknown creation zone; UTC-01 modified
    fix_set(&mut d, file);
    for i in 1..=8 {
        put32(&mut d, i * 4096 + 4092, 0xaa550000);
    }
    let checksum = sum(&d[..11 * 4096], 32, &[106, 107, 112]);
    for i in 0..1024 {
        put32(&mut d, 11 * 4096 + i * 4, checksum);
    }
    let boot = d[..12 * 4096].to_vec();
    d[12 * 4096..24 * 4096].copy_from_slice(&boot);
    let mut image = Memory::new(d);
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.info().block_size, 4096);
    let id = fs.resolve("/Gräße.txt").unwrap();
    let m = fs.metadata(id).unwrap();
    assert_eq!(m.times.created.unwrap().basis, TimeBasis::LocalCivil);
    assert_eq!(m.times.modified.unwrap().seconds, 1_718_458_496);
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(&data[..512], &source[cluster(6)..cluster(6) + 512]);
    assert!(data[700..].iter().all(|b| *b == 0));
}
