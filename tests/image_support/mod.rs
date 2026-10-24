#![allow(dead_code)]
use flate2::read::GzDecoder;
use inodex::image::DiskImage;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/images")
        .join(format!("{name}.gz"));
    let mut data = vec![];
    GzDecoder::new(fs::File::open(p).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}
pub fn corpus(dir: &Path) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/images");
    unpack_dir(&p, dir);
}
fn unpack_dir(p: &Path, dir: &Path) {
    for e in fs::read_dir(p).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap();
        if p.is_dir() {
            let dest = dir.join(name);
            fs::create_dir_all(&dest).unwrap();
            unpack_dir(&p, &dest);
            continue;
        }
        if let Some(name) = name.strip_suffix(".gz")
            && !name.ends_with(".decoded")
            && !name.contains('/')
        {
            let mut data = vec![];
            GzDecoder::new(fs::File::open(&p).unwrap())
                .read_to_end(&mut data)
                .unwrap();
            fs::write(dir.join(name), data).unwrap();
        }
    }
}
pub fn check_reads(image: &mut dyn DiskImage, expected: &[u8]) {
    assert_eq!(image.len(), expected.len() as u64);
    let mut whole = vec![0; expected.len()];
    image.read_exact_at(0, &mut whole).unwrap();
    assert_eq!(whole, expected);
    let mut seed = 0x483abd124u64;
    for i in 0..120 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let at = if i < 10 {
            [
                0,
                1,
                511,
                512,
                4095,
                4096,
                65535,
                65536,
                expected.len() - 1,
                expected.len(),
            ][i]
        } else {
            seed as usize % (expected.len() + 100)
        };
        let mut out = vec![0xa7; 1027];
        let count = image.read_at(at as u64, &mut out).unwrap();
        let n = expected.len().saturating_sub(at).min(out.len());
        assert_eq!(count, n);
        assert_eq!(
            &out[..n],
            &expected[at.min(expected.len())..at.min(expected.len()) + n]
        );
        assert!(out[n..].iter().all(|b| *b == 0xa7));
    }
    assert_eq!(image.read_at(u64::MAX, &mut [0; 10]).unwrap(), 0);
    assert!(
        image
            .read_exact_at(expected.len() as u64, &mut [0])
            .is_err()
    );
}
pub fn be32(d: &mut [u8], at: usize, n: u32) {
    d[at..at + 4].copy_from_slice(&n.to_be_bytes());
}
pub fn be64(d: &mut [u8], at: usize, n: u64) {
    d[at..at + 8].copy_from_slice(&n.to_be_bytes());
}
pub fn le32(d: &mut [u8], at: usize, n: u32) {
    d[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
pub fn le64(d: &mut [u8], at: usize, n: u64) {
    d[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
pub fn checksum(d: &mut [u8], at: usize) {
    d[at..at + 4].fill(0);
    let sum: u32 = d.iter().map(|b| u32::from(*b)).sum();
    be32(d, at, !sum);
}
pub fn aff_segment(out: &mut Vec<u8>, name: &str, flags: u32, data: &[u8]) {
    out.extend_from_slice(b"AFF\0");
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"ATT\0");
    out.extend_from_slice(&((24 + name.len() + data.len()) as u32).to_be_bytes());
}
pub fn aff_header(size: u64) -> Vec<u8> {
    let mut out = b"AFF10\r\n\0".to_vec();
    aff_segment(&mut out, "pagesize", 4096, &[]);
    aff_segment(&mut out, "sectorsize", 512, &[]);
    let mut quad = (size as u32).to_be_bytes().to_vec();
    quad.extend_from_slice(&((size >> 32) as u32).to_be_bytes());
    aff_segment(&mut out, "imagesize", 2, &quad);
    out
}
pub fn sparse_child(dir: &Path) -> (PathBuf, Vec<u8>) {
    fs::write(dir.join("parent.raw"), vec![0xa5; 12288]).unwrap();
    fs::write(
        dir.join("parent.vmdk"),
        "version=1\nCID=12345678\nparentCID=ffffffff\nRW 24 FLAT \"parent.raw\" 0\n",
    )
    .unwrap();
    let mut sparse = vec![0; 1536 + 4096];
    sparse[..4].copy_from_slice(b"KDMV");
    le32(&mut sparse, 4, 1);
    le32(&mut sparse, 8, 4);
    le64(&mut sparse, 12, 24);
    le64(&mut sparse, 20, 8);
    le32(&mut sparse, 44, 128);
    le64(&mut sparse, 56, 1);
    le32(&mut sparse, 512, 2);
    le32(&mut sparse, 1028, 1);
    le32(&mut sparse, 1032, 3);
    sparse[1536..].fill(0xc3);
    fs::write(dir.join("child-sparse.vmdk"), sparse).unwrap();
    let p = dir.join("child.vmdk");
    fs::write(&p, "version=1\nCID=87654321\nparentCID=12345678\nparentFileNameHint=\"parent.vmdk\"\nRW 24 SPARSE \"child-sparse.vmdk\"\n").unwrap();
    let mut expected = vec![0xa5; 4096];
    expected.extend_from_slice(&[0; 4096]);
    expected.extend_from_slice(&[0xc3; 4096]);
    (p, expected)
}
