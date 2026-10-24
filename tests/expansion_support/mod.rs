#![allow(dead_code)]
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/expansion")
}
pub fn fixture(name: &str) -> Vec<u8> {
    let bytes = fs::read(root().join(format!("{name}.gz"))).unwrap();
    let mut data = vec![];
    flate2::read::GzDecoder::new(bytes.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}
pub fn unpack(name: &str, dir: &Path) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, fixture(name)).unwrap();
    path
}
pub fn vhdx_corpus(dir: &Path) {
    for name in [
        "ext2",
        "fat-parent",
        "fat-differential",
        "ntfs-fixed",
        "ntfs-dynamic",
        "ntfs-parent",
        "ntfs-differential",
    ] {
        unpack(&format!("{name}.vhdx"), dir);
    }
}
pub fn crc32c(data: &mut [u8]) {
    data[4..8].fill(0);
    let mut c = !0u32;
    for &b in data.iter() {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = (c >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(c & 1));
        }
    }
    data[4..8].copy_from_slice(&(!c).to_le_bytes());
}
pub fn apfs_crc(data: &mut [u8], block: usize) {
    let s = &mut data[block * 4096..(block + 1) * 4096];
    let m = 0xffff_ffff;
    let (mut a, mut b) = (0u64, 0u64);
    for w in s[8..].as_chunks::<4>().0 {
        a = (a + u64::from(u32::from_le_bytes(*w))) % m;
        b = (b + a) % m;
    }
    let lo = m - (a + b) % m;
    let hi = m - (a + lo) % m;
    s[..8].copy_from_slice(&(lo | hi << 32).to_le_bytes());
}
