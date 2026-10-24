#![allow(dead_code)]
use flate2::{Compression, write::ZlibEncoder};
use std::{fs, io::Write, path::PathBuf};

pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

pub fn write_image(data: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.E01");
    fs::write(&path, data).unwrap();
    (dir, path)
}

pub fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
pub fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
pub fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub fn fix_checksum(data: &mut [u8]) {
    let split = data.len() - 4;
    put32(data, split, adler2::adler32_slice(&data[..split]));
}

pub fn section(data: &[u8], kind: &str) -> usize {
    let mut offset = 13;
    loop {
        let name = data[offset..offset + 16].split(|&b| b == 0).next().unwrap();
        if name == kind.as_bytes() {
            return offset;
        }
        let next = u64_at(data, offset + 16) as usize;
        assert_ne!(next, offset, "section {kind} not found");
        offset = next;
    }
}

pub fn fix_section_payload(data: &mut [u8], offset: usize) {
    let end = u64_at(data, offset + 16) as usize;
    fix_checksum(&mut data[offset + 76..end]);
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Purpose-built wire fixtures for edge cases absent from the external corpus.
/// Each group has a sectors section followed by primary and backup tables.
pub struct Builder {
    pub bytes_per_sector: u32,
    pub sectors_per_chunk: u32,
    pub chunks: Vec<Vec<u8>>,
    pub compressed: bool,
    pub pad_final: bool,
    pub extras: Vec<(&'static str, Vec<u8>)>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            bytes_per_sector: 512,
            sectors_per_chunk: 2,
            chunks: vec![vec![0x45; 1024], vec![0x92; 512]],
            compressed: true,
            pad_final: false,
            extras: Vec::new(),
        }
    }
}

fn add_section(image: &mut Vec<u8>, kind: &str, data: &[u8]) -> usize {
    let offset = image.len();
    let mut descriptor = vec![0; 76];
    descriptor[..kind.len()].copy_from_slice(kind.as_bytes());
    put64(&mut descriptor, 16, (offset + 76 + data.len()) as u64);
    put64(&mut descriptor, 24, (76 + data.len()) as u64);
    fix_checksum(&mut descriptor);
    image.extend(descriptor);
    image.extend(data);
    offset
}

impl Builder {
    pub fn build(&self) -> (Vec<u8>, Vec<u8>) {
        let mut image = b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00".to_vec();
        let raw: Vec<u8> = self.chunks.iter().flatten().copied().collect();
        let mut volume = vec![0; 1052];
        volume[0] = 1;
        put32(&mut volume, 4, self.chunks.len() as u32);
        put32(&mut volume, 8, self.sectors_per_chunk);
        put32(&mut volume, 12, self.bytes_per_sector);
        put64(
            &mut volume,
            16,
            raw.len() as u64 / u64::from(self.bytes_per_sector),
        );
        fix_checksum(&mut volume);
        add_section(&mut image, "volume", &volume);
        for (index, chunk) in self.chunks.iter().enumerate() {
            let base = image.len();
            let mut payload = chunk.clone();
            if self.pad_final && index + 1 == self.chunks.len() {
                payload.resize((self.bytes_per_sector * self.sectors_per_chunk) as usize, 0);
            }
            if self.compressed {
                payload = deflate(&payload);
            } else {
                payload.extend([0; 4]);
                fix_checksum(&mut payload);
            }
            add_section(&mut image, "sectors", &payload);
            let mut table = vec![0; 32];
            put32(&mut table, 0, 1);
            put64(&mut table, 8, base as u64);
            fix_checksum(&mut table[..24]);
            put32(
                &mut table,
                24,
                76 | if self.compressed { 0x8000_0000 } else { 0 },
            );
            fix_checksum(&mut table[24..]);
            add_section(&mut image, "table", &table);
            add_section(&mut image, "table2", &table);
        }
        for (kind, payload) in &self.extras {
            add_section(&mut image, kind, payload);
        }
        let offset = add_section(&mut image, "done", &[]);
        put64(&mut image, offset + 16, offset as u64);
        put64(&mut image, offset + 24, 0);
        fix_checksum(&mut image[offset..]);
        (image, raw)
    }
}
