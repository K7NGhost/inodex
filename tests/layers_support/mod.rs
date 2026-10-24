#![allow(dead_code)]
use inodex::{Result, image::DiskImage};
use std::{fs, io::Read, path::PathBuf};

pub fn raw(name: &str) -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = if name == "ext2.raw" {
        root.join("ext2.raw.gz")
    } else {
        root.join("layers").join(format!("{name}.gz"))
    };
    let data = fs::read(path).unwrap();
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(data.as_slice())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}
pub struct Memory {
    pub data: Vec<u8>,
    pub sector_size: u32,
}
impl Memory {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            sector_size: 512,
        }
    }
}
impl DiskImage for Memory {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let count = self.len().saturating_sub(offset).min(buffer.len() as u64) as usize;
        if count > 0 {
            buffer[..count].copy_from_slice(&self.data[offset as usize..offset as usize + count]);
        }
        Ok(count)
    }
}
pub fn u16at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}
pub fn u32at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
pub fn u64at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
pub fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub fn fix_header(data: &mut [u8], offset: usize) {
    let size = u32at(data, offset + 12) as usize;
    put32(data, offset + 16, 0);
    put32(
        data,
        offset + 16,
        crc32fast::hash(&data[offset..offset + size]),
    );
}
pub fn fix_gpt(data: &mut [u8]) {
    let backup = (data.len() / 512 - 1) * 512;
    let count = u32at(data, 512 + 80) as usize;
    let size = u32at(data, 512 + 84) as usize;
    let first = u64at(data, 512 + 72) as usize * 512;
    let second = u64at(data, backup + 72) as usize * 512;
    let entries = data[first..first + count * size].to_vec();
    data[second..second + entries.len()].copy_from_slice(&entries);
    let crc = crc32fast::hash(&entries);
    put32(data, 512 + 88, crc);
    put32(data, backup + 88, crc);
    fix_header(data, 512);
    fix_header(data, backup);
}
