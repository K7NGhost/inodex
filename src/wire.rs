//! Checked little-endian wire reads shared by partition and filesystem parsers.
use crate::{Error, Result};

pub(crate) fn corrupt(layer: &'static str, offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        layer,
        offset,
        reason: reason.into(),
    }
}
pub(crate) fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| corrupt("record", offset as u64, "field size overflow"))?;
    data.get(offset..end)
        .ok_or_else(|| corrupt("record", offset as u64, "truncated field"))
}
pub(crate) fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}
pub(crate) fn u32le(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}
pub(crate) fn u64le(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(data, offset, 8)?.try_into().unwrap(),
    ))
}
pub(crate) fn u16be(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}
pub(crate) fn u32be(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}
pub(crate) fn u64be(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes(data, offset, 8)?.try_into().unwrap(),
    ))
}
pub(crate) fn utf16(data: &[u8]) -> Result<String> {
    if !data.len().is_multiple_of(2) {
        return Err(corrupt("UTF-16", 0, "odd byte count"));
    }
    let units: Vec<_> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    String::from_utf16(&units).map_err(|_| corrupt("UTF-16", 0, "invalid surrogate sequence"))
}
pub(crate) fn checked_region(
    offset: u64,
    length: u64,
    limit: u64,
    layer: &'static str,
) -> Result<()> {
    if offset.checked_add(length).is_none_or(|end| end > limit) {
        return Err(corrupt(
            layer,
            offset,
            "region exceeds its containing image",
        ));
    }
    Ok(())
}
