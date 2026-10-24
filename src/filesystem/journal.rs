//! Read-only USN records; journal entries describe changes, not reconstructed files.
use super::{TimeBasis, Timestamp};
use crate::{Error, Result, wire::*};
use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
pub struct UsnExtent {
    pub offset: i64,
    pub length: i64,
}
#[derive(Debug, Clone, Serialize)]
pub struct UsnRecord {
    pub offset: u64,
    pub length: u32,
    pub major: u16,
    pub minor: u16,
    pub file_reference: String,
    pub parent_reference: String,
    pub usn: i64,
    pub timestamp: Option<Timestamp>,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: Option<u32>,
    pub file_attributes: Option<u32>,
    pub name: Option<String>,
    pub remaining_extents: Option<u32>,
    pub extents: Vec<UsnExtent>,
}
#[derive(Debug, Serialize)]
pub struct UsnScan {
    pub records: Vec<UsnRecord>,
    pub next_offset: Option<u64>,
    pub bytes_scanned: u64,
    pub journal_id: Option<u64>,
    pub lowest_valid_usn: Option<i64>,
}
#[derive(Debug, Serialize)]
pub struct RestartArea {
    pub page_offset: u64,
    pub major: u16,
    pub minor: u16,
    pub system_page_size: u32,
    pub log_page_size: u32,
    pub current_lsn: u64,
    pub flags: u16,
    pub clean_shutdown: bool,
    pub log_clients: u16,
    pub file_size: u64,
    pub record_header_size: u16,
    pub log_page_data_offset: u16,
}
#[derive(Debug, Serialize)]
pub struct LogFileInfo {
    pub restart_areas: Vec<RestartArea>,
    pub initialized: bool,
    pub issues: Vec<String>,
    pub replay_performed: bool,
}
pub fn parse_record(data: &[u8], offset: u64) -> Result<UsnRecord> {
    let length = u32le(data, 0)?;
    if length < 8 || !length.is_multiple_of(8) {
        return Err(corrupt("USN", offset, "invalid record length/alignment"));
    }
    let data = bytes(data, 0, length as usize)?;
    let major = u16le(data, 4)?;
    let minor = u16le(data, 6)?;
    let (reference_size, usn_at) = match major {
        2 => (8, 24),
        3 | 4 => (16, 40),
        _ => {
            return Err(Error::Unsupported(format!(
                "USN record version {major}.{minor}"
            )));
        }
    };
    let reference =
        |at| -> Result<String> { Ok(crate::ewf::hex(bytes(data, at, reference_size)?)) };
    let mut record = UsnRecord {
        offset,
        length,
        major,
        minor,
        file_reference: reference(8)?,
        parent_reference: reference(8 + reference_size)?,
        usn: u64le(data, usn_at)? as i64,
        timestamp: None,
        reason: 0,
        source_info: 0,
        security_id: None,
        file_attributes: None,
        name: None,
        remaining_extents: None,
        extents: vec![],
    };
    if major == 4 {
        record.reason = u32le(data, 48)?;
        record.source_info = u32le(data, 52)?;
        record.remaining_extents = Some(u32le(data, 56)?);
        let count = usize::from(u16le(data, 60)?);
        let stride = usize::from(u16le(data, 62)?);
        if stride < 16 || count > 4096 {
            return Err(corrupt("USN", offset, "invalid extent count/size"));
        }
        bytes(data, 64, count * stride)?;
        for i in 0..count {
            let at = 64 + i * stride;
            let length = u64le(data, at + 8)? as i64;
            let start = u64le(data, at)? as i64;
            if start < 0 || length < 0 || start.checked_add(length).is_none() {
                return Err(corrupt("USN", offset, "invalid extent range"));
            }
            record.extents.push(UsnExtent {
                offset: start,
                length,
            });
        }
    } else {
        let ticks = u64le(data, usn_at + 8)?;
        record.timestamp = Some(Timestamp {
            seconds: (ticks / 10_000_000) as i64 - 11_644_473_600,
            nanos: ((ticks % 10_000_000) * 100) as u32,
            basis: TimeBasis::Utc,
        });
        record.reason = u32le(data, usn_at + 16)?;
        record.source_info = u32le(data, usn_at + 20)?;
        record.security_id = Some(u32le(data, usn_at + 24)?);
        record.file_attributes = Some(u32le(data, usn_at + 28)?);
        let length = usize::from(u16le(data, usn_at + 32)?);
        let at = usize::from(u16le(data, usn_at + 34)?);
        if at < usn_at + 36 || !at.is_multiple_of(2) {
            return Err(corrupt(
                "USN",
                offset,
                "filename overlaps header or is unaligned",
            ));
        }
        record.name = Some(utf16(bytes(data, at, length)?)?);
    }
    Ok(record)
}
