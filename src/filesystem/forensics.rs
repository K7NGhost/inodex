use super::{Metadata, Times};
use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
pub struct FileName {
    pub name: String,
    pub namespace: u8,
    pub parent_id: u64,
    pub parent_sequence: u16,
    pub times: Times,
    pub allocated_size: u64,
    pub logical_size: u64,
    pub flags: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct NtfsDetails {
    pub metadata: Metadata,
    pub names: Vec<FileName>,
    pub security_id: Option<u32>,
    pub file_attributes: Option<u32>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Resident,
    UnallocatedClusters,
    ReallocatedClusters,
    MftBitmapConflict,
    Unsupported,
}
#[derive(Debug, Clone, Serialize)]
pub struct DeletedRecord {
    pub details: NtfsDetails,
    pub status: RecoveryStatus,
    pub assessed_stream: Option<String>,
    pub explanation: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct ScanIssue {
    pub record_id: u64,
    pub message: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct DeletedScan {
    pub records: Vec<DeletedRecord>,
    pub issues: Vec<ScanIssue>,
    pub next_record: Option<u64>,
    pub records_scanned: u64,
}
