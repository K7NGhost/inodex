mod layers_support;
use inodex::{
    Error,
    filesystem::{FileSystem, forensics::RecoveryStatus, journal, lznt1, security},
};
use layers_support::*;
use std::{fs, io::Read, path::Path};
fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/forensics")
        .join(format!("{name}.gz"));
    let mut data = vec![];
    flate2::read::GzDecoder::new(fs::File::open(p).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}
#[test]
fn native_windows_lznt1_and_ntfs_mixed_compression_units() {
    let source = fixture("compressed-source.bin");
    assert_eq!(
        lznt1::decompress(&fixture("windows-variable.lznt1"), 65536).unwrap(),
        fixture("windows-variable.bin")
    );
    assert_eq!(
        lznt1::decompress(&fixture("windows.lznt1"), 65536).unwrap(),
        source[..65536]
    );
    let mut image = Memory::new(fixture("ntfs-forensics.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/passwords.txt").unwrap();
    let mut output = vec![];
    fs.copy_file(id, None, &mut output).unwrap();
    assert_eq!(output, source);
    for offset in [
        0,
        4095,
        65530,
        65536,
        131070,
        131072,
        196607,
        196608,
        source.len() - 1,
        source.len(),
    ] {
        let mut out = [0xa5; 1027];
        let n = fs.read_file(id, None, offset as u64, &mut out).unwrap();
        let expected = (source.len() - offset).min(out.len());
        assert_eq!(n, expected);
        assert_eq!(&out[..n], &source[offset..offset + n]);
    }
    assert!(fs.metadata(id).unwrap().streams[0].compressed);
}
#[test]
fn windows_security_descriptor_and_ntfs_security_metadata() {
    let raw = fixture("windows.sd");
    let parsed = security::parse(&raw).unwrap();
    assert_eq!(parsed.owner.as_deref(), Some("S-1-5-18"));
    assert_eq!(parsed.group.as_deref(), Some("S-1-5-32-544"));
    let dacl = parsed.dacl.unwrap();
    assert_eq!(dacl.aces.len(), 3);
    assert_eq!(dacl.aces[0].kind, 1);
    assert_eq!(dacl.aces[0].sid.as_deref(), Some("S-1-5-32-546"));
    assert_eq!(parsed.sacl.unwrap().aces.len(), 1);
    let mut image = Memory::new(fixture("ntfs-forensics.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let id = fs.resolve("/passwords.txt").unwrap();
    assert_eq!(fs.security(id).unwrap().unwrap().raw, raw);
    let details = fs.ntfs_details(id).unwrap();
    assert_eq!(details.names[0].name, "passwords.txt");
    assert!(details.names[0].times.created.is_some());
    assert!(details.metadata.times.created.is_some());
}
#[test]
fn deleted_record_scan_and_conservative_recovery() {
    let mut image = Memory::new(fixture("ntfs-deleted.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    let report = fs.deleted_records(27, 3, None).unwrap();
    assert_eq!(report.records.len(), 3, "{:?}", report.issues);
    assert_eq!(report.next_record, Some(30));
    assert!(matches!(report.records[0].status, RecoveryStatus::Resident));
    assert!(matches!(
        report.records[1].status,
        RecoveryStatus::UnallocatedClusters
    ));
    assert!(matches!(
        report.records[2].status,
        RecoveryStatus::ReallocatedClusters
    ));
    let mut out = vec![];
    fs.recover_file(27, None, &mut out).unwrap();
    assert_eq!(out, b"resident deleted evidence");
    out.clear();
    fs.recover_file(28, None, &mut out).unwrap();
    assert!(out.starts_with(b"deleted cluster evidence"));
    out.clear();
    assert!(fs.recover_file(29, None, &mut out).is_err());
    assert!(out.is_empty());
    assert!(fs.recover_file(66, None, &mut out).is_err());
}
#[test]
fn malformed_lznt1_and_security_descriptors_are_rejected() {
    for bytes in [
        &[0x00, 0x80][..],
        &[0x02, 0xb0, 1, 0, 0][..],
        &[0x00, 0x30][..],
    ] {
        assert!(lznt1::decompress(bytes, 4096).is_err());
    }
    assert!(lznt1::decompress(&fixture("windows.lznt1"), 100).is_err());
    let sd = fixture("windows.sd");
    for length in [0, 19, sd.len() - 1] {
        assert!(security::parse(&sd[..length]).is_err());
    }
    let mut changed = sd;
    put32(&mut changed, 4, u32::MAX);
    assert!(security::parse(&changed).is_err());
}
#[test]
fn usn_v2_v3_v4_records_and_corruption() {
    for version in [2, 3] {
        let at = if version == 2 { 24 } else { 40 };
        let name = "deleted-日本語.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let length = (at + 36 + name.len()).div_ceil(8) * 8;
        let mut data = vec![0; length];
        put32(&mut data, 0, length as u32);
        put16(&mut data, 4, version);
        put64(&mut data, 8, 66 | (1 << 48));
        put64(&mut data, at, 4096);
        put64(&mut data, at + 8, 132000000000000000);
        put32(&mut data, at + 16, 0x80000200);
        put16(&mut data, at + 32, name.len() as u16);
        put16(&mut data, at + 34, (at + 36) as u16);
        data[at + 36..at + 36 + name.len()].copy_from_slice(&name);
        let parsed = journal::parse_record(&data, 4096).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("deleted-日本語.txt"));
        assert_eq!(parsed.reason, 0x80000200);
        assert!(parsed.timestamp.is_some());
        put16(&mut data, at + 34, 2);
        assert!(journal::parse_record(&data, 4096).is_err());
    }
    let mut data = vec![0; 80];
    put32(&mut data, 0, 80);
    put16(&mut data, 4, 4);
    put16(&mut data, 60, 1);
    put16(&mut data, 62, 16);
    put64(&mut data, 64, 4096);
    put64(&mut data, 72, 1024);
    let parsed = journal::parse_record(&data, 0).unwrap();
    assert!(parsed.name.is_none());
    assert_eq!(parsed.extents[0].offset, 4096);
    put16(&mut data, 4, 99);
    assert!(matches!(
        journal::parse_record(&data, 0),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn secure_sds_and_paginated_sparse_usn_and_logfile_restart_pages() {
    let mut image = Memory::new(fixture("ntfs-journal-security.raw"));
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert_eq!(fs.security(66).unwrap().unwrap().raw, fixture("windows.sd"));
    let details = fs.ntfs_details(66).unwrap();
    assert_eq!(details.security_id, Some(256));
    let first = fs.usn_journal(0, 8192, 1).unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].offset, 4096);
    assert_eq!(first.records[0].name.as_deref(), Some("created.txt"));
    assert_eq!(first.journal_id, Some(123456789));
    let rest = fs
        .usn_journal(first.next_offset.unwrap(), 8192, 100)
        .unwrap();
    assert_eq!(rest.records.len(), 2);
    assert_eq!(rest.records[1].name.as_deref(), Some("deleted.txt"));
    assert!(rest.next_offset.is_none());
    let log = fs.logfile_info().unwrap();
    assert!(log.initialized);
    assert_eq!(log.restart_areas.len(), 2, "{:?}", log.issues);
    assert!(log.restart_areas[0].clean_shutdown);
    assert!(!log.replay_performed);
}

#[test]
fn journal_limits_corrupt_records_torn_restart_page_and_sds_hash() {
    let original = fixture("ntfs-journal-security.raw");
    let mut image = Memory::new(original.clone());
    let mut fs = FileSystem::open(&mut image).unwrap();
    assert!(fs.usn_journal(1, 8192, 1).is_err());
    assert!(fs.usn_journal(4096, 8, 1).is_err());
    assert!(fs.deleted_records(0, 0, None).is_err());
    assert!(fs.deleted_records(0, usize::MAX, None).is_err());
    let mut changed = original.clone();
    put32(&mut changed, 928 * 4096, u32::MAX);
    let mut image = Memory::new(changed);
    assert!(
        FileSystem::open(&mut image)
            .unwrap()
            .usn_journal(4096, 8192, 10)
            .is_err()
    );
    let mut changed = original.clone();
    let index = changed.windows(4).position(|w| w == b"RSTR").unwrap();
    changed[index + 510] ^= 1;
    let mut image = Memory::new(changed);
    let report = FileSystem::open(&mut image)
        .unwrap()
        .logfile_info()
        .unwrap();
    assert_eq!(report.restart_areas.len(), 1);
    assert_eq!(report.issues.len(), 1);
    let mut changed = original;
    let mft = 4 * 4096;
    let rec = mft + 9 * 1024;
    let mut at = rec + u16at(&changed, rec + 20) as usize;
    while u32at(&changed, at) != 0x80 {
        at += u32at(&changed, at + 4) as usize;
    }
    let data = at + u16at(&changed, at + 20) as usize;
    changed[data] ^= 1;
    let mut image = Memory::new(changed);
    assert!(FileSystem::open(&mut image).unwrap().security(66).is_err());
}

#[test]
fn security_null_absent_acl_and_unknown_aces_preserve_their_distinction() {
    let mut descriptor = vec![0; 20];
    descriptor[0] = 1;
    put16(&mut descriptor, 2, 0x8000);
    let absent = security::parse(&descriptor).unwrap();
    assert!(!absent.dacl_present);
    assert!(absent.dacl.is_none());
    put16(&mut descriptor, 2, 0x8004);
    let null = security::parse(&descriptor).unwrap();
    assert!(null.dacl_present);
    assert!(null.dacl.is_none());
    put32(&mut descriptor, 16, 20);
    descriptor.extend_from_slice(&[2, 0, 12, 0, 1, 0, 0, 0, 99, 0, 4, 0]);
    let parsed = security::parse(&descriptor).unwrap();
    let ace = &parsed.dacl.as_ref().unwrap().aces[0];
    assert_eq!(ace.kind, 99);
    assert!(ace.sid.is_none());
    assert_eq!(ace.raw, [99, 0, 4, 0]);
}
