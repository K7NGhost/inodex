mod layers_support;
use inodex::{
    Error,
    filesystem::{FileSystem, Limits},
};
use layers_support::*;
fn image(name: &str) -> Vec<u8> {
    let d = raw(&format!("{name}.raw"));
    if name == "ufs1" || name == "ufs2" {
        d[8192..].to_vec()
    } else {
        d
    }
}
#[track_caller]
fn rejected(d: Vec<u8>) {
    assert!(FileSystem::open(&mut Memory::new(d)).is_err());
}
fn apfs_checksum(d: &mut [u8], block: usize) {
    let at = block * 4096;
    let mut a = 0u64;
    let mut b = 0u64;
    let m = 0xffff_ffff;
    for w in d[at + 8..at + 4096].as_chunks::<4>().0 {
        a = (a + u64::from(u32::from_le_bytes(*w))) % m;
        b = (b + a) % m;
    }
    let lo = m - (a + b) % m;
    let hi = m - (a + lo) % m;
    put64(d, at, lo | (hi << 32));
}
fn hfs_catalog(d: &[u8]) -> usize {
    u32::from_be_bytes(d[1312..1316].try_into().unwrap()) as usize
        * u32::from_be_bytes(d[1064..1068].try_into().unwrap()) as usize
}
#[test]
fn apfs_checksums_cover_referenced_metadata() {
    for block in [0, 101, 102, 103, 107, 108, 109] {
        let mut d = image("apfs");
        d[block * 4096] ^= 1;
        rejected(d);
    }
}
#[test]
fn apfs_valid_checksums_do_not_hide_invalid_tables_and_cycles() {
    for count in [u32::MAX, 65535] {
        let mut d = image("apfs");
        put32(&mut d, 101 * 4096 + 36, count);
        apfs_checksum(&mut d, 101);
        rejected(d);
    }
    let mut d = image("apfs");
    let at = 101 * 4096;
    let table = at + 56 + u16at(&d, at + 40) as usize;
    let value = at + 4096 - 40 - u16at(&d, table + 4) as usize;
    put16(&mut d, at + 32, 1);
    put16(&mut d, at + 34, 1);
    put32(&mut d, at + 36, 1);
    put16(&mut d, table + 6, 8);
    put64(&mut d, value, 1028);
    apfs_checksum(&mut d, 101);
    rejected(d);
}
#[test]
fn encrypted_apfs_is_explicit() {
    let mut d = image("apfs");
    let flags = u64at(&d, 107 * 4096 + 264);
    put64(&mut d, 107 * 4096 + 264, flags & !1);
    apfs_checksum(&mut d, 107);
    let mut m = Memory::new(d);
    assert!(matches!(
        FileSystem::open(&mut m),
        Err(Error::Unsupported(_))
    ));
}
#[test]
fn hfs_rejects_invalid_leaf_offsets_and_links() {
    for (offset, value) in [(32, 1u16), (4096 + 10, u16::MAX), (4096 + 4094, 0)] {
        let mut d = image("hfsplus");
        let cat = hfs_catalog(&d);
        d[cat + offset..cat + offset + 2].copy_from_slice(&value.to_be_bytes());
        rejected(d);
    }
    let mut d = image("hfsplus");
    let cat = hfs_catalog(&d);
    d[cat + 4096..cat + 4100].copy_from_slice(&1u32.to_be_bytes());
    rejected(d);
}
#[test]
fn hfs_rejects_forks_pointing_to_free_blocks() {
    let mut d = image("hfsplus");
    let size = u32::from_be_bytes(d[1064..1068].try_into().unwrap()) as usize;
    let bitmap = u32::from_be_bytes(d[1152..1156].try_into().unwrap()) as usize * size;
    d[bitmap..bitmap + 128].fill(0);
    rejected(d);
}
#[test]
fn unsupported_hfs_compression_fails_before_output() {
    let mut d = image("hfsplus");
    let cat = hfs_catalog(&d);
    let leaf = cat + 4096;
    let count = u16::from_be_bytes(d[leaf + 10..leaf + 12].try_into().unwrap()) as usize;
    let mut found = false;
    for i in 0..count {
        let offset = u16::from_be_bytes(
            d[leaf + 4096 - (i + 1) * 2..leaf + 4096 - i * 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let at = leaf + offset;
        let key = u16::from_be_bytes(d[at..at + 2].try_into().unwrap()) as usize;
        let value = at + ((key + 3) & !1);
        if u32::from_be_bytes(d[value + 8..value + 12].try_into().unwrap()) == 20 {
            d[value + 41] |= 0x20;
            found = true;
            break;
        }
    }
    assert!(found);
    let mut m = Memory::new(d);
    let mut fs = FileSystem::open(&mut m).unwrap();
    let id = fs.resolve("/passwords.txt").unwrap();
    let mut output = vec![];
    assert!(matches!(
        fs.copy_file(id, None, &mut output),
        Err(Error::Unsupported(_))
    ));
    assert!(output.is_empty());
}
#[test]
fn ufs_rejects_bad_geometry_allocation_and_record_lengths() {
    for name in ["ufs1", "ufs2"] {
        let source = image(name);
        let sb = if name == "ufs1" { 8192 } else { 65536 };
        for field in [48, 52, 120, 184, 188] {
            let mut d = source.clone();
            put32(&mut d, sb + field, 0);
            rejected(d);
        }
        let frag = u32at(&source, sb + 52) as usize;
        let group = u32at(&source, sb + 12) as usize * frag;
        let inode =
            u32at(&source, sb + 16) as usize * frag + 2 * if name == "ufs1" { 128 } else { 256 };
        let root = u32at(&source, inode + if name == "ufs1" { 40 } else { 112 }) as usize * frag;
        let mut d = source.clone();
        put16(&mut d, root + 4, 0);
        rejected(d);
        let mut d = source.clone();
        let bitmap = group + u32at(&d, group + 92) as usize;
        d[bitmap] &= !(1 << 2);
        rejected(d);
    }
}
#[test]
fn iso_rejects_endian_disagreement_directory_cycles_and_missing_terminator() {
    let source = image("iso9660");
    let mut d = source.clone();
    d[32768 + 84] ^= 1;
    rejected(d);
    let mut d = source.clone();
    let root = u32at(&d, 32768 + 158) as usize * 2048;
    let at = root + 68;
    let physical = u32at(&d, 32768 + 158);
    put32(&mut d, at + 2, physical);
    d[at + 6..at + 10].copy_from_slice(&physical.to_be_bytes());
    rejected(d);
    let mut d = source;
    d[17 * 2048] = 0;
    rejected(d);
}
#[test]
fn yaffs_rejects_invalid_tags_headers_and_hard_link_cycles() {
    let stride = 2112;
    for (at, value) in [
        (2048, 0),
        (7 * stride + 2048 + 12, 2049),
        (0, 9),
        (12 * stride + 296, 260),
    ] {
        let mut d = image("yaffs2");
        put32(&mut d, at, value);
        rejected(d);
    }
    let mut d = image("yaffs2");
    d[stride + 10..stride + 266].fill(b'x');
    rejected(d);
}
#[test]
fn yaffs_sequence_numbers_supersede_physical_order() {
    let mut d = image("yaffs2");
    put32(&mut d, 3 * 2112 + 2048, 0x2000);
    let mut m = Memory::new(d);
    let mut fs = FileSystem::open(&mut m).unwrap();
    let id = fs.resolve("/fragmented.bin").unwrap();
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(&data[..2048], &[b'X'; 2048]);
}
#[test]
fn yaffs_shrink_then_growth_does_not_restore_stale_bytes() {
    let mut d = image("yaffs2");
    let old = d[2 * 2112..3 * 2112].to_vec();
    d[18 * 2112..19 * 2112].copy_from_slice(&old);
    put32(&mut d, 18 * 2112 + 292, 100);
    put32(&mut d, 18 * 2112 + 508, 1);
    put32(&mut d, 18 * 2112 + 2048, 0x2000);
    d[19 * 2112..20 * 2112].copy_from_slice(&old);
    put32(&mut d, 19 * 2112 + 2048, 0x3000);
    let mut m = Memory::new(d);
    let mut fs = FileSystem::open(&mut m).unwrap();
    let id = fs.resolve("/fragmented.bin").unwrap();
    let mut data = vec![];
    fs.copy_file(id, None, &mut data).unwrap();
    assert_eq!(
        &data[..100],
        &(0..100)
            .map(|i| ((i * 11 + 3) % 251) as u8)
            .collect::<Vec<_>>()
    );
    assert!(data[100..].iter().all(|b| *b == 0));
}
#[test]
fn deterministic_metadata_mutations_are_bounded_and_never_panic() {
    for name in ["apfs", "hfsplus", "ufs1", "ufs2", "iso9660", "yaffs2"] {
        let source = image(name);
        for at in [
            0,
            8,
            32,
            1024,
            1032,
            1064,
            8192 + 48,
            65536 + 1372,
            32768 + 156,
            source.len() / 2,
        ] {
            if at >= source.len() {
                continue;
            }
            let mut d = source.clone();
            d[at] ^= 0xff;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut m = Memory::new(d);
                let _ = FileSystem::with_limits(
                    &mut m,
                    Limits {
                        max_chain_length: 4096,
                        ..Limits::default()
                    },
                );
            }));
            assert!(result.is_ok(), "{name}:{at}");
        }
    }
}
