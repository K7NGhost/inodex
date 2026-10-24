mod layers_support;
mod support;
use inodex::{
    Result,
    ewf::EwfImage,
    filesystem::{FileKind, FileSystem, Limits},
    image::DiskImage,
};
use std::{
    cell::Cell,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    rc::Rc,
};

struct TrackedFat {
    inner: layers_support::Memory,
    directory: std::ops::Range<u64>,
    reads: Rc<Cell<usize>>,
}
impl DiskImage for TrackedFat {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if offset < self.directory.end
            && offset.saturating_add(buffer.len() as u64) > self.directory.start
        {
            self.reads.set(self.reads.get() + 1);
        }
        self.inner.read_at(offset, buffer)
    }
}
fn tracked(data: Vec<u8>) -> TrackedFat {
    let sector = u64::from(layers_support::u16at(&data, 11));
    let start = (u64::from(layers_support::u16at(&data, 14))
        + u64::from(data[16]) * u64::from(layers_support::u16at(&data, 22)))
        * sector;
    let bytes = u64::from(layers_support::u16at(&data, 17)) * 32;
    TrackedFat {
        inner: layers_support::Memory::new(data),
        directory: start..start + bytes,
        reads: Rc::new(Cell::new(0)),
    }
}
#[test]
fn fat_repeated_resolution_does_not_reread_parent_directory() {
    for fixture in ["fat12.raw", "fat16.raw"] {
        let mut image = tracked(layers_support::raw(fixture));
        let reads = image.reads.clone();
        let mut fs = FileSystem::open(&mut image).unwrap();
        let entries = fs.read_dir(0).unwrap();
        let entry = entries.iter().find(|e| e.kind == FileKind::File).unwrap();
        let path = format!("/{}", entry.name);
        assert_eq!(fs.resolve(&path).unwrap(), entry.id);
        let before = reads.get();
        for _ in 0..100 {
            assert_eq!(fs.resolve(&path.to_ascii_uppercase()).unwrap(), entry.id);
            for alias in &entry.aliases {
                assert_eq!(fs.resolve(&format!("/{alias}")).unwrap(), entry.id);
            }
            assert!(fs.resolve("/not-a-file-in-this-fixture").is_err());
        }
        assert_eq!(
            reads.get(),
            before,
            "cached lookups must not reparse the parent"
        );
        assert!(fs.resolve(&(path + "/")).is_err());
    }
}
#[test]
fn fat_lookup_falls_back_when_metadata_cache_budget_is_zero() {
    let mut image = tracked(layers_support::raw("fat12.raw"));
    let reads = image.reads.clone();
    let mut fs = FileSystem::with_limits(
        &mut image,
        Limits {
            max_metadata_bytes: 0,
            ..Limits::default()
        },
    )
    .unwrap();
    let entry = fs
        .read_dir(0)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == FileKind::File)
        .unwrap();
    let before = reads.get();
    for _ in 0..3 {
        assert_eq!(fs.resolve(&format!("/{}", entry.name)).unwrap(), entry.id);
    }
    assert!(reads.get() >= before + 3);
}
#[test]
fn fat_cached_lookup_preserves_ambiguous_short_alias_rejection() {
    for budget in [0, 16 * 1024 * 1024] {
        let mut image = tracked(layers_support::raw("fat12.raw"));
        let at = image.directory.start as usize;
        image.inner.data[at..image.directory.end as usize].fill(0);
        let short = b"FIRST   TXT";
        let checksum = short
            .iter()
            .fold(0u8, |sum, b| sum.rotate_right(1).wrapping_add(*b));
        let mut lfn = [0xffu8; 32];
        lfn[0] = 0x41;
        lfn[11] = 0x0f;
        lfn[12] = 0;
        lfn[13] = checksum;
        lfn[26] = 0;
        lfn[27] = 0;
        let units: Vec<_> = "THIRD.TXT"
            .encode_utf16()
            .chain(std::iter::once(0))
            .chain(std::iter::repeat(0xffff))
            .take(13)
            .collect();
        for (offset, unit) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .zip(units)
        {
            lfn[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        image.inner.data[at..at + 32].copy_from_slice(&lfn);
        for start in [at + 32, at + 64] {
            image.inner.data[start..start + 11].copy_from_slice(short);
            image.inner.data[start + 11] = 0x20;
        }
        let mut fs = FileSystem::with_limits(
            &mut image,
            Limits {
                max_metadata_bytes: budget,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(fs.resolve("/THIRD.TXT").is_ok());
        for _ in 0..2 {
            assert!(matches!(
                fs.resolve("/FIRST.TXT"),
                Err(inodex::Error::Corrupt { .. })
            ));
        }
    }
}
fn corrupt_first_chunk(path: &std::path::Path, data: &[u8]) {
    let offset = support::section(data, "sectors") + 76;
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset as u64)).unwrap();
    file.write_all(&[data[offset] ^ 0x80]).unwrap();
    file.flush().unwrap();
}
#[test]
fn verification_rereads_all_cached_chunks() {
    let (data, expected) = support::Builder {
        compressed: false,
        ..Default::default()
    }
    .build();
    let (_dir, path) = support::write_image(&data);
    let mut image = EwfImage::open(&path).unwrap();
    let mut byte = [0];
    image.read_at(0, &mut byte).unwrap();
    image.read_at(1024, &mut byte).unwrap();
    corrupt_first_chunk(&path, &data);
    // The first chunk survives an intervening data-chunk read.
    image.read_at(0, &mut byte).unwrap();
    assert_eq!(byte[0], expected[0]);
    // Acquisition verification must bypass every cached chunk, including it.
    assert!(image.verify().is_err());
}
#[test]
fn decoded_cache_evicts_at_chunk_count_and_byte_budgets() {
    for (count, size) in [(300, 1024), (9, 1024 * 1024)] {
        let (data, expected) = support::Builder {
            chunks: (0..count).map(|i| vec![i as u8; size]).collect(),
            sectors_per_chunk: (size / 512) as u32,
            compressed: false,
            ..Default::default()
        }
        .build();
        let (_dir, path) = support::write_image(&data);
        let mut image = EwfImage::open(&path).unwrap();
        let mut byte = [0];
        for i in 0..count {
            image.read_at((i * size) as u64, &mut byte).unwrap();
            assert_eq!(byte[0], expected[i * size]);
        }
        corrupt_first_chunk(&path, &data);
        assert!(
            image.read_at(0, &mut byte).is_err(),
            "oldest chunk must have been evicted"
        );
    }
}
