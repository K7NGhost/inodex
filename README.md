# inodex

Native Rust forensic readers: **raw/split raw, E01, AFF/AFD/AFM, VMDK, VHD/VHDX,
logical directories, MBR/GPT partitions, and
read-only NTFS, FAT12/16/32, exFAT, ext2/3/4, APFS, HFS+/HFSX,
UFS1/UFS1b/UFS2, ISO 9660 and YAFFS2 filesystems**, plus **L01 logical evidence**.
The implementation has no TSK/libewf bindings and uses the Rust backend of
`flate2`. The supplied `D:\Projects\sleuthkit` checkout was inspected to identify
the image-reader behavior being replaced (`tsk/img/ewf.cpp` delegates to libewf).
Disk containers use the same partition/filesystem interface. See the
[disk-image support matrix](docs/disk-images.md) for variants and restrictions.

The layers now compose from an E01 image through partition selection to directory
listing, file metadata, named NTFS streams, and file extraction. This is an
initial implementation of these filesystem families; additional TSK formats
and advanced recovery features remain future work. See the
[filesystem support and validation notes](docs/filesystems.md) for exact scope.

The additional readers support live directory browsing, metadata and file
extraction through the same commands. APFS containers expose volume discovery
and selection; Apple resource forks are available as named streams. See
[additional filesystem coverage](docs/additional-filesystems.md) for tested
features, corpus provenance and restrictions. This is read-only parser coverage,
not complete feature parity with every TSK filesystem operation.

VHDX fixed/dynamic/differencing disks, recorded L01 trees, Solaris UFS1b,
HFS-wrapped HFS+/HFSX, Apple zlib/LZVN/LZFSE/raw compressed-file reads and
APFS snapshot selection are described in [format expansion coverage](docs/format-expansion.md).

NTFS forensic features now include LZNT1-compressed reads, security descriptors,
deleted-MFT scanning and conservative recovery, USN records and `$LogFile`
restart metadata. BitLocker v2 views accept explicit credentials, and logical
directories can be captured into self-contained, hash-checked `.inodex`
acquisitions. See [forensic feature coverage](docs/forensic-features.md) for
commands, tested scope and remaining limitations.

## Run

```powershell
cargo run --release -- info "D:\evidence\disk.E01"
cargo run --release -- verify "D:\evidence\disk.E01"
cargo run --release -- export "D:\evidence\disk.E01" "D:\evidence\disk.raw"

cargo run --release -- partitions "D:\evidence\disk.E01"
cargo run --release -- fs-info "D:\evidence\disk.E01" --partition 1
cargo run --release -- ls "D:\evidence\disk.E01" / --partition 1
cargo run --release -- stat "D:\evidence\disk.E01" /documents/report.txt --partition 1
cargo run --release -- extract "D:\evidence\disk.E01" /documents/report.txt "D:\evidence\report.txt" --partition 1
```

Subsequent segments are discovered automatically, including `.E99` to `.EAA`
and `.EZZ` to `.FAA`; lower-case extensions are accepted. Export creates a new
file, verifies the actual exported bytes in a single pass, and removes partial
output on failure. Existing files are never overwritten.

Partition/filesystem commands accept every supported disk container. Omit `--partition` for a
whole-volume image, or select a byte range with `--offset BYTES --length BYTES`.
Raw images can specify `--sector-size 4096`. `--json` provides machine-readable
partition, filesystem, directory, and metadata results. Filesystem paths use
`/`; `extract --stream NAME` selects an NTFS alternate data stream. Extraction
creates a new output file and removes it on failure.

Open the first `.000`, `.001` or `.aa` member for split raw; numeric/alphabetic
successors are discovered automatically. `info`, `verify` and `export` also
accept AFF/AFD/AFM, VMDK and VHD. Pass a host directory to `fs-info`, `ls`,
`stat` or `extract` to browse logical evidence. Logical directories have no
physical export or partition map.

## Library

See the [Rust API integration guide](docs/api.md) for Cargo setup, ownership,
metadata, streaming reads, forensic methods and application integration.
`cargo doc --locked --no-deps --open` builds the browsable API reference.

```rust,no_run
use inodex::{ewf::EwfImage, image::DiskImage};
use std::io::{Read, Seek, SeekFrom};

let mut image = EwfImage::open("disk.E01")?;
let mut sector = vec![0; image.sector_size() as usize];
image.read_at(0, &mut sector)?; // independent of the stream position
image.seek(SeekFrom::Start(512))?;
image.read_exact(&mut sector)?;
let report = image.verify()?; // checks the whole media; preserves stream position
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `EwfImage::open_segments(paths)` for explicit segment lists with arbitrary
filenames. The list is sorted by the segment numbers in the headers. Missing,
duplicate, mixed-set, and extra segments are rejected. A nonzero set identifier
helps distinguish mixed sets; old images with identical geometry and no set
identifier cannot be distinguished at open time, so full digest verification
is necessary.

`export_to(&mut writer)` verifies the exported stream and returns computed
MD5/SHA1 hashes. On error, discard the partial output. `DiskImage` provides
`len`, `sector_size`, and `read_at` for future partition/filesystem parsers.
`Read` and `Seek` support ordinary Rust consumers. Each handle caches up to 256 decoded
chunks / 8 MiB with least-recently-used eviction (an oversized permitted chunk
is retained alone). Full verification bypasses cached data. Handles require
mutable access; open independent handles for concurrent reads.

## Supported and validated

- Single and split physical E01 images; uncompressed and zlib-compressed chunks.
- EnCase 1 inline chunk tables and later sectors/table/table2 layouts, including
  64-bit table base offsets. Chunk tables are indexed without loading media.
- Volume geometry, acquisition fields (Unicode header2 preferred), MD5/SHA1
  digests, section inventory, and acquisition error sector ranges.
- Adler-32 checks for section descriptors, volume/data, tables and backup tables,
  hash/digest sections, error2 records, and chunks. Zlib streams must finish and
  pass their embedded checksum. Conflicting backup tables are rejected.
- Partial and padded final chunks, non-default sector/chunk sizes, bounded
  decompression and allocations, checked offsets, and complete segment chains.

Opening validates structure and supported metadata, while reading validates
each requested chunk. **Run `verify` to validate all chunks and available media
digests.** If an image stores no media digest, verification still checks chunks
and reports computed hashes with `md5_verified`/`sha1_verified` set to false.
Acquisition error ranges describe unreadable sectors in the original acquisition;
a matching digest does not restore those original bytes.

The original E01 corpus contains 16 independently written image sets: compressed
single-file and uncompressed split dfVFS images, plus EnCase 1–6 and FTK output
from libewf 20130416 at compression levels 0 and 2. Every decoded byte is compared
with independently supplied raw data. The EnCase labels identify libewf writer
profiles; files produced by EnCase or FTK themselves have not been tested.
Modern layout support follows the EWF specification, but native EnCase 7 output
has not been independently validated.

EWF2 (`.Ex01`), logical EWF2 (`.Lx01`), SMART, delta/shadow images,
encryption, EWF-X XML metadata, and the historical EnCase 6.7.1 overflowing-offset
quirk are outside this deliverable. Unknown optional sections are inventoried and
skipped; their payload checksums are not interpreted. This reader rejects
corruption instead of attempting recovery from `table2`.

The default limits are 64 MiB decoded chunks, 16 MiB metadata payloads and
accumulated acquisition fields/error ranges, 16,777,216 indexed chunks,
1,048,576 entries per table, and 1,048,576 sections. Raise limits explicitly
through `ewf::OpenOptions` for larger evidence. The chunk limit permits 512 GiB
at the usual 32 KiB chunk size; the index uses roughly 16 bytes per chunk plus
allocation overhead. Segment files remain open for the lifetime of the handle.

## Validation

Fixtures are committed. Ordinary tests require neither network access nor
libewf, Python, TSK, or an installed forensic tool.

```powershell
cargo test --locked
cargo test --locked --release
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

Tests cover byte-for-byte corpus reads, random and sequential access, boundaries,
segmentation, MD5/SHA1, malformed structures, corruption, resource limits,
Unicode metadata/paths, export cleanup, and deterministic byte mutations.

Partition/filesystem tests additionally compare with committed output from an
independent `pytsk3` runtime: file trees, inode/MFT IDs, timestamps, stream sizes,
SHA256 hashes, and partition ranges. They cover fragmented FAT chains, NTFS
attribute-list extension records, indirect blocks, sparse files, ext4 extent
trees/checksums, 4 KiB sectors, and complete E01-to-file extraction. Normal tests
use local fixtures and need no TSK installation. See
[layer fixture provenance](tests/fixtures/layers/README.md).

Optional independent validation against an installed libewf reader:

```powershell
cargo build --locked
python tools/validate_libewf.py --library "D:\Projects\autopsy\thirdparty\ewfexport_exec\64-bit\libewf.dll" --binary target/debug/inodex.exe
```

The development script checks both libewf's output and the Rust export against
the original raw bytes for every corpus image. It is separate from the Rust
implementation. See [fixture provenance](tests/fixtures/README.md) for sources,
hashes, licenses, and reproduction.

## Rewrite boundary

| Layer | Current status | Next work |
| --- | --- | --- |
| Disk images (`tsk/img`) | Raw/split raw, E01, AFF/AFD/AFM, VMDK, VHD/VHDX, L01 and logical directories; verification/export where applicable | Additional variants, encryption and scale; see disk-image matrix |
| Volume systems (`tsk/vs`) | MBR, extended MBR/EBR, GPT, bounded partition slices | Other partition schemes and APFS/LVM pools |
| Filesystems (`tsk/fs`) | NTFS, FAT, exFAT, ext, APFS, HFS+/HFSX, UFS1/UFS1b/UFS2, ISO9660 and YAFFS2 core readers | Advanced features and deleted-file recovery; see coverage documents |
| Higher-level TSK APIs/tools | Not implemented | Compose the Rust layers and compatibility interfaces |

Each later parser should add independently produced image fixtures and compare
its output with TSK before claiming compatibility. The E01 wire-format reference
is the [libyal EWF specification](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20%28EWF%29.asciidoc).
No C parser source was translated or linked into this deliverable.
