# Rust API integration guide

Inodex provides read-only image, partition and filesystem readers. Applications
own case databases, job scheduling, output files and any working copies needed
by external tools. Reading an image does not extract its entire contents.

## Add the dependency

For a local checkout:

```toml
[dependencies]
inodex = { path = "../inodex" }
```

Once version 0.1.0 is published, consumers can use `inodex = "0.1"` instead.
The crate includes a library and the `inodex` command-line binary.

## Open an image and list a directory

`Image::open` selects the supported container reader, including raw and split
raw images, E01, AFF-family images, VMDK, VHD/VHDX, logical directories,
logical acquisitions and supported L01 evidence. Filesystem detection is a
separate operation over the decoded image or a bounded partition view.

This example opens a whole-volume image with no partition table:

```no_run
use inodex::{filesystem::FileSystem, image::Image};

let mut image = Image::open("volume.E01")?;
let mut fs = FileSystem::open(&mut image)?;
let root = fs.info().root_id;
for entry in fs.read_dir(root)? {
    let metadata = fs.metadata(entry.id)?;
    println!("{}: {} bytes ({:?})", entry.name, metadata.size, entry.kind);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

For a partitioned disk, discover the table and select a partition by its
reported `index`; indices are not zero-based vector positions:

```no_run
use inodex::{filesystem::FileSystem, image::Image, partition::PartitionTable};

let mut image = Image::open("disk.E01")?;
let table = PartitionTable::read(&mut image)?.ok_or("no partition table")?;
for partition in &table.partitions {
    println!("partition {}: {}", partition.index, partition.name);
}
let mut volume = table.get(1)?.volume(&mut image)?;
let mut fs = FileSystem::open(&mut volume)?;
let id = fs.resolve("/documents/report.txt")?;
println!("{:?}", fs.metadata(id)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`PartitionTable::read` returns `Ok(None)` when no table is recognized. A
recognized corrupt table returns an error; do not silently treat that error
as a whole-volume filesystem. Extended partition containers cannot be opened
as filesystems: select one of their logical partitions instead.
For a known byte range, use `image::Volume::new(&mut image, offset, length)`.
Raw images default to 512-byte sectors; `Image::set_sector_size` or
`RawImage::with_sector_size` allows an explicit raw-image sector size.

## Ownership and concurrency

A `Volume` mutably borrows its image. A disk-backed `FileSystem` mutably borrows
the image or volume it reads. Keep these owners in scope, and finish using the
filesystem before accessing the underlying image again. Return owned metadata
and directory records from functions when their readers must be closed.

Reads require mutable access because the readers seek and maintain caches.
For concurrent work, use independent handles or serialize requests through an
application-owned reader. Avoid reopening a reader for each small read; doing
so discards its indexes and caches. The crate does not provide an async runtime
or a cancellation scheduler.

## Paths, identifiers and metadata

Filesystem paths use `/`, independently of the host operating system.
`resolve` does not follow symlinks or reparse points. A path inside an image
is not a Windows filename and cannot be passed directly to a tool that expects
a local file.

Use `fs.info().root_id`; root identifiers differ between filesystems. Treat
entry IDs as scoped to their source and selected filesystem/view, rather than
globally unique IDs. Save the evidence source identity and partition/view
selection alongside an ID or evidence path.

`Metadata` describes size, allocation, links, optional ownership/mode fields,
timestamps and available streams. Missing timestamps remain `None`.
`Timestamp::basis` distinguishes UTC from local civil times; do not invent a
timezone for the latter. `DirEntry::raw_name` preserves original ext name bytes
where its display name may be lossy UTF-8. Several metadata records implement
Serde serialization for application storage or interchange.

For recursive enumeration, track visited directory IDs to avoid cycles and
apply application-level limits to the total traversal. The repository's
`examples/library_ingest.rs` demonstrates owned NDJSON records.

## Read file bytes or create a working copy

`read_file(id, stream, offset, buffer)` reads a range and returns its byte count.
Handle short reads and zero at end of file. `None` selects the default stream;
`Some(name)` selects a named stream where supported. Inspect
`Metadata::streams` rather than assuming stream availability.

```no_run
use inodex::{filesystem::FileSystem, image::Image};

let mut image = Image::open("volume.E01")?;
let mut fs = FileSystem::open(&mut image)?;
let id = fs.resolve("/photo.jpg")?;
let mut header = [0_u8; 32];
let count = fs.read_file(id, None, 0, &mut header)?;
println!("header: {:?}", &header[..count]);

// For a plugin requiring a local path, create a separate working copy.
let output_path = "photo-working-copy.jpg";
let mut output = std::fs::OpenOptions::new()
    .write(true).create_new(true).open(output_path)?;
let copied = match fs.copy_file(id, None, &mut output) {
    Ok(bytes) => bytes,
    Err(error) => {
        drop(output);
        std::fs::remove_file(output_path)?;
        return Err(error.into());
    }
};
std::io::Write::flush(&mut output)?;
println!("copied {copied} bytes");
# Ok::<(), Box<dyn std::error::Error>>(())
```

`copy_file` streams through a bounded buffer. The caller owns the writer and
must discard partial output on failure, including writer flush failures.
Choose working-copy names independently of untrusted evidence paths. Keep the
source identity, stream and evidence path with the copy; hash its contents if
your processing workflow requires content verification. Materialize only the
files needed by tools requiring local paths; other consumers can use ranges or
streamed copies. Inodex does not manage a working-copy cache or its lifetime.

## Read decoded media and verify E01 evidence

`image::DiskImage` exposes decoded media length, sector size and offset-based
reads independently of the container's compressed size. Import the trait to
call `read_at` or `read_exact_at`. `EwfImage` additionally implements
`std::io::Read` and `std::io::Seek`.

```no_run
use inodex::{ewf::EwfImage, image::DiskImage};

let mut image = EwfImage::open("disk.E01")?;
let mut sector = vec![0; image.sector_size() as usize];
image.read_exact_at(0, &mut sector)?;
let report = image.verify()?;
println!("{} decoded bytes checked", report.bytes_read);
println!("stored MD5 verified: {}", report.md5_verified);
println!("stored SHA1 verified: {}", report.sha1_verified);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Opening validates supported structure and metadata; reads validate requested
chunks. Full `verify` reads every E01 chunk and compares available acquisition
digests. If a stored digest is absent, the corresponding `*_verified` flag is
false even though a digest was computed. Verification does not reconstruct
sectors the acquisition tool recorded as unreadable.

`EwfImage::open_segments` accepts explicit segment paths and sorts them by
header number. `metadata`, `sections` and `segment_paths` expose acquisition
information and container inventory. EWF2 (`.Ex01`/`.Lx01`) is not supported.

E01 handles retain at most 256 decoded chunks and 8 MiB of decoded payload,
except that a permitted oversized chunk is retained alone. Cached bytes have
already passed read validation; cache hits do not reread their backing bytes.
Full E01 verification and export bypass the chunk cache. Keep evidence stable
while a handle is open. FAT directory lookup also caches the most recently
used directory within the filesystem metadata budget.

`export_to(&mut writer)` exports decoded physical media, not a directory tree.
The E01 implementation checks the exported stream and returns its MD5/SHA1
report. Other containers have format-specific validation; they do not acquire
E01 checksum guarantees through the common interface. Logical sources have no
physical media export. Discard partial output if export fails.

## Limits, errors and specialized operations

Use `image::Limits`, `ewf::OpenOptions` and `filesystem::Limits` at their
respective layers. They bound parser-controlled metadata, decompression,
directory sizes and traversal. Increase limits deliberately for larger inputs;
do not remove them merely to suppress an error. They are not an application-wide
memory or total-work budget.

The library returns `inodex::Result<T>`. Match `inodex::Error` to distinguish
I/O failures, unsupported features, malformed/corrupt structures, checksum or
digest mismatches, resource limits and missing paths/segments. An unsupported
feature is not an empty file or a successful parse.

The shared filesystem facade exposes NTFS-specific `security`, `ntfs_details`,
`deleted_records`, `recover_file`, `usn_journal` and `logfile_info` operations.
Unsupported filesystems return errors for these methods. Recovery is
conservative and cannot guarantee that deleted content survived reuse.
The `filesystem::apfs` module provides volume and snapshot selection;
`bitlocker` provides an explicitly credentialed decrypted view;
`acquisition` provides logical snapshots. Refer to their Rust API signatures
for options and result types. Filesystem-family support does not imply support
for every feature or format variant.

## Build the reference

From the repository, run `cargo doc --locked --no-deps --open` and
`cargo test --locked --doc` to build the API reference and check these examples.
The published package contains the runtime Rust sources, this embedded guide,
README, Cargo metadata and any root license files. Fixture-backed integration
tests and development tools remain in the repository.
