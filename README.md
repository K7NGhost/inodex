# inodex

Inodex is a read-only Rust library and command-line tool for inspecting disk
images and filesystems. It lists directories, reads file metadata, extracts
files, and verifies supported image checksums without modifying the source.
It uses native Rust readers with no Sleuth Kit or libewf dependency.

## Supported formats

| Type | Support |
| --- | --- |
| Disk images | Raw, split raw, E01 (EWF v1), AFF/AFD/AFM, VMDK, VHD, VHDX |
| Logical sources | Local directories, L01 evidence, `.inodex` logical acquisitions |
| Partition tables | MBR, extended MBR/EBR, GPT |
| Filesystems | NTFS, FAT12/16/32, exFAT, ext2/3/4, APFS, HFS+/HFSX, UFS1/UFS1b/UFS2, ISO 9660, YAFFS2 |

## Features

- File metadata, timestamps, named streams and bounded-memory extraction.
- Single and segmented E01 reads, full verification and raw export.
- NTFS compressed files, security descriptors, deleted-record scanning,
  conservative file recovery, USN records and `$LogFile` restart metadata.
- APFS volume and snapshot selection, plus supported Apple compressed files
  and resource forks.
- BitLocker v2 reads with explicit credentials.
- Logical directory acquisition with content hashes.

Support varies by format and feature. EWF2 (`.Ex01`/`.Lx01`) and AFF4 are not
supported.

See the [API guide](docs/api.md) for library integration and `inodex --help`
for command-line usage.

## License

[MIT](LICENSE).
