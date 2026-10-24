mod support;
use inodex::{
    Error,
    ewf::{EwfImage, OpenOptions},
};
use std::{fs, io::Read};
use support::*;

fn decode(builder: Builder) {
    let (data, expected) = builder.build();
    let (_dir, path) = write_image(&data);
    let mut image = EwfImage::open(path).unwrap();
    let mut actual = Vec::new();
    image.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected);
    let report = image.verify().unwrap();
    assert_eq!(report.bytes_read, expected.len() as u64);
    assert!(!report.md5_verified);
    assert!(!report.sha1_verified);
}

#[test]
fn multiple_chunk_groups_and_partial_final_chunk() {
    decode(Builder::default());
}

#[test]
fn padded_final_chunk_is_clipped_to_media_size() {
    for compressed in [false, true] {
        decode(Builder {
            compressed,
            pad_final: true,
            ..Builder::default()
        });
    }
}

#[test]
fn non_default_4096_byte_sectors_and_chunk_geometry() {
    decode(Builder {
        bytes_per_sector: 4096,
        sectors_per_chunk: 3,
        chunks: vec![vec![7; 12288], vec![8; 8192]],
        ..Builder::default()
    });
}

#[test]
fn empty_image_is_a_valid_empty_stream() {
    decode(Builder {
        chunks: Vec::new(),
        ..Builder::default()
    });
}

#[test]
fn unknown_optional_sections_are_inventoried() {
    let (data, _) = Builder {
        extras: vec![("vendor", vec![1, 2, 3])],
        ..Builder::default()
    }
    .build();
    let (_dir, path) = write_image(&data);
    let mut image = EwfImage::open(path).unwrap();
    assert!(image.sections().iter().any(|s| s.kind == "vendor"));
    image.verify().unwrap();
}

#[test]
fn incomplete_images_and_logical_sections_are_rejected() {
    for kind in ["incomplete", "ltree", "ltypes"] {
        let (data, _) = Builder {
            extras: vec![(kind, Vec::new())],
            ..Builder::default()
        }
        .build();
        let (_dir, path) = write_image(&data);
        assert!(EwfImage::open(path).is_err());
    }
}

#[test]
fn acquisition_errors_are_preserved_and_checked() {
    let mut errors = vec![0; 532];
    put32(&mut errors, 0, 1);
    fix_checksum(&mut errors[..520]);
    put32(&mut errors, 520, 1);
    put32(&mut errors, 524, 2);
    fix_checksum(&mut errors[520..]);
    let (data, _) = Builder {
        extras: vec![("error2", errors.clone())],
        ..Builder::default()
    }
    .build();
    let (_dir, path) = write_image(&data);
    let image = EwfImage::open(&path).unwrap();
    assert_eq!(
        image.metadata().acquisition_errors[0],
        inodex::ewf::SectorRange { start: 1, count: 2 }
    );
    drop(image);
    put32(&mut errors, 524, 3);
    fix_checksum(&mut errors[520..]);
    let (data, _) = Builder {
        extras: vec![("error2", errors)],
        ..Builder::default()
    }
    .build();
    fs::write(&path, data).unwrap();
    assert!(EwfImage::open(path).is_err());
}

#[test]
fn header2_unicode_and_big_endian_text_are_decoded() {
    for big_endian in [false, true] {
        let text = "1\nmain\nc\te\nCaf\u{e9}\t\u{6e2c}\u{8a66}\n\n";
        let mut text_bytes = if big_endian {
            vec![0xfe, 0xff]
        } else {
            vec![0xff, 0xfe]
        };
        for unit in text.encode_utf16() {
            text_bytes.extend(if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            });
        }
        let (data, _) = Builder {
            extras: vec![("header2", deflate(&text_bytes))],
            ..Builder::default()
        }
        .build();
        let (_dir, path) = write_image(&data);
        let image = EwfImage::open(path).unwrap();
        assert_eq!(image.metadata().acquisition["c"], "Caf\u{e9}");
        assert_eq!(image.metadata().acquisition["e"], "\u{6e2c}\u{8a66}");
    }
}

#[test]
fn decompression_bombs_and_truncated_streams_are_rejected() {
    for payload in [deflate(&vec![0; 4096]), vec![0x78, 0x9c, 0x01]] {
        let (data, _) = Builder {
            extras: vec![("header", payload)],
            ..Builder::default()
        }
        .build();
        let (_dir, path) = write_image(&data);
        assert!(
            OpenOptions {
                max_metadata_size: 2048,
                ..OpenOptions::default()
            }
            .open(path)
            .is_err()
        );
    }
}

#[test]
fn compressed_chunk_cannot_expand_beyond_declared_chunk_size() {
    let (mut data, _) = Builder {
        chunks: vec![vec![0; 1024]],
        ..Builder::default()
    }
    .build();
    // Change the geometry to a 512-byte chunk while retaining the 1024-byte stream.
    let volume = section(&data, "volume");
    put32(&mut data, volume + 84, 1);
    put64(&mut data, volume + 92, 1);
    fix_section_payload(&mut data, volume);
    let (_dir, path) = write_image(&data);
    let mut image = EwfImage::open(path).unwrap();
    assert!(matches!(image.verify(), Err(Error::ResourceLimit(_))));
}

#[test]
fn malformed_utf16_headers_are_errors() {
    for text in [vec![0xff], vec![0, 0, 1, 0], vec![0xff, 0xfe, 0, 0xd8]] {
        let (data, _) = Builder {
            extras: vec![("header2", deflate(&text))],
            ..Builder::default()
        }
        .build();
        let (_dir, path) = write_image(&data);
        assert!(EwfImage::open(path).is_err());
    }
}

#[test]
fn verified_export_hashes_exact_output_and_preserves_position() {
    use std::io::{Seek, SeekFrom, Write};
    let (data, expected) = Builder::default().build();
    let (_dir, path) = write_image(&data);
    let mut image = EwfImage::open(path).unwrap();
    image.seek(SeekFrom::Start(123)).unwrap();
    let mut output = Vec::new();
    let report = image.export_to(&mut output).unwrap();
    assert_eq!(output, expected);
    assert_eq!(report.bytes_read, output.len() as u64);
    assert_eq!(image.stream_position().unwrap(), 123);

    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        image.export_to(&mut BrokenWriter),
        Err(Error::Io(_))
    ));
    assert_eq!(image.stream_position().unwrap(), 123);
}

#[test]
fn cumulative_metadata_cannot_exceed_the_configured_budget() {
    let header = |key: &str| deflate(format!("1\nmain\n{key}\n{}\n", "v".repeat(600)).as_bytes());
    let (data, _) = Builder {
        extras: vec![("header", header("first")), ("header", header("second"))],
        ..Builder::default()
    }
    .build();
    let (_dir, path) = write_image(&data);
    assert!(matches!(
        OpenOptions {
            max_metadata_size: 1100,
            ..OpenOptions::default()
        }
        .open(path),
        Err(Error::ResourceLimit("total acquisition metadata"))
    ));
}

#[test]
fn volume_sector_count_is_read_as_64_bits() {
    let (mut data, _) = Builder {
        chunks: Vec::new(),
        ..Builder::default()
    }
    .build();
    let volume = section(&data, "volume");
    put64(&mut data, volume + 92, 0x1_0000_0000);
    put32(&mut data, volume + 80, 0x8000_0000);
    fix_section_payload(&mut data, volume);
    let (_dir, path) = write_image(&data);
    // Valid 2 TiB geometry with an intentionally absent index. A reader that
    // truncates the sector count to 32 bits would fail the geometry check.
    let result = OpenOptions {
        max_chunks: u32::MAX as usize,
        ..OpenOptions::default()
    }
    .open(path);
    assert!(
        matches!(result, Err(Error::InvalidFormat { reason, .. }) if reason.contains("chunk count mismatch"))
    );
}
