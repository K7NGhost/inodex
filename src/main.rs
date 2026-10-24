use inodex::{
    ewf::hex,
    image::{DiskImage, Image},
};
mod layer_cli;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::ExitCode,
};

const USAGE: &str = "Usage:
  inodex info <image-or-directory>
  inodex verify <image>
  inodex export <image> <output.raw>

  inodex partitions <image> [--sector-size N] [--json]
  inodex apfs-volumes <image> [volume options] [--json]
  inodex apfs-snapshots <image> [volume options] [--apfs-volume OID] [--json]
  inodex fs-info <image> [volume options] [--json]
  inodex ls <image> [path] [volume options] [--json]
  inodex stat <image> <path> [volume options] [--json]
  inodex extract <image> <path> <output> [--stream NAME] [volume options]
  inodex ntfs-details <image> [path | --id N] [volume options]
  inodex security <image> [path | --id N] [volume options]
  inodex deleted <image> [--start RECORD] [--count N] [--stream NAME] [volume options]
  inodex recover <image> <output> --id N [--stream NAME] [volume options]
  inodex usn <image> [--start BYTE] [--scan-bytes N] [--count N] [volume options]
  inodex logfile-info <image> [volume options]
  inodex decrypt <image> <output.raw> [BitLocker option] [volume options]
  inodex acquire-logical <directory> <output.inodex>

Volume options: --partition N, or --offset BYTES [--length BYTES]
APFS filesystem commands may select --apfs-volume OID (see apfs-volumes).
Use --apfs-snapshot XID to select a recorded APFS snapshot.
Raw images may specify --sector-size N. Paths inside filesystems use '/'.
Filesystem commands and decrypt accept one BitLocker credential file option:
  --bitlocker-password-file PATH, --bitlocker-recovery-file PATH,
  --bitlocker-vmk-file PATH, or --bitlocker-fvek-file PATH.
Password files are UTF-8; VMK/FVEK files contain raw key bytes. Keys are not logged.

Subsequent segments are discovered automatically. Export refuses to overwrite files.";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.first().and_then(|value| value.to_str()).unwrap_or("");
    if command == "acquire-logical" {
        if args.len() != 3 {
            return Err("usage: inodex acquire-logical <source-directory> <output.inodex>".into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&inodex::acquisition::acquire(
                &args[1],
                &args[2],
                inodex::filesystem::Limits::default()
            )?)?
        );
        return Ok(());
    }
    if matches!(
        command,
        "partitions"
            | "apfs-volumes"
            | "apfs-snapshots"
            | "fs-info"
            | "ls"
            | "stat"
            | "extract"
            | "security"
            | "ntfs-details"
            | "deleted"
            | "recover"
            | "usn"
            | "decrypt"
            | "logfile-info"
    ) {
        return layer_cli::run(command, &args[1..]);
    }
    let expected = match command {
        "info" | "verify" => 2,
        "export" => 3,
        _ => return Err(USAGE.into()),
    };
    if args.len() != expected {
        return Err(USAGE.into());
    }
    let mut image = match Image::open(&args[1])? {
        Image::Ewf(image) => image,
        image => return generic(command, image, &args),
    };
    match command {
        "info" => {
            let metadata = image.metadata();
            println!("Format: EWF v1 (E01)");
            println!("Segments: {}", image.segment_paths().len());
            println!("Media size: {} bytes", image.len());
            println!("Sector size: {} bytes", image.sector_size());
            println!("Sectors: {}", metadata.sector_count);
            println!(
                "Chunks: {} ({} bytes each)",
                metadata.chunk_count,
                metadata.chunk_size()
            );
            if let Some(hash) = metadata.md5 {
                println!("Stored MD5: {}", hex(&hash));
            }
            if let Some(hash) = metadata.sha1 {
                println!("Stored SHA1: {}", hex(&hash));
            }
            for (key, label) in [
                ("c", "Case"),
                ("n", "Evidence"),
                ("a", "Description"),
                ("e", "Examiner"),
                ("t", "Notes"),
                ("av", "Acquisition tool version"),
                ("ov", "Acquisition platform"),
            ] {
                if let Some(value) = metadata.acquisition.get(key) {
                    println!("{label}: {value}");
                }
            }
            println!(
                "Acquisition error ranges: {}",
                metadata.acquisition_errors.len()
            );
            println!("Run 'inodex verify' to validate every chunk and stored media digest.");
        }
        "verify" => {
            let report = image.verify()?;
            println!(
                "Verified {} bytes (all chunk checksums passed)",
                report.bytes_read
            );
            println!(
                "MD5: {} ({})",
                hex(&report.md5),
                if report.md5_verified {
                    "matches acquisition digest"
                } else {
                    "computed; no stored digest"
                }
            );
            println!(
                "SHA1: {} ({})",
                hex(&report.sha1),
                if report.sha1_verified {
                    "matches acquisition digest"
                } else {
                    "computed; no stored digest"
                }
            );
            if !image.metadata().acquisition_errors.is_empty() {
                println!(
                    "Acquisition reported {} unreadable sector ranges.",
                    image.metadata().acquisition_errors.len()
                );
            }
        }
        "export" => {
            let path = Path::new(&args[2]);
            let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
            let result = (|| -> Result<u64, Box<dyn std::error::Error>> {
                let report = image.export_to(&mut output)?;
                output.flush()?;
                Ok(report.bytes_read)
            })();
            drop(output);
            match result {
                Ok(written) => println!("Exported {written} verified bytes to {}", path.display()),
                Err(error) => {
                    // This file was created exclusively by this invocation.
                    if let Err(cleanup) = fs::remove_file(path) {
                        eprintln!(
                            "Could not remove incomplete export {}: {cleanup}",
                            path.display()
                        );
                    }
                    return Err(error);
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn generic(
    command: &str,
    mut image: Image,
    args: &[std::ffi::OsString],
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        "info" => {
            println!("Format: {}", image.kind());
            if let Some(root) = image.logical_root() {
                println!("Root: {}", root.display());
            } else {
                println!(
                    "Media size: {} bytes\nSector size: {} bytes",
                    image.len(),
                    image.sector_size()
                );
                if let Image::Aff(a) = &image {
                    if let Some(h) = a.stored_md5()? {
                        println!("Stored MD5: {}", hex(&h));
                    }
                    if let Some(h) = a.stored_sha1()? {
                        println!("Stored SHA1: {}", hex(&h));
                    }
                }
            }
        }
        "verify" => {
            let report = image.verify()?;
            println!("Read and checked {} decoded bytes", report.bytes_read);
            println!(
                "MD5: {} ({})",
                hex(&report.md5),
                if report.md5_verified {
                    "matches stored digest"
                } else {
                    "computed; no stored digest"
                }
            );
            println!(
                "SHA1: {} ({})",
                hex(&report.sha1),
                if report.sha1_verified {
                    "matches stored digest"
                } else {
                    "computed; no stored digest"
                }
            );
        }
        "export" => {
            if image.logical_root().is_some() {
                return Err("logical directories have no disk stream; use file extraction".into());
            }
            let path = Path::new(&args[2]);
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            let result = (|| -> Result<u64, Box<dyn std::error::Error>> {
                let report = image.export_to(&mut file)?;
                file.flush()?;
                Ok(report.bytes_read)
            })();
            drop(file);
            match result {
                Ok(n) => println!("Exported {n} decoded bytes to {}", path.display()),
                Err(e) => {
                    if let Err(cleanup) = fs::remove_file(path) {
                        eprintln!(
                            "Could not remove incomplete export {}: {cleanup}",
                            path.display()
                        );
                    }
                    return Err(e);
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("inodex: {error}");
            ExitCode::FAILURE
        }
    }
}
