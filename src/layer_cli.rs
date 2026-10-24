use inodex::{
    filesystem::{FileKind, FileSystem, Limits, apfs},
    image::{DiskImage, Image, Volume},
    partition::PartitionTable,
};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Default)]
struct Options {
    positional: Vec<OsString>,
    partition: Option<u32>,
    offset: Option<u64>,
    length: Option<u64>,
    sector_size: Option<u32>,
    json: bool,
    stream: Option<String>,
    apfs_volume: Option<u64>,
    apfs_snapshot: Option<u64>,
    id: Option<u64>,
    start: Option<u64>,
    count: Option<usize>,
    scan_bytes: Option<usize>,
    unlock: Option<(String, std::path::PathBuf)>,
}
fn parse(args: &[OsString]) -> Result<Options> {
    let mut options = Options::default();
    let mut index = 0;
    let mut literal = false;
    while index < args.len() {
        let option = args[index].to_str().unwrap_or("");
        if !literal && option == "--" {
            literal = true;
            index += 1;
            continue;
        }
        if !literal && option == "--json" {
            options.json = true;
            index += 1;
            continue;
        }
        if !literal && option.starts_with("--") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {option}"))?
                .to_str()
                .ok_or("option value must be UTF-8")?;
            match option {
                "--apfs-snapshot" => {
                    if options.apfs_snapshot.replace(value.parse()?).is_some() {
                        return Err("duplicate --apfs-snapshot".into());
                    }
                }
                "--id" => {
                    if options.id.replace(value.parse()?).is_some() {
                        return Err("duplicate --id".into());
                    }
                }
                "--start" => {
                    if options.start.replace(value.parse()?).is_some() {
                        return Err("duplicate --start".into());
                    }
                }
                "--count" => {
                    if options.count.replace(value.parse()?).is_some() {
                        return Err("duplicate --count".into());
                    }
                }
                "--scan-bytes" => {
                    if options.scan_bytes.replace(value.parse()?).is_some() {
                        return Err("duplicate --scan-bytes".into());
                    }
                }
                "--bitlocker-password-file"
                | "--bitlocker-recovery-file"
                | "--bitlocker-vmk-file"
                | "--bitlocker-fvek-file" => {
                    if options
                        .unlock
                        .replace((option.into(), value.into()))
                        .is_some()
                    {
                        return Err("choose one BitLocker credential source".into());
                    }
                }
                "--apfs-volume" => {
                    if options.apfs_volume.is_some() {
                        return Err("duplicate --apfs-volume".into());
                    }
                    options.apfs_volume = Some(value.parse()?);
                }
                "--partition" => {
                    if options.partition.is_some() {
                        return Err("duplicate --partition".into());
                    }
                    options.partition = Some(value.parse()?);
                }
                "--offset" => {
                    if options.offset.is_some() {
                        return Err("duplicate --offset".into());
                    }
                    options.offset = Some(value.parse()?);
                }
                "--length" => {
                    if options.length.is_some() {
                        return Err("duplicate --length".into());
                    }
                    options.length = Some(value.parse()?);
                }
                "--sector-size" => {
                    if options.sector_size.is_some() {
                        return Err("duplicate --sector-size".into());
                    }
                    options.sector_size = Some(value.parse()?);
                }
                "--stream" => {
                    if options.stream.is_some() {
                        return Err("duplicate --stream".into());
                    }
                    options.stream = Some(value.into());
                }
                _ => return Err(format!("unknown option {option}").into()),
            }
            index += 2;
        } else {
            options.positional.push(args[index].clone());
            index += 1;
        }
    }
    if options.partition.is_some() && (options.offset.is_some() || options.length.is_some()) {
        return Err("use --partition or --offset/--length".into());
    }
    Ok(options)
}
pub fn run(command: &str, args: &[OsString]) -> Result<()> {
    let options = parse(args)?;
    let valid_count = match command {
        "recover" | "decrypt" => options.positional.len() == 2,
        "security" | "ntfs-details" => (1..=2).contains(&options.positional.len()),
        "ls" => (1..=2).contains(&options.positional.len()),
        "stat" => options.positional.len() == 2,
        "extract" => options.positional.len() == 3,
        _ => options.positional.len() == 1,
    };
    if !valid_count {
        return Err("invalid arguments; run inodex --help".into());
    }
    if !["extract", "recover", "deleted"].contains(&command) && options.stream.is_some() {
        return Err("--stream is an extraction option".into());
    }
    if ["extract", "recover", "decrypt"].contains(&command) && options.json {
        return Err("--json is unavailable for extraction".into());
    }
    if options.id.is_some() && !["recover", "security", "ntfs-details"].contains(&command) {
        return Err("--id requires recover, security, or ntfs-details".into());
    }
    if (options.start.is_some() || options.count.is_some())
        && !["deleted", "usn"].contains(&command)
    {
        return Err("scan pagination requires deleted or usn".into());
    }
    if options.scan_bytes.is_some() && command != "usn" {
        return Err("--scan-bytes requires usn".into());
    }
    if command == "recover" && options.id.is_none() {
        return Err("recover requires --id from deleted-record scan".into());
    }
    let path = Path::new(&options.positional[0]);
    let mut image = Image::open(path)?;
    if image.logical_root().is_some()
        && (options.partition.is_some()
            || options.offset.is_some()
            || options.length.is_some()
            || options.apfs_volume.is_some()
            || options.apfs_snapshot.is_some()
            || options.unlock.is_some()
            || !["fs-info", "ls", "stat", "extract"].contains(&command))
    {
        return Err(
            "logical directories support filesystem operations without partition/container offsets"
                .into(),
        );
    }
    if let Some(sector_size) = options.sector_size {
        image.set_sector_size(sector_size)?;
    }
    if command == "partitions" {
        if options.unlock.is_some() {
            return Err(
                "BitLocker unlock applies to a selected volume, not partition discovery".into(),
            );
        }
        if options.apfs_volume.is_some() || options.apfs_snapshot.is_some() {
            return Err("--apfs-volume requires an APFS filesystem command".into());
        }
        if options.partition.is_some() || options.offset.is_some() || options.length.is_some() {
            return Err("partition discovery operates on the whole image".into());
        }
        let table = PartitionTable::read(&mut image)?;
        if options.json {
            println!("{}", serde_json::to_string_pretty(&table)?);
        } else if let Some(table) = table {
            println!(
                "{:?} partition table ({} bytes per sector)",
                table.scheme, table.sector_size
            );
            println!("Index\tStart LBA\tSectors\tKind\tName");
            for part in table.partitions {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    part.index,
                    part.start_lba,
                    part.sectors,
                    if part.is_container {
                        "extended"
                    } else if part.is_logical {
                        "logical"
                    } else {
                        "partition"
                    },
                    part.name
                );
            }
        } else {
            println!("No partition table detected; the image may contain a filesystem directly.");
        }
        return Ok(());
    }
    let mut volume = if let Some(index) = options.partition {
        let table = PartitionTable::read(&mut image)?.ok_or("no partition table detected")?;
        table.get(index)?.volume(&mut image)?
    } else {
        let offset = options.offset.unwrap_or(0);
        let size = options
            .length
            .unwrap_or_else(|| image.len().saturating_sub(offset));
        Volume::new(&mut image, offset, size)?
    };
    let secret = if let Some((_, path)) = &options.unlock {
        let input = std::fs::File::open(path)?;
        if input.metadata()?.len() > 4096 {
            return Err("BitLocker credential file exceeds 4096 bytes".into());
        }
        let mut value = zeroize::Zeroizing::new(vec![]);
        use std::io::Read;
        input.take(4097).read_to_end(&mut value)?;
        if value.len() > 4096 {
            return Err("BitLocker credential file exceeds 4096 bytes".into());
        }
        Some(value)
    } else {
        None
    };
    let mut decrypted = if let Some((kind, _)) = &options.unlock {
        use inodex::bitlocker::{BitLocker, Credential};
        let value = secret.as_ref().unwrap();
        let credential = match kind.as_str() {
            "--bitlocker-password-file" => {
                Credential::Password(std::str::from_utf8(value)?.trim_end_matches(['\r', '\n']))
            }
            "--bitlocker-recovery-file" => Credential::RecoveryPassword(
                std::str::from_utf8(value)?.trim_end_matches(['\r', '\n']),
            ),
            "--bitlocker-vmk-file" => Credential::Vmk(value),
            _ => Credential::Fvek(value),
        };
        Some(BitLocker::open(&mut volume, credential)?)
    } else {
        None
    };
    let volume: &mut dyn DiskImage = if let Some(view) = decrypted.as_mut() {
        view
    } else {
        &mut volume
    };
    if command == "decrypt" {
        if options.unlock.is_none() {
            return Err("decrypt requires a BitLocker credential file".into());
        }
        let destination = Path::new(&options.positional[1]);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let result = (|| -> Result<()> {
            let mut at = 0;
            let mut buffer = [0; 65536];
            while at < volume.len() {
                let size = (volume.len() - at).min(buffer.len() as u64) as usize;
                volume.read_exact_at(at, &mut buffer[..size])?;
                output.write_all(&buffer[..size])?;
                at += size as u64;
            }
            output.flush()?;
            Ok(())
        })();
        drop(output);
        if let Err(error) = result {
            fs::remove_file(destination)?;
            return Err(error);
        }
        println!(
            "Exported {} decrypted bytes to {}",
            volume.len(),
            destination.display()
        );
        return Ok(());
    }
    if command == "apfs-volumes" || command == "apfs-snapshots" {
        if options.apfs_snapshot.is_some() {
            return Err("snapshot selection is unavailable while listing".into());
        }
        if command == "apfs-snapshots" {
            println!(
                "{}",
                serde_json::to_string_pretty(&apfs::snapshots(
                    volume,
                    Limits::default(),
                    options.apfs_volume
                )?)?
            );
            return Ok(());
        }
        if options.apfs_volume.is_some() {
            return Err("volume selection is unavailable while listing volumes".into());
        }
        let volumes = apfs::volumes(volume, Limits::default())?;
        if options.json {
            println!("{}", serde_json::to_string_pretty(&volumes)?);
        } else {
            for v in volumes {
                println!(
                    "{}\t{}\t{}",
                    v.oid,
                    if v.encrypted {
                        "encrypted"
                    } else {
                        "unencrypted"
                    },
                    v.name
                );
            }
        }
        return Ok(());
    }
    let mut fs = if let Some(xid) = options.apfs_snapshot {
        FileSystem::Indexed(apfs::open_snapshot(
            volume,
            Limits::default(),
            options.apfs_volume,
            xid,
        )?)
    } else if let Some(oid) = options.apfs_volume {
        FileSystem::Indexed(apfs::open_volume(volume, Limits::default(), Some(oid))?)
    } else {
        FileSystem::open(volume)?
    };
    if command == "deleted" {
        println!(
            "{}",
            serde_json::to_string_pretty(&fs.deleted_records(
                options.start.unwrap_or(0),
                options.count.unwrap_or(1000),
                options.stream.as_deref()
            )?)?
        );
        return Ok(());
    }
    if command == "usn" {
        println!(
            "{}",
            serde_json::to_string_pretty(&fs.usn_journal(
                options.start.unwrap_or(0),
                options.scan_bytes.unwrap_or(1024 * 1024),
                options.count.unwrap_or(1000)
            )?)?
        );
        return Ok(());
    }
    if command == "logfile-info" {
        println!("{}", serde_json::to_string_pretty(&fs.logfile_info()?)?);
        return Ok(());
    }
    if command == "fs-info" {
        if options.json {
            println!("{}", serde_json::to_string_pretty(fs.info())?);
        } else {
            let info = fs.info();
            println!(
                "Filesystem: {:?}\nLabel: {}\nBlock size: {}\nVolume size: {}\nRoot ID: {}\nJournal recovery required: {}",
                info.filesystem,
                info.label,
                info.block_size,
                info.total_bytes,
                info.root_id,
                info.needs_journal_recovery
            );
        }
        return Ok(());
    }
    let internal_path = options
        .positional
        .get(1)
        .map(|p| p.to_str().ok_or("filesystem paths must be UTF-8"))
        .transpose()?
        .unwrap_or("/");
    let id = if let Some(id) = options.id {
        if options.positional.len() > 1 && ["security", "ntfs-details"].contains(&command) {
            return Err("choose a path or --id".into());
        }
        id
    } else {
        fs.resolve(internal_path)?
    };
    match command {
        "ls" => {
            let entries = fs.read_dir(id)?;
            if options.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for entry in entries {
                    let kind = match entry.kind {
                        FileKind::Directory => 'd',
                        FileKind::File => 'f',
                        FileKind::Symlink => 'l',
                        FileKind::Other => '?',
                    };
                    println!("{kind}\t{}\t{}\t{}", entry.id, entry.size, entry.name);
                }
            }
        }
        "stat" => {
            println!("{}", serde_json::to_string_pretty(&fs.metadata(id)?)?);
        }
        "security" => {
            println!("{}", serde_json::to_string_pretty(&fs.security(id)?)?);
        }
        "ntfs-details" => {
            println!("{}", serde_json::to_string_pretty(&fs.ntfs_details(id)?)?);
        }
        "extract" | "recover" => {
            let destination =
                Path::new(&options.positional[if command == "recover" { 1 } else { 2 }]);
            if let FileSystem::Logical(logical) = &fs
                && destination
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .canonicalize()?
                    .starts_with(logical.root())
            {
                return Err("extraction output must be outside the logical evidence root".into());
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            let result = (|| -> Result<u64> {
                let size = if command == "recover" {
                    fs.recover_file(id, options.stream.as_deref(), &mut output)?
                } else {
                    fs.copy_file(id, options.stream.as_deref(), &mut output)?
                };
                output.flush()?;
                Ok(size)
            })();
            drop(output);
            match result {
                Ok(size) => println!("Extracted {size} bytes to {}", destination.display()),
                Err(error) => {
                    if let Err(cleanup) = fs::remove_file(destination) {
                        eprintln!(
                            "Could not remove partial extraction {}: {cleanup}",
                            destination.display()
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
