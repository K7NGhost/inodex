//! Minimal library consumer: emit owned directory-entry/metadata records as NDJSON.
//! Usage: cargo run --example library_ingest -- IMAGE [PARTITION_NUMBER]
use inodex::{
    filesystem::{FileKind, FileSystem},
    image::Image,
    partition::PartitionTable,
};
use std::{
    collections::HashSet,
    io::{self, Write},
};

fn enumerate(fs: &mut FileSystem<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let root = fs.info().root_id;
    let mut pending = vec![(root, String::new())];
    let mut visited = HashSet::new();
    let mut output = io::BufWriter::new(io::stdout().lock());
    while let Some((parent, path)) = pending.pop() {
        if !visited.insert(parent) {
            continue;
        }
        for entry in fs.read_dir(parent)? {
            let display_path = format!("{path}/{}", entry.name);
            let metadata = fs.metadata(entry.id)?;
            serde_json::to_writer(
                &mut output,
                &serde_json::json!({
                    "path":display_path,"parent_id":parent,"entry":entry,"metadata":metadata
                }),
            )?;
            output.write_all(b"\n")?;
            if entry.kind == FileKind::Directory {
                pending.push((entry.id, display_path));
            }
        }
    }
    output.flush()?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("usage: library_ingest IMAGE [PARTITION_NUMBER]")?;
    let partition = args
        .next()
        .map(|v| {
            v.to_str()
                .ok_or("partition must be UTF-8")?
                .parse::<u32>()
                .map_err(|_| "invalid partition")
        })
        .transpose()?;
    if args.next().is_some() {
        return Err("usage: library_ingest IMAGE [PARTITION_NUMBER]".into());
    }
    let mut image = Image::open(path)?;
    if let Some(index) = partition {
        let table = PartitionTable::read(&mut image)?.ok_or("source has no partition table")?;
        let mut volume = table.get(index)?.volume(&mut image)?;
        enumerate(&mut FileSystem::open(&mut volume)?)
    } else {
        enumerate(&mut FileSystem::open(&mut image)?)
    }
}
