use dazhbog::config::{Config, Engine};
use dazhbog::engine::{migrate_legacy_index_files, OpenSegments, ShardedIndex};

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

struct Args {
    config_path: PathBuf,
    output_path: PathBuf,
    all_versions: bool,
    unique: bool,
    include_key: bool,
}

struct DumpStats {
    written: u64,
    skipped_deleted: u64,
    skipped_duplicates: u64,
    read_errors: u64,
}

fn print_usage(program: &str) {
    println!("Usage: {program} [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config <path>      Config file path (default: config.toml)");
    println!("  --output <path>      Output text file (default: function_names.txt)");
    println!("  --all-versions       Dump every non-deleted record version");
    println!("  --unique             Keep only the first occurrence of each name");
    println!("  --include-key        Prefix each line with the 128-bit function key");
    println!("  --help, -h           Show this help message");
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> io::Result<String> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn parse_args() -> io::Result<Args> {
    let args: Vec<String> = std::env::args().collect();
    let program = args
        .first()
        .map(String::as_str)
        .unwrap_or("dump_function_names");

    let mut parsed = Args {
        config_path: PathBuf::from("config.toml"),
        output_path: PathBuf::from("function_names.txt"),
        all_versions: false,
        unique: false,
        include_key: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                parsed.config_path = PathBuf::from(take_value(&args, &mut i, "--config")?);
            }
            "--output" => {
                parsed.output_path = PathBuf::from(take_value(&args, &mut i, "--output")?);
            }
            "--all-versions" => parsed.all_versions = true,
            "--unique" => parsed.unique = true,
            "--include-key" => parsed.include_key = true,
            "--help" | "-h" => {
                print_usage(program);
                std::process::exit(0);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {other}"),
                ));
            }
        }
        i += 1;
    }

    Ok(parsed)
}

fn open_storage(engine: &Engine) -> io::Result<(OpenSegments, ShardedIndex)> {
    let data_dir = PathBuf::from(&engine.data_dir);
    if !data_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("data directory not found: {}", data_dir.display()),
        ));
    }

    let segments = OpenSegments::open(&data_dir, engine.segment_bytes, engine.use_mmap_reads)?;

    let index_dir = engine
        .index_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("index"));
    std::fs::create_dir_all(&index_dir)?;
    migrate_legacy_index_files(&index_dir)?;

    let index_db = sled::Config::default()
        .path(&index_dir)
        .cache_capacity(64 * 1024 * 1024)
        .flush_every_ms(Some(500))
        .open()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open index db: {e}")))?;

    let index = ShardedIndex::new(&index_db)?;
    if index.is_empty()? {
        segments.rebuild_index(&index)?;
    }

    Ok((segments, index))
}

fn write_line<W: Write>(
    writer: &mut W,
    include_key: bool,
    key: u128,
    name: &str,
) -> io::Result<()> {
    if include_key {
        writeln!(writer, "{key:032x} {name}")
    } else {
        writeln!(writer, "{name}")
    }
}

fn main() -> io::Result<()> {
    let args = parse_args()?;
    let config_path = args.config_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-utf8 config path: {}", args.config_path.display()),
        )
    })?;

    let cfg = Config::load(config_path)?;
    let (segments, index) = open_storage(&cfg.engine)?;

    if let Some(parent) = args.output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let file = File::create(&args.output_path)?;
    let mut writer = BufWriter::new(file);
    let mut seen_names = args.unique.then(HashSet::new);
    let mut stats = DumpStats {
        written: 0,
        skipped_deleted: 0,
        skipped_duplicates: 0,
        read_errors: 0,
    };

    if args.all_versions {
        segments.for_each_record(|_, _, rec| {
            if rec.flags & 0x01 == 0x01 {
                stats.skipped_deleted += 1;
                return Ok(());
            }

            if let Some(seen) = seen_names.as_mut() {
                if !seen.insert(rec.name.clone()) {
                    stats.skipped_duplicates += 1;
                    return Ok(());
                }
            }

            write_line(&mut writer, args.include_key, rec.key, &rec.name)?;
            stats.written += 1;
            Ok(())
        })?;
    } else {
        for (key, addr) in index.iter_keys() {
            match segments.read_record(addr) {
                Ok(rec) => {
                    if rec.flags & 0x01 == 0x01 {
                        stats.skipped_deleted += 1;
                        continue;
                    }

                    if let Some(seen) = seen_names.as_mut() {
                        if !seen.insert(rec.name.clone()) {
                            stats.skipped_duplicates += 1;
                            continue;
                        }
                    }

                    write_line(&mut writer, args.include_key, key, &rec.name)?;
                    stats.written += 1;
                }
                Err(e) => {
                    stats.read_errors += 1;
                    eprintln!("warning: failed to read {:032x}: {}", key, e);
                }
            }
        }
    }

    writer.flush()?;

    println!(
        "Wrote {} names to {}",
        stats.written,
        args.output_path.display()
    );
    if stats.skipped_deleted > 0 {
        println!("Skipped {} deleted records", stats.skipped_deleted);
    }
    if stats.skipped_duplicates > 0 {
        println!("Skipped {} duplicate names", stats.skipped_duplicates);
    }
    if stats.read_errors > 0 {
        println!("Encountered {} read errors", stats.read_errors);
    }

    Ok(())
}
