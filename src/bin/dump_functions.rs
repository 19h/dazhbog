use chrono::{DateTime, Utc};
use std::{fs, io, path::PathBuf};

const MAGIC: u32 = 0x4C4D4E31;

struct Args {
    limit: usize,
    dump_dir: Option<PathBuf>,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut limit = 10usize;
    let mut dump_dir = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--dump" => {
                // --dump <count> [dir]
                i += 1;
                if i < args.len() {
                    limit = args[i].parse().unwrap_or(2000);
                }
                i += 1;
                if i < args.len() && !args[i].starts_with("--") {
                    dump_dir = Some(PathBuf::from(&args[i]));
                } else {
                    dump_dir = Some(PathBuf::from("analysis/data"));
                    i -= 1; // didn't consume this arg
                }
            }
            "--help" | "-h" => {
                println!("Usage: dump_functions [OPTIONS]");
                println!();
                println!("Options:");
                println!("  <count>              Display this many function records (default: 10)");
                println!("  --dump <count> [dir] Dump <count> metadata payloads to <dir>");
                println!("                       Default: --dump 2000 analysis/data");
                println!("  --help, -h           Show this help message");
                std::process::exit(0);
            }
            arg => {
                // Legacy: first positional arg is limit
                if let Ok(n) = arg.parse::<usize>() {
                    limit = n;
                }
            }
        }
        i += 1;
    }

    Args { limit, dump_dir }
}

mod crc32c_impl {
    use std::sync::Once;

    const POLY_REFLECTED: u32 = 0x82F63B78;

    static INIT_REF: Once = Once::new();
    static mut TABLE_REF: [u32; 256] = [0; 256];

    fn init_reflected() {
        unsafe {
            for i in 0..256 {
                let mut crc = i as u32;
                for _ in 0..8 {
                    if (crc & 1) != 0 {
                        crc = (crc >> 1) ^ POLY_REFLECTED;
                    } else {
                        crc >>= 1;
                    }
                }
                TABLE_REF[i] = crc;
            }
        }
    }

    pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
        INIT_REF.call_once(init_reflected);
        crc = !crc;
        for &b in data {
            let idx = (crc ^ (b as u32)) & 0xFF;
            let t = unsafe { TABLE_REF[idx as usize] };
            crc = (crc >> 8) ^ t;
        }
        !crc
    }
}

#[derive(Clone)]
struct Record {
    key: u128,
    ts_sec: u64,
    prev_addr: u64,
    len_bytes: u32,
    popularity: u32,
    name: String,
    data: Vec<u8>,
    flags: u8,
}

fn scan_segment_tree(tree: &sled::Tree, limit: usize) -> io::Result<Vec<(u64, Record)>> {
    let mut records = Vec::new();
    let mut count = 0;

    for item in tree.iter() {
        if count >= limit {
            break;
        }

        let (offset_bytes, record_bytes) = match item {
            Ok(i) => i,
            Err(e) => {
                eprintln!("Error iterating tree: {}", e);
                continue;
            }
        };

        let off = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());

        if record_bytes.len() < 12 {
            continue;
        }
        let hdr: &[u8] = &record_bytes[0..12];

        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != MAGIC {
            continue;
        }

        let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if rec_len != record_bytes.len() {
            continue;
        }

        let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let body = &record_bytes[12..];

        // Verify CRC
        let computed_crc = crc32c_impl::crc32c(0, body);
        if computed_crc != stored_crc {
            continue;
        }

        // Parse record
        if body.len() < 52 {
            continue;
        }

        let p = body;
        let lo = u64::from_le_bytes(p[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(p[8..16].try_into().unwrap());
        let key = ((hi as u128) << 64) | (lo as u128);
        let ts_sec = u64::from_le_bytes(p[16..24].try_into().unwrap());
        let prev_addr = u64::from_le_bytes(p[24..32].try_into().unwrap());
        let len_bytes = u32::from_le_bytes(p[32..36].try_into().unwrap());
        let popularity = u32::from_le_bytes(p[36..40].try_into().unwrap());
        let name_len = u16::from_le_bytes(p[40..42].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(p[42..46].try_into().unwrap()) as usize;
        let flags = p[46];

        let name_start = 52;
        if name_start + name_len + data_len > body.len() {
            continue;
        }

        let name = match std::str::from_utf8(&p[name_start..name_start + name_len]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let data_start = name_start + name_len;
        let data = p[data_start..data_start + data_len].to_vec();

        let rec = Record {
            key,
            ts_sec,
            prev_addr,
            len_bytes,
            popularity,
            name,
            data,
            flags,
        };

        records.push((off, rec));
        count += 1;
    }

    Ok(records)
}

fn print_hexdump(data: &[u8], max_bytes: usize) {
    let bytes_to_show = std::cmp::min(data.len(), max_bytes);

    for (i, chunk) in data[..bytes_to_show].chunks(16).enumerate() {
        let offset = i * 16;
        print!("  {:08x}  ", offset);

        // Print hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                print!("   ");
                if j == 7 {
                    print!(" ");
                }
            }
        }

        print!(" |");

        // Print ASCII representation
        for byte in chunk {
            let ch = if *byte >= 0x20 && *byte <= 0x7e {
                *byte as char
            } else {
                '.'
            };
            print!("{}", ch);
        }

        println!("|");
    }

    if data.len() > max_bytes {
        println!("  ... ({} more bytes)", data.len() - max_bytes);
    }
}

fn print_record(idx: usize, offset: u64, rec: &Record) {
    let dt = DateTime::<Utc>::from_timestamp(rec.ts_sec as i64, 0)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ FUNCTION #{:<2}                                                              │",
        idx + 1
    );
    println!("├─────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ Key (MD5):     {:032x}                                    │",
        rec.key
    );
    println!("│ Name:          {:<60} │", truncate_string(&rec.name, 60));
    println!(
        "│ Offset:        0x{:016x}                                          │",
        offset
    );
    println!(
        "│ Timestamp:     {} ({})",
        dt.format("%Y-%m-%d %H:%M:%S UTC"),
        rec.ts_sec
    );
    println!("│ Popularity:    {:<60} │", rec.popularity);
    println!("│ Declared size: {} bytes{:<51} │", rec.len_bytes, "");
    println!("│ Data Size:     {} bytes{:<51} │", rec.data.len(), "");
    println!("│ Prev Address:  0x{:016x}{:<42} │", rec.prev_addr, "");
    println!(
        "│ Flags:         0x{:02x} {}                    │",
        rec.flags,
        if rec.flags & 0x01 != 0 {
            "(TOMBSTONE)"
        } else {
            "(ACTIVE)    "
        }
    );
    println!("├─────────────────────────────────────────────────────────────────────────────┤");
    println!("│ DATA HEXDUMP:                                                               │");
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    print_hexdump(&rec.data, 256);
    println!();
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:<width$}", s, width = max_len)
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn dump_metadata_to_disk(
    records: &[(u64, Record)],
    dump_dir: &PathBuf,
) -> io::Result<(usize, usize)> {
    fs::create_dir_all(dump_dir)?;

    let mut dumped = 0;
    let mut skipped = 0;

    for (idx, (offset, rec)) in records.iter().enumerate() {
        if rec.data.is_empty() {
            skipped += 1;
            continue;
        }

        // Create a meaningful filename: index_key_name.bin
        let safe_name: String = rec
            .name
            .chars()
            .take(40)
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let filename = format!(
            "{:05}_{:032x}_{}.bin",
            idx,
            rec.key,
            if safe_name.is_empty() {
                "unknown"
            } else {
                &safe_name
            }
        );

        let filepath = dump_dir.join(&filename);
        fs::write(&filepath, &rec.data)?;

        // Also write a companion .json file with metadata
        let json = format!(
            r#"{{
  "index": {},
  "key": "{:032x}",
  "name": {:?},
  "offset": {},
  "timestamp": {},
  "popularity": {},
  "flags": {},
  "data_len": {},
  "len_bytes": {}
}}"#,
            idx,
            rec.key,
            rec.name,
            offset,
            rec.ts_sec,
            rec.popularity,
            rec.flags,
            rec.data.len(),
            rec.len_bytes
        );

        let json_filename = format!(
            "{:05}_{:032x}_{}.json",
            idx,
            rec.key,
            if safe_name.is_empty() {
                "unknown"
            } else {
                &safe_name
            }
        );
        let json_filepath = dump_dir.join(&json_filename);
        fs::write(&json_filepath, json)?;

        dumped += 1;

        if dumped % 500 == 0 {
            println!("  Dumped {} records...", dumped);
        }
    }

    Ok((dumped, skipped))
}

fn main() -> io::Result<()> {
    let args = parse_args();

    let data_dir = PathBuf::from("data");
    let seg_db_dir = data_dir.join("segments_db");

    if !seg_db_dir.exists() {
        eprintln!("Error: data/segments_db directory not found.");
        eprintln!("Run the main dazhbog server first to create the database.");
        std::process::exit(1);
    }

    let is_dump_mode = args.dump_dir.is_some();

    if !is_dump_mode {
        println!("╔═════════════════════════════════════════════════════════════════════════════╗");
        println!("║           DAZHBOG FUNCTION METADATA VIEWER                                  ║");
        println!("╚═════════════════════════════════════════════════════════════════════════════╝");
        println!();
    }

    let db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    let mut tree_names: Vec<_> = db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();

    tree_names.sort();

    if tree_names.is_empty() {
        println!("No segment trees found in the database.");
        return Ok(());
    }

    let mut total_records = 0;
    let mut records_to_display = Vec::new();

    for name in tree_names {
        let tree = db
            .open_tree(&name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {}", e)))?;

        let remaining = args.limit.saturating_sub(records_to_display.len());
        if remaining == 0 {
            break;
        }

        match scan_segment_tree(&tree, remaining) {
            Ok(records) => {
                for record in records {
                    records_to_display.push(record);
                    if records_to_display.len() >= args.limit {
                        break;
                    }
                }
                total_records += tree.len();
            }
            Err(e) => {
                eprintln!("Error scanning tree {}: {}", name, e);
            }
        }
    }

    if let Some(ref dump_dir) = args.dump_dir {
        // Dump mode
        println!(
            "Dumping {} function metadata payloads to {:?}...",
            records_to_display.len(),
            dump_dir
        );

        let (dumped, skipped) = dump_metadata_to_disk(&records_to_display, dump_dir)?;

        println!();
        println!("Dump complete:");
        println!("  Directory: {:?}", dump_dir);
        println!("  Total records in database: {}", total_records);
        println!("  Records dumped: {}", dumped);
        println!("  Records skipped (empty data): {}", skipped);
        println!();
        println!("Each record generates two files:");
        println!("  - *.bin: Raw metadata payload");
        println!("  - *.json: Associated metadata (key, name, timestamp, etc.)");
    } else {
        // Display mode
        println!("Database Statistics:");
        println!("  Total records in database: {}", total_records);
        println!("  Displaying: {} function(s)", records_to_display.len());
        println!();

        for (idx, (offset, record)) in records_to_display.iter().enumerate() {
            print_record(idx, *offset, record);
        }

        println!("╔═════════════════════════════════════════════════════════════════════════════╗");
        println!("║                               END OF DUMP                                   ║");
        println!("╚═════════════════════════════════════════════════════════════════════════════╝");
    }

    Ok(())
}
