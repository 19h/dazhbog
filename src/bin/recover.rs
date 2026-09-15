use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::time::Instant;
use std::{io, path::PathBuf};

const MAGIC: u32 = 0x4C4D4E31;
const RECOVER_SEG_BYTES: u64 = 1024 * 1024 * 1024;

// ═══════════════════════════════════════════════════════════════════════════
// Progress Reporting
// ═══════════════════════════════════════════════════════════════════════════

struct Progress {
    name: String,
    total: u64,
    current: u64,
    start: Instant,
    last_print: Instant,
    print_interval_ms: u128,
}

impl Progress {
    fn new(name: &str, total: u64) -> Self {
        let now = Instant::now();
        Self {
            name: name.to_string(),
            total,
            current: 0,
            start: now,
            last_print: now,
            print_interval_ms: 100,
        }
    }

    fn inc(&mut self, n: u64) {
        self.current += n;
        let now = Instant::now();
        if now.duration_since(self.last_print).as_millis() >= self.print_interval_ms {
            self.print();
            self.last_print = now;
        }
    }

    #[allow(dead_code)]
    fn set(&mut self, n: u64) {
        self.current = n;
        let now = Instant::now();
        if now.duration_since(self.last_print).as_millis() >= self.print_interval_ms {
            self.print();
            self.last_print = now;
        }
    }

    fn print(&self) {
        let pct = if self.total > 0 {
            (self.current as f64 / self.total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let elapsed = self.start.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            self.current as f64 / elapsed
        } else {
            0.0
        };
        let eta = if rate > 0.0 && self.current < self.total {
            let remaining = self.total - self.current;
            remaining as f64 / rate
        } else {
            0.0
        };

        print!(
            "\r  {} [{:>6.2}%] {:>12} / {:>12} | {:>10.0}/s | ETA: {:>6.1}s",
            self.name,
            pct,
            fmt_num(self.current),
            fmt_num(self.total),
            rate,
            eta
        );
        let _ = std::io::stdout().flush();
    }

    fn finish(&self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            self.current as f64 / elapsed
        } else {
            0.0
        };
        println!(
            "\r  {} [100.00%] {:>12} / {:>12} | {:>10.0}/s | Done in {:.2}s",
            self.name,
            fmt_num(self.current),
            fmt_num(self.total),
            rate,
            elapsed
        );
    }

    #[allow(dead_code)]
    fn finish_with(&self, msg: &str) {
        let elapsed = self.start.elapsed().as_secs_f64();
        println!(
            "\r  {} {:>12} {} in {:.2}s                              ",
            self.name,
            fmt_num(self.current),
            msg,
            elapsed
        );
    }
}

fn fmt_num(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

fn log_info(msg: &str) {
    println!("[INFO]  {}", msg);
}

fn log_step(step: u32, total: u32, msg: &str) {
    println!("\n[{}/{}] {}", step, total, msg);
    println!("{}", "─".repeat(60));
}

/// Pack segment ID, offset, and flags into a single 64-bit address.
const fn pack_addr(seg_id: u16, offset: u64, flags: u8) -> u64 {
    ((seg_id as u64) << 48) | ((offset & ((1u64 << 40) - 1)) << 8) | (flags as u64)
}

mod crc32c_impl {
    pub use dazhbog::common::hash::{crc32c, crc32c_legacy};
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

#[allow(dead_code)]
fn scan_segment_tree(tree: &sled::Tree) -> io::Result<Vec<(u64, Record)>> {
    let mut records = Vec::new();
    println!(
        "Scanning tree {} ({} records)",
        String::from_utf8_lossy(&tree.name()),
        tree.len()
    );

    for item in tree.iter() {
        let (offset_bytes, record_bytes) = match item {
            Ok(i) => i,
            Err(e) => {
                eprintln!("  Error iterating tree: {}", e);
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
            eprintln!("  Skipping record at offset {} (bad magic)", off);
            continue;
        }

        let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if rec_len != record_bytes.len() {
            eprintln!("  Skipping record at offset {} (length mismatch)", off);
            continue;
        }

        let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let body = &record_bytes[12..];

        // Verify CRC
        let computed_crc = crc32c_impl::crc32c(0, body);
        let crc_valid = if computed_crc == stored_crc {
            true
        } else {
            let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
            computed_crc_legacy == stored_crc
        };

        if !crc_valid {
            println!("  Skipping corrupt record at offset {}", off);
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
    }

    println!("  Found {} valid records", records.len());
    Ok(records)
}

fn write_record_to_tree(tree: &sled::Tree, offset: u64, rec: &Record) -> io::Result<usize> {
    let name_len = rec.name.len() as u16;
    let data_len = rec.data.len() as u32;
    let body_len: usize =
        8 + 8 + 8 + 8 + 4 + 4 + 2 + 4 + 1 + 5 + (name_len as usize) + (data_len as usize);
    let total_len = 4 + 4 + 4 + body_len;

    let mut buf = Vec::with_capacity(total_len);
    let rec_len = total_len as u32;

    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&rec_len.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf.extend_from_slice(&(rec.key as u64).to_le_bytes());
    buf.extend_from_slice(&((rec.key >> 64) as u64).to_le_bytes());
    buf.extend_from_slice(&rec.ts_sec.to_le_bytes());
    buf.extend_from_slice(&rec.prev_addr.to_le_bytes());
    buf.extend_from_slice(&rec.len_bytes.to_le_bytes());
    buf.extend_from_slice(&rec.popularity.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.push(rec.flags);
    buf.extend_from_slice(&[0u8; 5]);
    buf.extend_from_slice(rec.name.as_bytes());
    buf.extend_from_slice(&rec.data);

    let crc = crc32c_impl::crc32c(0, &buf[12..]);
    buf[8..12].copy_from_slice(&crc.to_le_bytes());

    tree.insert(offset.to_be_bytes(), buf.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(total_len)
}

fn print_usage() {
    eprintln!("Usage: recover [COMMAND] [OPTIONS]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  --migrate-context [DATA_DIR]    Migrate context trees from index to context_db");
    eprintln!("  --rebuild-index [DATA_DIR]      Rebuild the key->addr index from segment data");
    eprintln!("  --rebuild-search [DATA_DIR]     Rebuild the full-text search index");
    eprintln!("  --rebuild-basenames [DATA_DIR]  Populate key_basenames from binary_meta");
    eprintln!("  --rebuild-all [DATA_DIR]        Migrate context + rebuild index + rebuild search");
    eprintln!("  --full-recover [DATA_DIR]       Full recovery with deduplication");
    eprintln!("  --list-trees [DATA_DIR]         List all sled trees and their sizes");
    eprintln!("  --help                          Show this help message");
    eprintln!();
    eprintln!("Default DATA_DIR is 'data/'");
}

fn list_trees(data_dir: &PathBuf) -> io::Result<()> {
    println!("=== Dazhbog Database Inspector ===\n");
    println!("Data directory: {}", data_dir.display());

    // Check segments_db
    let seg_db_dir = data_dir.join("segments_db");
    if seg_db_dir.exists() {
        println!("\n--- segments_db (raw records) ---");
        let db = sled::open(&seg_db_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            println!("  {:30} {:>12} entries", name_str, tree.len());
        }
    }

    // Check index (key->addr mapping only)
    let index_dir = data_dir.join("index");
    if index_dir.exists() {
        println!("\n--- index (key->addr mapping) ---");
        let db = sled::open(&index_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        let mut has_ctx_trees = false;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            if name_str.starts_with("ctx.") {
                has_ctx_trees = true;
                println!(
                    "  {:30} {:>12} entries (NEEDS MIGRATION)",
                    name_str,
                    tree.len()
                );
            } else {
                println!("  {:30} {:>12} entries", name_str, tree.len());
            }
        }
        if has_ctx_trees {
            println!("  WARNING: ctx.* trees found - run --migrate-context to move to context_db");
        }
    }

    // Check context_db (isolated context index)
    let ctx_db_dir = data_dir.join("context_db");
    if ctx_db_dir.exists() {
        println!("\n--- context_db (binary/function metadata) ---");
        let db = sled::open(&ctx_db_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            println!("  {:30} {:>12} entries", name_str, tree.len());
        }
    } else {
        println!("\n--- context_db (NOT FOUND) ---");
        println!("  Run --migrate-context to create from old index/ctx.* trees");
    }

    // Check for orphaned index_db (created by old recover versions)
    let index_db_dir = data_dir.join("index_db");
    if index_db_dir.exists() {
        println!("\n--- index_db (ORPHANED - can be deleted) ---");
        let db = sled::open(&index_db_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open: {}", e)))?;
        for name in db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            let tree = db
                .open_tree(&name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
            println!("  {:30} {:>12} entries", name_str, tree.len());
        }
    }

    // Check search_index
    let search_dir = data_dir.join("search_index");
    if search_dir.exists() {
        println!("\n--- search_index (Tantivy) ---");
        println!("  (Full-text search index exists)");
    }

    Ok(())
}

fn migrate_context(data_dir: &PathBuf) -> io::Result<()> {
    let index_dir = data_dir.join("index");
    let ctx_db_dir = data_dir.join("context_db");

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║            DAZHBOG CONTEXT MIGRATION                         ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    log_info(&format!("Data directory: {}", data_dir.display()));

    // Check if context_db already exists
    if ctx_db_dir.exists() {
        log_info(&format!(
            "context_db already exists at {}",
            ctx_db_dir.display()
        ));
        log_info("If you want to re-migrate, delete it first");
        log_info(&format!("  rm -rf {}", ctx_db_dir.display()));
        return Ok(());
    }

    // Check if source index exists
    if !index_dir.exists() {
        eprintln!("[ERROR] {}/index directory not found.", data_dir.display());
        std::process::exit(1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    log_step(1, 4, "Opening source database");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Opening index database...");
    let src_db = sled::open(&index_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open index: {}", e)))?;

    // Check for ctx.* trees
    let ctx_tree_names: Vec<String> = src_db
        .tree_names()
        .into_iter()
        .map(|n| String::from_utf8_lossy(&n).to_string())
        .filter(|n| n.starts_with("ctx."))
        .collect();

    if ctx_tree_names.is_empty() {
        log_info("No ctx.* trees found in index");
        log_info("Creating empty context_db...");
        std::fs::create_dir_all(&ctx_db_dir)?;
        let dst_db = sled::open(&ctx_db_dir).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("sled open context_db: {}", e))
        })?;
        for name in &[
            "key_md5",
            "key_bins",
            "version_stats",
            "binary_meta",
            "key_basenames",
        ] {
            dst_db
                .open_tree(name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
        }
        dst_db.flush()?;

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  CONTEXT MIGRATION COMPLETE                                  ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Created empty context_db (no ctx.* trees to migrate)        ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        return Ok(());
    }

    // ─────────────────────────────────────────────────────────────────────────
    log_step(2, 4, "Analyzing source trees");
    // ─────────────────────────────────────────────────────────────────────────

    log_info(&format!(
        "Found {} context trees to migrate",
        ctx_tree_names.len()
    ));
    let mut total_entries: u64 = 0;
    for name in &ctx_tree_names {
        let tree = src_db
            .open_tree(name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
        let count = tree.len() as u64;
        total_entries += count;
        log_info(&format!("  {} ({} entries)", name, fmt_num(count)));
    }
    log_info(&format!(
        "Total entries to migrate: {}",
        fmt_num(total_entries)
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(3, 4, "Migrating trees");
    // ─────────────────────────────────────────────────────────────────────────

    std::fs::create_dir_all(&ctx_db_dir)?;
    let dst_db = sled::Config::default()
        .path(&ctx_db_dir)
        .cache_capacity(64 * 1024 * 1024)
        .open()
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("sled open context_db: {}", e))
        })?;

    let mut overall_progress = Progress::new("Migration", total_entries);
    let mut total_migrated = 0u64;

    for (tree_idx, src_name) in ctx_tree_names.iter().enumerate() {
        let dst_name = src_name.strip_prefix("ctx.").unwrap_or(src_name);
        let src_tree = src_db
            .open_tree(src_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;
        let dst_tree = dst_db
            .open_tree(dst_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {}", e)))?;

        let tree_len = src_tree.len() as u64;
        println!(
            "\n  [{}/{}] {} -> {} ({} entries)",
            tree_idx + 1,
            ctx_tree_names.len(),
            src_name,
            dst_name,
            fmt_num(tree_len)
        );

        let mut tree_progress = Progress::new("  Copying", tree_len);
        let mut tree_migrated = 0u64;

        for item in src_tree.iter() {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            dst_tree
                .insert(&k, &v)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("insert: {}", e)))?;
            tree_migrated += 1;
            tree_progress.inc(1);
            overall_progress.inc(1);
        }
        tree_progress.finish();
        total_migrated += tree_migrated;
    }

    println!();
    log_info("Flushing destination database...");
    let flush_start = Instant::now();
    dst_db.flush()?;
    log_info(&format!(
        "Flushed in {:.2}s",
        flush_start.elapsed().as_secs_f64()
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(4, 4, "Cleaning up source database");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Removing ctx.* trees from index...");
    for name in &ctx_tree_names {
        src_db
            .drop_tree(name.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("drop_tree: {}", e)))?;
        log_info(&format!("  Dropped {}", name));
    }
    src_db.flush()?;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  CONTEXT MIGRATION COMPLETE                                  ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Entries migrated:  {:>12}                           ║",
        fmt_num(total_migrated)
    );
    println!(
        "║  Trees processed:   {:>12}                           ║",
        ctx_tree_names.len()
    );
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

fn rebuild_index(data_dir: &PathBuf) -> io::Result<()> {
    let seg_db_dir = data_dir.join("segments_db");
    let index_dir = data_dir.join("index");

    if !seg_db_dir.exists() {
        eprintln!(
            "[ERROR] {}/segments_db directory not found.",
            data_dir.display()
        );
        std::process::exit(1);
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║            DAZHBOG INDEX REBUILD                             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    log_info(&format!("Data directory: {}", data_dir.display()));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(1, 4, "Opening databases");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Opening segments database...");
    let seg_db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open segments: {}", e)))?;

    log_info("Opening index database...");
    std::fs::create_dir_all(&index_dir)?;
    let index_db = sled::Config::default()
        .path(&index_dir)
        .cache_capacity(128 * 1024 * 1024)
        .open()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open index: {}", e)))?;

    // ─────────────────────────────────────────────────────────────────────────
    log_step(2, 4, "Clearing existing index");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Dropping old 'latest' tree (this is fast)...");
    let drop_start = Instant::now();
    index_db
        .drop_tree("latest")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("drop latest tree: {}", e)))?;
    log_info(&format!(
        "Dropped in {:.2}s",
        drop_start.elapsed().as_secs_f64()
    ));

    let index_tree = index_db.open_tree("latest").map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("sled open latest tree: {}", e),
        )
    })?;

    // ─────────────────────────────────────────────────────────────────────────
    log_step(3, 4, "Scanning segment records");
    // ─────────────────────────────────────────────────────────────────────────

    let mut tree_names: Vec<_> = seg_db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();
    tree_names.sort();

    log_info(&format!("Found {} segment trees", tree_names.len()));

    // Count total records first
    let total_expected: u64 = tree_names
        .iter()
        .filter_map(|name| seg_db.open_tree(name).ok())
        .map(|t| t.len() as u64)
        .sum();
    log_info(&format!(
        "Total records to scan: {}",
        fmt_num(total_expected)
    ));

    let mut latest_by_key: HashMap<u128, (u64, u64, u8)> = HashMap::new();
    let mut total_records = 0u64;
    let mut corrupt_records = 0u64;

    let mut progress = Progress::new("Scanning", total_expected);

    for (tree_idx, name) in tree_names.iter().enumerate() {
        let seg_id: u16 = name[4..9].parse().unwrap_or(0);
        let tree = seg_db.open_tree(name).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("open tree {}: {}", name, e))
        })?;

        let tree_len = tree.len() as u64;
        println!(
            "\n  [{}/{}] {} ({} records)",
            tree_idx + 1,
            tree_names.len(),
            name,
            fmt_num(tree_len)
        );

        let mut tree_progress = Progress::new("  Records", tree_len);

        for item in tree.iter() {
            tree_progress.inc(1);
            progress.inc(1);

            let (offset_bytes, record_bytes) = match item {
                Ok(i) => i,
                Err(_) => continue,
            };

            let offset = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());

            if record_bytes.len() < 12 {
                corrupt_records += 1;
                continue;
            }

            let hdr: &[u8] = &record_bytes[0..12];
            let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            if magic != MAGIC {
                corrupt_records += 1;
                continue;
            }

            let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
            let body = &record_bytes[12..];

            let computed_crc = crc32c_impl::crc32c(0, body);
            let crc_valid = if computed_crc == stored_crc {
                true
            } else {
                let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
                computed_crc_legacy == stored_crc
            };

            if !crc_valid {
                corrupt_records += 1;
                continue;
            }

            if body.len() < 52 {
                corrupt_records += 1;
                continue;
            }

            let lo = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(body[8..16].try_into().unwrap());
            let key = ((hi as u128) << 64) | (lo as u128);
            let ts_sec = u64::from_le_bytes(body[16..24].try_into().unwrap());
            let flags = body[46];

            let addr = pack_addr(seg_id, offset, flags);

            match latest_by_key.get(&key) {
                Some(&(existing_ts, _, _)) if existing_ts >= ts_sec => {}
                _ => {
                    latest_by_key.insert(key, (ts_sec, addr, flags));
                }
            }

            total_records += 1;
        }
        tree_progress.finish();
    }

    println!();
    log_info(&format!(
        "Valid records scanned: {}",
        fmt_num(total_records)
    ));
    log_info(&format!(
        "Corrupt records skipped: {}",
        fmt_num(corrupt_records)
    ));
    log_info(&format!(
        "Unique keys found: {}",
        fmt_num(latest_by_key.len() as u64)
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(4, 4, "Writing index entries");
    // ─────────────────────────────────────────────────────────────────────────

    let total_keys = latest_by_key.len() as u64;
    let mut progress = Progress::new("Indexing", total_keys);
    let mut indexed = 0u64;
    let mut deleted = 0u64;

    for (key, (_ts, addr, flags)) in &latest_by_key {
        progress.inc(1);

        if flags & 0x01 == 0x01 {
            deleted += 1;
            continue;
        }

        index_tree
            .insert(key.to_le_bytes(), addr.to_le_bytes().as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("index insert: {}", e)))?;
        indexed += 1;
    }
    progress.finish();

    log_info("Flushing to disk...");
    let flush_start = Instant::now();
    index_db.flush()?;
    log_info(&format!(
        "Flushed in {:.2}s",
        flush_start.elapsed().as_secs_f64()
    ));

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  INDEX REBUILD COMPLETE                                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Indexed keys:    {:>12}                              ║",
        fmt_num(indexed)
    );
    println!(
        "║  Deleted keys:    {:>12}                              ║",
        fmt_num(deleted)
    );
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

/// Decode binary metadata from ctx.binary_meta format
fn decode_binary_meta_basename(b: &[u8]) -> Option<String> {
    // Format: md5[16] + first_seen_ts[8] + last_seen_ts[8] + obs_count[8] + basename_len[2] + basename + ...
    if b.len() < 16 + 8 + 8 + 8 + 2 {
        return None;
    }
    let mut offset = 16 + 8 + 8 + 8; // skip md5 + timestamps + obs_count
    let basename_len = u16::from_le_bytes([b[offset], b[offset + 1]]) as usize;
    offset += 2;
    if b.len() < offset + basename_len {
        return None;
    }
    std::str::from_utf8(&b[offset..offset + basename_len])
        .ok()
        .map(|s| s.to_string())
}

/// Decode key_bins to get list of MD5s for a key
fn decode_key_bins_md5s(b: &[u8]) -> Vec<[u8; 16]> {
    if b.is_empty() {
        return Vec::new();
    }
    let count = b[0] as usize;
    let mut out = Vec::with_capacity(count);
    let mut offset = 1;
    for _ in 0..count {
        if offset + 16 + 4 > b.len() {
            break;
        }
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&b[offset..offset + 16]);
        out.push(md5);
        offset += 16 + 4; // md5 + obs_count
    }
    out
}

/// Encode basenames for ctx.key_basenames
fn encode_basenames_for_key(names: &[String]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + names.len() * 18);
    v.push(names.len().min(255) as u8);
    for name in names.iter().take(16) {
        let b = name.as_bytes();
        let len = b.len().min(u16::MAX as usize) as u16;
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&b[..len as usize]);
    }
    v
}

fn rebuild_basenames(data_dir: &PathBuf) -> io::Result<()> {
    let ctx_db_dir = data_dir.join("context_db");

    if !ctx_db_dir.exists() {
        eprintln!(
            "[ERROR] {}/context_db directory not found.",
            data_dir.display()
        );
        eprintln!("        Run --migrate-context first to create it.");
        std::process::exit(1);
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║            DAZHBOG BASENAMES REBUILD                         ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    log_info(&format!("Data directory: {}", data_dir.display()));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(1, 4, "Opening database");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Opening context_db...");
    let db = sled::open(&ctx_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    let key_bins = db
        .open_tree("key_bins")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open key_bins: {}", e)))?;
    let binary_meta = db
        .open_tree("binary_meta")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open binary_meta: {}", e)))?;
    let key_basenames = db
        .open_tree("key_basenames")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open key_basenames: {}", e)))?;

    let key_bins_count = key_bins.len() as u64;
    let binary_meta_count = binary_meta.len() as u64;
    let basenames_before = key_basenames.len() as u64;

    log_info(&format!(
        "key_bins:        {} entries",
        fmt_num(key_bins_count)
    ));
    log_info(&format!(
        "binary_meta:     {} entries",
        fmt_num(binary_meta_count)
    ));
    log_info(&format!(
        "key_basenames:   {} entries (before)",
        fmt_num(basenames_before)
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(2, 4, "Building MD5 -> basename lookup");
    // ─────────────────────────────────────────────────────────────────────────

    let mut progress = Progress::new("Scanning", binary_meta_count);
    let mut md5_to_basename: HashMap<[u8; 16], String> = HashMap::new();

    for item in binary_meta.iter() {
        progress.inc(1);
        let (md5_key, meta_val) = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        if md5_key.len() != 16 {
            continue;
        }
        if let Some(basename) = decode_binary_meta_basename(&meta_val) {
            if !basename.is_empty() {
                let mut md5 = [0u8; 16];
                md5.copy_from_slice(&md5_key);
                md5_to_basename.insert(md5, basename);
            }
        }
    }
    progress.finish();
    log_info(&format!(
        "Found {} binaries with basenames",
        fmt_num(md5_to_basename.len() as u64)
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(3, 4, "Populating key_basenames");
    // ─────────────────────────────────────────────────────────────────────────

    let mut progress = Progress::new("Processing", key_bins_count);
    let mut populated = 0u64;

    for item in key_bins.iter() {
        progress.inc(1);
        let (key_bytes, bins_val) = match item {
            Ok(i) => i,
            Err(_) => continue,
        };

        let md5s = decode_key_bins_md5s(&bins_val);

        let mut basenames: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for md5 in md5s {
            if let Some(basename) = md5_to_basename.get(&md5) {
                let lower = basename.to_lowercase();
                if seen.insert(lower) && basenames.len() < 16 {
                    basenames.push(basename.clone());
                }
            }
        }

        if !basenames.is_empty() {
            let encoded = encode_basenames_for_key(&basenames);
            key_basenames
                .insert(&key_bytes, encoded)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("insert: {}", e)))?;
            populated += 1;
        }
    }
    progress.finish();

    // ─────────────────────────────────────────────────────────────────────────
    log_step(4, 4, "Flushing database");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Flushing to disk...");
    let flush_start = Instant::now();
    db.flush()?;
    log_info(&format!(
        "Flushed in {:.2}s",
        flush_start.elapsed().as_secs_f64()
    ));

    let basenames_after = key_basenames.len() as u64;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  BASENAMES REBUILD COMPLETE                                  ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Keys processed:     {:>12}                          ║",
        fmt_num(key_bins_count)
    );
    println!(
        "║  Keys populated:     {:>12}                          ║",
        fmt_num(populated)
    );
    println!(
        "║  key_basenames now:  {:>12}                          ║",
        fmt_num(basenames_after)
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nRun --rebuild-search to update the search index with basenames.");

    Ok(())
}

fn rebuild_search(data_dir: &PathBuf) -> io::Result<()> {
    if !data_dir.join("segments_db").exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "segments_db missing",
        ));
    }
    let mut cfg = dazhbog::config::Config::default();
    cfg.engine.data_dir = data_dir.to_string_lossy().into_owned();
    cfg.engine.segment_bytes = RECOVER_SEG_BYTES;
    let prepared = dazhbog::engine::EngineRuntime::prepare(cfg.engine, cfg.scoring)?;
    prepared.flush()?;
    log_info(&format!(
        "Published prepared search generation ({} documents); previous generations retained",
        prepared.search.doc_count()
    ));
    Ok(())
}

fn rebuild_all(data_dir: &PathBuf) -> io::Result<()> {
    let start = Instant::now();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║            DAZHBOG FULL REBUILD                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    log_info(&format!("Data directory: {}", data_dir.display()));
    println!();
    log_info("This will run the following operations:");
    log_info("  1. Migrate context trees from index to context_db");
    log_info("  2. Rebuild key->addr index from segments");
    log_info("  3. Rebuild full-text search index");

    println!("\n\n══════════════════════════════════════════════════════════════");
    println!("  PHASE 1 OF 3: CONTEXT MIGRATION");
    println!("══════════════════════════════════════════════════════════════");
    migrate_context(data_dir)?;

    println!("\n\n══════════════════════════════════════════════════════════════");
    println!("  PHASE 2 OF 3: INDEX REBUILD");
    println!("══════════════════════════════════════════════════════════════");
    rebuild_index(data_dir)?;

    println!("\n\n══════════════════════════════════════════════════════════════");
    println!("  PHASE 3 OF 3: SEARCH INDEX REBUILD");
    println!("══════════════════════════════════════════════════════════════");
    rebuild_search(data_dir)?;

    let elapsed = start.elapsed();

    println!("\n\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  FULL REBUILD COMPLETE                                       ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Total time: {:>10.2}s                                    ║",
        elapsed.as_secs_f64()
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nAll databases have been rebuilt. You can now start the server.");

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let command = args.get(1).map(|s| s.as_str());
    let data_path = args
        .get(2)
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("data"));

    match command {
        Some("--help") | Some("-h") => {
            print_usage();
            return Ok(());
        }
        Some("--migrate-context") => {
            return migrate_context(&data_path);
        }
        Some("--rebuild-index") => {
            return rebuild_index(&data_path);
        }
        Some("--rebuild-search") => {
            return rebuild_search(&data_path);
        }
        Some("--rebuild-basenames") => {
            return rebuild_basenames(&data_path);
        }
        Some("--rebuild-all") => {
            return rebuild_all(&data_path);
        }
        Some("--list-trees") => {
            return list_trees(&data_path);
        }
        Some("--full-recover") | None => {
            // Continue with full recovery below
        }
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            std::process::exit(1);
        }
    }

    // Full recovery mode
    let start = Instant::now();
    let data_dir = data_path;
    let seg_db_dir = data_dir.join("segments_db");
    let backup_dir = PathBuf::from("data.backup");
    let temp_dir = PathBuf::from("data.recovered");

    if !seg_db_dir.exists() {
        eprintln!(
            "[ERROR] {}/segments_db directory not found.",
            data_dir.display()
        );
        eprintln!("        This tool requires the new sled-based storage.");
        eprintln!("        If you have old seg.*.dat files, run the main dazhbog server once to migrate them.");
        std::process::exit(1);
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║            DAZHBOG FULL RECOVERY                             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    log_info(&format!("Data directory: {}", data_dir.display()));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(1, 5, "Opening segment database");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Opening segments_db...");
    let db = sled::open(&seg_db_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open: {}", e)))?;

    let mut tree_names: Vec<_> = db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| name.starts_with("seg."))
        .collect();
    tree_names.sort();

    let total_expected: u64 = tree_names
        .iter()
        .filter_map(|name| db.open_tree(name).ok())
        .map(|t| t.len() as u64)
        .sum();

    log_info(&format!("Found {} segment trees", tree_names.len()));
    log_info(&format!(
        "Total records to scan: {}",
        fmt_num(total_expected)
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(2, 5, "Scanning segment records");
    // ─────────────────────────────────────────────────────────────────────────

    let mut all_records: HashMap<u128, Vec<Record>> = HashMap::new();
    let mut total_valid = 0u64;
    let mut corrupt_records = 0u64;
    let mut progress = Progress::new("Scanning", total_expected);

    for (tree_idx, name) in tree_names.iter().enumerate() {
        let tree = db
            .open_tree(name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open_tree: {}", e)))?;

        let tree_len = tree.len() as u64;
        println!(
            "\n  [{}/{}] {} ({} records)",
            tree_idx + 1,
            tree_names.len(),
            name,
            fmt_num(tree_len)
        );

        let mut tree_progress = Progress::new("  Records", tree_len);

        for item in tree.iter() {
            tree_progress.inc(1);
            progress.inc(1);

            let (offset_bytes, record_bytes) = match item {
                Ok(i) => i,
                Err(_) => continue,
            };

            let _off = u64::from_be_bytes(offset_bytes.as_ref().try_into().unwrap());

            if record_bytes.len() < 12 {
                corrupt_records += 1;
                continue;
            }

            let hdr: &[u8] = &record_bytes[0..12];
            let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            if magic != MAGIC {
                corrupt_records += 1;
                continue;
            }

            let stored_crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
            let body = &record_bytes[12..];

            let computed_crc = crc32c_impl::crc32c(0, body);
            let crc_valid = if computed_crc == stored_crc {
                true
            } else {
                let computed_crc_legacy = crc32c_impl::crc32c_legacy(0, body);
                computed_crc_legacy == stored_crc
            };

            if !crc_valid || body.len() < 52 {
                corrupt_records += 1;
                continue;
            }

            // Parse record
            let lo = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(body[8..16].try_into().unwrap());
            let key = ((hi as u128) << 64) | (lo as u128);
            let ts_sec = u64::from_le_bytes(body[16..24].try_into().unwrap());
            let prev_addr = u64::from_le_bytes(body[24..32].try_into().unwrap());
            let len_bytes = u32::from_le_bytes(body[32..36].try_into().unwrap());
            let popularity = u32::from_le_bytes(body[36..40].try_into().unwrap());
            let name_len = u16::from_le_bytes(body[40..42].try_into().unwrap()) as usize;
            let data_len = u32::from_le_bytes(body[42..46].try_into().unwrap()) as usize;
            let flags = body[46];

            let name_start = 52;
            if name_start + name_len + data_len > body.len() {
                corrupt_records += 1;
                continue;
            }

            let name = match std::str::from_utf8(&body[name_start..name_start + name_len]) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    corrupt_records += 1;
                    continue;
                }
            };

            let data_start = name_start + name_len;
            let data = body[data_start..data_start + data_len].to_vec();

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

            all_records
                .entry(rec.key)
                .or_insert_with(Vec::new)
                .push(rec);
            total_valid += 1;
        }
        tree_progress.finish();
    }

    println!();
    log_info(&format!("Valid records scanned: {}", fmt_num(total_valid)));
    log_info(&format!(
        "Corrupt records skipped: {}",
        fmt_num(corrupt_records)
    ));
    log_info(&format!(
        "Unique keys found: {}",
        fmt_num(all_records.len() as u64)
    ));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(3, 5, "Deduplicating records");
    // ─────────────────────────────────────────────────────────────────────────

    let total_keys = all_records.len() as u64;
    let mut progress = Progress::new("Deduplicating", total_keys);
    let mut final_records: Vec<Record> = Vec::new();
    let mut deleted_count = 0u64;

    for (_key, mut versions) in all_records {
        progress.inc(1);
        versions.sort_by(|a, b| b.ts_sec.cmp(&a.ts_sec));
        if let Some(latest) = versions.into_iter().next() {
            if latest.flags & 0x01 == 0 {
                final_records.push(latest);
            } else {
                deleted_count += 1;
            }
        }
    }
    progress.finish();

    log_info(&format!(
        "Records to recover: {}",
        fmt_num(final_records.len() as u64)
    ));
    log_info(&format!(
        "Deleted records skipped: {}",
        fmt_num(deleted_count)
    ));

    if final_records.is_empty() {
        println!("\n[WARN] No records to recover!");
        return Ok(());
    }

    // ─────────────────────────────────────────────────────────────────────────
    log_step(4, 5, "Writing recovered data");
    // ─────────────────────────────────────────────────────────────────────────

    if temp_dir.exists() {
        log_info("Removing old temp directory...");
        std::fs::remove_dir_all(&temp_dir)?;
    }
    std::fs::create_dir_all(&temp_dir)?;

    log_info("Opening new segment database...");
    let recovered_db = sled::open(&temp_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open temp db: {}", e)))?;
    let recovered_tree = recovered_db
        .open_tree("seg.00001")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled open temp tree: {}", e)))?;

    let total_to_write = final_records.len() as u64;
    let mut progress = Progress::new("Writing", total_to_write);
    let mut offset = 0u64;
    let mut bytes_written = 0u64;

    for rec in final_records.iter() {
        let len = write_record_to_tree(&recovered_tree, offset, rec)?;
        offset += len as u64;
        bytes_written += len as u64;
        progress.inc(1);
    }
    progress.finish();

    log_info("Flushing to disk...");
    let flush_start = Instant::now();
    recovered_db.flush()?;
    log_info(&format!(
        "Flushed in {:.2}s",
        flush_start.elapsed().as_secs_f64()
    ));
    drop(recovered_db);

    log_info(&format!("Written {} bytes", fmt_num(bytes_written)));

    // ─────────────────────────────────────────────────────────────────────────
    log_step(5, 5, "Finalizing recovery");
    // ─────────────────────────────────────────────────────────────────────────

    log_info("Creating backup of old segments...");
    if backup_dir.exists() {
        std::fs::remove_dir_all(&backup_dir)?;
    }
    std::fs::create_dir_all(&backup_dir)?;
    std::fs::rename(&seg_db_dir, backup_dir.join("segments_db"))?;
    log_info(&format!(
        "Old data backed up to {}",
        backup_dir.join("segments_db").display()
    ));

    log_info("Moving recovered data into place...");
    std::fs::rename(&temp_dir, &seg_db_dir)?;
    log_info(&format!("Recovered data moved to {}", seg_db_dir.display()));

    let elapsed = start.elapsed();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  FULL RECOVERY COMPLETE                                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Records recovered:   {:>12}                         ║",
        fmt_num(final_records.len() as u64)
    );
    println!(
        "║  Data written:        {:>12}                         ║",
        fmt_num(bytes_written)
    );
    println!(
        "║  Total time:          {:>10.2}s                           ║",
        elapsed.as_secs_f64()
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nBackup location: {}", backup_dir.display());
    println!("You can now restart the dazhbog server.");

    Ok(())
}
