//! Bounded latest/history audit. Opens writable storage handles: use an offline copy.
use dazhbog::config::Config;
use dazhbog::engine::{OpenSegments, ShardedIndex};
use std::{collections::HashSet, io, path::Path, time::Instant};

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let config = args
        .next()
        .ok_or_else(|| io::Error::other("usage: storage-audit CONFIG [LIMIT]"))?;
    let limit = args
        .next()
        .map_or(Ok(1000usize), |s| s.parse().map_err(io::Error::other))?;
    if args.next().is_some() {
        return Err(io::Error::other("unexpected arguments"));
    }
    let cfg = Config::load(&config)?;
    let start = Instant::now();
    let segments = OpenSegments::open_mode(
        Path::new(&cfg.engine.data_dir),
        cfg.engine.segment_bytes,
        false,
        false,
    )?;
    let segments_s = start.elapsed().as_secs_f64();
    let index_dir = cfg
        .engine
        .index_dir
        .map_or_else(|| Path::new(&cfg.engine.data_dir).join("index"), Into::into);
    let db = sled::open(index_dir)?;
    let index = ShardedIndex::open(&db, false)?;
    let index_s = start.elapsed().as_secs_f64() - segments_s;
    let (mut scanned, mut mismatches, mut invalid, mut truncated) =
        (0usize, 0usize, 0usize, 0usize);
    let mut examples = Vec::new();
    for entry in index.try_iter_keys().take(limit) {
        let (key, head) = entry?;
        scanned += 1;
        let mut address = head;
        let mut seen = HashSet::new();
        for depth in 0..64 {
            if address == 0 {
                break;
            }
            if !seen.insert(address) {
                invalid += 1;
                if examples.len() < 10 {
                    examples.push(serde_json::json!({"key":format!("{key:032x}"),"address":format!("{address:016x}"),"depth":depth,"error":"cycle"}));
                }
                break;
            }
            let record = match segments.read_record(address) {
                Ok(record) => record,
                Err(error) => {
                    invalid += 1;
                    if examples.len() < 10 {
                        examples.push(serde_json::json!({"key":format!("{key:032x}"),"address":format!("{address:016x}"),"depth":depth,"error":error.to_string()}));
                    }
                    break;
                }
            };
            if record.key != key {
                mismatches += 1;
                if examples.len() < 10 {
                    examples.push(serde_json::json!({"key":format!("{key:032x}"),"stored":format!("{:032x}",record.key),"head":format!("{head:016x}"),"address":format!("{address:016x}"),"depth":depth}));
                }
                break;
            }
            if record.flags & 1 != 0 {
                break;
            }
            address = record.prev_addr;
            if depth == 63 && address != 0 {
                truncated += 1;
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"segments_open_s":segments_s,"index_open_s":index_s,
        "elapsed_s":start.elapsed().as_secs_f64(),"scanned_keys":scanned,
        "mismatched_chains":mismatches,"invalid_chains":invalid,"truncated_chains":truncated,"examples":examples})
    );
    Ok(())
}
