//! Bounded latest/history audit. Opens writable storage handles: use an offline copy.
use dazhbog::common::hash::{legacy_version_id, version_id};
use dazhbog::config::Config;
use dazhbog::db::semantic::is_rejected_function_name;
use dazhbog::engine::{OpenSegments, ShardedIndex};
use std::{collections::HashSet, io, path::Path, time::Instant};

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let config = args.next().ok_or_else(|| {
        io::Error::other("usage: storage-audit CONFIG [LIMIT | --key KEY [VERSION_ID]]")
    })?;
    let argument = args.next();
    let target = if argument.as_deref() == Some("--key") {
        let text = args
            .next()
            .ok_or_else(|| io::Error::other("--key requires a hexadecimal key"))?;
        let key = u128::from_str_radix(text.strip_prefix("0x").unwrap_or(&text), 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let expected = args.next().map(|s| parse_version(&s)).transpose()?;
        Some((key, expected))
    } else {
        None
    };
    let limit = if target.is_some() {
        0
    } else {
        argument.map_or(Ok(1000usize), |s| s.parse().map_err(io::Error::other))?
    };
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
    if let Some((key, expected)) = target {
        println!("{}", audit_key(&segments, &index, key, expected)?);
        return Ok(());
    }
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

fn parse_version(text: &str) -> io::Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VERSION_ID requires 64 hexadecimal digits",
        ));
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    }
    Ok(result)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inspect the source records independently of selection and visibility policy.
/// Bounds: 4096 records, 256 Unicode scalar values per displayed name, no payload dump.
fn audit_key(
    segments: &OpenSegments,
    index: &ShardedIndex,
    key: u128,
    expected: Option<[u8; 32]>,
) -> io::Result<serde_json::Value> {
    let head = index.try_get(key)?;
    let mut address = head;
    let mut seen = HashSet::new();
    let mut candidates = HashSet::new();
    let mut records = Vec::new();
    let mut found = false;
    let mut accepted = false;
    let mut stop = if head == 0 {
        "missing_index_entry"
    } else {
        "end_of_chain"
    };
    let mut error = None;
    while address != 0 {
        if records.len() == 4096 {
            stop = "traversal_limit";
            break;
        }
        if !seen.insert(address) {
            stop = "cycle";
            break;
        }
        let record = match segments.read_record(address) {
            Ok(record) => record,
            Err(e) => {
                stop = "read_error";
                error = Some(e.to_string());
                break;
            }
        };
        let current = version_id(record.key, &record.name, &record.data);
        let legacy = legacy_version_id(record.key, &record.name, &record.data);
        let matches = expected.is_some_and(|id| id == current || id == legacy);
        let same_key = record.key == key;
        let tombstone = record.flags & 1 != 0;
        let rejected = is_rejected_function_name(&record.name);
        let live = same_key && !tombstone && !rejected;
        found |= same_key && matches;
        accepted |= live && matches;
        if live {
            candidates.insert(current);
        }
        records.push(serde_json::json!({
            "address":format!("{address:016x}"), "stored_key":format!("{:032x}",record.key),
            "previous":format!("{:016x}",record.prev_addr), "timestamp_seconds":record.ts_sec,
            "name":record.name.chars().take(256).collect::<String>(),
            "name_truncated":record.name.chars().nth(256).is_some(),
            "name_bytes":record.name.len(), "metadata_bytes":record.data.len(),
            "rejected_name":rejected, "tombstone":tombstone,
            "current_version":hex(&current), "legacy_version":hex(&legacy),
            "expected_matches":expected.map(|_| matches), "live_candidate":live,
        }));
        if !same_key {
            stop = "foreign_key";
            break;
        }
        if tombstone {
            stop = "tombstone";
            break;
        }
        address = record.prev_addr;
    }
    Ok(serde_json::json!({
        "key":format!("{key:032x}"), "head_address":format!("{head:016x}"),
        "expected_version":expected.map(|id| hex(&id)),
        "expected_found":expected.map(|_| found), "expected_live":expected.map(|_| accepted),
        "live_candidates":candidates.len(), "stop_reason":stop,
        "stop_address":format!("{address:016x}"), "error":error, "records":records,
    }))
}
