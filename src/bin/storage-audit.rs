//! Bounded latest/history audit. Opens writable storage handles: use an offline copy.
use dazhbog::common::hash::{legacy_version_id, version_id};
use dazhbog::config::Config;
use dazhbog::db::semantic::is_rejected_function_name_with;
use dazhbog::engine::{OpenSegments, ShardedIndex};
use std::{collections::HashSet, io, path::Path, time::Instant};

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let config = args.next().ok_or_else(|| {
        io::Error::other(
            "usage: storage-audit CONFIG [LIMIT | --key KEY [VERSION_ID [--physical ROW_LIMIT]]]",
        )
    })?;
    let argument = args.next();
    let target = if argument.as_deref() == Some("--key") {
        let text = args
            .next()
            .ok_or_else(|| io::Error::other("--key requires a hexadecimal key"))?;
        let key = u128::from_str_radix(text.strip_prefix("0x").unwrap_or(&text), 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let expected = args.next().map(|s| parse_version(&s)).transpose()?;
        let physical_limit = match args.next().as_deref() {
            None => None,
            Some("--physical") if expected.is_some() => {
                let limit = args
                    .next()
                    .ok_or_else(|| io::Error::other("--physical requires ROW_LIMIT"))?
                    .parse::<usize>()
                    .map_err(io::Error::other)?;
                if !(1..=100_000_000).contains(&limit) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ROW_LIMIT must be 1..100000000",
                    ));
                }
                Some(limit)
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected argument after VERSION_ID",
                ))
            }
        };
        Some((key, expected, physical_limit))
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
    if let Some((key, expected, physical_limit)) = target {
        let mut report = audit_key(&segments, &index, key, expected, cfg.engine.name_rejection)?;
        if let Some(limit) = physical_limit {
            report["physical_scan"] = audit_physical(
                &segments,
                key,
                expected,
                limit,
                &report,
                cfg.engine.name_rejection,
            )?;
        }
        println!("{report}");
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

/// Inspect embedded keys across physical rows without assuming latest-chain membership.
/// Decode matching rows with the serving reader. Nonmatching rows are not CRC-audited.
fn audit_physical(
    segments: &OpenSegments,
    key: u128,
    expected: Option<[u8; 32]>,
    limit: usize,
    history: &serde_json::Value,
    policy: dazhbog::config::NameRejection,
) -> io::Result<serde_json::Value> {
    let started = Instant::now();
    let mut scanned = 0usize;
    let mut matched = 0usize;
    let mut invalid_offsets = 0usize;
    let mut short_rows = 0usize;
    let mut invalid_matching_rows = 0usize;
    let mut expected_matches = 0usize;
    let mut off_chain_expected_matches = 0usize;
    let mut truncated = false;
    let mut examples = Vec::new();
    let inspected: HashSet<_> = history["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["address"].as_str())
        .filter_map(|address| u64::from_str_radix(address, 16).ok())
        .map(|address| address & !0xff)
        .collect();
    'segments: for segment in 1..=segments.get_segment_count() {
        let reader = segments
            .get_reader(segment)
            .ok_or_else(|| io::Error::other("missing segment reader"))?;
        let tree = segments.sled_db().open_tree(format!("seg.{segment:05}"))?;
        for row in tree.iter() {
            let (offset_bytes, raw) = row?;
            // One-row lookahead distinguishes an exhausted limit from a complete scan.
            if scanned == limit {
                truncated = true;
                break 'segments;
            }
            scanned += 1;
            let Ok(offset_bytes) = <[u8; 8]>::try_from(offset_bytes.as_ref()) else {
                invalid_offsets += 1;
                continue;
            };
            let offset = u64::from_be_bytes(offset_bytes);
            if offset >= 1u64 << 40 {
                invalid_offsets += 1;
                continue;
            }
            let Some(raw_key) = raw.get(12..28) else {
                short_rows += 1;
                continue;
            };
            if raw_key != key.to_le_bytes() {
                continue;
            }
            let record = match reader.read_at(offset) {
                Ok(record) if record.key == key => record,
                _ => {
                    invalid_matching_rows += 1;
                    continue;
                }
            };
            matched += 1;
            let current = version_id(key, &record.name, &record.data);
            let legacy = legacy_version_id(key, &record.name, &record.data);
            let is_expected = expected.is_some_and(|id| id == current || id == legacy);
            let address = dazhbog::common::pack_addr(segment, offset, 0);
            let in_history = inspected.contains(&address);
            expected_matches += usize::from(is_expected);
            off_chain_expected_matches += usize::from(is_expected && !in_history);
            if examples.len() < 64 {
                examples.push(serde_json::json!({
                    "address":format!("{address:016x}"), "previous":format!("{:016x}", record.prev_addr),
                    "current_version":hex(&current), "legacy_version":hex(&legacy),
                    "name":record.name.chars().take(256).collect::<String>(),
                    "name_truncated":record.name.chars().nth(256).is_some(),
                    "metadata_bytes":record.data.len(), "timestamp_seconds":record.ts_sec,
                    "tombstone":record.flags & 1 != 0,
                    "rejected_name":is_rejected_function_name_with(policy, &record.name),
                    "in_inspected_history":in_history, "expected_matches":is_expected,
                }));
            }
        }
    }
    Ok(serde_json::json!({
        "row_limit":limit, "rows_scanned":scanned, "truncated":truncated,
        "registered_segments":segments.get_segment_count(),
        "valid_matching_records":matched, "expected_matches":expected_matches,
        "outside_inspected_history_matches":off_chain_expected_matches,
        "invalid_offsets":invalid_offsets, "short_rows":short_rows,
        "invalid_matching_rows":invalid_matching_rows,
        "examples_truncated":matched > examples.len(), "records":examples,
        "nonmatching_records_validated":false, "snapshot_consistent":false,
        "elapsed_seconds":started.elapsed().as_secs_f64(),
    }))
}

/// Inspect the source records independently of selection and visibility policy.
/// Bounds: 4096 records, 256 Unicode scalar values per displayed name, no payload dump.
fn audit_key(
    segments: &OpenSegments,
    index: &ShardedIndex,
    key: u128,
    expected: Option<[u8; 32]>,
    policy: dazhbog::config::NameRejection,
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
        let rejected = is_rejected_function_name_with(policy, &record.name);
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
