//! Replay a captured Lumina pull against an offline copy and explain each answer.
//!
//! Takes a request payload recorded by `debug.dump_pull` and runs the serving
//! selector over it with diagnostics retained, so every served name can be read
//! next to the alternatives that lost, the binaries that observed each of them,
//! and how ubiquitous the key is. Opens writable storage handles: use a copy, or
//! stop the server first.
use dazhbog::{
    config::load_config,
    db::{Database, QueryContext, VariantInventory},
    protocol::lumina::{parse_lumina_pull_metadata, LuminaCaps},
};
use serde::Serialize;
use std::{collections::HashMap, io, sync::Arc};

#[derive(Serialize)]
struct KeyReport {
    i: usize,
    key_hex: String,
    status: &'static str,
    served_name: Option<String>,
    score: f64,
    margin: f64,
    entropy: f64,
    binary_support: f64,
    binary_match: f64,
    binary_priority_floor: f64,
    used_synthesis: bool,
    candidate_count: usize,
    binary_count: usize,
    binary_count_capped: bool,
    membership_rows: usize,
    votes_in_inference: bool,
    variants: Vec<VariantLine>,
}

#[derive(Serialize)]
struct VariantLine {
    name: String,
    selected: bool,
    ts_sec: u64,
    total_obs: u32,
    num_binaries: u32,
    binaries: Vec<String>,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} CONFIG PULL.bin [--max-versions N] [--binary-cap N] [--hits-only]",
            args[0]
        );
        std::process::exit(2);
    }
    let cfg_path = &args[1];
    let pull_path = &args[2];
    let mut max_versions = 64usize;
    let mut binary_cap = 4096usize;
    let mut hits_only = false;
    let mut it = args[3..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--max-versions" => max_versions = it.next().and_then(|v| v.parse().ok()).unwrap_or(64),
            "--binary-cap" => binary_cap = it.next().and_then(|v| v.parse().ok()).unwrap_or(4096),
            "--hits-only" => hits_only = true,
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }

    let payload = std::fs::read(pull_path)?;
    let caps = LuminaCaps {
        max_funcs: 4_000_000,
        max_name_bytes: 65536,
        max_data_bytes: 64 * 1024 * 1024,
        max_cstr_bytes: 65536,
        max_hash_bytes: 4096,
    };
    let pull = parse_lumina_pull_metadata(&payload, caps)
        .map_err(|e| io::Error::other(format!("parse pull: {e}")))?;

    let mut keys = Vec::with_capacity(pull.funcs.len());
    let mut key_pos = Vec::with_capacity(pull.funcs.len());
    for (i, func) in pull.funcs.iter().enumerate() {
        if let Some(key) = func.md5_key() {
            keys.push(key);
            key_pos.push(i);
        }
    }
    eprintln!(
        "pull: {} patterns, {} valid md5 keys, mdkeys={:?}, flags={}",
        pull.funcs.len(),
        keys.len(),
        pull.keys,
        pull.flags
    );

    let cfg = Arc::new(load_config(cfg_path)?);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let db = Database::open(cfg).await?;
        let ctx = QueryContext {
            keys: &keys,
            requested_mdkeys: &pull.keys,
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
        };
        let (informative, donors) = db.infer_batch_binaries(&keys, 25)?;
        eprintln!(
            "\nbinary inference: {} of {} requested keys carry membership evidence",
            informative,
            keys.len()
        );
        eprintln!("  {:>7}  {:>6}  {:>8}  binary", "share", "keys", "funcs");
        for d in &donors {
            eprintln!(
                "  {:>6.2}%  {:>6}  {:>8}  {} · {}",
                100.0 * d.share,
                d.keys_supported,
                d.function_count,
                d.basename,
                &d.md5_hex[..8]
            );
        }
        eprintln!();

        let started = std::time::Instant::now();
        let selections = db.select_variant_details(&ctx).await?;
        eprintln!("selection over {} keys in {:?}", keys.len(), started.elapsed());

        let mut inventories: HashMap<u128, VariantInventory> = HashMap::new();
        let out = io::stdout();
        let mut w = io::BufWriter::new(out.lock());
        use std::io::Write;
        for (j, selection) in selections.iter().enumerate() {
            if hits_only && selection.is_none() {
                continue;
            }
            let key = keys[j];
            let inv = match inventories.get(&key) {
                Some(v) => v,
                None => {
                    let v = db.variant_inventory(key, max_versions, binary_cap)?;
                    inventories.entry(key).or_insert(v)
                }
            };
            let variants = inv
                .variants
                .iter()
                .map(|v| VariantLine {
                    name: v.name.clone(),
                    selected: selection.as_ref().is_some_and(|s| s.name == v.name),
                    ts_sec: v.ts_sec,
                    total_obs: v.total_obs,
                    num_binaries: v.num_binaries,
                    binaries: v
                        .top_binaries
                        .iter()
                        .map(|b| format!("{}·{}", b.basename, &b.md5_hex[..8]))
                        .collect(),
                })
                .collect();
            let report = KeyReport {
                i: key_pos[j],
                key_hex: inv.key_hex.clone(),
                status: if selection.is_some() { "ok" } else { "notfound" },
                served_name: selection.as_ref().map(|s| s.name.clone()),
                score: selection.as_ref().map_or(0.0, |s| s.score),
                margin: selection.as_ref().map_or(0.0, |s| s.margin),
                entropy: selection.as_ref().map_or(0.0, |s| s.entropy),
                binary_support: selection.as_ref().map_or(0.0, |s| s.binary_support),
                binary_match: selection.as_ref().map_or(0.0, |s| s.binary_match),
                binary_priority_floor: selection
                    .as_ref()
                    .map_or(0.0, |s| s.binary_priority_floor),
                used_synthesis: selection.as_ref().is_some_and(|s| s.used_synthesis),
                candidate_count: selection
                    .as_ref()
                    .map_or(0, |s| s.candidate_version_ids.len().max(1)),
                binary_count: inv.binary_count,
                binary_count_capped: inv.binary_count_capped,
                membership_rows: inv.membership_rows,
                votes_in_inference: inv.votes_in_inference,
                variants,
            };
            writeln!(w, "{}", serde_json::to_string(&report).unwrap())?;
        }
        w.flush()?;
        Ok::<(), io::Error>(())
    })
}
