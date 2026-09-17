//! Replay a captured Lumina pull against an offline copy and explain each answer.
//!
//! Takes a request payload recorded by `debug.dump_pull` and runs the serving
//! selector over it with diagnostics retained, so every served name can be read
//! next to the alternatives that lost, the binaries that observed each of them,
//! and how ubiquitous the key is. Opens writable storage handles: use a copy, or
//! stop the server first.
use dazhbog::{
    config::load_config,
    db::{
        Database, PatternClass, Provenance, QueryContext, ServedForm, TypeConsensus,
        VariantInventory,
    },
    protocol::lumina::{parse_lumina_pull_metadata, LuminaCaps},
};
use serde::Serialize;
use std::{collections::HashMap, io, sync::Arc};

#[derive(Serialize)]
struct KeyReport {
    i: usize,
    key_hex: String,
    status: &'static str,
    /// Positions of this request that carried the key.
    repeat_count: u32,
    served: ServedForm,
    provenance: Provenance,
    type_consensus: Option<TypeConsensus>,
    specialized_by: Option<dazhbog::db::Specialization>,
    class: PatternClass,
    skeleton: Option<String>,
    distinct_names: usize,
    skeleton_share: f64,
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
    skeleton: Option<String>,
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
        let selections = db.select_variant_decisions(&ctx).await?;
        eprintln!("selection over {} keys in {:?}", keys.len(), started.elapsed());
        let declined = selections
            .iter()
            .filter(|(_, decision)| decision.is_declined())
            .count();
        let served = selections
            .iter()
            .filter(|(selection, _)| selection.is_some())
            .count();
        eprintln!(
            "positions: {} served, {} declined, {} not found",
            served,
            declined,
            selections.len() - served - declined
        );
        let mut by_outcome: HashMap<String, usize> = HashMap::new();
        for (selection, decision) in &selections {
            let label = match (&decision.served, &decision.provenance) {
                (ServedForm::Declined(reason), _) => format!("declined:{reason:?}"),
                (ServedForm::Skeleton, _) => format!(
                    "served:skeleton:{}",
                    decision
                        .type_consensus
                        .map_or("untyped".to_string(), |c| format!("{c:?}").to_lowercase())
                ),
                (ServedForm::Corroborated, _) => "served:corroborated".to_string(),
                (_, provenance) if selection.is_some() => {
                    let kind = match provenance {
                        Provenance::Unchecked => "unchecked",
                        Provenance::Explicit { .. } => "explicit",
                        Provenance::RelatedDonor { .. } => "related-donor",
                        Provenance::Library { .. } => "library",
                        Provenance::Foreign { .. } => "foreign(served)",
                    };
                    format!("served:{kind}")
                }
                _ => continue,
            };
            *by_outcome.entry(label).or_default() += 1;
        }
        let mut outcomes: Vec<_> = by_outcome.into_iter().collect();
        outcomes.sort();
        for (label, count) in outcomes {
            eprintln!("  {:>6}  {label}", count);
        }

        let mut inventories: HashMap<u128, VariantInventory> = HashMap::new();
        let out = io::stdout();
        let mut w = io::BufWriter::new(out.lock());
        use std::io::Write;
        for (j, (selection, decision)) in selections.iter().enumerate() {
            if hits_only && selection.is_none() && !decision.is_declined() {
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
                    skeleton: v.skeleton.clone(),
                    selected: selection
                        .as_ref()
                        .is_some_and(|s| s.name == v.name || s.name == v.normalized_name),
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
                status: if selection.is_some() {
                    "ok"
                } else if decision.is_declined() {
                    "declined"
                } else {
                    "notfound"
                },
                repeat_count: decision.repeat_count,
                served: decision.served,
                provenance: decision.provenance.clone(),
                type_consensus: decision.type_consensus,
                specialized_by: decision.specialized_by.clone(),
                class: inv.classification.class,
                skeleton: inv.classification.skeleton.clone(),
                distinct_names: inv.classification.distinct_names,
                skeleton_share: inv.classification.skeleton_share,
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

        // Class split over distinct known keys and over the positions they
        // answer, so the shape of the request is visible at a glance.
        let mut by_class: HashMap<PatternClass, (usize, usize)> = HashMap::new();
        for (key, inv) in &inventories {
            if inv.variants.is_empty() {
                continue;
            }
            let positions = selections
                .iter()
                .zip(&keys)
                .filter(|(_, k)| *k == key)
                .count();
            let entry = by_class.entry(inv.classification.class).or_default();
            entry.0 += 1;
            entry.1 += positions;
        }
        eprintln!("\nclass              keys  positions");
        for class in [
            PatternClass::Specific,
            PatternClass::Disagreement,
            PatternClass::TemplateMember,
            PatternClass::Coincidence,
        ] {
            let (k, p) = by_class.get(&class).copied().unwrap_or_default();
            eprintln!("  {:<16} {:>5}  {:>9}", format!("{class:?}"), k, p);
        }
        Ok::<(), io::Error>(())
    })
}
