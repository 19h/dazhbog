//! Measure retrospective known-binary variant agreement on an offline copy.
use dazhbog::{
    config::load_config,
    db::{BinaryEvaluation, Database},
};
use serde::Serialize;
use std::{io, sync::Arc, time::Instant};

#[derive(Default, Serialize)]
struct Counts {
    cases: usize,
    labeled: usize,
    available: usize,
    reachable_with_identity: usize,
    selected_correct: usize,
    latest_correct: usize,
    canonical_correct: usize,
    ambiguous_available: usize,
    ambiguous_correct: usize,
    semantic_judged: usize,
    semantic_correct: usize,
    name_correct: usize,
}
impl Counts {
    fn add(&mut self, report: &BinaryEvaluation) {
        for case in &report.cases {
            self.cases += 1;
            self.labeled += usize::from(case.expected_version.is_some());
            self.available += usize::from(case.expected_in_candidates);
            self.reachable_with_identity += usize::from(case.expected_reachable_with_identity);
            self.selected_correct += usize::from(case.selected_matches_observation);
            self.latest_correct += usize::from(case.latest_matches_observation);
            self.canonical_correct += usize::from(case.canonical_matches_observation);
            self.semantic_judged += usize::from(case.semantic_payload_matches.is_some());
            self.semantic_correct += usize::from(case.semantic_payload_matches == Some(true));
            self.name_correct += usize::from(case.name_matches_observation == Some(true));
            if case.candidate_count > 1 && case.expected_in_candidates {
                self.ambiguous_available += 1;
                self.ambiguous_correct += usize::from(case.selected_matches_observation);
            }
        }
    }
}

fn number(value: Option<String>, default: usize) -> io::Result<usize> {
    value.map_or(Ok(default), |v| {
        v.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let config = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: eval-binary-context CONFIG [BINARIES=32] [FUNCTIONS=64] [SEED=1] [observed|transfer]",
        )
    })?;
    let binaries = number(args.next(), 32)?;
    let functions = number(args.next(), 64)?;
    let seed = number(args.next(), 1)? as u64;
    let transfer = match args.next().as_deref() {
        None | Some("observed") => false,
        Some("transfer") => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mode must be observed or transfer",
            ))
        }
    };
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected argument",
        ));
    }
    let cfg = load_config(&config)?;
    if cfg.scoring.experimental_synthesis {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "disable experimental synthesis for exact variant evaluation",
        ));
    }
    let selection_policy = serde_json::json!({
        "binary_priority":cfg.scoring.binary_priority,
        "binary_single_key_tolerance":cfg.scoring.binary_single_key_tolerance,
    });
    let db = Database::open_for_replay(Arc::new(cfg)).await?;
    let started = Instant::now();
    let batches = db.sample_observed_binary_batches(binaries, functions, seed)?;
    if batches.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no qualifying binary batches",
        ));
    }
    let mode = if transfer {
        "binary-identity-holdout-transfer"
    } else {
        "retrospective-known-binary-observation-agreement"
    };
    println!(
        "{}",
        serde_json::json!({"kind":"sample", "evaluation":mode,
        "independent_accuracy":false, "selection_policy":selection_policy, "seed":seed, "binaries":batches.len(), "functions_per_batch":functions,
        "sampling_seconds":started.elapsed().as_secs_f64()})
    );
    let mut total = Counts::default();
    let mut failed = 0usize;
    for (md5, keys) in batches {
        let report = if transfer {
            db.evaluate_binary_transfer(md5, &keys).await
        } else {
            db.evaluate_observed_binary(md5, &keys).await
        };
        match report {
            Ok(report) => {
                let mut counts = Counts::default();
                counts.add(&report);
                total.add(&report);
                let mismatches: Vec<_> = report
                    .cases
                    .iter()
                    .filter(|c| c.expected_in_candidates && !c.selected_matches_observation)
                    .take(3)
                    .collect();
                let unavailable: Vec<_> = report
                    .cases
                    .iter()
                    .filter(|c| c.expected_version.is_some() && !c.expected_in_candidates)
                    .take(2)
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({"kind":"binary", "binary":report.binary, "counts":counts,
                    "withheld_binary":report.withheld_binary,
                    "selection_seconds":report.selection_seconds, "identity_selection_seconds":report.identity_selection_seconds,
                    "mismatch_examples":mismatches, "unavailable_examples":unavailable})
                );
            }
            Err(error) => {
                failed += 1;
                println!(
                    "{}",
                    serde_json::json!({"kind":"error", "binary":md5, "error":error.to_string()})
                );
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"kind":"summary", "counts":total, "failed_batches":failed})
    );
    if failed > 0 {
        return Err(io::Error::other(
            "one or more evaluation batches failed; partial results reported",
        ));
    }
    Ok(())
}
