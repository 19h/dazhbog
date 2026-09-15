use dazhbog::config::load_config;
use dazhbog::db::semantic::{bundle_for_mdkey, normalize_requested_mdkeys, SemanticBundle};
use dazhbog::db::{
    Database, ReplayCaseOptions, ReplayCaseResult, ReplayRequestMode, ReplaySelectorResult,
};
use dazhbog::protocol::lumina::parse_metadata;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::Arc;

#[derive(Clone)]
struct Cli {
    config_path: String,
    sample: usize,
    max_versions: usize,
    request_mode: ReplayRequestMode,
    emit_corpus: Option<String>,
    authoritative_scores: Option<String>,
}

#[derive(Default)]
struct MetricAccumulator {
    cases: usize,
    exact_bytes: usize,
    exact_names: usize,
    coverage_sum: f64,
    chunk_precision_sum: f64,
    chunk_recall_sum: f64,
    chunk_f1_sum: f64,
    bundle_precision_sum: f64,
    bundle_recall_sum: f64,
    bundle_f1_sum: f64,
    margin_sum: f64,
    entropy_sum: f64,
    synthesis_count: usize,
}

#[derive(Default)]
struct AuthoritativeAccumulator {
    paired_cases: usize,
    semantic_score_sum: f64,
    baseline_score_sum: f64,
    semantic_margin_pairs: Vec<(f64, f64)>,
    semantic_confidence_pairs: Vec<(f64, f64)>,
}

#[derive(Default)]
struct SelectionMetrics {
    exact_bytes: bool,
    exact_name: bool,
    coverage_ratio: f64,
    chunk_precision: f64,
    chunk_recall: f64,
    chunk_f1: f64,
    bundle_precision: f64,
    bundle_recall: f64,
    bundle_f1: f64,
}

#[derive(Deserialize)]
struct AuthoritativeScoreRow {
    case_id: String,
    selector: String,
    score: f64,
}

#[derive(Serialize)]
struct ReplayCorpusRow {
    case_id: String,
    key_hex: String,
    holdout_version_id: String,
    request_mode: String,
    requested_mdkeys: Vec<u32>,
    candidate_count: usize,
    holdout_name: String,
    holdout_data_hex: String,
    baseline_base_version_id: String,
    baseline_name: String,
    baseline_data_hex: String,
    semantic_base_version_id: String,
    semantic_name: String,
    semantic_data_hex: String,
    semantic_score: f64,
    semantic_margin: f64,
    semantic_entropy: f64,
    semantic_used_synthesis: bool,
}

fn usage() -> &'static str {
    "usage: eval_semantic <config.toml> [--sample N] [--max-versions N] [--request-mode full|structure|comments|operands] [--emit-corpus path.jsonl] [--authoritative-scores path.jsonl]"
}

fn parse_args() -> io::Result<Cli> {
    let mut args = std::env::args().skip(1);
    let Some(config_path) = args.next() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage()));
    };

    let mut cli = Cli {
        config_path,
        sample: 250,
        max_versions: 16,
        request_mode: ReplayRequestMode::Full,
        emit_corpus: None,
        authoritative_scores: None,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--sample" => {
                let Some(value) = args.next() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --sample",
                    ));
                };
                cli.sample = value.parse::<usize>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("bad --sample: {e}"))
                })?;
            }
            "--max-versions" => {
                let Some(value) = args.next() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --max-versions",
                    ));
                };
                cli.max_versions = value.parse::<usize>().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("bad --max-versions: {e}"),
                    )
                })?;
            }
            "--request-mode" => {
                let Some(value) = args.next() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --request-mode",
                    ));
                };
                cli.request_mode = match value.as_str() {
                    "full" => ReplayRequestMode::Full,
                    "structure" => ReplayRequestMode::Structure,
                    "comments" => ReplayRequestMode::Comments,
                    "operands" => ReplayRequestMode::Operands,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--request-mode must be one of: full, structure, comments, operands",
                        ));
                    }
                };
            }
            "--emit-corpus" => {
                let Some(value) = args.next() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --emit-corpus",
                    ));
                };
                cli.emit_corpus = Some(value);
            }
            "--authoritative-scores" => {
                let Some(value) = args.next() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --authoritative-scores",
                    ));
                };
                cli.authoritative_scores = Some(value);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {arg}\n{usage}", usage = usage()),
                ));
            }
        }
    }

    Ok(cli)
}

fn request_mode_name(mode: ReplayRequestMode) -> &'static str {
    match mode {
        ReplayRequestMode::Full => "full",
        ReplayRequestMode::Structure => "structure",
        ReplayRequestMode::Comments => "comments",
        ReplayRequestMode::Operands => "operands",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn case_id(case: &ReplayCaseResult, mode: ReplayRequestMode) -> String {
    format!(
        "{:032x}:{}:{}",
        case.key,
        hex_bytes(&case.holdout_version_id),
        request_mode_name(mode)
    )
}

fn exact_chunk_set(data: &[u8]) -> HashSet<(u32, Vec<u8>)> {
    let parsed = parse_metadata(data);
    parsed
        .raw_chunks
        .into_iter()
        .map(|chunk| (chunk.raw_key, chunk.data))
        .collect()
}

fn bundle_payloads(data: &[u8]) -> BTreeMap<SemanticBundle, Vec<(u32, Vec<u8>)>> {
    let parsed = parse_metadata(data);
    let mut bundles: BTreeMap<SemanticBundle, Vec<(u32, Vec<u8>)>> = BTreeMap::new();
    for chunk in parsed.raw_chunks {
        bundles
            .entry(bundle_for_mdkey(chunk.key))
            .or_default()
            .push((chunk.raw_key, chunk.data));
    }
    for payloads in bundles.values_mut() {
        payloads.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    }
    bundles
}

fn selection_metrics(
    selector: &ReplaySelectorResult,
    holdout_name: &str,
    holdout_data: &[u8],
    requested_mdkeys: &[u32],
) -> SelectionMetrics {
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    let selected_meta = parse_metadata(&selector.data);
    let coverage_den = requested.len().max(1) as f64;
    let coverage_ratio = if requested.is_empty() {
        if selector.data == holdout_data {
            1.0
        } else {
            0.0
        }
    } else {
        (selected_meta.requested_coverage(&requested) as f64) / coverage_den
    };

    let holdout_chunks = exact_chunk_set(holdout_data);
    let selected_chunks = exact_chunk_set(&selector.data);
    let chunk_matches = holdout_chunks.intersection(&selected_chunks).count() as f64;
    let chunk_precision = if selected_chunks.is_empty() && holdout_chunks.is_empty() {
        1.0
    } else if selected_chunks.is_empty() {
        0.0
    } else {
        chunk_matches / (selected_chunks.len() as f64)
    };
    let chunk_recall = if selected_chunks.is_empty() && holdout_chunks.is_empty() {
        1.0
    } else if holdout_chunks.is_empty() {
        0.0
    } else {
        chunk_matches / (holdout_chunks.len() as f64)
    };
    let chunk_f1 = harmonic_mean(chunk_precision, chunk_recall);

    let holdout_bundles = bundle_payloads(holdout_data);
    let selected_bundles = bundle_payloads(&selector.data);
    let bundle_matches = holdout_bundles
        .iter()
        .filter(|(bundle, payloads)| selected_bundles.get(bundle) == Some(*payloads))
        .count() as f64;
    let bundle_precision = if selected_bundles.is_empty() && holdout_bundles.is_empty() {
        1.0
    } else if selected_bundles.is_empty() {
        0.0
    } else {
        bundle_matches / (selected_bundles.len() as f64)
    };
    let bundle_recall = if selected_bundles.is_empty() && holdout_bundles.is_empty() {
        1.0
    } else if holdout_bundles.is_empty() {
        0.0
    } else {
        bundle_matches / (holdout_bundles.len() as f64)
    };
    let bundle_f1 = harmonic_mean(bundle_precision, bundle_recall);

    SelectionMetrics {
        exact_bytes: selector.data == holdout_data,
        exact_name: selector.name == holdout_name,
        coverage_ratio,
        chunk_precision,
        chunk_recall,
        chunk_f1,
        bundle_precision,
        bundle_recall,
        bundle_f1,
    }
}

fn harmonic_mean(a: f64, b: f64) -> f64 {
    if a <= f64::EPSILON || b <= f64::EPSILON {
        0.0
    } else {
        (2.0 * a * b) / (a + b)
    }
}

fn apply_metrics(
    acc: &mut MetricAccumulator,
    selector: &ReplaySelectorResult,
    metrics: &SelectionMetrics,
) {
    acc.cases += 1;
    acc.exact_bytes += usize::from(metrics.exact_bytes);
    acc.exact_names += usize::from(metrics.exact_name);
    acc.coverage_sum += metrics.coverage_ratio;
    acc.chunk_precision_sum += metrics.chunk_precision;
    acc.chunk_recall_sum += metrics.chunk_recall;
    acc.chunk_f1_sum += metrics.chunk_f1;
    acc.bundle_precision_sum += metrics.bundle_precision;
    acc.bundle_recall_sum += metrics.bundle_recall;
    acc.bundle_f1_sum += metrics.bundle_f1;
    acc.margin_sum += selector.margin;
    acc.entropy_sum += selector.entropy;
    acc.synthesis_count += usize::from(selector.used_synthesis);
}

fn print_metric_block(label: &str, acc: &MetricAccumulator) {
    let denom = acc.cases.max(1) as f64;
    println!("{label}:");
    println!("  cases                {}", acc.cases);
    println!(
        "  exact bytes          {:>6.2}%",
        (acc.exact_bytes as f64 / denom) * 100.0
    );
    println!(
        "  exact names          {:>6.2}%",
        (acc.exact_names as f64 / denom) * 100.0
    );
    println!("  requested coverage   {:>6.3}", acc.coverage_sum / denom);
    println!(
        "  chunk precision      {:>6.3}",
        acc.chunk_precision_sum / denom
    );
    println!(
        "  chunk recall         {:>6.3}",
        acc.chunk_recall_sum / denom
    );
    println!("  chunk f1             {:>6.3}", acc.chunk_f1_sum / denom);
    println!(
        "  bundle precision     {:>6.3}",
        acc.bundle_precision_sum / denom
    );
    println!(
        "  bundle recall        {:>6.3}",
        acc.bundle_recall_sum / denom
    );
    println!("  bundle f1            {:>6.3}", acc.bundle_f1_sum / denom);
    println!("  mean margin          {:>6.3}", acc.margin_sum / denom);
    println!("  mean entropy         {:>6.3}", acc.entropy_sum / denom);
    println!(
        "  entropy reduction    {:>6.3}",
        1.0 - (acc.entropy_sum / denom)
    );
    println!(
        "  used synthesis       {:>6.2}%",
        (acc.synthesis_count as f64 / denom) * 100.0
    );
    println!();
}

fn load_authoritative_scores(path: &str) -> io::Result<HashMap<(String, String), f64>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut scores = HashMap::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: AuthoritativeScoreRow = serde_json::from_str(&line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{path}:{}: {e}", lineno + 1),
            )
        })?;
        scores.insert((row.case_id, row.selector), row.score);
    }
    Ok(scores)
}

fn maybe_record_authoritative(
    acc: &mut AuthoritativeAccumulator,
    case_id: &str,
    semantic: &ReplaySelectorResult,
    authoritative: &HashMap<(String, String), f64>,
) {
    let semantic_score = authoritative
        .get(&(case_id.to_string(), "semantic".to_string()))
        .copied();
    let baseline_score = authoritative
        .get(&(case_id.to_string(), "baseline".to_string()))
        .copied();

    if let (Some(semantic_score), Some(baseline_score)) = (semantic_score, baseline_score) {
        acc.paired_cases += 1;
        acc.semantic_score_sum += semantic_score;
        acc.baseline_score_sum += baseline_score;
        acc.semantic_margin_pairs
            .push((semantic.margin, semantic_score));
        acc.semantic_confidence_pairs
            .push((1.0 - semantic.entropy, semantic_score));
    }
}

fn pearson_correlation(pairs: &[(f64, f64)]) -> Option<f64> {
    if pairs.len() < 2 {
        return None;
    }
    let n = pairs.len() as f64;
    let sum_x: f64 = pairs.iter().map(|(x, _)| *x).sum();
    let sum_y: f64 = pairs.iter().map(|(_, y)| *y).sum();
    let mean_x = sum_x / n;
    let mean_y = sum_y / n;

    let mut num = 0.0;
    let mut den_x = 0.0;
    let mut den_y = 0.0;
    for (x, y) in pairs {
        let dx = *x - mean_x;
        let dy = *y - mean_y;
        num += dx * dy;
        den_x += dx * dx;
        den_y += dy * dy;
    }
    let denom = (den_x * den_y).sqrt();
    if denom <= f64::EPSILON {
        None
    } else {
        Some(num / denom)
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = parse_args()?;
    let config = Arc::new(load_config(&cli.config_path)?);
    let db = Database::open_for_replay(config).await?;
    let options = ReplayCaseOptions {
        request_mode: cli.request_mode,
        max_versions: cli.max_versions,
    };
    let authoritative = if let Some(path) = &cli.authoritative_scores {
        Some(load_authoritative_scores(path)?)
    } else {
        None
    };
    let mut corpus_writer = if let Some(path) = &cli.emit_corpus {
        Some(BufWriter::new(File::create(path)?))
    } else {
        None
    };

    let mut baseline_acc = MetricAccumulator::default();
    let mut semantic_acc = MetricAccumulator::default();
    let mut authoritative_acc = AuthoritativeAccumulator::default();
    let mut eligible = 0usize;
    let mut sampled = 0usize;

    let scan_limit = cli.sample.saturating_mul(64).max(cli.sample);
    for key in db.list_keys(Some(scan_limit)) {
        if sampled >= cli.sample {
            break;
        }
        let Some(case) = db.replay_select_for_key(key, &options).await? else {
            continue;
        };
        eligible += 1;
        sampled += 1;

        let baseline_metrics = selection_metrics(
            &case.baseline,
            &case.holdout_name,
            &case.holdout_data,
            &case.requested_mdkeys,
        );
        let semantic_metrics = selection_metrics(
            &case.semantic,
            &case.holdout_name,
            &case.holdout_data,
            &case.requested_mdkeys,
        );
        apply_metrics(&mut baseline_acc, &case.baseline, &baseline_metrics);
        apply_metrics(&mut semantic_acc, &case.semantic, &semantic_metrics);

        let cid = case_id(&case, cli.request_mode);
        if let Some(scores) = &authoritative {
            maybe_record_authoritative(&mut authoritative_acc, &cid, &case.semantic, scores);
        }

        if let Some(writer) = corpus_writer.as_mut() {
            let row = ReplayCorpusRow {
                case_id: cid,
                key_hex: format!("{:032x}", case.key),
                holdout_version_id: hex_bytes(&case.holdout_version_id),
                request_mode: request_mode_name(cli.request_mode).to_string(),
                requested_mdkeys: case.requested_mdkeys.clone(),
                candidate_count: case.candidate_count,
                holdout_name: case.holdout_name.clone(),
                holdout_data_hex: hex_bytes(&case.holdout_data),
                baseline_base_version_id: hex_bytes(&case.baseline.base_version_id),
                baseline_name: case.baseline.name.clone(),
                baseline_data_hex: hex_bytes(&case.baseline.data),
                semantic_base_version_id: hex_bytes(&case.semantic.base_version_id),
                semantic_name: case.semantic.name.clone(),
                semantic_data_hex: hex_bytes(&case.semantic.data),
                semantic_score: case.semantic.score,
                semantic_margin: case.semantic.margin,
                semantic_entropy: case.semantic.entropy,
                semantic_used_synthesis: case.semantic.used_synthesis,
            };
            serde_json::to_writer(&mut *writer, &row)
                .map_err(|e| io::Error::other(format!("json write: {e}")))?;
            writer.write_all(b"\n")?;
        }
    }

    println!("Semantic Replay Evaluation");
    println!("  design               retrospective within-key replay; stored observations are not held out");
    println!("  interpretation       agreement with a stored version, not independent accuracy");
    println!(
        "  request mode         {}",
        request_mode_name(cli.request_mode)
    );
    println!("  sampled cases        {}", sampled);
    println!("  eligible cases       {}", eligible);
    println!();
    print_metric_block("Baseline (latest previous version)", &baseline_acc);
    print_metric_block("Semantic selector", &semantic_acc);

    println!("Delta:");
    let denom = semantic_acc.cases.max(1) as f64;
    println!(
        "  exact bytes lift     {:+.2}%",
        ((semantic_acc.exact_bytes as f64 - baseline_acc.exact_bytes as f64) / denom) * 100.0
    );
    println!(
        "  exact names lift     {:+.2}%",
        ((semantic_acc.exact_names as f64 - baseline_acc.exact_names as f64) / denom) * 100.0
    );
    println!(
        "  coverage lift        {:+.3}",
        (semantic_acc.coverage_sum - baseline_acc.coverage_sum) / denom
    );
    println!(
        "  chunk f1 lift        {:+.3}",
        (semantic_acc.chunk_f1_sum - baseline_acc.chunk_f1_sum) / denom
    );
    println!(
        "  bundle f1 lift       {:+.3}",
        (semantic_acc.bundle_f1_sum - baseline_acc.bundle_f1_sum) / denom
    );
    println!();

    if authoritative.is_some() {
        println!("Authoritative Comparison:");
        println!("  paired cases         {}", authoritative_acc.paired_cases);
        if authoritative_acc.paired_cases > 0 {
            let denom = authoritative_acc.paired_cases as f64;
            println!(
                "  baseline mean score  {:.3}",
                authoritative_acc.baseline_score_sum / denom
            );
            println!(
                "  semantic mean score  {:.3}",
                authoritative_acc.semantic_score_sum / denom
            );
            println!(
                "  mean score lift      {:+.3}",
                (authoritative_acc.semantic_score_sum - authoritative_acc.baseline_score_sum)
                    / denom
            );
            if let Some(r) = pearson_correlation(&authoritative_acc.semantic_margin_pairs) {
                println!("  corr(margin, score)  {:.3}", r);
            }
            if let Some(r) = pearson_correlation(&authoritative_acc.semantic_confidence_pairs) {
                println!("  corr(confidence, score) {:.3}", r);
            }
        }
        println!();
    } else {
        println!("Authoritative Comparison:");
        println!("  no authoritative score file supplied");
        println!("  expected jsonl rows: {{\"case_id\":\"...\",\"selector\":\"baseline|semantic\",\"score\":123.4}}\n");
    }

    if let Some(writer) = corpus_writer.as_mut() {
        writer.flush()?;
    }

    Ok(())
}
