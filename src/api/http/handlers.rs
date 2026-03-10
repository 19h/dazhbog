//! HTTP request handlers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, Request, Response, StatusCode};
use log::*;
use percent_encoding::percent_decode_str;
use serde::Serialize;
use std::sync::Arc;

use crate::api::metrics::METRICS;
use crate::common::demangle;
use crate::db::{
    BinaryCompareBucket, BinaryCompareItem, BinaryFacetSummary, BinarySummary, Database,
};
use crate::engine::SearchHit;
use crate::protocol::lumina::metadata::{
    parse_metadata, InsnCmt, MdKey, MetadataChunk, OpaqueMetadataBlob,
};

fn parse_jumptable_addr(cmt: &str) -> Option<(&str, &str)> {
    let rest = cmt.strip_prefix("jumptable ")?;
    let mut parts = rest.splitn(2, ' ');
    let addr = parts.next()?.trim();
    let relation = parts.next().unwrap_or("").trim();
    if addr.is_empty() {
        return None;
    }
    Some((addr, relation))
}

fn estimate_case_count(relation: &str) -> usize {
    let mut count = 0usize;
    for token in relation.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = token.trim();
        if tok.is_empty() || tok == "case" || tok == "cases" || tok == "default" {
            continue;
        }
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
                if b >= a {
                    count += (b - a + 1) as usize;
                    continue;
                }
            }
        }
        if tok.chars().all(|c| c.is_ascii_digit()) {
            count += 1;
        }
    }
    count
}

fn extract_case_labels(relation: &str) -> Vec<String> {
    let mut labels = Vec::new();
    if relation.contains("default case") {
        labels.push("default".to_string());
    }

    let mut capture = false;
    for token in relation.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = token.trim();
        if tok.is_empty() {
            continue;
        }
        if tok == "case" || tok == "cases" {
            capture = true;
            continue;
        }
        if !capture {
            continue;
        }
        if tok.chars().all(|c| c.is_ascii_digit() || c == '-') {
            labels.push(tok.to_string());
        }
    }

    labels.sort();
    labels.dedup();
    labels
}

fn sort_case_label_key(label: &str) -> (i64, i64, &str) {
    if label == "default" {
        return (i64::MAX, i64::MAX, label);
    }
    if let Some((a, b)) = label.split_once('-') {
        if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
            return (a, b, label);
        }
    }
    if let Ok(v) = label.parse::<i64>() {
        return (v, v, label);
    }
    (i64::MAX - 1, i64::MAX - 1, label)
}

fn normalize_case_labels(labels: &[String]) -> Vec<String> {
    let mut nums = Vec::<i64>::new();
    let mut ranges = Vec::<(i64, i64)>::new();
    let mut has_default = false;

    for label in labels {
        if label == "default" {
            has_default = true;
            continue;
        }
        if let Some((a, b)) = label.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
                if b >= a {
                    ranges.push((a, b));
                    continue;
                }
            }
        }
        if let Ok(v) = label.parse::<i64>() {
            nums.push(v);
        }
    }

    for n in nums {
        ranges.push((n, n));
    }
    if ranges.is_empty() {
        let mut out = Vec::new();
        if has_default {
            out.push("default".to_string());
        }
        return out;
    }

    ranges.sort_unstable();
    let mut merged = Vec::<(i64, i64)>::new();
    for (a, b) in ranges {
        if let Some((_, last_b)) = merged.last_mut() {
            if a <= *last_b + 1 {
                *last_b = (*last_b).max(b);
                continue;
            }
        }
        merged.push((a, b));
    }

    let mut out = merged
        .into_iter()
        .map(|(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect::<Vec<_>>();
    if has_default {
        out.push("default".to_string());
    }
    out
}

fn expand_case_labels(labels: &[String]) -> Vec<i64> {
    let mut out = Vec::new();
    for label in labels {
        if label == "default" {
            continue;
        }
        if let Some((a, b)) = label.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
                for v in a..=b {
                    out.push(v);
                }
                continue;
            }
        }
        if let Ok(v) = label.parse::<i64>() {
            out.push(v);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn compress_case_numbers(nums: &[i64]) -> Vec<String> {
    if nums.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = nums[0];
    let mut last = nums[0];
    for &v in &nums[1..] {
        if v == last + 1 {
            last = v;
        } else {
            out.push(if start == last {
                start.to_string()
            } else {
                format!("{start}-{last}")
            });
            start = v;
            last = v;
        }
    }
    out.push(if start == last {
        start.to_string()
    } else {
        format!("{start}-{last}")
    });
    out
}

fn classify_source_role(relation: &str, labels: &[String]) -> &'static str {
    if relation.contains("default case") {
        return "default";
    }
    if relation.contains("case") || labels.iter().any(|l| l != "default") {
        return "case";
    }
    "entry"
}

fn derive_control_flow(
    insn_cmts: &[InsnCmt],
    rpt_insn_cmts: &[InsnCmt],
) -> Option<ControlFlowJson> {
    let mut switches = Vec::new();
    let mut tables: std::collections::BTreeMap<String, JumpTableJson> =
        std::collections::BTreeMap::new();

    for (kind, items) in [("REG", insn_cmts), ("RPT", rpt_insn_cmts)] {
        for c in items {
            let text = c.cmt.trim();
            if text.starts_with("switch ") {
                switches.push(SwitchSiteJson {
                    kind: kind.to_string(),
                    fchunk_nr: c.fchunk_nr,
                    fchunk_off: c.fchunk_off,
                    description: text.to_string(),
                });
            }
            if let Some((addr, relation)) = parse_jumptable_addr(text) {
                let entry = tables
                    .entry(addr.to_string())
                    .or_insert_with(|| JumpTableJson {
                        addr: addr.to_string(),
                        refs: Vec::new(),
                        case_count: 0,
                        has_default: false,
                        all_case_labels: Vec::new(),
                        coverage_runs: Vec::new(),
                        sparse: false,
                    });
                let case_labels = normalize_case_labels(&extract_case_labels(relation));
                entry.refs.push(JumpTableRefJson {
                    kind: kind.to_string(),
                    fchunk_nr: c.fchunk_nr,
                    fchunk_off: c.fchunk_off,
                    relation: relation.to_string(),
                    case_labels: case_labels.clone(),
                    is_default: relation.contains("default case"),
                    lane_size: 1,
                    source_role: classify_source_role(relation, &case_labels).to_string(),
                });
                entry.case_count = entry.case_count.max(estimate_case_count(relation));
                if relation.contains("default case") {
                    entry.has_default = true;
                }
                entry.all_case_labels.extend(case_labels);
            }
        }
    }

    for table in tables.values_mut() {
        table.all_case_labels = normalize_case_labels(&table.all_case_labels);
        let expanded = expand_case_labels(&table.all_case_labels);
        table.coverage_runs = compress_case_numbers(&expanded);
        table.sparse = if expanded.len() >= 2 {
            let min = *expanded.first().unwrap_or(&0);
            let max = *expanded.last().unwrap_or(&0);
            let span = (max - min + 1).max(1) as usize;
            expanded.len() * 2 < span
        } else {
            false
        };
        let mut grouped: std::collections::BTreeMap<(String, String), JumpTableRefJson> =
            std::collections::BTreeMap::new();
        for mut r in std::mem::take(&mut table.refs) {
            r.case_labels = normalize_case_labels(&r.case_labels);
            let key = (r.kind.clone(), r.relation.clone());
            if let Some(existing) = grouped.get_mut(&key) {
                existing.lane_size += 1;
            } else {
                grouped.insert(key, r);
            }
        }
        table.refs = grouped.into_values().collect();
        table.refs.sort_by(|a, b| {
            a.fchunk_nr
                .cmp(&b.fchunk_nr)
                .then(a.fchunk_off.cmp(&b.fchunk_off))
                .then(
                    sort_case_label_key(a.case_labels.first().map(String::as_str).unwrap_or(""))
                        .cmp(&sort_case_label_key(
                            b.case_labels.first().map(String::as_str).unwrap_or(""),
                        )),
                )
        });
    }

    let dominant = tables
        .values()
        .max_by_key(|jt| (jt.refs.len(), jt.case_count))
        .map(|jt| DominantSwitchJson {
            addr: jt.addr.clone(),
            ref_count: jt.refs.len(),
            case_count: jt.case_count,
            labels: jt.all_case_labels.iter().take(12).cloned().collect(),
        });

    if switches.is_empty() && tables.is_empty() {
        None
    } else {
        Some(ControlFlowJson {
            switches,
            jumptables: tables.into_values().collect(),
            dominant,
        })
    }
}

/// Search response structure with pagination.
#[derive(Serialize)]
pub struct SearchResponse {
    mode: &'static str,
    query: String,
    results: Vec<SearchHit>,
    total: usize,
    page: usize,
    per_page: usize,
    total_pages: usize,
}

#[derive(Serialize)]
pub struct BinarySearchResponse {
    mode: &'static str,
    query: String,
    results: Vec<BinarySummary>,
    total: usize,
    page: usize,
    per_page: usize,
    total_pages: usize,
}

#[derive(Serialize)]
pub struct TypePartsJson {
    pub userti: bool,
    pub declaration: Option<String>,
    pub decode_error: Option<String>,
}

#[derive(Serialize)]
pub struct SerializedTinfoJson {
    pub declaration: Option<String>,
    pub decode_error: Option<String>,
}

#[derive(Serialize)]
pub struct FrameMemJson {
    pub name: Option<String>,
    pub tinfo: Option<SerializedTinfoJson>,
    pub cmt: Option<String>,
    pub rptcmt: Option<String>,
    pub offset: Option<u64>,
    pub nbytes: Option<u64>,
    pub has_info: bool,
}

#[derive(Serialize)]
pub struct FrameDescJson {
    pub frsize: u64,
    pub argsize: u64,
    pub frregs: u16,
    pub members: Vec<FrameMemJson>,
}

#[derive(Serialize)]
pub struct InsnCmtJson {
    pub fchunk_nr: u32,
    pub fchunk_off: u32,
    pub cmt: String,
}

#[derive(Serialize)]
pub struct OpaqueMetadataBlobJson {
    pub size: usize,
    pub printable_texts: Vec<String>,
}

#[derive(Serialize)]
pub struct MetadataChunkJson {
    pub raw_key: u32,
    pub key_name: String,
    pub size: usize,
    pub printable_texts: Vec<String>,
}

#[derive(Serialize)]
pub struct SwitchSiteJson {
    pub kind: String,
    pub fchunk_nr: u32,
    pub fchunk_off: u32,
    pub description: String,
}

#[derive(Serialize)]
pub struct JumpTableRefJson {
    pub kind: String,
    pub fchunk_nr: u32,
    pub fchunk_off: u32,
    pub relation: String,
    pub case_labels: Vec<String>,
    pub is_default: bool,
    pub lane_size: usize,
    pub source_role: String,
}

#[derive(Serialize)]
pub struct JumpTableJson {
    pub addr: String,
    pub refs: Vec<JumpTableRefJson>,
    pub case_count: usize,
    pub has_default: bool,
    pub all_case_labels: Vec<String>,
    pub coverage_runs: Vec<String>,
    pub sparse: bool,
}

#[derive(Serialize)]
pub struct DominantSwitchJson {
    pub addr: String,
    pub ref_count: usize,
    pub case_count: usize,
    pub labels: Vec<String>,
}

#[derive(Serialize)]
pub struct ControlFlowJson {
    pub switches: Vec<SwitchSiteJson>,
    pub jumptables: Vec<JumpTableJson>,
    pub dominant: Option<DominantSwitchJson>,
}

/// Parsed metadata for JSON response.
#[derive(Serialize)]
pub struct ParsedMetadataJson {
    pub raw_size: usize,
    pub bytes_parsed: usize,
    pub errors: Vec<String>,
    pub raw_chunk_count: usize,
    pub raw_chunks: Vec<MetadataChunkJson>,
    pub type_parts: Option<TypePartsJson>,
    pub frame_desc: Option<FrameDescJson>,
    pub vd_elapsed: Option<u64>,
    pub fcmt: Option<String>,
    pub frptcmt: Option<String>,
    pub extra_cmts: Vec<String>,
    pub user_stkpnts: Option<OpaqueMetadataBlobJson>,
    pub ops: Option<OpaqueMetadataBlobJson>,
    pub ops_ex: Option<OpaqueMetadataBlobJson>,
    pub control_flow: Option<ControlFlowJson>,
    pub insn_cmts: Vec<InsnCmtJson>,
    pub rpt_insn_cmts: Vec<InsnCmtJson>,
}

/// Function detail response with full metadata.
#[derive(Serialize)]
pub struct FunctionDetailResponse {
    pub key_hex: String,
    pub name: String,
    pub raw_name: Option<String>,
    pub lang: Option<String>,
    pub popularity: u32,
    pub ts: u64,
    pub data_size: usize,
    pub metadata: Option<ParsedMetadataJson>,
    pub binary_names: Vec<String>,
    pub binaries: Vec<crate::engine::BinaryRefHit>,
}

#[derive(Serialize)]
pub struct SemanticNeighborsResponse {
    pub key_hex: String,
    pub limit: usize,
    pub strict_family: bool,
    pub results: Vec<SearchHit>,
}

#[derive(Serialize)]
pub struct BinaryOverlapEdge {
    pub target: BinarySummary,
    pub shared_functions: u64,
    pub shared_observations: u64,
    pub known_overlap_pct: f32,
    pub observed_overlap_pct: f32,
}

#[derive(Serialize)]
pub struct BinaryGraphNode {
    pub binary: BinarySummary,
}

#[derive(Serialize)]
pub struct BinaryGraphEdge {
    pub source_md5: String,
    pub target_md5: String,
    pub shared_functions: u64,
}

#[derive(Serialize)]
pub struct BinaryGraphResponse {
    pub nodes: Vec<BinaryGraphNode>,
    pub edges: Vec<BinaryGraphEdge>,
}

#[derive(Serialize)]
pub struct BinaryCompareResponse {
    pub left: BinarySummary,
    pub right: BinarySummary,
    pub left_facets: BinaryFacetSummary,
    pub right_facets: BinaryFacetSummary,
    pub shared_count: usize,
    pub left_only_count: usize,
    pub right_only_count: usize,
    pub sample_limit: usize,
    pub active_bucket: String,
    pub active_bucket_total: usize,
    pub active_bucket_page: usize,
    pub active_bucket_total_pages: usize,
    pub active_bucket_query: String,
    pub active_bucket_items: Vec<BinaryCompareItem>,
    pub shared: Vec<BinaryCompareItem>,
    pub left_only: Vec<BinaryCompareItem>,
    pub right_only: Vec<BinaryCompareItem>,
    pub buckets: Vec<BinaryCompareBucket>,
}

#[derive(Serialize)]
pub struct BinaryFunctionsPage {
    pub results: Vec<SearchHit>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub total_pages: usize,
}

#[derive(Serialize)]
pub struct BinaryDetailResponse {
    pub binary: BinarySummary,
    pub facets: BinaryFacetSummary,
    pub related: Vec<BinaryOverlapEdge>,
    pub graph: BinaryGraphResponse,
    pub timeline: Vec<BinaryTimelineItem>,
    pub functions: BinaryFunctionsPage,
}

#[derive(Serialize)]
pub struct BinaryGraphConfigResponse {
    pub depth: usize,
    pub limit: usize,
    pub graph: BinaryGraphResponse,
}

#[derive(Serialize)]
pub struct BinaryTimelineItem {
    pub binary: BinarySummary,
    pub shared_functions: u64,
    pub shared_observations: u64,
    pub known_overlap_pct: f32,
    pub observed_overlap_pct: f32,
    pub is_root: bool,
}

/// Metrics snapshot for JSON API.
#[derive(Serialize)]
pub struct MetricsSnapshot {
    // Database stats
    indexed_funcs: u64,
    total_records: u64,
    storage_bytes: u64,
    search_docs: u64,
    unique_binaries: u64,
    uptime_secs: u64,
    start_time: u64,

    // Traffic counters
    pulls: u64,
    pushes: u64,
    new_funcs: u64,
    queried_funcs: u64,
    active_connections: u64,

    // Protocol counters
    lumina_v0_4: u64,
    lumina_v5p: u64,

    // Error counters
    errors: u64,
    timeouts: u64,
    index_overflows: u64,
    append_failures: u64,
    decoder_rejects: u64,

    // Upstream counters
    upstream_requests: u64,
    upstream_fetched: u64,
    upstream_errors: u64,

    // Scoring counters
    scoring_batches: u64,
    scoring_versions_considered: u64,
    scoring_fallback_latest: u64,
}

/// Get current metrics snapshot.
pub fn metrics_snapshot() -> MetricsSnapshot {
    use std::sync::atomic::Ordering::Relaxed;
    MetricsSnapshot {
        // Database stats
        indexed_funcs: METRICS.indexed_funcs.load(Relaxed),
        total_records: METRICS.total_records.load(Relaxed),
        storage_bytes: METRICS.storage_bytes.load(Relaxed),
        search_docs: METRICS.search_docs.load(Relaxed),
        unique_binaries: METRICS.unique_binaries.load(Relaxed),
        uptime_secs: METRICS.uptime_secs(),
        start_time: METRICS.start_time.load(Relaxed),

        // Traffic counters
        pulls: METRICS.pulls.load(Relaxed),
        pushes: METRICS.pushes.load(Relaxed),
        new_funcs: METRICS.new_funcs.load(Relaxed),
        queried_funcs: METRICS.queried_funcs.load(Relaxed),
        active_connections: METRICS.active_connections.load(Relaxed),

        // Protocol counters
        lumina_v0_4: METRICS.lumina_v0_4.load(Relaxed),
        lumina_v5p: METRICS.lumina_v5p.load(Relaxed),

        // Error counters
        errors: METRICS.errors.load(Relaxed),
        timeouts: METRICS.timeouts.load(Relaxed),
        index_overflows: METRICS.index_overflows.load(Relaxed),
        append_failures: METRICS.append_failures.load(Relaxed),
        decoder_rejects: METRICS.decoder_rejects.load(Relaxed),

        // Upstream counters
        upstream_requests: METRICS.upstream_requests.load(Relaxed),
        upstream_fetched: METRICS.upstream_fetched.load(Relaxed),
        upstream_errors: METRICS.upstream_errors.load(Relaxed),

        // Scoring counters
        scoring_batches: METRICS.scoring_batches.load(Relaxed),
        scoring_versions_considered: METRICS.scoring_versions_considered.load(Relaxed),
        scoring_fallback_latest: METRICS.scoring_fallback_latest.load(Relaxed),
    }
}

/// Parse a query parameter from a request.
pub fn parse_query_param(req: &Request<Incoming>, key: &str) -> Option<String> {
    let query = req.uri().query()?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        if k == key {
            let raw = it.next().unwrap_or_default();
            return percent_decode_str(raw)
                .decode_utf8()
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}

/// Create a JSON response.
pub fn json_response<T: Serialize>(value: &T, status: StatusCode) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut r = Response::new(Full::new(Bytes::from(body)));
            *r.status_mut() = status;
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
            r
        }
        Err(e) => {
            error!("json serialize error: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from_static(
                    b"{\"error\":\"serialization\"}",
                )))
                .unwrap()
        }
    }
}

fn trim_preview_text(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut chars = text.trim().chars();
    for _ in 0..max_chars {
        let Some(ch) = chars.next() else {
            return out;
        };
        out.push(ch);
    }
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

fn compact_preview_texts(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|item| trim_preview_text(item, 160))
        .filter(|item| !item.is_empty())
        .take(8)
        .collect()
}

fn extract_chunk_printable_texts(data: &[u8]) -> Vec<String> {
    let mut texts = Vec::new();
    let mut current = Vec::new();
    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else if current.len() >= 3 {
            texts.push(String::from_utf8_lossy(&current).into_owned());
            current.clear();
        } else {
            current.clear();
        }
    }
    if current.len() >= 3 {
        texts.push(String::from_utf8_lossy(&current).into_owned());
    }
    texts.sort();
    texts.dedup();
    compact_preview_texts(&texts)
}

fn mdkey_name(mdkey: MdKey, raw_key: u32) -> String {
    match mdkey {
        MdKey::None => "MDK_NONE".to_string(),
        MdKey::Type => "MDK_TYPE".to_string(),
        MdKey::VdElapsed => "MDK_VD_ELAPSED".to_string(),
        MdKey::Fcmt => "MDK_FCMT".to_string(),
        MdKey::Frptcmt => "MDK_FRPTCMT".to_string(),
        MdKey::Cmts => "MDK_CMTS".to_string(),
        MdKey::Rptcmts => "MDK_RPTCMTS".to_string(),
        MdKey::Extracmts => "MDK_EXTRACMTS".to_string(),
        MdKey::UserStkpnts => "MDK_USER_STKPNTS".to_string(),
        MdKey::FrameDesc => "MDK_FRAME_DESC".to_string(),
        MdKey::Ops => "MDK_OPS".to_string(),
        MdKey::OpsEx => "MDK_OPS_EX".to_string(),
        MdKey::Other(_) => format!("MDK_OTHER_{raw_key}"),
    }
}

fn metadata_chunk_to_json(chunk: &MetadataChunk) -> MetadataChunkJson {
    MetadataChunkJson {
        raw_key: chunk.raw_key,
        key_name: mdkey_name(chunk.key, chunk.raw_key),
        size: chunk.data.len(),
        printable_texts: extract_chunk_printable_texts(&chunk.data),
    }
}

fn opaque_blob_to_json(blob: OpaqueMetadataBlob) -> OpaqueMetadataBlobJson {
    OpaqueMetadataBlobJson {
        size: blob.raw.len(),
        printable_texts: compact_preview_texts(&blob.printable_texts),
    }
}

/// Handle function detail API request.
pub async fn handle_function_detail(db: Arc<Database>, key_hex: &str) -> Response<Full<Bytes>> {
    // Parse the key from hex
    let key = match u128::from_str_radix(key_hex, 16) {
        Ok(k) => k,
        Err(_) => {
            return json_response(
                &serde_json::json!({"error": "invalid key format"}),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // Fetch the function from database
    match db.get_latest(key).await {
        Ok(Some(func)) => {
            // Parse the metadata
            let parsed = parse_metadata(&func.data);
            let control_flow = derive_control_flow(&parsed.insn_cmts, &parsed.rpt_insn_cmts);
            let raw_chunk_count = parsed.raw_chunks.len();
            let raw_chunks = parsed
                .raw_chunks
                .iter()
                .map(metadata_chunk_to_json)
                .collect();
            let extra_cmts = compact_preview_texts(&parsed.extra_cmts);
            let user_stkpnts = parsed.user_stkpnts.map(opaque_blob_to_json);
            let ops = parsed.ops.map(opaque_blob_to_json);
            let ops_ex = parsed.ops_ex.map(opaque_blob_to_json);

            let metadata = Some(ParsedMetadataJson {
                raw_size: parsed.raw_size,
                bytes_parsed: parsed.bytes_parsed,
                errors: parsed.errors,
                raw_chunk_count,
                raw_chunks,
                vd_elapsed: parsed.vd_elapsed,
                fcmt: parsed.fcmt,
                frptcmt: parsed.frptcmt,
                extra_cmts,
                user_stkpnts,
                ops,
                ops_ex,
                control_flow,
                insn_cmts: parsed
                    .insn_cmts
                    .into_iter()
                    .map(|c| InsnCmtJson {
                        fchunk_nr: c.fchunk_nr,
                        fchunk_off: c.fchunk_off,
                        cmt: c.cmt,
                    })
                    .collect(),
                rpt_insn_cmts: parsed
                    .rpt_insn_cmts
                    .into_iter()
                    .map(|c| InsnCmtJson {
                        fchunk_nr: c.fchunk_nr,
                        fchunk_off: c.fchunk_off,
                        cmt: c.cmt,
                    })
                    .collect(),
                type_parts: parsed.type_parts.map(|tp| TypePartsJson {
                    userti: tp.userti,
                    declaration: tp.declaration,
                    decode_error: tp.decode_error,
                }),
                frame_desc: parsed.frame_desc.map(|fd| FrameDescJson {
                    frsize: fd.frsize,
                    argsize: fd.argsize,
                    frregs: fd.frregs,
                    members: fd
                        .members
                        .into_iter()
                        .map(|m| FrameMemJson {
                            name: m.name,
                            tinfo: m.tinfo.map(|t| SerializedTinfoJson {
                                declaration: t.declaration,
                                decode_error: t.decode_error,
                            }),
                            cmt: m.cmt,
                            rptcmt: m.rptcmt,
                            offset: m.offset,
                            nbytes: m.nbytes,
                            has_info: m.info.is_some(),
                        })
                        .collect(),
                }),
            });

            let demangle_result = demangle(&func.name);

            // Get binary names from context index
            let binary_names = db.get_basenames_for_key(key).unwrap_or_default();
            let binaries = db.get_binary_refs_for_key(key, 12).unwrap_or_default();

            json_response(
                &FunctionDetailResponse {
                    key_hex: format!("{:032x}", key),
                    name: demangle_result.name,
                    raw_name: if demangle_result.demangled {
                        Some(func.name)
                    } else {
                        None
                    },
                    lang: demangle_result.lang.map(|lang| lang.to_string()),
                    popularity: func.popularity,
                    ts: func.ts_sec,
                    data_size: func.data.len(),
                    metadata,
                    binary_names,
                    binaries,
                },
                StatusCode::OK,
            )
        }
        Ok(None) => json_response(
            &serde_json::json!({"error": "function not found"}),
            StatusCode::NOT_FOUND,
        ),
        Err(e) => {
            error!("get_latest failed for key {}: {}", key_hex, e);
            json_response(
                &serde_json::json!({"error": "database error"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

/// Handle search API request.
pub async fn handle_search(db: Arc<Database>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let Some(q) = parse_query_param(&req, "q") else {
        return json_response(
            &serde_json::json!({"error": "missing query"}),
            StatusCode::BAD_REQUEST,
        );
    };

    // Parse pagination parameters
    const DEFAULT_PER_PAGE: usize = 25;
    const MAX_PER_PAGE: usize = 100;
    const MAX_PAGE: usize = 10_000;

    let page: usize = parse_query_param(&req, "page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .clamp(1, MAX_PAGE);

    let per_page: usize = parse_query_param(&req, "per_page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PER_PAGE)
        .clamp(1, MAX_PER_PAGE);

    let offset = (page - 1) * per_page;
    let mode = parse_query_param(&req, "mode").unwrap_or_else(|| "functions".to_string());

    if mode == "binaries" {
        match db.search_binaries_paginated(&q, offset, per_page).await {
            Ok((results, total)) => {
                let total_pages = (total + per_page - 1) / per_page;
                return json_response(
                    &BinarySearchResponse {
                        mode: "binaries",
                        query: q,
                        results,
                        total,
                        page,
                        per_page,
                        total_pages,
                    },
                    StatusCode::OK,
                );
            }
            Err(e) => {
                error!("binary search failed: {}", e);
                return json_response(
                    &serde_json::json!({"error": "binary search failed"}),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        }
    }

    match db.search_functions_paginated(&q, offset, per_page).await {
        Ok((results, total)) => {
            let total_pages = (total + per_page - 1) / per_page;
            json_response(
                &SearchResponse {
                    mode: "functions",
                    query: q,
                    results,
                    total,
                    page,
                    per_page,
                    total_pages,
                },
                StatusCode::OK,
            )
        }
        Err(e) => {
            error!("search failed: {}", e);
            json_response(
                &serde_json::json!({"error": "search failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

pub async fn handle_function_neighbors(
    db: Arc<Database>,
    key_hex: &str,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let key = match u128::from_str_radix(key_hex, 16) {
        Ok(k) => k,
        Err(_) => {
            return json_response(
                &serde_json::json!({"error": "invalid key format"}),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let limit = parse_query_param(&req, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 24);
    let strict_family = parse_query_param(&req, "strict_family")
        .map(|s| matches!(s.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    match db
        .semantic_neighbors_for_key(key, limit, strict_family)
        .await
    {
        Ok(results) => json_response(
            &SemanticNeighborsResponse {
                key_hex: format!("{:032x}", key),
                limit,
                strict_family,
                results,
            },
            StatusCode::OK,
        ),
        Err(err) => {
            error!("semantic neighbors failed for {}: {}", key_hex, err);
            json_response(
                &serde_json::json!({"error": "semantic neighbors unavailable"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

pub async fn handle_binary_detail(db: Arc<Database>, md5_hex: &str) -> Response<Full<Bytes>> {
    let md5 = match parse_md5_hex(md5_hex) {
        Some(md5) => md5,
        None => {
            return json_response(
                &serde_json::json!({"error": "invalid md5 format"}),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    match db.get_binary_summary(md5).await {
        Ok(Some(binary)) => {
            let per_page = 25usize;
            let facets = db.get_binary_facets(md5, 8192).await.unwrap_or_default();
            let (functions, total) = match db.get_binary_function_hits(md5, 0, per_page).await {
                Ok(res) => res,
                Err(e) => {
                    error!("binary functions failed: {}", e);
                    return json_response(
                        &serde_json::json!({"error": "binary functions failed"}),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                }
            };
            let related = db
                .get_binary_related(md5, 8)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(
                    |(
                        target,
                        shared_functions,
                        shared_observations,
                        known_overlap_pct,
                        observed_overlap_pct,
                    )| BinaryOverlapEdge {
                        target,
                        shared_functions,
                        shared_observations,
                        known_overlap_pct,
                        observed_overlap_pct,
                    },
                )
                .collect();
            let graph = match db.get_binary_graph(md5, 2, 6).await {
                Ok((nodes, edges)) => BinaryGraphResponse {
                    nodes: nodes
                        .into_iter()
                        .map(|binary| BinaryGraphNode { binary })
                        .collect(),
                    edges: edges
                        .into_iter()
                        .map(
                            |(source_md5, target_md5, shared_functions)| BinaryGraphEdge {
                                source_md5,
                                target_md5,
                                shared_functions,
                            },
                        )
                        .collect(),
                },
                Err(_) => BinaryGraphResponse {
                    nodes: Vec::new(),
                    edges: Vec::new(),
                },
            };
            let timeline = db
                .get_binary_family_timeline(md5, 12)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(
                    |(
                        binary,
                        shared_functions,
                        shared_observations,
                        known_overlap_pct,
                        observed_overlap_pct,
                        is_root,
                    )| BinaryTimelineItem {
                        binary,
                        shared_functions,
                        shared_observations,
                        known_overlap_pct,
                        observed_overlap_pct,
                        is_root,
                    },
                )
                .collect();
            json_response(
                &BinaryDetailResponse {
                    binary,
                    facets,
                    related,
                    graph,
                    timeline,
                    functions: BinaryFunctionsPage {
                        results: functions,
                        total,
                        page: 1,
                        per_page,
                        total_pages: (total + per_page - 1) / per_page,
                    },
                },
                StatusCode::OK,
            )
        }
        Ok(None) => json_response(
            &serde_json::json!({"error": "binary not found"}),
            StatusCode::NOT_FOUND,
        ),
        Err(e) => {
            error!("get binary failed for {}: {}", md5_hex, e);
            json_response(
                &serde_json::json!({"error": "database error"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

pub async fn handle_binary_functions(
    db: Arc<Database>,
    md5_hex: &str,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let md5 = match parse_md5_hex(md5_hex) {
        Some(md5) => md5,
        None => {
            return json_response(
                &serde_json::json!({"error": "invalid md5 format"}),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let page: usize = parse_query_param(&req, "page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let per_page: usize = parse_query_param(&req, "per_page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(25)
        .clamp(1, 100);
    let offset = (page - 1) * per_page;
    match db.get_binary_function_hits(md5, offset, per_page).await {
        Ok((results, total)) => json_response(
            &BinaryFunctionsPage {
                results,
                total,
                page,
                per_page,
                total_pages: (total + per_page - 1) / per_page,
            },
            StatusCode::OK,
        ),
        Err(e) => {
            error!("binary functions failed for {}: {}", md5_hex, e);
            json_response(
                &serde_json::json!({"error": "binary functions failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

pub async fn handle_binary_overlap(
    db: Arc<Database>,
    md5_hex: &str,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let md5 = match parse_md5_hex(md5_hex) {
        Some(md5) => md5,
        None => {
            return json_response(
                &serde_json::json!({"error": "invalid md5 format"}),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let depth: usize = parse_query_param(&req, "depth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .clamp(1, 3);
    let limit: usize = parse_query_param(&req, "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .clamp(1, 32);
    match db.get_binary_related(md5, limit * depth).await {
        Ok(edges) => json_response(
            &edges
                .into_iter()
                .map(
                    |(
                        target,
                        shared_functions,
                        shared_observations,
                        known_overlap_pct,
                        observed_overlap_pct,
                    )| BinaryOverlapEdge {
                        target,
                        shared_functions,
                        shared_observations,
                        known_overlap_pct,
                        observed_overlap_pct,
                    },
                )
                .collect::<Vec<_>>(),
            StatusCode::OK,
        ),
        Err(e) => {
            error!("binary overlap failed for {}: {}", md5_hex, e);
            json_response(
                &serde_json::json!({"error": "binary overlap failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

pub async fn handle_binary_graph(
    db: Arc<Database>,
    md5_hex: &str,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let md5 = match parse_md5_hex(md5_hex) {
        Some(md5) => md5,
        None => {
            return json_response(
                &serde_json::json!({"error": "invalid md5 format"}),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let depth: usize = parse_query_param(&req, "depth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2)
        .clamp(1, 3);
    let limit: usize = parse_query_param(&req, "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6)
        .clamp(1, 16);
    match db.get_binary_graph(md5, depth, limit).await {
        Ok((nodes, edges)) => json_response(
            &BinaryGraphConfigResponse {
                depth,
                limit,
                graph: BinaryGraphResponse {
                    nodes: nodes
                        .into_iter()
                        .map(|binary| BinaryGraphNode { binary })
                        .collect(),
                    edges: edges
                        .into_iter()
                        .map(
                            |(source_md5, target_md5, shared_functions)| BinaryGraphEdge {
                                source_md5,
                                target_md5,
                                shared_functions,
                            },
                        )
                        .collect(),
                },
            },
            StatusCode::OK,
        ),
        Err(e) => {
            error!("binary graph failed for {}: {}", md5_hex, e);
            json_response(
                &serde_json::json!({"error": "binary graph failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

pub async fn handle_binary_compare(
    db: Arc<Database>,
    left_md5_hex: &str,
    right_md5_hex: &str,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let Some(left) = parse_md5_hex(left_md5_hex) else {
        return json_response(
            &serde_json::json!({"error": "invalid left md5 format"}),
            StatusCode::BAD_REQUEST,
        );
    };
    let Some(right) = parse_md5_hex(right_md5_hex) else {
        return json_response(
            &serde_json::json!({"error": "invalid right md5 format"}),
            StatusCode::BAD_REQUEST,
        );
    };
    let Ok(Some(left_summary)) = db.get_binary_summary(left).await else {
        return json_response(
            &serde_json::json!({"error": "left binary not found"}),
            StatusCode::NOT_FOUND,
        );
    };
    let Ok(Some(right_summary)) = db.get_binary_summary(right).await else {
        return json_response(
            &serde_json::json!({"error": "right binary not found"}),
            StatusCode::NOT_FOUND,
        );
    };
    let sample_limit: usize = parse_query_param(&req, "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(18)
        .clamp(1, 100);
    let bucket_mode = parse_query_param(&req, "mode").unwrap_or_else(|| "all".to_string());
    let bucket_query = parse_query_param(&req, "q")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let bucket_page: usize = parse_query_param(&req, "page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let bucket_per_page: usize = parse_query_param(&req, "per_page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
        .clamp(1, 50);
    match db.compare_binaries(left, right, sample_limit).await {
        Ok((
            left_facets,
            right_facets,
            shared_count,
            left_only_count,
            right_only_count,
            shared,
            left_only,
            right_only,
            recent,
            metadata_rich,
            rare_symbols,
            freshest_drift,
        )) => json_response(
            &{
                let buckets = vec![
                    BinaryCompareBucket {
                        label: "Shared".to_string(),
                        items: shared.clone(),
                    },
                    BinaryCompareBucket {
                        label: "Left Only".to_string(),
                        items: left_only.clone(),
                    },
                    BinaryCompareBucket {
                        label: "Right Only".to_string(),
                        items: right_only.clone(),
                    },
                    BinaryCompareBucket {
                        label: "Recent".to_string(),
                        items: recent.clone(),
                    },
                    BinaryCompareBucket {
                        label: "Metadata Rich".to_string(),
                        items: metadata_rich.clone(),
                    },
                    BinaryCompareBucket {
                        label: "Rare Symbols".to_string(),
                        items: rare_symbols.clone(),
                    },
                    BinaryCompareBucket {
                        label: "Freshest Drift".to_string(),
                        items: freshest_drift.clone(),
                    },
                ];
                let active_label = match bucket_mode.as_str() {
                    "Shared" | "Left Only" | "Right Only" | "Recent" | "Metadata Rich"
                    | "Rare Symbols" | "Freshest Drift" => bucket_mode.clone(),
                    _ => "All".to_string(),
                };
                let merged_all = [shared.clone(), left_only.clone(), right_only.clone()].concat();
                let active_source = if active_label == "All" {
                    merged_all
                } else {
                    buckets
                        .iter()
                        .find(|b| b.label == active_label)
                        .map(|b| b.items.clone())
                        .unwrap_or_default()
                };
                let filtered: Vec<BinaryCompareItem> = active_source
                    .into_iter()
                    .filter(|item| {
                        bucket_query.is_empty()
                            || item.name.to_ascii_lowercase().contains(&bucket_query)
                            || item.key_hex.to_ascii_lowercase().contains(&bucket_query)
                    })
                    .collect();
                let active_bucket_total = filtered.len();
                let active_bucket_total_pages =
                    active_bucket_total.div_ceil(bucket_per_page).max(1);
                let active_bucket_page = bucket_page.min(active_bucket_total_pages);
                let start = (active_bucket_page - 1) * bucket_per_page;
                let active_bucket_items = filtered
                    .into_iter()
                    .skip(start)
                    .take(bucket_per_page)
                    .collect();
                BinaryCompareResponse {
                    left: left_summary,
                    right: right_summary,
                    left_facets,
                    right_facets,
                    shared_count,
                    left_only_count,
                    right_only_count,
                    sample_limit,
                    active_bucket: active_label,
                    active_bucket_total,
                    active_bucket_page,
                    active_bucket_total_pages,
                    active_bucket_query: bucket_query,
                    active_bucket_items,
                    shared,
                    left_only,
                    right_only,
                    buckets,
                }
            },
            StatusCode::OK,
        ),
        Err(e) => {
            error!(
                "binary compare failed for {} vs {}: {}",
                left_md5_hex, right_md5_hex, e
            );
            json_response(
                &serde_json::json!({"error": "binary compare failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

fn parse_md5_hex(md5_hex: &str) -> Option<[u8; 16]> {
    if md5_hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in md5_hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        out[idx] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}
