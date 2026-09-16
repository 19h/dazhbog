//! Semantic analysis helpers for canonicalization, bundle synthesis, and search indexing.

use crate::common::demangle::demangle;
use crate::config::NameRejection;
use crate::protocol::lumina::{
    parse_metadata, serialize_metadata_chunks, FunctionMetadata, MdKey, MetadataChunk,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};

const DEFAULT_NAME_PREFIXES: &[&str] = &[
    "sub_", "nullsub_", "fun_", "j_", "unknown_", "loc_", "__imp_", "thunk_", "func_",
];

/// Prefixes of IDA-generated dummy names that carry no user information.
const REJECTED_NAME_PREFIXES: &[&str] = &["sub_", "nullsub_", "fun_", "vftable_", "unknown_"];

/// Process-wide name rejection policy (`lumina.name_rejection`). Stored as a
/// global because rejection is consulted from storage internals without a config.
static NAME_REJECTION_POLICY: AtomicU8 = AtomicU8::new(1);

pub fn set_name_rejection_policy(policy: NameRejection) {
    let v = match policy {
        NameRejection::Off => 0,
        NameRejection::Prefixes => 1,
        NameRejection::Heuristic => 2,
    };
    NAME_REJECTION_POLICY.store(v, Ordering::Relaxed);
}

pub fn name_rejection_policy() -> NameRejection {
    match NAME_REJECTION_POLICY.load(Ordering::Relaxed) {
        0 => NameRejection::Off,
        2 => NameRejection::Heuristic,
        _ => NameRejection::Prefixes,
    }
}

const NAME_DISTRIBUTION_EVIDENCE_THRESHOLD_BITS: f64 = 3123.085;
const NAME_DISTRIBUTION_MATCH_THRESHOLD: f64 = 0.1;
const NAME_DISTRIBUTION_MATCH_MIN_LEN: usize = 32;
const NAME_DISTRIBUTION_MATCH_MIN_EVIDENCE_BITS: f64 = 96.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NameDistributionScore {
    pub length: usize,
    pub unknown_characters: usize,
    pub evidence_bits: f64,
    pub kl_bits_per_char: f64,
    pub match_score: f64,
    pub cross_entropy_bits_per_char: f64,
    pub entropy_bits_per_char: f64,
}

const CONSISTENCY_STOPWORDS: &[&str] = &[
    "arg", "argsize", "byte", "bytes", "case", "char", "chunk", "const", "default", "dword",
    "entry", "field", "frame", "frregs", "frsize", "int", "loc", "long", "member", "offset",
    "param", "ptr", "qword", "reg", "regs", "return", "short", "signed", "size", "state", "struct",
    "sub", "switch", "this", "type", "uint", "ulong", "unsigned", "ushort", "var", "void", "word",
];

const KNOWN_MDKEY_ORDER: [MdKey; 11] = [
    MdKey::Type,
    MdKey::VdElapsed,
    MdKey::Fcmt,
    MdKey::Frptcmt,
    MdKey::Cmts,
    MdKey::Rptcmts,
    MdKey::Extracmts,
    MdKey::UserStkpnts,
    MdKey::FrameDesc,
    MdKey::Ops,
    MdKey::OpsEx,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SemanticBundle {
    Type,
    Timing,
    Comments,
    Frame,
    Operands,
    Other(u32),
}

#[derive(Debug, Clone, Default)]
pub struct SemanticFingerprint {
    pub name_tokens: Vec<String>,
    pub tokens: Vec<String>,
    pub prototype_tokens: Vec<String>,
    pub frame_tokens: Vec<String>,
    pub comment_tokens: Vec<String>,
    pub operand_tokens: Vec<String>,
    pub language: String,
}

#[derive(Debug, Clone)]
pub struct SemanticAnalysis {
    pub metadata: FunctionMetadata,
    pub fingerprint: SemanticFingerprint,
    pub quality_score: f64,
    pub consistency_score: f64,
}

#[derive(Debug, Clone)]
pub struct SynthesisInput<'a> {
    pub score: f64,
    pub name: &'a str,
    pub raw_data: &'a [u8],
    pub metadata: &'a FunctionMetadata,
}

pub fn bundle_for_mdkey(mdkey: MdKey) -> SemanticBundle {
    match mdkey {
        MdKey::Type => SemanticBundle::Type,
        MdKey::VdElapsed => SemanticBundle::Timing,
        MdKey::Fcmt | MdKey::Frptcmt | MdKey::Cmts | MdKey::Rptcmts | MdKey::Extracmts => {
            SemanticBundle::Comments
        }
        MdKey::UserStkpnts | MdKey::FrameDesc => SemanticBundle::Frame,
        MdKey::Ops | MdKey::OpsEx => SemanticBundle::Operands,
        MdKey::Other(raw) => SemanticBundle::Other(raw),
        MdKey::None => SemanticBundle::Other(0),
    }
}

pub fn analyze_function(name: &str, data: &[u8]) -> SemanticAnalysis {
    let metadata = parse_metadata(data);
    let fingerprint = build_fingerprint(name, &metadata);
    let consistency_score =
        cross_field_consistency_score_with_fingerprint(name, &metadata, &fingerprint);
    let quality_score = metadata_quality_score_with_fingerprint(name, &metadata, &fingerprint);
    SemanticAnalysis {
        metadata,
        fingerprint,
        quality_score,
        consistency_score,
    }
}

pub fn build_fingerprint(name: &str, metadata: &FunctionMetadata) -> SemanticFingerprint {
    let demangled = demangle(name);
    let mut name_tokens = tokenize_semantic_text(name);
    if demangled.demangled {
        name_tokens.extend(tokenize_semantic_text(&demangled.name));
    }
    dedup_tokens(&mut name_tokens);
    let mut tokens = name_tokens.clone();
    let language = demangled.lang.unwrap_or("").to_string();

    let mut prototype_tokens = Vec::new();
    if let Some(type_parts) = &metadata.type_parts {
        if let Some(decl) = &type_parts.declaration {
            prototype_tokens.extend(tokenize_semantic_text(decl));
            tokens.extend(tokenize_semantic_text(decl));
        }
    }

    let mut frame_tokens = Vec::new();
    if let Some(frame) = &metadata.frame_desc {
        frame_tokens.extend(tokenize_semantic_text(&format!(
            "frsize {} argsize {} frregs {}",
            frame.frsize, frame.argsize, frame.frregs
        )));
        for member in &frame.members {
            if let Some(name) = &member.name {
                frame_tokens.extend(tokenize_semantic_text(name));
            }
            if let Some(tinfo) = &member.tinfo {
                if let Some(decl) = &tinfo.declaration {
                    frame_tokens.extend(tokenize_semantic_text(decl));
                }
            }
            if let Some(cmt) = &member.cmt {
                frame_tokens.extend(tokenize_semantic_text(cmt));
            }
            if let Some(rptcmt) = &member.rptcmt {
                frame_tokens.extend(tokenize_semantic_text(rptcmt));
            }
        }
        tokens.extend(frame_tokens.iter().cloned());
    }

    let mut comment_tokens = Vec::new();
    if let Some(fcmt) = &metadata.fcmt {
        comment_tokens.extend(tokenize_semantic_text(fcmt));
    }
    if let Some(frptcmt) = &metadata.frptcmt {
        comment_tokens.extend(tokenize_semantic_text(frptcmt));
    }
    for cmt in &metadata.insn_cmts {
        comment_tokens.extend(tokenize_semantic_text(&cmt.cmt));
    }
    for cmt in &metadata.rpt_insn_cmts {
        comment_tokens.extend(tokenize_semantic_text(&cmt.cmt));
    }
    for cmt in &metadata.extra_cmts {
        comment_tokens.extend(tokenize_semantic_text(cmt));
    }
    tokens.extend(comment_tokens.iter().cloned());

    let mut operand_tokens = Vec::new();
    if let Some(blob) = &metadata.user_stkpnts {
        for text in &blob.printable_texts {
            operand_tokens.extend(tokenize_semantic_text(text));
        }
    }
    if let Some(blob) = &metadata.ops {
        for text in &blob.printable_texts {
            operand_tokens.extend(tokenize_semantic_text(text));
        }
    }
    if let Some(blob) = &metadata.ops_ex {
        for text in &blob.printable_texts {
            operand_tokens.extend(tokenize_semantic_text(text));
        }
    }
    tokens.extend(operand_tokens.iter().cloned());

    dedup_tokens(&mut tokens);
    dedup_tokens(&mut prototype_tokens);
    dedup_tokens(&mut frame_tokens);
    dedup_tokens(&mut comment_tokens);
    dedup_tokens(&mut operand_tokens);

    SemanticFingerprint {
        name_tokens,
        tokens,
        prototype_tokens,
        frame_tokens,
        comment_tokens,
        operand_tokens,
        language,
    }
}

pub fn metadata_quality_score(name: &str, metadata: &FunctionMetadata) -> f64 {
    let fingerprint = build_fingerprint(name, metadata);
    metadata_quality_score_with_fingerprint(name, metadata, &fingerprint)
}

fn metadata_quality_score_with_fingerprint(
    name: &str,
    metadata: &FunctionMetadata,
    fingerprint: &SemanticFingerprint,
) -> f64 {
    let mut score = 0.0;

    score += name_quality(name);

    if let Some(type_parts) = &metadata.type_parts {
        score += 2.0;
        if type_parts.declaration.is_some() {
            score += 2.5;
        }
        if type_parts.decode_error.is_some() {
            score -= 0.75;
        }
    }

    if let Some(frame) = &metadata.frame_desc {
        score += 1.5;
        score += (frame.members.len().min(16) as f64) * 0.2;
    }

    score += usize_to_f64(metadata.insn_cmts.len().min(32)) * 0.15;
    score += usize_to_f64(metadata.rpt_insn_cmts.len().min(32)) * 0.15;
    score += usize_to_f64(metadata.extra_cmts.len().min(32)) * 0.1;
    score += usize_to_f64(metadata.component_count()) * 0.1;
    score += usize_to_f64(metadata.raw_chunks.len().min(16)) * 0.05;
    score += usize::from(metadata.fcmt.is_some()) as f64 * 0.75;
    score += usize::from(metadata.frptcmt.is_some()) as f64 * 0.5;
    score += usize::from(metadata.user_stkpnts.is_some()) as f64 * 0.4;
    score += usize::from(metadata.ops.is_some()) as f64 * 0.35;
    score += usize::from(metadata.ops_ex.is_some()) as f64 * 0.35;
    score += usize_to_f64(fingerprint.prototype_tokens.len().min(24)) * 0.03;
    score += usize_to_f64(fingerprint.frame_tokens.len().min(24)) * 0.02;
    score += usize_to_f64(fingerprint.comment_tokens.len().min(24)) * 0.015;
    score += usize_to_f64(fingerprint.operand_tokens.len().min(24)) * 0.015;

    if let Some(vd) = metadata.vd_elapsed {
        score += if vd > 0 { 0.15 } else { 0.05 };
    }

    score -= usize_to_f64(metadata.errors.len().min(8)) * 0.5;
    score
}

pub fn cross_field_consistency_score(name: &str, metadata: &FunctionMetadata) -> f64 {
    let fingerprint = build_fingerprint(name, metadata);
    cross_field_consistency_score_with_fingerprint(name, metadata, &fingerprint)
}

fn cross_field_consistency_score_with_fingerprint(
    name: &str,
    metadata: &FunctionMetadata,
    fingerprint: &SemanticFingerprint,
) -> f64 {
    let name_is_generic = name_quality(name) <= 0.35;
    let name_tokens = signal_token_set(&fingerprint.name_tokens);
    let prototype_tokens = signal_token_set(&fingerprint.prototype_tokens);
    let frame_tokens = signal_token_set(&fingerprint.frame_tokens);
    let comment_tokens = signal_token_set(&fingerprint.comment_tokens);
    let operand_tokens = signal_token_set(&fingerprint.operand_tokens);

    let populated = [
        !name_tokens.is_empty(),
        !prototype_tokens.is_empty(),
        !frame_tokens.is_empty(),
        !comment_tokens.is_empty(),
        !operand_tokens.is_empty(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    if populated <= 1 {
        return if metadata.raw_chunks.is_empty() {
            0.0
        } else {
            0.45
        };
    }

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for (lhs_name, lhs_tokens, rhs_name, rhs_tokens, base_weight) in [
        ("name", &name_tokens, "prototype", &prototype_tokens, 0.28),
        ("name", &name_tokens, "frame", &frame_tokens, 0.16),
        ("name", &name_tokens, "comment", &comment_tokens, 0.14),
        ("prototype", &prototype_tokens, "frame", &frame_tokens, 0.24),
        (
            "prototype",
            &prototype_tokens,
            "comment",
            &comment_tokens,
            0.08,
        ),
        ("frame", &frame_tokens, "comment", &comment_tokens, 0.06),
        ("frame", &frame_tokens, "operand", &operand_tokens, 0.04),
    ] {
        if lhs_tokens.is_empty() || rhs_tokens.is_empty() {
            continue;
        }
        let mut weight = base_weight;
        if name_is_generic && (lhs_name == "name" || rhs_name == "name") {
            weight *= 0.4;
        }
        weighted_sum += weight * token_overlap_score(lhs_tokens, rhs_tokens);
        total_weight += weight;
    }

    let mean_overlap = if total_weight > f64::EPSILON {
        weighted_sum / total_weight
    } else {
        0.0
    };
    let consensus = consensus_token_bonus(&[
        &name_tokens,
        &prototype_tokens,
        &frame_tokens,
        &comment_tokens,
        &operand_tokens,
    ]);
    let comment_bridge = if !comment_tokens.is_empty()
        && ((!prototype_tokens.is_empty()
            && token_overlap_score(&comment_tokens, &prototype_tokens) > 0.0)
            || (!frame_tokens.is_empty()
                && token_overlap_score(&comment_tokens, &frame_tokens) > 0.0))
    {
        0.08
    } else {
        0.0
    };
    let mismatch_penalty = if populated >= 3 && mean_overlap < 0.03 && !name_is_generic {
        0.15
    } else {
        0.0
    };

    (0.35 + 0.55 * mean_overlap + 0.20 * consensus + comment_bridge - mismatch_penalty)
        .clamp(0.0, 1.0)
}

pub fn name_quality(name: &str) -> f64 {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return -1.0;
    }
    if is_rejected_function_name(trimmed) {
        return -1.0;
    }
    let lower = trimmed.to_ascii_lowercase();
    if DEFAULT_NAME_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return 0.25;
    }
    let demangled = demangle(trimmed);
    if demangled.demangled {
        return 2.5;
    }
    if trimmed.contains("::") || trimmed.contains('.') {
        return 1.5;
    }
    if trimmed.chars().any(|c| c.is_ascii_alphabetic()) && trimmed.len() >= 3 {
        return 1.0;
    }
    0.5
}

pub fn is_rejected_function_name(name: &str) -> bool {
    is_rejected_function_name_with(name_rejection_policy(), name)
}

/// Reference Lumina rejects no names server-side. `Prefixes` drops IDA dummy
/// names only; `Heuristic` adds address-like suffixes and the character model.
/// Empty names are always rejected: they carry nothing worth storing.
pub fn is_rejected_function_name_with(policy: NameRejection, name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return true;
    }
    if policy == NameRejection::Off {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if REJECTED_NAME_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || contains_generated_helper_or_wrapper(&lower)
    {
        return true;
    }
    if policy == NameRejection::Prefixes {
        return false;
    }
    if ends_with_address_suffix(&lower) {
        return true;
    }

    let score = character_distribution_score(trimmed);
    score.unknown_characters != 0
        || score.evidence_bits >= NAME_DISTRIBUTION_EVIDENCE_THRESHOLD_BITS
        || (score.length >= NAME_DISTRIBUTION_MATCH_MIN_LEN
            && score.match_score < NAME_DISTRIBUTION_MATCH_THRESHOLD
            && score.evidence_bits >= NAME_DISTRIBUTION_MATCH_MIN_EVIDENCE_BITS)
}

pub fn character_distribution_score(input: &str) -> NameDistributionScore {
    let mut counts: HashMap<u32, usize> = HashMap::new();
    let mut length = 0usize;
    let mut cross_entropy_bits = 0.0f64;
    let mut unknown_characters = 0usize;

    for original in input.chars() {
        for ch in original.to_lowercase() {
            let codepoint = ch as u32;
            length += 1;
            *counts.entry(codepoint).or_insert(0) += 1;
            if let Some(p) = lumina_name_char_frequency(codepoint) {
                cross_entropy_bits += -p.log2();
            } else {
                unknown_characters += 1;
            }
        }
    }

    if length == 0 {
        return NameDistributionScore {
            length: 0,
            unknown_characters: 0,
            evidence_bits: 0.0,
            kl_bits_per_char: 0.0,
            match_score: 1.0,
            cross_entropy_bits_per_char: 0.0,
            entropy_bits_per_char: 0.0,
        };
    }

    let length_f = length as f64;
    let count_log_sum = counts
        .values()
        .map(|&count| {
            let count_f = count as f64;
            count_f * count_f.log2()
        })
        .sum::<f64>();
    let entropy_bits = length_f * length_f.log2() - count_log_sum;

    if unknown_characters != 0 {
        return NameDistributionScore {
            length,
            unknown_characters,
            evidence_bits: f64::INFINITY,
            kl_bits_per_char: f64::INFINITY,
            match_score: 0.0,
            cross_entropy_bits_per_char: f64::INFINITY,
            entropy_bits_per_char: entropy_bits / length_f,
        };
    }

    let evidence_bits = (cross_entropy_bits - entropy_bits).max(0.0);
    let kl_bits_per_char = evidence_bits / length_f;
    NameDistributionScore {
        length,
        unknown_characters,
        evidence_bits,
        kl_bits_per_char,
        match_score: 2f64.powf(-kl_bits_per_char),
        cross_entropy_bits_per_char: cross_entropy_bits / length_f,
        entropy_bits_per_char: entropy_bits / length_f,
    }
}

fn contains_generated_helper_or_wrapper(lower: &str) -> bool {
    generated_hex_marker_len(lower, "_helper_") >= 6
        || generated_hex_marker_len(lower, "_wrapper_") >= 6
}

fn generated_hex_marker_len(lower: &str, marker: &str) -> usize {
    let mut search_from = 0usize;
    while let Some(pos) = lower[search_from..].find(marker) {
        let hex_start = search_from + pos + marker.len();
        let hex_len = lower[hex_start..]
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .count();
        if hex_len >= 6 {
            return hex_len;
        }
        search_from = hex_start.saturating_add(hex_len).saturating_add(1);
        if search_from >= lower.len() {
            break;
        }
    }
    0
}

/// Address-like suffix: `_0x<hex>` or `_<7+ hex digits containing a digit>`.
/// Short numeric suffixes (`crc_32`, `aes_256`, `utf8_2`) are legitimate names.
fn ends_with_address_suffix(lower: &str) -> bool {
    let Some((_, suffix)) = lower.rsplit_once('_') else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    if let Some(hex) = suffix.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit());
    }
    suffix.len() >= 7
        && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
        && suffix.chars().any(|ch| ch.is_ascii_digit())
}

fn lumina_name_char_frequency(codepoint: u32) -> Option<f64> {
    match codepoint {
        32 => Some(0.00154780926045719),
        33 => Some(0.00000000164516870),
        36 => Some(0.00706262203038824),
        37 => Some(0.00000005922607316),
        38 => Some(0.00004527339742472),
        39 => Some(0.00001883553643358),
        40 => Some(0.00019023579215860),
        41 => Some(0.00019023579215860),
        42 => Some(0.00000002632269918),
        43 => Some(0.00015705109433332),
        44 => Some(0.00000278691577592),
        45 => Some(0.00137303311856204),
        46 => Some(0.00236755898423336),
        47 => Some(0.00000034054992067),
        48 => Some(0.00815365020159897),
        49 => Some(0.01711514897660636),
        50 => Some(0.01143508888188413),
        51 => Some(0.00818231233067101),
        52 => Some(0.00751653888092993),
        53 => Some(0.00602500426098693),
        54 => Some(0.00574510183923280),
        55 => Some(0.00519849947453312),
        56 => Some(0.00534034921008870),
        57 => Some(0.00458027304535862),
        58 => Some(0.00668383509881870),
        60 => Some(0.00000404711499927),
        61 => Some(0.00000000658067480),
        62 => Some(0.00000402079230008),
        63 => Some(0.00692918404239007),
        64 => Some(0.03618394894449267),
        91 => Some(0.00168282661040628),
        92 => Some(0.00000046393757309),
        93 => Some(0.00168299770795097),
        94 => Some(0.00000036029194506),
        95 => Some(0.04349690477960991),
        96 => Some(0.00000792971312864),
        97 => Some(0.06752062218964057),
        98 => Some(0.01815522298287511),
        99 => Some(0.04232959178100041),
        100 => Some(0.028_677_086_945_849_6),
        101 => Some(0.10491020998275205),
        102 => Some(0.01707962320372255),
        103 => Some(0.01615862815304807),
        104 => Some(0.01211540397775469),
        105 => Some(0.05354585677424534),
        106 => Some(0.00347549126382518),
        107 => Some(0.00983971285883597),
        108 => Some(0.03568929607179779),
        109 => Some(0.02149127139295117),
        110 => Some(0.05426049173434342),
        111 => Some(0.04711351038858227),
        112 => Some(0.02726503371608732),
        113 => Some(0.00331106981372084),
        114 => Some(0.05602581203881808),
        115 => Some(0.05209040070386898),
        116 => Some(0.06743995134249056),
        117 => Some(0.02219692866745942),
        118 => Some(0.01791203908131148),
        119 => Some(0.00672245214368772),
        120 => Some(0.00696550772209284),
        121 => Some(0.00999843873490476),
        122 => Some(0.00878596092000466),
        126 => Some(0.00000001974202439),
        1089 => Some(0.00000000329033740),
        _ => None,
    }
}

pub fn tokenize_semantic_text(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let push_cur = |cur: &mut String, out: &mut Vec<String>| {
        if cur.len() >= 2 {
            out.push(cur.to_ascii_lowercase());
        }
        cur.clear();
    };

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else {
            push_cur(&mut cur, &mut out);
        }
    }
    push_cur(&mut cur, &mut out);
    dedup_tokens(&mut out);
    out
}

pub fn normalize_origin_token(input: &str) -> String {
    let input = input.trim().replace('\\', "/");
    if input.is_empty() {
        return String::new();
    }
    let mut base = input
        .rsplit('/')
        .next()
        .unwrap_or(&input)
        .to_ascii_lowercase();
    if let Some(dot) = base.rfind('.') {
        if dot > 0 {
            base.truncate(dot);
        }
    }
    let tokens = tokenize_semantic_text(&base);
    let mut token = tokens.into_iter().take(4).collect::<Vec<_>>().join("_");
    if token.len() > 96 {
        token.truncate(96);
    }
    token
}

pub fn normalize_requested_mdkeys(requested_mdkeys: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(requested_mdkeys.len());
    let mut seen = HashSet::new();
    for &raw_key in requested_mdkeys {
        if seen.insert(raw_key) {
            out.push(raw_key);
        }
    }
    out
}

pub fn shape_metadata_for_request(data: &[u8], requested_mdkeys: &[u32]) -> Vec<u8> {
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    if requested.is_empty() {
        return data.to_vec();
    }
    let parsed = parse_metadata(data);
    if parsed.raw_chunks.is_empty() {
        return Vec::new();
    }
    let shaped = filter_chunks_for_request(&parsed.raw_chunks, &requested);
    serialize_metadata_chunks(&shaped)
}

pub fn fingerprint_similarity(tokens: &[String], weights: &HashMap<String, f64>) -> f64 {
    if weights.is_empty() || tokens.is_empty() {
        return 0.0;
    }
    let mut seen = HashSet::new();
    let mut hit = 0.0;
    let mut total = 0.0;
    for token in tokens {
        if !seen.insert(token) {
            continue;
        }
        total += 1.0;
        hit += weights.get(token).copied().unwrap_or(0.0);
    }
    if total <= f64::EPSILON {
        0.0
    } else {
        hit / total
    }
}

pub fn choose_canonical_name<'a>(inputs: &[SynthesisInput<'a>]) -> &'a str {
    inputs
        .iter()
        .max_by(|a, b| {
            let sa = a.score + name_quality(a.name);
            let sb = b.score + name_quality(b.name);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|input| input.name)
        .unwrap_or("")
}

/// A complete selection; fallback preserves the donor's name and payload together.
#[derive(Debug, Default)]
pub struct SynthesizedSelection {
    pub name: String,
    pub data: Vec<u8>,
    pub used_synthesis: bool,
    pub donor_indices: Vec<usize>,
}

fn fallback_selection(inputs: &[SynthesisInput<'_>], requested: &[u32]) -> SynthesizedSelection {
    let best = inputs
        .iter()
        .enumerate()
        .max_by(|(ia, a), (ib, b)| a.score.total_cmp(&b.score).then_with(|| ib.cmp(ia)));
    match best {
        Some((idx, input)) => SynthesizedSelection {
            name: input.name.to_owned(),
            data: shape_metadata_for_request(input.raw_data, requested),
            used_synthesis: false,
            donor_indices: vec![idx],
        },
        None => SynthesizedSelection::default(),
    }
}

pub fn synthesize_metadata(inputs: &[SynthesisInput<'_>], requested_mdkeys: &[u32]) -> Vec<u8> {
    synthesize_selection(inputs, requested_mdkeys).data
}

pub fn synthesize_selection(
    inputs: &[SynthesisInput<'_>],
    requested_mdkeys: &[u32],
) -> SynthesizedSelection {
    if inputs.is_empty() {
        return SynthesizedSelection::default();
    }
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    if inputs.len() == 1 {
        return fallback_selection(inputs, &requested);
    }

    let mut base_input = &inputs[0];
    for input in &inputs[1..] {
        if input.score > base_input.score {
            base_input = input;
        }
    }

    if base_input.metadata.raw_chunks.is_empty() {
        return fallback_selection(inputs, &requested);
    }

    let requested_set: HashSet<u32> = requested.iter().copied().collect();
    let mut selected_by_bundle: BTreeMap<SemanticBundle, usize> = BTreeMap::new();
    let mut bundle_score: BTreeMap<SemanticBundle, f64> = BTreeMap::new();

    for (idx, input) in inputs.iter().enumerate() {
        for chunk in &input.metadata.raw_chunks {
            if !requested_set.is_empty() && !requested_set.contains(&chunk.raw_key) {
                continue;
            }
            let bundle = bundle_for_mdkey(chunk.key);
            let score = input.score + bundle_chunk_bonus(input.metadata, bundle);
            let replace = match bundle_score.get(&bundle) {
                Some(prev) => score > *prev,
                None => true,
            };
            if replace {
                bundle_score.insert(bundle, score);
                selected_by_bundle.insert(bundle, idx);
            }
        }
    }

    let mut merged = filter_chunks_for_request(&base_input.metadata.raw_chunks, &requested);
    for (bundle, selected_idx) in &selected_by_bundle {
        let selected = &inputs[*selected_idx];
        let replacements: Vec<MetadataChunk> = selected
            .metadata
            .raw_chunks
            .iter()
            .filter(|chunk| {
                bundle_for_mdkey(chunk.key) == *bundle
                    && (requested_set.is_empty() || requested_set.contains(&chunk.raw_key))
            })
            .cloned()
            .collect();
        merged.retain(|chunk| {
            if bundle_for_mdkey(chunk.key) != *bundle {
                return true;
            }
            if requested_set.is_empty() {
                return false;
            }
            !requested_set.contains(&chunk.raw_key)
        });
        merged.extend(replacements);
    }

    merged.sort_by_key(|chunk| metadata_order_key(chunk.key, chunk.raw_key));
    if !requested_set.is_empty() {
        merged = filter_chunks_for_request(&merged, &requested);
    }

    let chosen_name = choose_canonical_name(inputs);
    if !synthesized_chunks_are_compatible(
        inputs,
        &selected_by_bundle,
        &merged,
        &requested,
        chosen_name,
    ) {
        return fallback_selection(inputs, &requested);
    }
    let data = serialize_metadata_chunks(&merged);
    let mut donor_indices: Vec<usize> = selected_by_bundle.values().copied().collect();
    donor_indices.sort_unstable();
    donor_indices.dedup();
    SynthesizedSelection {
        name: chosen_name.to_owned(),
        data,
        used_synthesis: true,
        donor_indices,
    }
}

fn metadata_order_key(mdkey: MdKey, raw_key: u32) -> (usize, u32) {
    let pos = KNOWN_MDKEY_ORDER
        .iter()
        .position(|candidate| *candidate == mdkey)
        .unwrap_or(KNOWN_MDKEY_ORDER.len());
    (pos, raw_key)
}

fn bundle_chunk_bonus(metadata: &FunctionMetadata, bundle: SemanticBundle) -> f64 {
    match bundle {
        SemanticBundle::Type => metadata
            .type_parts
            .as_ref()
            .map(|parts| {
                1.25 + parts.declaration.as_ref().map(|_| 0.75).unwrap_or(0.0)
                    - parts.decode_error.as_ref().map(|_| 0.25).unwrap_or(0.0)
            })
            .unwrap_or(0.0),
        SemanticBundle::Timing => metadata.vd_elapsed.map(|_| 0.15).unwrap_or(0.0),
        SemanticBundle::Comments => {
            metadata.fcmt.as_ref().map(|_| 0.5).unwrap_or(0.0)
                + metadata.frptcmt.as_ref().map(|_| 0.3).unwrap_or(0.0)
                + usize_to_f64(metadata.insn_cmts.len().min(32)) * 0.1
                + usize_to_f64(metadata.rpt_insn_cmts.len().min(32)) * 0.08
                + usize_to_f64(metadata.extra_cmts.len().min(32)) * 0.05
        }
        SemanticBundle::Frame => {
            metadata
                .frame_desc
                .as_ref()
                .map(|fd| 0.8 + usize_to_f64(fd.members.len().min(16)) * 0.15)
                .unwrap_or(0.0)
                + metadata.user_stkpnts.as_ref().map(|_| 0.3).unwrap_or(0.0)
        }
        SemanticBundle::Operands => {
            metadata.ops.as_ref().map(|_| 0.25).unwrap_or(0.0)
                + metadata.ops_ex.as_ref().map(|_| 0.25).unwrap_or(0.0)
        }
        SemanticBundle::Other(_) => 0.05,
    }
}

fn filter_chunks_for_request(
    chunks: &[MetadataChunk],
    requested_mdkeys: &[u32],
) -> Vec<MetadataChunk> {
    if requested_mdkeys.is_empty() {
        return chunks.to_vec();
    }
    let requested: HashSet<u32> = requested_mdkeys.iter().copied().collect();
    chunks
        .iter()
        .filter(|chunk| requested.contains(&chunk.raw_key))
        .cloned()
        .collect()
}

fn synthesized_chunks_are_compatible(
    inputs: &[SynthesisInput<'_>],
    selected_by_bundle: &BTreeMap<SemanticBundle, usize>,
    merged: &[MetadataChunk],
    requested_mdkeys: &[u32],
    chosen_name: &str,
) -> bool {
    if merged.is_empty() {
        return requested_mdkeys.is_empty();
    }

    let merged_data = serialize_metadata_chunks(merged);
    let merged_metadata = parse_metadata(&merged_data);
    let requested = normalize_requested_mdkeys(requested_mdkeys);
    if !requested.is_empty() {
        let requested_set: HashSet<u32> = requested.iter().copied().collect();
        if merged_metadata
            .raw_chunks
            .iter()
            .any(|chunk| !requested_set.contains(&chunk.raw_key))
        {
            return false;
        }
        let best_requested_coverage = inputs
            .iter()
            .map(|input| input.metadata.requested_coverage(&requested))
            .max()
            .unwrap_or(0);
        if merged_metadata.requested_coverage(&requested) < best_requested_coverage {
            return false;
        }
    }

    let min_errors = inputs
        .iter()
        .map(|input| input.metadata.errors.len())
        .min()
        .unwrap_or(0);
    if merged_metadata.errors.len() > min_errors + 1 {
        return false;
    }

    let merged_analysis = analyze_function(chosen_name, &merged_data);
    let merged_total = merged_analysis.quality_score + (merged_analysis.consistency_score * 2.0);

    let mut best_input_total = f64::NEG_INFINITY;
    for input in inputs {
        let candidate_data = shape_metadata_for_request(input.raw_data, &requested);
        if candidate_data.is_empty() {
            continue;
        }
        let analysis = analyze_function(input.name, &candidate_data);
        let total = analysis.quality_score + (analysis.consistency_score * 2.0);
        if total > best_input_total {
            best_input_total = total;
        }
    }
    if best_input_total.is_finite() && merged_total + 0.35 < best_input_total {
        return false;
    }

    let mut structured_languages = HashSet::new();
    for (bundle, idx) in selected_by_bundle {
        if !is_structural_bundle(*bundle) {
            continue;
        }
        let lang = demangle(inputs[*idx].name).lang.unwrap_or("");
        if !lang.is_empty() {
            structured_languages.insert(lang.to_string());
        }
    }
    !(structured_languages.len() > 1 && merged_analysis.consistency_score < 0.45)
}

fn is_structural_bundle(bundle: SemanticBundle) -> bool {
    matches!(
        bundle,
        SemanticBundle::Type | SemanticBundle::Frame | SemanticBundle::Operands
    )
}

fn signal_token_set(tokens: &[String]) -> HashSet<String> {
    tokens
        .iter()
        .filter(|token| token.len() >= 3)
        .filter(|token| !token.chars().all(|ch| ch.is_ascii_digit()))
        .filter(|token| !CONSISTENCY_STOPWORDS.contains(&token.as_str()))
        .cloned()
        .collect()
}

fn token_overlap_score(lhs: &HashSet<String>, rhs: &HashSet<String>) -> f64 {
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }
    let intersection = lhs.intersection(rhs).count();
    if intersection == 0 {
        return 0.0;
    }
    (2.0 * usize_to_f64(intersection)) / usize_to_f64(lhs.len() + rhs.len())
}

fn consensus_token_bonus(token_sets: &[&HashSet<String>]) -> f64 {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for set in token_sets {
        for token in set.iter() {
            *counts.entry(token.as_str()).or_insert(0) += 1;
        }
    }
    let shared_across_three = counts.values().filter(|&&count| count >= 3).count();
    let shared_across_two = counts.values().filter(|&&count| count >= 2).count();
    ((usize_to_f64(shared_across_three.min(8)) * 0.06)
        + (usize_to_f64(shared_across_two.min(12)) * 0.02))
        .min(0.35)
}

fn dedup_tokens(tokens: &mut Vec<String>) {
    tokens.sort();
    tokens.dedup();
}

fn usize_to_f64(v: usize) -> f64 {
    v as f64
}
