//! Leave-one-function-out evidence for distinguishing variants in a batch.

use super::semantic::{SemanticAnalysis, SemanticFingerprint};
use crate::common::demangle::demangle;
use crate::common::neighbor::is_generic_neighbor_token;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Expand only transient batch evidence. Persisted search tokens, quality scores,
/// canonical selection and single-key replay keep their original representation.
pub(super) fn batch_fingerprint(name: &str, analysis: &SemanticAnalysis) -> SemanticFingerprint {
    let mut fp = analysis.fingerprint.clone();
    extend_components(name, &mut fp.name_tokens);
    let demangled = demangle(name);
    if demangled.demangled {
        extend_components(&demangled.name, &mut fp.name_tokens);
    }
    let md = &analysis.metadata;
    if let Some(decl) = md
        .type_parts
        .as_ref()
        .and_then(|p| p.declaration.as_deref())
    {
        extend_components(decl, &mut fp.prototype_tokens);
    }
    if let Some(frame) = &md.frame_desc {
        for member in &frame.members {
            for text in [
                member.name.as_deref(),
                member.tinfo.as_ref().and_then(|p| p.declaration.as_deref()),
                member.cmt.as_deref(),
                member.rptcmt.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                extend_components(text, &mut fp.frame_tokens);
            }
        }
    }
    for text in md
        .fcmt
        .iter()
        .chain(&md.frptcmt)
        .chain(md.insn_cmts.iter().map(|c| &c.cmt))
        .chain(md.rpt_insn_cmts.iter().map(|c| &c.cmt))
        .chain(&md.extra_cmts)
    {
        extend_components(text, &mut fp.comment_tokens);
    }
    for text in [&md.user_stkpnts, &md.ops, &md.ops_ex]
        .into_iter()
        .flatten()
        .flat_map(|blob| &blob.printable_texts)
    {
        extend_components(text, &mut fp.operand_tokens);
    }
    for field in [
        &mut fp.name_tokens,
        &mut fp.prototype_tokens,
        &mut fp.frame_tokens,
        &mut fp.comment_tokens,
        &mut fp.operand_tokens,
    ] {
        field.sort();
        field.dedup();
        fp.tokens.extend(field.iter().cloned());
    }
    fp.tokens.sort();
    fp.tokens.dedup();
    fp
}

/// ASCII identifier boundaries: separators, lower-to-upper transitions and the
/// last capital before a lowercase acronym suffix (HTTPReader -> HTTP, Reader).
fn extend_components(text: &str, out: &mut Vec<String>) {
    for identifier in text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
        // Preserve prefix-sensitive exclusions such as __customcall and __m128
        // before separators remove the prefix that identifies compiler syntax.
        if is_generic_neighbor_token(identifier) {
            continue;
        }
        for word in identifier.split('_') {
            let bytes = word.as_bytes();
            let mut start = 0;
            for i in 1..=bytes.len() {
                let boundary = i == bytes.len()
                    || (bytes[i].is_ascii_uppercase()
                        && (bytes[i - 1].is_ascii_lowercase()
                            || bytes[i - 1].is_ascii_digit()
                            || (bytes[i - 1].is_ascii_uppercase()
                                && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase))));
                if boundary {
                    let token = word[start..i].to_ascii_lowercase();
                    if !is_generic_neighbor_token(&token) {
                        out.push(token);
                    }
                    start = i;
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct BatchAnchors {
    total: BTreeMap<String, f64>,
    own: Vec<BTreeMap<String, f64>>,
    identifiers: HashMap<String, usize>,
    own_identifiers: Vec<HashSet<String>>,
}

impl BatchAnchors {
    pub fn push(&mut self, fingerprint: Option<&SemanticFingerprint>) {
        let mut weights = BTreeMap::<String, f64>::new();
        let mut identifiers = HashSet::new();
        if let Some(fp) = fingerprint {
            // Preserve the existing relative field weights, but give each source
            // function one unit of mass regardless of its metadata verbosity.
            for (tokens, weight) in [
                (&fp.tokens, 1.0),
                (&fp.prototype_tokens, 0.5),
                (&fp.frame_tokens, 0.35),
                (&fp.comment_tokens, 0.25),
                (&fp.operand_tokens, 0.2),
            ] {
                let mut seen = HashSet::new();
                for token in tokens {
                    if seen.insert(token) && !is_generic_neighbor_token(token) {
                        *weights.entry(token.clone()).or_default() += weight;
                    }
                }
            }
            let mass: f64 = weights.values().sum();
            if mass > 0.0 {
                for (token, weight) in &mut weights {
                    *weight /= mass;
                    *self.total.entry(token.clone()).or_default() += *weight;
                }
            }
            for token in fp.name_tokens.iter().chain(&fp.prototype_tokens) {
                if weights.contains_key(token) && identifiers.insert(token.clone()) {
                    *self.identifiers.entry(token.clone()).or_default() += 1;
                }
            }
        }
        self.own.push(weights);
        self.own_identifiers.push(identifiers);
    }

    /// Relative support among terms that distinguish this key's candidates.
    /// Common terms cannot decide between candidates; unmatched extra metadata
    /// cannot dilute a match. No supported distinction means no semantic vote.
    pub fn excluding(
        &self,
        index: usize,
        candidates: &[&SemanticFingerprint],
    ) -> HashMap<String, f64> {
        if candidates.len() < 2 {
            return HashMap::new();
        }
        let mut occurrences = BTreeMap::<&str, usize>::new();
        for fp in candidates {
            let mut seen = HashSet::new();
            for token in &fp.tokens {
                if seen.insert(token) && self.total.contains_key(token) {
                    *occurrences.entry(token).or_default() += 1;
                }
            }
        }
        let mut supported = BTreeMap::new();
        for (token, count) in occurrences {
            if count == candidates.len() {
                continue;
            }
            let weight = self.total[token] - self.own[index].get(token).copied().unwrap_or(0.0);
            // Suppress cancellation noise when the target was the only source.
            if weight > 1e-12 {
                supported.insert(token, weight);
            }
        }
        let mass: f64 = supported.values().sum();
        supported
            .into_iter()
            .map(|(token, weight)| (token.to_owned(), weight / mass))
            .collect()
    }

    /// A weaker binary needs an identifier on at least one side of the match.
    /// Repeated comment/operand boilerplate alone is insufficient corroboration.
    pub fn corroboration(
        &self,
        index: usize,
        weights: &HashMap<String, f64>,
    ) -> HashMap<String, f64> {
        weights
            .iter()
            .filter(|(token, _)| {
                self.identifiers.get(*token).copied().unwrap_or(0)
                    > usize::from(self.own_identifiers[index].contains(*token))
            })
            .map(|(token, weight)| (token.clone(), *weight))
            .collect()
    }
}

pub(super) fn corroborated_support(
    fp: &SemanticFingerprint,
    weights: &HashMap<String, f64>,
    source_identifiers: &HashMap<String, f64>,
) -> f64 {
    if weights.is_empty() {
        return 0.0;
    }
    let identifiers: HashSet<_> = fp.name_tokens.iter().chain(&fp.prototype_tokens).collect();
    let mut seen = HashSet::new();
    fp.tokens
        .iter()
        .filter(|t| seen.insert(t.as_str()))
        .filter(|t| identifiers.contains(t) || source_identifiers.contains_key(*t))
        .map(|t| weights.get(t).copied().unwrap_or(0.0))
        .sum::<f64>()
        .clamp(0.0, 1.0)
}

pub(super) fn contrastive_support(tokens: &[String], weights: &HashMap<String, f64>) -> f64 {
    if weights.is_empty() {
        return 0.0;
    }
    let mut seen = HashSet::new();
    tokens
        .iter()
        .filter(|token| seen.insert(token.as_str()))
        .map(|token| weights.get(token).copied().unwrap_or(0.0))
        .sum::<f64>()
        .clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_components_respect_acronyms_separators_and_noise() {
        let mut tokens = Vec::new();
        extend_components("readHTTPHeader http_decode_header URL2Reader __fastcall __customcall __m128 r15 arg_12 x86_64", &mut tokens);
        assert_eq!(
            tokens,
            ["read", "http", "header", "http", "decode", "header", "url2", "reader"]
        );
        let mut empty = Vec::new();
        extend_components("_ ! é😀 42", &mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn batch_components_bridge_metadata_without_changing_search_fingerprint() {
        use crate::protocol::lumina::metadata::{
            FrameDesc, FrameMem, MdTypeParts, OpaqueMetadataBlob,
        };
        let mut analysis = super::super::semantic::analyze_function("readHttpHeader", &[]);
        let original = analysis.fingerprint.tokens.clone();
        analysis.metadata.type_parts = Some(MdTypeParts {
            userti: true,
            type_bytes: vec![],
            fields_bytes: vec![],
            declaration: Some("void parseTLSRecord(TLSConnection *)".into()),
            decode_error: None,
        });
        analysis.metadata.frame_desc = Some(FrameDesc {
            members: vec![FrameMem {
                name: Some("zip_archive_cursor".into()),
                ..Default::default()
            }],
            ..Default::default()
        });
        analysis.metadata.fcmt = Some("decode_png_pixel".into());
        analysis.metadata.ops = Some(OpaqueMetadataBlob {
            raw: vec![],
            printable_texts: vec!["readSqlitePage".into()],
        });
        let expanded = batch_fingerprint("readHttpHeader", &analysis);
        assert!(expanded.name_tokens.contains(&"http".into()));
        assert!(expanded.prototype_tokens.contains(&"tls".into()));
        assert!(expanded.frame_tokens.contains(&"archive".into()));
        assert!(expanded.comment_tokens.contains(&"png".into()));
        assert!(expanded.operand_tokens.contains(&"sqlite".into()));
        assert_eq!(analysis.fingerprint.tokens, original);
        assert!(!original.contains(&"http".into()));
    }

    fn fp(tokens: &[&str]) -> SemanticFingerprint {
        SemanticFingerprint {
            tokens: tokens.iter().map(|s| (*s).into()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn common_generic_and_self_terms_cannot_vote() {
        let a = fp(&["orchid", "shared", "void", "__fastcall", "frsize"]);
        let b = fp(&["cobalt", "shared", "512"]);
        let mut anchors = BatchAnchors::default();
        anchors.push(Some(&a));
        anchors.push(Some(&fp(&["shared", "void", "512"])));
        assert!(anchors.excluding(0, &[&a, &b]).is_empty());
        assert!(anchors.excluding(1, &[&a]).is_empty());
        assert!(anchors.excluding(1, &[&a, &a]).is_empty());
    }

    #[test]
    fn unmatched_metadata_and_duplicate_terms_do_not_dilute_evidence() {
        let a = fp(&["orchid", "orchid", "shared", "extra", "unrelated"]);
        let b = fp(&["cobalt", "shared"]);
        let mut anchors = BatchAnchors::default();
        anchors.push(None);
        anchors.push(Some(&fp(&["orchid", "shared"])));
        let weights = anchors.excluding(0, &[&a, &b]);
        assert_eq!(contrastive_support(&a.tokens, &weights), 1.0);
        assert_eq!(contrastive_support(&b.tokens, &weights), 0.0);
    }

    #[test]
    fn source_mass_is_bounded_and_fields_can_supply_evidence() {
        let mut rich = fp(&["orchid", "cobalt", "shared", "extra", "unrelated"]);
        rich.prototype_tokens = vec!["orchid".into()];
        rich.frame_tokens = vec!["orchid".into()];
        rich.comment_tokens = vec!["orchid".into()];
        rich.operand_tokens = vec!["orchid".into()];
        let mut anchors = BatchAnchors::default();
        anchors.push(None);
        anchors.push(Some(&rich));
        assert!((anchors.total.values().sum::<f64>() - 1.0).abs() < 1e-12);
        let a = fp(&["orchid"]);
        let b = fp(&["cobalt"]);
        let weights = anchors.excluding(0, &[&a, &b]);
        let sa = contrastive_support(&a.tokens, &weights);
        let sb = contrastive_support(&b.tokens, &weights);
        assert!(sa > sb);
        assert!((sa + sb - 1.0).abs() < 1e-12);
    }

    #[test]
    fn source_order_and_target_position_preserve_relative_support() {
        let a = fp(&["orchid", "shared"]);
        let b = fp(&["cobalt", "shared"]);
        let source = fp(&["orchid", "shared", "other"]);
        let mut first = BatchAnchors::default();
        for item in [Some(&a), Some(&source), Some(&b)] {
            first.push(item);
        }
        let mut permuted = BatchAnchors::default();
        for item in [Some(&b), Some(&a), Some(&source)] {
            permuted.push(item);
        }
        let x = first.excluding(0, &[&a, &b]);
        let y = permuted.excluding(1, &[&b, &a]);
        for candidate in [&a, &b] {
            assert!(
                (contrastive_support(&candidate.tokens, &x)
                    - contrastive_support(&candidate.tokens, &y))
                .abs()
                    < 1e-12
            );
        }
    }

    #[test]
    fn repeated_comment_boilerplate_cannot_supply_identifier_corroboration() {
        let a = fp(&["pic", "mode"]);
        let b = fp(&["other"]);
        let mut anchors = BatchAnchors::default();
        anchors.push(None);
        anchors.push(Some(&a));
        let weights = anchors.excluding(0, &[&a, &b]);
        assert!(!weights.is_empty());
        assert_eq!(
            corroborated_support(&a, &weights, &anchors.corroboration(0, &weights)),
            0.0
        );
        // A meaningful identifier can bridge a free-text annotation on either side.
        let mut named = a.clone();
        named.name_tokens = named.tokens.clone();
        assert!(corroborated_support(&named, &weights, &anchors.corroboration(0, &weights)) > 0.0);
        assert_eq!(
            corroborated_support(&a, &weights, &anchors.corroboration(0, &weights)),
            0.0
        );
        anchors.push(Some(&named));
        assert!(corroborated_support(&a, &weights, &anchors.corroboration(0, &weights)) > 0.0);
        assert_eq!(
            corroborated_support(&a, &weights, &anchors.corroboration(2, &weights)),
            0.0
        );
    }
}
