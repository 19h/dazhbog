//! Leave-one-function-out evidence for distinguishing variants in a batch.

use super::semantic::SemanticFingerprint;
use crate::common::neighbor::is_generic_neighbor_token;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Default)]
pub(super) struct BatchAnchors {
    total: BTreeMap<String, f64>,
    own: Vec<BTreeMap<String, f64>>,
}

impl BatchAnchors {
    pub fn push(&mut self, fingerprint: Option<&SemanticFingerprint>) {
        let mut weights = BTreeMap::<String, f64>::new();
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
        }
        self.own.push(weights);
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
}
