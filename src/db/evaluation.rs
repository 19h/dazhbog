//! Retrospective binary-observation agreement, using the actual serving selector.
use super::{Database, QueryContext, SelectedVariant};
use crate::common::hash::version_id_matches;
use crate::protocol::lumina::{parse_metadata, MdKey};
use serde::Serialize;
use std::{io, time::Instant};

#[derive(Debug, Serialize)]
pub struct FrameMetadataSummary {
    pub frsize: u64,
    pub argsize: u64,
    pub frregs: u16,
    pub members: usize,
}

#[derive(Debug, Serialize)]
pub struct MetadataSummary {
    pub name: String,
    pub type_declaration: Option<String>,
    pub declaration_truncated: bool,
    pub userti: Option<bool>,
    pub frame: Option<FrameMetadataSummary>,
    /// (metadata key, payload length in bytes), preserving chunk order.
    pub chunks: Vec<(u32, usize)>,
    /// Up to four 128-character samples per annotation family for diagnosis.
    pub comment_samples: Vec<String>,
    pub operand_samples: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MetadataComparison {
    pub expected: MetadataSummary,
    pub selected: MetadataSummary,
}

fn summarize_metadata(name: &str, data: &[u8]) -> MetadataSummary {
    let metadata = parse_metadata(data);
    let declaration = metadata
        .type_parts
        .as_ref()
        .and_then(|p| p.declaration.as_deref());
    MetadataSummary {
        name: name.to_owned(),
        type_declaration: declaration.map(|s| s.chars().take(512).collect()),
        declaration_truncated: declaration.is_some_and(|s| s.chars().nth(512).is_some()),
        userti: metadata.type_parts.as_ref().map(|p| p.userti),
        frame: metadata
            .frame_desc
            .as_ref()
            .map(|frame| FrameMetadataSummary {
                frsize: frame.frsize,
                argsize: frame.argsize,
                frregs: frame.frregs,
                members: frame.members.len(),
            }),
        chunks: metadata
            .raw_chunks
            .iter()
            .map(|c| (c.raw_key, c.data.len()))
            .collect(),
        comment_samples: metadata
            .fcmt
            .iter()
            .chain(metadata.frptcmt.iter())
            .chain(metadata.insn_cmts.iter().map(|c| &c.cmt))
            .chain(metadata.rpt_insn_cmts.iter().map(|c| &c.cmt))
            .chain(metadata.extra_cmts.iter())
            .take(4)
            .map(|s| s.chars().take(128).collect())
            .collect(),
        operand_samples: [&metadata.user_stkpnts, &metadata.ops, &metadata.ops_ex]
            .into_iter()
            .flatten()
            .flat_map(|b| &b.printable_texts)
            .take(4)
            .map(|s| s.chars().take(128).collect())
            .collect(),
    }
}

#[derive(Debug, Serialize)]
pub struct ObservedVariantEvaluation {
    pub key: String,
    pub expected_version: Option<String>,
    pub expected_key_matches: bool,
    pub selected_version: Option<String>,
    pub selected_name: Option<String>,
    pub candidate_count: usize,
    pub binary_priority_floor: f64,
    pub selected_binary_support: Option<f64>,
    pub expected_binary_support: Option<f64>,
    pub available_binary_support: f64,
    pub selected_binary_match: Option<f64>,
    pub expected_binary_match: Option<f64>,
    pub expected_in_candidates: bool,
    pub expected_reachable_with_identity: bool,
    /// Diagnostic only; populated when the reference is absent from candidates.
    pub candidate_absence: Option<&'static str>,
    pub availability_error: Option<String>,
    pub selected_matches_observation: bool,
    pub latest_matches_observation: bool,
    pub canonical_matches_observation: bool,
    /// A failed diagnostic is unjudged; the corresponding match boolean is false.
    pub latest_error: Option<String>,
    pub canonical_error: Option<String>,
    pub name_matches_observation: Option<bool>,
    pub semantic_payload_matches: Option<bool>,
    pub changed_metadata_keys: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_comparison: Option<MetadataComparison>,
}

#[derive(Debug, Serialize)]
pub struct BinaryEvaluation {
    pub binary: String,
    pub withheld_binary: bool,
    pub selection_seconds: f64,
    pub identity_selection_seconds: f64,
    pub cases: Vec<ObservedVariantEvaluation>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Database {
    /// Samples actual observed binaries and keys, not independently labeled source
    /// families. No global context is withheld; this measures retrieval agreement.
    pub fn sample_observed_binary_batches(
        &self,
        binaries: usize,
        functions: usize,
        seed: u64,
    ) -> io::Result<Vec<([u8; 16], Vec<u128>)>> {
        if !(1..=1024).contains(&binaries) || !(2..=1024).contains(&functions) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "binary sample must be 1..1024 and function batch 2..1024",
            ));
        }
        self.rt
            .ctx_index
            .sample_binary_ids(binaries, functions as u64, seed)?
            .into_iter()
            .map(|md5| {
                Ok((
                    md5,
                    self.rt
                        .ctx_index
                        .sample_binary_functions(&md5, functions, seed)?,
                ))
            })
            .collect()
    }

    /// Compare the no-identity serving request with recorded labels and an explicit
    /// identity retrieval probe. Both use the same selector; no responses are pushed.
    pub async fn evaluate_observed_binary(
        &self,
        md5: [u8; 16],
        keys: &[u128],
    ) -> io::Result<BinaryEvaluation> {
        self.evaluate_binary(md5, keys, false).await
    }

    /// Withhold this binary from inference and require positive variant provenance
    /// in another binary. Summary priors and canonical hints are suppressed. Labels
    /// remain retrospective; physical history bounds and incomplete provenance apply.
    pub async fn evaluate_binary_transfer(
        &self,
        md5: [u8; 16],
        keys: &[u128],
    ) -> io::Result<BinaryEvaluation> {
        self.evaluate_binary(md5, keys, true).await
    }

    async fn evaluate_binary(
        &self,
        md5: [u8; 16],
        keys: &[u128],
        withheld_binary: bool,
    ) -> io::Result<BinaryEvaluation> {
        if keys.is_empty() || keys.len() > 1024 || self.rt.scoring.experimental_synthesis {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "evaluate 1..1024 keys with synthesis disabled",
            ));
        }
        let ctx = QueryContext {
            keys,
            requested_mdkeys: &[],
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
        };
        let started = Instant::now();
        let selected = if withheld_binary {
            self.select_transfer_batch(keys, md5).await?
        } else {
            self.select_variant_details(&ctx).await?
        };
        let selection_seconds = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let identity = self
            .select_variant_details(&QueryContext {
                md5: Some(md5),
                ..ctx
            })
            .await?;
        let identity_selection_seconds = started.elapsed().as_secs_f64();
        let mut cases = Vec::with_capacity(keys.len());
        for (i, &key) in keys.iter().enumerate() {
            let expected = self
                .rt
                .ctx_index
                .get_key_md5_stats(key, &md5)?
                .map(|stats| stats.last_version_id)
                .filter(|vid| *vid != [0; 32]);
            let chosen = selected[i].as_ref();
            let expected_index = expected.and_then(|id| {
                chosen.and_then(|s| {
                    s.candidate_version_ids
                        .iter()
                        .position(|v| *v == id)
                        .or_else(|| s.candidate_legacy_version_ids.iter().position(|v| *v == id))
                })
            });
            let latest = self.get_latest(key).await;
            let canonical = self.get_canonical(key).await;
            let reference =
                expected.and_then(|id| identity[i].as_ref().filter(|s| s.matches_version(&id)));
            let name_matches_observation =
                reference.map(|r| chosen.is_some_and(|s| s.name == r.name));
            let (semantic_payload_matches, changed_metadata_keys) = match (reference, chosen) {
                (Some(reference), Some(chosen)) => {
                    semantic_agreement(&reference.name, &reference.data, &chosen.name, &chosen.data)
                }
                (Some(_), None) => (Some(false), Vec::new()),
                _ => (None, Vec::new()),
            };
            let expected_in_candidates =
                expected.is_some_and(|id| chosen.is_some_and(|s| s.contains_version(&id)));
            let absence = if expected_in_candidates {
                Ok(None)
            } else {
                self.explain_candidate_absence(
                    key,
                    md5,
                    expected.is_some(),
                    reference,
                    withheld_binary,
                )
                .map(Some)
            };
            let (candidate_absence, availability_error) = match absence {
                Ok(reason) => (reason, None),
                Err(error) => (None, Some(error.to_string())),
            };
            cases.push(ObservedVariantEvaluation {
                key: format!("{key:032x}"),
                expected_version: expected.as_ref().map(|id| hex(id)),
                expected_key_matches: expected.is_some_and(|id| id[..16] == key.to_le_bytes()),
                selected_version: chosen.map(|s| hex(&s.base_version_id)),
                selected_name: chosen.map(|s| s.name.clone()),
                candidate_count: chosen.map_or(0, |s| s.candidate_version_ids.len()),
                binary_priority_floor: chosen.map_or(0.0, |s| s.binary_priority_floor),
                selected_binary_support: chosen.map(|s| s.binary_support),
                expected_binary_support: expected_index
                    .and_then(|i| chosen?.candidate_binary_support.get(i).copied()),
                selected_binary_match: chosen.map(|s| s.binary_match),
                expected_binary_match: expected_index
                    .and_then(|i| chosen?.candidate_binary_match.get(i).copied()),
                available_binary_support: chosen
                    .map_or(0.0, |s| s.candidate_binary_support.iter().sum()),
                expected_in_candidates,
                expected_reachable_with_identity: expected.is_some_and(|id| {
                    identity[i]
                        .as_ref()
                        .is_some_and(|s| s.contains_version(&id))
                }),
                candidate_absence,
                availability_error,
                selected_matches_observation: expected
                    .is_some_and(|id| chosen.is_some_and(|s| s.matches_version(&id))),
                latest_matches_observation: expected.is_some_and(|id| {
                    latest
                        .as_ref()
                        .ok()
                        .and_then(|f| f.as_ref())
                        .is_some_and(|f| version_id_matches(&id, key, &f.name, &f.data))
                }),
                canonical_matches_observation: expected.is_some_and(|id| {
                    canonical
                        .as_ref()
                        .ok()
                        .and_then(|f| f.as_ref())
                        .is_some_and(|f| version_id_matches(&id, key, &f.name, &f.data))
                }),
                latest_error: latest.err().map(|e| e.to_string()),
                canonical_error: canonical.err().map(|e| e.to_string()),
                name_matches_observation,
                semantic_payload_matches,
                changed_metadata_keys,
                metadata_comparison: if semantic_payload_matches == Some(false)
                    && expected_index.is_some()
                {
                    reference
                        .zip(chosen)
                        .map(|(expected, selected)| MetadataComparison {
                            expected: summarize_metadata(&expected.name, &expected.data),
                            selected: summarize_metadata(&selected.name, &selected.data),
                        })
                } else {
                    None
                },
            });
        }
        Ok(BinaryEvaluation {
            binary: hex(&md5),
            withheld_binary,
            selection_seconds,
            identity_selection_seconds,
            cases,
        })
    }

    /// Run only after selection; held-out labels must never seed serving candidates.
    /// Absence of recorded provenance is not proof that a variant is private.
    fn explain_candidate_absence(
        &self,
        key: u128,
        heldout: [u8; 16],
        labeled: bool,
        reference: Option<&SelectedVariant>,
        transfer: bool,
    ) -> io::Result<&'static str> {
        if !labeled {
            return Ok("unlabeled");
        }
        let Some(reference) = reference else {
            return Ok("identity_probe_unavailable");
        };
        if !transfer {
            return Ok("reachable_but_not_retrieved");
        }
        let stats = crate::engine::merge_alias_stats(
            self.rt
                .ctx_index
                .get_version_stats(&reference.base_version_id)?,
            self.rt
                .ctx_index
                .get_version_stats(&reference.base_legacy_version_id)?,
        );
        if stats.is_some_and(|stats| {
            stats
                .top_md5s
                .iter()
                .any(|entry| entry.md5 != heldout && entry.obs_count > 0)
        }) {
            return Ok("shared_but_not_retrieved");
        }
        let Some(binaries) = self
            .rt
            .ctx_index
            .key_binary_memberships(key, super::family::MAX_KEY_MEMBERSHIPS + 1)?
        else {
            return Ok("membership_scan_limit");
        };
        for binary in binaries.into_iter().filter(|binary| *binary != heldout) {
            if let Some(observed) = self.rt.ctx_index.get_key_md5_stats(key, &binary)? {
                if observed.obs_count > 0
                    && (reference.matches_version(&observed.last_version_id)
                        || self
                            .rt
                            .ctx_index
                            .binary_has_version(&binary, &reference.base_version_id)?
                        || self
                            .rt
                            .ctx_index
                            .binary_has_version(&binary, &reference.base_legacy_version_id)?)
                {
                    return Ok("shared_but_not_retrieved");
                }
            }
        }
        Ok("sharing_not_proven")
    }
}

/// Ignore only the decompilation timing chunk. All other raw chunk bytes and
/// per-key multiplicity/order remain significant; failed parses are unjudged.
pub(super) fn semantic_agreement(
    expected_name: &str,
    expected: &[u8],
    name: &str,
    data: &[u8],
) -> (Option<bool>, Vec<u32>) {
    use std::collections::{BTreeMap, BTreeSet};
    let expected = parse_metadata(expected);
    let selected = parse_metadata(data);
    if !expected.errors.is_empty()
        || !selected.errors.is_empty()
        || expected.bytes_parsed != expected.raw_size
        || selected.bytes_parsed != selected.raw_size
    {
        return (None, Vec::new());
    }
    let group = |metadata: &crate::protocol::lumina::FunctionMetadata| {
        let mut map = BTreeMap::<u32, Vec<Vec<u8>>>::new();
        for chunk in &metadata.raw_chunks {
            if chunk.raw_key != MdKey::VdElapsed.raw() {
                map.entry(chunk.raw_key)
                    .or_default()
                    .push(chunk.data.clone());
            }
        }
        map
    };
    let expected = group(&expected);
    let selected = group(&selected);
    let keys: BTreeSet<_> = expected.keys().chain(selected.keys()).copied().collect();
    let changed: Vec<_> = keys
        .into_iter()
        .filter(|key| expected.get(key) != selected.get(key))
        .collect();
    (Some(expected_name == name && changed.is_empty()), changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::lumina::pack_dd;
    fn chunk(key: u32, value: &[u8]) -> Vec<u8> {
        [pack_dd(key), pack_dd(value.len() as u32), value.to_vec()].concat()
    }
    #[test]
    fn semantic_comparison_ignores_timing_but_preserves_unknown_chunks_and_names() {
        let mut a = chunk(MdKey::VdElapsed.raw(), &[1]);
        let mut b = chunk(MdKey::VdElapsed.raw(), &[2]);
        a.extend(chunk(42, b"opaque"));
        b.extend(chunk(42, b"opaque"));
        assert_eq!(
            semantic_agreement("parser", &a, "parser", &b),
            (Some(true), vec![])
        );
        assert_eq!(
            semantic_agreement("parser", &a, "decoder", &b).0,
            Some(false)
        );
        b.extend(chunk(42, b"extra"));
        assert_eq!(
            semantic_agreement("parser", &a, "parser", &b),
            (Some(false), vec![42])
        );
        assert_eq!(semantic_agreement("parser", &[255], "parser", &a).0, None);
        assert_eq!(
            semantic_agreement("parser", &[0, 42], "parser", &[]).0,
            None
        );
    }
}
