//! Search index rebuild from engine data.

use super::index::SearchIndex;
use super::types::SearchDocument;
use crate::common::demangle::demangle;
use crate::common::hash::version_id_matches;
use crate::db::semantic::{analyze_function, is_rejected_function_name};
use crate::engine::{ContextIndex, OpenSegments, ShardedIndex};
use log::info;
use std::collections::HashMap;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildProgressPhase {
    ScanSegments,
    BuildDocuments,
    Commit,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct RebuildProgress {
    pub phase: RebuildProgressPhase,
    pub current: u64,
    pub total: u64,
    pub valid_records: u64,
    pub unique_keys: u64,
    pub indexed_docs: u64,
    pub demangled: u64,
    pub with_basenames: u64,
    pub with_origin_tokens: u64,
    pub canonical_versions: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SearchRebuildSummary {
    pub total_records: u64,
    pub valid_records: u64,
    pub unique_keys: u64,
    pub indexed_docs: u64,
    pub demangled: u64,
    pub with_basenames: u64,
    pub with_origin_tokens: u64,
    pub canonical_versions: u64,
}

struct ResolvedRecord {
    ts: u64,
    name: String,
    data: Vec<u8>,
    used_canonical: bool,
}

/// Rebuild the search index from engine data.
pub fn rebuild_from_engine(
    search: &SearchIndex,
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
) -> io::Result<()> {
    rebuild_from_engine_with_progress(search, segments, index, ctx_index, |_| {}).map(|_| ())
}

pub fn rebuild_from_engine_with_progress<F>(
    search: &SearchIndex,
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
    mut progress: F,
) -> io::Result<SearchRebuildSummary>
where
    F: FnMut(RebuildProgress),
{
    let (docs, summary) =
        collect_rebuild_documents_with_progress(segments, index, ctx_index, &mut progress)?;

    info!("rebuilding full-text index for {} functions", docs.len());
    progress(progress_snapshot(
        RebuildProgressPhase::Commit,
        0,
        summary.indexed_docs,
        summary,
    ));
    search.rebuild(docs)?;
    progress(progress_snapshot(
        RebuildProgressPhase::Commit,
        summary.indexed_docs,
        summary.indexed_docs,
        summary,
    ));

    Ok(summary)
}

fn collect_rebuild_documents_with_progress<F>(
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
    progress: &mut F,
) -> io::Result<(Vec<SearchDocument>, SearchRebuildSummary)>
where
    F: FnMut(RebuildProgress),
{
    let total_records = segments.get_record_count()?;
    let mut summary = SearchRebuildSummary {
        total_records,
        ..SearchRebuildSummary::default()
    };
    let mut latest: HashMap<u128, (u64, String, Vec<u8>)> = HashMap::new();
    let mut scanned = 0u64;

    progress(progress_snapshot(
        RebuildProgressPhase::ScanSegments,
        0,
        total_records,
        summary,
    ));

    segments.for_each_record(|_seg_id, _off, rec| {
        scanned += 1;
        if rec.flags & 0x01 == 0 {
            summary.valid_records += 1;
            if is_rejected_function_name(&rec.name) {
                let mut snapshot = summary;
                snapshot.unique_keys = latest.len() as u64;
                progress(progress_snapshot(
                    RebuildProgressPhase::ScanSegments,
                    scanned,
                    total_records,
                    snapshot,
                ));
                return Ok(());
            }
            let entry =
                latest
                    .entry(rec.key)
                    .or_insert((rec.ts_sec, rec.name.clone(), rec.data.clone()));
            if rec.ts_sec >= entry.0 {
                *entry = (rec.ts_sec, rec.name.clone(), rec.data.clone());
            }
        }

        let mut snapshot = summary;
        snapshot.unique_keys = latest.len() as u64;
        progress(progress_snapshot(
            RebuildProgressPhase::ScanSegments,
            scanned,
            total_records,
            snapshot,
        ));
        Ok(())
    })?;

    if !index.is_empty()? {
        latest.retain(|k, _| index.get(*k) != 0);
    }
    summary.unique_keys = latest.len() as u64;
    progress(progress_snapshot(
        RebuildProgressPhase::ScanSegments,
        total_records,
        total_records,
        summary,
    ));

    let total_docs = latest.len() as u64;
    progress(progress_snapshot(
        RebuildProgressPhase::BuildDocuments,
        0,
        total_docs,
        summary,
    ));

    let mut docs = Vec::with_capacity(latest.len());
    for (key, fallback_latest) in latest.into_iter() {
        let Some(resolved) =
            resolve_canonical_or_latest_record(segments, index, ctx_index, key, fallback_latest)?
        else {
            continue;
        };
        if resolved.used_canonical {
            summary.canonical_versions += 1;
        }

        let basenames = ctx_index.resolve_basenames_for_key(key).unwrap_or_default();
        if !basenames.is_empty() {
            summary.with_basenames += 1;
        }

        let binary_refs = ctx_index
            .get_binary_refs_for_key(key, 8)
            .unwrap_or_default();
        let origin_tokens: Vec<String> = binary_refs
            .into_iter()
            .filter_map(|meta| {
                if meta.origin_token.is_empty() {
                    None
                } else {
                    Some(meta.origin_token)
                }
            })
            .collect();
        if !origin_tokens.is_empty() {
            summary.with_origin_tokens += 1;
        }

        let demangle_result = demangle(&resolved.name);
        let (func_name_demangled, lang) = if demangle_result.demangled {
            summary.demangled += 1;
            (
                demangle_result.name,
                demangle_result.lang.unwrap_or("").to_string(),
            )
        } else {
            (String::new(), String::new())
        };

        let analysis = analyze_function(&resolved.name, &resolved.data);
        docs.push(SearchDocument {
            key,
            func_name: resolved.name,
            func_name_demangled,
            lang: if lang.is_empty() {
                analysis.fingerprint.language.clone()
            } else {
                lang
            },
            binary_names: basenames,
            origin_tokens,
            prototype_tokens: analysis.fingerprint.prototype_tokens,
            frame_tokens: analysis.fingerprint.frame_tokens,
            comment_tokens: analysis.fingerprint.comment_tokens,
            operand_tokens: analysis.fingerprint.operand_tokens,
            semantic_tokens: analysis.fingerprint.tokens,
            ts: resolved.ts,
        });

        summary.indexed_docs += 1;
        progress(progress_snapshot(
            RebuildProgressPhase::BuildDocuments,
            summary.indexed_docs,
            total_docs,
            summary,
        ));
    }

    Ok((docs, summary))
}

fn progress_snapshot(
    phase: RebuildProgressPhase,
    current: u64,
    total: u64,
    summary: SearchRebuildSummary,
) -> RebuildProgress {
    RebuildProgress {
        phase,
        current,
        total,
        valid_records: summary.valid_records,
        unique_keys: summary.unique_keys,
        indexed_docs: summary.indexed_docs,
        demangled: summary.demangled,
        with_basenames: summary.with_basenames,
        with_origin_tokens: summary.with_origin_tokens,
        canonical_versions: summary.canonical_versions,
    }
}

fn resolve_canonical_or_latest_record(
    segments: &OpenSegments,
    index: &ShardedIndex,
    ctx_index: &ContextIndex,
    key: u128,
    fallback_latest: (u64, String, Vec<u8>),
) -> io::Result<Option<ResolvedRecord>> {
    let canonical_vid = ctx_index
        .get_canonical_version(key)?
        .map(|cv| cv.version_id);

    let head = index.try_get(key)?;
    if head == 0 {
        let (ts, name, data) = fallback_latest;
        return Ok(Some(ResolvedRecord {
            ts,
            name,
            data,
            used_canonical: false,
        }));
    }

    let resolved = crate::engine::resolve_visible_record(segments, index, ctx_index, key, true)?;
    Ok(resolved.map(|rec| ResolvedRecord {
        used_canonical: canonical_vid
            .is_some_and(|id| version_id_matches(&id, key, &rec.name, &rec.data)),
        ts: rec.ts_sec,
        name: rec.name,
        data: rec.data,
    }))
}
