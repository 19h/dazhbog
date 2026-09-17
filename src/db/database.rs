//! Main database implementation for function metadata storage.

#[cfg(test)]
#[path = "selection_tests.rs"]
mod selection_tests;

#[cfg(test)]
#[path = "mutation_tests.rs"]
mod mutation_tests;

#[cfg(test)]
#[path = "graph_tests.rs"]
mod graph_tests;

#[path = "candidate_history.rs"]
mod candidate_history;

#[path = "candidate_provenance.rs"]
mod candidate_provenance;

use crate::api::metrics::METRICS;
use crate::common::demangle::demangle;
use crate::common::hash::{legacy_version_id, version_id};
use crate::common::neighbor::is_generic_neighbor_token;
use crate::common::parallel::{in_scan_worker, map_chunks, map_chunks_offthread};
use crate::common::skeleton::strip_ida_duplicate_suffix;
use crate::common::{addr_off, addr_seg};
use crate::config::Config;
use crate::engine::{
    merge_alias_stats, BinaryOverlapEntry, BinaryRefHit, EngineRuntime, IndexError, Record,
    SearchDocument, SearchHit, SemanticNeighborRationale, UpsertResult, MAX_BINARY_OVERLAP_ROWS,
    REC_FLAG_DECLARED_SIZE, REC_FLAG_DELETED,
};
use crate::protocol::lumina::metadata::parse_metadata;

use super::anchors::{
    batch_fingerprint, consensus_fingerprint, contrastive_support, corroborated_support,
    restrict_contrastive_weights, selection_fingerprint, BatchAnchors,
};
use super::failure_cache::FailureCache;
use super::family::{BatchFamilyEvidence, MAX_KEY_MEMBERSHIPS};
use super::pattern::{
    classify_names, CandidateName, Classification, ClassifyParams, DeclineReason, KeyDecision,
    PatternClass, Provenance, ServedForm, TypeConsensus,
};
use super::provenance::ProvenanceGate;
use crate::common::remangle::{splice_placeholder_class, splice_placeholder_template};
use super::semantic::{
    analyze_function_with_policy, fingerprint_similarity, is_rejected_function_name_with,
    normalize_origin_token, normalize_requested_mdkeys, shape_metadata_for_request,
    SemanticAnalysis, SynthesisInput,
};
use super::types::{
    BinaryCompareItem, BinaryCompareVariant, BinaryFacetSummary, BinarySummary, FuncLatest,
    OwnedPushContext, PushContext, QueryContext, ReplayCaseOptions, ReplayCaseResult,
    ReplayRequestMode, ReplaySelectorResult, SelectedVariant, SharedCodeProfile, SharedComponent,
    InferredBinary, SharedFunctionSample, VariantBinary, VariantInfo, VariantInventory,
};

use log::*;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Main database handle for function metadata.
#[derive(Clone)]
pub struct Database {
    pub(super) rt: Arc<EngineRuntime>,
    pub failure_cache: FailureCache,
}

#[derive(Clone)]
struct AnalyzedVersion {
    rec: Record,
    version_id: [u8; 32],
    legacy_version_id: [u8; 32],
    binary_support: f64,
    binary_match: f64,
    binary_priority_floor: f64,
    name_quality: f64,
    analysis: OnceLock<SemanticAnalysis>,
    batch_fingerprint: Option<Box<super::semantic::SemanticFingerprint>>,
    stats: Option<crate::engine::VersionStats>,
}

impl AnalyzedVersion {
    fn analysis(&self) -> &SemanticAnalysis {
        self.analysis.get_or_init(|| {
            super::semantic::analyze_function_with_name_quality(
                &self.rec.name,
                &self.rec.data,
                self.name_quality,
            )
        })
    }

    fn anchor_fingerprint(&self) -> &super::semantic::SemanticFingerprint {
        self.batch_fingerprint
            .as_deref()
            .unwrap_or_else(|| &self.analysis().fingerprint)
    }
    fn matches_id(&self, id: &[u8; 32]) -> bool {
        *id == self.version_id || *id == self.legacy_version_id
    }
}

#[derive(Default)]
struct NeighborFamilyContext {
    direct_weights: HashMap<[u8; 16], f64>,
    related_weights: HashMap<[u8; 16], f64>,
    // At most four direct and twelve related binaries per direct binary.
    // Resolve metadata once; candidate membership uses targeted key/MD5 reads.
    binary_metas: Vec<crate::engine::BinaryMeta>,
}

struct SemanticNeighborScore {
    final_score: f64,
    rationale: SemanticNeighborRationale,
}

impl Database {
    fn require_current_projection(rt: &EngineRuntime) -> io::Result<()> {
        if !rt.projection_compatible {
            return Err(io::Error::other(
                "mutation requires a search projection prepared with the current name policy",
            ));
        }
        Ok(())
    }

    pub(crate) fn rejects_function_name(&self, name: &str) -> bool {
        is_rejected_function_name_with(self.rt.cfg.name_rejection, name)
    }

    /// Stream canonical documents into a new, empty search generation.
    pub(crate) fn rebuild_search_projection(
        rt: &EngineRuntime,
        quarantine_path: Option<&std::path::Path>,
    ) -> io::Result<()> {
        use std::io::Write;
        let mut quarantine = quarantine_path
            .map(std::fs::File::create_new)
            .transpose()?
            .map(io::BufWriter::new);
        let mut count = 0u64;
        let mut excluded = 0u64;
        for entry in rt.index.try_iter_keys() {
            let (key, _) = entry?;
            let resolved = crate::engine::resolve_visible_record_with_policy(
                &rt.segments,
                &rt.index,
                &rt.ctx_index,
                key,
                true,
                rt.cfg.name_rejection,
            );
            let record = match resolved {
                Ok(record) => record,
                Err(error)
                    if quarantine.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::InvalidData | io::ErrorKind::NotFound
                        ) =>
                {
                    let writer = quarantine.as_mut().expect("quarantine enabled");
                    serde_json::to_writer(
                        &mut *writer,
                        &serde_json::json!({"key":format!("{key:032x}"), "error":error.to_string()}),
                    )?;
                    writer.write_all(b"\n")?;
                    excluded += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some(rec) = record {
                let mut doc =
                    Self::build_search_document_static(rt, key, &rec.name, &rec.data, rec.ts_sec);
                doc.variant_tokens = crate::engine::search::variant_vocabulary(
                    &rt.segments,
                    &rt.index,
                    key,
                    &doc.semantic_tokens,
                    version_id(key, &rec.name, &rec.data),
                    rt.cfg.name_rejection,
                )?;
                rt.search.append_prepared_document(&doc)?;
                count += 1;
                if count.is_multiple_of(100_000) {
                    log::info!("prepared search documents={count}");
                }
            }
        }
        rt.search.commit()?;
        if let Some(mut writer) = quarantine {
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        log::info!("prepared search complete documents={count} quarantined_keys={excluded}");
        Ok(())
    }

    pub fn flush(&self) -> io::Result<()> {
        self.rt.flush()
    }

    /// Open or create a database with the given configuration.
    pub async fn open(cfg: Arc<Config>) -> io::Result<Arc<Self>> {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;

        // Initialize metrics with current database stats
        let stats = rt.get_stats()?;
        if let Err(e) = METRICS.init(
            &rt.index_db,
            stats.indexed_funcs,
            stats.total_records,
            stats.storage_bytes,
            stats.search_docs,
            stats.unique_binaries,
        ) {
            warn!("Failed to initialize persistent metrics: {}", e);
        }

        Ok(Arc::new(Self {
            rt: Arc::new(rt),
            failure_cache: FailureCache::new(),
        }))
    }

    /// Open the database for offline replay/evaluation without rebuilding search.
    pub async fn open_for_replay(cfg: Arc<Config>) -> io::Result<Arc<Self>> {
        let rt = EngineRuntime::open_for_replay(cfg.engine.clone(), cfg.scoring.clone())?;
        Ok(Arc::new(Self {
            rt: Arc::new(rt),
            failure_cache: FailureCache::new(),
        }))
    }

    /// Get the latest version of a function by key.
    pub async fn get_latest(&self, key: u128) -> io::Result<Option<FuncLatest>> {
        let Some(rec) = Self::visible_latest_record_sync(&self.rt, key)? else {
            return Ok(None);
        };
        Ok(Some(FuncLatest {
            popularity: rec.popularity,
            len_bytes: rec.len_bytes,
            ts_sec: rec.ts_sec,
            name: rec.name,
            data: rec.data,
        }))
    }

    fn visible_latest_record_sync(rt: &EngineRuntime, key: u128) -> io::Result<Option<Record>> {
        crate::engine::resolve_visible_record_with_policy(
            &rt.segments,
            &rt.index,
            &rt.ctx_index,
            key,
            false,
            rt.cfg.name_rejection,
        )
    }

    /// Canonical metadata within the current live history interval.
    pub async fn get_canonical(&self, key: u128) -> io::Result<Option<FuncLatest>> {
        Ok(crate::engine::resolve_visible_record_with_policy(
            &self.rt.segments,
            &self.rt.index,
            &self.rt.ctx_index,
            key,
            true,
            self.rt.cfg.name_rejection,
        )?
        .map(|rec| FuncLatest {
            popularity: rec.popularity,
            len_bytes: rec.len_bytes,
            ts_sec: rec.ts_sec,
            name: rec.name,
            data: rec.data,
        }))
    }

    /// Resolve a browser record using the same explicit-identity selector as pulls.
    /// Unknown/stale binary observations retain the selector's documented fallback.
    pub async fn get_function_in_context(
        &self,
        key: u128,
        md5: Option<[u8; 16]>,
    ) -> io::Result<Option<FuncLatest>> {
        let Some(md5) = md5 else {
            return self.get_canonical(key).await;
        };
        Ok(self
            .select_binary_variant(key, md5)
            .await?
            .map(|s| FuncLatest {
                popularity: s.popularity,
                len_bytes: s.func_size,
                ts_sec: s.ts_sec,
                name: s.name,
                data: s.data,
            }))
    }

    async fn select_binary_variant(
        &self,
        key: u128,
        md5: [u8; 16],
    ) -> io::Result<Option<SelectedVariant>> {
        let mut selected = self
            .select_batch(
                &QueryContext {
                    keys: &[key],
                    requested_mdkeys: &[],
                    md5: Some(md5),
                    basename: None,
                    hostname: None,
                    origin_token: None,
                },
                false,
                None,
                false,
            )
            .await?;
        Ok(selected.pop().and_then(|(result, _)| result))
    }

    /// Push function metadata without context.
    pub async fn push(&self, items: &[(u128, u32, u32, &str, &[u8])]) -> io::Result<Vec<u32>> {
        let null_ctx = PushContext {
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
        };
        self.push_with_ctx(items, &null_ctx).await
    }

    /// Push function metadata with context information.
    ///
    /// Items are `(key, popularity, declared function size, name, metadata)`.
    pub async fn push_with_ctx(
        &self,
        items: &[(u128, u32, u32, &str, &[u8])],
        ctx: &PushContext<'_>,
    ) -> io::Result<Vec<u32>> {
        self.push_with_ctx_mode(items, ctx, false).await
    }

    /// Push with an explicit conflict mode. `do_not_override` mirrors Lumina's
    /// `PMF_PUSH_DO_NOT_OVERRIDE`: keys that already have a live version only
    /// record the binary observation and report "unchanged".
    pub async fn push_with_ctx_mode(
        &self,
        items: &[(u128, u32, u32, &str, &[u8])],
        ctx: &PushContext<'_>,
        do_not_override: bool,
    ) -> io::Result<Vec<u32>> {
        Self::require_current_projection(&self.rt)?;
        // Convert to owned data for spawn_blocking ('static requirement)
        let owned_items: Vec<(u128, u32, u32, String, Vec<u8>)> = items
            .iter()
            .map(|(k, p, l, n, d)| (*k, *p, *l, n.to_string(), d.to_vec()))
            .collect();
        let owned_ctx = OwnedPushContext {
            md5: ctx.md5,
            basename: ctx.basename.map(|s| s.to_string()),
            hostname: ctx.hostname.map(|s| s.to_string()),
            origin_token: ctx.origin_token.map(|s| s.to_string()),
        };
        let rt = self.rt.clone();

        // Move blocking sled I/O to dedicated thread pool
        tokio::task::spawn_blocking(move || {
            Self::push_with_ctx_sync(&rt, &owned_items, &owned_ctx, do_not_override)
        })
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking: {}", e)))?
    }

    /// Synchronous implementation of push_with_ctx (runs on blocking thread pool).
    fn push_with_ctx_sync(
        rt: &EngineRuntime,
        items: &[(u128, u32, u32, String, Vec<u8>)],
        ctx: &OwnedPushContext,
        do_not_override: bool,
    ) -> io::Result<Vec<u32>> {
        let mut status = Vec::with_capacity(items.len());
        let mut search_docs_delta = 0u64;
        for (key, pop, len_decl, pushed_name, data) in items.iter() {
            // An IDA collision suffix is not part of the symbol; store the
            // symbol so every upload of it lands on one version.
            let normalized;
            let name: &String = if rt.scoring.normalize_collision_suffixes {
                match strip_ida_duplicate_suffix(pushed_name) {
                    Some(stem) => {
                        normalized = stem.to_string();
                        &normalized
                    }
                    None => pushed_name,
                }
            } else {
                pushed_name
            };
            if is_rejected_function_name_with(rt.cfg.name_rejection, name) {
                log::debug!(
                    "ignoring push for key {:032x}: rejected generated function name '{}'",
                    key,
                    name
                );
                status.push(2);
                continue;
            }
            // A served skeleton carries the placeholder; a client that keeps
            // it must not turn the server's own artefact into a stored name.
            let placeholder = &rt.scoring.skeleton_placeholder;
            if !placeholder.is_empty() && name.contains(placeholder.as_str()) {
                log::debug!(
                    "ignoring push for key {:032x}: skeleton placeholder in '{}'",
                    key,
                    name
                );
                status.push(2);
                continue;
            }
            if name.len() > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "name too long (> u16::MAX)",
                ));
            }
            if data.len() > u32::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "data large (> u32::MAX)",
                ));
            }

            let _mutation = rt.mutations.lock(*key);
            let _facets = rt.ctx_index.facets.begin_mutation(Some(*key), None);
            let old = rt.index.get(*key);

            // Track whether the existing HEAD record is readable.  When it
            // is not (missing segment or corrupt/missing record), we snip the
            // dead chain so that the newly appended record starts a fresh
            // chain instead of perpetuating a dangling prev_addr link.
            let mut head_ok = false;

            if old != 0 {
                let seg_id = addr_seg(old);
                let off = addr_off(old);
                match rt.segments.get_reader(seg_id) {
                    Some(reader) => match reader.read_at(off) {
                        Ok(existing) if existing.key == *key => {
                            head_ok = true;
                            let live = existing.flags & REC_FLAG_DELETED == 0;
                            // A legacy head has no declared size; only compare it
                            // when both sides carry one (reference compares size too).
                            let same_size = existing.flags & REC_FLAG_DECLARED_SIZE == 0
                                || existing.len_bytes == *len_decl;
                            let unchanged = live
                                && existing.name == *name
                                && existing.data == *data
                                && same_size;
                            if unchanged || (do_not_override && live) {
                                status.push(2);
                                let ts = now_ts_sec();
                                if Self::record_context_observation(rt, *key, name, data, ctx, ts) {
                                    METRICS.inc_unique_binaries();
                                }
                                if let Some((canonical, _, _)) =
                                    Self::refresh_canonical_for_key(rt, *key)?
                                {
                                    Self::update_search_entry_no_commit_static(
                                        rt,
                                        *key,
                                        &canonical.name,
                                        &canonical.data,
                                        canonical.ts_sec,
                                    );
                                } else {
                                    Self::update_search_entry_no_commit_static(
                                        rt,
                                        *key,
                                        name,
                                        data,
                                        existing.ts_sec,
                                    );
                                }
                                continue;
                            }
                        }
                        Ok(existing) => {
                            // A readable head belonging to another key is not this
                            // key's history.  Linking it would propagate the bad
                            // pointer, and comparing against it could discard the
                            // push outright via the do_not_override branch above.
                            log::warn!(
                                "Existing record at seg={}, off={} holds key {:032x}; \
                                 new record will start a fresh chain for key {:032x}",
                                seg_id,
                                off,
                                existing.key,
                                key
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "Failed to read existing record at seg={}, off={}: {}; \
                                 new record will start a fresh chain for key {:032x}",
                                seg_id,
                                off,
                                e,
                                key
                            );
                        }
                    },
                    None => {
                        log::warn!(
                            "Segment {} not found for existing record; \
                             new record will start a fresh chain for key {:032x}",
                            seg_id,
                            key
                        );
                    }
                }
            }

            let prev_addr = if head_ok { old } else { 0 };

            let rec = Record {
                key: *key,
                ts_sec: now_ts_sec(),
                prev_addr,
                len_bytes: *len_decl,
                popularity: *pop,
                name: name.to_string(),
                data: data.to_vec(),
                flags: REC_FLAG_DECLARED_SIZE,
            };
            let addr = rt.segments.append(&rec)?;
            METRICS.inc_total_records();
            METRICS.add_storage_bytes(rec.encoded_len());
            match rt.index.upsert(*key, addr) {
                Ok(UpsertResult::Inserted) => {
                    status.push(1);
                    METRICS.inc_indexed_funcs();
                    search_docs_delta += 1;
                }
                Ok(UpsertResult::Replaced(_)) => {
                    status.push(0);
                }
                Err(IndexError::Full) => {
                    METRICS.inc_append_failures();
                    return Err(io::Error::other("index full"));
                }
                Err(IndexError::Io(e)) => {
                    METRICS.inc_append_failures();
                    return Err(io::Error::other(format!("index io error: {}", e)));
                }
            }

            let ts = rec.ts_sec;
            if Self::record_context_observation(rt, *key, name, data, ctx, ts) {
                METRICS.inc_unique_binaries();
            }
            if let Some((canonical, _, _)) = Self::refresh_canonical_for_key(rt, *key)? {
                Self::update_search_entry_no_commit_static(
                    rt,
                    *key,
                    &canonical.name,
                    &canonical.data,
                    canonical.ts_sec,
                );
            } else {
                Self::update_search_entry_no_commit_static(rt, *key, name, data, rec.ts_sec);
            }
        }
        // Commit all search index changes at once
        match rt.search.commit() {
            Ok(()) => {
                if search_docs_delta != 0 {
                    METRICS.add_search_docs(search_docs_delta);
                }
            }
            Err(e) => {
                log::warn!("failed to commit search index: {}", e);
            }
        }

        Ok(status)
    }

    fn update_search_entry_no_commit_static(
        rt: &EngineRuntime,
        key: u128,
        name: &str,
        data: &[u8],
        ts: u64,
    ) {
        let mut doc = Self::build_search_document_static(rt, key, name, data, ts);
        match crate::engine::search::variant_vocabulary(
            &rt.segments,
            &rt.index,
            key,
            &doc.semantic_tokens,
            version_id(key, name, data),
            rt.cfg.name_rejection,
        ) {
            Ok(tokens) => doc.variant_tokens = tokens,
            Err(error) => {
                log::warn!("failed to collect variant vocabulary key={key:032x}: {error}");
                return;
            }
        }
        if let Err(e) = rt.search.index_function_no_commit(&doc) {
            log::warn!("failed to update search index for key {:032x}: {}", key, e);
        }
    }

    pub(crate) fn build_search_document_static(
        rt: &EngineRuntime,
        key: u128,
        name: &str,
        data: &[u8],
        ts: u64,
    ) -> SearchDocument {
        let basenames = match rt.ctx_index.resolve_basenames_for_key(key) {
            Ok(b) => b,
            Err(e) => {
                log::debug!("no basenames for key {:032x}: {}", key, e);
                Vec::new()
            }
        };
        let origin_tokens: Vec<String> = rt
            .ctx_index
            .get_binary_refs_for_key(key, 8)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|meta| {
                if meta.origin_token.is_empty() {
                    None
                } else {
                    Some(meta.origin_token)
                }
            })
            .collect();
        let demangle_result = demangle(name);
        let (func_name_demangled, lang) = if demangle_result.demangled {
            (
                demangle_result.name,
                demangle_result.lang.unwrap_or("").to_string(),
            )
        } else {
            (String::new(), String::new())
        };
        let analysis = analyze_function_with_policy(name, data, rt.cfg.name_rejection);
        SearchDocument {
            key,
            func_name: name.to_string(),
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
            variant_tokens: Vec::new(),
            ts,
        }
    }

    fn record_context_observation(
        rt: &EngineRuntime,
        key: u128,
        name: &str,
        data: &[u8],
        ctx: &OwnedPushContext,
        ts: u64,
    ) -> bool {
        if let Some(md5) = ctx.md5 {
            let vid = version_id(key, name, data);
            let is_new_binary = match rt.ctx_index.record_binary_meta(
                md5,
                ctx.basename.as_deref().unwrap_or(""),
                ctx.hostname.as_deref().unwrap_or(""),
                ctx.origin_token.as_deref().unwrap_or(""),
                ts,
            ) {
                Ok(is_new_binary) => is_new_binary,
                Err(e) => {
                    log::warn!(
                        "failed to record binary metadata for key {:032x}: {}",
                        key,
                        e
                    );
                    false
                }
            };
            if let Err(e) = rt.ctx_index.record_key_observation(
                key,
                md5,
                Some(vid),
                ts,
                ctx.basename.as_deref(),
            ) {
                log::warn!(
                    "failed to record key observation for key {:032x}: {}",
                    key,
                    e
                );
            }
            return is_new_binary;
        }
        false
    }

    fn collect_versions_sync(
        rt: &EngineRuntime,
        key: u128,
        cap: usize,
    ) -> io::Result<Vec<AnalyzedVersion>> {
        Self::collect_versions_targeted(rt, key, cap, &HashSet::new(), None)
    }

    fn collect_versions_targeted(
        rt: &EngineRuntime,
        key: u128,
        cap: usize,
        wanted: &HashSet<[u8; 32]>,
        provenance: Option<&candidate_provenance::TransferProvenance>,
    ) -> io::Result<Vec<AnalyzedVersion>> {
        Self::collect_versions_bounded(
            rt,
            key,
            cap,
            wanted,
            provenance,
            crate::engine::MAX_HISTORY_RECORDS,
        )
    }

    /// Validate one physical history record without loading ranking evidence.
    /// An invalid ancestor truncates the chain; a foreign head is an error.
    fn read_history_record(
        rt: &EngineRuntime,
        key: u128,
        addr: u64,
        is_head: bool,
    ) -> io::Result<Option<Record>> {
        let seg_id = addr_seg(addr);
        let off = addr_off(addr);
        let Some(reader) = rt.segments.get_reader(seg_id) else {
            return Ok(None);
        };
        let rec = match reader.read_at(off) {
            Ok(rec) => rec,
            Err(e) => {
                log::warn!(
                    "history read failed at seg={seg_id}, off={off}: {e}; \
                     truncating version chain for key {key:032x}"
                );
                return Ok(None);
            }
        };
        if rec.key != key {
            if is_head {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "version history key mismatch",
                ));
            }
            log::warn!("collect_versions: cross-key ancestry for key {key:032x}; retaining validated prefix");
            return Ok(None);
        }
        Ok(Some(rec))
    }

    fn exact_observed_head(
        rt: &EngineRuntime,
        key: u128,
        observed: &[u8; 32],
    ) -> io::Result<Option<Record>> {
        let addr = rt.index.try_get(key)?;
        if addr == 0 {
            return Ok(None);
        }
        let Some(rec) = Self::read_history_record(rt, key, addr, true)? else {
            return Ok(None);
        };
        if rec.flags & REC_FLAG_DELETED != 0
            || is_rejected_function_name_with(rt.cfg.name_rejection, &rec.name)
        {
            return Ok(None);
        }
        Ok((*observed == version_id(key, &rec.name, &rec.data)
            || *observed == legacy_version_id(key, &rec.name, &rec.data))
        .then_some(rec))
    }

    fn collect_versions_bounded(
        rt: &EngineRuntime,
        key: u128,
        cap: usize,
        wanted: &HashSet<[u8; 32]>,
        provenance: Option<&candidate_provenance::TransferProvenance>,
        record_limit: usize,
    ) -> io::Result<Vec<AnalyzedVersion>> {
        let record_limit = record_limit.min(crate::engine::MAX_HISTORY_RECORDS);
        if cap == 0 || record_limit == 0 {
            return Ok(Vec::new());
        }
        let mut versions = Vec::new();
        let mut seen_versions = HashSet::new();
        let mut remaining = wanted.clone();
        let mut addr = rt.index.try_get(key)?;
        let mut seen_addrs = HashSet::new();
        while addr != 0
            && (versions.len() < cap || !remaining.is_empty())
            && !seen_addrs.contains(&addr)
        {
            if seen_addrs.len() >= record_limit {
                if record_limit == crate::engine::MAX_HISTORY_RECORDS {
                    log::warn!("collect_versions: traversal limit for key {key:032x}");
                }
                break;
            }
            seen_addrs.insert(addr);
            let Some(mut rec) = Self::read_history_record(rt, key, addr, seen_addrs.len() == 1)?
            else {
                break;
            };
            let next = rec.prev_addr;
            if rec.flags & 0x01 == 0x01 {
                break;
            }
            if !is_rejected_function_name_with(rt.cfg.name_rejection, &rec.name) {
                let vid = version_id(key, &rec.name, &rec.data);
                let legacy_vid = legacy_version_id(key, &rec.name, &rec.data);
                // Both removals must execute when the two IDs are requested.
                let targeted = remaining.remove(&vid) | remaining.remove(&legacy_vid);
                if seen_versions.insert(vid) && (versions.len() < cap || targeted) {
                    let mut stats = merge_alias_stats(
                        rt.ctx_index.get_version_stats(&vid)?,
                        rt.ctx_index.get_version_stats(&legacy_vid)?,
                    );
                    if let Some(provenance) = provenance {
                        if !provenance.permits(rt, &vid, &legacy_vid, &mut stats)? {
                            addr = next;
                            continue;
                        }
                        // The newest physical copy may have been uploaded by the
                        // held-out binary. It cannot supply a recency tie-break.
                        rec.ts_sec = 0;
                    }
                    versions.push(AnalyzedVersion {
                        version_id: vid,
                        legacy_version_id: legacy_vid,
                        binary_support: 0.0,
                        binary_match: 0.0,
                        binary_priority_floor: 0.0,
                        name_quality: super::semantic::name_quality_with(
                            rt.cfg.name_rejection,
                            &rec.name,
                        ),
                        stats,
                        rec,
                        analysis: OnceLock::new(),
                        batch_fingerprint: None,
                    });
                }
            }
            addr = next;
        }
        Ok(versions)
    }

    fn refresh_canonical_for_key(
        rt: &EngineRuntime,
        key: u128,
    ) -> io::Result<Option<(Record, [u8; 32], f64)>> {
        // Retain the validated incumbent as a challenger even after it leaves
        // the recent window. It receives no incumbent bonus during refresh.
        let wanted = rt
            .ctx_index
            .get_canonical_version(key)?
            .map(|canonical| canonical.version_id)
            .into_iter()
            .collect();
        let versions = Self::collect_versions_targeted(
            rt,
            key,
            rt.scoring.max_versions_per_key,
            &wanted,
            None,
        )?;
        if versions.is_empty() {
            return Ok(None);
        }

        let (ts_min, ts_max, max_total_obs, max_bins) = version_population_bounds(&versions);

        let empty_weights: HashMap<String, f64> = HashMap::new();
        let requested: [u32; 0] = [];
        let scoring_ctx = CandidateScoringContext {
            capture_candidates: false,
            suppress_observation_priors: false,
            contrastive_anchors: false,
            key,
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
            requested_mdkeys: &requested,
            anchor_token_weights: &empty_weights,
            priority_anchor_weights: &empty_weights,
            corroboration_weights: &empty_weights,
            canonical_hint: None,
        };

        let mut best_idx = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (idx, version) in versions.iter().enumerate() {
            let score = score_candidate_version(
                rt,
                version,
                &scoring_ctx,
                ts_min,
                ts_max,
                max_total_obs,
                max_bins,
            )?;
            if score > best_score {
                best_score = score;
                best_idx = idx;
            }
        }

        let best = &versions[best_idx];
        rt.ctx_index
            .set_canonical_version(key, best.version_id, best_score, best.rec.ts_sec)?;
        Ok(Some((best.rec.clone(), best.version_id, best_score)))
    }

    /// Delete function metadata by keys.
    pub async fn delete_keys(&self, keys: &[u128]) -> io::Result<u32> {
        Self::require_current_projection(&self.rt)?;
        let rt = self.rt.clone();
        let keys = keys.to_vec();
        tokio::task::spawn_blocking(move || Self::delete_keys_sync(&rt, &keys))
            .await
            .map_err(|e| io::Error::other(format!("spawn_blocking: {}", e)))?
    }

    fn delete_keys_sync(rt: &EngineRuntime, keys: &[u128]) -> io::Result<u32> {
        let mut deleted = 0u32;
        let mut deleted_search_docs = 0u64;
        for &key in keys {
            let _mutation = rt.mutations.lock(key);
            let _facets = rt.ctx_index.facets.begin_mutation(Some(key), None);
            let old = rt.index.get(key);
            // A head that is unreadable or belongs to another key can neither
            // report liveness for this key nor be linked into the tombstone.
            let head = match old {
                0 => None,
                _ => match rt.segments.read_record(old) {
                    Ok(rec) if rec.key == key => Some(rec),
                    Ok(rec) => {
                        log::warn!(
                            "Existing record at {old:016x} holds key {:032x}; \
                             tombstone will start a fresh chain for key {key:032x}",
                            rec.key
                        );
                        None
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to read existing record at {old:016x}: {e}; \
                             tombstone will start a fresh chain for key {key:032x}"
                        );
                        None
                    }
                },
            };
            let had_live_head = head.as_ref().is_some_and(|rec| rec.flags & 0x01 == 0);
            let rec = Record {
                key,
                ts_sec: now_ts_sec(),
                prev_addr: if head.is_some() { old } else { 0 },
                len_bytes: 0,
                popularity: 0,
                name: String::new(),
                data: Vec::new(),
                flags: 0x01,
            };
            let addr = rt.segments.append(&rec)?;
            METRICS.inc_total_records();
            METRICS.add_storage_bytes(rec.encoded_len());
            match rt.index.upsert(key, addr) {
                Ok(UpsertResult::Inserted) => METRICS.inc_indexed_funcs(),
                Ok(UpsertResult::Replaced(_)) => {}
                Err(IndexError::Full) => METRICS.inc_append_failures(),
                Err(IndexError::Io(_)) => METRICS.inc_append_failures(),
            }
            if rt.search.delete(key).is_ok() && had_live_head {
                deleted_search_docs += 1;
            }
            if had_live_head {
                deleted += 1;
            }
        }
        if deleted_search_docs != 0 {
            METRICS.sub_search_docs(deleted_search_docs);
        }
        Ok(deleted)
    }

    /// Get function history by key.
    pub async fn get_history(
        &self,
        key: u128,
        mut limit: u32,
    ) -> io::Result<Vec<(u64, String, Vec<u8>)>> {
        if limit == 0 {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut addr = self.rt.index.try_get(key)?;
        let mut seen_addrs = HashSet::new();
        while addr != 0 && limit > 0 && seen_addrs.insert(addr) {
            if seen_addrs.len() > crate::engine::MAX_HISTORY_RECORDS {
                log::warn!("get_history: traversal limit for key {key:032x}");
                break;
            }
            let r = self
                .rt
                .segments
                .get_reader(addr_seg(addr))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "seg"))?;
            let rec = r.read_at(addr_off(addr))?;
            if rec.key != key {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "history key mismatch",
                ));
            }
            if rec.flags & REC_FLAG_DELETED != 0 {
                // A deleted key has no visible history (reference: rows removed).
                break;
            }
            if !is_rejected_function_name_with(self.rt.cfg.name_rejection, &rec.name) {
                out.push((rec.ts_sec, rec.name, rec.data));
                limit -= 1;
            }
            addr = rec.prev_addr;
        }
        Ok(out)
    }

    /// Search functions by query string. Returns up to `limit` results.
    pub async fn search_functions(&self, query: &str, limit: usize) -> io::Result<Vec<SearchHit>> {
        let hits = self.rt.search.search(query, limit)?;
        let (mut hits, _) = self.filter_visible_search_hits(hits).await?;
        self.attach_binary_refs(&mut hits)?;
        Ok(hits)
    }

    /// Search functions with pagination. Returns (results, total_count).
    pub async fn search_functions_paginated(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        let (hits, total) = self.rt.search.search_paginated(query, offset, limit)?;
        let (mut hits, hidden) = self.filter_visible_search_hits(hits).await?;
        self.attach_binary_refs(&mut hits)?;
        Ok((hits, total.saturating_sub(hidden)))
    }

    async fn filter_visible_search_hits(
        &self,
        hits: Vec<SearchHit>,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        let mut out = Vec::with_capacity(hits.len());
        let mut hidden = 0;
        for hit in hits {
            let Ok(key) = u128::from_str_radix(&hit.key_hex, 16) else {
                hidden += 1;
                continue;
            };
            match self.get_canonical(key).await? {
                Some(func) if hit.func_name == func.name && hit.ts == func.ts_sec => out.push(hit),
                _ => hidden += 1,
            }
        }
        Ok((out, hidden))
    }

    fn apply_visible_function_to_hit(hit: &mut SearchHit, func: &FuncLatest) {
        let demangle_result = demangle(&func.name);
        let (func_name_demangled, lang) = if demangle_result.demangled {
            (
                Some(demangle_result.name),
                demangle_result.lang.map(|s| s.to_string()),
            )
        } else {
            (None, None)
        };
        hit.func_name = func.name.clone();
        hit.func_name_demangled = func_name_demangled;
        hit.lang = lang;
        hit.ts = func.ts_sec;
    }

    pub async fn semantic_neighbors_for_key(
        &self,
        key: u128,
        limit: usize,
        strict_family: bool,
    ) -> io::Result<Vec<SearchHit>> {
        self.semantic_neighbors_with_budget(
            key,
            limit,
            strict_family,
            limit.saturating_mul(8).clamp(24, 96),
        )
        .await
        .map(|(_, hits)| hits)
    }

    /// Offline evaluation surface: retrieve 24..=384 candidates independently of output size.
    /// Returns retrieved keys before reranking, followed by the visible reranked hits.
    pub async fn semantic_neighbors_with_budget(
        &self,
        key: u128,
        limit: usize,
        strict_family: bool,
        candidate_budget: usize,
    ) -> io::Result<(Vec<u128>, Vec<SearchHit>)> {
        self.semantic_neighbors_in_context(key, limit, strict_family, candidate_budget, None)
            .await
    }

    /// Binary-conditioned seed and reranking, with live-variant vocabulary retrieval.
    pub async fn semantic_neighbors_in_context(
        &self,
        key: u128,
        limit: usize,
        strict_family: bool,
        candidate_budget: usize,
        md5: Option<[u8; 16]>,
    ) -> io::Result<(Vec<u128>, Vec<SearchHit>)> {
        if limit == 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let Some(seed) = self.get_function_in_context(key, md5).await? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let seed_doc =
            Self::build_search_document_static(&self.rt, key, &seed.name, &seed.data, seed.ts_sec);
        let seed_analysis =
            analyze_function_with_policy(&seed.name, &seed.data, self.rt.cfg.name_rejection);
        if seed_analysis.fingerprint.tokens.is_empty()
            && seed_analysis.fingerprint.prototype_tokens.is_empty()
            && seed_analysis.fingerprint.frame_tokens.is_empty()
            && seed_analysis.fingerprint.comment_tokens.is_empty()
            && seed_analysis.fingerprint.operand_tokens.is_empty()
        {
            return Ok((Vec::new(), Vec::new()));
        }

        let seed_binary_metas = match md5 {
            Some(md5) => self
                .rt
                .ctx_index
                .get_binary_meta(&md5)?
                .into_iter()
                .collect(),
            None => self.rt.ctx_index.get_binary_refs_for_key(key, 8)?,
        };
        if strict_family && seed_binary_metas.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let family_ctx = self
            .build_neighbor_family_context(&seed_binary_metas)
            .await?;

        let candidate_limit = candidate_budget.clamp(24, 384);
        let initial_hits = self
            .rt
            .search
            .semantic_neighbors(&seed_doc, key, candidate_limit)?;
        let candidate_keys = initial_hits
            .iter()
            .filter_map(|hit| u128::from_str_radix(&hit.key_hex, 16).ok())
            .collect();
        let mut reranked = Vec::new();
        for mut hit in initial_hits {
            let Ok(candidate_key) = u128::from_str_radix(&hit.key_hex, 16) else {
                continue;
            };
            if candidate_key == key {
                continue;
            }
            let mut candidate_binary_metas = Vec::new();
            for meta in &family_ctx.binary_metas {
                if self
                    .rt
                    .ctx_index
                    .get_positive_key_md5_stats(candidate_key, &meta.md5)?
                    .is_some()
                {
                    candidate_binary_metas.push(meta);
                }
            }
            if strict_family && candidate_binary_metas.is_empty() {
                continue;
            }
            let Some(candidate) = self.get_function_in_context(candidate_key, md5).await? else {
                continue;
            };
            let candidate_doc = Self::build_search_document_static(
                &self.rt,
                candidate_key,
                &candidate.name,
                &candidate.data,
                candidate.ts_sec,
            );
            let candidate_analysis = analyze_function_with_policy(
                &candidate.name,
                &candidate.data,
                self.rt.cfg.name_rejection,
            );
            let Some(scored) = semantic_neighbor_similarity(
                &seed_analysis,
                &seed_doc,
                &candidate_analysis,
                &candidate_doc,
                &family_ctx,
                &candidate_binary_metas,
                hit.score as f64,
            ) else {
                continue;
            };
            if scored.final_score < 0.08 {
                continue;
            }
            if strict_family && scored.rationale.family_score <= 0.0 {
                continue;
            }
            Self::apply_visible_function_to_hit(&mut hit, &candidate);
            hit.score = scored.final_score as f32;
            hit.semantic_neighbor = Some(scored.rationale);
            reranked.push(hit);
        }

        reranked.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.ts.cmp(&a.ts))
                .then_with(|| a.key_hex.cmp(&b.key_hex))
        });
        reranked.truncate(limit);
        self.attach_binary_refs(&mut reranked)?;
        Ok((candidate_keys, reranked))
    }

    async fn build_neighbor_family_context(
        &self,
        seed_binary_metas: &[crate::engine::BinaryMeta],
    ) -> io::Result<NeighborFamilyContext> {
        let mut ctx = NeighborFamilyContext::default();
        if seed_binary_metas.is_empty() {
            return Ok(ctx);
        }

        let max_obs = seed_binary_metas
            .iter()
            .map(|meta| meta.obs_count.max(1) as f64)
            .fold(1.0f64, f64::max);
        let obs_denom = max_obs.ln_1p().max(1.0);

        for (seed_rank, meta) in seed_binary_metas.iter().take(4).enumerate() {
            let rank_decay = 1.0 / (1.0 + (seed_rank as f64 * 0.22));
            let obs_norm = ((meta.obs_count.max(1) as f64).ln_1p() / obs_denom).clamp(0.35, 1.0);
            let direct_weight = ((0.45 + (0.55 * obs_norm)) * rank_decay).clamp(0.0, 1.0);
            let direct_entry = ctx.direct_weights.entry(meta.md5).or_insert(0.0);
            *direct_entry = direct_entry.max(direct_weight);

            let overlap_rows: Vec<([u8; 16], u64)> =
                if let Some(cached) = self.rt.ctx_index.get_binary_overlap_cache(&meta.md5)? {
                    cached
                        .into_iter()
                        .take(12)
                        .map(|entry| (entry.md5, entry.shared_functions))
                        .collect()
                } else {
                    self.get_binary_overlap(meta.md5, 12)
                        .await?
                        .into_iter()
                        .filter_map(|(summary, shared)| {
                            parse_md5_hex_local(&summary.md5_hex).map(|md5| (md5, shared))
                        })
                        .collect()
                };

            let max_shared = overlap_rows
                .iter()
                .map(|(_, shared)| *shared as f64)
                .fold(1.0f64, f64::max);
            for (overlap_rank, (other_md5, shared)) in overlap_rows.into_iter().enumerate() {
                if other_md5 == meta.md5 {
                    continue;
                }
                let shared_norm = ((shared as f64) / max_shared).clamp(0.0, 1.0);
                let overlap_decay = 1.0 / (1.0 + (overlap_rank as f64 * 0.18));
                let related_weight =
                    (direct_weight * (0.25 + (0.75 * shared_norm)) * overlap_decay * 0.9)
                        .clamp(0.0, 1.0);
                let related_entry = ctx.related_weights.entry(other_md5).or_insert(0.0);
                *related_entry = related_entry.max(related_weight);
            }
        }

        let mut family_ids: Vec<_> = ctx
            .direct_weights
            .keys()
            .chain(ctx.related_weights.keys())
            .copied()
            .collect();
        family_ids.sort_unstable();
        family_ids.dedup();
        for md5 in family_ids {
            if let Some(meta) = self.rt.ctx_index.get_binary_meta(&md5)? {
                ctx.binary_metas.push(meta);
            }
        }
        // Keep rationale examples deterministic and put the strongest supporting
        // member first before each category is truncated for presentation.
        let weight = |md5: &[u8; 16]| {
            ctx.direct_weights
                .get(md5)
                .or_else(|| ctx.related_weights.get(md5))
                .copied()
                .unwrap_or(0.0)
        };
        ctx.binary_metas.sort_by(|a, b| {
            weight(&b.md5)
                .total_cmp(&weight(&a.md5))
                .then_with(|| a.md5.cmp(&b.md5))
        });
        Ok(ctx)
    }

    pub async fn get_popular_functions(&self, limit: usize) -> io::Result<Vec<(u128, FuncLatest)>> {
        let top_keys = self.rt.ctx_index.get_top_popular_keys(limit)?;
        let mut results = Vec::with_capacity(top_keys.len());

        for (key, pop) in top_keys {
            if let Ok(Some(mut func)) = self.get_latest(key).await {
                // Overwrite the segment popularity with the live context popularity
                func.popularity = pop;
                results.push((key, func));
            }
        }

        Ok(results)
    }

    /// Remember that these stored versions were served verbatim, so a client
    /// that keeps the name and pushes it back is recognised as an echo.
    pub async fn note_served(&self, entries: Vec<(u128, [u8; 32])>) -> io::Result<()> {
        if entries.is_empty() || !self.rt.scoring.served_log {
            return Ok(());
        }
        let rt = self.rt.clone();
        tokio::task::spawn_blocking(move || rt.ctx_index.note_served(&entries, now_ts_sec()))
            .await
            .map_err(|e| io::Error::other(format!("spawn_blocking: {}", e)))?
    }

    /// Lumina pull frequencies: returns the counters as they were **before** this
    /// call (the reference reads the row, then increments), and bumps each key by
    /// its number of occurrences in `keys` unless `bump` is false
    /// (`PULL_MD_SEEN_FILE`). The Lumina handler passes each key once per
    /// request, so a pattern answered at several positions counts as one pull.
    pub async fn note_pull_hits(&self, keys: &[u128], bump: bool) -> io::Result<Vec<u32>> {
        let rt = self.rt.clone();
        let keys = keys.to_vec();
        tokio::task::spawn_blocking(move || {
            let before = rt.ctx_index.get_pull_frequencies(&keys)?;
            if bump {
                rt.ctx_index.bump_pull_frequencies(&keys)?;
            }
            Ok(before)
        })
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking: {}", e)))?
    }

    /// Lumina `del_history` with `BOPF_LAST_FUNC_RECORD`: undo the most recent
    /// change of each key. When an older version exists it becomes visible again
    /// (a copy is appended as the new head); otherwise the key is tombstoned.
    /// Returns the number of keys that had a live head.
    pub async fn revert_last_versions(&self, keys: &[u128]) -> io::Result<u32> {
        let rt = self.rt.clone();
        let keys = keys.to_vec();
        tokio::task::spawn_blocking(move || Self::revert_last_versions_sync(&rt, &keys))
            .await
            .map_err(|e| io::Error::other(format!("spawn_blocking: {}", e)))?
    }

    fn revert_last_versions_sync(rt: &EngineRuntime, keys: &[u128]) -> io::Result<u32> {
        Self::require_current_projection(rt)?;
        let mut reverted = 0u32;
        let mut search_docs_removed = 0u64;
        for &key in keys {
            let _mutation = rt.mutations.lock(key);
            let _facets = rt.ctx_index.facets.begin_mutation(Some(key), None);
            let head_addr = rt.index.get(key);
            if head_addr == 0 {
                continue;
            }
            let head = match rt.segments.read_record(head_addr) {
                Ok(rec) if rec.key == key && rec.flags & REC_FLAG_DELETED == 0 => rec,
                _ => continue,
            };
            // Find the closest older live version.
            let mut prev_addr = head.prev_addr;
            let mut previous = None;
            let mut seen = std::collections::HashSet::new();
            while prev_addr != 0 && seen.insert(prev_addr) {
                if seen.len() > crate::engine::MAX_HISTORY_RECORDS {
                    break;
                }
                match rt.segments.read_record(prev_addr) {
                    Ok(rec) if rec.key == key => {
                        if rec.flags & REC_FLAG_DELETED != 0 {
                            break;
                        }
                        if !is_rejected_function_name_with(rt.cfg.name_rejection, &rec.name) {
                            previous = Some(rec);
                            break;
                        }
                        prev_addr = rec.prev_addr;
                    }
                    _ => break,
                }
            }
            // The restored copy links past both the undone head and the original
            // of the restored version, so a second undo does not bring the undone
            // version back (the reference deletes the history row outright).
            let new_rec = match previous {
                Some(prev) => Record {
                    key,
                    ts_sec: now_ts_sec(),
                    prev_addr: prev.prev_addr,
                    len_bytes: prev.len_bytes,
                    popularity: prev.popularity,
                    name: prev.name,
                    data: prev.data,
                    flags: prev.flags & !REC_FLAG_DELETED,
                },
                None => Record {
                    key,
                    ts_sec: now_ts_sec(),
                    prev_addr: head_addr,
                    len_bytes: 0,
                    popularity: 0,
                    name: String::new(),
                    data: Vec::new(),
                    flags: REC_FLAG_DELETED,
                },
            };
            let is_tombstone = new_rec.flags & REC_FLAG_DELETED != 0;
            let addr = rt.segments.append(&new_rec)?;
            METRICS.inc_total_records();
            METRICS.add_storage_bytes(new_rec.encoded_len());
            match rt.index.upsert(key, addr) {
                Ok(_) => {}
                Err(IndexError::Full) => {
                    METRICS.inc_append_failures();
                    return Err(io::Error::other("index full"));
                }
                Err(IndexError::Io(e)) => {
                    METRICS.inc_append_failures();
                    return Err(io::Error::other(format!("index io error: {}", e)));
                }
            }
            reverted += 1;
            if is_tombstone {
                if rt.search.delete(key).is_ok() {
                    search_docs_removed += 1;
                }
            } else if let Some((canonical, _, _)) = Self::refresh_canonical_for_key(rt, key)? {
                Self::update_search_entry_no_commit_static(
                    rt,
                    key,
                    &canonical.name,
                    &canonical.data,
                    canonical.ts_sec,
                );
            } else {
                Self::update_search_entry_no_commit_static(
                    rt,
                    key,
                    &new_rec.name,
                    &new_rec.data,
                    new_rec.ts_sec,
                );
            }
        }
        if let Err(e) = rt.search.commit() {
            log::warn!("failed to commit search index after revert: {}", e);
        }
        if search_docs_removed != 0 {
            METRICS.sub_search_docs(search_docs_removed);
        }
        Ok(reverted)
    }

    /// `(input path, hostname, input md5)` of the first binary a key was observed
    /// in, for `get_pop_result.pop_fun_t`.
    pub fn get_pop_provenance(&self, key: u128) -> Option<(String, String, [u8; 16])> {
        self.rt
            .ctx_index
            .get_binary_refs_for_key(key, 1)
            .ok()?
            .into_iter()
            .next()
            .map(|meta| (meta.basename, meta.hostname, meta.md5))
    }

    /// Get binary basenames associated with a function key.
    pub fn get_basenames_for_key(&self, key: u128) -> io::Result<Vec<String>> {
        Ok(self
            .rt
            .ctx_index
            .resolve_basenames_for_key(key)?
            .into_iter()
            .map(|name| basename_only(&name))
            .collect())
    }

    /// Get structured binary references associated with a function key.
    pub fn get_binary_refs_for_key(
        &self,
        key: u128,
        limit: usize,
    ) -> io::Result<Vec<BinaryRefHit>> {
        Ok(self
            .rt
            .ctx_index
            .get_binary_refs_for_key(key, limit)?
            .into_iter()
            .map(|meta| BinaryRefHit {
                md5_hex: hex_md5(&meta.md5),
                short_id: short_md5(&meta.md5),
                basename: basename_only(&meta.basename),
                display_name: format!(
                    "{} · {}",
                    basename_only(&meta.basename),
                    short_md5(&meta.md5)
                ),
            })
            .collect())
    }

    pub async fn search_binaries_paginated(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<BinarySummary>, usize)> {
        if query.trim().is_empty() {
            return Ok((Vec::new(), 0));
        }

        let mut matches: Vec<_> = self
            .rt
            .ctx_index
            .search_binary_meta_ranked(query)?
            .into_iter()
            .map(|(meta, alias_score)| {
                let score = score_binary_meta(&meta, alias_score);
                (meta, score)
            })
            .collect();
        matches.sort_by(|(a, a_score), (b, b_score)| {
            b_score
                .total_cmp(a_score)
                .then_with(|| b.last_seen_ts.cmp(&a.last_seen_ts))
                .then_with(|| a.md5.cmp(&b.md5))
        });
        let total = matches.len();
        let mut rows = Vec::new();
        for (meta, score) in matches.into_iter().skip(offset).take(limit) {
            let mut summary = binary_summary_from_meta(&meta, score);
            if let Some(facets) = self.rt.ctx_index.get_binary_facets(&meta.md5)? {
                summary.apply_facets(facets);
            }
            rows.push(summary);
        }
        Ok((rows, total))
    }

    pub async fn get_binary_summary(&self, md5: [u8; 16]) -> io::Result<Option<BinarySummary>> {
        match self.rt.ctx_index.get_binary_meta(&md5)? {
            Some(meta) => Ok(Some(self.build_binary_summary(meta, 0.0).await?)),
            None => Ok(None),
        }
    }

    pub async fn get_binary_function_hits(
        &self,
        md5: [u8; 16],
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        let (entries, total) = self
            .rt
            .ctx_index
            .get_binary_function_entries(&md5, offset, limit)?;
        let mut entries = entries;
        entries.sort_by(|a, b| {
            b.obs_count
                .cmp(&a.obs_count)
                .then_with(|| b.last_ts_sec.cmp(&a.last_ts_sec))
        });
        // Each row resolves its own annotation, which is the expensive part of
        // a page; the rows are independent, so they resolve side by side.
        let runtime = tokio::runtime::Handle::try_current().ok();
        let hits: Vec<SearchHit> = map_chunks_offthread(&entries, PAGE_RESOLVE_CHUNK, |chunk| {
            let mut local = Vec::with_capacity(chunk.len());
            for entry in chunk {
                let resolved = match &runtime {
                    Some(handle) => {
                        handle.block_on(self.get_function_in_context(entry.key, Some(md5)))?
                    }
                    None => tokio::runtime::Builder::new_current_thread()
                        .build()?
                        .block_on(self.get_function_in_context(entry.key, Some(md5)))?,
                };
                let Some(func) = resolved else {
                    continue;
                };
                let demangle_result = demangle(&func.name);
                let (func_name_demangled, lang) = if demangle_result.demangled {
                    (
                        Some(demangle_result.name),
                        demangle_result.lang.map(|s| s.to_string()),
                    )
                } else {
                    (None, None)
                };
                local.push(SearchHit {
                    key_hex: format!("{:032x}", entry.key),
                    func_name: func.name,
                    func_name_demangled,
                    lang,
                    binary_names: self.get_basenames_for_key(entry.key).unwrap_or_default(),
                    binaries: self
                        .get_binary_refs_for_key(entry.key, 12)
                        .unwrap_or_default(),
                    semantic_neighbor: None,
                    ts: func.ts_sec,
                    score: entry.obs_count as f32,
                });
            }
            Ok(local)
        })?
        .concat();
        Ok((hits, total))
    }

    /// Keys of a binary examined when deriving overlap; a larger binary is
    /// sampled by this bounded prefix, so overlap counts read as estimates.
    pub const OVERLAP_PROBE_KEYS: usize = BINARY_OVERLAP_PROBE_KEYS;

    /// Shared functions and observations between `md5` and every binary that
    /// carries one of its keys, ranked and cached for the views built on it.
    ///
    /// This is the one scan behind overlap, related binaries, the graph and the
    /// family timeline: each key is read once, and the postings of a key are
    /// aggregated in a single pass instead of being probed per neighbour.
    fn binary_overlap_rows(&self, md5: [u8; 16]) -> io::Result<Vec<BinaryOverlapEntry>> {
        if let Some(cached) = self.rt.ctx_index.get_binary_overlap_cache(&md5)? {
            return Ok(cached);
        }
        let listing = std::time::Instant::now();
        let seed_keys = self
            .rt
            .ctx_index
            .get_binary_function_keys(&md5, BINARY_OVERLAP_PROBE_KEYS)?;
        let listed = listing.elapsed();
        let aggregating = std::time::Instant::now();
        // Keys are independent point reads, so the scan is spread over threads
        // and the per-thread tallies are merged.
        let partials = map_chunks(&seed_keys, OVERLAP_SCAN_CHUNK, |chunk| {
            let mut local: HashMap<[u8; 16], (u64, u64)> = HashMap::new();
            for &key in chunk {
                let Some(stats) = self.rt.ctx_index.get_positive_key_md5_stats(key, &md5)? else {
                    continue;
                };
                let seed_obs = u64::from(stats.obs_count);
                if seed_obs == 0 {
                    continue;
                }
                self.rt
                    .ctx_index
                    .for_each_key_observation(key, |other_md5, count| {
                        if other_md5 == md5 {
                            return;
                        }
                        let entry = local.entry(other_md5).or_insert((0, 0));
                        entry.0 = entry.0.saturating_add(1);
                        entry.1 = entry.1.saturating_add(seed_obs.min(u64::from(count)));
                    })?;
            }
            Ok(local)
        })?;
        debug!(
            "binary overlap scan: {} keys listed in {:?}, aggregated in {:?}",
            seed_keys.len(),
            listed,
            aggregating.elapsed()
        );
        let mut merged: HashMap<[u8; 16], (u64, u64)> = HashMap::new();
        for partial in partials {
            for (other_md5, (functions, observations)) in partial {
                let entry = merged.entry(other_md5).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(functions);
                entry.1 = entry.1.saturating_add(observations);
            }
        }
        let mut rows: Vec<BinaryOverlapEntry> = merged
            .into_iter()
            .map(
                |(md5, (shared_functions, shared_observations))| BinaryOverlapEntry {
                    md5,
                    shared_functions,
                    shared_observations,
                },
            )
            .collect();
        rows.sort_by(|a, b| {
            b.shared_functions
                .cmp(&a.shared_functions)
                .then_with(|| b.shared_observations.cmp(&a.shared_observations))
                .then_with(|| a.md5.cmp(&b.md5))
        });
        // Readers rank by either measure, so keep the leaders of both before
        // the cache bound drops the tail.
        if rows.len() > MAX_BINARY_OVERLAP_ROWS {
            let keep = MAX_BINARY_OVERLAP_ROWS / 2;
            let mut by_observations: Vec<BinaryOverlapEntry> = rows.clone();
            by_observations.sort_by(|a, b| {
                b.shared_observations
                    .cmp(&a.shared_observations)
                    .then_with(|| a.md5.cmp(&b.md5))
            });
            let mut kept: HashSet<[u8; 16]> = rows.iter().take(keep).map(|row| row.md5).collect();
            kept.extend(by_observations.iter().take(keep).map(|row| row.md5));
            rows.retain(|row| kept.contains(&row.md5));
        }
        let _ = self.rt.ctx_index.set_binary_overlap_cache(&md5, &rows);
        Ok(rows)
    }

    /// Resolve cached overlap rows into summaries, dropping forgotten binaries.
    fn overlap_summaries(
        &self,
        rows: impl IntoIterator<Item = BinaryOverlapEntry>,
        limit: usize,
    ) -> io::Result<Vec<(BinarySummary, u64, u64)>> {
        let mut out = Vec::new();
        for entry in rows {
            if out.len() >= limit {
                break;
            }
            if let Some(meta) = self.rt.ctx_index.get_binary_meta(&entry.md5)? {
                out.push((
                    binary_summary_from_meta(&meta, entry.shared_functions as f32),
                    entry.shared_functions,
                    entry.shared_observations,
                ));
            }
        }
        Ok(out)
    }

    /// Build the neighbourhood aggregate for `md5` if it is not cached yet.
    ///
    /// Views that share the aggregate can then read it without each paying for
    /// the scan, or racing to repeat it.
    pub async fn warm_binary_neighbourhood(&self, md5: [u8; 16]) -> io::Result<()> {
        self.binary_overlap_rows(md5)?;
        Ok(())
    }

    pub async fn get_binary_overlap(
        &self,
        md5: [u8; 16],
        limit: usize,
    ) -> io::Result<Vec<(BinarySummary, u64)>> {
        let rows = self.binary_overlap_rows(md5)?;
        Ok(self
            .overlap_summaries(rows, limit)?
            .into_iter()
            .map(|(summary, shared_functions, _)| (summary, shared_functions))
            .collect())
    }

    pub async fn get_binary_related(
        &self,
        md5: [u8; 16],
        limit: usize,
    ) -> io::Result<Vec<(BinarySummary, u64, u64, f32, f32)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let seed_meta = match self.rt.ctx_index.get_binary_meta(&md5)? {
            Some(meta) => meta,
            None => return Ok(Vec::new()),
        };
        let mut rows = self.binary_overlap_rows(md5)?;
        // Ranked by agreeing observations: repeated evidence outweighs a long
        // tail of once-seen functions.
        rows.sort_by(|a, b| {
            b.shared_observations
                .cmp(&a.shared_observations)
                .then_with(|| b.shared_functions.cmp(&a.shared_functions))
                .then_with(|| a.md5.cmp(&b.md5))
        });
        let mut metas = Vec::with_capacity(limit);
        for entry in rows {
            if metas.len() >= limit {
                break;
            }
            if let Some(meta) = self.rt.ctx_index.get_binary_meta(&entry.md5)? {
                metas.push((meta, entry.shared_functions, entry.shared_observations));
            }
        }
        metas.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| b.0.last_seen_ts.cmp(&a.0.last_seen_ts))
                .then_with(|| a.0.md5.cmp(&b.0.md5))
        });
        // Coverage requires contextual selection for up to 8192 functions per
        // binary. It does not affect ranking: only analyze retained rows, and
        // analyze them side by side, since each row is a scan of its own.
        let runtime = tokio::runtime::Handle::try_current().ok();
        let out = map_chunks_offthread(&metas, 1, |chunk| {
            let mut local = Vec::with_capacity(chunk.len());
            for (meta, shared_functions, shared_observations) in chunk {
                let known_den = seed_meta.function_count.min(meta.function_count).max(1);
                let obs_den = seed_meta.obs_count.min(meta.obs_count).max(1);
                let summary = match &runtime {
                    Some(handle) => {
                        handle.block_on(self.build_binary_summary(meta.clone(), 0.0))?
                    }
                    None => tokio::runtime::Builder::new_current_thread()
                        .build()?
                        .block_on(self.build_binary_summary(meta.clone(), 0.0))?,
                };
                local.push((
                    summary,
                    *shared_functions,
                    *shared_observations,
                    (*shared_functions as f32 / known_den as f32) * 100.0,
                    (*shared_observations as f32 / obs_den as f32) * 100.0,
                ));
            }
            Ok(local)
        })?
        .concat();
        Ok(out)
    }

    /// Coverage inputs for a key whose stored head is not the observed variant.
    ///
    /// Returns the selected annotation and whether it differs from what this
    /// binary last observed.
    async fn selected_facet_row(
        &self,
        key: u128,
        md5: [u8; 16],
    ) -> io::Result<Option<(String, Vec<u8>, bool)>> {
        let Some(func) = self.select_binary_variant(key, md5).await? else {
            return Ok(None);
        };
        let observed = self.rt.ctx_index.get_positive_key_md5_stats(key, &md5)?;
        let fallback = func.used_synthesis
            || !observed.is_some_and(|stats| func.matches_version(&stats.last_version_id));
        Ok(Some((func.name, func.data, fallback)))
    }

    pub async fn get_binary_facets(
        &self,
        md5: [u8; 16],
        limit: usize,
    ) -> io::Result<BinaryFacetSummary> {
        let limit = limit.min(crate::engine::facet_cache::MAX_FACET_KEYS);
        if let Some(cached) = self.rt.ctx_index.facets.get(&md5, Some(limit)) {
            return Ok(cached);
        }
        let token = self.rt.ctx_index.facets.read_token();
        let mut keys = self
            .rt
            .ctx_index
            .get_binary_function_keys(&md5, limit + 1)?;
        let truncated = keys.len() > limit;
        keys.truncate(limit);
        let mut out = BinaryFacetSummary {
            function_count: keys.len() as u64,
            key_limit: limit,
            truncated,
            ..BinaryFacetSummary::default()
        };
        // A key whose physical head matches its positive observation is already
        // the unique eligible variant, and reading it is pure storage work, so
        // that pass runs over threads. Only the keys it cannot answer need the
        // selector, and those are resolved afterwards, in async context: a
        // scan worker must never drive the runtime it may be running under.
        let (tallies, deferred): (Vec<_>, Vec<_>) = map_chunks(&keys, FACET_SCAN_CHUNK, |chunk| {
            let mut tally = BinaryFacetSummary::default();
            let mut deferred = Vec::new();
            for &key in chunk {
                let observed = self.rt.ctx_index.get_positive_key_md5_stats(key, &md5)?;
                // Coverage needs the record's raw data, not ranking
                // diagnostics or an additional semantic analysis pass.
                // Bound this probe to one physical record, including
                // rejected heads.
                let exact_head = match observed.filter(|stats| stats.last_version_id != [0; 32]) {
                    Some(stats) if self.rt.scoring.max_versions_per_key != 0 => {
                        Self::exact_observed_head(&self.rt, key, &stats.last_version_id)?
                    }
                    _ => None,
                };
                match exact_head {
                    Some(rec) => tally_facet_row(&mut tally, &rec.name, &rec.data, false),
                    None => deferred.push(key),
                }
            }
            Ok((tally, deferred))
        })?
        .into_iter()
        .unzip();
        for tally in tallies {
            out.unavailable_functions += tally.unavailable_functions;
            out.fallback_functions += tally.fallback_functions;
            out.typed_functions += tally.typed_functions;
            out.framed_functions += tally.framed_functions;
            out.commented_functions += tally.commented_functions;
            out.parse_partial_functions += tally.parse_partial_functions;
            out.switch_functions += tally.switch_functions;
            out.demangled_functions += tally.demangled_functions;
        }
        let deferred = deferred.concat();
        let runtime = tokio::runtime::Handle::try_current().ok();
        let resolved = match runtime {
            // A scan worker may already be driving this call from inside the
            // runtime, and blocking there again would panic.
            Some(handle) if !in_scan_worker() => {
                map_chunks_offthread(&deferred, FACET_SELECT_CHUNK, |chunk| {
                    let mut rows = Vec::with_capacity(chunk.len());
                    for &key in chunk {
                        rows.push(handle.block_on(self.selected_facet_row(key, md5))?);
                    }
                    Ok(rows)
                })?
                .concat()
            }
            _ => {
                let mut rows = Vec::with_capacity(deferred.len());
                for &key in &deferred {
                    rows.push(self.selected_facet_row(key, md5).await?);
                }
                rows
            }
        };
        let mut uses_completed_context = false;
        for row in resolved {
            let Some((name, data, fallback)) = row else {
                out.unavailable_functions += 1;
                continue;
            };
            // A stale positive pointer can also require companion identities.
            // Conservatively track completion dependencies for every fallback.
            uses_completed_context |= fallback;
            tally_facet_row(&mut out, &name, &data, fallback);
        }
        out.cached_at_ts = now_ts_sec();
        if uses_completed_context {
            // Completion may use keys beyond a small coverage limit. Include
            // every inspected row (also current placeholders) as a dependency:
            // a later positive observation can change donor-family inference.
            keys.extend(
                self.rt
                    .ctx_index
                    .get_binary_function_keys(&md5, MAX_BINARY_CONTEXT_KEYS)?,
            );
            keys.sort_unstable();
            keys.dedup();
        }
        self.rt
            .ctx_index
            .facets
            .publish(md5, limit, token, keys, out.clone());
        Ok(out)
    }

    /// Expand the overlap neighbourhood around `md5` into a node/edge graph.
    ///
    /// Returns `(nodes, edges)` where each node carries its BFS depth from the
    /// seed and whether its own neighbourhood was expanded. Expanding a binary
    /// whose overlap cache is cold scans its whole key prefix, so past the seed
    /// only warm neighbours are expanded plus a small cold budget; everything
    /// else is reported unexpanded so callers can expand it on demand.
    pub async fn get_binary_graph(
        &self,
        md5: [u8; 16],
        depth: usize,
        limit: usize,
    ) -> io::Result<(Vec<(BinarySummary, u32, bool)>, Vec<(String, String, u64)>)> {
        const MAX_GRAPH_NODES: usize = 64;
        const COLD_EXPANSION_BUDGET: usize = 2;
        let depth = depth.clamp(1, 3);
        let limit = limit.clamp(1, 24);
        let Some(seed) = self.get_binary_summary(md5).await? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut seed = seed;
        if let Some(facets) = self.rt.ctx_index.get_binary_facets(&md5)? {
            seed.apply_facets(facets);
        }
        let seed_hex = seed.md5_hex.clone();
        let mut nodes: Vec<(BinarySummary, u32, bool)> = vec![(seed, 0, false)];
        let mut node_index: HashMap<String, usize> = HashMap::from([(seed_hex.clone(), 0usize)]);
        let mut edge_seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        let mut edges = Vec::new();
        let mut frontier = vec![(md5, seed_hex)];
        let mut cold_budget = COLD_EXPANSION_BUDGET;
        for level in 0..depth as u32 {
            let mut next = Vec::new();
            // Decide what this level expands before reading it, so the reads
            // can run together while the budget stays deterministic.
            let mut expanding = Vec::with_capacity(frontier.len());
            for (node_md5, node_hex) in frontier {
                if level > 0
                    && self
                        .rt
                        .ctx_index
                        .get_binary_overlap_cache(&node_md5)?
                        .is_none()
                {
                    if cold_budget == 0 {
                        continue;
                    }
                    cold_budget -= 1;
                }
                expanding.push((node_md5, node_hex));
            }
            let expanded: Vec<Vec<(BinarySummary, u64)>> = map_chunks(&expanding, 1, |chunk| {
                let mut local: Vec<Vec<(BinarySummary, u64)>> = Vec::with_capacity(chunk.len());
                for (node_md5, _) in chunk {
                    let rows = self.binary_overlap_rows(*node_md5)?;
                    local.push(
                        self.overlap_summaries(rows, limit)?
                            .into_iter()
                            .map(|(summary, shared, _)| (summary, shared))
                            .collect(),
                    );
                }
                Ok(local)
            })?
            .concat();
            for ((_, node_hex), neighbors) in expanding.into_iter().zip(expanded) {
                if let Some(&idx) = node_index.get(&node_hex) {
                    nodes[idx].2 = true;
                }
                for (neighbor, shared) in neighbors {
                    let neighbor_hex = neighbor.md5_hex.clone();
                    let pair = if node_hex <= neighbor_hex {
                        (node_hex.clone(), neighbor_hex.clone())
                    } else {
                        (neighbor_hex.clone(), node_hex.clone())
                    };
                    if edge_seen.insert(pair) {
                        edges.push((node_hex.clone(), neighbor_hex.clone(), shared));
                    }
                    if node_index.contains_key(&neighbor_hex) || nodes.len() >= MAX_GRAPH_NODES {
                        continue;
                    }
                    let Some(neighbor_md5) = parse_md5_hex_local(&neighbor_hex) else {
                        continue;
                    };
                    let mut neighbor = neighbor;
                    if let Some(facets) = self.rt.ctx_index.get_binary_facets(&neighbor_md5)? {
                        neighbor.apply_facets(facets);
                    }
                    node_index.insert(neighbor_hex.clone(), nodes.len());
                    nodes.push((neighbor, level + 1, false));
                    next.push((neighbor_md5, neighbor_hex));
                }
            }
            frontier = next;
            if frontier.is_empty() || nodes.len() >= MAX_GRAPH_NODES {
                break;
            }
        }
        // Edges discovered from an expanded node can point at binaries that the
        // node budget rejected. Drop them so every edge has both endpoints.
        edges.retain(|(source, target, _)| {
            node_index.contains_key(source) && node_index.contains_key(target)
        });
        Ok((nodes, edges))
    }

    /// Evidence for what code `left` and `right` have in common.
    ///
    /// Scans a bounded prefix of `left`'s keys for membership in `right`, then
    /// spends its remaining budget on the rarest shared keys: a symbol carried
    /// by few binaries identifies a shared component, while a ubiquitous one
    /// only says both binaries link the same runtime.
    pub async fn shared_code_profile(
        &self,
        left: [u8; 16],
        right: [u8; 16],
        sample_limit: usize,
    ) -> io::Result<SharedCodeProfile> {
        const SCORE_KEYS: usize = 768;
        const NAME_KEYS: usize = 288;
        const SELECTION_FALLBACKS: usize = 64;
        const BINARY_CAP: usize = 64;
        const MAX_COMPONENTS: usize = 8;
        let sample_limit = sample_limit.clamp(1, 60);
        let mut keys = self
            .rt
            .ctx_index
            .get_binary_function_keys(&left, BINARY_OVERLAP_PROBE_KEYS + 1)?;
        let truncated = keys.len() > BINARY_OVERLAP_PROBE_KEYS;
        keys.truncate(BINARY_OVERLAP_PROBE_KEYS);
        let mut profile = SharedCodeProfile {
            probed_keys: keys.len(),
            probe_limit: BINARY_OVERLAP_PROBE_KEYS,
            truncated,
            binary_count_cap: BINARY_CAP,
            ..SharedCodeProfile::default()
        };
        if left == right {
            return Ok(profile);
        }
        let shared: Vec<u128> = map_chunks(&keys, OVERLAP_SCAN_CHUNK, |chunk| {
            let mut local = Vec::new();
            for &key in chunk {
                if self.rt.ctx_index.binary_contains_function(&right, key)? {
                    local.push(key);
                }
            }
            Ok(local)
        })?
        .concat();
        profile.shared_keys = shared.len();
        if shared.is_empty() {
            return Ok(profile);
        }
        // Rarity ranks the budget: the scan stops at a cap, so a popular symbol
        // reports the cap rather than its true breadth.
        let candidates = &shared[..shared.len().min(SCORE_KEYS)];
        let mut scored: Vec<(usize, bool, u128)> =
            map_chunks(candidates, OVERLAP_SCAN_CHUNK, |chunk| {
                let mut local = Vec::with_capacity(chunk.len());
                for &key in chunk {
                    let (count, capped) = self.rt.ctx_index.count_key_binaries(key, BINARY_CAP)?;
                    local.push((count, capped, key));
                }
                Ok(local)
            })?
            .concat();
        scored.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));
        profile.scored_keys = scored.len();

        // Component naming prefers the observed head, a single record read; a
        // key whose head moved on falls back to full selection under a budget,
        // so a wide sample stays affordable without inventing names.
        let mut token_functions: HashMap<String, Vec<usize>> = HashMap::new();
        let mut selection_budget = SELECTION_FALLBACKS;
        for &(count, _, key) in scored.iter().take(NAME_KEYS) {
            let observed = self
                .rt
                .ctx_index
                .get_positive_key_md5_stats(key, &left)?
                .filter(|stats| stats.last_version_id != [0; 32]);
            let head = match observed {
                Some(stats) => Self::exact_observed_head(&self.rt, key, &stats.last_version_id)?
                    .map(|r| r.name),
                None => None,
            };
            let name = match head {
                Some(name) => Some(name),
                None if selection_budget > 0 => {
                    selection_budget -= 1;
                    self.select_binary_variant(key, left)
                        .await?
                        .map(|selected| selected.name)
                }
                None => None,
            };
            let Some(name) = name else {
                continue;
            };
            profile.named_keys += 1;
            if let Some(token) = component_token(&name) {
                token_functions.entry(token).or_default().push(count);
            }
        }
        let mut components: Vec<SharedComponent> = token_functions
            .into_iter()
            .map(|(token, mut counts)| {
                counts.sort_unstable();
                SharedComponent {
                    functions: counts.len(),
                    median_binary_count: counts[counts.len() / 2],
                    token,
                }
            })
            .collect();
        components.sort_by(|a, b| {
            b.functions
                .cmp(&a.functions)
                .then_with(|| a.median_binary_count.cmp(&b.median_binary_count))
                .then_with(|| a.token.cmp(&b.token))
        });
        components.truncate(MAX_COMPONENTS);
        profile.components = components;

        for &(count, capped, key) in scored.iter().take(sample_limit) {
            let Some(selected) = self.select_binary_variant(key, left).await? else {
                continue;
            };
            let demangled = demangle(&selected.name);
            profile.samples.push(SharedFunctionSample {
                key_hex: format!("{key:032x}"),
                name: selected.name,
                name_demangled: demangled.demangled.then_some(demangled.name),
                binary_count: count,
                binary_count_capped: capped,
            });
        }
        Ok(profile)
    }

    pub async fn get_binary_family_timeline(
        &self,
        md5: [u8; 16],
        limit: usize,
    ) -> io::Result<Vec<(BinarySummary, u64, u64, f32, f32, bool)>> {
        let mut out = Vec::new();
        let seed_summary = self.get_binary_summary(md5).await?;
        if let Some(mut root) = seed_summary.clone() {
            if let Some(facets) = self.rt.ctx_index.get_binary_facets(&md5)? {
                root.apply_facets(facets);
            }
            out.push((root, 0, 0, 0.0, 0.0, true));
        }
        // Shared observations come from the same aggregate as the row itself,
        // so a neighbour costs no further probe of the seed's keys.
        let overlaps = self.overlap_summaries(self.binary_overlap_rows(md5)?, limit)?;
        for (mut summary, shared, shared_observations) in overlaps {
            if let Some(other_md5) = parse_md5_hex_local(&summary.md5_hex) {
                if let Some(facets) = self.rt.ctx_index.get_binary_facets(&other_md5)? {
                    summary.apply_facets(facets);
                }
            }
            let (known_pct, observed_pct) = if let Some(seed) = &seed_summary {
                let known_den = seed.function_count.min(summary.function_count).max(1);
                let obs_den = seed.obs_count.min(summary.obs_count).max(1);
                (
                    (shared as f32 / known_den as f32) * 100.0,
                    (shared_observations as f32 / obs_den as f32) * 100.0,
                )
            } else {
                (0.0, 0.0)
            };
            out.push((
                summary,
                shared,
                shared_observations,
                known_pct,
                observed_pct,
                false,
            ));
        }
        out.sort_by(|a, b| {
            b.0.last_seen_ts
                .cmp(&a.0.last_seen_ts)
                .then_with(|| b.1.cmp(&a.1))
        });
        Ok(out)
    }

    pub async fn compare_binaries(
        &self,
        left: [u8; 16],
        right: [u8; 16],
        sample_limit: usize,
    ) -> io::Result<(
        BinaryFacetSummary,
        BinaryFacetSummary,
        usize,
        usize,
        usize,
        Vec<BinaryCompareItem>,
        Vec<BinaryCompareItem>,
        Vec<BinaryCompareItem>,
        Vec<BinaryCompareItem>,
        Vec<BinaryCompareItem>,
        Vec<BinaryCompareItem>,
        Vec<BinaryCompareItem>,
    )> {
        let left_keys = self.rt.ctx_index.get_binary_function_keys(&left, 8192)?;
        let right_keys = self.rt.ctx_index.get_binary_function_keys(&right, 8192)?;
        let mut left_set: HashSet<u128> = left_keys.iter().copied().collect();
        let mut right_set: HashSet<u128> = right_keys.iter().copied().collect();
        // A key missing from the bounded prefix can still belong to the other
        // binary. Probe its actual forward membership before classifying it;
        // the probes are independent point reads, so they run in parallel.
        let probe =
            |keys: &[u128], seen: &HashSet<u128>, other: [u8; 16]| -> io::Result<Vec<u128>> {
                Ok(map_chunks(keys, OVERLAP_SCAN_CHUNK, |chunk| {
                    let mut local = Vec::new();
                    for &key in chunk {
                        if !seen.contains(&key)
                            && self.rt.ctx_index.binary_contains_function(&other, key)?
                        {
                            local.push(key);
                        }
                    }
                    Ok(local)
                })?
                .concat())
            };
        right_set.extend(probe(&left_keys, &right_set, right)?);
        left_set.extend(probe(&right_keys, &left_set, left)?);
        let mut shared_keys: Vec<u128> = left_set.intersection(&right_set).copied().collect();
        let mut left_only_keys: Vec<u128> = left_set.difference(&right_set).copied().collect();
        let mut right_only_keys: Vec<u128> = right_set.difference(&left_set).copied().collect();
        let mut union_keys: Vec<u128> = left_set.union(&right_set).copied().collect();
        shared_keys.sort_unstable();
        left_only_keys.sort_unstable();
        right_only_keys.sort_unstable();
        union_keys.sort_unstable();
        let sample_limit = sample_limit.min(100);
        // Resolve each (key, side) once, even when it appears in several buckets.
        let mut needed: Vec<_> = union_keys.iter().take(sample_limit * 4).copied().collect();
        for keys in [&shared_keys, &left_only_keys, &right_only_keys] {
            needed.extend(keys.iter().take(sample_limit).copied());
        }
        needed.sort_unstable();
        needed.dedup();
        let mut rows = HashMap::with_capacity(needed.len());
        for key in needed {
            rows.insert(
                key,
                self.compare_key_variants(
                    key,
                    left_set.contains(&key).then_some(left),
                    right_set.contains(&key).then_some(right),
                )
                .await?,
            );
        }
        let bucket = |keys: &[u128]| {
            let mut items: Vec<_> = keys
                .iter()
                .take(sample_limit)
                .filter_map(|key| rows.get(key).cloned())
                .collect();
            sort_compare_items(&mut items);
            items
        };
        let shared = bucket(&shared_keys);
        let left_only = bucket(&left_only_keys);
        let right_only = bucket(&right_only_keys);
        let mut union_items: Vec<_> = union_keys
            .iter()
            .take(sample_limit * 4)
            .filter_map(|key| rows.get(key).cloned())
            .collect();
        let mut by_recent = union_items.clone();
        by_recent.sort_by(|a, b| {
            compare_item_latest_ts(b)
                .cmp(&compare_item_latest_ts(a))
                .then_with(|| a.rarity_score.cmp(&b.rarity_score))
                .then_with(|| compare_item_richness(b).cmp(&compare_item_richness(a)))
                .then_with(|| a.key_hex.cmp(&b.key_hex))
        });
        let recent = by_recent.iter().take(sample_limit).cloned().collect();
        let freshest_drift = by_recent
            .iter()
            .filter(|item| {
                !item.left_member || !item.right_member || item.annotation_relation == "different"
            })
            .take(sample_limit)
            .cloned()
            .collect();
        union_items.sort_by(|a, b| {
            compare_item_richness(b)
                .cmp(&compare_item_richness(a))
                .then_with(|| a.rarity_score.cmp(&b.rarity_score))
                .then_with(|| compare_item_latest_ts(b).cmp(&compare_item_latest_ts(a)))
                .then_with(|| a.key_hex.cmp(&b.key_hex))
        });
        let metadata_rich = union_items.iter().take(sample_limit).cloned().collect();
        union_items.sort_by(|a, b| {
            a.rarity_score
                .cmp(&b.rarity_score)
                .then_with(|| compare_item_richness(b).cmp(&compare_item_richness(a)))
                .then_with(|| compare_item_latest_ts(b).cmp(&compare_item_latest_ts(a)))
                .then_with(|| a.key_hex.cmp(&b.key_hex))
        });
        let rare_symbols = union_items.into_iter().take(sample_limit).collect();
        let shared_count = left_set.intersection(&right_set).count();
        let left_only_count = left_set.difference(&right_set).count();
        let right_only_count = right_set.difference(&left_set).count();
        let left_facets = self.get_binary_facets(left, 8192).await?;
        let right_facets = self.get_binary_facets(right, 8192).await?;
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
        ))
    }

    async fn compare_key_variants(
        &self,
        key: u128,
        left: Option<[u8; 16]>,
        right: Option<[u8; 16]>,
    ) -> io::Result<BinaryCompareItem> {
        let left_selected = match left {
            Some(md5) => self.select_binary_variant(key, md5).await?,
            None => None,
        };
        let right_selected = if right == left {
            left_selected.clone()
        } else {
            match right {
                Some(md5) => self.select_binary_variant(key, md5).await?,
                None => None,
            }
        };
        let (agreement, changed_metadata_keys) = match (&left_selected, &right_selected) {
            (Some(a), Some(b)) => {
                super::evaluation::semantic_agreement(&a.name, &a.data, &b.name, &b.data)
            }
            _ => (None, Vec::new()),
        };
        let annotation_relation = match agreement {
            Some(true) => "same",
            Some(false) => "different",
            None if left_selected.is_some() && right_selected.is_some() => "unjudged",
            None => "unavailable",
        };
        let preferred = left_selected.as_ref().or(right_selected.as_ref());
        let summary = |md5: Option<[u8; 16]>,
                       selection: Option<&SelectedVariant>|
         -> io::Result<Option<BinaryCompareVariant>> {
            let Some((md5, selection)) = md5.zip(selection) else {
                return Ok(None);
            };
            let expected = self.rt.ctx_index.get_positive_key_md5_stats(key, &md5)?;
            Ok(Some(BinaryCompareVariant {
                name: selection.name.clone(),
                ts: selection.ts_sec,
                richness_score: metadata_richness(&selection.data),
                version_id: selection
                    .base_version_id
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                matches_last_observation: !selection.used_synthesis
                    && expected.is_some_and(|s| selection.matches_version(&s.last_version_id)),
                used_synthesis: selection.used_synthesis,
            }))
        };
        Ok(BinaryCompareItem {
            key_hex: format!("{key:032x}"),
            name: preferred.map_or_else(String::new, |s| s.name.clone()),
            ts: preferred.map_or(0, |s| s.ts_sec),
            rarity_score: self.get_binary_refs_for_key(key, 64)?.len(),
            richness_score: preferred.map_or(0, |s| metadata_richness(&s.data)),
            left: summary(left, left_selected.as_ref())?,
            right: summary(right, right_selected.as_ref())?,
            left_member: left.is_some(),
            right_member: right.is_some(),
            annotation_relation: annotation_relation.into(),
            changed_metadata_keys,
        })
    }

    fn attach_binary_refs(&self, hits: &mut [SearchHit]) -> io::Result<()> {
        for hit in hits.iter_mut() {
            let key = match u128::from_str_radix(&hit.key_hex, 16) {
                Ok(key) => key,
                Err(_) => continue,
            };
            let refs = self.get_binary_refs_for_key(key, 12)?;
            if !refs.is_empty() {
                hit.binary_names = refs.iter().map(|item| item.basename.clone()).collect();
                hit.binaries = refs;
            }
        }
        Ok(())
    }

    async fn build_binary_summary(
        &self,
        meta: crate::engine::BinaryMeta,
        score: f32,
    ) -> io::Result<BinarySummary> {
        let mut summary = binary_summary_from_meta(&meta, score);
        summary.apply_facets(self.get_binary_facets(meta.md5, 8192).await?);
        Ok(summary)
    }

    /// Select best versions for a batch of keys using semantic-aware scoring.
    pub async fn select_versions_for_batch(
        &self,
        ctx: &QueryContext<'_>,
    ) -> io::Result<Vec<Option<(u32, u32, String, Vec<u8>)>>> {
        Ok(self
            .select_batch(ctx, false, None, true)
            .await?
            .into_iter()
            .map(|(result, _)| {
                result.map(|selection| {
                    (
                        selection.popularity,
                        selection.func_size,
                        selection.name,
                        selection.data,
                    )
                })
            })
            .collect())
    }

    /// The same selector with donor and candidate diagnostics retained and
    /// no provenance gate: every resolvable name is returned for inspection.
    pub async fn select_variant_details(
        &self,
        ctx: &QueryContext<'_>,
    ) -> io::Result<Vec<Option<SelectedVariant>>> {
        Ok(self
            .select_batch(ctx, true, None, false)
            .await?
            .into_iter()
            .map(|(result, _)| result)
            .collect())
    }

    /// The serving selector with, per request position, the decision that
    /// produced (or withheld) the answer.
    pub async fn select_variant_decisions(
        &self,
        ctx: &QueryContext<'_>,
    ) -> io::Result<Vec<(Option<SelectedVariant>, KeyDecision)>> {
        self.select_batch(ctx, true, None, true).await
    }

    pub(super) async fn select_transfer_batch(
        &self,
        keys: &[u128],
        withheld: [u8; 16],
    ) -> io::Result<Vec<Option<SelectedVariant>>> {
        Ok(self
            .select_batch(
                &QueryContext {
                    keys,
                    requested_mdkeys: &[],
                    md5: None,
                    basename: None,
                    hostname: None,
                    origin_token: None,
                },
                true,
                Some(withheld),
                false,
            )
            .await?
            .into_iter()
            .map(|(result, _)| result)
            .collect())
    }

    /// `gate` applies the provenance judgement that withholds another
    /// program's name from an unrelated requester; it is on for answers that
    /// reach a client and off for inspection and evaluation.
    async fn select_batch(
        &self,
        ctx: &QueryContext<'_>,
        capture_candidates: bool,
        withheld: Option<[u8; 16]>,
        gate: bool,
    ) -> io::Result<Vec<(Option<SelectedVariant>, KeyDecision)>> {
        let mut keys = Vec::new();
        let mut positions = HashMap::new();
        let mut order = Vec::with_capacity(ctx.keys.len());
        // Request positions per unique key, in request order. A key that
        // recurs stands for several functions of the requesting binary.
        let mut layout: Vec<Vec<u32>> = Vec::new();
        for (position, &key) in ctx.keys.iter().enumerate() {
            let index = *positions.entry(key).or_insert_with(|| {
                keys.push(key);
                layout.push(Vec::new());
                keys.len() - 1
            });
            layout[index].push(position as u32);
            order.push(index);
        }
        let unique = QueryContext {
            keys: &keys,
            ..ctx.clone()
        };
        let decided = self
            .select_unique_versions(&unique, capture_candidates, withheld, gate, &layout, &order)
            .await?;
        Ok(order
            .into_iter()
            .enumerate()
            .map(|(position, i)| {
                decided[i]
                    .overrides
                    .get(&(position as u32))
                    .cloned()
                    .unwrap_or_else(|| decided[i].primary.clone())
            })
            .collect())
    }

    /// `layout` lists, per unique key, the request positions that carried
    /// it; `order` maps each request position back to its unique key.
    async fn select_unique_versions(
        &self,
        ctx: &QueryContext<'_>,
        capture_candidates: bool,
        withheld: Option<[u8; 16]>,
        gate: bool,
        layout: &[Vec<u32>],
        order: &[usize],
    ) -> io::Result<Vec<KeyOutcome>> {
        use std::sync::atomic::Ordering::Relaxed;
        use std::time::Instant;
        METRICS.inc_scoring_batches();
        let start = Instant::now();
        let requested_mdkeys = normalize_requested_mdkeys(ctx.requested_mdkeys);
        let max_repeats = self.rt.scoring.max_key_repeats;
        let repeat_count = |i: usize| layout.get(i).map_or(1, |p| p.len().max(1)) as u32;

        if withheld.is_none() && self.rt.ctx_index.approx_is_empty() {
            METRICS.inc_scoring_fallback();
            let mut out = Vec::with_capacity(ctx.keys.len());
            for (i, &k) in ctx.keys.iter().enumerate() {
                if repeat_count(i) as usize > max_repeats {
                    out.push(KeyOutcome::single(
                        None,
                        KeyDecision::declined(repeat_count(i), DeclineReason::Repeated),
                    ));
                    continue;
                }
                let canonical = self.get_canonical(k).await?.map(|f| {
                    let base_version_id = version_id(k, &f.name, &f.data);
                    let base_legacy_version_id = legacy_version_id(k, &f.name, &f.data);
                    let data = if requested_mdkeys.is_empty() {
                        f.data
                    } else {
                        shape_metadata_for_request(&f.data, &requested_mdkeys)
                    };
                    SelectedVariant {
                        popularity: f.popularity,
                        func_size: f.len_bytes,
                        ts_sec: f.ts_sec,
                        name: f.name,
                        data,
                        score: 0.0,
                        margin: 0.0,
                        entropy: 0.0,
                        used_synthesis: false,
                        base_version_id,
                        base_legacy_version_id,
                        binary_support: 0.0,
                        binary_match: 0.0,
                        binary_priority_floor: 0.0,
                        candidate_binary_match: if capture_candidates {
                            vec![0.0]
                        } else {
                            Vec::new()
                        },
                        candidate_binary_support: if capture_candidates {
                            vec![0.0]
                        } else {
                            Vec::new()
                        },
                        candidate_legacy_version_ids: if capture_candidates {
                            vec![base_legacy_version_id]
                        } else {
                            Vec::new()
                        },
                        candidate_version_ids: if capture_candidates {
                            vec![base_version_id]
                        } else {
                            Vec::new()
                        },
                    }
                });
                out.push(KeyOutcome::single(
                    canonical,
                    KeyDecision {
                        repeat_count: repeat_count(i),
                        ..KeyDecision::default()
                    },
                ));
            }
            METRICS
                .scoring_time_ns
                .fetch_add(start.elapsed().as_nanos() as u64, Relaxed);
            return Ok(out);
        }

        let (context_keys, context_completed) =
            complete_binary_context(&self.rt, ctx, withheld, false)?;
        // A known query binary supplies additional function identities, not a
        // competing donor vote. Apply the same exclusion when the caller already
        // supplied those identities. Exact observations still take precedence.
        let family = build_family_evidence(
            &self.rt,
            &context_keys,
            withheld.or(ctx.md5),
            ctx.keys.len() as u64,
        )?;
        let family_weights: Vec<_> = ctx.keys.iter().map(|key| family.excluding(*key)).collect();
        // Holdout evaluation judges selection against a withheld binary and
        // has no requester to relate a name to.
        let gate = (gate && withheld.is_none()).then(|| ProvenanceGate::new(&self.rt, &family));

        // Canonical hints must be known before bounded candidate discovery.
        // Holdout evaluation must not use the source binary's global canonical hint.
        let canonical_hints: Vec<Option<[u8; 32]>> = ctx
            .keys
            .iter()
            .map(|&k| {
                if withheld.is_some() {
                    return None;
                }
                self.rt
                    .ctx_index
                    .get_canonical_version(k)
                    .ok()
                    .flatten()
                    .map(|cv| cv.version_id)
            })
            .collect();

        let mut per_key_versions: Vec<Vec<AnalyzedVersion>> = Vec::with_capacity(ctx.keys.len());
        let completion_md5 = ctx.md5.filter(|_| withheld.is_none() && !context_completed);
        let mut fallback = Vec::with_capacity(ctx.keys.len());
        for (i, &k) in ctx.keys.iter().enumerate() {
            let last_versions = candidate_last_versions(&self.rt, k, &family_weights[i], ctx.md5)?;
            let provenance = withheld
                .filter(|_| self.rt.scoring.max_versions_per_key > 0)
                .map(|heldout| {
                    candidate_provenance::TransferProvenance::new(
                        &self.rt,
                        k,
                        heldout,
                        &family_weights[i],
                    )
                })
                .transpose()?;
            let mut wanted: HashSet<_> = last_versions
                .values()
                .copied()
                .chain(canonical_hints[i])
                .collect();
            let mut versions = Self::collect_versions_targeted(
                &self.rt,
                k,
                self.rt.scoring.max_versions_per_key,
                &wanted,
                provenance.as_ref(),
            )?;
            let target_count = wanted.len();
            wanted.extend(candidate_history::historical_targets(
                &self.rt,
                k,
                &versions,
                &family_weights[i],
                &last_versions,
                ctx,
                withheld,
            )?);
            if wanted.len() > target_count {
                drop(versions);
                versions = Self::collect_versions_targeted(
                    &self.rt,
                    k,
                    self.rt.scoring.max_versions_per_key,
                    &wanted,
                    provenance.as_ref(),
                )?;
            }
            let mut needs_completion = false;
            if let Some(md5) = completion_md5 {
                let mut explicit = last_versions
                    .get(&md5)
                    .is_some_and(|id| versions.iter().any(|version| version.matches_id(id)));
                if !explicit {
                    for version in &versions {
                        if version_observed_in(&self.rt, version, &md5)? {
                            explicit = true;
                            break;
                        }
                    }
                }
                needs_completion = !versions.is_empty() && !explicit;
            }
            fallback.push(needs_completion);
            assign_binary_support(
                &self.rt,
                &mut versions,
                &family_weights[i],
                &last_versions,
                &family,
                k,
            )?;
            per_key_versions.push(versions);
        }

        // Positive observation rows may outlive their payloads. Only after the
        // explicit/historical search fails, try the same bounded completion as
        // for missing observations. A request enumerates the prefix at most once.
        if let Some(md5) = completion_md5 {
            if fallback.iter().any(|needed| *needed) {
                let (completed_keys, _) = complete_binary_context(&self.rt, ctx, withheld, true)?;
                if completed_keys.len() > context_keys.len() {
                    let completed_family = build_family_evidence(
                        &self.rt,
                        &completed_keys,
                        Some(md5),
                        ctx.keys.len() as u64,
                    )?;
                    for (i, &key) in ctx.keys.iter().enumerate() {
                        let weights = completed_family.excluding(key);
                        let last_versions =
                            candidate_last_versions(&self.rt, key, &weights, Some(md5))?;
                        let versions = &mut per_key_versions[i];
                        let previous_targets = if fallback[i] {
                            candidate_last_versions(&self.rt, key, &family_weights[i], Some(md5))?
                        } else {
                            HashMap::new()
                        };
                        let historical = if fallback[i] {
                            candidate_history::historical_targets(
                                &self.rt,
                                key,
                                versions,
                                &weights,
                                &last_versions,
                                ctx,
                                withheld,
                            )?
                        } else {
                            HashSet::new()
                        };
                        if fallback[i]
                            && last_versions.values().chain(&historical).any(|id| {
                                !previous_targets.values().any(|prior| prior == id)
                                    && !versions.iter().any(|version| version.matches_id(id))
                            })
                        {
                            // Preserve validated candidates from the earlier
                            // passes while seeking new related-binary targets.
                            let wanted: HashSet<_> = versions
                                .iter()
                                .map(|v| v.version_id)
                                .chain(last_versions.values().copied())
                                .chain(historical)
                                .chain(canonical_hints[i])
                                .collect();
                            versions.clear();
                            *versions = Self::collect_versions_targeted(
                                &self.rt,
                                key,
                                self.rt.scoring.max_versions_per_key,
                                &wanted,
                                None, // Explicit-context completion is disabled for holdout.
                            )?;
                        }
                        assign_binary_support(
                            &self.rt,
                            versions,
                            &weights,
                            &last_versions,
                            &completed_family,
                            key,
                        )?;
                    }
                }
            }
        }
        let versions_considered_total = per_key_versions
            .iter()
            .map(|versions| versions.len() as u64)
            .sum();

        // What each pattern can identify, read from every collected candidate
        // before eligibility narrows the pool to one.
        let classify = self.classify_params();
        let classes: Vec<Classification> = per_key_versions
            .iter()
            .zip(ctx.keys)
            .map(|(versions, &key)| {
                let candidates: Vec<CandidateName<'_>> = versions
                    .iter()
                    .map(|version| CandidateName {
                        name: &version.rec.name,
                        num_binaries: version.stats.as_ref().map_or(0, |s| s.num_binaries),
                        declared_size: (version.rec.flags & REC_FLAG_DECLARED_SIZE != 0)
                            .then_some(version.rec.len_bytes),
                    })
                    .collect();
                classify_names(&candidates, family.membership_count(key), &classify)
            })
            .collect();

        let mut anchors = BatchAnchors::default();
        let mut whole_token_anchors = BatchAnchors::default();
        let mut eligible_candidates = Vec::with_capacity(per_key_versions.len());
        for (i, versions) in per_key_versions.iter_mut().enumerate() {
            // After deduplication a single requested key has no other semantic
            // source. Leave-one-key-out anchors are necessarily empty, so skip
            // their scoring pass and construction. Identity completion and the
            // final eligibility/scoring/synthesis pass still run normally.
            // A key that stands for many programs' code supplies no batch
            // evidence either: its specializations name other programs.
            let generic = matches!(
                classes[i].class,
                PatternClass::TemplateMember | PatternClass::Coincidence
            );
            if versions.is_empty() || ctx.keys.len() == 1 || generic {
                anchors.push(None);
                whole_token_anchors.push(None);
                eligible_candidates.push(Vec::new());
                continue;
            }
            let key = ctx.keys[i];
            let empty_weights: HashMap<String, f64> = HashMap::new();
            let scoring_ctx = CandidateScoringContext {
                capture_candidates,
                suppress_observation_priors: withheld.is_some(),
                contrastive_anchors: true,
                key,
                md5: ctx.md5,
                basename: ctx.basename,
                hostname: ctx.hostname,
                origin_token: ctx.origin_token,
                requested_mdkeys: &requested_mdkeys,
                anchor_token_weights: &empty_weights,
                priority_anchor_weights: &empty_weights,
                corroboration_weights: &empty_weights,
                canonical_hint: canonical_hints[i],
            };
            let mut eligible: Vec<_> = (0..versions.len()).collect();
            let explicit = retain_binary_compatible_candidates(
                &self.rt,
                versions,
                &scoring_ctx,
                &mut eligible,
            )?;
            eligible_candidates.push(eligible.clone());
            // The first scoring pass has no anchor weights. Expand only after
            // identity eligibility is known, before constructing source anchors.
            if ctx.keys.len() > 1 {
                for &index in &eligible {
                    let version = &mut versions[index];
                    version.batch_fingerprint = selection_fingerprint(
                        &version.rec.name,
                        version.analysis(),
                        self.rt.scoring.batch_identifier_components,
                    )
                    .map(Box::new);
                }
            }
            // Do not bootstrap semantic anchors from the ambiguity relaxation.
            // The initial source still follows the strongest binary evidence.
            if !explicit && self.rt.scoring.binary_priority {
                let best = versions.iter().map(|v| v.binary_match).fold(0.0, f64::max);
                if best > 1e-12 {
                    eligible.retain(|i| best - versions[*i].binary_match <= 1e-12);
                }
            }
            let mut scored =
                score_candidate_population(&self.rt, versions, &scoring_ctx, &eligible)?;
            sort_candidate_scores(versions, &mut scored);
            let anchor = match scored.as_slice() {
                [] => None,
                [top] => Some(top.0),
                [top, second, ..] if top.1 - second.1 >= 1.0 => Some(top.0),
                _ => None,
            };
            if let Some(best_idx) = anchor {
                anchors.push(Some(versions[best_idx].anchor_fingerprint()));
                whole_token_anchors.push(Some(&versions[best_idx].analysis().fingerprint));
            } else if self.rt.scoring.batch_consensus_anchors && scored.len() > 1 {
                // Uncertainty about the source's complete annotation does not
                // erase metadata shared by every eligible strongest variant.
                // Keep whole-token identifier provenance separate from components.
                let common = consensus_fingerprint(
                    scored
                        .iter()
                        .map(|(idx, _)| versions[*idx].anchor_fingerprint()),
                );
                let whole_common = consensus_fingerprint(
                    scored
                        .iter()
                        .map(|(idx, _)| &versions[*idx].analysis().fingerprint),
                );
                anchors.push(Some(&common));
                whole_token_anchors.push(Some(&whole_common));
            } else {
                anchors.push(None);
                whole_token_anchors.push(None);
            }
        }

        let mut results: Vec<KeyOutcome> = Vec::with_capacity(ctx.keys.len());
        for (i, versions) in per_key_versions.iter().enumerate() {
            if versions.is_empty() {
                results.push(KeyOutcome::single(
                    None,
                    KeyDecision {
                        repeat_count: repeat_count(i),
                        ..KeyDecision::default()
                    },
                ));
                continue;
            }

            let fingerprints: Vec<_> = eligible_candidates[i]
                .iter()
                .map(|index| versions[*index].anchor_fingerprint())
                .collect();
            let target_anchor_weights = anchors.excluding(i, &fingerprints);
            let whole_fingerprints: Vec<_> = eligible_candidates[i]
                .iter()
                .map(|index| &versions[*index].analysis().fingerprint)
                .collect();
            let priority_anchor_weights = whole_token_anchors.excluding(i, &whole_fingerprints);
            let corroboration_weights =
                whole_token_anchors.corroboration(i, &priority_anchor_weights);

            let key = ctx.keys[i];
            let scoring_ctx = CandidateScoringContext {
                capture_candidates,
                suppress_observation_priors: withheld.is_some(),
                contrastive_anchors: true,
                key,
                md5: ctx.md5,
                basename: ctx.basename,
                hostname: ctx.hostname,
                origin_token: ctx.origin_token,
                requested_mdkeys: &requested_mdkeys,
                anchor_token_weights: &target_anchor_weights,
                priority_anchor_weights: &priority_anchor_weights,
                corroboration_weights: &corroboration_weights,
                canonical_hint: canonical_hints[i],
            };
            let selected = select_from_versions(&self.rt, versions, &scoring_ctx)?;
            let (selected, provenance) =
                apply_provenance_gate(&self.rt, gate.as_ref(), versions, selected, ctx.md5);
            let primary = self.decide_by_class(
                versions,
                &classes[i],
                selected,
                provenance,
                repeat_count(i),
                &requested_mdkeys,
            );
            results.push(KeyOutcome::single(primary.0, primary.1));
        }

        // A skeleton answer can still be pinned per position: the request's
        // own neighbourhood may show which specialization this function is.
        // Only neighbours served to this requester on credible provenance can
        // vouch; a neighbour whose own name is foreign here is as ambiguous
        // as the candidate it would confirm.
        if gate.is_some() {
            let credible: Vec<bool> = results
                .iter()
                .map(|outcome| {
                    outcome.primary.0.is_some()
                        && matches!(
                            outcome.primary.1.provenance,
                            Provenance::Explicit { .. } | Provenance::RelatedDonor { .. }
                        )
                })
                .collect();
            for i in 0..ctx.keys.len() {
                if results[i].primary.1.served != ServedForm::Skeleton {
                    continue;
                }
                let overrides = self.corroborate_positions(
                    i,
                    &per_key_versions,
                    &classes,
                    &credible,
                    &family,
                    layout,
                    order,
                    ctx.keys,
                    &requested_mdkeys,
                );
                results[i].overrides = overrides;
            }
        }

        METRICS.inc_scoring_versions(versions_considered_total);
        METRICS
            .scoring_time_ns
            .fetch_add(start.elapsed().as_nanos() as u64, Relaxed);
        Ok(results)
    }

    /// Which stored binaries a batch of requested keys looks like, strongest
    /// first. This is the aggregate of the same per-key evidence the selector
    /// uses, so it shows what binary context a pull infers when the protocol
    /// carries no file identity. Diagnostics only; nothing is mutated.
    pub fn infer_batch_binaries(
        &self,
        keys: &[u128],
        limit: usize,
    ) -> io::Result<(usize, Vec<InferredBinary>)> {
        let family = build_family_evidence(&self.rt, keys, None, keys.len() as u64)?;
        let mut out = Vec::new();
        for (md5, share, keys_supported) in family.ranked_donors(limit) {
            let meta = self.rt.ctx_index.get_binary_meta(&md5)?;
            out.push(InferredBinary {
                md5_hex: hex_md5(&md5),
                basename: meta
                    .as_ref()
                    .map(|m| basename_only(&m.basename))
                    .unwrap_or_default(),
                share,
                keys_supported,
                function_count: meta.map_or(0, |m| m.function_count),
            });
        }
        Ok((family.informative_keys(), out))
    }

    /// Everything the selector can see for one key: every stored variant it
    /// would consider, each with the binaries that observed it, plus how many
    /// binaries carry the key at all. Read-only diagnostics for offline
    /// analysis of why a candidate won; it is not on any serving path.
    pub fn variant_inventory(
        &self,
        key: u128,
        max_versions: usize,
        binary_count_cap: usize,
    ) -> io::Result<VariantInventory> {
        let (binary_count, binary_count_capped) =
            self.rt.ctx_index.count_key_binaries(key, binary_count_cap)?;
        let (membership_rows, _, _) = self
            .rt
            .ctx_index
            .count_key_membership_rows(key, binary_count_cap)?;
        let votes_in_inference = self
            .rt
            .ctx_index
            .key_binary_memberships(key, MAX_KEY_MEMBERSHIPS)?
            .is_some_and(|bins| bins.len() <= MAX_KEY_MEMBERSHIPS);
        let versions = Self::collect_versions_sync(&self.rt, key, max_versions.max(1))?;
        let mut variants = Vec::with_capacity(versions.len());
        for version in &versions {
            let (total_obs, num_binaries, top) = match version.stats.as_ref() {
                Some(stats) => (
                    stats.total_obs,
                    stats.num_binaries,
                    stats.top_md5s.clone(),
                ),
                None => (0, 0, Vec::new()),
            };
            let mut top_binaries = Vec::with_capacity(top.len());
            for entry in top {
                let basename = self
                    .rt
                    .ctx_index
                    .get_binary_meta(&entry.md5)?
                    .map(|meta| basename_only(&meta.basename))
                    .unwrap_or_default();
                top_binaries.push(VariantBinary {
                    md5_hex: hex_md5(&entry.md5),
                    basename,
                    obs_count: entry.obs_count,
                    echo: self.rt.ctx_index.is_echo(key, &entry.md5)?,
                });
            }
            top_binaries.sort_by(|a, b| b.obs_count.cmp(&a.obs_count));
            variants.push(VariantInfo {
                version_id_hex: version
                    .version_id
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                name: version.rec.name.clone(),
                normalized_name: strip_ida_duplicate_suffix(&version.rec.name)
                    .unwrap_or(&version.rec.name)
                    .to_string(),
                skeleton: crate::common::skeleton::skeleton_of(&version.rec.name)
                    .map(|skeleton| skeleton.text),
                ts_sec: version.rec.ts_sec,
                data_len: version.rec.data.len(),
                declared_size: version.rec.len_bytes,
                total_obs,
                num_binaries,
                top_binaries,
            });
        }
        let candidates: Vec<CandidateName<'_>> = versions
            .iter()
            .map(|version| CandidateName {
                name: &version.rec.name,
                num_binaries: version.stats.as_ref().map_or(0, |stats| stats.num_binaries),
                declared_size: (version.rec.flags & REC_FLAG_DECLARED_SIZE != 0)
                    .then_some(version.rec.len_bytes),
            })
            .collect();
        let classification = classify_names(
            &candidates,
            votes_in_inference.then_some(binary_count),
            &self.classify_params(),
        );
        Ok(VariantInventory {
            key_hex: format!("{key:032x}"),
            binary_count,
            binary_count_capped,
            membership_rows,
            votes_in_inference,
            classification,
            variants,
        })
    }

    fn classify_params(&self) -> ClassifyParams {
        ClassifyParams {
            skeleton_min_share: self.rt.scoring.skeleton_min_share,
            generic_min_binaries: self.rt.scoring.generic_min_binaries,
            trivial_body_bytes: self.rt.scoring.trivial_body_bytes,
            class_hole_members: self.rt.scoring.class_hole_members.clone(),
        }
    }

    /// For each position of template-member key `i`, look within
    /// `scoring.sibling_window` positions for a rare, specifically named
    /// neighbour — served to this requester on credible provenance — that a
    /// donor of one candidate also carries and whose name mentions that
    /// candidate's specialization. Exactly one candidate so corroborated is
    /// served verbatim at that position.
    #[allow(clippy::too_many_arguments)]
    fn corroborate_positions(
        &self,
        i: usize,
        per_key_versions: &[Vec<AnalyzedVersion>],
        classes: &[Classification],
        credible: &[bool],
        family: &BatchFamilyEvidence,
        layout: &[Vec<u32>],
        order: &[usize],
        keys: &[u128],
        requested_mdkeys: &[u32],
    ) -> HashMap<u32, (Option<SelectedVariant>, KeyDecision)> {
        let scoring = &self.rt.scoring;
        let window = scoring.sibling_window as i64;
        let mut overrides = HashMap::new();
        if window == 0 {
            return overrides;
        }
        let Some(skeleton_text) = classes[i].skeleton.as_deref() else {
            return overrides;
        };
        // Candidates of the member with their specialization tokens and donors.
        let candidates: Vec<(usize, HashSet<String>, Vec<[u8; 16]>)> = per_key_versions[i]
            .iter()
            .enumerate()
            .filter_map(|(c, version)| {
                let skeleton = crate::common::skeleton::skeleton_of(&version.rec.name)?;
                let member = skeleton.text == skeleton_text
                    || skeleton_text
                        .strip_prefix("?::")
                        .is_some_and(|rest| skeleton.text.ends_with(&format!("::{rest}")));
                if !member {
                    return None;
                }
                let argument = skeleton.blanked_args.first().cloned().or_else(|| {
                    // A class hole: the specialization is the class itself.
                    skeleton.text.split("::").next().map(str::to_string)
                })?;
                let tokens = super::sibling::specialization_tokens(&argument);
                if tokens.is_empty() {
                    return None;
                }
                let donors: Vec<[u8; 16]> = version
                    .stats
                    .as_ref()
                    .map(|stats| stats.top_md5s.iter().map(|entry| entry.md5).collect())
                    .unwrap_or_default();
                (!donors.is_empty()).then_some((c, tokens, donors))
            })
            .collect();
        if candidates.is_empty() {
            return overrides;
        }
        let mut verdicts: HashMap<(usize, usize), Option<([u8; 16], String)>> = HashMap::new();
        for &position in &layout[i] {
            let mut hits: Vec<(usize, [u8; 16], usize, u32, String)> = Vec::new();
            let low = (position as i64 - window).max(0);
            let high = position as i64 + window;
            for q in low..=high {
                let q = q as usize;
                if q == position as usize || q >= order.len() {
                    continue;
                }
                let n = order[q];
                if n == i
                    || per_key_versions[n].is_empty()
                    || !credible[n]
                    || !matches!(
                        classes[n].class,
                        PatternClass::Specific | PatternClass::Disagreement
                    )
                    || family
                        .membership_count(keys[n])
                        .is_none_or(|count| count > scoring.sibling_max_binaries)
                {
                    continue;
                }
                for (c, tokens, donors) in &candidates {
                    let verdict = verdicts.entry((n, *c)).or_insert_with(|| {
                        per_key_versions[n].iter().find_map(|neighbour| {
                            let shared = neighbour.stats.as_ref().and_then(|stats| {
                                stats
                                    .top_md5s
                                    .iter()
                                    .map(|entry| entry.md5)
                                    .find(|md5| donors.contains(md5))
                            })?;
                            super::sibling::name_mentions(&neighbour.rec.name, tokens)
                                .then(|| (shared, neighbour.rec.name.clone()))
                        })
                    });
                    if let Some((donor, name)) = verdict {
                        hits.push((*c, *donor, n, q as u32, name.clone()));
                    }
                }
            }
            if hits.len() < scoring.sibling_min_corroborations.max(1) {
                continue;
            }
            let distinct: HashSet<usize> = hits.iter().map(|hit| hit.0).collect();
            if distinct.len() != 1 {
                continue;
            }
            let (c, donor, n, q, sibling_name) = hits.swap_remove(0);
            let version = &per_key_versions[i][c];
            let mut decision = results_decision_template(&classes[i], layout[i].len() as u32);
            decision.served = ServedForm::Corroborated;
            decision.specialized_by = Some(super::pattern::Specialization {
                donor_md5_hex: hex_md5(&donor),
                sibling_key_hex: format!("{:032x}", keys[n]),
                sibling_position: q,
                sibling_name,
            });
            let answer = SelectedVariant {
                popularity: version.rec.popularity,
                func_size: version.rec.len_bytes,
                ts_sec: version.rec.ts_sec,
                name: served_name(&self.rt, &version.rec.name),
                data: shape_metadata_for_request(&version.rec.data, requested_mdkeys),
                score: 0.0,
                margin: 0.0,
                entropy: 0.0,
                used_synthesis: false,
                base_version_id: version.version_id,
                base_legacy_version_id: version.legacy_version_id,
                binary_support: version.binary_support,
                binary_match: version.binary_match,
                binary_priority_floor: version.binary_priority_floor,
                candidate_binary_match: Vec::new(),
                candidate_binary_support: Vec::new(),
                candidate_legacy_version_ids: Vec::new(),
                candidate_version_ids: Vec::new(),
            };
            overrides.insert(position, (Some(answer), decision));
        }
        overrides
    }

    /// The serving decision for one key, as a client asking for it (with the
    /// given binary context) would receive it.
    pub async fn explain_function(&self, key: u128, md5: Option<[u8; 16]>) -> io::Result<KeyDecision> {
        let mut decided = self
            .select_batch(
                &QueryContext {
                    keys: &[key],
                    requested_mdkeys: &[],
                    md5,
                    basename: None,
                    hostname: None,
                    origin_token: None,
                },
                false,
                None,
                true,
            )
            .await?;
        Ok(decided
            .pop()
            .map(|(_, decision)| decision)
            .unwrap_or_default())
    }

    /// Turn the ranked, provenance-judged winner into the answer the pattern
    /// supports. A requester known to be related keeps the verbatim record;
    /// otherwise a template member serves its skeleton, a coincidence serves
    /// nothing, and a repeated pattern serves only what holds for every
    /// function it matched.
    #[allow(clippy::too_many_arguments)]
    fn decide_by_class(
        &self,
        versions: &[AnalyzedVersion],
        classification: &Classification,
        selected: Option<SelectedVariant>,
        provenance: Provenance,
        repeat_count: u32,
        requested_mdkeys: &[u32],
    ) -> (Option<SelectedVariant>, KeyDecision) {
        let scoring = &self.rt.scoring;
        let related = matches!(
            provenance,
            Provenance::Explicit { .. } | Provenance::RelatedDonor { .. }
        );
        let repeated = repeat_count as usize > scoring.max_key_repeats;
        let mut decision = KeyDecision {
            repeat_count,
            served: ServedForm::Verbatim,
            provenance,
            class: classification.class,
            skeleton: classification.skeleton.clone(),
            type_consensus: None,
            specialized_by: None,
        };
        let decline = |mut decision: KeyDecision, reason: DeclineReason| {
            decision.served = ServedForm::Declined(reason);
            (None, decision)
        };
        match classification.class {
            PatternClass::TemplateMember => {
                if related && !repeated {
                    return (selected, decision);
                }
                if !scoring.template_skeleton_names {
                    return decline(decision, DeclineReason::TemplateNoSkeleton);
                }
                match self.skeleton_answer(versions, classification, requested_mdkeys) {
                    Some((answer, consensus)) => {
                        decision.served = ServedForm::Skeleton;
                        decision.type_consensus = Some(consensus);
                        (Some(answer), decision)
                    }
                    None => decline(decision, DeclineReason::TemplateNoSkeleton),
                }
            }
            PatternClass::Coincidence => {
                // Withheld only on positive evidence that the requester is
                // unrelated; an unjudged request keeps the ranked answer.
                let unrelated = matches!(
                    decision.provenance,
                    Provenance::Foreign { .. } | Provenance::Library { .. }
                );
                if repeated {
                    decline(decision, DeclineReason::Repeated)
                } else if related || !unrelated || !scoring.coincidence_suppress {
                    (selected, decision)
                } else {
                    decline(decision, DeclineReason::Coincidence)
                }
            }
            PatternClass::Specific | PatternClass::Disagreement => {
                if repeated {
                    decline(decision, DeclineReason::Repeated)
                } else if selected.is_none()
                    && matches!(decision.provenance, Provenance::Foreign { .. })
                {
                    decline(decision, DeclineReason::ForeignSpecific)
                } else {
                    (selected, decision)
                }
            }
        }
    }

    /// The template member as a servable answer: the heaviest specialization
    /// whose mangled name splices cleanly around the placeholder, or an
    /// identifier built from the skeleton text; metadata only when every
    /// typed specialization declares the same prototype.
    fn skeleton_answer(
        &self,
        versions: &[AnalyzedVersion],
        classification: &Classification,
        requested_mdkeys: &[u32],
    ) -> Option<(SelectedVariant, TypeConsensus)> {
        let skeleton_text = classification.skeleton.as_deref()?;
        let placeholder = &self.rt.scoring.skeleton_placeholder;
        let mut members: Vec<(&AnalyzedVersion, crate::common::skeleton::SkeletonName)> = versions
            .iter()
            .filter_map(|version| {
                let skeleton = crate::common::skeleton::skeleton_of(&version.rec.name)?;
                let member = skeleton.text == skeleton_text
                    || skeleton_text
                        .strip_prefix("?::")
                        .is_some_and(|rest| skeleton.text.ends_with(&format!("::{rest}")));
                member.then_some((version, skeleton))
            })
            .collect();
        if members.is_empty() {
            return None;
        }
        members.sort_by(|a, b| {
            let weight = |v: &AnalyzedVersion| v.stats.as_ref().map_or(0, |s| s.num_binaries);
            weight(b.0)
                .cmp(&weight(a.0))
                .then_with(|| b.0.rec.ts_sec.cmp(&a.0.rec.ts_sec))
        });
        let name = members
            .iter()
            .find_map(|(version, skeleton)| {
                if skeleton_text.starts_with("?::") {
                    splice_placeholder_class(&version.rec.name, skeleton_text, placeholder)
                } else {
                    splice_placeholder_template(&version.rec.name, skeleton, placeholder)
                }
            })
            .unwrap_or_else(|| skeleton_identifier(skeleton_text, placeholder));

        // Declared prototypes shared by every typed specialization carry no
        // specialization-specific bytes, so they are safe to serve as stored.
        let mut consensus = TypeConsensus::Absent;
        let mut type_chunk: Option<crate::protocol::lumina::MetadataChunk> = None;
        let mut agreed: Option<(Vec<u8>, Vec<u8>)> = None;
        for (version, _) in &members {
            let metadata = &version.analysis().metadata;
            let Some(parts) = metadata.type_parts.as_ref() else {
                continue;
            };
            let Some(chunk) = metadata
                .raw_chunks
                .iter()
                .find(|chunk| chunk.key == crate::protocol::lumina::MdKey::Type)
            else {
                continue;
            };
            // The prototype is compared without its `userti` flag; a guessed
            // copy of a declared prototype agrees on the type but not on the
            // evidence for it.
            let prototype = (parts.type_bytes.clone(), parts.fields_bytes.clone());
            match &agreed {
                None => {
                    agreed = Some(prototype);
                    type_chunk = Some(chunk.clone());
                    consensus = if parts.userti {
                        TypeConsensus::Declared
                    } else {
                        TypeConsensus::Guessed
                    };
                }
                Some(existing) if *existing != prototype => {
                    consensus = TypeConsensus::Disagree;
                    break;
                }
                Some(_) => {
                    if !parts.userti {
                        consensus = TypeConsensus::Guessed;
                    }
                }
            }
        }
        let data = match (consensus, type_chunk) {
            (TypeConsensus::Declared, Some(chunk)) => shape_metadata_for_request(
                &crate::protocol::lumina::serialize_metadata_chunks(&[chunk]),
                requested_mdkeys,
            ),
            _ => Vec::new(),
        };

        let (donor, _) = members[0];
        Some((
            SelectedVariant {
                popularity: donor.rec.popularity,
                func_size: donor.rec.len_bytes,
                ts_sec: donor.rec.ts_sec,
                name,
                data,
                score: 0.0,
                margin: 0.0,
                entropy: 0.0,
                used_synthesis: true,
                base_version_id: donor.version_id,
                base_legacy_version_id: donor.legacy_version_id,
                binary_support: donor.binary_support,
                binary_match: donor.binary_match,
                binary_priority_floor: donor.binary_priority_floor,
                candidate_binary_match: Vec::new(),
                candidate_binary_support: Vec::new(),
                candidate_legacy_version_ids: Vec::new(),
                candidate_version_ids: members.iter().map(|(v, _)| v.version_id).collect(),
            },
            consensus,
        ))
    }

    pub fn list_keys(&self, limit: Option<usize>) -> Vec<u128> {
        let iter = self.rt.index.iter_keys().map(|(key, _)| key);
        match limit {
            Some(limit) => iter.take(limit).collect(),
            None => iter.collect(),
        }
    }

    pub async fn replay_select_for_key(
        &self,
        key: u128,
        options: &ReplayCaseOptions,
    ) -> io::Result<Option<ReplayCaseResult>> {
        let max_versions = options.max_versions.max(2);
        let mut versions = Self::collect_versions_sync(&self.rt, key, max_versions)?;
        if versions.len() < 2 {
            return Ok(None);
        }

        let holdout = versions.remove(0);
        let requested_mdkeys =
            replay_requested_mdkeys(&holdout.analysis().metadata, options.request_mode);
        let holdout_data = shape_metadata_for_request(&holdout.rec.data, &requested_mdkeys);
        let canonical_hint = self
            .rt
            .ctx_index
            .get_canonical_version(key)?
            .and_then(|canonical| {
                if holdout.matches_id(&canonical.version_id) {
                    None
                } else {
                    Some(canonical.version_id)
                }
            });
        let (md5, basename, hostname, origin_token) = replay_query_context(&self.rt, &holdout)?;
        let (ts_min, ts_max, max_total_obs, max_bins) = version_population_bounds(&versions);

        let empty_weights: HashMap<String, f64> = HashMap::new();
        let mut anchor_token_weights: HashMap<String, f64> = HashMap::new();
        let initial_ctx = CandidateScoringContext {
            capture_candidates: false,
            suppress_observation_priors: false,
            contrastive_anchors: false,
            key,
            md5,
            basename: basename.as_deref(),
            hostname: hostname.as_deref(),
            origin_token: origin_token.as_deref(),
            requested_mdkeys: &requested_mdkeys,
            anchor_token_weights: &empty_weights,
            priority_anchor_weights: &empty_weights,
            corroboration_weights: &empty_weights,
            canonical_hint,
        };
        let mut first_pass: Vec<(usize, f64)> = versions
            .iter()
            .enumerate()
            .map(|(idx, version)| {
                Ok((
                    idx,
                    score_candidate_version(
                        &self.rt,
                        version,
                        &initial_ctx,
                        ts_min,
                        ts_max,
                        max_total_obs,
                        max_bins,
                    )?,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        first_pass.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let anchor = match first_pass.as_slice() {
            [] => None,
            [top] => Some(top.0),
            [top, second, ..] if top.1 - second.1 >= 1.0 => Some(top.0),
            _ => None,
        };
        if let Some(anchor_idx) = anchor {
            for token in &versions[anchor_idx].analysis().fingerprint.tokens {
                *anchor_token_weights.entry(token.clone()).or_insert(0.0) += 1.0;
            }
            for token in &versions[anchor_idx].analysis().fingerprint.prototype_tokens {
                *anchor_token_weights.entry(token.clone()).or_insert(0.0) += 0.5;
            }
            for token in &versions[anchor_idx].analysis().fingerprint.frame_tokens {
                *anchor_token_weights.entry(token.clone()).or_insert(0.0) += 0.35;
            }
            for token in &versions[anchor_idx].analysis().fingerprint.comment_tokens {
                *anchor_token_weights.entry(token.clone()).or_insert(0.0) += 0.25;
            }
            for token in &versions[anchor_idx].analysis().fingerprint.operand_tokens {
                *anchor_token_weights.entry(token.clone()).or_insert(0.0) += 0.2;
            }
        }
        let max_anchor_weight = anchor_token_weights
            .values()
            .copied()
            .fold(0.0f64, f64::max);
        if max_anchor_weight > 0.0 {
            for value in anchor_token_weights.values_mut() {
                *value /= max_anchor_weight;
            }
        }

        let semantic_ctx = CandidateScoringContext {
            capture_candidates: false,
            suppress_observation_priors: false,
            contrastive_anchors: false,
            key,
            md5,
            basename: basename.as_deref(),
            hostname: hostname.as_deref(),
            origin_token: origin_token.as_deref(),
            requested_mdkeys: &requested_mdkeys,
            anchor_token_weights: &anchor_token_weights,
            priority_anchor_weights: &anchor_token_weights,
            corroboration_weights: &empty_weights,
            canonical_hint,
        };
        let Some(semantic_selection) = select_from_versions(&self.rt, &versions, &semantic_ctx)?
        else {
            return Ok(None);
        };

        let baseline_version = &versions[0];
        let baseline = ReplaySelectorResult {
            base_version_id: baseline_version.version_id,
            name: baseline_version.rec.name.clone(),
            data: shape_metadata_for_request(&baseline_version.rec.data, &requested_mdkeys),
            score: 0.0,
            margin: 0.0,
            entropy: 1.0,
            used_synthesis: false,
        };
        let semantic = ReplaySelectorResult {
            base_version_id: semantic_selection.base_version_id,
            name: semantic_selection.name,
            data: semantic_selection.data,
            score: semantic_selection.score,
            margin: semantic_selection.margin,
            entropy: semantic_selection.entropy,
            used_synthesis: semantic_selection.used_synthesis,
        };

        Ok(Some(ReplayCaseResult {
            key,
            holdout_version_id: holdout.version_id,
            holdout_name: holdout.rec.name,
            holdout_data,
            requested_mdkeys,
            candidate_count: versions.len(),
            baseline,
            semantic,
        }))
    }
}

// Helper functions

fn select_from_versions(
    rt: &EngineRuntime,
    versions: &[AnalyzedVersion],
    scoring_ctx: &CandidateScoringContext<'_>,
) -> io::Result<Option<SelectedVariant>> {
    if versions.is_empty() {
        return Ok(None);
    }

    let mut eligible: Vec<_> = (0..versions.len()).collect();
    let explicit = retain_binary_compatible_candidates(rt, versions, scoring_ctx, &mut eligible)?;
    if !explicit && rt.scoring.binary_priority {
        let best = versions.iter().map(|v| v.binary_match).fold(0.0, f64::max);
        if best > 1e-12
            && eligible
                .iter()
                .any(|i| best - versions[*i].binary_match > 1e-12)
        {
            let mut support = vec![0.0; versions.len()];
            for i in &eligible {
                support[*i] = corroborated_support(
                    &versions[*i].analysis().fingerprint,
                    scoring_ctx.priority_anchor_weights,
                    scoring_ctx.corroboration_weights,
                );
            }
            let strongest_context = versions
                .iter()
                .enumerate()
                .filter(|(_, v)| best - v.binary_match <= 1e-12)
                .map(|(i, _)| support[i])
                .fold(0.0, f64::max);
            eligible.retain(|i| {
                best - versions[*i].binary_match <= 1e-12 || support[*i] > strongest_context + 1e-12
            });
        }
    }
    let anchor_weights = if scoring_ctx.contrastive_anchors
        && eligible.len() < versions.len()
        && !scoring_ctx.anchor_token_weights.is_empty()
    {
        let fingerprints: Vec<_> = eligible
            .iter()
            .map(|index| versions[*index].anchor_fingerprint())
            .collect();
        std::borrow::Cow::Owned(restrict_contrastive_weights(
            scoring_ctx.anchor_token_weights,
            &fingerprints,
        ))
    } else {
        std::borrow::Cow::Borrowed(scoring_ctx.anchor_token_weights)
    };
    let scoring_ctx = &CandidateScoringContext {
        anchor_token_weights: anchor_weights.as_ref(),
        ..*scoring_ctx
    };
    let mut scored = score_candidate_population(rt, versions, scoring_ctx, &eligible)?;
    sort_candidate_scores(versions, &mut scored);

    let best_idx = scored[0].0;
    let best_version = &versions[best_idx];
    let best_score = scored[0].1;
    let second_score = scored
        .get(1)
        .map(|entry| entry.1)
        .unwrap_or(f64::NEG_INFINITY);
    let margin = best_score - second_score;
    let entropy = score_entropy(&scored);
    let use_synthesis = rt.scoring.experimental_synthesis
        && scored.len() > 1
        && (!scoring_ctx.requested_mdkeys.is_empty() || margin < 1.25);

    let mut top_inputs = Vec::new();
    for (idx, score) in scored.iter().take(3) {
        let version = &versions[*idx];
        top_inputs.push(SynthesisInput {
            score: *score,
            name: &version.rec.name,
            raw_data: &version.rec.data,
            metadata: &version.analysis().metadata,
        });
    }

    let fallback_data =
        shape_metadata_for_request(&best_version.rec.data, scoring_ctx.requested_mdkeys);
    let outcome = if use_synthesis {
        super::semantic::synthesize_selection_with_policy(
            &top_inputs,
            scoring_ctx.requested_mdkeys,
            rt.cfg.name_rejection,
        )
    } else {
        super::semantic::SynthesizedSelection {
            name: served_name(rt, &best_version.rec.name),
            data: fallback_data,
            used_synthesis: false,
            donor_indices: vec![0],
        }
    };

    Ok(Some(SelectedVariant {
        popularity: best_version.rec.popularity,
        func_size: best_version.rec.len_bytes,
        ts_sec: best_version.rec.ts_sec,
        name: outcome.name,
        data: outcome.data,
        score: best_score,
        margin,
        entropy,
        used_synthesis: outcome.used_synthesis,
        base_version_id: best_version.version_id,
        base_legacy_version_id: best_version.legacy_version_id,
        binary_support: best_version.binary_support,
        binary_match: best_version.binary_match,
        binary_priority_floor: inferred_priority_floor(rt, versions),
        candidate_binary_match: if scoring_ctx.capture_candidates {
            versions
                .iter()
                .map(|version| version.binary_match)
                .collect()
        } else {
            Vec::new()
        },
        candidate_binary_support: if scoring_ctx.capture_candidates {
            versions
                .iter()
                .map(|version| version.binary_support)
                .collect()
        } else {
            Vec::new()
        },
        candidate_legacy_version_ids: if scoring_ctx.capture_candidates {
            versions
                .iter()
                .map(|version| version.legacy_version_id)
                .collect()
        } else {
            Vec::new()
        },
        candidate_version_ids: if scoring_ctx.capture_candidates {
            versions.iter().map(|version| version.version_id).collect()
        } else {
            Vec::new()
        },
    }))
}

fn replay_requested_mdkeys(
    metadata: &crate::protocol::lumina::FunctionMetadata,
    mode: ReplayRequestMode,
) -> Vec<u32> {
    let all = normalize_requested_mdkeys(
        &metadata
            .raw_chunks
            .iter()
            .map(|chunk| chunk.raw_key)
            .collect::<Vec<_>>(),
    );
    if all.is_empty() {
        return all;
    }

    let wanted = match mode {
        ReplayRequestMode::Full => all.clone(),
        ReplayRequestMode::Structure => all
            .iter()
            .copied()
            .filter(|raw_key| {
                matches!(
                    crate::protocol::lumina::MdKey::from(*raw_key),
                    crate::protocol::lumina::MdKey::Type
                        | crate::protocol::lumina::MdKey::FrameDesc
                        | crate::protocol::lumina::MdKey::UserStkpnts
                )
            })
            .collect(),
        ReplayRequestMode::Comments => all
            .iter()
            .copied()
            .filter(|raw_key| {
                matches!(
                    crate::protocol::lumina::MdKey::from(*raw_key),
                    crate::protocol::lumina::MdKey::Fcmt
                        | crate::protocol::lumina::MdKey::Frptcmt
                        | crate::protocol::lumina::MdKey::Cmts
                        | crate::protocol::lumina::MdKey::Rptcmts
                        | crate::protocol::lumina::MdKey::Extracmts
                )
            })
            .collect(),
        ReplayRequestMode::Operands => all
            .iter()
            .copied()
            .filter(|raw_key| {
                matches!(
                    crate::protocol::lumina::MdKey::from(*raw_key),
                    crate::protocol::lumina::MdKey::UserStkpnts
                        | crate::protocol::lumina::MdKey::Ops
                        | crate::protocol::lumina::MdKey::OpsEx
                )
            })
            .collect(),
    };
    if wanted.is_empty() {
        all
    } else {
        normalize_requested_mdkeys(&wanted)
    }
}

/// Bound physical enumeration as well as retained evidence. The forward index
/// can contain zero-observation placeholders, so verify each extra key through
/// the authoritative positive-observation lookup before using it.
const MAX_BINARY_CONTEXT_KEYS: usize = 128;

/// Keys of a binary examined when deriving its neighbourhood. One bound serves
/// overlap, related binaries, the graph and the timeline, so every view reports
/// the same shared counts for a pair.
const BINARY_OVERLAP_PROBE_KEYS: usize = 8192;

/// Keys per thread in a neighbourhood scan. Small enough to keep threads even,
/// large enough that a short scan stays on the calling thread.
const OVERLAP_SCAN_CHUNK: usize = 256;

/// Keys per thread when reading coverage. Each key can pull a record body, so
/// the chunks are smaller than a plain posting scan.
const FACET_SCAN_CHUNK: usize = 128;

/// Keys per thread when coverage has to fall back to full selection, which
/// costs far more per key than reading a head record.
const FACET_SELECT_CHUNK: usize = 8;

/// Rows per thread when resolving a page of functions. A page is short and
/// every row runs a full selection, so the chunks are short too.
const PAGE_RESOLVE_CHUNK: usize = 4;

/// Count one resolved annotation into a coverage tally.
fn tally_facet_row(out: &mut BinaryFacetSummary, name: &str, data: &[u8], fallback: bool) {
    if fallback {
        out.fallback_functions += 1;
    }
    let parsed = parse_metadata(data);
    if parsed.type_parts.is_some() {
        out.typed_functions += 1;
    }
    if parsed.frame_desc.is_some() {
        out.framed_functions += 1;
    }
    if parsed.fcmt.is_some()
        || parsed.frptcmt.is_some()
        || !parsed.insn_cmts.is_empty()
        || !parsed.rpt_insn_cmts.is_empty()
        || !parsed.extra_cmts.is_empty()
    {
        out.commented_functions += 1;
    }
    if !parsed.errors.is_empty() {
        out.parse_partial_functions += 1;
    }
    if parsed
        .insn_cmts
        .iter()
        .chain(parsed.rpt_insn_cmts.iter())
        .any(|c| c.cmt.starts_with("switch ") || c.cmt.starts_with("jumptable "))
    {
        out.switch_functions += 1;
    }
    if demangle(name).demangled {
        out.demangled_functions += 1;
    }
}

/// Name of the component a symbol belongs to, when its shape reveals one.
///
/// Only namespace and prefix conventions are honoured; a bare name reports no
/// component rather than inviting a guess from an arbitrary substring.
fn component_token(name: &str) -> Option<String> {
    const GENERIC: [&str; 18] = [
        "std", "operator", "sub", "loc", "unk", "nullsub", "j", "thunk", "off", "byte", "word",
        "dword", "qword", "unknown", "void", "this", "type", "vtable",
    ];
    let name = demangle(name).name;
    let name = name
        .split(['(', '<', ' '])
        .next()
        .unwrap_or_default()
        .trim_start_matches(['_', '?', '@', '.']);
    let candidate = match name.split_once("::") {
        Some((head, rest)) => {
            let head = head.trim_start_matches(['_', '?', '@']);
            if GENERIC.contains(&head.to_ascii_lowercase().as_str()) || head.len() < 2 {
                rest.split("::").next().unwrap_or_default()
            } else {
                head
            }
        }
        None => name.split_once('_')?.0,
    };
    let candidate = candidate.trim_start_matches(['_', '?', '@']);
    if candidate.len() < 2
        || candidate.len() > 24
        || !candidate.starts_with(|c: char| c.is_ascii_alphabetic())
        || !candidate.chars().all(|c| c.is_ascii_alphanumeric())
        || candidate.chars().all(|c| c.is_ascii_digit())
        || GENERIC.contains(&candidate.to_ascii_lowercase().as_str())
    {
        return None;
    }
    Some(candidate.to_string())
}

/// Return request identities plus whether the bounded forward prefix was
/// enumerated, even when it supplied no additional positive identities.
fn complete_binary_context<'a>(
    rt: &EngineRuntime,
    ctx: &QueryContext<'a>,
    withheld: Option<[u8; 16]>,
    stale_observation: bool,
) -> io::Result<(std::borrow::Cow<'a, [u128]>, bool)> {
    let mut keys = std::borrow::Cow::Borrowed(ctx.keys);
    let Some(md5) = ctx.md5.filter(|_| withheld.is_none() && !keys.is_empty()) else {
        return Ok((keys, false));
    };
    let mut needs_context = stale_observation;
    if !needs_context {
        for &key in ctx.keys {
            if rt
                .ctx_index
                .get_positive_key_md5_stats(key, &md5)?
                .is_none()
            {
                needs_context = true;
                break;
            }
        }
    }
    if !needs_context {
        return Ok((keys, false));
    }
    let mut seen: HashSet<_> = keys.iter().copied().collect();
    for key in rt
        .ctx_index
        .get_binary_function_keys(&md5, MAX_BINARY_CONTEXT_KEYS)?
    {
        if seen.insert(key)
            && rt
                .ctx_index
                .get_positive_key_md5_stats(key, &md5)?
                .is_some()
        {
            keys.to_mut().push(key);
        }
    }
    Ok((keys, true))
}

fn candidate_last_versions(
    rt: &EngineRuntime,
    key: u128,
    weights: &HashMap<[u8; 16], f64>,
    md5: Option<[u8; 16]>,
) -> io::Result<HashMap<[u8; 16], [u8; 32]>> {
    let mut versions = HashMap::new();
    for binary in weights.keys().copied().chain(md5) {
        if let Some(stats) = rt.ctx_index.get_positive_key_md5_stats(key, &binary)? {
            if stats.last_version_id != [0; 32] {
                versions.insert(binary, stats.last_version_id);
            }
        }
    }
    Ok(versions)
}

/// `withheld` is the query's own binary when known: excluded from the vote
/// and, when its size is recorded, the reference for donor scaling. Otherwise
/// `request_size` (the number of requested keys) is the reference. A donor
/// with `function_count` above the reference is discounted by
/// `(reference / function_count)^donor_size_exponent`, so a binary that is
/// ten times larger than the query cannot outvote a same-sized one merely by
/// containing more shared code.
fn build_family_evidence(
    rt: &EngineRuntime,
    keys: &[u128],
    withheld: Option<[u8; 16]>,
    request_size: u64,
) -> io::Result<BatchFamilyEvidence> {
    let mut rows = Vec::with_capacity(keys.len());
    let mut raw_counts = std::collections::BTreeMap::new();
    let echoes_recorded = rt.ctx_index.has_echoes();
    for &key in keys {
        if let Some(mut bins) = rt
            .ctx_index
            .key_binary_memberships(key, MAX_KEY_MEMBERSHIPS + usize::from(withheld.is_some()))?
        {
            if bins.len() <= MAX_KEY_MEMBERSHIPS {
                raw_counts.insert(key, bins.len());
            }
            bins.retain(|md5| Some(*md5) != withheld);
            // A binary whose observation merely echoed a served name does not
            // vouch for the key.
            if echoes_recorded {
                let mut kept = Vec::with_capacity(bins.len());
                for md5 in bins {
                    if !rt.ctx_index.is_echo(key, &md5)? {
                        kept.push(md5);
                    }
                }
                bins = kept;
            }
            if !bins.is_empty() && bins.len() <= MAX_KEY_MEMBERSHIPS {
                rows.push((key, bins));
            }
        }
    }
    let rare_limit = rt.scoring.generic_min_binaries;
    let exponent = rt.scoring.donor_size_exponent;
    if exponent <= 0.0 {
        return Ok(BatchFamilyEvidence::with_donor_scale(rows, rare_limit, |_| 1.0)
            .with_raw_counts(raw_counts));
    }
    let reference = withheld
        .and_then(|md5| rt.ctx_index.get_binary_meta(&md5).ok().flatten())
        .map(|meta| meta.function_count)
        .filter(|count| *count > 0)
        .unwrap_or(request_size)
        .max(1) as f64;
    Ok(BatchFamilyEvidence::with_donor_scale(rows, rare_limit, |md5| {
        match rt.ctx_index.get_binary_meta(md5) {
            Ok(Some(meta)) if meta.function_count > 0 => {
                (reference / meta.function_count as f64).powf(exponent)
            }
            _ => 1.0,
        }
    })
    .with_raw_counts(raw_counts))
}

/// Judge the winning record's provenance for this request; a foreign name is
/// withheld when `scoring.foreign_specific_decline` is set, and recorded
/// either way.
fn apply_provenance_gate(
    rt: &EngineRuntime,
    gate: Option<&ProvenanceGate<'_>>,
    versions: &[AnalyzedVersion],
    selected: Option<SelectedVariant>,
    explicit: Option<[u8; 16]>,
) -> (Option<SelectedVariant>, Provenance) {
    let Some(gate) = gate else {
        return (selected, Provenance::Unchecked);
    };
    let Some(selected) = selected else {
        return (None, Provenance::Unchecked);
    };
    let winner = versions
        .iter()
        .find(|version| selected.matches_version(&version.version_id));
    let observers: Vec<[u8; 16]> = winner
        .and_then(|version| version.stats.as_ref())
        .map(|stats| stats.top_md5s.iter().map(|entry| entry.md5).collect())
        .unwrap_or_default();
    // The observer summary is capped; an explicit requester is recognised
    // through the full observation history.
    let explicit = explicit.filter(|md5| {
        winner.is_some_and(|version| version_observed_in(rt, version, md5).unwrap_or(false))
    });
    let key = winner.map_or(0, |version| version.rec.key);
    let provenance = gate.check(key, &observers, explicit);
    if matches!(provenance, Provenance::Foreign { .. }) && rt.scoring.foreign_specific_decline {
        (None, provenance)
    } else {
        (Some(selected), provenance)
    }
}

/// The answer for one unique key: what every position receives unless a
/// position-specific answer overrides it.
#[derive(Clone)]
struct KeyOutcome {
    primary: (Option<SelectedVariant>, KeyDecision),
    overrides: HashMap<u32, (Option<SelectedVariant>, KeyDecision)>,
}

impl KeyOutcome {
    fn single(selected: Option<SelectedVariant>, decision: KeyDecision) -> Self {
        Self {
            primary: (selected, decision),
            overrides: HashMap::new(),
        }
    }
}

fn results_decision_template(classification: &Classification, repeat_count: u32) -> KeyDecision {
    KeyDecision {
        repeat_count,
        class: classification.class,
        skeleton: classification.skeleton.clone(),
        ..KeyDecision::default()
    }
}

/// A plain identifier for a skeleton whose mangled form could not be
/// spliced: `QtPrivate::QCallableObject<?>::impl(…)` becomes
/// `QtPrivate__QCallableObject__lumina_T__impl`.
fn skeleton_identifier(skeleton_text: &str, placeholder: &str) -> String {
    let head = skeleton_text.split('(').next().unwrap_or(skeleton_text);
    let head = head
        .replace("<?>", &format!("_{placeholder}_"))
        .replace("?::", &format!("{placeholder}::"));
    let mut out = String::with_capacity(head.len());
    let mut last_underscore = false;
    for c in head.chars() {
        let mapped = if c.is_ascii_alphanumeric() { c } else { '_' };
        if mapped == '_' {
            if last_underscore {
                continue;
            }
            last_underscore = true;
        } else {
            last_underscore = false;
        }
        out.push(mapped);
    }
    out.trim_matches('_').to_string()
}

/// The stored name as it is served: a record written before collision
/// suffixes were normalized on push still serves the bare symbol.
fn served_name(rt: &EngineRuntime, stored: &str) -> String {
    if rt.scoring.normalize_collision_suffixes {
        if let Some(stem) = strip_ida_duplicate_suffix(stored) {
            return stem.to_string();
        }
    }
    stored.to_string()
}

fn sort_candidate_scores(versions: &[AnalyzedVersion], scored: &mut [(usize, f64)]) {
    scored.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| versions[b.0].rec.ts_sec.cmp(&versions[a.0].rec.ts_sec))
            .then_with(|| versions[a.0].version_id.cmp(&versions[b.0].version_id))
    });
}

/// Normalize and score only the final eligible population for this pass. Excluded
/// candidates keep diagnostic identities but cannot rescale compatible evidence.
fn score_candidate_population(
    rt: &EngineRuntime,
    versions: &[AnalyzedVersion],
    ctx: &CandidateScoringContext<'_>,
    eligible: &[usize],
) -> io::Result<Vec<(usize, f64)>> {
    let (ts_min, ts_max, max_total_obs, max_bins) =
        version_population_bounds(eligible.iter().map(|index| &versions[*index]));
    eligible
        .iter()
        .map(|index| {
            let score = score_candidate_version(
                rt,
                &versions[*index],
                ctx,
                ts_min,
                ts_max,
                max_total_obs,
                max_bins,
            )?;
            Ok((*index, score))
        })
        .collect()
}

/// Explicit observations take precedence; otherwise inferred binary support
/// is primary when configured. Only validated live candidates are eligible.
/// Returns true when explicit observations determined the eligible pool.
fn retain_binary_compatible_candidates(
    rt: &EngineRuntime,
    versions: &[AnalyzedVersion],
    ctx: &CandidateScoringContext<'_>,
    eligible: &mut Vec<usize>,
) -> io::Result<bool> {
    if let Some(md5) = ctx.md5 {
        if let Some(stats) = rt.ctx_index.get_positive_key_md5_stats(ctx.key, &md5)? {
            if eligible
                .iter()
                .any(|i| versions[*i].matches_id(&stats.last_version_id))
            {
                eligible.retain(|i| versions[*i].matches_id(&stats.last_version_id));
                return Ok(true);
            }
        }
        let mut observed = HashSet::new();
        for &i in eligible.iter() {
            if version_observed_in(rt, &versions[i], &md5)? {
                observed.insert(i);
            }
        }
        if !observed.is_empty() {
            eligible.retain(|i| observed.contains(i));
            return Ok(true);
        }
    }
    if rt.scoring.binary_priority {
        let best = inferred_priority_floor(rt, versions);
        // Absolute tolerance in evidence-mass units, solely for numerical ties.
        // It is not a calibrated confidence threshold.
        const TIE_TOLERANCE: f64 = 1e-12;
        if best > TIE_TOLERANCE {
            eligible.retain(|i| best - versions[*i].binary_match <= TIE_TOLERANCE);
        }
    }
    Ok(false)
}

fn inferred_priority_floor(rt: &EngineRuntime, versions: &[AnalyzedVersion]) -> f64 {
    if !rt.scoring.binary_priority {
        return 0.0;
    }
    versions
        .iter()
        .map(|v| {
            if rt.scoring.binary_single_key_tolerance {
                v.binary_priority_floor
            } else {
                v.binary_match
            }
        })
        .fold(0.0, f64::max)
}

fn version_observed_in(
    rt: &EngineRuntime,
    version: &AnalyzedVersion,
    md5: &[u8; 16],
) -> io::Result<bool> {
    Ok(version
        .stats
        .as_ref()
        .is_some_and(|stats| stats.top_md5s.iter().any(|e| e.md5 == *md5))
        || rt.ctx_index.binary_has_version(md5, &version.version_id)?
        || rt
            .ctx_index
            .binary_has_version(md5, &version.legacy_version_id)?)
}

/// Each inferred binary contributes its weight once. A retrievable last-observed
/// variant receives that weight; otherwise historical candidates share it. The
/// target's own key contributed no weight to binary inference. No normalization
/// restores mass from omitted binaries or unavailable candidates.
/// Also retain the strongest individual binary match: many weaker sibling
/// binaries must not outweigh one binary matching more of the query.
fn assign_binary_support(
    rt: &EngineRuntime,
    versions: &mut [AnalyzedVersion],
    weights: &HashMap<[u8; 16], f64>,
    last_versions: &HashMap<[u8; 16], [u8; 32]>,
    family: &BatchFamilyEvidence,
    key: u128,
) -> io::Result<()> {
    for version in versions.iter_mut() {
        version.binary_support = 0.0;
        version.binary_match = 0.0;
        version.binary_priority_floor = 0.0;
    }
    let mut binaries: Vec<_> = weights.iter().collect();
    binaries.sort_unstable_by_key(|(md5, _)| **md5);
    for (md5, weight) in binaries {
        let mut eligible: Vec<_> = versions
            .iter()
            .enumerate()
            .filter(|(_, version)| {
                last_versions
                    .get(md5)
                    .is_some_and(|id| version.matches_id(id))
            })
            .map(|(i, _)| i)
            .collect();
        if eligible.is_empty() {
            for (i, version) in versions.iter().enumerate() {
                if version_observed_in(rt, version, md5)? {
                    eligible.push(i);
                }
            }
        }
        if !eligible.is_empty() {
            let share = weight / eligible.len() as f64;
            let floor = family.priority_floor(key, md5, *weight);
            for i in eligible {
                versions[i].binary_support += share;
                versions[i].binary_match = versions[i].binary_match.max(*weight);
                versions[i].binary_priority_floor = versions[i].binary_priority_floor.max(floor);
            }
        }
    }
    Ok(())
}

fn version_population_bounds<'a>(
    versions: impl IntoIterator<Item = &'a AnalyzedVersion>,
) -> (u64, u64, u32, u32) {
    let mut versions = versions.into_iter();
    let Some(first) = versions.next() else {
        return (0, 0, 1, 1);
    };
    let mut ts_min = first.rec.ts_sec;
    let mut ts_max = ts_min;
    let mut max_total_obs = 1;
    let mut max_bins = 1;
    for version in std::iter::once(first).chain(versions) {
        ts_min = ts_min.min(version.rec.ts_sec);
        ts_max = ts_max.max(version.rec.ts_sec);
        if let Some(stats) = &version.stats {
            max_total_obs = max_total_obs.max(stats.total_obs);
            max_bins = max_bins
                .max(stats.num_binaries)
                .max(stats.top_md5s.len() as u32);
        }
    }
    (ts_min, ts_max, max_total_obs, max_bins)
}

type ReplayQueryContext = (
    Option<[u8; 16]>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn replay_query_context(
    rt: &EngineRuntime,
    version: &AnalyzedVersion,
) -> io::Result<ReplayQueryContext> {
    let Some(version_stats) = &version.stats else {
        return Ok((None, None, None, None));
    };
    let Some(top_md5) = version_stats.top_md5s.first().map(|entry| entry.md5) else {
        return Ok((None, None, None, None));
    };
    let Some(meta) = rt.ctx_index.get_binary_meta(&top_md5)? else {
        return Ok((Some(top_md5), None, None, None));
    };
    Ok((
        Some(top_md5),
        (!meta.basename.is_empty()).then_some(meta.basename),
        (!meta.hostname.is_empty()).then_some(meta.hostname),
        (!meta.origin_token.is_empty()).then_some(meta.origin_token),
    ))
}

fn score_entropy(scored: &[(usize, f64)]) -> f64 {
    if scored.len() <= 1 {
        return 0.0;
    }
    let max_score = scored
        .iter()
        .map(|(_, score)| *score)
        .fold(f64::NEG_INFINITY, f64::max);
    let weights: Vec<f64> = scored
        .iter()
        .map(|(_, score)| (score - max_score).exp())
        .collect();
    let sum: f64 = weights.iter().sum();
    if sum <= f64::EPSILON {
        return 1.0;
    }
    let mut entropy = 0.0;
    for weight in weights {
        let p = weight / sum;
        if p > f64::EPSILON {
            entropy -= p * p.ln();
        }
    }
    let denom = (scored.len() as f64).ln();
    if denom <= f64::EPSILON {
        0.0
    } else {
        (entropy / denom).clamp(0.0, 1.0)
    }
}

fn semantic_neighbor_similarity(
    seed_analysis: &SemanticAnalysis,
    seed_doc: &SearchDocument,
    candidate_analysis: &SemanticAnalysis,
    candidate_doc: &SearchDocument,
    family_ctx: &NeighborFamilyContext,
    candidate_binary_metas: &[&crate::engine::BinaryMeta],
    lexical_prior: f64,
) -> Option<SemanticNeighborScore> {
    let semantic_overlap = semantic_token_dice_score(
        &seed_analysis.fingerprint.tokens,
        &candidate_analysis.fingerprint.tokens,
    );
    let prototype_overlap = semantic_token_dice_score(
        &seed_analysis.fingerprint.prototype_tokens,
        &candidate_analysis.fingerprint.prototype_tokens,
    );
    let frame_overlap = semantic_token_dice_score(
        &seed_analysis.fingerprint.frame_tokens,
        &candidate_analysis.fingerprint.frame_tokens,
    );
    let comment_overlap = semantic_token_dice_score(
        &seed_analysis.fingerprint.comment_tokens,
        &candidate_analysis.fingerprint.comment_tokens,
    );
    let operand_overlap = semantic_token_dice_score(
        &seed_analysis.fingerprint.operand_tokens,
        &candidate_analysis.fingerprint.operand_tokens,
    );
    let origin_overlap = token_dice_score(&seed_doc.origin_tokens, &candidate_doc.origin_tokens);
    let binary_overlap = token_dice_score(&seed_doc.binary_names, &candidate_doc.binary_names);
    // A historical vocabulary hit is only a candidate. The annotation actually
    // selected for this request must supply semantic/origin evidence itself;
    // shared binary membership cannot validate an unrelated visible annotation.
    if semantic_overlap == 0.0
        && prototype_overlap == 0.0
        && frame_overlap == 0.0
        && comment_overlap == 0.0
        && operand_overlap == 0.0
        && origin_overlap == 0.0
    {
        let seed_components = batch_fingerprint(&seed_doc.func_name, seed_analysis);
        let candidate_components = batch_fingerprint(&candidate_doc.func_name, candidate_analysis);
        if semantic_token_intersection_count(&seed_components.tokens, &candidate_components.tokens)
            == 0
        {
            return None;
        }
    }
    let lexical = (lexical_prior / 10.0).clamp(0.0, 1.0);
    let (
        direct_binary_score,
        related_binary_score,
        direct_family_binaries,
        related_family_binaries,
    ) = family_support_rationale(family_ctx, candidate_binary_metas);
    let family_score = direct_binary_score.max(related_binary_score * 0.92);

    let intersection = semantic_token_intersection_count(
        &seed_analysis.fingerprint.tokens,
        &candidate_analysis.fingerprint.tokens,
    );
    if intersection < 2
        && prototype_overlap < 0.12
        && frame_overlap < 0.12
        && comment_overlap < 0.12
        && operand_overlap < 0.12
        && origin_overlap < 0.2
        && binary_overlap < 0.2
        && family_score < 0.18
    {
        return None;
    }

    if family_score < 0.08
        && semantic_overlap < 0.22
        && prototype_overlap < 0.18
        && frame_overlap < 0.18
        && comment_overlap < 0.18
        && operand_overlap < 0.18
    {
        return None;
    }

    let language_match = !seed_analysis.fingerprint.language.is_empty()
        && !candidate_analysis.fingerprint.language.is_empty()
        && seed_analysis.fingerprint.language == candidate_analysis.fingerprint.language;
    let language_bonus = match (
        seed_analysis.fingerprint.language.is_empty(),
        candidate_analysis.fingerprint.language.is_empty(),
        language_match,
    ) {
        (false, false, true) => 0.08,
        (false, false, false) => -0.03,
        _ => 0.0,
    };

    let candidate_consistency = candidate_analysis.consistency_score.clamp(0.0, 1.0);
    let final_score = (0.28 * semantic_overlap
        + 0.18 * prototype_overlap
        + 0.1 * frame_overlap
        + 0.08 * comment_overlap
        + 0.07 * operand_overlap
        + 0.04 * origin_overlap
        + 0.03 * binary_overlap
        + 0.04 * lexical
        + 0.14 * family_score
        + 0.08 * candidate_consistency
        + language_bonus)
        .clamp(0.0, 1.0);

    Some(SemanticNeighborScore {
        final_score,
        rationale: SemanticNeighborRationale {
            family_score: family_score as f32,
            direct_binary_score: direct_binary_score as f32,
            related_binary_score: related_binary_score as f32,
            lexical_prior: lexical as f32,
            semantic_overlap: semantic_overlap as f32,
            prototype_overlap: prototype_overlap as f32,
            frame_overlap: frame_overlap as f32,
            comment_overlap: comment_overlap as f32,
            operand_overlap: operand_overlap as f32,
            origin_overlap: origin_overlap as f32,
            binary_name_overlap: binary_overlap as f32,
            candidate_consistency: candidate_consistency as f32,
            language_match,
            shared_semantic_tokens: shared_ranked_tokens(
                &seed_analysis.fingerprint.tokens,
                &candidate_analysis.fingerprint.tokens,
                6,
            ),
            shared_prototype_tokens: shared_ranked_tokens(
                &seed_analysis.fingerprint.prototype_tokens,
                &candidate_analysis.fingerprint.prototype_tokens,
                4,
            ),
            shared_frame_tokens: shared_ranked_tokens(
                &seed_analysis.fingerprint.frame_tokens,
                &candidate_analysis.fingerprint.frame_tokens,
                4,
            ),
            shared_comment_tokens: shared_ranked_tokens(
                &seed_analysis.fingerprint.comment_tokens,
                &candidate_analysis.fingerprint.comment_tokens,
                4,
            ),
            shared_operand_tokens: shared_ranked_tokens(
                &seed_analysis.fingerprint.operand_tokens,
                &candidate_analysis.fingerprint.operand_tokens,
                4,
            ),
            direct_family_binaries,
            related_family_binaries,
        },
    })
}

fn token_dice_score(lhs: &[String], rhs: &[String]) -> f64 {
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }
    let lhs_set: HashSet<&str> = lhs.iter().map(String::as_str).collect();
    let rhs_set: HashSet<&str> = rhs.iter().map(String::as_str).collect();
    let intersection = lhs_set.intersection(&rhs_set).count();
    if intersection == 0 {
        0.0
    } else {
        (2.0 * intersection as f64) / ((lhs_set.len() + rhs_set.len()) as f64)
    }
}

fn semantic_token_dice_score(lhs: &[String], rhs: &[String]) -> f64 {
    let lhs_set = filtered_neighbor_token_set(lhs);
    let rhs_set = filtered_neighbor_token_set(rhs);
    if lhs_set.is_empty() || rhs_set.is_empty() {
        return 0.0;
    }
    let intersection = lhs_set.intersection(&rhs_set).count();
    if intersection == 0 {
        0.0
    } else {
        (2.0 * intersection as f64) / ((lhs_set.len() + rhs_set.len()) as f64)
    }
}

fn semantic_token_intersection_count(lhs: &[String], rhs: &[String]) -> usize {
    let lhs_set = filtered_neighbor_token_set(lhs);
    let rhs_set = filtered_neighbor_token_set(rhs);
    lhs_set.intersection(&rhs_set).count()
}

fn family_support_rationale(
    family_ctx: &NeighborFamilyContext,
    candidate_binary_metas: &[&crate::engine::BinaryMeta],
) -> (f64, f64, Vec<BinaryRefHit>, Vec<BinaryRefHit>) {
    let mut direct_binary_score: f64 = 0.0;
    let mut related_binary_score: f64 = 0.0;
    let mut direct_family_binaries = Vec::new();
    let mut related_family_binaries = Vec::new();

    for meta in candidate_binary_metas {
        if let Some(weight) = family_ctx.direct_weights.get(&meta.md5) {
            direct_binary_score = direct_binary_score.max(*weight);
            direct_family_binaries.push(binary_ref_hit_from_meta(meta));
            continue;
        }
        if let Some(weight) = family_ctx.related_weights.get(&meta.md5) {
            related_binary_score = related_binary_score.max(*weight);
            related_family_binaries.push(binary_ref_hit_from_meta(meta));
        }
    }

    dedup_binary_refs(&mut direct_family_binaries);
    dedup_binary_refs(&mut related_family_binaries);
    direct_family_binaries.truncate(3);
    related_family_binaries.truncate(3);

    (
        direct_binary_score,
        related_binary_score,
        direct_family_binaries,
        related_family_binaries,
    )
}

fn shared_ranked_tokens(lhs: &[String], rhs: &[String], limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let lhs_set: HashSet<&str> = lhs.iter().map(String::as_str).collect();
    let rhs_set: HashSet<&str> = rhs.iter().map(String::as_str).collect();
    let mut shared: Vec<String> = lhs_set
        .intersection(&rhs_set)
        .copied()
        .filter(|token| !is_generic_neighbor_token(token))
        .map(|token| (*token).to_string())
        .collect();
    shared.sort_by(|a, b| {
        neighbor_token_rank(b)
            .partial_cmp(&neighbor_token_rank(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| a.cmp(b))
    });
    shared.truncate(limit);
    shared
}

fn filtered_neighbor_token_set(tokens: &[String]) -> HashSet<&str> {
    tokens
        .iter()
        .map(String::as_str)
        .filter(|token| !is_generic_neighbor_token(token))
        .collect()
}

fn neighbor_token_rank(token: &str) -> f64 {
    let mut score = match token.len() {
        0..=3 => 0.4,
        4..=5 => 0.7,
        6..=9 => 1.0,
        10..=15 => 1.25,
        _ => 1.45,
    };
    if token.contains('_') {
        score += 0.12;
    }
    if token.chars().any(|ch| ch.is_ascii_digit()) {
        score += 0.04;
    }
    score
}

fn binary_ref_hit_from_meta(meta: &crate::engine::BinaryMeta) -> BinaryRefHit {
    BinaryRefHit {
        md5_hex: hex_md5(&meta.md5),
        short_id: short_md5(&meta.md5),
        basename: basename_only(&meta.basename),
        display_name: format!("{}#{}", basename_only(&meta.basename), short_md5(&meta.md5)),
    }
}

fn dedup_binary_refs(items: &mut Vec<BinaryRefHit>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.md5_hex.clone()));
}

#[derive(Clone, Copy)]
struct CandidateScoringContext<'a> {
    capture_candidates: bool,
    suppress_observation_priors: bool,
    contrastive_anchors: bool,
    key: u128,
    md5: Option<[u8; 16]>,
    basename: Option<&'a str>,
    hostname: Option<&'a str>,
    origin_token: Option<&'a str>,
    requested_mdkeys: &'a [u32],
    anchor_token_weights: &'a HashMap<String, f64>,
    /// Whole-token evidence alone may relax inferred binary priority.
    priority_anchor_weights: &'a HashMap<String, f64>,
    corroboration_weights: &'a HashMap<String, f64>,
    canonical_hint: Option<[u8; 32]>,
}

fn score_candidate_version(
    rt: &EngineRuntime,
    version: &AnalyzedVersion,
    ctx: &CandidateScoringContext<'_>,
    ts_min: u64,
    ts_max: u64,
    max_total_obs: u32,
    max_bins: u32,
) -> io::Result<f64> {
    let version_stats = &version.stats;

    let s_md5 = if let Some(md5q) = ctx.md5 {
        match rt.ctx_index.get_positive_key_md5_stats(ctx.key, &md5q)? {
            Some(st) if version.matches_id(&st.last_version_id) => 1.0,
            _ => {
                if version_observed_in(rt, version, &md5q)? {
                    0.5
                } else {
                    0.0
                }
            }
        }
    } else {
        0.0
    };

    let mut s_name = 0.0f64;
    let mut s_host = 0.0f64;
    let mut s_origin = 0.0f64;
    let normalized_origin = ctx.origin_token.map(normalize_origin_token);
    if let Some(vs) = version_stats
        .as_ref()
        .filter(|_| ctx.basename.is_some() || ctx.hostname.is_some() || normalized_origin.is_some())
    {
        for entry in vs.top_md5s.iter().take(rt.scoring.max_md5_per_version) {
            if let Ok(Some(meta)) = rt.ctx_index.get_binary_meta(&entry.md5) {
                if let Some(bq) = ctx.basename {
                    s_name = s_name.max(name_suffix_similarity(&meta.basename, bq));
                }
                if let Some(hq) = ctx.hostname {
                    s_host = s_host.max(name_suffix_similarity(&meta.hostname, hq));
                }
                if let Some(oq) = normalized_origin.as_deref() {
                    s_origin = s_origin.max(name_suffix_similarity(&meta.origin_token, oq));
                }
            }
        }
    }

    let s_coh = version.binary_support.clamp(0.0, 1.0);

    let s_stab = version_stats
        .as_ref()
        .map(|vs| (vs.total_obs as f64) / ((max_total_obs as f64) + f64::EPSILON))
        .unwrap_or(0.5);

    let s_rec = if ts_max == ts_min {
        1.0
    } else {
        (version.rec.ts_sec.saturating_sub(ts_min) as f64) / ((ts_max - ts_min) as f64)
    };

    let s_pop_bin = version_stats
        .as_ref()
        .map(|vs| {
            let nb = if vs.num_binaries == 0 {
                vs.top_md5s.len() as u32
            } else {
                vs.num_binaries
            };
            let denom = (1.0 + (max_bins as f64)).ln();
            if denom > 0.0 {
                ((1.0 + (nb as f64)).ln()) / denom
            } else {
                0.5
            }
        })
        .unwrap_or(0.5);

    let s_req = if ctx.requested_mdkeys.is_empty() {
        if version.analysis().metadata.raw_chunks.is_empty() {
            0.0
        } else {
            1.0
        }
    } else {
        (version
            .analysis()
            .metadata
            .requested_coverage(ctx.requested_mdkeys) as f64)
            / (ctx.requested_mdkeys.len() as f64)
    };

    let s_sem = (version.analysis().quality_score / 8.0).clamp(0.0, 1.0);
    let s_cons = version.analysis().consistency_score.clamp(0.0, 1.0);
    let s_anchor = if ctx.contrastive_anchors {
        contrastive_support(
            &version.anchor_fingerprint().tokens,
            ctx.anchor_token_weights,
        )
    } else {
        fingerprint_similarity(
            &version.analysis().fingerprint.tokens,
            ctx.anchor_token_weights,
        )
        .clamp(0.0, 1.0)
    };
    let s_can = if ctx.canonical_hint.is_some_and(|id| version.matches_id(&id)) {
        1.0
    } else {
        0.0
    };

    let w = &rt.scoring;
    let (s_stab, s_rec, s_pop_bin, s_can) = if ctx.suppress_observation_priors {
        (0.0, 0.0, 0.0, 0.0)
    } else {
        (s_stab, s_rec, s_pop_bin, s_can)
    };
    let score = w.w_md5 * s_md5
        + w.w_name * s_name
        + w.w_coh * s_coh
        + w.w_stab * s_stab
        + w.w_rec * s_rec
        + w.w_pop_bin * s_pop_bin
        + w.w_host * s_host
        + w.w_origin * s_origin
        + 1.25 * s_req
        + 0.75 * s_sem
        + 0.85 * s_cons
        + 0.75 * s_anchor
        + 0.5 * s_can;

    Ok(score)
}

fn now_ts_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn name_suffix_similarity(a: &str, b: &str) -> f64 {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = ab.len();
    let mut j = bb.len();
    let mut l = 0usize;
    while i > 0 && j > 0 {
        let ca = ab[i - 1].to_ascii_lowercase();
        let cb = bb[j - 1].to_ascii_lowercase();
        if ca == cb {
            l += 1;
            i -= 1;
            j -= 1;
        } else {
            break;
        }
    }
    let denom = ab.len().max(bb.len()) as f64;
    if denom <= 0.0 {
        0.0
    } else {
        (l as f64) / denom
    }
}

fn hex_md5(md5: &[u8; 16]) -> String {
    md5.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn short_md5(md5: &[u8; 16]) -> String {
    hex_md5(md5)[0..8].to_string()
}

fn parse_md5_hex_local(md5_hex: &str) -> Option<[u8; 16]> {
    if md5_hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in md5_hex.as_bytes().chunks(2).enumerate() {
        out[idx] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

fn score_binary_meta(meta: &crate::engine::BinaryMeta, alias_score: u8) -> f32 {
    f32::from(alias_score)
        + (meta.function_count.min(10_000) as f32).ln_1p() * 6.0
        + (meta.obs_count.min(1_000_000) as f32).ln_1p()
}

fn binary_summary_from_meta(meta: &crate::engine::BinaryMeta, score: f32) -> BinarySummary {
    let facet_hint = BinaryFacetSummary::default();
    let basename = basename_only(&meta.basename);
    BinarySummary {
        md5_hex: hex_md5(&meta.md5),
        short_id: short_md5(&meta.md5),
        basename: basename.clone(),
        display_name: format!("{} · {}", basename, short_md5(&meta.md5)),
        hostname: meta.hostname.clone(),
        first_seen_ts: meta.first_seen_ts,
        last_seen_ts: meta.last_seen_ts,
        obs_count: meta.obs_count,
        function_count: meta.function_count,
        version_count: meta.version_count,
        host_count: meta.host_count,
        typed_functions: facet_hint.typed_functions,
        commented_functions: facet_hint.commented_functions,
        switch_functions: facet_hint.switch_functions,
        coverage: None,
        score,
    }
}

fn basename_only(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    normalized.rsplit('/').next().unwrap_or(name).to_string()
}

fn metadata_richness(data: &[u8]) -> usize {
    let parsed = parse_metadata(data);
    usize::from(parsed.type_parts.is_some())
        + usize::from(parsed.frame_desc.is_some())
        + usize::from(parsed.fcmt.is_some() || parsed.frptcmt.is_some())
        + usize::from(!parsed.insn_cmts.is_empty() || !parsed.rpt_insn_cmts.is_empty())
        + usize::from(!parsed.extra_cmts.is_empty())
        + usize::from(parsed.user_stkpnts.is_some())
        + usize::from(parsed.ops.is_some() || parsed.ops_ex.is_some())
        + usize::from(parsed.vd_elapsed.is_some())
        + usize::from(parsed.errors.is_empty())
}

fn compare_item_latest_ts(item: &BinaryCompareItem) -> u64 {
    item.left
        .iter()
        .chain(&item.right)
        .map(|v| v.ts)
        .max()
        .unwrap_or(0)
}

fn compare_item_richness(item: &BinaryCompareItem) -> usize {
    item.left
        .iter()
        .chain(&item.right)
        .map(|v| v.richness_score)
        .max()
        .unwrap_or(0)
}

fn sort_compare_items(items: &mut [BinaryCompareItem]) {
    items.sort_by(|a, b| {
        compare_item_latest_ts(b)
            .cmp(&compare_item_latest_ts(a))
            .then_with(|| a.rarity_score.cmp(&b.rarity_score))
            .then_with(|| compare_item_richness(b).cmp(&compare_item_richness(a)))
            .then_with(|| a.key_hex.cmp(&b.key_hex))
    });
}
