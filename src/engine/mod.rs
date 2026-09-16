mod context_index;
pub(crate) use context_index::{merge_alias_stats, VersionStats};
mod counted_tree;
mod crc32c;
pub(crate) mod facet_cache;
mod index;
pub mod search;
mod segment;
mod visibility;
pub(crate) use visibility::MAX_HISTORY_RECORDS;
pub use visibility::{resolve_visible_record, resolve_visible_record_with_policy};

pub use context_index::{BinaryMeta, BinaryOverlapEntry, CanonicalVersion, ContextIndex};
pub use index::{migrate_legacy_index_files, IndexError, ShardedIndex, UpsertResult};
pub use search::{
    rebuild_from_engine, BinaryRefHit, SearchDocument, SearchHit, SearchIndex,
    SemanticNeighborRationale,
};
pub use segment::{OpenSegments, Record, REC_FLAG_DECLARED_SIZE, REC_FLAG_DELETED};

use crate::config::{Engine, NameRejection, Scoring};
use std::{io, path::PathBuf, sync::Arc};

/// One atomic publication binds a completed generation to its admission policy.
#[derive(serde::Serialize, serde::Deserialize)]
struct ProjectionManifest {
    generation: String,
    name_rejection: NameRejection,
}

#[derive(Clone)]
pub struct EngineRuntime {
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub segments: Arc<OpenSegments>,
    pub index: Arc<ShardedIndex>,
    pub ctx_index: Arc<ContextIndex>,
    pub search: Arc<SearchIndex>,
    pub index_db: sled::Db,
    #[allow(dead_code)]
    pub cfg: Engine,
    #[allow(dead_code)]
    pub scoring: Scoring,
    pub(crate) projection_compatible: bool,
}

impl EngineRuntime {
    pub fn open(cfg: Engine, scoring: Scoring) -> io::Result<Self> {
        Self::open_inner(cfg, scoring, false, false, false)
    }

    pub fn open_for_replay(cfg: Engine, scoring: Scoring) -> io::Result<Self> {
        Self::open_inner(cfg, scoring, false, false, true)
    }

    /// Explicit offline maintenance. Keep the original database intact.
    pub fn prepare(cfg: Engine, scoring: Scoring) -> io::Result<Self> {
        Self::open_inner(cfg, scoring, true, false, false)
    }

    /// Explicitly exclude unreadable keys from the derived projection and report each one.
    /// Raw records, latest pointers and observations are retained.
    pub fn prepare_salvage(cfg: Engine, scoring: Scoring) -> io::Result<Self> {
        Self::open_inner(cfg, scoring, true, true, false)
    }

    fn open_inner(
        cfg: Engine,
        scoring: Scoring,
        prepare: bool,
        salvage: bool,
        replay: bool,
    ) -> io::Result<Self> {
        let started = std::time::Instant::now();
        std::fs::create_dir_all(&cfg.data_dir)?;
        let dir = PathBuf::from(&cfg.data_dir);
        let index_dir = if let Some(ref override_dir) = cfg.index_dir {
            PathBuf::from(override_dir)
        } else {
            dir.join("index")
        };
        std::fs::create_dir_all(&index_dir)?;

        if prepare {
            migrate_legacy_index_files(&index_dir)?;
        }

        let open_segments = || {
            let segments =
                OpenSegments::open_mode(&dir, cfg.segment_bytes, cfg.use_mmap_reads, prepare)?;
            log::info!(
                "startup phase=segments elapsed_s={:.6}",
                started.elapsed().as_secs_f64()
            );
            Ok::<_, io::Error>(Arc::new(segments))
        };
        let open_index = || {
            let db = sled::Config::default()
                .path(&index_dir)
                .cache_capacity(64 * 1024 * 1024)
                .flush_every_ms(Some(500))
                .open()
                .map_err(|e| io::Error::other(format!("sled open index db: {e}")))?;
            let index = Arc::new(ShardedIndex::open(&db, prepare)?);
            log::info!(
                "startup phase=index_open elapsed_s={:.6}",
                started.elapsed().as_secs_f64()
            );
            Ok::<_, io::Error>((db, index))
        };
        // Existing stores are independent until their cross-store checks below.
        // Do not create a missing context store before validating latest/records.
        let (segments, (index_db, index), ready_context) = if prepare {
            (open_segments()?, open_index()?, None)
        } else {
            std::thread::scope(|scope| {
                let segments = scope.spawn(open_segments);
                let index = scope.spawn(open_index);
                let context = scope.spawn(|| -> io::Result<Option<Arc<ContextIndex>>> {
                    if dir.join("context_db").exists() {
                        let context = ContextIndex::open_ready(&dir)?;
                        log::info!(
                            "startup phase=context_open elapsed_s={:.6}",
                            started.elapsed().as_secs_f64()
                        );
                        Ok(Some(Arc::new(context)))
                    } else {
                        Ok(None)
                    }
                });
                // Join every worker before propagating a failure and dropping handles.
                let segments = segments.join();
                let index = index.join();
                let context = context.join();
                let panic_error = |_| io::Error::other("storage open worker panicked");
                Ok::<_, io::Error>((
                    segments.map_err(panic_error)??,
                    index.map_err(panic_error)??,
                    context.map_err(panic_error)??,
                ))
            })?
        };

        if index.is_empty()? && segments.get_record_count()? > 0 {
            if !prepare {
                return Err(io::Error::other(
                    "missing latest index; run offline preparation",
                ));
            }
            segments.rebuild_index(&index)?;
        }
        log::info!(
            "startup phase=latest elapsed_s={:.6}",
            started.elapsed().as_secs_f64()
        );

        // If index is empty AND context db is missing, this is likely a fresh instance.
        // Create it automatically to avoid crashing on fresh starts.
        let ctx_index = if let Some(context) = ready_context {
            context
        } else if !dir.join("context_db").exists() && !index.is_empty()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "context_db missing; original observations cannot be reconstructed completely",
            ));
        } else if prepare {
            Arc::new(ContextIndex::open_or_create(&dir)?)
        } else {
            Arc::new(ContextIndex::open_ready(&dir)?)
        };
        log::info!(
            "startup phase=context elapsed_s={:.6}",
            started.elapsed().as_secs_f64()
        );

        let mut existing_generation = None;
        let mut projection_compatible = prepare;
        if !prepare {
            if let Some(value) = index_db.get(b"canonical_projection_v4")? {
                let manifest: ProjectionManifest = serde_json::from_slice(&value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                projection_compatible = manifest.name_rejection == cfg.name_rejection;
                if manifest.name_rejection != cfg.name_rejection {
                    if !replay {
                        return Err(io::Error::other(
                            "search projection name policy changed; run offline preparation",
                        ));
                    }
                    log::warn!("replay search projection uses a different name policy; search results require offline preparation");
                }
                existing_generation = Some(manifest.generation);
            } else {
                for key in [
                    b"canonical_projection_v3",
                    b"canonical_projection_v2",
                    b"canonical_projection_v1",
                ] {
                    if let Some(value) = index_db.get(key)? {
                        if !replay {
                            return Err(io::Error::other("search projection has no certified name policy; run offline preparation"));
                        }
                        existing_generation = Some(
                            std::str::from_utf8(&value)
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                                .to_owned(),
                        );
                        log::warn!("replay opened legacy search projection without a certified name policy; search results require offline preparation");
                        break;
                    }
                }
            }
        }
        let fresh_projection = existing_generation.is_none() && !dir.join("search_index").exists();
        let generation = if prepare {
            format!(
                "search_index.prepared-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_nanos()
            )
        } else if let Some(ref name) = existing_generation {
            if !name.starts_with("search_index") || name.contains('/') || name.contains('\\') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid search generation",
                ));
            }
            name.to_owned()
        } else if index.is_empty()?
            && segments.get_record_count()? == 0
            && (replay || fresh_projection)
        {
            "search_index".to_owned()
        } else {
            return Err(io::Error::other(
                "canonical search projection requires dazhbog --prepare CONFIG on an offline copy",
            ));
        };
        let search_dir = dir.join(&generation);
        if !prepare && existing_generation.is_some() && !search_dir.join("meta.json").exists() {
            return Err(io::Error::other(
                "prepared search generation is missing; run preparation",
            ));
        }
        let search = Arc::new(SearchIndex::open(&search_dir)?);
        if !replay && !search.has_variant_vocabulary() {
            return Err(io::Error::other(
                "variant search projection requires offline preparation",
            ));
        }

        let rt = Self {
            dir,
            segments,
            index,
            ctx_index,
            search,
            index_db,
            cfg,
            scoring,
            projection_compatible: projection_compatible || fresh_projection,
        };
        if prepare {
            let quarantine = search_dir.join("quarantine.jsonl");
            crate::db::Database::rebuild_search_projection(
                &rt,
                salvage.then_some(quarantine.as_path()),
            )?;
        }
        if (prepare || fresh_projection) && rt.search.has_variant_vocabulary() {
            rt.flush()?;
            let manifest = ProjectionManifest {
                generation,
                name_rejection: rt.cfg.name_rejection,
            };
            rt.index_db
                .insert(b"canonical_projection_v4", serde_json::to_vec(&manifest)?)?;
            rt.index_db.flush()?;
        }
        log::info!(
            "startup phase=search elapsed_s={:.6}",
            started.elapsed().as_secs_f64()
        );
        Ok(rt)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.search.commit()?;
        self.segments.flush()?;
        self.ctx_index.flush()?;
        self.index_db.flush()?;
        Ok(())
    }

    /// Get current database statistics for metrics initialization.
    pub fn get_stats(&self) -> io::Result<EngineStats> {
        Ok(EngineStats {
            indexed_funcs: self.index.entry_count()?,
            total_records: self.segments.get_record_count()?,
            storage_bytes: self.segments.get_storage_bytes()?,
            search_docs: self.search.doc_count(),
            unique_binaries: self.ctx_index.unique_binaries_count()?,
        })
    }
}

/// Statistics snapshot for metrics initialization.
pub struct EngineStats {
    pub indexed_funcs: u64,
    pub total_records: u64,
    pub storage_bytes: u64,
    pub search_docs: u64,
    pub unique_binaries: u64,
}
