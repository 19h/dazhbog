use log::*;
use std::{io, path::Path};

use crate::db::BinaryFacetSummary;

#[derive(Clone, Debug)]
pub struct BinaryMeta {
    pub md5: [u8; 16],
    pub basename: String,
    pub hostname: String,
    pub origin_token: String,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
    pub obs_count: u64,
    pub function_count: u64,
    pub version_count: u64,
    pub host_count: u64,
}

#[derive(Clone, Debug)]
pub struct BinaryFunctionEntry {
    pub key: u128,
    pub obs_count: u32,
    pub last_ts_sec: u64,
    pub last_version_id: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct KeyMd5Stats {
    pub obs_count: u32,
    pub last_ts_sec: u64,
    pub last_version_id: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct KeyMd5Entry {
    pub md5: [u8; 16],
    pub obs_count: u32,
}

#[derive(Clone, Debug)]
pub struct VersionStats {
    pub total_obs: u32,
    pub first_ts_sec: u64,
    pub last_ts_sec: u64,
    pub num_binaries: u32,
    pub top_md5s: Vec<KeyMd5Entry>,
}

#[derive(Clone, Debug)]
pub struct BinaryOverlapEntry {
    pub md5: [u8; 16],
    pub shared_functions: u64,
}

#[derive(Clone, Debug)]
pub struct CanonicalVersion {
    pub version_id: [u8; 32],
    pub score: f64,
    pub ts_sec: u64,
}

pub struct ContextIndex {
    #[allow(dead_code)]
    db: sled::Db, // Keep db handle alive
    t_key_md5: sled::Tree,                           // key||md5 -> KeyMd5Stats
    t_key_bins: sled::Tree,                          // key -> Vec<KeyMd5Entry>
    t_version_stats: sled::Tree,                     // version_id -> VersionStats
    t_binary_meta: super::counted_tree::CountedTree, // md5 -> BinaryMeta
    t_binary_functions: sled::Tree,                  // md5||key -> KeyMd5Stats
    t_binary_versions: sled::Tree,                   // md5||version_id -> last_ts_sec
    t_binary_name_index: sled::Tree,                 // normalized basename -> Vec<md5>
    t_binary_hosts: sled::Tree,                      // md5||normalized host -> last_ts_sec
    t_binary_facets: sled::Tree,                     // md5 -> cached BinaryFacetSummary
    t_binary_overlap: sled::Tree,                    // md5 -> cached overlap rows
    t_key_basenames: sled::Tree,                     // key -> Vec<String>
    t_key_canonical: sled::Tree,                     // key -> CanonicalVersion
    t_pop_val: sled::Tree,                           // key -> u32 (popularity)
    t_pop_rank: sled::Tree,                          // [u32::MAX - pop][key] -> []
}

const MAX_MD5_PER_KEY: usize = 16;
const MAX_MD5_PER_VERSION: usize = 16;
const MAX_BASENAMES_PER_KEY: usize = 16;

impl ContextIndex {
    /// Open existing context_db for explicit maintenance.
    /// Use `recover --migrate-context` to create it from old data.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let ctx_dir = dir.join("context_db");
        if !ctx_dir.exists() {
            error!("context_db not found at {}", ctx_dir.display());
            error!("Run `recover --migrate-context` to migrate from old index format");
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "context_db missing; recover original context before preparation",
            ));
        }
        Self::open_internal(&ctx_dir, true)
    }

    /// Open or create context_db (for recover tool).
    pub fn open_or_create(dir: &Path) -> io::Result<Self> {
        let ctx_dir = dir.join("context_db");
        std::fs::create_dir_all(&ctx_dir)?;
        Self::open_internal(&ctx_dir, true)
    }

    /// Open context_db directly at the given path (for recover tool migration).
    pub fn open_at_path(ctx_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(ctx_dir)?;
        Self::open_internal(ctx_dir, true)
    }

    pub fn open_ready(dir: &Path) -> io::Result<Self> {
        Self::open_internal(&dir.join("context_db"), false)
    }

    fn open_internal(ctx_dir: &Path, prepare: bool) -> io::Result<Self> {
        debug!("opening context index at {}", ctx_dir.display());
        let db = sled::Config::default()
            .path(ctx_dir)
            .cache_capacity(32 * 1024 * 1024)
            .flush_every_ms(Some(500))
            .open()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("sled open context_db: {e}"))
            })?;

        let t_key_md5 = db
            .open_tree("key_md5")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_key_bins = db
            .open_tree("key_bins")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_version_stats = db
            .open_tree("version_stats")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_meta = super::counted_tree::CountedTree::open(&db, b"binary_meta", prepare);
        let t_binary_functions = db
            .open_tree("binary_functions")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_versions = db
            .open_tree("binary_versions")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_name_index = db
            .open_tree("binary_name_index")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_hosts = db
            .open_tree("binary_hosts")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_facets = db
            .open_tree("binary_facets")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_binary_overlap = db
            .open_tree("binary_overlap")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")));
        let t_key_basenames = db
            .open_tree("key_basenames")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")))?;
        let t_key_canonical = db
            .open_tree("key_canonical")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")))?;
        let t_pop_val = db
            .open_tree("pop_val")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")))?;
        let t_pop_rank = db
            .open_tree("pop_rank")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open_tree: {e}")))?;
        info!("context index initialized successfully");
        let out = Self {
            db,
            t_key_md5: t_key_md5?,
            t_key_bins: t_key_bins?,
            t_version_stats: t_version_stats?,
            t_binary_meta: t_binary_meta?,
            t_binary_functions: t_binary_functions?,
            t_binary_versions: t_binary_versions?,
            t_binary_name_index: t_binary_name_index?,
            t_binary_hosts: t_binary_hosts?,
            t_binary_facets: t_binary_facets?,
            t_binary_overlap: t_binary_overlap?,
            t_key_basenames,
            t_key_canonical,
            t_pop_val,
            t_pop_rank,
        };
        if prepare || out.db.get(b"binary_indexes_v1")?.as_deref() != Some(b"complete") {
            if !prepare && !out.approx_is_empty() {
                return Err(io::Error::other(
                    "context indexes require offline preparation",
                ));
            }
            out.ensure_binary_indexes()?;
            out.db.flush()?;
            out.db.insert(b"binary_indexes_v1", b"complete")?;
            out.db.flush()?;
        }
        Ok(out)
    }

    pub fn approx_is_empty(&self) -> bool {
        self.t_key_md5.is_empty() && self.t_version_stats.is_empty()
    }

    fn ensure_binary_indexes(&self) -> io::Result<()> {
        info!("rebuilding binary-centric context indexes");

        {
            for item in self.t_key_md5.iter() {
                let (raw_key, raw_val) = item
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
                if raw_key.len() != 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid key_md5 key during preparation",
                    ));
                }
                let mut md5 = [0u8; 16];
                md5.copy_from_slice(&raw_key[16..32]);
                let stats = match decode_key_md5_stats(&raw_val) {
                    Some(stats) => stats,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid key_md5 value during preparation",
                        ))
                    }
                };
                let bf_key = binary_function_key(
                    &md5,
                    u128::from_le_bytes(raw_key[0..16].try_into().unwrap()),
                );
                self.t_binary_functions
                    .insert(bf_key, encode_key_md5_stats(&stats))?;
                if stats.last_version_id != [0u8; 32] {
                    self.t_binary_versions.insert(
                        binary_version_key(&md5, &stats.last_version_id),
                        &stats.last_ts_sec.to_le_bytes(),
                    )?;
                }
            }
        }

        {
            for item in self.t_binary_meta.iter() {
                let (raw_key, raw_val) = item
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
                if raw_key.len() != 16 {
                    continue;
                }
                let meta = match decode_binary_meta(&raw_val) {
                    Some(meta) => meta,
                    None => continue,
                };
                self.record_binary_name_alias(meta.md5, &meta.basename)?;
                self.record_binary_host(meta.md5, &meta.hostname, meta.last_seen_ts)?;
            }
        }

        for item in self.t_binary_meta.iter() {
            let (raw_key, raw_val) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            if raw_key.len() != 16 {
                continue;
            }
            let mut meta = match decode_binary_meta(&raw_val) {
                Some(meta) => meta,
                None => continue,
            };
            let function_count = self.count_binary_functions(&meta.md5)?;
            let version_count = self.count_binary_versions(&meta.md5)?;
            let host_count = self.count_binary_hosts(&meta.md5)?;
            if meta.function_count != function_count
                || meta.version_count != version_count
                || meta.host_count != host_count
            {
                meta.function_count = function_count;
                meta.version_count = version_count;
                meta.host_count = host_count;
                self.t_binary_meta
                    .insert(meta.md5, encode_binary_meta(&meta))
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}"))
                    })?;
            }
        }

        Ok(())
    }

    /// Retrieve the top N most popular keys and their scores
    pub fn get_top_popular_keys(&self, limit: usize) -> io::Result<Vec<(u128, u32)>> {
        let mut results = Vec::with_capacity(limit);
        for item in self.t_pop_rank.iter().take(limit) {
            let (k, _) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            if k.len() == 20 {
                let pop_inv = u32::from_be_bytes(k[0..4].try_into().unwrap());
                let pop = u32::MAX - pop_inv;
                let key = u128::from_le_bytes(k[4..20].try_into().unwrap());
                results.push((key, pop));
            }
        }
        Ok(results)
    }

    pub fn record_binary_meta(
        &self,
        md5: [u8; 16],
        basename: &str,
        hostname: &str,
        origin_token: &str,
        ts_sec: u64,
    ) -> io::Result<bool> {
        let clean_basename = sanitize_basename(basename);
        let clean_origin = normalize_lookup(origin_token);
        let key = md5;
        let val = self
            .t_binary_meta
            .get(key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let is_new_binary = val.is_none();
        let mut meta = if let Some(v) = val {
            decode_binary_meta(&v).unwrap_or(BinaryMeta {
                md5,
                basename: String::new(),
                hostname: String::new(),
                origin_token: String::new(),
                first_seen_ts: ts_sec,
                last_seen_ts: ts_sec,
                obs_count: 0,
                function_count: 0,
                version_count: 0,
                host_count: 0,
            })
        } else {
            BinaryMeta {
                md5,
                basename: String::new(),
                hostname: String::new(),
                origin_token: String::new(),
                first_seen_ts: ts_sec,
                last_seen_ts: ts_sec,
                obs_count: 0,
                function_count: 0,
                version_count: 0,
                host_count: 0,
            }
        };
        meta.last_seen_ts = meta.last_seen_ts.max(ts_sec);
        meta.obs_count = meta.obs_count.saturating_add(1);
        if meta.basename.is_empty() && !clean_basename.is_empty() {
            meta.basename = clean_basename.clone();
        }
        if meta.hostname.is_empty() {
            meta.hostname = hostname.to_string();
        }
        if meta.origin_token.is_empty() && !clean_origin.is_empty() {
            meta.origin_token = clean_origin;
        }
        self.record_binary_name_alias(md5, &clean_basename)?;
        self.record_binary_host(md5, hostname, ts_sec)?;
        meta.host_count = self.count_binary_hosts(&md5)?;
        let enc = encode_binary_meta(&meta);
        self.t_binary_meta
            .insert(key, enc)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        let _ = self.t_binary_facets.remove(key);
        let _ = self.t_binary_overlap.remove(key);

        Ok(is_new_binary)
    }

    pub fn record_key_observation(
        &self,
        key: u128,
        md5: [u8; 16],
        version_id: Option<[u8; 32]>,
        ts_sec: u64,
        basename: Option<&str>,
    ) -> io::Result<()> {
        let mut key_bytes = [0u8; 32];
        key_bytes[0..16].copy_from_slice(&key.to_le_bytes());
        key_bytes[16..32].copy_from_slice(&md5);

        let now_stats = self
            .t_key_md5
            .get(&key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut st = if let Some(v) = now_stats {
            decode_key_md5_stats(&v).unwrap_or(KeyMd5Stats {
                obs_count: 0,
                last_ts_sec: 0,
                last_version_id: [0u8; 32],
            })
        } else {
            KeyMd5Stats {
                obs_count: 0,
                last_ts_sec: 0,
                last_version_id: [0u8; 32],
            }
        };
        st.obs_count = st.obs_count.saturating_add(1);
        st.last_ts_sec = ts_sec;
        if let Some(vid) = version_id {
            st.last_version_id = vid;
        }
        let enc = encode_key_md5_stats(&st);
        self.t_key_md5
            .insert(&key_bytes, enc)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

        // t_key_bins update
        let key_only = key.to_le_bytes();
        let bins_raw = self
            .t_key_bins
            .get(&key_only)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut bins = if let Some(v) = bins_raw {
            decode_key_bins(&v).unwrap_or_default()
        } else {
            Vec::<KeyMd5Entry>::new()
        };
        let mut found = false;
        for e in &mut bins {
            if e.md5 == md5 {
                e.obs_count = e.obs_count.saturating_add(1);
                found = true;
                break;
            }
        }
        if !found {
            bins.push(KeyMd5Entry { md5, obs_count: 1 });
        }
        bins.sort_by_key(|e| std::cmp::Reverse(e.obs_count));
        if bins.len() > MAX_MD5_PER_KEY {
            bins.truncate(MAX_MD5_PER_KEY);
        }
        let enc_bins = encode_key_bins(&bins);
        self.t_key_bins
            .insert(&key_only, enc_bins)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

        // update popularity ranking
        let new_pop: u32 = bins.iter().map(|e| e.obs_count).sum();
        let old_pop_raw = self.t_pop_val.get(&key_only).unwrap_or(None);
        let old_pop = if let Some(p) = old_pop_raw {
            u32::from_le_bytes(p[0..4].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        if new_pop > old_pop {
            if old_pop > 0 {
                let mut old_rank_key = [0u8; 20];
                old_rank_key[0..4].copy_from_slice(&(u32::MAX - old_pop).to_be_bytes());
                old_rank_key[4..20].copy_from_slice(&key_only);
                let _ = self.t_pop_rank.remove(&old_rank_key);
            }
            let mut new_rank_key = [0u8; 20];
            new_rank_key[0..4].copy_from_slice(&(u32::MAX - new_pop).to_be_bytes());
            new_rank_key[4..20].copy_from_slice(&key_only);
            let _ = self.t_pop_rank.insert(&new_rank_key, &[]);
            let _ = self.t_pop_val.insert(&key_only, &new_pop.to_le_bytes());
        }

        if let Some(bn) = basename {
            self.record_basename_for_key(key, bn)?;
        }

        let bin_key = binary_function_key(&md5, key);
        let existing_bin = self
            .t_binary_functions
            .get(&bin_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut inc_function_count = 0u64;
        let mut bstats = if let Some(v) = existing_bin {
            decode_key_md5_stats(&v).unwrap_or(KeyMd5Stats {
                obs_count: 0,
                last_ts_sec: 0,
                last_version_id: [0u8; 32],
            })
        } else {
            inc_function_count = 1;
            KeyMd5Stats {
                obs_count: 0,
                last_ts_sec: 0,
                last_version_id: [0u8; 32],
            }
        };
        bstats.obs_count = bstats.obs_count.saturating_add(1);
        bstats.last_ts_sec = ts_sec;
        if let Some(vid) = version_id {
            bstats.last_version_id = vid;
        }
        self.t_binary_functions
            .insert(&bin_key, encode_key_md5_stats(&bstats))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;

        let mut inc_version_count = 0u64;
        if let Some(vid) = version_id {
            let version_key = binary_version_key(&md5, &vid);
            let seen = self
                .t_binary_versions
                .contains_key(&version_key)
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("sled contains_key: {e}"))
                })?;
            if !seen {
                inc_version_count = 1;
            }
            self.t_binary_versions
                .insert(version_key, &ts_sec.to_le_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        }
        if inc_function_count > 0 || inc_version_count > 0 {
            self.bump_binary_meta_counts(&md5, inc_function_count, inc_version_count)?;
        }
        let _ = self.t_binary_facets.remove(md5);
        let mut overlap_invalidate = Vec::with_capacity(bins.len() + 1);
        overlap_invalidate.push(md5);
        overlap_invalidate.extend(bins.iter().map(|entry| entry.md5));
        overlap_invalidate.sort();
        overlap_invalidate.dedup();
        for entry_md5 in overlap_invalidate {
            let _ = self.t_binary_overlap.remove(entry_md5);
        }

        // version stats (if provided)
        if let Some(vid) = version_id {
            let cur = self
                .t_version_stats
                .get(&vid)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
            let mut vs = if let Some(v) = cur {
                decode_version_stats(&v).unwrap_or(VersionStats {
                    total_obs: 0,
                    first_ts_sec: ts_sec,
                    last_ts_sec: ts_sec,
                    num_binaries: 0,
                    top_md5s: Vec::new(),
                })
            } else {
                VersionStats {
                    total_obs: 0,
                    first_ts_sec: ts_sec,
                    last_ts_sec: ts_sec,
                    num_binaries: 0,
                    top_md5s: Vec::new(),
                }
            };
            vs.total_obs = vs.total_obs.saturating_add(1);
            if vs.first_ts_sec == 0 {
                vs.first_ts_sec = ts_sec;
            }
            vs.last_ts_sec = vs.last_ts_sec.max(ts_sec);
            let mut seen = false;
            for e in &mut vs.top_md5s {
                if e.md5 == md5 {
                    e.obs_count = e.obs_count.saturating_add(1);
                    seen = true;
                    break;
                }
            }
            if !seen {
                vs.top_md5s.push(KeyMd5Entry { md5, obs_count: 1 });
                if vs.num_binaries < u32::MAX {
                    vs.num_binaries += 1;
                }
            }
            vs.top_md5s.sort_by_key(|e| std::cmp::Reverse(e.obs_count));
            if vs.top_md5s.len() > MAX_MD5_PER_VERSION {
                vs.top_md5s.truncate(MAX_MD5_PER_VERSION);
            }
            let enc = encode_version_stats(&vs);
            self.t_version_stats
                .insert(&vid, enc)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        }

        Ok(())
    }

    pub fn set_canonical_version(
        &self,
        key: u128,
        version_id: [u8; 32],
        score: f64,
        ts_sec: u64,
    ) -> io::Result<()> {
        let key_only = key.to_le_bytes();
        self.t_key_canonical
            .insert(
                &key_only,
                encode_canonical_version(&CanonicalVersion {
                    version_id,
                    score,
                    ts_sec,
                }),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        Ok(())
    }

    pub fn get_canonical_version(&self, key: u128) -> io::Result<Option<CanonicalVersion>> {
        let key_only = key.to_le_bytes();
        match self.t_key_canonical.get(&key_only) {
            Ok(Some(v)) => Ok(decode_canonical_version(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_md5_bins_for_key(&self, key: u128) -> io::Result<Vec<KeyMd5Entry>> {
        trace!("getting md5 bins for key: {}", key);
        let key_only = key.to_le_bytes();
        match self.t_key_bins.get(&key_only) {
            Ok(Some(v)) => Ok(decode_key_bins(&v).unwrap_or_default()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_version_stats(&self, version_id: &[u8; 32]) -> io::Result<Option<VersionStats>> {
        trace!("getting version stats");
        match self.t_version_stats.get(version_id) {
            Ok(Some(v)) => Ok(decode_version_stats(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_binary_meta(&self, md5: &[u8; 16]) -> io::Result<Option<BinaryMeta>> {
        trace!("getting binary meta");
        match self.t_binary_meta.get(md5) {
            Ok(Some(v)) => Ok(decode_binary_meta(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn list_binary_metas(&self) -> io::Result<Vec<BinaryMeta>> {
        let mut metas = Vec::new();
        for item in self.t_binary_meta.iter() {
            let (_, raw_val) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            if let Some(meta) = decode_binary_meta(&raw_val) {
                metas.push(meta);
            }
        }
        Ok(metas)
    }

    pub fn get_key_md5_stats(&self, key: u128, md5: &[u8; 16]) -> io::Result<Option<KeyMd5Stats>> {
        let mut k = [0u8; 32];
        k[0..16].copy_from_slice(&key.to_le_bytes());
        k[16..32].copy_from_slice(md5);
        match self.t_key_md5.get(&k) {
            Ok(Some(v)) => Ok(decode_key_md5_stats(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn get_basenames_for_key(&self, key: u128) -> io::Result<Vec<String>> {
        let key_only = key.to_le_bytes();
        match self.t_key_basenames.get(&key_only) {
            Ok(Some(v)) => Ok(decode_basenames(&v).unwrap_or_default()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn resolve_basenames_for_key(&self, key: u128) -> io::Result<Vec<String>> {
        // Sanitize all basenames to ensure only filenames are returned (no paths)
        // This protects against leaking usernames or directory structure from old data
        let mut names: Vec<String> = self
            .get_basenames_for_key(key)?
            .into_iter()
            .map(|b| sanitize_basename(&b))
            .filter(|b| !b.is_empty())
            .collect();
        let mut seen: std::collections::HashSet<String> =
            names.iter().map(|s| s.to_lowercase()).collect();

        if names.len() < MAX_BASENAMES_PER_KEY {
            let md5_list = self.get_md5_bins_for_key(key)?;
            for entry in md5_list.iter() {
                if let Ok(Some(meta)) = self.get_binary_meta(&entry.md5) {
                    let clean = sanitize_basename(&meta.basename);
                    if !clean.is_empty()
                        && seen.insert(clean.to_lowercase())
                        && names.len() < MAX_BASENAMES_PER_KEY
                    {
                        names.push(clean);
                    }
                }
            }
        }

        Ok(names)
    }

    pub fn get_binary_refs_for_key(&self, key: u128, limit: usize) -> io::Result<Vec<BinaryMeta>> {
        let prefix = key.to_le_bytes();
        let mut out = Vec::new();
        for item in self.t_key_md5.scan_prefix(prefix) {
            let (raw_key, _) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            if raw_key.len() != 32 {
                continue;
            }
            let mut md5 = [0u8; 16];
            md5.copy_from_slice(&raw_key[16..32]);
            if let Some(meta) = self.get_binary_meta(&md5)? {
                out.push(meta);
            }
            if out.len() >= limit {
                break;
            }
        }
        out.sort_by(|a, b| {
            b.obs_count
                .cmp(&a.obs_count)
                .then_with(|| b.last_seen_ts.cmp(&a.last_seen_ts))
                .then_with(|| a.basename.cmp(&b.basename))
        });
        Ok(out)
    }

    pub fn get_binary_function_entries(
        &self,
        md5: &[u8; 16],
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<BinaryFunctionEntry>, usize)> {
        let mut all_entries = Vec::new();
        for item in self.t_binary_functions.scan_prefix(md5) {
            let (raw_key, raw_val) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            if raw_key.len() != 32 {
                continue;
            }
            let key = u128::from_le_bytes(raw_key[16..32].try_into().unwrap());
            if let Some(stats) = decode_key_md5_stats(&raw_val) {
                all_entries.push(BinaryFunctionEntry {
                    key,
                    obs_count: stats.obs_count,
                    last_ts_sec: stats.last_ts_sec,
                    last_version_id: stats.last_version_id,
                });
            }
        }
        all_entries.sort_by(|a, b| {
            b.obs_count
                .cmp(&a.obs_count)
                .then_with(|| b.last_ts_sec.cmp(&a.last_ts_sec))
                .then_with(|| a.key.cmp(&b.key))
        });
        let total = all_entries.len();
        let entries = all_entries.into_iter().skip(offset).take(limit).collect();
        Ok((entries, total))
    }

    pub fn get_binary_function_keys(&self, md5: &[u8; 16], limit: usize) -> io::Result<Vec<u128>> {
        let mut keys = Vec::new();
        for item in self.t_binary_functions.scan_prefix(md5).take(limit) {
            let (raw_key, _) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            if raw_key.len() != 32 {
                continue;
            }
            keys.push(u128::from_le_bytes(raw_key[16..32].try_into().unwrap()));
        }
        Ok(keys)
    }

    pub fn search_binary_meta(&self, query: &str) -> io::Result<Vec<BinaryMeta>> {
        let q = normalize_lookup(query);
        if q.is_empty() {
            return Ok(Vec::new());
        }

        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for item in self.t_binary_name_index.iter() {
            let (raw_name, raw_md5s) =
                item.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled iter: {e}")))?;
            let name = match std::str::from_utf8(&raw_name) {
                Ok(name) => name,
                Err(_) => continue,
            };
            if !name.contains(&q) {
                continue;
            }
            for md5 in decode_md5_list(&raw_md5s).unwrap_or_default() {
                if !seen.insert(md5) {
                    continue;
                }
                if let Some(meta) = self.get_binary_meta(&md5)? {
                    matches.push(meta);
                }
            }
        }
        Ok(matches)
    }

    pub fn get_binary_facets(&self, md5: &[u8; 16]) -> io::Result<Option<BinaryFacetSummary>> {
        match self.t_binary_facets.get(md5) {
            Ok(Some(v)) => Ok(decode_binary_facets(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn set_binary_facets(&self, md5: &[u8; 16], facets: &BinaryFacetSummary) -> io::Result<()> {
        self.t_binary_facets
            .insert(md5, encode_binary_facets(facets))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        Ok(())
    }

    pub fn get_binary_overlap_cache(
        &self,
        md5: &[u8; 16],
    ) -> io::Result<Option<Vec<BinaryOverlapEntry>>> {
        match self.t_binary_overlap.get(md5) {
            Ok(Some(v)) => Ok(decode_binary_overlap_entries(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sled get: {e}"),
            )),
        }
    }

    pub fn set_binary_overlap_cache(
        &self,
        md5: &[u8; 16],
        entries: &[BinaryOverlapEntry],
    ) -> io::Result<()> {
        self.t_binary_overlap
            .insert(md5, encode_binary_overlap_entries(entries))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        Ok(())
    }

    pub fn invalidate_binary_overlap_cache(&self, md5: &[u8; 16]) -> io::Result<()> {
        self.t_binary_overlap
            .remove(md5)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled remove: {e}")))?;
        Ok(())
    }

    fn record_binary_name_alias(&self, md5: [u8; 16], basename: &str) -> io::Result<()> {
        let clean = sanitize_basename(basename);
        let normalized = normalize_lookup(&clean);
        if normalized.is_empty() {
            return Ok(());
        }
        let current = self
            .t_binary_name_index
            .get(normalized.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut md5s = current
            .as_deref()
            .and_then(decode_md5_list)
            .unwrap_or_default();
        if !md5s.iter().any(|entry| entry == &md5) {
            md5s.push(md5);
            self.t_binary_name_index
                .insert(normalized.as_bytes(), encode_md5_list(&md5s))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        }
        Ok(())
    }

    fn record_binary_host(&self, md5: [u8; 16], hostname: &str, ts_sec: u64) -> io::Result<()> {
        let host = normalize_lookup(hostname);
        if host.is_empty() {
            return Ok(());
        }
        self.t_binary_hosts
            .insert(binary_host_key(&md5, &host), &ts_sec.to_le_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        Ok(())
    }

    fn count_binary_functions(&self, md5: &[u8; 16]) -> io::Result<u64> {
        Ok(self.t_binary_functions.scan_prefix(md5).count() as u64)
    }

    fn count_binary_versions(&self, md5: &[u8; 16]) -> io::Result<u64> {
        Ok(self.t_binary_versions.scan_prefix(md5).count() as u64)
    }

    fn count_binary_hosts(&self, md5: &[u8; 16]) -> io::Result<u64> {
        Ok(self.t_binary_hosts.scan_prefix(md5).count() as u64)
    }

    fn bump_binary_meta_counts(
        &self,
        md5: &[u8; 16],
        function_inc: u64,
        version_inc: u64,
    ) -> io::Result<()> {
        let Some(mut meta) = self.get_binary_meta(md5)? else {
            return Ok(());
        };
        meta.function_count = meta.function_count.saturating_add(function_inc);
        meta.version_count = meta.version_count.saturating_add(version_inc);
        meta.host_count = self.count_binary_hosts(md5)?;
        self.t_binary_meta
            .insert(md5, encode_binary_meta(&meta))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        Ok(())
    }

    fn record_basename_for_key(&self, key: u128, basename: &str) -> io::Result<()> {
        let clean = sanitize_basename(basename);
        if clean.is_empty() {
            return Ok(());
        }

        let key_only = key.to_le_bytes();
        let current = self
            .t_key_basenames
            .get(&key_only)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled get: {e}")))?;
        let mut basenames = if let Some(v) = current {
            decode_basenames(&v).unwrap_or_default()
        } else {
            Vec::new()
        };

        if !basenames
            .iter()
            .any(|b| b.eq_ignore_ascii_case(clean.as_str()))
        {
            basenames.insert(0, clean);
            if basenames.len() > MAX_BASENAMES_PER_KEY {
                basenames.truncate(MAX_BASENAMES_PER_KEY);
            }
            let enc = encode_basenames(&basenames);
            self.t_key_basenames
                .insert(&key_only, enc)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sled insert: {e}")))?;
        }

        Ok(())
    }

    /// Get the count of unique binaries (md5s) observed.
    pub fn unique_binaries_count(&self) -> io::Result<u64> {
        Ok(self.t_binary_meta.totals()?.0)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

// ----------------- encoding helpers -----------------

fn put_u16_le(v: u16, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn put_u32_le(v: u32, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn put_u64_le(v: u64, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn get_u16_le(src: &mut &[u8]) -> Option<u16> {
    if src.len() < 2 {
        return None;
    }
    let v = u16::from_le_bytes(src[0..2].try_into().ok()?);
    *src = &src[2..];
    Some(v)
}
fn get_u32_le(src: &mut &[u8]) -> Option<u32> {
    if src.len() < 4 {
        return None;
    }
    let v = u32::from_le_bytes(src[0..4].try_into().ok()?);
    *src = &src[4..];
    Some(v)
}
fn get_u64_le(src: &mut &[u8]) -> Option<u64> {
    if src.len() < 8 {
        return None;
    }
    let v = u64::from_le_bytes(src[0..8].try_into().ok()?);
    *src = &src[8..];
    Some(v)
}
fn get_bytes<'a>(src: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if src.len() < n {
        return None;
    }
    let out = &src[..n];
    *src = &src[n..];
    Some(out)
}

fn put_str(dst: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    put_u16_le(b.len() as u16, dst);
    dst.extend_from_slice(b);
}
fn get_str(src: &mut &[u8]) -> Option<String> {
    let n = get_u16_le(src)? as usize;
    let b = get_bytes(src, n)?;
    std::str::from_utf8(b).ok().map(|s| s.to_string())
}

fn normalize_lookup(input: &str) -> String {
    sanitize_basename(input).to_ascii_lowercase()
}

fn binary_function_key(md5: &[u8; 16], key: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(md5);
    out[16..32].copy_from_slice(&key.to_le_bytes());
    out
}

fn binary_version_key(md5: &[u8; 16], version_id: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[0..16].copy_from_slice(md5);
    out[16..48].copy_from_slice(version_id);
    out
}

fn binary_host_key(md5: &[u8; 16], host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + host.len());
    out.extend_from_slice(md5);
    out.extend_from_slice(host.as_bytes());
    out
}

fn encode_md5_list(values: &[[u8; 16]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + values.len() * 16);
    out.push(values.len().min(255) as u8);
    for value in values.iter().take(255) {
        out.extend_from_slice(value);
    }
    out
}

fn decode_md5_list(mut bytes: &[u8]) -> Option<Vec<[u8; 16]>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let count = bytes[0] as usize;
    bytes = &bytes[1..];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = get_bytes(&mut bytes, 16)?;
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(raw);
        out.push(md5);
    }
    Some(out)
}

fn encode_binary_facets(facets: &BinaryFacetSummary) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 * 8);
    put_u64_le(facets.function_count, &mut v);
    put_u64_le(facets.typed_functions, &mut v);
    put_u64_le(facets.framed_functions, &mut v);
    put_u64_le(facets.commented_functions, &mut v);
    put_u64_le(facets.switch_functions, &mut v);
    put_u64_le(facets.parse_partial_functions, &mut v);
    put_u64_le(facets.demangled_functions, &mut v);
    put_u64_le(facets.cached_at_ts, &mut v);
    v
}

fn decode_binary_facets(mut bytes: &[u8]) -> Option<BinaryFacetSummary> {
    Some(BinaryFacetSummary {
        function_count: get_u64_le(&mut bytes)?,
        typed_functions: get_u64_le(&mut bytes)?,
        framed_functions: get_u64_le(&mut bytes)?,
        commented_functions: get_u64_le(&mut bytes)?,
        switch_functions: get_u64_le(&mut bytes)?,
        parse_partial_functions: get_u64_le(&mut bytes)?,
        demangled_functions: get_u64_le(&mut bytes)?,
        cached_at_ts: get_u64_le(&mut bytes)?,
    })
}

fn encode_binary_overlap_entries(entries: &[BinaryOverlapEntry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + entries.len() * 24);
    v.push(entries.len().min(255) as u8);
    for entry in entries.iter().take(255) {
        v.extend_from_slice(&entry.md5);
        put_u64_le(entry.shared_functions, &mut v);
    }
    v
}

fn decode_binary_overlap_entries(mut bytes: &[u8]) -> Option<Vec<BinaryOverlapEntry>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let count = bytes[0] as usize;
    bytes = &bytes[1..];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let raw_md5 = get_bytes(&mut bytes, 16)?;
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(raw_md5);
        out.push(BinaryOverlapEntry {
            md5,
            shared_functions: get_u64_le(&mut bytes)?,
        });
    }
    Some(out)
}

fn encode_binary_meta(m: &BinaryMeta) -> Vec<u8> {
    let mut v =
        Vec::with_capacity(112 + m.basename.len() + m.hostname.len() + m.origin_token.len());
    v.extend_from_slice(&m.md5);
    put_u64_le(m.first_seen_ts, &mut v);
    put_u64_le(m.last_seen_ts, &mut v);
    put_u64_le(m.obs_count, &mut v);
    put_str(&mut v, &m.basename);
    put_str(&mut v, &m.hostname);
    put_str(&mut v, &m.origin_token);
    put_u64_le(m.function_count, &mut v);
    put_u64_le(m.version_count, &mut v);
    put_u64_le(m.host_count, &mut v);
    v
}
fn decode_binary_meta(mut b: &[u8]) -> Option<BinaryMeta> {
    if b.len() < 16 {
        return None;
    }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&b[..16]);
    b = &b[16..];
    let first_seen_ts = get_u64_le(&mut b)?;
    let last_seen_ts = get_u64_le(&mut b)?;
    let obs_count = get_u64_le(&mut b)?;
    let basename = get_str(&mut b)?;
    let hostname = get_str(&mut b)?;

    let mut origin_token = String::new();
    if b.len() > 24 {
        let mut probe = b;
        if let Some(n) = get_u16_le(&mut probe) {
            let n = n as usize;
            if probe.len() >= n + 24 {
                origin_token = std::str::from_utf8(&probe[..n])
                    .ok()
                    .unwrap_or("")
                    .to_string();
                b = &probe[n..];
            }
        }
    }

    Some(BinaryMeta {
        md5,
        first_seen_ts,
        last_seen_ts,
        obs_count,
        basename,
        hostname,
        origin_token,
        function_count: get_u64_le(&mut b).unwrap_or(0),
        version_count: get_u64_le(&mut b).unwrap_or(0),
        host_count: get_u64_le(&mut b).unwrap_or(0),
    })
}

fn encode_canonical_version(cv: &CanonicalVersion) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 8 + 8);
    v.extend_from_slice(&cv.version_id);
    v.extend_from_slice(&cv.score.to_le_bytes());
    put_u64_le(cv.ts_sec, &mut v);
    v
}

fn decode_canonical_version(mut b: &[u8]) -> Option<CanonicalVersion> {
    let version_id = {
        let bytes = get_bytes(&mut b, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        out
    };
    let score = {
        let bytes = get_bytes(&mut b, 8)?;
        f64::from_le_bytes(bytes.try_into().ok()?)
    };
    Some(CanonicalVersion {
        version_id,
        score,
        ts_sec: get_u64_le(&mut b).unwrap_or(0),
    })
}

fn encode_key_md5_stats(s: &KeyMd5Stats) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + 32);
    put_u32_le(s.obs_count, &mut v);
    put_u64_le(s.last_ts_sec, &mut v);
    v.extend_from_slice(&s.last_version_id);
    v
}
fn decode_key_md5_stats(mut b: &[u8]) -> Option<KeyMd5Stats> {
    Some(KeyMd5Stats {
        obs_count: get_u32_le(&mut b)?,
        last_ts_sec: get_u64_le(&mut b)?,
        last_version_id: {
            let bytes = get_bytes(&mut b, 32)?;
            let mut a = [0u8; 32];
            a.copy_from_slice(bytes);
            a
        },
    })
}

fn encode_key_bins(vv: &[KeyMd5Entry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + vv.len() * (16 + 4));
    v.push(vv.len() as u8);
    for e in vv.iter() {
        v.extend_from_slice(&e.md5);
        put_u32_le(e.obs_count, &mut v);
    }
    v
}
fn decode_key_bins(mut b: &[u8]) -> Option<Vec<KeyMd5Entry>> {
    let n = if b.is_empty() {
        0
    } else {
        let n = b[0] as usize;
        b = &b[1..];
        n
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let md5 = {
            let s = get_bytes(&mut b, 16)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(s);
            arr
        };
        let cnt = get_u32_le(&mut b)?;
        out.push(KeyMd5Entry {
            md5,
            obs_count: cnt,
        });
    }
    Some(out)
}

fn encode_version_stats(vs: &VersionStats) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + 8 + 4 + 1 + vs.top_md5s.len() * (16 + 4));
    put_u32_le(vs.total_obs, &mut v);
    put_u64_le(vs.first_ts_sec, &mut v);
    put_u64_le(vs.last_ts_sec, &mut v);
    put_u32_le(vs.num_binaries, &mut v);
    v.push(vs.top_md5s.len() as u8);
    for e in &vs.top_md5s {
        v.extend_from_slice(&e.md5);
        put_u32_le(e.obs_count, &mut v);
    }
    v
}
fn decode_version_stats(mut b: &[u8]) -> Option<VersionStats> {
    let total_obs = get_u32_le(&mut b)?;
    let first_ts_sec = get_u64_le(&mut b)?;
    let last_ts_sec = get_u64_le(&mut b)?;
    let num_binaries = get_u32_le(&mut b)?;
    let n = if b.is_empty() {
        0
    } else {
        let n = b[0] as usize;
        b = &b[1..];
        n
    };
    let mut top_md5s = Vec::with_capacity(n);
    for _ in 0..n {
        let md5 = {
            let s = get_bytes(&mut b, 16)?;
            let mut a = [0u8; 16];
            a.copy_from_slice(s);
            a
        };
        let cnt = get_u32_le(&mut b)?;
        top_md5s.push(KeyMd5Entry {
            md5,
            obs_count: cnt,
        });
    }
    Some(VersionStats {
        total_obs,
        first_ts_sec,
        last_ts_sec,
        num_binaries,
        top_md5s,
    })
}

fn encode_basenames(names: &[String]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + names.len() * 18);
    v.push(names.len() as u8);
    for name in names {
        let b = name.as_bytes();
        let len = (b.len().min(u16::MAX as usize)) as u16;
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&b[..len as usize]);
    }
    v
}

fn decode_basenames(mut b: &[u8]) -> Option<Vec<String>> {
    if b.is_empty() {
        return Some(Vec::new());
    }
    let count = b[0] as usize;
    b = &b[1..];

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = get_u16_le(&mut b)? as usize;
        let bytes = get_bytes(&mut b, len)?;
        let s = std::str::from_utf8(bytes).ok()?.to_string();
        out.push(s);
    }
    Some(out)
}

fn sanitize_basename(input: &str) -> String {
    let input = input.trim();
    if input.is_empty() {
        return String::new();
    }

    // Find the last occurrence of either path separator
    let last_sep = input.rfind('/').into_iter().chain(input.rfind('\\')).max();

    let base = match last_sep {
        Some(idx) => &input[idx + 1..],
        None => input,
    };

    let base = base.trim();
    if base.is_empty() {
        return String::new();
    }

    if base.len() > 255 {
        base[..255].to_string()
    } else {
        base.to_string()
    }
}
