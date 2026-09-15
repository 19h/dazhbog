//! Global metrics collection using atomic counters with sled persistence.

use log::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Keys for persisted metrics in sled
const KEY_START_TIME: &[u8] = b"start_time";
/// Resolves after shutdown is requested, including when requested before polling.
pub async fn shutdown_requested() {
    while !METRICS
        .shutting_down
        .load(std::sync::atomic::Ordering::Acquire)
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

const KEY_INDEXED_FUNCS: &[u8] = b"indexed_funcs";
const KEY_TOTAL_RECORDS: &[u8] = b"total_records";
const KEY_STORAGE_BYTES: &[u8] = b"storage_bytes";
const KEY_SEARCH_DOCS: &[u8] = b"search_docs";
const KEY_UNIQUE_BINARIES: &[u8] = b"unique_binaries";
const KEY_PULLS: &[u8] = b"pulls";
const KEY_PUSHES: &[u8] = b"pushes";
const KEY_NEW_FUNCS: &[u8] = b"new_funcs";
const KEY_QUERIED_FUNCS: &[u8] = b"queried_funcs";
const KEY_ERRORS: &[u8] = b"errors";
const KEY_TIMEOUTS: &[u8] = b"timeouts";
const KEY_INDEX_OVERFLOWS: &[u8] = b"index_overflows";
const KEY_APPEND_FAILURES: &[u8] = b"append_failures";
const KEY_DECODER_REJECTS: &[u8] = b"decoder_rejects";
const KEY_UPSTREAM_REQUESTS: &[u8] = b"upstream_requests";
const KEY_UPSTREAM_FETCHED: &[u8] = b"upstream_fetched";
const KEY_UPSTREAM_ERRORS: &[u8] = b"upstream_errors";
const KEY_SCORING_BATCHES: &[u8] = b"scoring_batches";
const KEY_SCORING_VERSIONS: &[u8] = b"scoring_versions";
const KEY_SCORING_FALLBACK: &[u8] = b"scoring_fallback";

/// Global metrics structure with persistent backing.
pub struct Metrics {
    // Sled tree for persistence (initialized via init())
    tree: OnceLock<sled::Tree>,

    // === Session metrics (reset on restart) ===
    pub active_connections: AtomicU64,
    pub lumina_v0_4: AtomicU64,
    pub lumina_v5p: AtomicU64,
    pub shutting_down: AtomicBool,
    pub scoring_time_ns: AtomicU64,

    // === Persisted counters ===
    pub start_time: AtomicU64,
    pub indexed_funcs: AtomicU64,
    pub total_records: AtomicU64,
    pub storage_bytes: AtomicU64,
    pub search_docs: AtomicU64,
    pub unique_binaries: AtomicU64,

    // Traffic counters (persisted)
    pub pulls: AtomicU64,
    pub pushes: AtomicU64,
    pub new_funcs: AtomicU64,
    pub queried_funcs: AtomicU64,

    // Error counters (persisted)
    pub errors: AtomicU64,
    pub timeouts: AtomicU64,
    pub index_overflows: AtomicU64,
    pub append_failures: AtomicU64,
    pub decoder_rejects: AtomicU64,

    // Upstream counters (persisted)
    pub upstream_requests: AtomicU64,
    pub upstream_fetched: AtomicU64,
    pub upstream_errors: AtomicU64,

    // Scoring counters (persisted)
    pub scoring_batches: AtomicU64,
    pub scoring_versions_considered: AtomicU64,
    pub scoring_fallback_latest: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            tree: OnceLock::new(),
            active_connections: AtomicU64::new(0),
            lumina_v0_4: AtomicU64::new(0),
            lumina_v5p: AtomicU64::new(0),
            shutting_down: AtomicBool::new(false),
            scoring_time_ns: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
            indexed_funcs: AtomicU64::new(0),
            total_records: AtomicU64::new(0),
            storage_bytes: AtomicU64::new(0),
            search_docs: AtomicU64::new(0),
            unique_binaries: AtomicU64::new(0),
            pulls: AtomicU64::new(0),
            pushes: AtomicU64::new(0),
            new_funcs: AtomicU64::new(0),
            queried_funcs: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            index_overflows: AtomicU64::new(0),
            append_failures: AtomicU64::new(0),
            decoder_rejects: AtomicU64::new(0),
            upstream_requests: AtomicU64::new(0),
            upstream_fetched: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            scoring_batches: AtomicU64::new(0),
            scoring_versions_considered: AtomicU64::new(0),
            scoring_fallback_latest: AtomicU64::new(0),
        }
    }
}

/// Global metrics singleton.
pub static METRICS: once_cell::sync::Lazy<&'static Metrics> =
    once_cell::sync::Lazy::new(|| Box::leak(Box::new(Metrics::default())));

impl Metrics {
    /// Initialize metrics with sled persistence and load persisted values.
    /// Also initializes database stats from the provided counts.
    pub fn init(
        &self,
        db: &sled::Db,
        indexed_funcs: u64,
        total_records: u64,
        storage_bytes: u64,
        search_docs: u64,
        unique_binaries: u64,
    ) -> std::io::Result<()> {
        let tree = db.open_tree("metrics").map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("open metrics tree: {e}"))
        })?;

        // Load persisted values
        self.load_u64(&tree, KEY_PULLS, &self.pulls);
        self.load_u64(&tree, KEY_PUSHES, &self.pushes);
        self.load_u64(&tree, KEY_NEW_FUNCS, &self.new_funcs);
        self.load_u64(&tree, KEY_QUERIED_FUNCS, &self.queried_funcs);
        self.load_u64(&tree, KEY_ERRORS, &self.errors);
        self.load_u64(&tree, KEY_TIMEOUTS, &self.timeouts);
        self.load_u64(&tree, KEY_INDEX_OVERFLOWS, &self.index_overflows);
        self.load_u64(&tree, KEY_APPEND_FAILURES, &self.append_failures);
        self.load_u64(&tree, KEY_DECODER_REJECTS, &self.decoder_rejects);
        self.load_u64(&tree, KEY_UPSTREAM_REQUESTS, &self.upstream_requests);
        self.load_u64(&tree, KEY_UPSTREAM_FETCHED, &self.upstream_fetched);
        self.load_u64(&tree, KEY_UPSTREAM_ERRORS, &self.upstream_errors);
        self.load_u64(&tree, KEY_SCORING_BATCHES, &self.scoring_batches);
        self.load_u64(
            &tree,
            KEY_SCORING_VERSIONS,
            &self.scoring_versions_considered,
        );
        self.load_u64(&tree, KEY_SCORING_FALLBACK, &self.scoring_fallback_latest);

        // Load or set start_time
        if let Ok(Some(v)) = tree.get(KEY_START_TIME) {
            if v.len() >= 8 {
                let ts = u64::from_le_bytes(v[0..8].try_into().unwrap());
                self.start_time.store(ts, Ordering::Relaxed);
                info!("loaded persisted start_time: {}", ts);
            }
        } else {
            // First run - set start time
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.start_time.store(now, Ordering::Relaxed);
            let _ = tree.insert(KEY_START_TIME, &now.to_le_bytes());
            info!("initialized start_time: {}", now);
        }

        // Set database stats from actual counts
        self.indexed_funcs.store(indexed_funcs, Ordering::Relaxed);
        self.total_records.store(total_records, Ordering::Relaxed);
        self.storage_bytes.store(storage_bytes, Ordering::Relaxed);
        self.search_docs.store(search_docs, Ordering::Relaxed);
        self.unique_binaries
            .store(unique_binaries, Ordering::Relaxed);

        // Persist current database stats
        let _ = tree.insert(KEY_INDEXED_FUNCS, &indexed_funcs.to_le_bytes());
        let _ = tree.insert(KEY_TOTAL_RECORDS, &total_records.to_le_bytes());
        let _ = tree.insert(KEY_STORAGE_BYTES, &storage_bytes.to_le_bytes());
        let _ = tree.insert(KEY_SEARCH_DOCS, &search_docs.to_le_bytes());
        let _ = tree.insert(KEY_UNIQUE_BINARIES, &unique_binaries.to_le_bytes());

        let _ = self.tree.set(tree);

        info!(
            "metrics initialized: indexed_funcs={}, total_records={}, storage_bytes={}, search_docs={}, unique_binaries={}",
            indexed_funcs, total_records, storage_bytes, search_docs, unique_binaries
        );

        Ok(())
    }

    fn load_u64(&self, tree: &sled::Tree, key: &[u8], target: &AtomicU64) {
        if let Ok(Some(v)) = tree.get(key) {
            if v.len() >= 8 {
                let val = u64::from_le_bytes(v[0..8].try_into().unwrap());
                target.store(val, Ordering::Relaxed);
            }
        }
    }

    fn persist_u64(&self, key: &[u8], value: u64) {
        if let Some(tree) = self.tree.get() {
            let _ = tree.insert(key, &value.to_le_bytes());
        }
    }

    // === Increment helpers with persistence ===

    pub fn inc_pulls(&self, n: u64) {
        let new_val = self.pulls.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_PULLS, new_val);
    }

    pub fn inc_pushes(&self, n: u64) {
        let new_val = self.pushes.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_PUSHES, new_val);
    }

    pub fn inc_new_funcs(&self, n: u64) {
        let new_val = self.new_funcs.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_NEW_FUNCS, new_val);
    }

    pub fn inc_queried_funcs(&self, n: u64) {
        let new_val = self.queried_funcs.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_QUERIED_FUNCS, new_val);
    }

    pub fn inc_errors(&self) {
        let new_val = self.errors.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_ERRORS, new_val);
    }

    pub fn inc_timeouts(&self) {
        let new_val = self.timeouts.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_TIMEOUTS, new_val);
    }

    pub fn inc_index_overflows(&self) {
        let new_val = self.index_overflows.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_INDEX_OVERFLOWS, new_val);
    }

    pub fn inc_append_failures(&self) {
        let new_val = self.append_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_APPEND_FAILURES, new_val);
    }

    pub fn inc_decoder_rejects(&self) {
        let new_val = self.decoder_rejects.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_DECODER_REJECTS, new_val);
    }

    pub fn inc_upstream_requests(&self) {
        let new_val = self.upstream_requests.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_UPSTREAM_REQUESTS, new_val);
    }

    pub fn inc_upstream_fetched(&self, n: u64) {
        let new_val = self.upstream_fetched.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_UPSTREAM_FETCHED, new_val);
    }

    pub fn inc_upstream_errors(&self) {
        let new_val = self.upstream_errors.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_UPSTREAM_ERRORS, new_val);
    }

    pub fn inc_scoring_batches(&self) {
        let new_val = self.scoring_batches.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_SCORING_BATCHES, new_val);
    }

    pub fn inc_scoring_versions(&self, n: u64) {
        let new_val = self
            .scoring_versions_considered
            .fetch_add(n, Ordering::Relaxed)
            + n;
        self.persist_u64(KEY_SCORING_VERSIONS, new_val);
    }

    pub fn inc_scoring_fallback(&self) {
        let new_val = self.scoring_fallback_latest.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_SCORING_FALLBACK, new_val);
    }

    // === Database stats updates ===

    pub fn set_indexed_funcs(&self, n: u64) {
        self.indexed_funcs.store(n, Ordering::Relaxed);
        self.persist_u64(KEY_INDEXED_FUNCS, n);
    }

    pub fn inc_indexed_funcs(&self) {
        let new_val = self.indexed_funcs.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_INDEXED_FUNCS, new_val);
    }

    pub fn set_total_records(&self, n: u64) {
        self.total_records.store(n, Ordering::Relaxed);
        self.persist_u64(KEY_TOTAL_RECORDS, n);
    }

    pub fn inc_total_records(&self) {
        let new_val = self.total_records.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_TOTAL_RECORDS, new_val);
    }

    pub fn add_storage_bytes(&self, n: u64) {
        let new_val = self.storage_bytes.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_STORAGE_BYTES, new_val);
    }

    pub fn set_storage_bytes(&self, n: u64) {
        self.storage_bytes.store(n, Ordering::Relaxed);
        self.persist_u64(KEY_STORAGE_BYTES, n);
    }

    pub fn set_search_docs(&self, n: u64) {
        self.search_docs.store(n, Ordering::Relaxed);
        self.persist_u64(KEY_SEARCH_DOCS, n);
    }

    pub fn add_search_docs(&self, n: u64) {
        let new_val = self.search_docs.fetch_add(n, Ordering::Relaxed) + n;
        self.persist_u64(KEY_SEARCH_DOCS, new_val);
    }

    pub fn inc_search_docs(&self) {
        let new_val = self.search_docs.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_SEARCH_DOCS, new_val);
    }

    pub fn sub_search_docs(&self, n: u64) {
        let mut current = self.search_docs.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(n);
            match self.search_docs.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.persist_u64(KEY_SEARCH_DOCS, next);
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub fn set_unique_binaries(&self, n: u64) {
        self.unique_binaries.store(n, Ordering::Relaxed);
        self.persist_u64(KEY_UNIQUE_BINARIES, n);
    }

    pub fn inc_unique_binaries(&self) {
        let new_val = self.unique_binaries.fetch_add(1, Ordering::Relaxed) + 1;
        self.persist_u64(KEY_UNIQUE_BINARIES, new_val);
    }

    /// Get current uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        let start = self.start_time.load(Ordering::Relaxed);
        if start == 0 {
            return 0;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(start)
    }

    /// Render metrics in Prometheus exposition format.
    pub fn render_prometheus(&self) -> String {
        let g = |name: &str, help: &str, val: u64| -> String {
            format!(
                "# HELP {0} {1}\n# TYPE {0} counter\n{0} {2}\n",
                name, help, val
            )
        };
        let gauge = |name: &str, help: &str, val: u64| -> String {
            format!(
                "# HELP {0} {1}\n# TYPE {0} gauge\n{0} {2}\n",
                name, help, val
            )
        };

        let mut s = String::with_capacity(4096);

        // Database stats (gauges)
        s.push_str(&gauge(
            "dazhbog_indexed_funcs",
            "Number of unique functions in the index",
            self.indexed_funcs.load(Ordering::Relaxed),
        ));
        s.push_str(&gauge(
            "dazhbog_total_records",
            "Total records in segment storage",
            self.total_records.load(Ordering::Relaxed),
        ));
        s.push_str(&gauge(
            "dazhbog_storage_bytes",
            "Total bytes used by segment storage",
            self.storage_bytes.load(Ordering::Relaxed),
        ));
        s.push_str(&gauge(
            "dazhbog_search_docs",
            "Documents in full-text search index",
            self.search_docs.load(Ordering::Relaxed),
        ));
        s.push_str(&gauge(
            "dazhbog_unique_binaries",
            "Unique binary files observed",
            self.unique_binaries.load(Ordering::Relaxed),
        ));
        s.push_str(&gauge(
            "dazhbog_uptime_seconds",
            "Server uptime in seconds",
            self.uptime_secs(),
        ));
        s.push_str(&gauge(
            "dazhbog_active_connections",
            "Active binary RPC connections",
            self.active_connections.load(Ordering::Relaxed),
        ));

        // Traffic counters
        s.push_str(&g(
            "dazhbog_pulls_total",
            "Number of functions successfully pulled",
            self.pulls.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_pushes_total",
            "Number of functions pushed",
            self.pushes.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_new_funcs_total",
            "New unique functions inserted",
            self.new_funcs.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_queried_funcs_total",
            "Requested function keys",
            self.queried_funcs.load(Ordering::Relaxed),
        ));

        // Protocol counters
        s.push_str(&g(
            "dazhbog_lumina_v0_4",
            "Hello protocol versions 0..4",
            self.lumina_v0_4.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_lumina_v5p",
            "Hello protocol versions >=5",
            self.lumina_v5p.load(Ordering::Relaxed),
        ));

        // Error counters
        s.push_str(&g(
            "dazhbog_errors_total",
            "Errors",
            self.errors.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_timeouts_total",
            "Timeouts",
            self.timeouts.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_index_overflows_total",
            "Index insertion overflows (no overwrite)",
            self.index_overflows.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_append_failures_total",
            "Database append operation failures",
            self.append_failures.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_decoder_rejects_total",
            "Protocol decoder rejections due to size limits",
            self.decoder_rejects.load(Ordering::Relaxed),
        ));

        // Upstream counters
        s.push_str(&g(
            "dazhbog_upstream_requests_total",
            "Batches requested from upstream",
            self.upstream_requests.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_upstream_fetched_total",
            "Functions fetched from upstream",
            self.upstream_fetched.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_upstream_errors_total",
            "Errors contacting upstream",
            self.upstream_errors.load(Ordering::Relaxed),
        ));

        // Scoring counters
        s.push_str(&g(
            "dazhbog_scoring_batches_total",
            "Version selection batches scored",
            self.scoring_batches.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_versions_considered_total",
            "Versions considered across batches",
            self.scoring_versions_considered.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_fallback_latest_total",
            "Batches falling back to latest semantics",
            self.scoring_fallback_latest.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_time_ns_total",
            "Cumulative time spent scoring (ns)",
            self.scoring_time_ns.load(Ordering::Relaxed),
        ));
        s
    }
}
