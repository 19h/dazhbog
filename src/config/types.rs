//! Configuration type definitions.

/// Connection and resource limits.
#[derive(Clone, Debug)]
pub struct Limits {
    pub hello_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub tls_handshake_timeout_ms: u64,
    pub pull_timeout_ms: u64,
    pub push_timeout_ms: u64,
    pub max_active_conns: usize,
    pub max_hello_frame_bytes: usize,
    pub max_cmd_frame_bytes: usize,
    pub max_pull_items: usize,
    pub max_push_items: usize,
    pub max_del_items: usize,
    pub max_hist_items: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
    pub per_connection_inflight_bytes: usize,
    pub global_inflight_bytes: usize,
    pub lumina_max_cstr_bytes: usize,
    pub lumina_max_hash_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            hello_timeout_ms: 3000,
            command_timeout_ms: 15000,
            tls_handshake_timeout_ms: 5000,
            pull_timeout_ms: 15000,
            push_timeout_ms: 15000,
            max_active_conns: 2048,
            max_hello_frame_bytes: 16 * 1024 * 1024,
            max_cmd_frame_bytes: 256 * 1024 * 1024,
            max_pull_items: 524288,
            max_push_items: 524288,
            max_del_items: 524288,
            max_hist_items: 4096,
            max_name_bytes: 65535,
            max_data_bytes: 8 * 1024 * 1024,
            per_connection_inflight_bytes: 32 * 1024 * 1024,
            global_inflight_bytes: 512 * 1024 * 1024,
            lumina_max_cstr_bytes: 4096,
            lumina_max_hash_bytes: 64,
        }
    }
}

/// TLS configuration.
///
/// Supports two modes:
/// 1. PKCS#12 (native-tls): Set `pkcs12_path` - no ALPN/HTTP2 over TLS
/// 2. PEM (rustls): Set `cert_pem_path` and `key_pem_path` - full ALPN/HTTP2 support
///
/// If both are configured, PEM/rustls is preferred for HTTP/2 ALPN support.
#[derive(Clone, Debug)]
pub struct TLS {
    /// Path to PKCS#12 certificate bundle (native-tls, no ALPN)
    pub pkcs12_path: String,
    /// Environment variable containing PKCS#12 password
    pub env_password_var: String,
    /// Allow SSLv3 as minimum protocol (native-tls only)
    pub min_protocol_sslv3: bool,
    /// Path to PEM-encoded certificate chain (rustls, enables ALPN/HTTP2)
    pub cert_pem_path: Option<String>,
    /// Path to PEM-encoded private key (rustls, enables ALPN/HTTP2)
    pub key_pem_path: Option<String>,
}

impl Default for TLS {
    fn default() -> Self {
        Self {
            pkcs12_path: String::new(),
            env_password_var: "PKCSPASSWD".into(),
            min_protocol_sslv3: true,
            cert_pem_path: None,
            key_pem_path: None,
        }
    }
}

/// HTTP server configuration.
#[derive(Clone, Debug)]
pub struct Http {
    pub bind_addr: String,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".into(),
        }
    }
}

/// Storage engine configuration.
#[derive(Clone, Debug)]
pub struct Engine {
    pub data_dir: String,
    pub segment_bytes: u64,
    pub shard_count: usize,
    pub index_capacity: usize,
    pub sync_interval_ms: u64,
    pub compaction_check_ms: u64,
    pub use_mmap_reads: bool,
    pub deduplicate_on_startup: bool,
    pub index_dir: Option<String>,
    pub index_memtable_max_entries: usize,
    pub index_block_entries: usize,
    pub index_level0_compact_trigger: usize,
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            data_dir: "data".into(),
            segment_bytes: 1 << 30,
            shard_count: 64,
            index_capacity: 1 << 30,
            sync_interval_ms: 200,
            compaction_check_ms: 30000,
            use_mmap_reads: false,
            deduplicate_on_startup: false,
            index_dir: None,
            index_memtable_max_entries: 200_000,
            index_block_entries: 128,
            index_level0_compact_trigger: 8,
        }
    }
}

/// Server-side rejection policy for pushed function names.
///
/// The Hex-Rays reference server rejects no names (only non-ASCII bytes).
/// `Prefixes` rejects IDA dummy names only; `Heuristic` adds the statistical
/// character-distribution model and address-like numeric suffixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameRejection {
    Off,
    Prefixes,
    Heuristic,
}

impl NameRejection {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" => Some(Self::Off),
            "prefixes" | "prefix" | "dummy" => Some(Self::Prefixes),
            "heuristic" | "strict" => Some(Self::Heuristic),
            _ => None,
        }
    }
}

/// Lumina protocol server configuration.
#[derive(Clone, Debug)]
pub struct Lumina {
    pub bind_addr: String,
    pub server_name: String,
    pub allow_deletes: bool,
    /// Maximum history entries returned per function; 0 disables the request.
    pub get_history_limit: u32,
    pub use_tls: bool,
    pub tls: Option<TLS>,
    /// Accept any hello username (reference noauth behaviour). When false only
    /// an empty username or `guest` is accepted.
    pub accept_any_username: bool,
    pub name_rejection: NameRejection,
}

impl Default for Lumina {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:20667".into(),
            server_name: "dazhbog".into(),
            allow_deletes: false,
            get_history_limit: 128,
            use_tls: false,
            tls: None,
            accept_any_username: false,
            name_rejection: NameRejection::Prefixes,
        }
    }
}

/// Upstream server configuration for forwarding.
#[derive(Clone, Debug)]
pub struct Upstream {
    pub enabled: bool,
    pub priority: u32,
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub insecure_no_verify: bool,
    pub hello_protocol_version: u32,
    pub license_path: Option<String>,
    pub timeout_ms: u64,
    pub batch_max: usize,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            enabled: false,
            priority: 0,
            host: String::new(),
            port: 0,
            use_tls: true,
            insecure_no_verify: true,
            hello_protocol_version: 6,
            license_path: None,
            timeout_ms: 8000,
            batch_max: 1024,
        }
    }
}

/// Debug configuration.
#[derive(Clone, Debug)]
pub struct Debug {
    pub dump_hello: bool,
    pub dump_hello_dir: String,
}

impl Default for Debug {
    fn default() -> Self {
        Self {
            dump_hello: false,
            dump_hello_dir: "debug_dumps".into(),
        }
    }
}

/// Version selection scoring weights.
#[derive(Clone, Debug)]
pub struct Scoring {
    /// Experimental cross-version synthesis; coherent stored versions are the default.
    pub experimental_synthesis: bool,
    /// Prioritize inferred binary evidence, subject to the configured sensitivity rule.
    pub binary_priority: bool,
    /// Permit independently corroborated alternatives within one-key sensitivity.
    pub binary_single_key_tolerance: bool,
    /// Expand identifier components for transient batch semantic ranking.
    pub batch_identifier_components: bool,
    /// Use shared metadata when a batch source has no decisive variant.
    pub batch_consensus_anchors: bool,
    pub w_md5: f64,
    pub w_name: f64,
    pub w_coh: f64,
    pub w_stab: f64,
    pub w_rec: f64,
    pub w_pop_bin: f64,
    pub w_host: f64,
    pub w_origin: f64,
    pub max_versions_per_key: usize,
    pub max_md5_per_key: usize,
    pub max_md5_per_version: usize,
}

impl Default for Scoring {
    fn default() -> Self {
        Self {
            experimental_synthesis: false,
            binary_priority: true,
            binary_single_key_tolerance: true,
            batch_identifier_components: true,
            batch_consensus_anchors: true,
            w_md5: 2.0,
            w_name: 1.0,
            w_coh: 2.0,
            w_stab: 0.5,
            w_rec: 0.5,
            w_pop_bin: 0.5,
            w_host: 0.25,
            w_origin: 0.25,
            max_versions_per_key: 16,
            max_md5_per_key: 16,
            max_md5_per_version: 16,
        }
    }
}

/// Root configuration container.
#[derive(Clone, Debug)]
pub struct Config {
    pub limits: Limits,
    pub http: Option<Http>,
    pub engine: Engine,
    pub lumina: Lumina,
    pub upstreams: Vec<Upstream>,
    pub scoring: Scoring,
    pub debug: Debug,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            http: Some(Http::default()),
            engine: Engine::default(),
            lumina: Lumina::default(),
            upstreams: Vec::new(),
            scoring: Scoring::default(),
            debug: Debug::default(),
        }
    }
}
