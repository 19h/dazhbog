use std::{fs, io};

#[derive(Clone, Debug)]
pub struct Limits {
    pub hello_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub tls_handshake_timeout_ms: u64,
    pub pull_timeout_ms: u64,
    pub push_timeout_ms: u64,
    pub max_active_conns: usize,
    // --- Per-frame hard caps ---
    // Maximum wire payload sizes (big-endian length field from the wire), in bytes.
    // For the new protocol, the length INCLUDES the 1-byte message type.
    // For the legacy protocol, the length EXCLUDES the 1-byte message type.
    pub max_hello_frame_bytes: usize, // e.g., 4 MiB
    pub max_cmd_frame_bytes: usize,   // e.g., 16 MiB
    // --- Item-count & per-item caps (defend allocations before they happen) ---
    pub max_pull_items: usize,
    pub max_push_items: usize,
    pub max_del_items: usize,
    pub max_hist_items: usize,
    // Per-item bytes caps
    pub max_name_bytes: usize, // must be <= u16::MAX due to on-disk format
    pub max_data_bytes: usize, // per function metadata payload
    // --- In-flight memory budgets ---
    pub per_connection_inflight_bytes: usize, // soft limit per connection for frame buffers
    pub global_inflight_bytes: usize,         // node-wide limit for all connections
    // --- Legacy parser safety caps ---
    pub legacy_max_cstr_bytes: usize, // cap for C-strings in legacy messages (paths, hostnames)
    pub legacy_max_hash_bytes: usize, // cap for variable-length "mb_hash" (should be small; 16 is expected)
}

#[derive(Clone, Debug)]
pub struct TLS {
    pub pkcs12_path: String,
    pub env_password_var: String, // default PKCSPASSWD
    pub min_protocol_sslv3: bool, // for compatibility parity with source
}

#[derive(Clone, Debug)]
pub struct Http {
    pub bind_addr: String, // "127.0.0.1:8080"
}

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
}

#[derive(Clone, Debug)]
pub struct Lumina {
    pub bind_addr: String, // "0.0.0.0:20667"
    pub server_name: String,
    pub allow_deletes: bool,
    pub get_history_limit: u32, // 0 disables
    pub use_tls: bool,
    pub tls: Option<TLS>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub limits: Limits,
    pub http: Option<Http>,
    pub engine: Engine,
    pub lumina: Lumina,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits {
                hello_timeout_ms: 3000,
                command_timeout_ms: 15000,
                tls_handshake_timeout_ms: 5000,
                pull_timeout_ms: 15000,
                push_timeout_ms: 15000,
                max_active_conns: 2048,
                // Defaults (balanced for safety with compatibility):
                max_hello_frame_bytes: 4 * 1024 * 1024,  // 4 MiB
                max_cmd_frame_bytes: 16 * 1024 * 1024,   // 16 MiB
                max_pull_items: 16384,
                max_push_items: 8192,
                max_del_items: 16384,
                max_hist_items: 4096,
                max_name_bytes: 65535,       // u16::MAX; required by on-disk format
                max_data_bytes: 8 * 1024 * 1024, // 8 MiB per item
                per_connection_inflight_bytes: 32 * 1024 * 1024, // 32 MiB
                global_inflight_bytes: 512 * 1024 * 1024,        // 512 MiB
                legacy_max_cstr_bytes: 4096, // 4 KiB cap for C-strings (paths, hostnames)
                legacy_max_hash_bytes: 64,   // hashes expected 16 bytes; allow small slack
            },
            http: Some(Http { bind_addr: "127.0.0.1:8080".into() }),
            engine: Engine {
                data_dir: "data".into(),
                segment_bytes: 1 << 30, // 1 GiB
                shard_count: 64,
                index_capacity: 1 << 21, // 2,097,152 slots
                sync_interval_ms: 200,
                compaction_check_ms: 30000,
                use_mmap_reads: false,
                deduplicate_on_startup: false,
            },
            lumina: Lumina {
                bind_addr: "0.0.0.0:20667".into(),
                server_name: "lumen".into(),
                allow_deletes: false,
                get_history_limit: 0,
                use_tls: false,
                tls: None,
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> io::Result<Self> {
        let s = fs::read_to_string(path)?;
        // Minimal T0 "toml-like" parser to avoid deps.
        // Format:
        // group.key = value
        // Strings must be in quotes, booleans true/false, ints decimal.
        let mut cfg = Self::default();
        for (lineno, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let Some((lhs, rhs)) = line.split_once('=') else { continue; };
            let lhs = lhs.trim();
            let mut val = rhs.trim();
            if val.ends_with('#') {
                val = val.split('#').next().unwrap().trim();
            }
            let set = |section: &str, key: &str, val: &str, cfg: &mut Self| -> Result<(), String> {
                macro_rules! parse {
                    (s) => { val.trim_matches('"').to_string() };
                    (b) => { match val { "true" => true, "false" => false, _ => return Err(format!("bad bool {val}")) } };
                    (u) => { val.parse::<u64>().map_err(|e| e.to_string())? };
                    (usize_) => { val.parse::<usize>().map_err(|e| e.to_string())? };
                    (u32_) => { val.parse::<u32>().map_err(|e| e.to_string())? };
                }
                match (section, key) {
                    ("limits","hello_timeout_ms") => cfg.limits.hello_timeout_ms = parse!(u),
                    ("limits","command_timeout_ms") => cfg.limits.command_timeout_ms = parse!(u),
                    ("limits","tls_handshake_timeout_ms") => cfg.limits.tls_handshake_timeout_ms = parse!(u),
                    ("limits","pull_timeout_ms") => cfg.limits.pull_timeout_ms = parse!(u),
                    ("limits","push_timeout_ms") => cfg.limits.push_timeout_ms = parse!(u),
                    ("limits","max_active_conns") => cfg.limits.max_active_conns = parse!(usize_),
                    // Additional limits:
                    ("limits","max_hello_frame_bytes") => cfg.limits.max_hello_frame_bytes = parse!(usize_),
                    ("limits","max_cmd_frame_bytes") => cfg.limits.max_cmd_frame_bytes = parse!(usize_),
                    ("limits","max_pull_items") => cfg.limits.max_pull_items = parse!(usize_),
                    ("limits","max_push_items") => cfg.limits.max_push_items = parse!(usize_),
                    ("limits","max_del_items") => cfg.limits.max_del_items = parse!(usize_),
                    ("limits","max_hist_items") => cfg.limits.max_hist_items = parse!(usize_),
                    ("limits","max_name_bytes") => cfg.limits.max_name_bytes = parse!(usize_),
                    ("limits","max_data_bytes") => cfg.limits.max_data_bytes = parse!(usize_),
                    ("limits","per_connection_inflight_bytes") => cfg.limits.per_connection_inflight_bytes = parse!(usize_),
                    ("limits","global_inflight_bytes") => cfg.limits.global_inflight_bytes = parse!(usize_),
                    ("limits","legacy_max_cstr_bytes") => cfg.limits.legacy_max_cstr_bytes = parse!(usize_),
                    ("limits","legacy_max_hash_bytes") => cfg.limits.legacy_max_hash_bytes = parse!(usize_),

                    ("http","bind_addr") => { cfg.http.get_or_insert_with(|| super::config::Http { bind_addr: "".into() }).bind_addr = parse!(s); },

                    ("engine","data_dir") => cfg.engine.data_dir = parse!(s),
                    ("engine","segment_bytes") => cfg.engine.segment_bytes = parse!(u),
                    ("engine","shard_count") => cfg.engine.shard_count = parse!(usize_),
                    ("engine","index_capacity") => cfg.engine.index_capacity = parse!(usize_),
                    ("engine","sync_interval_ms") => cfg.engine.sync_interval_ms = parse!(u),
                    ("engine","compaction_check_ms") => cfg.engine.compaction_check_ms = parse!(u),
                    ("engine","use_mmap_reads") => cfg.engine.use_mmap_reads = parse!(b),
                    ("engine","deduplicate_on_startup") => cfg.engine.deduplicate_on_startup = parse!(b),

                    ("lumina","bind_addr") => cfg.lumina.bind_addr = parse!(s),
                    ("lumina","server_name") => cfg.lumina.server_name = parse!(s),
                    ("lumina","allow_deletes") => cfg.lumina.allow_deletes = parse!(b),
                    ("lumina","get_history_limit") => cfg.lumina.get_history_limit = parse!(u32_),
                    ("lumina","use_tls") => cfg.lumina.use_tls = parse!(b),

                    ("tls","pkcs12_path") => { cfg.lumina.tls.get_or_insert_with(|| super::config::TLS { pkcs12_path: "".into(), env_password_var: "PKCSPASSWD".into(), min_protocol_sslv3: true }).pkcs12_path = parse!(s); },
                    ("tls","env_password_var") => { cfg.lumina.tls.get_or_insert_with(|| super::config::TLS { pkcs12_path: "".into(), env_password_var: "PKCSPASSWD".into(), min_protocol_sslv3: true }).env_password_var = parse!(s); },
                    ("tls","min_protocol_sslv3") => { cfg.lumina.tls.get_or_insert_with(|| super::config::TLS { pkcs12_path: "".into(), env_password_var: "PKCSPASSWD".into(), min_protocol_sslv3: true }).min_protocol_sslv3 = parse!(b); },

                    _ => return Err(format!("unknown key {section}.{key}")),
                }
                Ok(())
            };
            let (section, key) = if let Some((a,b)) = lhs.split_once('.') {(a.trim(), b.trim())} else { ("", lhs) };
            if section.is_empty() { continue; }
            set(section, key, val, &mut cfg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("line {}: {}", lineno+1, e)))?;
        }
        Ok(cfg)
    }
}
