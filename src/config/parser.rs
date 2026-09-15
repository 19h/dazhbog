//! Configuration file parser.
//!
//! Parses TOML-style configuration files with a custom lightweight parser.

use super::types::*;
use std::{fs, io};

/// Load configuration from a file path.
pub fn load_config(path: &str) -> io::Result<Config> {
    let s = fs::read_to_string(path)?;
    parse_config(&s)
}

/// Parse configuration from a string.
fn parse_config(s: &str) -> io::Result<Config> {
    let mut cfg = Config::default();

    for (lineno, line) in s.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let lhs = lhs.trim();
        let mut val = rhs.trim();
        if val.ends_with('#') {
            val = val.split('#').next().unwrap().trim();
        }

        let (section, key) = if let Some((a, b)) = lhs.split_once('.') {
            (a.trim(), b.trim())
        } else {
            ("", lhs)
        };

        if section.is_empty() {
            continue;
        }

        set_config_value(section, key, val, &mut cfg).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: {}", lineno + 1, e),
            )
        })?;
    }

    Ok(cfg)
}

#[cfg(test)]
mod scoring_validation_tests {
    use super::*;
    #[test]
    fn rejects_nonfinite_and_negative_weights() {
        for value in ["NaN", "inf", "-inf", "-1"] {
            assert!(parse_config(&format!("scoring.w_md5 = {value}")).is_err());
        }
        assert!(
            !parse_config("scoring.w_md5 = 0")
                .unwrap()
                .scoring
                .experimental_synthesis
        );
        assert!(
            parse_config("scoring.experimental_synthesis = true")
                .unwrap()
                .scoring
                .experimental_synthesis
        );
    }
}

/// Set a configuration value based on section, key, and value strings.
fn set_config_value(section: &str, key: &str, val: &str, cfg: &mut Config) -> Result<(), String> {
    macro_rules! parse {
        (s) => {
            val.trim_matches('"').to_string()
        };
        (b) => {
            match val {
                "true" => true,
                "false" => false,
                _ => return Err(format!("bad bool {val}")),
            }
        };
        (u) => {
            val.parse::<u64>().map_err(|e| e.to_string())?
        };
        (usize_) => {
            val.parse::<usize>().map_err(|e| e.to_string())?
        };
        (u32_) => {
            val.parse::<u32>().map_err(|e| e.to_string())?
        };
        (u16_) => {
            val.parse::<u16>().map_err(|e| e.to_string())?
        };
        (f64_) => {{
            let value = val.parse::<f64>().map_err(|e| e.to_string())?;
            if !value.is_finite() || value < 0.0 {
                return Err("scoring weights must be finite and nonnegative".into());
            }
            value
        }};
    }

    match (section, key) {
        // Limits section
        ("limits", "hello_timeout_ms") => cfg.limits.hello_timeout_ms = parse!(u),
        ("limits", "command_timeout_ms") => cfg.limits.command_timeout_ms = parse!(u),
        ("limits", "tls_handshake_timeout_ms") => cfg.limits.tls_handshake_timeout_ms = parse!(u),
        ("limits", "pull_timeout_ms") => cfg.limits.pull_timeout_ms = parse!(u),
        ("limits", "push_timeout_ms") => cfg.limits.push_timeout_ms = parse!(u),
        ("limits", "max_active_conns") => cfg.limits.max_active_conns = parse!(usize_),
        ("limits", "max_hello_frame_bytes") => cfg.limits.max_hello_frame_bytes = parse!(usize_),
        ("limits", "max_cmd_frame_bytes") => cfg.limits.max_cmd_frame_bytes = parse!(usize_),
        ("limits", "max_pull_items") => cfg.limits.max_pull_items = parse!(usize_),
        ("limits", "max_push_items") => cfg.limits.max_push_items = parse!(usize_),
        ("limits", "max_del_items") => cfg.limits.max_del_items = parse!(usize_),
        ("limits", "max_hist_items") => cfg.limits.max_hist_items = parse!(usize_),
        ("limits", "max_name_bytes") => cfg.limits.max_name_bytes = parse!(usize_),
        ("limits", "max_data_bytes") => cfg.limits.max_data_bytes = parse!(usize_),
        ("limits", "per_connection_inflight_bytes") => {
            cfg.limits.per_connection_inflight_bytes = parse!(usize_)
        }
        ("limits", "global_inflight_bytes") => cfg.limits.global_inflight_bytes = parse!(usize_),
        ("limits", "lumina_max_cstr_bytes") => cfg.limits.lumina_max_cstr_bytes = parse!(usize_),
        ("limits", "lumina_max_hash_bytes") => cfg.limits.lumina_max_hash_bytes = parse!(usize_),

        // HTTP section
        ("http", "bind_addr") => {
            cfg.http.get_or_insert_with(Http::default).bind_addr = parse!(s);
        }

        // Engine section
        ("engine", "data_dir") => cfg.engine.data_dir = parse!(s),
        ("engine", "segment_bytes") => cfg.engine.segment_bytes = parse!(u),
        ("engine", "shard_count") => cfg.engine.shard_count = parse!(usize_),
        ("engine", "index_capacity") => cfg.engine.index_capacity = parse!(usize_),
        ("engine", "sync_interval_ms") => cfg.engine.sync_interval_ms = parse!(u),
        ("engine", "compaction_check_ms") => cfg.engine.compaction_check_ms = parse!(u),
        ("engine", "use_mmap_reads") => cfg.engine.use_mmap_reads = parse!(b),
        ("engine", "deduplicate_on_startup") => cfg.engine.deduplicate_on_startup = parse!(b),
        ("engine", "index_dir") => {
            let v = parse!(s);
            cfg.engine.index_dir = if v.is_empty() { None } else { Some(v) };
        }
        ("engine", "index_memtable_max_entries") => {
            cfg.engine.index_memtable_max_entries = parse!(usize_)
        }
        ("engine", "index_block_entries") => cfg.engine.index_block_entries = parse!(usize_),
        ("engine", "index_level0_compact_trigger") => {
            cfg.engine.index_level0_compact_trigger = parse!(usize_)
        }

        // Lumina section
        ("lumina", "bind_addr") => cfg.lumina.bind_addr = parse!(s),
        ("lumina", "server_name") => cfg.lumina.server_name = parse!(s),
        ("lumina", "allow_deletes") => cfg.lumina.allow_deletes = parse!(b),
        ("lumina", "get_history_limit") => cfg.lumina.get_history_limit = parse!(u32_),
        ("lumina", "use_tls") => cfg.lumina.use_tls = parse!(b),

        // TLS section
        ("tls", "pkcs12_path") => {
            cfg.lumina.tls.get_or_insert_with(TLS::default).pkcs12_path = parse!(s);
        }
        ("tls", "env_password_var") => {
            cfg.lumina
                .tls
                .get_or_insert_with(TLS::default)
                .env_password_var = parse!(s);
        }
        ("tls", "min_protocol_sslv3") => {
            cfg.lumina
                .tls
                .get_or_insert_with(TLS::default)
                .min_protocol_sslv3 = parse!(b);
        }
        ("tls", "cert_pem_path") => {
            let v = parse!(s);
            cfg.lumina
                .tls
                .get_or_insert_with(TLS::default)
                .cert_pem_path = if v.is_empty() { None } else { Some(v) };
        }
        ("tls", "key_pem_path") => {
            let v = parse!(s);
            cfg.lumina.tls.get_or_insert_with(TLS::default).key_pem_path =
                if v.is_empty() { None } else { Some(v) };
        }

        // Upstream section (indexed)
        ("upstream", key) if key.starts_with(|c: char| c.is_ascii_digit()) => {
            let parts: Vec<&str> = key.splitn(2, '.').collect();
            if parts.len() != 2 {
                return Err(format!("invalid upstream key format: {}", key));
            }
            let idx = parts[0].parse::<usize>().map_err(|e| e.to_string())?;
            let field = parts[1];

            while cfg.upstreams.len() <= idx {
                cfg.upstreams.push(Upstream {
                    priority: cfg.upstreams.len() as u32,
                    ..Upstream::default()
                });
            }

            match field {
                "enabled" => cfg.upstreams[idx].enabled = parse!(b),
                "priority" => cfg.upstreams[idx].priority = parse!(u32_),
                "host" => cfg.upstreams[idx].host = parse!(s),
                "port" => cfg.upstreams[idx].port = parse!(u16_),
                "use_tls" => cfg.upstreams[idx].use_tls = parse!(b),
                "insecure_no_verify" => cfg.upstreams[idx].insecure_no_verify = parse!(b),
                "hello_protocol_version" => {
                    cfg.upstreams[idx].hello_protocol_version = parse!(u32_)
                }
                "license_path" => {
                    let v = parse!(s);
                    cfg.upstreams[idx].license_path = if v.is_empty() { None } else { Some(v) };
                }
                "timeout_ms" => cfg.upstreams[idx].timeout_ms = parse!(u),
                "batch_max" => cfg.upstreams[idx].batch_max = parse!(usize_),
                _ => return Err(format!("unknown upstream field: {}", field)),
            }
        }

        // Scoring section
        ("scoring", "experimental_synthesis") => cfg.scoring.experimental_synthesis = parse!(b),
        ("scoring", "w_md5") => cfg.scoring.w_md5 = parse!(f64_),
        ("scoring", "w_name") => cfg.scoring.w_name = parse!(f64_),
        ("scoring", "w_coh") => cfg.scoring.w_coh = parse!(f64_),
        ("scoring", "w_stab") => cfg.scoring.w_stab = parse!(f64_),
        ("scoring", "w_rec") => cfg.scoring.w_rec = parse!(f64_),
        ("scoring", "w_pop_bin") => cfg.scoring.w_pop_bin = parse!(f64_),
        ("scoring", "w_host") => cfg.scoring.w_host = parse!(f64_),
        ("scoring", "w_origin") => cfg.scoring.w_origin = parse!(f64_),
        ("scoring", "max_versions_per_key") => cfg.scoring.max_versions_per_key = parse!(usize_),
        ("scoring", "max_md5_per_key") => cfg.scoring.max_md5_per_key = parse!(usize_),
        ("scoring", "max_md5_per_version") => cfg.scoring.max_md5_per_version = parse!(usize_),

        // Debug section
        ("debug", "dump_hello") => cfg.debug.dump_hello = parse!(b),
        ("debug", "dump_hello_dir") => cfg.debug.dump_hello_dir = parse!(s),

        _ => return Err(format!("unknown key {section}.{key}")),
    }

    Ok(())
}

impl Config {
    /// Load configuration from a file path.
    pub fn load(path: &str) -> io::Result<Self> {
        load_config(path)
    }
}
