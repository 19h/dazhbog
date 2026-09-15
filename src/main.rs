#![deny(clippy::all)]
#![warn(unused_crate_dependencies)]

use dazhbog::{api, config, db, engine, net};

use crate::api::http::serve_http;
use crate::api::metrics::METRICS;
use crate::config::Config;
use crate::net::serve_binary_rpc;

use log::*;
use std::sync::Arc;

fn setup_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", concat!(env!("CARGO_PKG_NAME"), "=debug"));
    }
    pretty_env_logger::init_timed();
}

fn print_help() {
    println!("dazhbog v{}", env!("CARGO_PKG_VERSION"));
    println!("A high-performance, embedded-storage Lumina server compatible with IDA Pro 7.2+\n");
    println!("USAGE:");
    println!("    dazhbog [OPTIONS] [CONFIG_FILE]\n");
    println!("OPTIONS:");
    println!("    -h, --help       Show this help message\n");
    println!("    --prepare FILE   Prepare an offline database copy; never starts listeners\n");
    println!("    --prepare-salvage FILE   Prepare while reporting/excluding unreadable keys from search\n");
    println!("ARGUMENTS:");
    println!("    [CONFIG_FILE]    Path to configuration file (default: config.toml)\n");
    println!("CONFIGURATION:");
    println!("The configuration file uses a simple key=value format with sections.\n");
    println!("[limits] - Connection and resource limits");
    println!("  hello_timeout_ms = 3000                    # Timeout for initial handshake (ms)");
    println!("  command_timeout_ms = 15000                 # Timeout for commands (ms)");
    println!("  tls_handshake_timeout_ms = 5000            # TLS handshake timeout (ms)");
    println!("  pull_timeout_ms = 15000                    # PULL operation timeout (ms)");
    println!("  push_timeout_ms = 15000                    # PUSH operation timeout (ms)");
    println!("  max_active_conns = 2048                    # Maximum concurrent connections");
    println!("  max_hello_frame_bytes = 16777216           # Max size of hello frame (16MB)");
    println!("  max_cmd_frame_bytes = 268435456            # Max size of command frame (256MB)");
    println!("  max_pull_items = 524288                    # Max items in PULL request");
    println!("  max_push_items = 524288                    # Max items in PUSH request");
    println!("  max_del_items = 524288                     # Max items in DELETE request");
    println!("  max_hist_items = 4096                      # Max items in history request");
    println!("  max_name_bytes = 65535                     # Max length of name field");
    println!("  max_data_bytes = 8388608                   # Max size of data field (8MB)");
    println!("  per_connection_inflight_bytes = 33554432   # Per-connection memory limit (32MB)");
    println!("  global_inflight_bytes = 536870912          # Global memory limit (512MB)");
    println!(
        "  lumina_max_cstr_bytes = 4096               # Max C-string length in Lumina protocol"
    );
    println!("  lumina_max_hash_bytes = 64                 # Max hash length\n");
    println!("[engine] - Storage engine configuration");
    println!("  data_dir = \"data\"                          # Data directory path");
    println!("  segment_bytes = 1073741824                 # Segment file size (1GB)");
    println!("  shard_count = 64                           # Number of shards");
    println!("  index_capacity = 1073741824                # Index capacity (1GB)");
    println!("  sync_interval_ms = 200                     # Sync to disk interval (ms)");
    println!("  compaction_check_ms = 30000                # Compaction check interval (ms)");
    println!("  use_mmap_reads = false                     # Use memory-mapped file reads");
    println!("  deduplicate_on_startup = false             # Remove duplicates on startup (rewrites segments)");
    println!("  index_dir = \"\"                             # Optional separate index directory");
    println!("  index_memtable_max_entries = 200000        # Max entries in index memtable");
    println!("  index_block_entries = 128                  # Entries per index block");
    println!("  index_level0_compact_trigger = 8           # Trigger for level 0 compaction\n");
    println!("[lumina] - Lumina protocol server configuration");
    println!("  bind_addr = \"0.0.0.0:20667\"                # Lumina server bind address");
    println!("  server_name = \"dazhbog\"                    # Server identifier");
    println!("  allow_deletes = false                      # Allow DELETE operations");
    println!("  get_history_limit = 0                      # History query limit (0 = disabled)");
    println!("  use_tls = false                            # Enable TLS\n");
    println!("[tls] - TLS configuration (when lumina.use_tls = true)");
    println!("  pkcs12_path = \"\"                           # Path to PKCS12 certificate file");
    println!(
        "  env_password_var = \"PKCSPASSWD\"            # Environment variable for PKCS12 password"
    );
    println!("  min_protocol_sslv3 = true                  # Allow SSLv3 as minimum protocol\n");
    println!("[http] - HTTP API server configuration");
    println!("  bind_addr = \"127.0.0.1:8080\"               # HTTP server bind address\n");
    println!("[upstream] - Optional upstream server configuration");
    println!("  enabled = false                            # Enable upstream forwarding");
    println!("  host = \"\"                                  # Upstream server hostname");
    println!("  port = 0                                   # Upstream server port");
    println!("  use_tls = true                             # Use TLS for upstream connection");
    println!("  insecure_no_verify = true                  # Skip TLS certificate verification");
    println!("  hello_protocol_version = 6                 # Protocol version for handshake");
    println!("  license = \"\"                               # Optional license string");
    println!("  timeout_ms = 8000                          # Upstream request timeout (ms)");
    println!("  batch_max = 1024                           # Max items per upstream batch\n");
    println!("EXAMPLES:");
    println!("    dazhbog                                   # Use default config.toml");
    println!("    dazhbog myconfig.toml                     # Use custom config file");
    println!("    dazhbog --help                            # Show this help");
}

fn main() {
    let mut args = std::env::args().skip(1);

    // Check for help flag
    if let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            print_help();
            return;
        }
        if arg == "--prepare" || arg == "--prepare-salvage" {
            setup_logger();
            let result = (|| -> std::io::Result<()> {
                let path = args
                    .next()
                    .ok_or_else(|| std::io::Error::other("--prepare requires CONFIG"))?;
                if args.next().is_some() {
                    return Err(std::io::Error::other("unexpected arguments"));
                }
                let cfg = Config::load(&path)?;
                let rt = if arg == "--prepare-salvage" {
                    engine::EngineRuntime::prepare_salvage(cfg.engine, cfg.scoring)?
                } else {
                    engine::EngineRuntime::prepare(cfg.engine, cfg.scoring)?
                };
                rt.flush()?;
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("preparation failed: {e}");
                std::process::exit(1);
            }
            return;
        }
        // Use provided config path
        setup_logger();
        let cfg = Config::load(&arg).unwrap_or_else(|e| {
            eprintln!("failed to read config {}: {}", arg, e);
            std::process::exit(1);
        });
        let cfg = Arc::new(cfg);
        info!("config loaded from {}", arg);

        run_server(cfg);
    } else {
        // Use default config.toml
        setup_logger();
        let cfg = Config::load("config.toml").unwrap_or_else(|e| {
            eprintln!("failed to read config config.toml: {}", e);
            std::process::exit(1);
        });
        let cfg = Arc::new(cfg);
        info!("config loaded from config.toml");

        run_server(cfg);
    }
}

fn run_server(cfg: Arc<Config>) {
    // Create a small runtime just for initialization
    let init_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build init runtime");

    let db = init_runtime.block_on(async {
        db::Database::open(cfg.clone()).await.unwrap_or_else(|e| {
            eprintln!("failed to open storage: {e}");
            std::process::exit(1);
        })
    });

    // Create separate runtime for RPC server with more worker threads
    // RPC handles large responses and needs more parallelism
    let rpc_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16) // Increased worker threads for RPC
        .thread_name("rpc-worker")
        .enable_all()
        .build()
        .expect("failed to build RPC runtime");

    // Create separate runtime for HTTP server
    // HTTP needs to stay responsive and gets its own dedicated pool
    let http_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4) // Smaller pool for HTTP (lighter load)
        .thread_name("http-worker")
        .enable_all()
        .build()
        .expect("failed to build HTTP runtime");

    info!("Created separate runtimes: RPC (16 workers), HTTP (4 workers)");

    // Spawn HTTP server on its dedicated runtime
    let http_handle = {
        let cfg = cfg.clone();
        let db = db.clone();
        std::thread::spawn(move || {
            http_runtime.block_on(async move {
                serve_http(cfg, db).await;
            });
        })
    };

    // Spawn RPC server on its dedicated runtime
    let rpc_handle = {
        let cfg = cfg.clone();
        let db = db.clone();
        std::thread::spawn(move || {
            rpc_runtime.block_on(async move {
                serve_binary_rpc(cfg, db).await;
            });
        })
    };

    info!("dazhbog server started; press Ctrl-C to stop.");

    // Wait for Ctrl-C in the init runtime
    init_runtime.block_on(async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    });

    info!("shutting down...");

    METRICS
        .shutting_down
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let http_result = http_handle.join();
    let rpc_result = rpc_handle.join();
    if http_result.is_err() || rpc_result.is_err() {
        error!("listener runtime failed during shutdown");
    }
    if let Err(e) = db.flush() {
        error!("storage flush failed: {e}");
        std::process::exit(1);
    }

    info!("Goodbye.");
}
