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
    println!(
        r#"
Lumina-compatible function metadata server

USAGE:
    dazhbog [CONFIG_FILE]
    dazhbog --prepare CONFIG_FILE
    dazhbog --prepare-salvage CONFIG_FILE
    dazhbog --help

CONFIG_FILE defaults to config.toml for server startup.
Preparation requires an explicit configuration pointing to an offline copy.
--prepare-salvage reports and excludes unreadable keys from the search projection.

CONFIGURATION:
    Use dotted key=value assignments, for example:
    engine.data_dir = "data"
    lumina.bind_addr = "127.0.0.1:20667"
    lumina.use_tls = false
    http.bind_addr = "127.0.0.1:8080"
    scoring.experimental_synthesis = false
    scoring.max_key_repeats = 1                # decline a pattern matching several functions
    scoring.template_skeleton_names = true     # serve template members with a placeholder type
    scoring.foreign_specific_decline = true    # withhold another program's name from unrelated requesters
    scoring.sibling_window = 8                 # neighbours searched to pin a specialization
    debug.dump_pull = false                    # capture pulls as replayable fixtures for analyze-pull

See README.md for preparation, configuration and evaluation details.
"#
    );
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
