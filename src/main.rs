#![deny(clippy::all)]
#![warn(unused_crate_dependencies)]

mod config;
mod codec;
mod rpc;
mod engine;
mod db;
mod server;
mod http;
mod metrics;
mod util;
mod legacy;

use crate::server::serve_binary_rpc;
use crate::http::serve_http;
use crate::config::Config;
use crate::metrics::METRICS;

use log::*;
use std::sync::Arc;

fn setup_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", concat!(env!("CARGO_PKG_NAME"), "=debug"));
    }
    pretty_env_logger::init_timed();
}

#[tokio::main]
async fn main() {
    setup_logger();

    // CLI
    let mut args = std::env::args().skip(1);
    let cfg_path = args.next().unwrap_or_else(|| "config.toml".to_string());
    let cfg = Config::load(&cfg_path).unwrap_or_else(|e| {
        eprintln!("failed to read config {}: {}", cfg_path, e);
        std::process::exit(1);
    });
    let cfg = Arc::new(cfg);
    info!("config loaded from {}", cfg_path);

    // Storage engine
    let db = db::Database::open(cfg.clone())
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to open storage: {e}");
            std::process::exit(1);
        });

    // HTTP server (metrics + home + /api stub room)
    let http_task = {
        let cfg = cfg.clone();
        let db = db.clone();
        tokio::spawn(async move {
            serve_http(cfg, db).await;
        })
    };

    // Binary RPC server (TCP/TLS)
    let rpc_task = {
        let cfg = cfg.clone();
        let db = db.clone();
        tokio::spawn(async move {
            serve_binary_rpc(cfg, db).await;
        })
    };

    info!("lumen server started; press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await.expect("failed to install Ctrl-C handler");
    info!("shutting down...");

    METRICS.shutting_down.store(true, std::sync::atomic::Ordering::Relaxed);

    rpc_task.abort();
    http_task.abort();

    info!("Goodbye.");
}
