//! Timings for the binary neighbourhood scans.
//!
//! Ignored by default: it needs a synthetic store, which is expensive to write
//! and is therefore built once and reused. Run it by hand when the scan paths
//! change:
//!
//! ```text
//! BENCH_STORE=/tmp/dazhbog-bench-store \
//!   cargo test --release --test neighbor_scan_bench -- --ignored --nocapture
//! ```
//!
//! The first run populates `BENCH_STORE`; later runs copy it, so every run
//! measures the same cold caches.

use dazhbog::config::Config;
use dazhbog::db::Database;
use dazhbog::engine::EngineRuntime;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const BINARIES: u8 = 24;
const SEED_KEYS: u128 = 8192;

fn env_keys() -> u128 {
    std::env::var("BENCH_KEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SEED_KEYS)
}

struct TemporaryStore(PathBuf);

impl Drop for TemporaryStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Write the synthetic store: the seed carries every key, and each key is also
/// carried by a slice of the other binaries, so neighbour aggregation has to
/// visit every posting.
fn populate(path: &Path) -> io::Result<()> {
    let mut cfg = Config::default();
    cfg.engine.data_dir = path.to_string_lossy().into_owned();
    let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
    for binary in 1..=BINARIES {
        rt.ctx_index.record_binary_meta(
            [binary; 16],
            &format!("bin{binary}.dll"),
            "host",
            "token",
            1_700_000_000 + u64::from(binary),
        )?;
    }
    let start = Instant::now();
    for key in 0..env_keys() {
        rt.ctx_index
            .record_key_observation(key, [1; 16], Some([1; 32]), 1_700_000_000, None)?;
        let fanout = 2 + (key % 6) as u8;
        for step in 0..fanout {
            let binary = 2 + ((key as u8).wrapping_add(step) % (BINARIES - 1));
            rt.ctx_index.record_key_observation(
                key,
                [binary; 16],
                Some([1; 32]),
                1_700_000_000,
                None,
            )?;
        }
    }
    rt.flush()?;
    println!(
        "store: {} keys over {BINARIES} binaries written in {:.1} s",
        env_keys(),
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

/// A private copy of the fixture, so each run starts from the same caches.
fn checkout() -> io::Result<(TemporaryStore, Arc<Config>)> {
    let fixture = std::env::var("BENCH_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("dazhbog-bench-store"));
    if !fixture.join("context_db").exists() {
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(&fixture)?;
        populate(&fixture)?;
    }
    let path = std::env::temp_dir().join(format!("dazhbog-bench-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let start = Instant::now();
    copy_tree(&fixture, &path)?;
    println!("fixture copied in {:.1} s", start.elapsed().as_secs_f64());
    let cleanup = TemporaryStore(path.clone());
    let mut cfg = Config::default();
    cfg.engine.data_dir = path.to_string_lossy().into_owned();
    Ok((cleanup, Arc::new(cfg)))
}

async fn timed<T>(label: &str, future: impl std::future::Future<Output = io::Result<T>>) -> T {
    let start = Instant::now();
    let value = future.await.expect("scan failed");
    println!(
        "{label:<10} {:>9.1} ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
    value
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "timing harness over a synthetic store"]
async fn neighbour_scan_timings() -> io::Result<()> {
    let _ = pretty_env_logger::try_init();
    let (_cleanup, cfg) = checkout()?;
    let db = Database::open_for_replay(cfg).await?;
    // The order a binary detail page reads in.
    for pass in ["cold caches", "warm caches"] {
        println!("--- {pass} ---");
        let start = Instant::now();
        timed("facets", db.get_binary_facets([1; 16], 8192)).await;
        timed("functions", db.get_binary_function_hits([1; 16], 0, 25)).await;
        timed("related", db.get_binary_related([1; 16], 8)).await;
        timed("overlap", db.get_binary_overlap([1; 16], 8)).await;
        timed("graph", db.get_binary_graph([1; 16], 2, 6)).await;
        timed("timeline", db.get_binary_family_timeline([1; 16], 12)).await;
        timed("shared", db.shared_code_profile([1; 16], [2; 16], 12)).await;
        println!(
            "{:<10} {:>9.1} ms",
            "page",
            start.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}
