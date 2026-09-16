//! Sequential phase timings on an offline prepared copy; later phases reuse caches.
use dazhbog::{config::Config, db::Database};
use std::{future::Future, io, sync::Arc, time::Instant};

async fn timed<T>(phase: &str, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    let start = Instant::now();
    let result = future.await;
    println!(
        "{}",
        serde_json::json!({
            "phase": phase,
            "elapsed_s": start.elapsed().as_secs_f64(),
            "success": result.is_ok(),
            "error": result.as_ref().err().map(ToString::to_string),
        })
    );
    result
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[1].len() != 32 || !args[1].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: profile-binary CONFIG MD5 (32 hexadecimal digits); use an offline prepared copy",
        ));
    }
    let md5 = u128::from_str_radix(&args[1], 16)
        .map_err(io::Error::other)?
        .to_be_bytes();
    let cfg = Arc::new(Config::load(&args[0])?);
    dazhbog::db::semantic::set_name_rejection_policy(cfg.lumina.name_rejection);
    let db = timed("open", Database::open_for_replay(cfg)).await?;
    let summary = timed("summary_and_facets", db.get_binary_summary(md5))
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "binary not found"))?;
    println!(
        "{}",
        serde_json::json!({"binary_md5": args[1], "functions": summary.function_count,
            "coverage": summary.coverage})
    );
    timed("functions", db.get_binary_function_hits(md5, 0, 25)).await?;
    timed("related", db.get_binary_related(md5, 8)).await?;
    timed("graph", db.get_binary_graph(md5, 2, 6)).await?;
    timed("timeline", db.get_binary_family_timeline(md5, 12)).await?;
    db.flush()
}
