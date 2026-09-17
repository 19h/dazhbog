use super::*;

struct TemporaryStore(std::path::PathBuf);

impl Drop for TemporaryStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store(label: &str) -> io::Result<(TemporaryStore, Database)> {
    let path = std::env::temp_dir().join(format!("dazhbog-graph-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir(&path)?;
    let mut cfg = Config::default();
    cfg.engine.data_dir = path.to_string_lossy().into_owned();
    let cleanup = TemporaryStore(path);
    let rt = Arc::new(EngineRuntime::open(cfg.engine, cfg.scoring)?);
    Ok((
        cleanup,
        Database {
            rt,
            failure_cache: FailureCache::new(),
        },
    ))
}

fn md5_hex(binary: u8) -> String {
    format!("{binary:02x}").repeat(16)
}

/// Star of five neighbours around seed `1`, each carrying one outer binary.
fn record_star(db: &Database) -> io::Result<()> {
    let mut key = 0u128;
    for (left, right) in (2u8..=6)
        .map(|neighbor| (1u8, neighbor))
        .chain((2u8..=6).map(|neighbor| (neighbor, neighbor + 10)))
    {
        for binary in [left, right] {
            db.rt.ctx_index.record_binary_meta(
                [binary; 16],
                &format!("bin{binary}.dll"),
                "host",
                "token",
                1000 + u64::from(binary),
            )?;
        }
        for _ in 0..6 {
            key += 1;
            for binary in [left, right] {
                db.rt.ctx_index.record_key_observation(
                    key,
                    [binary; 16],
                    Some([key as u8; 32]),
                    1000,
                    None,
                )?;
            }
        }
    }
    Ok(())
}

fn node(nodes: &[(BinarySummary, u32, bool)], binary: u8) -> Option<(u32, bool)> {
    nodes
        .iter()
        .find(|(summary, _, _)| summary.md5_hex == md5_hex(binary))
        .map(|(_, depth, expanded)| (*depth, *expanded))
}

#[tokio::test]
async fn binary_graph_tags_depth_and_defers_cold_expansion() -> io::Result<()> {
    let (_cleanup, db) = store("expansion")?;
    record_star(&db)?;

    // Expanding a binary with a cold overlap cache scans its whole key prefix,
    // so a deep request must not fan out over every neighbour at once.
    let (nodes, edges) = db.get_binary_graph([1; 16], 3, 8).await?;
    assert_eq!(node(&nodes, 1), Some((0, true)));
    for neighbor in 2u8..=6 {
        assert_eq!(
            node(&nodes, neighbor).map(|(depth, _)| depth),
            Some(1),
            "neighbour {neighbor} must be a direct relation"
        );
    }
    let cold_expanded = (2u8..=6)
        .filter(|neighbor| node(&nodes, *neighbor) == Some((1, true)))
        .count();
    assert_eq!(cold_expanded, 2, "cold expansion must stop at the budget");
    assert_eq!(
        nodes.iter().filter(|(_, depth, _)| *depth == 2).count(),
        cold_expanded,
        "every expanded neighbour contributes exactly one inferred binary"
    );
    assert!(
        edges.iter().all(|(source, target, shared)| {
            *shared > 0
                && nodes.iter().any(|(node, _, _)| &node.md5_hex == source)
                && nodes.iter().any(|(node, _, _)| &node.md5_hex == target)
        }),
        "every edge must be weighted and anchored on retained nodes"
    );
    let mut pairs: Vec<_> = edges
        .iter()
        .map(|(source, target, _)| {
            if source <= target {
                (source.clone(), target.clone())
            } else {
                (target.clone(), source.clone())
            }
        })
        .collect();
    let reported = pairs.len();
    pairs.sort();
    pairs.dedup();
    assert_eq!(reported, pairs.len(), "graph edges are reported twice");

    // A warm overlap cache is what makes deeper expansion cheap, so priming
    // every neighbour must open up the whole second hop.
    for neighbor in 2u8..=6 {
        let _ = db.get_binary_overlap([neighbor; 16], 8).await?;
    }
    let (warm_nodes, _) = db.get_binary_graph([1; 16], 3, 8).await?;
    for neighbor in 2u8..=6 {
        assert_eq!(
            node(&warm_nodes, neighbor),
            Some((1, true)),
            "warm neighbour {neighbor} was not expanded"
        );
        assert_eq!(
            node(&warm_nodes, neighbor + 10).map(|(depth, _)| depth),
            Some(2),
            "inferred binary behind neighbour {neighbor} is missing"
        );
    }

    // Depth 1 stops at the direct relations regardless of cache state.
    let (shallow, _) = db.get_binary_graph([1; 16], 1, 8).await?;
    assert!(shallow.iter().all(|(_, depth, _)| *depth <= 1));
    Ok(())
}

#[tokio::test]
async fn binary_graph_is_empty_for_unknown_seed() -> io::Result<()> {
    let (_cleanup, db) = store("unknown")?;
    let (nodes, edges) = db.get_binary_graph([7; 16], 2, 6).await?;
    assert!(nodes.is_empty() && edges.is_empty());
    Ok(())
}
