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

fn push(db: &Database, binary: u8, key: u128, name: &str, data: &[u8]) -> io::Result<()> {
    Database::push_with_ctx_sync(
        &db.rt,
        &[(key, 1, 8, name.to_string(), data.to_vec())],
        &OwnedPushContext {
            md5: Some([binary; 16]),
            basename: Some(format!("bin{binary}.dll")),
            hostname: None,
            origin_token: None,
        },
        false,
    )?;
    Ok(())
}

#[test]
fn component_token_reads_conventions_and_refuses_guesses() {
    assert_eq!(component_token("png_read_info").as_deref(), Some("png"));
    assert_eq!(component_token("_curl_easy_init").as_deref(), Some("curl"));
    assert_eq!(component_token("SSL_CTX_new").as_deref(), Some("SSL"));
    assert_eq!(
        component_token("boost::filesystem::path::stem").as_deref(),
        Some("boost")
    );
    // A generic namespace defers to the component underneath it.
    assert_eq!(
        component_token("std::vector::_M_realloc").as_deref(),
        Some("vector")
    );
    // Nothing conventional to read: no component rather than a guess.
    assert_eq!(component_token("WinMain"), None);
    assert_eq!(component_token("sub_140001000"), None);
    assert_eq!(component_token("j_memcpy"), None);
    assert_eq!(component_token("a_b"), None);
    assert_eq!(component_token(""), None);
}

#[tokio::test]
async fn shared_code_profile_ranks_rare_symbols_and_names_components() -> io::Result<()> {
    let (_cleanup, db) = store("shared")?;
    // A private component in both binaries, plus a runtime symbol everywhere.
    for (key, name) in [
        (1u128, "zfoo_open"),
        (2, "zfoo_close"),
        (3, "zfoo_read"),
        (4, "memcpy_impl"),
    ] {
        for binary in [1u8, 2] {
            push(&db, binary, key, name, &[42, 1, 7])?;
        }
    }
    for binary in 3u8..=9 {
        push(&db, binary, 4, "memcpy_impl", &[42, 1, 7])?;
    }
    // A key whose head moved to another binary's metadata: naming must fall
    // back to selection instead of dropping the symbol.
    for binary in [1u8, 2] {
        push(&db, binary, 7, "zfoo_write", &[42, 1, binary])?;
    }
    push(&db, 1, 5, "only_left", &[42, 1, 1])?;
    push(&db, 2, 6, "only_right", &[42, 1, 2])?;

    let profile = db.shared_code_profile([1; 16], [2; 16], 12).await?;
    assert_eq!(profile.shared_keys, 5);
    assert_eq!(profile.probe_limit, Database::OVERLAP_PROBE_KEYS);
    assert!(!profile.truncated);
    assert_eq!(
        profile.components.first().map(|c| c.token.as_str()),
        Some("zfoo"),
        "the shared private component must lead: {:?}",
        profile.components
    );
    assert_eq!(profile.components[0].functions, 4);
    assert_eq!(profile.components[0].median_binary_count, 2);
    assert_eq!(profile.named_keys, 5);
    let names: Vec<&str> = profile.samples.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names.len(), 5);
    assert_eq!(
        names.last(),
        Some(&"memcpy_impl"),
        "the most widespread symbol must rank last: {names:?}"
    );
    assert!(profile.samples.iter().all(|s| !s.binary_count_capped));
    assert_eq!(
        profile
            .samples
            .iter()
            .find(|s| s.name == "memcpy_impl")
            .map(|s| s.binary_count),
        Some(9)
    );

    // A binary compared with itself reports no shared evidence.
    let self_profile = db.shared_code_profile([1; 16], [1; 16], 12).await?;
    assert_eq!(self_profile.shared_keys, 0);
    assert!(self_profile.samples.is_empty());
    Ok(())
}

#[tokio::test]
async fn neighbourhood_views_agree_and_survive_the_cache() -> io::Result<()> {
    let (_cleanup, db) = store("aggregate")?;
    for binary in 1..=3u8 {
        db.rt.ctx_index.record_binary_meta(
            [binary; 16],
            &format!("bin{binary}.dll"),
            "host",
            "token",
            1_700_000_000 + u64::from(binary),
        )?;
    }
    // Seed key 1 is seen twice here and once next door; key 2 the other way
    // round. Agreement is capped per key by the scarcer side, so each key
    // contributes one observation.
    let observe = |key: u128, binary: u8, times: usize| -> io::Result<()> {
        for _ in 0..times {
            db.rt.ctx_index.record_key_observation(
                key,
                [binary; 16],
                Some([binary; 32]),
                1_700_000_000,
                None,
            )?;
        }
        Ok(())
    };
    observe(1, 1, 2)?;
    observe(1, 2, 1)?;
    observe(2, 1, 1)?;
    observe(2, 2, 3)?;
    observe(3, 1, 1)?;
    observe(3, 3, 1)?;

    let expected = [([2u8; 16], 2u64, 2u64), ([3u8; 16], 1, 1)];
    // Every view is built from one aggregate, so a pair reads the same way
    // wherever it is reported, cold or cached.
    for round in 0..2 {
        let overlap = db.get_binary_overlap([1; 16], 8).await?;
        let related = db.get_binary_related([1; 16], 8).await?;
        let timeline = db.get_binary_family_timeline([1; 16], 8).await?;
        for (md5, shared_functions, shared_observations) in expected {
            let hex = md5_hex(md5[0]);
            assert_eq!(
                overlap
                    .iter()
                    .find(|(summary, _)| summary.md5_hex == hex)
                    .map(|(_, shared)| *shared),
                Some(shared_functions),
                "overlap disagrees on round {round}"
            );
            assert_eq!(
                related
                    .iter()
                    .find(|(summary, ..)| summary.md5_hex == hex)
                    .map(|(_, functions, observations, ..)| (*functions, *observations)),
                Some((shared_functions, shared_observations)),
                "related disagrees on round {round}"
            );
            assert_eq!(
                timeline
                    .iter()
                    .find(|(summary, ..)| summary.md5_hex == hex)
                    .map(|(_, functions, observations, ..)| (*functions, *observations)),
                Some((shared_functions, shared_observations)),
                "timeline disagrees on round {round}"
            );
        }
        assert!(
            timeline
                .iter()
                .any(|(summary, .., is_root)| *is_root && summary.md5_hex == md5_hex(1)),
            "the seed is missing from its own timeline"
        );
    }

    // A later observation invalidates the aggregate rather than serving a
    // stale neighbour count.
    observe(4, 1, 1)?;
    observe(4, 3, 1)?;
    let related = db.get_binary_related([1; 16], 8).await?;
    assert_eq!(
        related
            .iter()
            .find(|(summary, ..)| summary.md5_hex == md5_hex(3))
            .map(|(_, functions, observations, ..)| (*functions, *observations)),
        Some((2, 2)),
        "a new shared observation did not reach the neighbourhood"
    );
    Ok(())
}
