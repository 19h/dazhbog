use dazhbog::common::hash::version_id;
use dazhbog::config::Config;
use dazhbog::db::{Database, QueryContext};
use dazhbog::engine::{EngineRuntime, Record};
use dazhbog::protocol::lumina::{pack_dd, MdKey};
use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

struct Fixture {
    path: PathBuf,
    cfg: Config,
}

#[test]
fn evaluation_cli_rejects_unknown_mode_and_empty_samples() {
    let executable = env!("CARGO_BIN_EXE_eval-binary-context");
    let invalid = std::process::Command::new(executable)
        .args(["unused-config", "1", "2", "1", "unknown-mode"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("mode must be observed or transfer"));

    let fixture = Fixture::new();
    let config_path = fixture.path.join("empty.toml");
    let data_path = fixture.path.join("empty-db");
    std::fs::write(
        &config_path,
        format!("engine.data_dir = \"{}\"\n", data_path.display()),
    )
    .unwrap();
    let empty = std::process::Command::new(executable)
        .arg(config_path)
        .args(["1", "2", "1", "transfer"])
        .output()
        .unwrap();
    assert!(!empty.status.success());
    assert!(String::from_utf8_lossy(&empty.stderr).contains("no qualifying binary batches"));
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "dazhbog-selection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let mut cfg = Config::default();
        cfg.engine.data_dir = path.to_string_lossy().into_owned();
        cfg.http = None;
        cfg.scoring.w_stab = 0.0;
        cfg.scoring.w_rec = 0.0;
        cfg.scoring.w_pop_bin = 0.0;
        Self { path, cfg }
    }
    fn runtime(&self) -> EngineRuntime {
        EngineRuntime::open(self.cfg.engine.clone(), self.cfg.scoring.clone()).unwrap()
    }
    async fn database(&self) -> Arc<Database> {
        drop(EngineRuntime::prepare(self.cfg.engine.clone(), self.cfg.scoring.clone()).unwrap());
        Database::open_for_replay(Arc::new(self.cfg.clone()))
            .await
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn append(
    rt: &EngineRuntime,
    key: u128,
    name: &str,
    ts: u64,
    md5: [u8; 16],
    observations: usize,
) -> [u8; 32] {
    append_with_identity(rt, key, name, ts, md5, observations, false)
}

fn append_with_identity(
    rt: &EngineRuntime,
    key: u128,
    name: &str,
    ts: u64,
    md5: [u8; 16],
    observations: usize,
    legacy: bool,
) -> [u8; 32] {
    let text = format!("{name}\0");
    let mut data = pack_dd(MdKey::Fcmt.raw());
    data.extend(pack_dd(text.len() as u32));
    data.extend(text.as_bytes());
    let vid = if legacy {
        historical_id(key, name, &data)
    } else {
        version_id(key, name, &data)
    };
    let rec = Record {
        key,
        ts_sec: ts,
        prev_addr: rt.index.try_get(key).unwrap(),
        len_bytes: data.len() as u32,
        popularity: 1,
        name: name.into(),
        data,
        flags: 0,
    };
    assert!(rt
        .index
        .upsert(key, rt.segments.append(&rec).unwrap())
        .is_ok());
    observe(rt, key, vid, md5, observations);
    rt.ctx_index
        .set_canonical_version(key, vid, 1.0, ts)
        .unwrap();
    vid
}

// Exact historical writer from 8e1ffd2, independent of compatibility code.
fn historical_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    name.hash(&mut h);
    data.hash(&mut h);
    let mut id = [0; 32];
    id[..16].copy_from_slice(&key.to_le_bytes());
    id[16..24].copy_from_slice(&h.finish().to_le_bytes());
    id[24..].copy_from_slice(&(name.len() as u64).to_le_bytes());
    id
}

#[cfg(all(target_pointer_width = "64", target_endian = "little"))]
#[tokio::test]
async fn legacy_observation_retrieves_old_variant_and_keeps_diagnostic_cardinality() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    let expected;
    {
        let rt = fixture.runtime();
        expected = append_with_identity(&rt, 1, "parse_legacy_headers", 1, [1; 16], 1, true);
        append(&rt, 1, "decode_recent_pixels", 2, [2; 16], 30);
        rt.ctx_index
            .set_canonical_version(1, expected, 1.0, 1)
            .unwrap();
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        db.get_canonical(1).await.unwrap().unwrap().name,
        "parse_legacy_headers"
    );
    assert_eq!(
        db.get_latest(1).await.unwrap().unwrap().name,
        "decode_recent_pixels"
    );
    let results = db
        .select_variant_details(&QueryContext {
            keys: &[1, 1, 999],
            requested_mdkeys: &[MdKey::Ops.raw()],
            md5: Some([1; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    let chosen = results[0].as_ref().unwrap();
    assert_eq!(chosen.name, "parse_legacy_headers");
    assert!(chosen.data.is_empty());
    assert!(chosen.matches_version(&expected));
    assert!(chosen.contains_version(&expected));
    assert_eq!(chosen.candidate_version_ids.len(), 2);
    assert_eq!(chosen.candidate_legacy_version_ids.len(), 2);
    assert_eq!(
        results[1].as_ref().unwrap().base_version_id,
        chosen.base_version_id
    );
    assert!(results[2].is_none());
    let evaluated = db.evaluate_observed_binary([1; 16], &[1]).await.unwrap();
    assert!(evaluated.cases[0].expected_reachable_with_identity);
    assert!(evaluated.cases[0].canonical_matches_observation);
    assert!(!evaluated.cases[0].latest_matches_observation);
}

#[cfg(all(target_pointer_width = "64", target_endian = "little"))]
#[tokio::test]
async fn legacy_family_memberships_support_batch_inference_beyond_summary_cap() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    let expected;
    {
        let rt = fixture.runtime();
        expected = append_with_identity(&rt, 1, "parse_legacy_headers", 1, [1; 16], 1, true);
        // Crowd the target binary out of the legacy top-16 summary.
        for n in 2..=18 {
            observe(&rt, 1, expected, [n; 16], 3);
        }
        append(&rt, 1, "decode_recent_pixels", 2, [99; 16], 50);
        append_with_identity(&rt, 2, "read_legacy_stream", 1, [1; 16], 1, true);
        append_with_identity(&rt, 3, "close_legacy_stream", 1, [1; 16], 1, true);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1, 2, 3], None).await[0],
        Some("parse_legacy_headers".into())
    );
    let evaluation = db
        .evaluate_observed_binary([1; 16], &[1, 2, 3])
        .await
        .unwrap();
    assert!(evaluation
        .cases
        .iter()
        .all(|c| c.selected_matches_observation));
    assert_eq!(evaluation.cases[0].candidate_count, 2);
    assert!(evaluation.cases[0].semantic_payload_matches.unwrap());
}

fn observe(rt: &EngineRuntime, key: u128, vid: [u8; 32], md5: [u8; 16], count: usize) {
    rt.ctx_index
        .record_binary_meta(md5, "fixture.bin", "", "", 1)
        .unwrap();
    for _ in 0..count {
        rt.ctx_index
            .record_key_observation(key, md5, Some(vid), 1, None)
            .unwrap();
    }
}

#[tokio::test]
async fn known_binary_completes_sparse_query_context_without_overriding_exact_observations() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    let expected;
    {
        let rt = fixture.runtime();
        expected = append(&rt, 1, "parse_related_headers", 1, [1; 16], 1);
        append(&rt, 1, "decode_unrelated_pixels", 2, [2; 16], 1);
        for key in [2, 3] {
            let vid = append(&rt, key, "neutral_helper", 1, [1; 16], 1);
            observe(&rt, key, vid, [3; 16], 1);
        }
        let exact = append(&rt, 4, "exact_local_annotation", 1, [2; 16], 1);
        observe(&rt, 4, exact, [3; 16], 1);
        append(&rt, 4, "newer_related_annotation", 2, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    for md5 in [None, Some([99; 16])] {
        assert_eq!(
            query(&db, &[1], md5).await[0].as_deref(),
            Some("decode_unrelated_pixels")
        );
    }
    let selected = db
        .select_variant_details(&QueryContext {
            keys: &[1, 4, 1, 999],
            requested_mdkeys: &[],
            md5: Some([3; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    assert!(selected[0].as_ref().unwrap().matches_version(&expected));
    assert_eq!(selected[1].as_ref().unwrap().name, "exact_local_annotation");
    assert!(selected[2].as_ref().unwrap().matches_version(&expected));
    assert!(selected[3].is_none());
    assert_eq!(
        query(&db, &[1], Some([3; 16])).await[0].as_deref(),
        Some("parse_related_headers")
    );
    assert_eq!(
        query(&db, &[4, 1], Some([3; 16])).await[1].as_deref(),
        Some("parse_related_headers")
    );
    assert_eq!(db.delete_keys(&[1]).await.unwrap(), 1);
    assert!(query(&db, &[1], Some([3; 16])).await[0].is_none());
}

#[tokio::test]
async fn completed_context_dependencies_invalidate_small_coverage_samples() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 0, "_Z12parse_headerv", 1, [1; 16], 1);
        append(&rt, 0, "decode_pixels", 2, [2; 16], 1);
        for key in [1, 2] {
            let vid = append(&rt, key, "neutral_helper", 1, [1; 16], 1);
            observe(&rt, key, vid, [3; 16], 1);
        }
        let vid = append(&rt, 3, "neutral_helper", 1, [2; 16], 1);
        observe(&rt, 3, vid, [3; 16], 1);
        rt.flush().unwrap();
    }
    {
        // A migrated forward membership may exist without a positive current
        // observation. It must not become an exact-identity selection claim.
        let raw = sled::open(fixture.path.join("context_db")).unwrap();
        raw.open_tree("key_md5")
            .unwrap()
            .insert(
                [0u128.to_le_bytes().as_slice(), &[3; 16]].concat(),
                &[0u8; 44][..],
            )
            .unwrap();
        raw.open_tree("binary_functions")
            .unwrap()
            .insert(
                [&[3; 16], 0u128.to_le_bytes().as_slice()].concat(),
                &[0u8; 44][..],
            )
            .unwrap();
        raw.flush().unwrap();
    }
    let db = fixture.database().await;
    let before = db.get_binary_facets([3; 16], 1).await.unwrap();
    assert_eq!(before.function_count, 1);
    assert_eq!(before.fallback_functions, 1);
    assert_eq!(before.demangled_functions, 1);
    assert!(before.truncated);
    // Change an inference dependency outside the coverage sample, in another
    // binary. The target key and query binary are untouched by this push.
    let data = [
        pack_dd(MdKey::Fcmt.raw()),
        pack_dd(15),
        b"neutral_helper\0".to_vec(),
    ]
    .concat();
    db.push_with_ctx(
        &[
            (1, 1, 16, "neutral_helper", &data),
            (2, 1, 16, "neutral_helper", &data),
        ],
        &dazhbog::db::PushContext {
            md5: Some([2; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        query(&db, &[0], Some([3; 16])).await[0].as_deref(),
        Some("decode_pixels")
    );
    let after = db.get_binary_facets([3; 16], 1).await.unwrap();
    assert_eq!(after.function_count, 1);
    assert_eq!(after.demangled_functions, 0);
}

#[tokio::test]
async fn explicit_and_completed_function_identities_have_the_same_donor_votes() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        let preferred = append(&rt, 1, "inspect_packet", 1, [1; 16], 1);
        append(&rt, 1, "decode_pixels", 1, [2; 16], 1);
        rt.ctx_index
            .set_canonical_version(1, preferred, 1.0, 1)
            .unwrap();
        // Without excluding the query MD5, these degrees change from 1,2,2
        // to 2,3,3. That turns equal donor mass into a spurious binary-2 lead.
        for (key, donors) in [(2, vec![1]), (3, vec![2, 3]), (4, vec![2, 4])] {
            let vid = append(&rt, key, "neutral_helper", 1, [donors[0]; 16], 1);
            for donor in donors.iter().skip(1) {
                observe(&rt, key, vid, [*donor; 16], 1);
            }
            observe(&rt, key, vid, [9; 16], 1);
        }
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let sparse = db
        .select_variant_details(&QueryContext {
            keys: &[1],
            requested_mdkeys: &[],
            md5: Some([9; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    let full = db
        .select_variant_details(&QueryContext {
            keys: &[1, 2, 3, 4],
            requested_mdkeys: &[],
            md5: Some([9; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    let sparse = sparse[0].as_ref().unwrap();
    let full = full[0].as_ref().unwrap();
    assert_eq!(sparse.name, "inspect_packet");
    assert_eq!(full.name, sparse.name);
    assert_eq!(full.candidate_version_ids, sparse.candidate_version_ids);
    assert_eq!(full.candidate_binary_match, sparse.candidate_binary_match);
    assert_eq!(
        full.candidate_binary_support,
        sparse.candidate_binary_support
    );
    let permuted = db
        .select_variant_details(&QueryContext {
            keys: &[4, 1, 3, 1, 2],
            requested_mdkeys: &[],
            md5: Some([9; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    for position in [1, 3] {
        let selected = permuted[position].as_ref().unwrap();
        assert_eq!(selected.name, sparse.name);
        assert_eq!(
            selected.candidate_binary_support,
            sparse.candidate_binary_support
        );
    }
}

async fn query(db: &Database, keys: &[u128], md5: Option<[u8; 16]>) -> Vec<Option<String>> {
    db.select_versions_for_batch(&QueryContext {
        keys,
        requested_mdkeys: &[],
        md5,
        basename: None,
        hostname: None,
        origin_token: None,
    })
    .await
    .unwrap()
    .into_iter()
    .map(|entry| entry.map(|e| e.2))
    .collect()
}

#[tokio::test]
async fn explicit_binary_recovers_older_variant_beyond_recent_cap() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    // Identity remains authoritative even when all heuristic MD5 weight is zero.
    fixture.cfg.scoring.w_md5 = 0.0;
    fixture.cfg.scoring.experimental_synthesis = true;
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_http_headers", 1, [1; 16], 1);
        append(&rt, 1, "decode_texture_pixels", 2, [2; 16], 20);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1], Some([1; 16])).await,
        vec![Some("parse_http_headers".into())]
    );
    let shaped = db
        .select_versions_for_batch(&QueryContext {
            keys: &[1],
            requested_mdkeys: &[MdKey::Ops.raw()],
            md5: Some([1; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    let chosen = shaped[0].as_ref().unwrap();
    assert_eq!(chosen.2, "parse_http_headers");
    assert!(chosen.3.is_empty());
    // The size field is the stored declared function size (the fixture stores
    // the metadata length there), never the length of the shaped blob.
    assert_eq!(chosen.1, 21);
}

#[tokio::test]
async fn canonical_refresh_preserves_incumbent_beyond_recent_window() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 2;
    let db = fixture.database().await;
    let text = b"decode archive directory\0";
    let mut rich = pack_dd(MdKey::Fcmt.raw());
    rich.extend(pack_dd(text.len() as u32));
    rich.extend(text);
    db.push(&[(1, 1, 0, "decode_archive_directory", &rich)])
        .await
        .unwrap();
    for name in [
        "scan_archive_left",
        "scan_archive_right",
        "scan_archive_front",
        "scan_archive_back",
        "scan_archive_side",
    ] {
        assert_eq!(db.push(&[(1, 1, 0, name, &[])]).await.unwrap(), [0]);
        assert_eq!(
            db.get_canonical(1).await.unwrap().unwrap().name,
            "decode_archive_directory"
        );
    }
    assert_eq!(
        db.get_latest(1).await.unwrap().unwrap().name,
        "scan_archive_side"
    );
    let hits = db
        .search_functions("decode_archive_directory", 10)
        .await
        .unwrap();
    assert_eq!(hits[0].func_name, "decode_archive_directory");
    db.flush().unwrap();
    drop(db);
    let db = fixture.database().await;
    assert_eq!(
        db.get_canonical(1).await.unwrap().unwrap().name,
        "decode_archive_directory"
    );
    let mut richer = rich.clone();
    richer.extend(pack_dd(MdKey::Frptcmt.raw()));
    richer.extend(pack_dd(text.len() as u32));
    richer.extend(text);
    db.push(&[(1, 1, 0, "decode_archive_directory_complete", &richer)])
        .await
        .unwrap();
    assert_eq!(
        db.get_canonical(1).await.unwrap().unwrap().name,
        "decode_archive_directory_complete"
    );
    db.delete_keys(&[1]).await.unwrap();
    db.push(&[(1, 1, 0, "decode_new_interval", &[])])
        .await
        .unwrap();
    assert_eq!(
        db.get_canonical(1).await.unwrap().unwrap().name,
        "decode_new_interval"
    );
}

#[tokio::test]
async fn serving_considers_canonical_outside_recent_candidates() {
    for legacy in [false, true] {
        let mut fixture = Fixture::new();
        fixture.cfg.scoring.max_versions_per_key = 1;
        {
            let rt = fixture.runtime();
            let canonical =
                append_with_identity(&rt, 1, "parse_canonical_headers", 1, [1; 16], 1, legacy);
            append(&rt, 1, "parse_recent_headers", 2, [2; 16], 1);
            rt.ctx_index
                .set_canonical_version(1, canonical, 1.0, 1)
                .unwrap();
            rt.flush().unwrap();
        }
        let db = fixture.database().await;
        assert_eq!(
            db.get_canonical(1).await.unwrap().unwrap().name,
            "parse_canonical_headers"
        );
        assert_eq!(
            query(&db, &[1, 999], None).await[0],
            Some("parse_canonical_headers".into())
        );
        assert_eq!(
            query(&db, &[1, 999], Some([2; 16])).await[0],
            Some("parse_recent_headers".into())
        );
    }
}

#[tokio::test]
async fn availability_diagnostics_distinguish_unproven_sharing_and_retrieval_misses() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    let malformed_version;
    {
        let rt = fixture.runtime();
        let old = append_with_identity(&rt, 1, "parse_shared_old", 1, [2; 16], 1, true);
        observe(&rt, 1, old, [1; 16], 1);
        append(&rt, 1, "parse_shared_recent", 2, [3; 16], 1);
        append(&rt, 2, "parse_private_annotation", 1, [1; 16], 1);
        observe(&rt, 3, version_id(3, "missing_record", &[]), [1; 16], 1);
        append(&rt, 5, "parse_unproven_annotation", 1, [1; 16], 1);
        for n in 10u128..268 {
            rt.ctx_index
                .record_key_observation(
                    5,
                    n.to_be_bytes(),
                    Some(version_id(5, "other_annotation", &n.to_le_bytes())),
                    1,
                    None,
                )
                .unwrap();
        }
        malformed_version = append(&rt, 6, "parse_old_unshared", 1, [1; 16], 1);
        rt.ctx_index
            .record_key_observation(
                6,
                [8; 16],
                Some(version_id(6, "unavailable_variant", &[])),
                1,
                None,
            )
            .unwrap();
        append(&rt, 6, "parse_new_shared", 2, [3; 16], 1);
        rt.flush().unwrap();
    }
    {
        let raw = sled::open(fixture.path.join("context_db")).unwrap();
        let key = [&[8u8; 16][..], &malformed_version[..]].concat();
        raw.open_tree("binary_versions")
            .unwrap()
            .insert(key, &[1u8])
            .unwrap();
        raw.flush().unwrap();
    }
    let db = fixture.database().await;
    let report = db
        .evaluate_binary_transfer([1; 16], &[1, 2, 3, 4, 5, 6])
        .await
        .unwrap();
    let reasons: Vec<_> = report
        .cases
        .iter()
        .map(|case| case.candidate_absence)
        .collect();
    assert_eq!(
        reasons,
        [
            Some("shared_but_not_retrieved"),
            Some("sharing_not_proven"),
            Some("identity_probe_unavailable"),
            Some("unlabeled"),
            Some("membership_scan_limit"),
            None
        ]
    );
    assert!(report.cases[..5]
        .iter()
        .all(|case| case.availability_error.is_none()));
    assert!(report.cases[5].availability_error.is_some());
    assert_eq!(
        report.cases[5].selected_name.as_deref(),
        Some("parse_new_shared")
    );
    assert_eq!(report.cases[0].candidate_count, 1);
    assert_eq!(
        report.cases[0].selected_name.as_deref(),
        Some("parse_shared_recent")
    );
    let observed = db.evaluate_observed_binary([1; 16], &[1]).await.unwrap();
    assert_eq!(
        observed.cases[0].candidate_absence,
        Some("reachable_but_not_retrieved")
    );
    drop(db);
    let config = fixture.path.join("availability.toml");
    std::fs::write(
        &config,
        format!(
            "engine.data_dir = \"{}\"\nscoring.max_versions_per_key = 1\n",
            fixture.path.display()
        ),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_eval-binary-context"))
        .arg(config)
        .args(["1", "5", "1", "transfer", "--all-cases"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let rows: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let summary = rows
        .iter()
        .find(|row| row["kind"] == "summary")
        .unwrap_or_else(|| {
            panic!(
                "CLI produced no summary: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(summary["failed_batches"], 0);
    assert_eq!(summary["counts"]["latest_errors"], 0);
    assert_eq!(summary["counts"]["canonical_errors"], 0);
    assert!(summary["counts"]["availability_errors"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn related_binary_coverage_is_computed_only_for_returned_rows() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        for (key, binaries) in [(1, vec![1, 2, 3, 4]), (2, vec![1, 2])] {
            for binary in binaries {
                append(&rt, key, "parse_orchid", 1, [binary; 16], 1);
            }
        }
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert!(db.get_binary_related([1; 16], 0).await.unwrap().is_empty());
    let (summaries, _) = db
        .search_binaries_paginated("fixture", 0, 10)
        .await
        .unwrap();
    assert_eq!(summaries.len(), 4);
    assert!(summaries.iter().all(|summary| summary.coverage.is_none()));

    let related = db.get_binary_related([1; 16], 1).await.unwrap();
    assert_eq!(related.len(), 1);
    assert_eq!(related[0].0.md5_hex, "02".repeat(16));
    assert_eq!((related[0].1, related[0].2), (2, 2));
    assert_eq!(related[0].3, 100.0);
    assert_eq!(related[0].4, 100.0);
    assert_eq!(related[0].0.coverage.as_ref().unwrap().function_count, 2);
    let (summaries, _) = db
        .search_binaries_paginated("fixture", 0, 10)
        .await
        .unwrap();
    assert!(summaries
        .iter()
        .find(|summary| summary.md5_hex == "03".repeat(16))
        .unwrap()
        .coverage
        .is_none());

    let all = db.get_binary_related([1; 16], 2).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].0.md5_hex, related[0].0.md5_hex);
    assert_eq!(all[1].0.md5_hex, "03".repeat(16));
    assert!(all.iter().all(|row| row.0.coverage.is_some()));
    assert_eq!((all[1].1, all[1].2), (1, 1));
}

#[tokio::test]
async fn historical_vocabulary_retrieves_only_the_contextually_matching_annotation() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "orchid", 1, [1; 16], 1);
        append(&rt, 2, "orchid", 1, [1; 16], 1);
        append(&rt, 2, "quartz", 2, [2; 16], 1);
        // This primary hit prevents the fallback parser from masking a miss.
        append(&rt, 3, "orchid_stub", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(db.get_canonical(2).await.unwrap().unwrap().name, "quartz");
    for (name, binary) in [("quartz", [2; 16]), ("orchid", [1; 16])] {
        let mut data = pack_dd(MdKey::Fcmt.raw());
        data.extend(pack_dd((name.len() + 1) as u32));
        data.extend(name.as_bytes());
        data.push(0);
        if name == "quartz" {
            data.extend(pack_dd(MdKey::Frptcmt.raw()));
            data.extend(pack_dd((name.len() + 1) as u32));
            data.extend(name.as_bytes());
            data.push(0);
        }
        db.push_with_ctx(
            &[(4, 1, data.len() as u32, name, &data)],
            &dazhbog::db::PushContext {
                md5: Some(binary),
                basename: None,
                hostname: None,
                origin_token: None,
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(db.get_canonical(4).await.unwrap().unwrap().name, "quartz");
    assert!(db
        .search_functions("orchid", 12)
        .await
        .unwrap()
        .iter()
        .all(|hit| hit.key_hex != format!("{:032x}", 2)));
    let (candidates, hits) = db
        .semantic_neighbors_in_context(1, 12, true, 96, Some([1; 16]))
        .await
        .unwrap();
    assert!(
        candidates.contains(&2),
        "historical annotation supplies retrieval vocabulary"
    );
    assert!(
        candidates.contains(&4),
        "live updates include noncanonical vocabulary"
    );
    assert_eq!(
        hits.iter()
            .find(|hit| hit.key_hex == format!("{:032x}", 4))
            .unwrap()
            .func_name,
        "orchid"
    );
    assert_eq!(
        hits.iter()
            .find(|hit| hit.key_hex == format!("{:032x}", 2))
            .unwrap()
            .func_name,
        "orchid"
    );
    let (candidates, hits) = db
        .semantic_neighbors_in_context(1, 12, true, 96, None)
        .await
        .unwrap();
    assert!(candidates.contains(&2));
    assert!(
        hits.iter().all(|hit| hit.key_hex != format!("{:032x}", 2)),
        "unrelated canonical annotation cannot borrow historical semantics"
    );
    assert_eq!(db.delete_keys(&[2]).await.unwrap(), 1);
    assert!(!db
        .semantic_neighbors_in_context(1, 12, false, 96, Some([1; 16]))
        .await
        .unwrap()
        .0
        .contains(&2));
    let data = Vec::new();
    db.push_with_ctx(
        &[(2, 1, 0, "topaz", &data)],
        &dazhbog::db::PushContext {
            md5: Some([1; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        },
    )
    .await
    .unwrap();
    assert!(
        !db.semantic_neighbors_in_context(1, 12, false, 96, Some([1; 16]))
            .await
            .unwrap()
            .0
            .contains(&2),
        "reinsertion does not index pre-delete vocabulary"
    );
    drop(db);
    let rebuilt = fixture.database().await;
    let (_, hits) = rebuilt
        .semantic_neighbors_in_context(1, 12, true, 96, Some([1; 16]))
        .await
        .unwrap();
    assert_eq!(
        hits.iter()
            .find(|hit| hit.key_hex == format!("{:032x}", 4))
            .unwrap()
            .func_name,
        "orchid"
    );
}

#[tokio::test]
async fn zero_count_observations_cannot_supply_binary_identity_or_inference() {
    for zero_last in [true, false] {
        let fixture = Fixture::new();
        let old;
        {
            let rt = fixture.runtime();
            old = append(&rt, 1, "parse_old_annotation", 1, [1; 16], 1);
            append(&rt, 1, "parse_fallback_annotation", 2, [2; 16], 1);
            rt.flush().unwrap();
        }
        {
            let raw = sled::open(fixture.path.join("context_db")).unwrap();
            let mut key = 1u128.to_le_bytes().to_vec();
            key.extend([3; 16]);
            let mut value = u32::from(!zero_last).to_le_bytes().to_vec();
            value.extend(1u64.to_le_bytes());
            value.extend(if zero_last { old } else { [0x99; 32] });
            raw.open_tree("key_md5")
                .unwrap()
                .insert(key, value)
                .unwrap();
            // A zero-count version-summary row is not an observed historical
            // variant. No binary_versions record exists for binary 3.
            let mut stats = 1u32.to_le_bytes().to_vec();
            stats.extend(1u64.to_le_bytes());
            stats.extend(1u64.to_le_bytes());
            stats.extend(1u32.to_le_bytes());
            stats.push(2);
            stats.extend([1; 16]);
            stats.extend(1u32.to_le_bytes());
            stats.extend([3; 16]);
            stats.extend(0u32.to_le_bytes());
            raw.open_tree("version_stats")
                .unwrap()
                .insert(old, stats)
                .unwrap();
            raw.flush().unwrap();
        }
        let db = fixture.database().await;
        assert_eq!(
            query(&db, &[1], None).await[0].as_deref(),
            Some("parse_fallback_annotation"),
            "fallback fixture, zero_last={zero_last}"
        );
        assert_eq!(
            query(&db, &[1], Some([3; 16])).await[0].as_deref(),
            Some("parse_fallback_annotation"),
            "identity fixture, zero_last={zero_last}"
        );
        if zero_last {
            let evaluation = db.evaluate_observed_binary([3; 16], &[1]).await.unwrap();
            assert!(evaluation.cases[0].expected_version.is_none());
        }
    }

    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_http_headers", 1, [1; 16], 1);
        append(&rt, 1, "decode_texture_pixels", 2, [2; 16], 1);
        append(&rt, 2, "open_input_stream", 1, [1; 16], 1);
        append(&rt, 3, "close_input_stream", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    {
        let raw = sled::open(fixture.path.join("context_db")).unwrap();
        for key in [2u128, 3] {
            let mut bytes = key.to_le_bytes().to_vec();
            bytes.extend([2; 16]);
            raw.open_tree("key_md5")
                .unwrap()
                .insert(bytes, &[0u8; 44][..])
                .unwrap();
            // Reproduce reverse rows created by older preparation code.
            let mut reverse = vec![2; 16];
            reverse.extend(key.to_le_bytes());
            raw.open_tree("binary_functions")
                .unwrap()
                .insert(reverse, &[0u8; 44][..])
                .unwrap();
        }
        for (seed, other) in [(1u8, 2u8), (2, 1)] {
            let mut legacy_cache = vec![1];
            legacy_cache.extend([other; 16]);
            legacy_cache.extend(3u64.to_le_bytes());
            raw.open_tree("binary_overlap")
                .unwrap()
                .insert([seed; 16], legacy_cache)
                .unwrap();
        }
        raw.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1, 2, 3], None).await[0].as_deref(),
        Some("parse_http_headers")
    );
    for seed in [1u8, 2] {
        let overlap = db.get_binary_overlap([seed; 16], 10).await.unwrap();
        assert_eq!(overlap.len(), 1);
        assert_eq!(overlap[0].1, 1);
        let cached = db.get_binary_overlap([seed; 16], 10).await.unwrap();
        assert_eq!(cached[0].1, 1);
        let related = db.get_binary_related([seed; 16], 10).await.unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].1, 1);
    }
}

#[tokio::test]
async fn independent_batch_keys_override_repeated_uploads_and_preserve_order() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_http_headers", 1, [1; 16], 1);
        append(&rt, 1, "decode_texture_pixels", 2, [2; 16], 100);
        append(&rt, 2, "accept_network_request", 1, [1; 16], 1);
        append(&rt, 3, "close_network_socket", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let selected = query(&db, &[1, 2, 3, 1, 999], None).await;
    assert_eq!(selected[0].as_deref(), Some("parse_http_headers"));
    assert_eq!(selected[0], selected[3]);
    assert!(selected[4].is_none());
    let reversed = query(&db, &[3, 2, 1], None).await;
    assert_eq!(reversed[2], selected[0]);
}

#[tokio::test]
async fn inferred_binary_prefers_last_annotation_over_its_older_submissions() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        let expected = append(&rt, 1, "parse_corrected_headers", 1, [1; 16], 1);
        // Both variants have historical membership in this binary. The global
        // newest record and canonical pointer refer to its superseded annotation.
        append(&rt, 1, "parse_superseded_headers", 2, [1; 16], 50);
        observe(&rt, 1, expected, [1; 16], 1);
        append(&rt, 2, "open_input_stream", 1, [1; 16], 1);
        append(&rt, 3, "close_input_stream", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let evaluation = db
        .evaluate_observed_binary([1; 16], &[1, 2, 3])
        .await
        .unwrap();
    assert!(evaluation.cases[0].selected_matches_observation);
    assert!(!evaluation.cases[0].latest_matches_observation);
    assert!(!evaluation.cases[0].canonical_matches_observation);
    assert_eq!(
        query(&db, &[3, 1, 2, 1], None).await[1],
        Some("parse_corrected_headers".into())
    );
}

#[tokio::test]
async fn historical_fallback_conserves_evidence_and_does_not_restore_missing_mass() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        for (n, suffix) in ["http", "png", "jpeg", "xml", "json"].iter().enumerate() {
            append(
                &rt,
                1,
                &format!("parse_format_{suffix}"),
                n as u64,
                [1; 16],
                1,
            );
        }
        // The recorded last variant cannot be found. Five known historical
        // candidates must share this binary's evidence, not each inherit it all.
        observe(&rt, 1, [0x77; 32], [1; 16], 1);
        for key in [2, 3] {
            let vid = append(&rt, key, "open_input_stream", 1, [1; 16], 1);
            observe(&rt, key, vid, [2; 16], 1);
        }
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let results = db
        .select_variant_details(&QueryContext {
            keys: &[1, 2, 3],
            requested_mdkeys: &[],
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
        })
        .await
        .unwrap();
    let chosen = results[0].as_ref().unwrap();
    assert_eq!(chosen.candidate_version_ids.len(), 5);
    // Other keys divide their evidence evenly between binaries 1 and 2.
    // Binary 2 has no candidate for key 1, so its half remains unavailable.
    assert!((chosen.candidate_binary_support.iter().sum::<f64>() - 0.5).abs() < 1e-12);
    assert!(chosen
        .candidate_binary_support
        .iter()
        .all(|s| (*s - 0.1).abs() < 1e-12));
}

#[tokio::test]
async fn binary_priority_precedes_richness_and_can_be_disabled_for_ablation() {
    for priority in [true, false] {
        let mut fixture = Fixture::new();
        fixture.cfg.scoring.binary_priority = priority;
        fixture.cfg.scoring.w_coh = 0.0;
        fixture.cfg.scoring.experimental_synthesis = true;
        {
            let rt = fixture.runtime();
            let rec = Record {
                key: 1,
                ts_sec: 1,
                prev_addr: 0,
                len_bytes: 0,
                popularity: 1,
                name: "parse_http_headers".into(),
                data: Vec::new(),
                flags: 0,
            };
            assert!(rt
                .index
                .upsert(1, rt.segments.append(&rec).unwrap())
                .is_ok());
            observe(&rt, 1, version_id(1, &rec.name, &rec.data), [1; 16], 1);
            append(&rt, 1, "decode_texture_pixels", 2, [2; 16], 100);
            append(&rt, 2, "open_input_stream", 1, [1; 16], 1);
            append(&rt, 3, "close_input_stream", 1, [1; 16], 1);
            rt.flush().unwrap();
        }
        let db = fixture.database().await;
        for md5 in [None, Some([99; 16])] {
            let results = db
                .select_variant_details(&QueryContext {
                    keys: &[1, 2, 3],
                    requested_mdkeys: &[],
                    md5,
                    basename: None,
                    hostname: None,
                    origin_token: None,
                })
                .await
                .unwrap();
            let chosen = results[0].as_ref().unwrap();
            if priority {
                assert_eq!(chosen.name, "parse_http_headers");
                assert!(chosen.data.is_empty());
                assert!(!chosen.used_synthesis);
                assert_eq!(chosen.binary_support, 1.0);
            } else {
                assert_eq!(chosen.name, "decode_texture_pixels");
            }
        }
    }
}

#[tokio::test]
async fn many_partial_binary_matches_cannot_outvote_one_complete_match() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_matching_headers", 1, [1; 16], 1);
        let decoy = append(&rt, 1, "decode_unrelated_pixels", 2, [2; 16], 100);
        for n in 3..=10 {
            observe(&rt, 1, decoy, [n; 16], 1);
        }
        let a = append(&rt, 2, "open_input_stream", 1, [1; 16], 1);
        for n in 2..=5 {
            observe(&rt, 2, a, [n; 16], 1);
        }
        let b = append(&rt, 3, "close_input_stream", 1, [1; 16], 1);
        for n in 6..=10 {
            observe(&rt, 3, b, [n; 16], 1);
        }
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1, 2, 3], None).await[0],
        Some("parse_matching_headers".into())
    );
    assert_eq!(
        query(&db, &[3, 1, 2, 1], None).await[1],
        Some("parse_matching_headers".into())
    );
}

#[tokio::test]
async fn transfer_withholds_identity_and_private_variants_before_history_cap() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    {
        let rt = fixture.runtime();
        // The other-binary variant must remain retrievable despite newer private
        // annotations from the withheld binary consuming the recent history.
        append(&rt, 1, "parse_shared_headers", 1, [2; 16], 1);
        append(&rt, 1, "parse_private_headers", 2, [1; 16], 20);
        append(&rt, 2, "open_private_stream", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let observed = db.evaluate_observed_binary([1; 16], &[1, 2]).await.unwrap();
    assert!(observed
        .cases
        .iter()
        .all(|c| c.selected_matches_observation));
    let transfer = db.evaluate_binary_transfer([1; 16], &[1, 2]).await.unwrap();
    assert!(transfer.withheld_binary);
    assert_eq!(
        transfer.cases[0].selected_name.as_deref(),
        Some("parse_shared_headers")
    );
    assert_eq!(transfer.cases[0].candidate_count, 1);
    assert!(!transfer.cases[0].expected_in_candidates);
    assert!(transfer.cases[0].expected_reachable_with_identity);
    assert_eq!(transfer.cases[0].available_binary_support, 0.0);
    assert_eq!(transfer.cases[1].candidate_count, 0);
    assert!(transfer.cases[1].selected_name.is_none());
    // Evaluation does not replace the stored last variant or its observations.
    assert_eq!(
        db.get_latest(1).await.unwrap().unwrap().name,
        "parse_private_headers"
    );
    assert!(db
        .evaluate_observed_binary([1; 16], &[1, 2])
        .await
        .unwrap()
        .cases
        .iter()
        .all(|c| c.selected_matches_observation));
}

#[tokio::test]
async fn distinguishing_batch_terms_overcome_unrelated_metadata_and_canonical_hint() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "OrchidSession::parseHeaders", 1, [1; 16], 1);
        append(&rt, 1, "CobaltSession::parseHeaders", 2, [2; 16], 1);
        // Both observed binaries contain every key, so binary overlap ties.
        // Only the neighboring function's metadata identifies the subsystem.
        let anchor = append(&rt, 2, "OrchidSession::openStream", 1, [1; 16], 1);
        observe(&rt, 2, anchor, [2; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let selected = query(&db, &[1, 2], None).await;
    assert_eq!(selected[0].as_deref(), Some("OrchidSession::parseHeaders"));
    // One key cannot manufacture corroboration from its own selected variant.
    let alone = query(&db, &[1], None).await;
    assert_eq!(alone[0].as_deref(), Some("CobaltSession::parseHeaders"));
}

#[tokio::test]
async fn ambiguous_sources_supply_only_shared_batch_evidence() {
    let mut fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "OrchidSession::parseHeaders", 1, [1; 16], 1);
        append(&rt, 1, "CobaltSession::parseHeaders", 2, [2; 16], 1);
        // Neither source variant has the 1.0 score margin needed to become an
        // anchor. Their common subsystem remains valid evidence for the target.
        append(&rt, 2, "OrchidSession::openLeft", 1, [1; 16], 1);
        append(&rt, 2, "OrchidSession::openRight", 2, [2; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1], None).await[0].as_deref(),
        Some("CobaltSession::parseHeaders")
    );
    assert_eq!(
        query(&db, &[1, 2], None).await[0].as_deref(),
        Some("OrchidSession::parseHeaders")
    );
    assert_eq!(
        query(&db, &[2, 1, 1], None).await[1..],
        [
            Some("OrchidSession::parseHeaders".into()),
            Some("OrchidSession::parseHeaders".into())
        ]
    );
    assert_eq!(
        query(&db, &[1, 2], Some([2; 16])).await[0].as_deref(),
        Some("CobaltSession::parseHeaders")
    );
    drop(db);
    fixture.cfg.scoring.batch_consensus_anchors = false;
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1, 2], None).await[0].as_deref(),
        Some("CobaltSession::parseHeaders")
    );
}

#[tokio::test]
async fn identifier_components_resolve_cross_style_batch_context() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.binary_priority = false;
    {
        let rt = fixture.runtime();
        append(&rt, 1, "read_http_header", 1, [1; 16], 1);
        append(&rt, 1, "read_tls_record", 2, [2; 16], 1);
        append(&rt, 2, "HttpDecodeHeader", 2, [3; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1], None).await[0],
        Some("read_tls_record".into())
    );
    assert_eq!(
        query(&db, &[1, 2], None).await[0],
        Some("read_http_header".into())
    );
    assert_eq!(
        query(&db, &[2, 1, 1], None).await[1..],
        [
            Some("read_http_header".into()),
            Some("read_http_header".into())
        ]
    );
    assert_eq!(
        query(&db, &[1, 2], Some([2; 16])).await[0],
        Some("read_tls_record".into())
    );
    drop(db);
    fixture.cfg.scoring.batch_identifier_components = false;
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1, 2], None).await[0],
        Some("read_tls_record".into())
    );
}

#[tokio::test]
async fn partial_binary_lead_depending_on_one_key_allows_corroborated_variant() {
    for tolerance in [true, false] {
        for evidence in 0..3 {
            let mut fixture = Fixture::new();
            fixture.cfg.scoring.binary_single_key_tolerance = tolerance;
            {
                let rt = fixture.runtime();
                let expected = append(&rt, 1, "OrchidSession::parseHeaders", 1, [2; 16], 1);
                append(&rt, 1, "CobaltSession::parseHeaders", 2, [1; 16], 1);
                rt.ctx_index
                    .set_canonical_version(1, expected, 1.0, 1)
                    .unwrap();
                append(&rt, 2, "open_auxiliary_stream", 1, [1; 16], 1);
                let shared = append(
                    &rt,
                    3,
                    if evidence == 1 {
                        "OrchidSession::openStream"
                    } else if evidence == 2 {
                        "orchid_session_open_stream"
                    } else {
                        "open_neutral_stream"
                    },
                    1,
                    [1; 16],
                    1,
                );
                observe(&rt, 3, shared, [2; 16], 1);
                let other = append(
                    &rt,
                    4,
                    if evidence == 1 {
                        "OrchidSession::closeStream"
                    } else if evidence == 2 {
                        "orchid_session_close_stream"
                    } else {
                        "close_neutral_stream"
                    },
                    1,
                    [2; 16],
                    1,
                );
                observe(&rt, 4, other, [3; 16], 1);
                rt.flush().unwrap();
            }
            let db = fixture.database().await;
            // Neither binary explains the full query: binary 1's larger rarity-weighted
            // score depends on key 2. Keys 3 and 4 corroborate the other subsystem.
            let selected = query(&db, &[1, 2, 3, 4], None).await;
            assert_eq!(
                selected[0].as_deref(),
                Some(if tolerance && evidence == 1 {
                    "OrchidSession::parseHeaders"
                } else {
                    "CobaltSession::parseHeaders"
                })
            );
            assert_eq!(query(&db, &[4, 1, 3, 2, 1], None).await[1], selected[0]);
            // An explicit observed identity still takes precedence over inferred doubt.
            assert_eq!(
                query(&db, &[1, 2, 3, 4], Some([1; 16])).await[0].as_deref(),
                Some("CobaltSession::parseHeaders")
            );
        }
    }
}

#[tokio::test]
async fn transfer_uses_other_binary_provenance() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.w_stab = 100.0;
    fixture.cfg.scoring.w_rec = 100.0;
    fixture.cfg.scoring.w_pop_bin = 100.0;
    let expected;
    {
        let rt = fixture.runtime();
        expected = append(&rt, 1, "parse_shared_headers", 1, [2; 16], 1);
        observe(&rt, 1, expected, [1; 16], 1);
        append(&rt, 1, "decode_unrelated_pixels", 2, [3; 16], 100);
        for key in [2, 3] {
            let vid = append(&rt, key, "open_shared_stream", 1, [2; 16], 1);
            observe(&rt, key, vid, [1; 16], 1);
        }
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let transfer = db
        .evaluate_binary_transfer([1; 16], &[1, 2, 3])
        .await
        .unwrap();
    assert!(transfer
        .cases
        .iter()
        .all(|c| c.selected_matches_observation));
    assert_eq!(transfer.cases[0].expected_binary_match, Some(1.0));
    assert_eq!(transfer.cases[0].candidate_count, 2);
    assert_eq!(
        transfer.cases[0].expected_version.as_deref(),
        Some(
            expected
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .as_str()
        )
    );
}

#[tokio::test]
async fn transfer_choice_is_invariant_to_heldout_counts_timestamps_and_canonical_hint() {
    let mut selections = Vec::new();
    for favor_first in [true, false] {
        let mut fixture = Fixture::new();
        fixture.cfg.scoring.binary_priority = false;
        fixture.cfg.scoring.w_stab = 100.0;
        fixture.cfg.scoring.w_rec = 100.0;
        fixture.cfg.scoring.w_pop_bin = 100.0;
        {
            let rt = fixture.runtime();
            let a = append(
                &rt,
                1,
                "parse_first_headers",
                if favor_first { 1000 } else { 1 },
                [2; 16],
                1,
            );
            let b = append(
                &rt,
                1,
                "parse_second_headers",
                if favor_first { 1 } else { 1000 },
                [2; 16],
                1,
            );
            observe(&rt, 1, a, [1; 16], if favor_first { 100 } else { 1 });
            observe(&rt, 1, b, [1; 16], if favor_first { 1 } else { 100 });
            rt.ctx_index
                .set_canonical_version(1, if favor_first { a } else { b }, 1.0, 1000)
                .unwrap();
            rt.flush().unwrap();
        }
        let db = fixture.database().await;
        // One key supplies no independent binary vote: this exercises secondary
        // scoring, rather than allowing primary binary priority to mask leakage.
        let transfer = db.evaluate_binary_transfer([1; 16], &[1]).await.unwrap();
        assert_eq!(transfer.cases[0].candidate_count, 2);
        assert_eq!(transfer.cases[0].available_binary_support, 0.0);
        selections.push(transfer.cases[0].selected_version.clone());
    }
    assert!(selections[0].is_some());
    assert_eq!(selections[0], selections[1]);
}

#[tokio::test]
async fn withholding_valid_head_does_not_turn_foreign_ancestry_into_a_head_error() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 9, "unrelated_record", 1, [9; 16], 1);
        let rec = Record {
            key: 1,
            ts_sec: 2,
            prev_addr: rt.index.try_get(9).unwrap(),
            name: "private_record".into(),
            data: Vec::new(),
            len_bytes: 0,
            popularity: 1,
            flags: 0,
        };
        assert!(rt
            .index
            .upsert(1, rt.segments.append(&rec).unwrap())
            .is_ok());
        observe(&rt, 1, version_id(1, &rec.name, &rec.data), [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let transfer = db.evaluate_binary_transfer([1; 16], &[1]).await.unwrap();
    assert!(transfer.cases[0].selected_name.is_none());
    assert!(transfer.cases[0].expected_reachable_with_identity);
}

#[tokio::test]
async fn family_support_uses_membership_beyond_top_sixteen() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 1, "decode_texture_pixels", 0, [99; 16], 100);
        let vid = append(&rt, 1, "parse_http_headers", 1, [1; 16], 2);
        for binary in 2..=32u8 {
            observe(&rt, 1, vid, [binary; 16], 2);
        }
        let stats = rt.ctx_index.get_version_stats(&vid).unwrap().unwrap();
        assert!(!stats.top_md5s.iter().any(|e| e.md5 == [32; 16]));
        append(&rt, 1, "decode_texture_pixels", 2, [99; 16], 1);
        append(&rt, 2, "accept_network_request", 1, [32; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1, 2], None).await[0].as_deref(),
        Some("parse_http_headers")
    );
}

#[tokio::test]
async fn binary_identity_never_resurrects_a_pre_delete_variant() -> io::Result<()> {
    for legacy in [false, true] {
        let mut fixture = Fixture::new();
        fixture.cfg.scoring.max_versions_per_key = 1;
        {
            let rt = fixture.runtime();
            append_with_identity(&rt, 1, "parse_http_headers", 1, [1; 16], 1, legacy);
            let rec = Record {
                key: 1,
                ts_sec: 2,
                prev_addr: rt.index.try_get(1)?,
                len_bytes: 0,
                popularity: 0,
                name: String::new(),
                data: Vec::new(),
                flags: 1,
            };
            assert!(rt.index.upsert(1, rt.segments.append(&rec)?).is_ok());
            append(&rt, 1, "decode_texture_pixels", 3, [2; 16], 1);
            rt.flush()?;
        }
        let db = fixture.database().await;
        assert_eq!(
            query(&db, &[1], Some([1; 16])).await[0].as_deref(),
            Some("decode_texture_pixels")
        );
    }
    Ok(())
}

#[tokio::test]
async fn explicit_binary_identity_beats_richer_unrelated_metadata() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.w_md5 = 0.0;
    fixture.cfg.scoring.experimental_synthesis = true;
    {
        let rt = fixture.runtime();
        let rec = Record {
            key: 1,
            ts_sec: 1,
            prev_addr: 0,
            len_bytes: 0,
            popularity: 1,
            name: "parse_http_headers".into(),
            data: Vec::new(),
            flags: 0,
        };
        assert!(rt
            .index
            .upsert(1, rt.segments.append(&rec).unwrap())
            .is_ok());
        observe(&rt, 1, version_id(1, &rec.name, &rec.data), [1; 16], 1);
        append(&rt, 1, "decode_texture_pixels", 2, [2; 16], 100);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        query(&db, &[1], Some([1; 16])).await[0].as_deref(),
        Some("parse_http_headers")
    );
}

#[tokio::test]
async fn zero_version_cap_disables_targeted_collection() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 0;
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_http_headers", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(query(&db, &[1], Some([1; 16])).await, vec![None]);
}

#[tokio::test]
async fn observation_evaluation_uses_serving_selection_and_reports_missing_labels() {
    let fixture = Fixture::new();
    let expected;
    {
        let rt = fixture.runtime();
        expected = append(&rt, 1, "parse_http_headers", 1, [1; 16], 1);
        append(&rt, 1, "decode_texture_pixels", 2, [2; 16], 100);
        append(&rt, 2, "accept_network_request", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let samples = db.sample_observed_binary_batches(10, 2, 7).unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].0, [1; 16]);
    assert_eq!(
        samples,
        db.sample_observed_binary_batches(10, 2, 7).unwrap()
    );
    let keys = [1, 2, 1, 999];
    let ctx = QueryContext {
        keys: &keys,
        requested_mdkeys: &[],
        md5: None,
        basename: None,
        hostname: None,
        origin_token: None,
    };
    let diagnostic = db.select_variant_details(&ctx).await.unwrap();
    let wire = db.select_versions_for_batch(&ctx).await.unwrap();
    for (detail, response) in diagnostic.iter().zip(&wire) {
        assert_eq!(
            detail.as_ref().map(|d| (&d.name, &d.data)),
            response.as_ref().map(|r| (&r.2, &r.3))
        );
    }
    let chosen = diagnostic[0].as_ref().unwrap();
    assert_eq!(chosen.base_version_id, expected);
    assert_eq!(chosen.candidate_version_ids.len(), 2);
    assert_eq!(
        chosen.candidate_version_ids,
        diagnostic[2].as_ref().unwrap().candidate_version_ids
    );
    let report = db.evaluate_observed_binary([1; 16], &keys).await.unwrap();
    assert!(report.cases[0].selected_matches_observation);
    assert!(report.cases[0].expected_in_candidates);
    assert!(report.cases[0].expected_reachable_with_identity);
    assert!(!report.cases[0].latest_matches_observation);
    assert!(report.cases[3].expected_version.is_none());
    assert!(!report.cases[3].selected_matches_observation);
}

#[tokio::test]
async fn diagnostic_history_failure_preserves_selection_results() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        append(&rt, 9, "foreign_function", 1, [1; 16], 1);
        let rec = Record {
            key: 1,
            ts_sec: 2,
            prev_addr: rt.index.try_get(9).unwrap(),
            len_bytes: 0,
            popularity: 1,
            name: "sub_1234".into(),
            data: Vec::new(),
            flags: 0,
        };
        assert!(rt
            .index
            .upsert(1, rt.segments.append(&rec).unwrap())
            .is_ok());
        observe(&rt, 1, version_id(1, &rec.name, &rec.data), [1; 16], 1);
        append(&rt, 2, "parse_http_headers", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    drop(
        EngineRuntime::prepare_salvage(fixture.cfg.engine.clone(), fixture.cfg.scoring.clone())
            .unwrap(),
    );
    let db = Database::open_for_replay(Arc::new(fixture.cfg.clone()))
        .await
        .unwrap();
    assert_eq!(
        query(&db, &[1, 2], None).await,
        vec![None, Some("parse_http_headers".into())]
    );
    let report = db
        .evaluate_observed_binary([1; 16], &[1, 2, 999])
        .await
        .unwrap();
    let broken = &report.cases[0];
    assert_eq!(broken.candidate_count, 0);
    assert!(broken
        .latest_error
        .as_ref()
        .unwrap()
        .contains("history key mismatch"));
    assert!(broken
        .canonical_error
        .as_ref()
        .unwrap()
        .contains("history key mismatch"));
    assert!(report.cases[1].selected_matches_observation);
    assert!(report.cases[1].latest_matches_observation);
    assert!(report.cases[1].latest_error.is_none());
    assert!(report.cases[2].latest_error.is_none());
    assert!(report.cases[2].expected_version.is_none());
    drop(db);
    let config = fixture.path.join("evaluation.toml");
    std::fs::write(
        &config,
        format!("engine.data_dir = \"{}\"\n", fixture.path.display()),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_eval-binary-context"))
        .arg(config)
        .args(["1", "3", "1", "observed", "--all-cases"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let rows: Vec<serde_json::Value> = stdout
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let summary = rows.iter().find(|r| r["kind"] == "summary").unwrap();
    assert_eq!(summary["failed_batches"], 0);
    assert_eq!(summary["counts"]["cases"], 3);
    assert_eq!(summary["counts"]["selected_correct"], 2);
    assert_eq!(summary["counts"]["latest_errors"], 1);
    assert_eq!(summary["counts"]["canonical_errors"], 1);
    assert_eq!(summary["counts"]["latest_judged"], 2);
    assert_eq!(summary["counts"]["canonical_judged"], 2);
    let binary = rows.iter().find(|r| r["kind"] == "binary").unwrap();
    assert_eq!(binary["cases"].as_array().unwrap().len(), 3);
    assert!(
        rows.iter().find(|r| r["kind"] == "sample").unwrap()["all_cases"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn targeted_storage_audit_distinguishes_policy_from_broken_history() {
    use dazhbog::common::hash::legacy_version_id;
    let fixture = Fixture::new();
    let expected;
    let legacy;
    {
        let rt = fixture.runtime();
        append(&rt, 9, "foreign_function", 1, [1; 16], 1);
        let rec = Record {
            key: 1,
            ts_sec: 2,
            prev_addr: rt.index.try_get(9).unwrap(),
            len_bytes: 0,
            popularity: 1,
            name: "sub_1234".into(),
            data: Vec::new(),
            flags: 0,
        };
        expected = version_id(1, &rec.name, &rec.data);
        legacy = legacy_version_id(1, &rec.name, &rec.data);
        assert!(rt
            .index
            .upsert(1, rt.segments.append(&rec).unwrap())
            .is_ok());
        let deleted = Record {
            key: 2,
            name: String::new(),
            flags: 1,
            ..rec
        };
        assert!(rt
            .index
            .upsert(2, rt.segments.append(&deleted).unwrap())
            .is_ok());
        append(&rt, 3, "parse_http_headers", 1, [1; 16], 1);
        rt.flush().unwrap();
    }
    let config = fixture.path.join("audit.toml");
    std::fs::write(
        &config,
        format!("engine.data_dir = \"{}\"\n", fixture.path.display()),
    )
    .unwrap();
    let run = |key: &str, id: Option<[u8; 32]>| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_storage-audit"));
        command.arg(&config).args(["--key", key]);
        if let Some(id) = id {
            command.arg(id.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    for id in [expected, legacy] {
        let report = run("0x1", Some(id));
        assert_eq!(report["expected_found"], true);
        assert_eq!(report["expected_live"], false);
        assert_eq!(report["live_candidates"], 0);
        assert_eq!(report["stop_reason"], "foreign_key");
        assert_eq!(report["records"].as_array().unwrap().len(), 2);
        assert_eq!(report["records"][1]["live_candidate"], false);
    }
    let deleted = run("2", None);
    assert_eq!(deleted["stop_reason"], "tombstone");
    assert_eq!(deleted["records"].as_array().unwrap().len(), 1);
    assert_eq!(run("3", None)["live_candidates"], 1);
    assert_eq!(run("999", None)["stop_reason"], "missing_index_entry");
    for id in [
        "f".repeat(63),
        "g".repeat(64),
        "é".repeat(32),
        "+f".repeat(32),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_storage-audit"))
            .args(["nonexistent-config", "--key", "1", &id])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("No such file"));
    }
}

async fn http_json(db: Arc<Database>, path: &str) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, server) = tokio::io::duplex(65536);
    let serving = tokio::spawn(dazhbog::api::http::handle_http_connection(server, db));
    client
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    serving.await.unwrap().unwrap();
    let response = String::from_utf8(bytes).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn binary_browser_paths_preserve_variant_identity_and_donor_timestamp() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_http_headers", 10, [1; 16], 1);
        append(&rt, 1, "parse_http_decoy_headers", 20, [2; 16], 10);
        append(&rt, 2, "parse_http_request_headers", 11, [1; 16], 1);
        append(&rt, 2, "parse_http_unrelated_headers", 21, [2; 16], 10);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let md5 = "01".repeat(16);
    let key = format!("{:032x}", 1);
    let base = format!("/api/function/{key}");
    let (status, global) = http_json(db.clone(), &base).await;
    assert_eq!(status, 200);
    assert_eq!(global["name"], "parse_http_decoy_headers");
    assert!(global["binary_md5"].is_null());
    let (status, contextual) = http_json(db.clone(), &format!("{base}?md5={md5}")).await;
    assert_eq!(status, 200);
    assert_eq!(contextual["name"], "parse_http_headers");
    assert_eq!(contextual["metadata"]["fcmt"], "parse_http_headers");
    assert_eq!(contextual["ts"], 10);
    assert_eq!(contextual["binary_md5"], md5);
    let (status, page) = http_json(db.clone(), &format!("/api/binary/{md5}/functions")).await;
    assert_eq!(status, 200);
    let hit = page["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["key_hex"] == key)
        .unwrap();
    assert_eq!(hit["func_name"], contextual["name"]);
    assert_eq!(hit["ts"], contextual["ts"]);
    assert_eq!(
        http_json(
            db.clone(),
            &format!(
                "/api/binary/{md5}/functions?page={}&per_page=100",
                usize::MAX
            )
        )
        .await
        .0,
        400
    );
    let (status, neighbors) = http_json(db.clone(), &format!("{base}/neighbors?md5={md5}")).await;
    assert_eq!(status, 200);
    assert_eq!(neighbors["binary_md5"], md5);
    let neighbor = neighbors["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["key_hex"] == format!("{:032x}", 2))
        .unwrap();
    assert_eq!(neighbor["func_name"], "parse_http_request_headers");
    assert_eq!(neighbor["ts"], 11);
    for suffix in [
        "md5=",
        "md5=%FF",
        "md5=abc",
        "md5=+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f",
        "md5=01010101010101010101010101010101&md5=02020202020202020202020202020202",
    ] {
        for endpoint in [&base, &format!("{base}/neighbors")] {
            assert_eq!(
                http_json(db.clone(), &format!("{endpoint}?{suffix}"))
                    .await
                    .0,
                400
            );
        }
    }
    assert_eq!(
        http_json(db, &format!("/api/function/{:032x}?md5={md5}", 999))
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn contextual_records_preserve_declared_function_size() {
    let fixture = Fixture::new();
    let db = fixture.database().await;
    let mut ctx = dazhbog::db::PushContext {
        md5: Some([1; 16]),
        basename: None,
        hostname: None,
        origin_token: None,
    };
    db.push_with_ctx(&[(1, 1, 1024, "first_annotation", &[])], &ctx)
        .await
        .unwrap();
    ctx.md5 = Some([2; 16]);
    db.push_with_ctx(&[(1, 1, 2048, "second_annotation", &[])], &ctx)
        .await
        .unwrap();
    assert_eq!(db.get_latest(1).await.unwrap().unwrap().len_bytes, 2048);
    for (md5, expected) in [([1; 16], 1024), ([2; 16], 2048)] {
        let selected = db
            .get_function_in_context(1, Some(md5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.len_bytes, expected);
        assert!(selected.data.is_empty());
    }
    let mut data = pack_dd(MdKey::Fcmt.raw());
    data.extend(pack_dd(5));
    data.extend(b"note\0");
    db.push_with_ctx(&[(2, 1, 0, "zero_sized_annotation", &data)], &ctx)
        .await
        .unwrap();
    let selected = db
        .get_function_in_context(2, ctx.md5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.len_bytes, 0);
    assert_eq!(selected.data, data);
}

#[tokio::test]
async fn coverage_selects_binary_annotations_and_invalidates_all_mutation_paths() {
    use dazhbog::db::PushContext;
    let fixture = Fixture::new();
    let db = fixture.database().await;
    let left = [1; 16];
    let right = [2; 16];
    let context = |md5| PushContext {
        md5: Some(md5),
        basename: Some("coverage.bin"),
        hostname: None,
        origin_token: None,
    };
    let text = b"extra annotation\0";
    let mut comments = pack_dd(MdKey::Extracmts.raw());
    comments.extend(pack_dd(text.len() as u32));
    comments.extend(text);
    db.push_with_ctx(&[(1, 1, 0, "parse_left", &comments)], &context(left))
        .await
        .unwrap();
    db.push_with_ctx(&[(1, 1, 0, "parse_right", &[])], &context(right))
        .await
        .unwrap();
    let (uncached_rows, _) = db
        .search_binaries_paginated("coverage", 0, 10)
        .await
        .unwrap();
    assert_eq!(uncached_rows.len(), 2);
    assert!(uncached_rows.iter().all(|row| row.coverage.is_none()));
    assert_eq!(
        db.get_binary_facets(left, 10)
            .await
            .unwrap()
            .commented_functions,
        1
    );
    assert_eq!(
        db.get_binary_facets(right, 10)
            .await
            .unwrap()
            .commented_functions,
        0
    );
    let zero = db.get_binary_facets(left, 0).await.unwrap();
    assert_eq!(zero.function_count, 0);
    assert!(zero.truncated);
    assert_eq!(
        db.get_binary_facets(left, 10).await.unwrap().function_count,
        1
    );

    // Identical payloads still update the binary's last observation.
    db.push_with_ctx(&[(1, 1, 0, "parse_right", &[])], &context(left))
        .await
        .unwrap();
    assert_eq!(
        db.get_binary_facets(left, 10)
            .await
            .unwrap()
            .commented_functions,
        0
    );
    // A new membership invalidates the binary even though the key was not a dependency.
    db.push_with_ctx(&[(2, 1, 0, "parse_second", &comments)], &context(left))
        .await
        .unwrap();
    let small = db.get_binary_facets(left, 1).await.unwrap();
    assert_eq!(small.function_count, 1);
    assert!(small.truncated);
    let all = db.get_binary_facets(left, usize::MAX).await.unwrap();
    assert_eq!(all.key_limit, 8192);
    assert_eq!(all.function_count, 2);
    assert!(!all.truncated);
    assert_eq!(all.commented_functions, 1);
    let summary = db.get_binary_summary(left).await.unwrap().unwrap();
    assert_eq!(summary.coverage.unwrap().function_count, 2);
    let (cached_rows, _) = db
        .search_binaries_paginated("coverage", 0, 10)
        .await
        .unwrap();
    assert_eq!(
        cached_rows
            .iter()
            .find(|row| row.md5_hex == "01".repeat(16))
            .unwrap()
            .coverage
            .as_ref()
            .unwrap()
            .function_count,
        2
    );

    db.delete_keys(&[1]).await.unwrap();
    assert_eq!(
        db.get_binary_facets(left, 10)
            .await
            .unwrap()
            .unavailable_functions,
        1
    );
    assert_eq!(
        db.get_binary_facets(right, 10)
            .await
            .unwrap()
            .unavailable_functions,
        1
    );
    // Context-free reinsertion changes both binaries' fallback annotations.
    db.push(&[(1, 1, 0, "parse_reinserted", &comments)])
        .await
        .unwrap();
    let restored = db.get_binary_facets(right, 10).await.unwrap();
    assert_eq!(restored.unavailable_functions, 0);
    assert_eq!(restored.fallback_functions, 1);
    assert_eq!(restored.commented_functions, 1);
    db.flush().unwrap();
    drop(db);

    // The old unversioned 64 B cache is retained but never trusted after reopening.
    let legacy = vec![0xff; 64];
    {
        let context_db = sled::open(fixture.path.join("context_db")).unwrap();
        context_db
            .open_tree("binary_facets")
            .unwrap()
            .insert(right, legacy.clone())
            .unwrap();
        context_db.flush().unwrap();
    }
    let db = fixture.database().await;
    assert_eq!(
        db.get_binary_facets(right, 10)
            .await
            .unwrap()
            .commented_functions,
        1
    );
    drop(db);
    let context_db = sled::open(fixture.path.join("context_db")).unwrap();
    assert_eq!(
        context_db
            .open_tree("binary_facets")
            .unwrap()
            .get(right)
            .unwrap()
            .unwrap()
            .as_ref(),
        legacy
    );
}

#[tokio::test]
async fn binary_comparison_resolves_each_side_and_distinguishes_annotation_drift() {
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    {
        let rt = fixture.runtime();
        append(&rt, 1, "left_annotation", 10, [1; 16], 1);
        append(&rt, 1, "right_annotation", 20, [2; 16], 1);
        append(&rt, 1, "unrelated_global_annotation", 30, [3; 16], 10);
        append(&rt, 3, "left_private_annotation", 10, [1; 16], 1);
        append(&rt, 3, "unrelated_private_annotation", 30, [3; 16], 10);
        for (key, name, key_code, left_data, right_data) in [
            (2, "timing_only", MdKey::VdElapsed.raw(), vec![1], vec![2]),
            (
                4,
                "opaque_metadata",
                42,
                b"before".to_vec(),
                b"after".to_vec(),
            ),
            (5, "partial_metadata", 0, vec![255], vec![255]),
        ] {
            for (md5, payload, ts) in [([1; 16], left_data, 10), ([2; 16], right_data, 20)] {
                let data = if key_code == 0 {
                    payload
                } else {
                    let mut bytes = pack_dd(key_code);
                    bytes.extend(pack_dd(payload.len() as u32));
                    bytes.extend(payload);
                    bytes
                };
                let rec = Record {
                    key,
                    name: name.into(),
                    data,
                    ts_sec: ts,
                    prev_addr: rt.index.try_get(key).unwrap(),
                    len_bytes: 0,
                    popularity: 1,
                    flags: 0,
                };
                let rec = Record {
                    len_bytes: rec.data.len() as u32,
                    ..rec
                };
                assert!(rt
                    .index
                    .upsert(key, rt.segments.append(&rec).unwrap())
                    .is_ok());
                observe(&rt, key, version_id(key, name, &rec.data), md5, 1);
            }
        }
        // Label unavailable, but a retrievable fallback exists on both sides.
        append(&rt, 6, "shared_fallback", 10, [1; 16], 1);
        append(&rt, 6, "shared_fallback", 10, [2; 16], 1);
        observe(&rt, 6, version_id(6, "missing_annotation", &[]), [2; 16], 1);
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let left = "01".repeat(16);
    let right = "02".repeat(16);
    let endpoint = format!("/api/binary-compare/{left}/{right}?limit=10");
    let (status, report) = http_json(db.clone(), &endpoint).await;
    assert_eq!(status, 200);
    assert_eq!(report["shared_count"], 5);
    assert_eq!(report["left_only_count"], 1);
    assert_eq!(report["examined_key_count"], 6);
    let shared = report["shared"].as_array().unwrap();
    let row = |key| {
        shared
            .iter()
            .find(|r| r["key_hex"] == format!("{key:032x}"))
            .unwrap()
    };
    assert_eq!(row(1)["left"]["name"], "left_annotation");
    assert_eq!(row(1)["right"]["name"], "right_annotation");
    assert_eq!(row(1)["left"]["ts"], 10);
    assert_eq!(row(1)["right"]["ts"], 20);
    assert_eq!(row(1)["left"]["matches_last_observation"], true);
    assert_eq!(row(1)["right"]["matches_last_observation"], true);
    assert_eq!(row(1)["annotation_relation"], "different");
    assert_eq!(row(2)["annotation_relation"], "same");
    assert_eq!(row(4)["changed_metadata_keys"], serde_json::json!([42]));
    assert_eq!(row(5)["annotation_relation"], "unjudged");
    assert_eq!(row(6)["annotation_relation"], "same");
    assert_eq!(row(6)["right"]["matches_last_observation"], false);
    assert_eq!(
        report["left_only"][0]["left"]["name"],
        "left_private_annotation"
    );
    assert!(report["left_only"][0]["right"].is_null());
    let drift = report["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["label"] == "Freshest Drift")
        .unwrap()["items"]
        .as_array()
        .unwrap();
    assert!(drift.iter().any(|r| r["key_hex"] == format!("{:032x}", 1)));
    assert!(!drift.iter().any(|r| r["key_hex"] == format!("{:032x}", 2)));
    let (_, filtered) = http_json(db.clone(), &format!("{endpoint}&q=right_annotation")).await;
    assert_eq!(filtered["active_bucket_total"], 1);
    let (_, reversed) =
        http_json(db, &format!("/api/binary-compare/{right}/{left}?limit=10")).await;
    let reversed_row = reversed["shared"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key_hex"] == format!("{:032x}", 1))
        .unwrap();
    assert_eq!(row(1)["left"], reversed_row["right"]);
    assert_eq!(row(1)["right"], reversed_row["left"]);
}

#[tokio::test]
async fn binary_comparison_does_not_mistake_prefix_omission_for_absence() {
    let fixture = Fixture::new();
    {
        let rt = fixture.runtime();
        let shared = append(&rt, 255, "shared_outside_prefix", 1, [1; 16], 1);
        observe(&rt, 255, shared, [2; 16], 1);
        for n in 1..=8192u128 {
            rt.ctx_index
                .record_key_observation(n << 8, [1; 16], None, 1, None)
                .unwrap();
        }
        assert!(!rt
            .ctx_index
            .get_binary_function_keys(&[1; 16], 8192)
            .unwrap()
            .contains(&255));
        assert!(rt
            .ctx_index
            .binary_contains_function(&[1; 16], 255)
            .unwrap());
        rt.flush().unwrap();
    }
    let db = fixture.database().await;
    let comparison = db.compare_binaries([1; 16], [2; 16], 1).await.unwrap();
    assert_eq!(comparison.2, 1);
    assert_eq!(comparison.3, 8192);
    assert_eq!(comparison.4, 0);
    assert_eq!(comparison.5[0].key_hex, format!("{:032x}", 255));
    assert_eq!(comparison.5[0].annotation_relation, "same");
}
