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
    assert_eq!(chosen.1, 0);
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
