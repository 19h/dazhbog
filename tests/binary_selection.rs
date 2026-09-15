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
    let text = format!("{name}\0");
    let mut data = pack_dd(MdKey::Fcmt.raw());
    data.extend(pack_dd(text.len() as u32));
    data.extend(text.as_bytes());
    let vid = version_id(key, name, &data);
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
    let mut fixture = Fixture::new();
    fixture.cfg.scoring.max_versions_per_key = 1;
    {
        let rt = fixture.runtime();
        append(&rt, 1, "parse_http_headers", 1, [1; 16], 1);
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
