use dazhbog::common::hash::version_id;
use dazhbog::config::Config;
use dazhbog::db::{Database, QueryContext};
use dazhbog::engine::{EngineRuntime, Record};
use dazhbog::protocol::lumina::{pack_dd, MdKey};
use std::{
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "dazhbog-projection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> Config {
        let mut cfg = Config::default();
        cfg.engine.data_dir = self.0.to_string_lossy().into_owned();
        cfg.http = None;
        cfg
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record(name: &str, ts_sec: u64, prev_addr: u64, flags: u8) -> Record {
    let text = b"parse network headers\0";
    let mut data = pack_dd(MdKey::Fcmt.raw());
    data.extend(pack_dd(text.len() as u32));
    data.extend(text);
    Record {
        key: 0x1234,
        ts_sec,
        prev_addr,
        len_bytes: data.len() as u32,
        popularity: 1,
        name: name.into(),
        data,
        flags,
    }
}

#[test]
fn counters_survive_replace_delete_and_reopen() -> io::Result<()> {
    let dir = TestDir::new();
    let cfg = dir.config();
    {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        let first = record("parse_headers", 1, 0, 0);
        let a = rt.segments.append(&first)?;
        rt.index
            .upsert(first.key, a)
            .map_err(|_| io::Error::other("upsert"))?;
        let second = record("decode_headers", 2, a, 0);
        let b = rt.segments.append(&second)?;
        rt.index
            .upsert(second.key, b)
            .map_err(|_| io::Error::other("upsert"))?;
        let stats = rt.get_stats()?;
        assert_eq!(stats.indexed_funcs, 1);
        assert_eq!(stats.total_records, 2);
        assert_eq!(
            stats.storage_bytes,
            first.encoded_len() + second.encoded_len()
        );
        rt.index.delete(first.key);
        assert_eq!(rt.index.entry_count()?, 0);
        rt.index
            .upsert(first.key, b)
            .map_err(|_| io::Error::other("upsert"))?;
        rt.flush()?;
    }
    let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
    assert_eq!(rt.get_stats()?.total_records, 2);
    assert_eq!(rt.get_stats()?.indexed_funcs, 1);
    Ok(())
}

#[tokio::test]
async fn canonical_search_does_not_mutate_to_latest() -> io::Result<()> {
    let dir = TestDir::new();
    let cfg = dir.config();
    {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        let first = record("parse_headers", 1, 0, 0);
        let a = rt.segments.append(&first)?;
        let second = record("decode_headers", 2, a, 0);
        let b = rt.segments.append(&second)?;
        rt.index
            .upsert(first.key, b)
            .map_err(|_| io::Error::other("upsert"))?;
        rt.ctx_index.set_canonical_version(
            first.key,
            version_id(first.key, &first.name, &first.data),
            10.0,
            1,
        )?;
        rt.flush()?;
    }
    {
        let prepared = EngineRuntime::prepare(cfg.engine.clone(), cfg.scoring.clone())?;
        assert_eq!(prepared.search.doc_count(), 1);
    }
    let db = Database::open(Arc::new(cfg)).await?;
    assert_eq!(db.get_latest(0x1234).await?.unwrap().name, "decode_headers");
    assert_eq!(
        db.get_canonical(0x1234).await?.unwrap().name,
        "parse_headers"
    );
    for _ in 0..3 {
        let hits = db.search_functions("parse_headers", 10).await?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].func_name, "parse_headers");
    }
    Ok(())
}

#[test]
fn reinsertion_does_not_resurrect_pre_delete_canonical() -> io::Result<()> {
    let dir = TestDir::new();
    let cfg = dir.config();
    {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        let old = record("parse_headers", 1, 0, 0);
        let a = rt.segments.append(&old)?;
        let tombstone = record("", 2, a, 1);
        let b = rt.segments.append(&tombstone)?;
        let new = record("decode_headers", 3, b, 0);
        let c = rt.segments.append(&new)?;
        rt.index
            .upsert(old.key, c)
            .map_err(|_| io::Error::other("upsert"))?;
        rt.ctx_index.set_canonical_version(
            old.key,
            version_id(old.key, &old.name, &old.data),
            10.0,
            1,
        )?;
        let visible = dazhbog::engine::resolve_visible_record(
            &rt.segments,
            &rt.index,
            &rt.ctx_index,
            old.key,
            true,
        )?
        .unwrap();
        assert_eq!(visible.name, new.name);
        rt.flush()?;
    }
    let rt = EngineRuntime::prepare(cfg.engine, cfg.scoring)?;
    assert_eq!(rt.search.search("decode_headers", 10)?.len(), 1);
    Ok(())
}

#[test]
fn missing_preparation_is_explicit_and_preserves_old_search() -> io::Result<()> {
    let dir = TestDir::new();
    let cfg = dir.config();
    {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        let first = record("parse_headers", 1, 0, 0);
        let a = rt.segments.append(&first)?;
        rt.index
            .upsert(first.key, a)
            .map_err(|_| io::Error::other("upsert"))?;
        rt.index_db.remove(b"canonical_projection_v1")?;
        rt.flush()?;
    }
    let old_manifest = std::fs::read(dir.0.join("search_index/meta.json"))?;
    assert!(EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone()).is_err());
    {
        let rt = EngineRuntime::prepare(cfg.engine.clone(), cfg.scoring.clone())?;
        assert_eq!(rt.search.doc_count(), 1);
    }
    assert_eq!(
        std::fs::read(dir.0.join("search_index/meta.json"))?,
        old_manifest
    );
    let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
    assert_eq!(rt.search.doc_count(), 1);
    Ok(())
}

#[tokio::test]
async fn duplicate_batch_keys_preserve_positions_without_reweighting() -> io::Result<()> {
    let dir = TestDir::new();
    let db = Database::open(Arc::new(dir.config())).await?;
    let a = record("parse_headers", 1, 0, 0);
    db.push(&[(a.key, 1, a.len_bytes, &a.name, &a.data)])
        .await?;
    let ctx = QueryContext {
        keys: &[a.key, 0x9999],
        requested_mdkeys: &[],
        md5: None,
        basename: None,
        hostname: None,
        origin_token: None,
    };
    let baseline = db.select_versions_for_batch(&ctx).await?;
    let repeated = QueryContext {
        keys: &[a.key, a.key, 0x9999, a.key],
        ..ctx
    };
    let actual = db.select_versions_for_batch(&repeated).await?;
    assert_eq!(
        actual,
        vec![
            baseline[0].clone(),
            baseline[0].clone(),
            None,
            baseline[0].clone()
        ]
    );
    Ok(())
}

#[test]
fn malformed_search_manifest_is_not_recreated() -> io::Result<()> {
    let dir = TestDir::new();
    std::fs::write(dir.0.join("meta.json"), b"corrupt")?;
    assert!(dazhbog::engine::SearchIndex::open(&dir.0).is_err());
    assert_eq!(std::fs::read(dir.0.join("meta.json"))?, b"corrupt");
    Ok(())
}

#[tokio::test]
async fn precision_default_preserves_name_payload_pairs() -> io::Result<()> {
    use dazhbog::db::PushContext;
    let dir = TestDir::new();
    let db = Database::open(Arc::new(dir.config())).await?;
    let first = record("parse_headers", 1, 0, 0);
    let mut second = record("decode_headers", 2, 0, 0);
    second.data = [pack_dd(MdKey::Fcmt.raw()), pack_dd(6), b"other\0".to_vec()].concat();
    second.len_bytes = second.data.len() as u32;
    let push = PushContext {
        md5: Some([1; 16]),
        basename: Some("parser.bin"),
        hostname: None,
        origin_token: None,
    };
    for rec in [&first, &second] {
        db.push_with_ctx(&[(rec.key, 1, rec.len_bytes, &rec.name, &rec.data)], &push)
            .await?;
    }
    let query = QueryContext {
        keys: &[first.key],
        requested_mdkeys: &[MdKey::Fcmt.raw()],
        md5: Some([1; 16]),
        basename: Some("parser.bin"),
        hostname: None,
        origin_token: None,
    };
    let output = db
        .select_versions_for_batch(&query)
        .await?
        .remove(0)
        .unwrap();
    assert!([&first, &second]
        .iter()
        .any(|r| r.name == output.2 && r.data == output.3));
    let repeated = QueryContext {
        keys: &[first.key, first.key, first.key],
        ..query
    };
    assert_eq!(
        db.select_versions_for_batch(&repeated).await?,
        vec![Some(output); 3]
    );
    Ok(())
}
