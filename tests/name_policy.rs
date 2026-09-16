use dazhbog::engine::EngineRuntime;
use dazhbog::{
    config::{Config, NameRejection},
    db::{Database, PushContext},
};
use std::{io, path::PathBuf, sync::Arc};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dazhbog-name-policy-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn config(&self, name: &str, policy: NameRejection) -> Config {
        let mut cfg = Config::default();
        cfg.engine.data_dir = self.0.join(name).to_string_lossy().into_owned();
        cfg.engine.name_rejection = policy;
        cfg.http = None;
        cfg
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn database_name_policies_do_not_change_one_anothers_annotations() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let off_cfg = Arc::new(fixture.config("off", NameRejection::Off));
    // Replay permits reopen: the process-global metrics tree retains the first
    // serving database's storage lock. The separate Prefixes store exercises open.
    let off = Database::open_for_replay(off_cfg.clone()).await?;
    let ctx = PushContext {
        md5: Some([1; 16]),
        basename: None,
        hostname: None,
        origin_token: None,
    };
    off.push_with_ctx(&[(1, 1, 1, "sub_retained", &[])], &ctx)
        .await?;
    assert_eq!(
        off.get_function_in_context(1, Some([1; 16]))
            .await?
            .unwrap()
            .name,
        "sub_retained"
    );

    let prefixes = Database::open(Arc::new(
        fixture.config("prefixes", NameRejection::Prefixes),
    ))
    .await?;
    assert!(
        off.get_function_in_context(1, Some([1; 16]))
            .await?
            .is_some(),
        "opening another database must not hide the off-policy annotation"
    );
    off.push_with_ctx(&[(2, 1, 1, "sub_second", &[])], &ctx)
        .await?;
    assert!(off.get_latest(2).await?.is_some());
    prefixes
        .push_with_ctx(&[(3, 1, 1, "sub_rejected", &[])], &ctx)
        .await?;
    assert!(prefixes.get_latest(3).await?.is_none());
    assert_eq!(off.get_history(1, 10).await?.len(), 1);
    assert!(off.get_canonical(1).await?.is_some());
    off.flush()?;
    drop(off);
    let replay = Database::open_for_replay(off_cfg).await?;
    assert!(replay
        .get_function_in_context(1, Some([1; 16]))
        .await?
        .is_some());
    prefixes
        .push_with_ctx(&[(4, 1, 1, "sub_still_rejected", &[])], &ctx)
        .await?;
    assert!(prefixes.get_latest(4).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn policy_changes_require_preparation_and_preserve_source_records() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let mut cfg = fixture.config("projection", NameRejection::Off);
    {
        let db = Database::open_for_replay(Arc::new(cfg.clone())).await?;
        db.push_with_ctx(
            &[
                (1, 1, 1, "sub_retained", &[]),
                (2, 1, 1, "decode_1234567", &[]),
                (3, 1, 1, "decode_packet", &[]),
            ],
            &PushContext {
                md5: None,
                basename: None,
                hostname: None,
                origin_token: None,
            },
        )
        .await?;
        db.flush()?;
    }
    let old_manifest;
    {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        assert_eq!(rt.search.doc_count(), 3);
        old_manifest = rt.index_db.get(b"canonical_projection_v4")?.unwrap();
    }
    for (policy, expected) in [
        (NameRejection::Prefixes, 2),
        (NameRejection::Heuristic, 1),
        (NameRejection::Off, 3),
    ] {
        cfg.engine.name_rejection = policy;
        let error = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())
            .err()
            .unwrap();
        assert!(error.to_string().contains("name policy changed"));
        {
            let rt = EngineRuntime::open_for_replay(cfg.engine.clone(), cfg.scoring.clone())?;
            assert_eq!(rt.segments.get_record_count()?, 3);
            if policy == NameRejection::Prefixes {
                assert_eq!(
                    rt.index_db.get(b"canonical_projection_v4")?.unwrap(),
                    old_manifest
                );
            }
        }
        {
            let db = Database::open_for_replay(Arc::new(cfg.clone())).await?;
            assert!(db.delete_keys(&[3]).await.is_err());
            assert!(db.revert_last_versions(&[3]).await.is_err());
            assert!(db
                .push_with_ctx(
                    &[(4, 1, 1, "new_name", &[])],
                    &PushContext {
                        md5: None,
                        basename: None,
                        hostname: None,
                        origin_token: None
                    }
                )
                .await
                .is_err());
            assert!(db.get_latest(3).await?.is_some());
        }
        {
            let rt = EngineRuntime::prepare(cfg.engine.clone(), cfg.scoring.clone())?;
            assert_eq!(rt.search.doc_count(), expected);
            assert_eq!(rt.segments.get_record_count()?, 3);
            let rebuilt = dazhbog::engine::search::rebuild_from_engine_with_policy(
                &rt.search,
                &rt.segments,
                &rt.index,
                &rt.ctx_index,
                policy,
                |_| {},
            )?;
            assert_eq!(rebuilt.indexed_docs, expected);
        }
        {
            let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
            assert_eq!(rt.search.doc_count(), expected);
        }
        let db = Database::open_for_replay(Arc::new(cfg.clone())).await?;
        assert_eq!(
            db.get_latest(1).await?.is_some(),
            policy == NameRejection::Off
        );
        assert_eq!(
            db.get_canonical(2).await?.is_some(),
            policy != NameRejection::Heuristic
        );
        assert!(db.get_function_in_context(3, None).await?.is_some());
    }
    assert!(fixture.0.join("projection/search_index/meta.json").exists());
    Ok(())
}

#[tokio::test]
async fn cli_preparation_uses_the_configured_policy_and_certifies_legacy_projection(
) -> io::Result<()> {
    let fixture = Fixture::new()?;
    let cfg = fixture.config("cli", NameRejection::Off);
    {
        let db = Database::open_for_replay(Arc::new(cfg.clone())).await?;
        db.push_with_ctx(
            &[(1, 1, 1, "sub_retained", &[])],
            &PushContext {
                md5: None,
                basename: None,
                hostname: None,
                origin_token: None,
            },
        )
        .await?;
        db.flush()?;
    }
    {
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        rt.index_db.remove(b"canonical_projection_v4")?;
        rt.index_db
            .insert(b"canonical_projection_v3", b"search_index")?;
        rt.flush()?;
    }
    assert!(EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone()).is_err());
    {
        let rt = EngineRuntime::open_for_replay(cfg.engine.clone(), cfg.scoring.clone())?;
        assert!(rt.index_db.get(b"canonical_projection_v4")?.is_none());
    }
    let config_path = fixture.0.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "engine.data_dir = {:?}\nlumina.name_rejection = \"off\"\n",
            cfg.engine.data_dir
        ),
    )?;
    assert_eq!(
        Config::load(config_path.to_str().unwrap())?
            .engine
            .name_rejection,
        NameRejection::Off
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dazhbog"))
        .arg("--prepare")
        .arg(&config_path)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
    assert_eq!(rt.search.doc_count(), 1);
    assert_eq!(rt.search.search("sub_retained", 10)?.len(), 1);
    let manifest: serde_json::Value =
        serde_json::from_slice(&rt.index_db.get(b"canonical_projection_v4")?.unwrap())?;
    assert_eq!(manifest["name_rejection"], "off");
    assert_eq!(
        rt.index_db
            .get(b"canonical_projection_v3")?
            .unwrap()
            .as_ref(),
        b"search_index"
    );
    Ok(())
}

#[test]
fn malformed_manifests_fail_closed_without_replacing_the_published_value() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let cfg = fixture.config("malformed", NameRejection::Off);
    let invalid = [
        br#"{"generation":"search_index"}"#.as_slice(),
        br#"{"generation":"search_index","name_rejection":"unknown"}"#.as_slice(),
        br#"{"generation":"search_index/../outside","name_rejection":"off"}"#.as_slice(),
        br#"{"generation":"search_index.missing","name_rejection":"off"}"#.as_slice(),
    ];
    for value in invalid {
        {
            let rt = EngineRuntime::prepare(cfg.engine.clone(), cfg.scoring.clone())?;
            rt.index_db.insert(b"canonical_projection_v4", value)?;
            rt.flush()?;
        }
        assert!(EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone()).is_err());
        assert!(EngineRuntime::open_for_replay(cfg.engine.clone(), cfg.scoring.clone()).is_err());
        let db = sled::open(fixture.0.join("malformed/index"))?;
        assert_eq!(db.get(b"canonical_projection_v4")?.unwrap().as_ref(), value);
    }
    Ok(())
}
