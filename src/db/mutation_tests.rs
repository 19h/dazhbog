use super::*;
use std::sync::Barrier;

struct TemporaryStore(std::path::PathBuf);

impl Drop for TemporaryStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store(label: &str) -> io::Result<(TemporaryStore, Arc<EngineRuntime>)> {
    let path =
        std::env::temp_dir().join(format!("dazhbog-mutation-{label}-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    let mut cfg = Config::default();
    cfg.engine.data_dir = path.to_string_lossy().into_owned();
    cfg.scoring.experimental_synthesis = false;
    let cleanup = TemporaryStore(path);
    let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
    Ok((cleanup, Arc::new(rt)))
}

fn context(binary: u8) -> OwnedPushContext {
    OwnedPushContext {
        md5: Some([binary; 16]),
        basename: None,
        hostname: None,
        origin_token: None,
    }
}

#[tokio::test]
async fn concurrent_pushes_preserve_history_and_binary_specific_retrieval() -> io::Result<()> {
    let (_cleanup, rt) = store("history")?;
    let start = Barrier::new(12);
    std::thread::scope(|scope| -> io::Result<()> {
        let threads: Vec<_> = (1..=12u8)
            .map(|binary| {
                let rt = &rt;
                let start = &start;
                scope.spawn(move || -> io::Result<()> {
                    start.wait();
                    for round in 0..3 {
                        let name = format!("parse_binary_{binary}_revision_{round}");
                        let statuses = Database::push_with_ctx_sync(
                            rt,
                            &[(1, 1, 8, name, vec![42, 1, binary])],
                            &context(binary),
                            false,
                        )?;
                        assert_eq!(statuses.len(), 1);
                        assert!(statuses[0] <= 1);
                    }
                    Ok(())
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap()?;
        }
        Ok(())
    })?;
    let db = Database {
        rt,
        failure_cache: FailureCache::new(),
    };
    let history = db.get_history(1, 100).await?;
    assert_eq!(
        history.len(),
        36,
        "a concurrent writer lost a history branch"
    );
    assert_eq!(
        history
            .iter()
            .map(|(_, name, _)| name)
            .collect::<HashSet<_>>()
            .len(),
        36
    );
    for binary in 1..=12u8 {
        let selected = db.select_binary_variant(1, [binary; 16]).await?.unwrap();
        assert_eq!(selected.name, format!("parse_binary_{binary}_revision_2"));
        assert_eq!(selected.data, [42, 1, binary]);
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_identical_pushes_append_once_but_preserve_observations() -> io::Result<()> {
    let (_cleanup, rt) = store("duplicates")?;
    let start = Barrier::new(12);
    std::thread::scope(|scope| -> io::Result<()> {
        let threads: Vec<_> = (1..=12u8)
            .map(|binary| {
                let rt = &rt;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    Database::push_with_ctx_sync(
                        rt,
                        &[(1, 1, 8, "parse_packet".into(), vec![42, 1, 7])],
                        &context(binary),
                        false,
                    )
                })
            })
            .collect();
        let mut inserted = 0;
        let mut unchanged = 0;
        for thread in threads {
            let statuses = thread.join().unwrap()?;
            assert_eq!(statuses.len(), 1);
            inserted += usize::from(statuses[0] == 1);
            unchanged += usize::from(statuses[0] == 2);
        }
        assert_eq!((inserted, unchanged), (1, 11));
        Ok(())
    })?;
    assert_eq!(rt.segments.get_record_count()?, 1);
    let db = Database {
        rt,
        failure_cache: FailureCache::new(),
    };
    assert_eq!(db.get_history(1, 100).await?.len(), 1);
    for binary in 1..=12u8 {
        assert_eq!(
            db.rt
                .ctx_index
                .get_positive_key_md5_stats(1, &[binary; 16])?
                .unwrap()
                .obs_count,
            1
        );
        assert_eq!(
            db.select_binary_variant(1, [binary; 16])
                .await?
                .unwrap()
                .name,
            "parse_packet"
        );
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_reverts_and_deletes_share_locks_across_runtime_clones() -> io::Result<()> {
    let (_cleanup, rt) = store("undo-delete")?;
    for version in 0..12 {
        Database::push_with_ctx_sync(
            &rt,
            &[(1, 1, 8, format!("parse_revision_{version}"), vec![])],
            &context(1),
            false,
        )?;
    }
    Database::push_with_ctx_sync(
        &rt,
        &[(2, 1, 8, "parse_old_packet".into(), vec![])],
        &context(1),
        false,
    )?;
    let start = Barrier::new(12);
    let (reverted, deleted) = std::thread::scope(|scope| -> io::Result<(u32, u32)> {
        let threads: Vec<_> = (0..12)
            .map(|_| {
                let clone = (*rt).clone();
                let start = &start;
                scope.spawn(move || -> io::Result<(u32, u32)> {
                    start.wait();
                    let reverted = Database::revert_last_versions_sync(&clone, &[1])?;
                    let deleted = Database::delete_keys_sync(&clone, &[2])?;
                    Ok((reverted, deleted))
                })
            })
            .collect();
        let mut counts = (0, 0);
        for thread in threads {
            let result = thread.join().unwrap()?;
            counts.0 += result.0;
            counts.1 += result.1;
        }
        Ok(counts)
    })?;
    assert_eq!((reverted, deleted), (12, 1));
    let db = Database {
        rt,
        failure_cache: FailureCache::new(),
    };
    for key in [1, 2] {
        assert!(db.get_latest(key).await?.is_none());
        assert!(db.get_history(key, 100).await?.is_empty());
        db.push(&[(key, 1, 8, "parse_reinserted_packet", &[])])
            .await?;
        assert_eq!(db.get_history(key, 100).await?.len(), 1);
        // Stale provenance must not cross the deletion boundary.
        assert_eq!(
            db.select_binary_variant(key, [1; 16]).await?.unwrap().name,
            "parse_reinserted_packet"
        );
    }
    Ok(())
}

#[tokio::test]
async fn racing_push_and_delete_has_a_serial_history() -> io::Result<()> {
    let (_cleanup, rt) = store("push-delete")?;
    let db = Database {
        rt,
        failure_cache: FailureCache::new(),
    };
    for key in 1..=8 {
        db.push(&[(key, 1, 8, "parse_old_packet", &[])]).await?;
        let items = [(key, 1, 8, "parse_new_packet", &[][..])];
        let keys = [key];
        let (pushed, deleted) = tokio::join!(db.push(&items), db.delete_keys(&keys));
        assert_eq!(pushed?, [0]);
        assert_eq!(deleted?, 1);
        let history = db.get_history(key, 100).await?;
        match db.get_latest(key).await? {
            Some(latest) => {
                assert_eq!(latest.name, "parse_new_packet");
                assert_eq!(
                    history.len(),
                    1,
                    "push after delete must stop at the tombstone"
                );
                assert_eq!(history[0].1, latest.name);
            }
            None => assert!(history.is_empty()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_no_override_uploads_keep_one_payload() -> io::Result<()> {
    let (_cleanup, rt) = store("no-override")?;
    let start = Barrier::new(12);
    let inserted = std::thread::scope(|scope| -> io::Result<usize> {
        let threads: Vec<_> = (1..=12u8)
            .map(|binary| {
                let rt = &rt;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    Database::push_with_ctx_sync(
                        rt,
                        &[(
                            1,
                            1,
                            8,
                            format!("parse_binary_{binary}"),
                            vec![42, 1, binary],
                        )],
                        &context(binary),
                        true,
                    )
                })
            })
            .collect();
        let mut inserted = 0;
        for thread in threads {
            let statuses = thread.join().unwrap()?;
            assert_eq!(statuses.len(), 1);
            assert!(matches!(statuses[0], 1 | 2));
            inserted += usize::from(statuses[0] == 1);
        }
        Ok(inserted)
    })?;
    assert_eq!(inserted, 1);
    assert_eq!(rt.segments.get_record_count()?, 1);
    let db = Database {
        rt,
        failure_cache: FailureCache::new(),
    };
    assert_eq!(db.get_history(1, 100).await?.len(), 1);
    Ok(())
}
