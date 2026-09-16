use dazhbog::common::hash::{crc32c, crc32c_legacy};
use dazhbog::engine::ShardedIndex;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "dazhbog-index-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let db = sled::open(fixture.0.join("index")).unwrap();
        let index = ShardedIndex::new(&db).unwrap();
        assert!(index.upsert(999, 123).is_ok());
        for version in 1..=4 {
            db.insert(
                format!("canonical_projection_v{version}"),
                b"old-generation",
            )
            .unwrap();
        }
        db.insert(b"unrelated", b"preserved").unwrap();
        db.flush().unwrap();
        fixture
    }

    fn run(&self) -> std::process::Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_dazhbog-recover"))
            .arg("--rebuild-index")
            .arg(&self.0)
            .current_dir(&self.0)
            .output()
            .unwrap()
    }

    fn assert_old_index(&self) {
        let db = sled::open(self.0.join("index")).unwrap();
        let index = ShardedIndex::open(&db, false).unwrap();
        assert_eq!(index.entry_count().unwrap(), 1);
        assert_eq!(index.try_get(999).unwrap(), 123);
        for version in 1..=4 {
            assert_eq!(
                db.get(format!("canonical_projection_v{version}"))
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                b"old-generation"
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Explicit persisted layout, independent of the recovery scanner/encoder.
fn record(key: u128, timestamp: u64, previous: u64, flags: u8, legacy: bool) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[0..4].copy_from_slice(&0x4c4d4e31u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&70u32.to_le_bytes());
    bytes[12..28].copy_from_slice(&key.to_le_bytes());
    bytes[28..36].copy_from_slice(&timestamp.to_le_bytes());
    bytes[36..44].copy_from_slice(&previous.to_le_bytes());
    bytes[44..48].copy_from_slice(&3u32.to_le_bytes());
    bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&3u16.to_le_bytes());
    bytes[54..58].copy_from_slice(&3u32.to_le_bytes());
    bytes[58] = flags;
    bytes.extend_from_slice(b"fooabc");
    checksum(&mut bytes, legacy);
    bytes
}

fn checksum(bytes: &mut [u8], legacy: bool) {
    let crc = if legacy {
        crc32c_legacy(0, &bytes[12..])
    } else {
        crc32c(0, &bytes[12..])
    };
    bytes[8..12].copy_from_slice(&crc.to_le_bytes());
}

fn address(segment: u16, offset: u64, flags: u8) -> u64 {
    (u64::from(segment) << 48) | (offset << 8) | u64::from(flags)
}

#[test]
fn rebuild_uses_append_order_for_ties_clock_rollback_deletion_and_reinsertion() {
    let fixture = Fixture::new();
    let mut expected = Vec::new();
    let mut original_rows = Vec::new();
    {
        let db = sled::open(fixture.0.join("segments_db")).unwrap();
        // Create the later tree first; tree creation order is not append order.
        let second = db.open_tree("seg.00002").unwrap();
        let first = db.open_tree("seg.00001").unwrap();
        for (key, old_ts, new_ts, old_flags, new_flags) in [
            (1u128, 100, 100, 0, 0),
            (2, 100, 1, 0, 0),
            (3, 100, 100, 0, 1),
            (4, 100, 1, 0, 1),
            (5, 100, 100, 1, 2),
            (6, 100, 1, 1, 2),
        ] {
            let old_offset = key as u64 * 140;
            let old_addr = address(1, old_offset, old_flags);
            let new_segment = if key % 2 == 0 { 2 } else { 1 };
            let new_offset = if new_segment == 2 {
                key as u64 * 70
            } else {
                old_offset + 70
            };
            let old = record(key, old_ts, 0, old_flags, false);
            let new = record(key, new_ts, old_addr, new_flags, true);
            first.insert(old_offset.to_be_bytes(), old.clone()).unwrap();
            let tree = if new_segment == 2 { &second } else { &first };
            // Distinct offsets in the later segment, all below old offsets.
            tree.insert(new_offset.to_be_bytes(), new.clone()).unwrap();
            original_rows.push((1, old_offset, old));
            original_rows.push((new_segment, new_offset, new));
            expected.push((
                key,
                if new_flags & 1 == 0 {
                    address(new_segment, new_offset, new_flags)
                } else {
                    0
                },
            ));
        }
        db.flush().unwrap();
    }
    let output = fixture.run();
    assert!(output.status.success(), "{:?}", output);
    {
        let db = sled::open(fixture.0.join("index")).unwrap();
        let index = ShardedIndex::open(&db, false).unwrap();
        for (key, address) in expected {
            assert_eq!(index.try_get(key).unwrap(), address, "key {key}");
        }
        assert_eq!(index.try_get(999).unwrap(), 0);
        assert_eq!(index.entry_count().unwrap(), 4);
        let stats = db.open_tree("__tree_stats_v1").unwrap();
        assert_eq!(
            stats.get(b"latest").unwrap().unwrap().as_ref(),
            [4u64.to_le_bytes(), 32u64.to_le_bytes()].concat()
        );
        for version in 1..=4 {
            assert!(db
                .get(format!("canonical_projection_v{version}"))
                .unwrap()
                .is_none());
        }
        assert_eq!(
            db.get(b"unrelated").unwrap().unwrap().as_ref(),
            b"preserved"
        );
    }
    let db = sled::open(fixture.0.join("segments_db")).unwrap();
    for (segment, offset, raw) in original_rows {
        assert_eq!(
            db.open_tree(format!("seg.{segment:05}"))
                .unwrap()
                .get(offset.to_be_bytes())
                .unwrap()
                .unwrap()
                .as_ref(),
            raw
        );
    }
}

#[test]
fn invalid_recovery_input_preserves_existing_index_and_projection() {
    for case in 0..12 {
        let fixture = Fixture::new();
        {
            let db = sled::open(fixture.0.join("segments_db")).unwrap();
            let tree = db.open_tree("seg.00001").unwrap();
            tree.insert(0u64.to_be_bytes(), record(1, 100, 0, 0, false))
                .unwrap();
            let mut raw = record(1, 100, address(1, 0, 0), 1, false);
            let mut offset = 70u64.to_be_bytes().to_vec();
            match case {
                0 => raw[8] ^= 1, // CRC-damaged tombstone must not resurrect old data.
                1 => raw[0] ^= 1,
                2 => raw[4..8].copy_from_slice(&71u32.to_le_bytes()),
                3 => raw[52..54].copy_from_slice(&4u16.to_le_bytes()),
                4 => raw[64] = 0xff,
                5 => raw.truncate(63),
                6 => offset = vec![0],
                7 => offset = (1u64 << 40).to_be_bytes().to_vec(),
                8 => {
                    db.open_tree("seg.x").unwrap();
                }
                9 => {
                    db.open_tree("seg.00000").unwrap();
                }
                10 => {
                    db.open_tree(b"seg.\xff0000").unwrap();
                }
                11 => {
                    db.open_tree("seg.65536").unwrap();
                }
                _ => unreachable!(),
            }
            if (2..=5).contains(&case) {
                checksum(&mut raw, false);
            }
            tree.insert(offset, raw).unwrap();
            db.flush().unwrap();
        }
        let output = fixture.run();
        assert!(!output.status.success(), "case {case}: {output:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("InvalidData"), "case {case}: {error}");
        assert!(!error.contains("panicked"), "case {case}: {error}");
        fixture.assert_old_index();
    }
}

#[test]
fn serving_requires_preparation_after_rebuild_and_retains_old_search_files() {
    use dazhbog::{
        config::Config,
        engine::{EngineRuntime, Record},
    };

    let fixture = Fixture::new();
    // The fixture seeds an intentionally invalid old index; use a separate,
    // fresh engine directory to exercise actual preparation manifests.
    let mut config = Config::default();
    let engine_dir = fixture.0.join("engine");
    config.engine.data_dir = engine_dir.to_string_lossy().into_owned();
    let expected;
    {
        let rt = EngineRuntime::open(config.engine.clone(), config.scoring.clone()).unwrap();
        let old = Record {
            key: 1,
            ts_sec: 100,
            prev_addr: 0,
            len_bytes: 0,
            popularity: 1,
            name: "old_name".into(),
            data: vec![],
            flags: 0,
        };
        let old_address = rt.segments.append(&old).unwrap();
        assert!(rt.index.upsert(1, old_address).is_ok());
        expected = rt
            .segments
            .append(&Record {
                name: "new_name".into(),
                prev_addr: old_address,
                ..old
            })
            .unwrap();
        rt.flush().unwrap();
    }
    let old_generation;
    {
        let rt = EngineRuntime::prepare(config.engine.clone(), config.scoring.clone()).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(
            &rt.index_db
                .get(b"canonical_projection_v4")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        old_generation = engine_dir.join(manifest["generation"].as_str().unwrap());
    }
    for _ in 0..2 {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_dazhbog-recover"))
            .arg("--rebuild-index")
            .arg(&engine_dir)
            .current_dir(&fixture.0)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(old_generation.is_dir());
        let error = match EngineRuntime::open(config.engine.clone(), config.scoring.clone()) {
            Ok(_) => panic!("uncertified projection served after index rebuild"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("canonical search projection"),
            "{error}"
        );
        let rt = EngineRuntime::prepare(config.engine.clone(), config.scoring.clone()).unwrap();
        assert_eq!(rt.index.try_get(1).unwrap(), expected);
        assert_eq!(rt.index.entry_count().unwrap(), 1);
        rt.flush().unwrap();
        drop(rt);
        let reopened = EngineRuntime::open(config.engine.clone(), config.scoring.clone()).unwrap();
        assert_eq!(reopened.index.try_get(1).unwrap(), expected);
    }
}

#[test]
fn segment_and_offset_maxima_are_preserved_without_masking() {
    let fixture = Fixture::new();
    let offset = (1u64 << 40) - 1;
    {
        let db = sled::open(fixture.0.join("segments_db")).unwrap();
        db.open_tree("seg.65535")
            .unwrap()
            .insert(offset.to_be_bytes(), record(1, 1, 0, 2, false))
            .unwrap();
        db.flush().unwrap();
    }
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    let db = sled::open(fixture.0.join("index")).unwrap();
    assert_eq!(
        ShardedIndex::open(&db, false).unwrap().try_get(1).unwrap(),
        address(u16::MAX, offset, 2)
    );
}

#[test]
fn absent_segment_trees_do_not_clear_the_index() {
    let fixture = Fixture::new();
    drop(sled::open(fixture.0.join("segments_db")).unwrap());
    let output = fixture.run();
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("no segment trees"));
    fixture.assert_old_index();
}

#[test]
fn empty_segment_and_all_deleted_rebuilds_have_zero_statistics() {
    for deleted in [false, true] {
        let fixture = Fixture::new();
        {
            let db = sled::open(fixture.0.join("segments_db")).unwrap();
            let tree = db.open_tree("seg.00001").unwrap();
            if deleted {
                tree.insert(0u64.to_be_bytes(), record(1, 1, 0, 1, false))
                    .unwrap();
            }
            db.flush().unwrap();
        }
        let output = fixture.run();
        assert!(output.status.success(), "{output:?}");
        let db = sled::open(fixture.0.join("index")).unwrap();
        let index = ShardedIndex::open(&db, false).unwrap();
        assert_eq!(index.entry_count().unwrap(), 0);
        assert!(index.is_empty().unwrap());
    }
}
