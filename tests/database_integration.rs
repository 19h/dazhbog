use dazhbog::config::{Config, Engine};
use dazhbog::db::Database;
use dazhbog::engine::{EngineRuntime, Record};
use rand::RngExt;
use std::path::PathBuf;
use std::sync::Arc;

// Helper to create a temporary directory for tests
fn setup_test_db_dir(test_name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let dir_name = format!("dazhbog_test_{}_{}", test_name, rand::rng().random::<u64>());
    path.push(dir_name);
    if path.exists() {
        std::fs::remove_dir_all(&path).unwrap();
    }
    std::fs::create_dir_all(&path).unwrap();
    path
}

// Helper to create a default config pointing to the temp dir
fn get_test_config(data_dir: PathBuf) -> Arc<Config> {
    let mut cfg = Config::default();
    cfg.engine = Engine {
        name_rejection: dazhbog::config::NameRejection::Prefixes,
        data_dir: data_dir.to_str().unwrap().to_string(),
        segment_bytes: 16 * 1024 * 1024, // 16MB segments for tests
        shard_count: 4,
        index_capacity: 1024 * 1024,
        sync_interval_ms: 100,
        compaction_check_ms: 1000,
        use_mmap_reads: false,
        deduplicate_on_startup: false,
        index_dir: Some(data_dir.join("index").to_str().unwrap().to_string()),
        index_memtable_max_entries: 1000,
        index_block_entries: 16,
        index_level0_compact_trigger: 4,
    };
    Arc::new(cfg)
}

#[tokio::test]
async fn test_db_open_and_close() {
    let data_dir = setup_test_db_dir("open_close");
    let config = get_test_config(data_dir.clone());

    let db = Database::open(config).await.unwrap();
    // The drop at the end of the function will test closing.
    // We just need to ensure it doesn't panic.
    drop(db);

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_db_push_and_get_latest() {
    let data_dir = setup_test_db_dir("push_get");
    let config = get_test_config(data_dir.clone());
    let db = Database::open(config).await.unwrap();

    let key = 0x112233445566778899AABBCCDDEEFF00;
    let name = "test_func";
    let data = b"some function data".to_vec();
    let pop = 100;
    let len_bytes = data.len() as u32;

    // 1. Push a new item
    let items = vec![(key, pop, len_bytes, name, data.as_slice())];
    let statuses = db.push(&items).await.unwrap();
    assert_eq!(statuses, vec![1]); // 1 = Inserted

    // 2. Get the item back
    let latest = db.get_latest(key).await.unwrap().unwrap();
    assert_eq!(latest.name, name);
    assert_eq!(latest.data, data);
    assert_eq!(latest.popularity, pop);
    assert_eq!(latest.len_bytes, len_bytes);

    // 3. Get a non-existent key
    let nonexistent = db.get_latest(key + 1).await.unwrap();
    assert!(nonexistent.is_none());

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_db_update_and_get_history() {
    let data_dir = setup_test_db_dir("update_history");
    let config = get_test_config(data_dir.clone());
    let db = Database::open(config).await.unwrap();

    let key = 0x2233445566778899AABBCCDDEEFF0011;

    // Version 1
    let name1 = "test_func_v1";
    let data1 = b"version 1 data".to_vec();
    let items1 = vec![(key, 10, data1.len() as u32, name1, data1.as_slice())];
    let statuses1 = db.push(&items1).await.unwrap();
    assert_eq!(statuses1, vec![1]); // Inserted
    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Ensure timestamp changes

    // Version 2
    let name2 = "test_func_v2";
    let data2 = b"version 2 data".to_vec();
    let items2 = vec![(key, 20, data2.len() as u32, name2, data2.as_slice())];
    let statuses2 = db.push(&items2).await.unwrap();
    assert_eq!(statuses2, vec![0]); // Replaced

    // Check get_latest returns version 2
    let latest = db.get_latest(key).await.unwrap().unwrap();
    assert_eq!(latest.name, name2);
    assert_eq!(latest.data, data2);
    assert_eq!(latest.popularity, 20);

    // Check get_history
    let history = db.get_history(key, 10).await.unwrap();
    assert_eq!(history.len(), 2);

    // History is newest first
    assert_eq!(history[0].1, name2);
    assert_eq!(history[0].2, data2);
    assert_eq!(history[1].1, name1);
    assert_eq!(history[1].2, data1);

    // Check history limit
    let history_limited = db.get_history(key, 1).await.unwrap();
    assert_eq!(history_limited.len(), 1);
    assert_eq!(history_limited[0].1, name2);

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_db_delete() {
    let data_dir = setup_test_db_dir("delete");
    let config = get_test_config(data_dir.clone());
    let db = Database::open(config).await.unwrap();

    let key1 = 0x33445566778899AABBCCDDEEFF001122;
    let key2 = 0x445566778899AABBCCDDEEFF00112233;

    // Push two items
    let items = vec![
        (key1, 1, 1, "a", &[1u8] as &[u8]),
        (key2, 2, 2, "b", &[2u8] as &[u8]),
    ];
    db.push(&items).await.unwrap();

    // Ensure they exist
    assert!(db.get_latest(key1).await.unwrap().is_some());
    assert!(db.get_latest(key2).await.unwrap().is_some());

    // Delete key1
    let deleted_count = db.delete_keys(&[key1]).await.unwrap();
    assert_eq!(deleted_count, 1);

    // Check key1 is gone, key2 remains
    assert!(db.get_latest(key1).await.unwrap().is_none());
    assert!(db.get_latest(key2).await.unwrap().is_some());

    // Deleting a non-existent key
    let deleted_count_none = db.delete_keys(&[key1 + 1]).await.unwrap();
    assert_eq!(deleted_count_none, 0);

    // Deleting multiple keys
    let key3 = 0x5566778899AABBCCDDEEFF0011223344;
    let items3 = vec![(key3, 3, 3, "c", &[3u8] as &[u8])];
    db.push(&items3).await.unwrap();
    let deleted_count_multi = db.delete_keys(&[key2, key3]).await.unwrap();
    assert_eq!(deleted_count_multi, 2);
    assert!(db.get_latest(key2).await.unwrap().is_none());
    assert!(db.get_latest(key3).await.unwrap().is_none());

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_db_push_identical() {
    let data_dir = setup_test_db_dir("push_identical");
    let config = get_test_config(data_dir.clone());
    let db = Database::open(config).await.unwrap();

    let key = 0x5566778899AABBCCDDEEFF0011223344;
    let name = "identical_func";
    let data = b"some identical data".to_vec();
    let pop = 50;
    let len_bytes = data.len() as u32;

    let items = vec![(key, pop, len_bytes, name, data.as_slice())];

    // First push
    let statuses1 = db.push(&items).await.unwrap();
    assert_eq!(statuses1, vec![1]); // Inserted

    // Second push (identical)
    let statuses2 = db.push(&items).await.unwrap();
    assert_eq!(statuses2, vec![2]); // Unchanged

    // Check history - should only be one entry
    let history = db.get_history(key, 10).await.unwrap();
    assert_eq!(history.len(), 1);

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_db_rejected_push_is_ignored() {
    let data_dir = setup_test_db_dir("rejected_push");
    let config = get_test_config(data_dir.clone());
    let db = Database::open(config).await.unwrap();

    let key = 0x66778899AABBCCDDEEFF001122334455;
    let data = b"generated function data".to_vec();
    let items = vec![(key, 1, data.len() as u32, "sub_140001000", data.as_slice())];

    let statuses = db.push(&items).await.unwrap();
    assert_eq!(statuses, vec![2]);
    assert!(db.get_latest(key).await.unwrap().is_none());
    assert!(db
        .search_functions("sub_140001000", 10)
        .await
        .unwrap()
        .is_empty());

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_rejected_latest_falls_back_to_visible_version() {
    let data_dir = setup_test_db_dir("rejected_latest_fallback");
    let config = get_test_config(data_dir.clone());
    let key = 0x778899AABBCCDDEEFF00112233445566;
    let clean_data = b"clean function data".to_vec();
    let rejected_data = b"generated function data".to_vec();

    let rt = EngineRuntime::open(config.engine.clone(), config.scoring.clone()).unwrap();
    let clean = Record {
        key,
        ts_sec: 1,
        prev_addr: 0,
        len_bytes: clean_data.len() as u32,
        popularity: 10,
        name: "NetworkParser::parse_headers".to_string(),
        data: clean_data.clone(),
        flags: 0,
    };
    let clean_addr = rt.segments.append(&clean).unwrap();
    assert!(rt.index.upsert(key, clean_addr).is_ok());
    let rejected = Record {
        key,
        ts_sec: 2,
        prev_addr: clean_addr,
        len_bytes: rejected_data.len() as u32,
        popularity: 1,
        name: "sub_140001000".to_string(),
        data: rejected_data,
        flags: 0,
    };
    let rejected_addr = rt.segments.append(&rejected).unwrap();
    assert!(rt.index.upsert(key, rejected_addr).is_ok());
    drop(rt);

    // Direct storage writes bypass live projection updates. Rebuild explicitly.
    drop(EngineRuntime::prepare(config.engine.clone(), config.scoring.clone()).unwrap());

    let db = Database::open(config).await.unwrap();
    let latest = db.get_latest(key).await.unwrap().unwrap();
    assert_eq!(latest.name, "NetworkParser::parse_headers");
    assert_eq!(latest.data, clean_data);

    let history = db.get_history(key, 10).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].1, "NetworkParser::parse_headers");

    assert!(db
        .search_functions("sub_140001000", 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(db.search_functions("headers", 10).await.unwrap().len(), 1);

    std::fs::remove_dir_all(&data_dir).unwrap();
}

#[tokio::test]
async fn test_rejected_only_version_is_invisible() {
    let data_dir = setup_test_db_dir("rejected_only_invisible");
    let config = get_test_config(data_dir.clone());
    let key = 0x8899AABBCCDDEEFF0011223344556677;
    let data = b"generated function data".to_vec();

    let rt = EngineRuntime::open(config.engine.clone(), config.scoring.clone()).unwrap();
    let rejected = Record {
        key,
        ts_sec: 1,
        prev_addr: 0,
        len_bytes: data.len() as u32,
        popularity: 1,
        name: "FUN_140001000".to_string(),
        data,
        flags: 0,
    };
    let rejected_addr = rt.segments.append(&rejected).unwrap();
    assert!(rt.index.upsert(key, rejected_addr).is_ok());
    drop(rt);

    let db = Database::open(config).await.unwrap();
    assert!(db.get_latest(key).await.unwrap().is_none());
    assert!(db.get_history(key, 10).await.unwrap().is_empty());
    assert!(db
        .search_functions("FUN_140001000", 10)
        .await
        .unwrap()
        .is_empty());

    std::fs::remove_dir_all(&data_dir).unwrap();
}
