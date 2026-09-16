use dazhbog::common::{
    addr_off,
    hash::{legacy_version_id, version_id},
};
use dazhbog::config::Config;
use dazhbog::engine::{EngineRuntime, Record};
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "dazhbog-physical-audit-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn config(&self) -> Config {
        let mut config = Config::default();
        config.engine.data_dir = self.0.to_string_lossy().into_owned();
        config
    }

    fn run(&self, key: u128, expected: [u8; 32], limit: usize) -> serde_json::Value {
        let config = self.0.join("audit.toml");
        std::fs::write(
            &config,
            format!("engine.data_dir = \"{}\"\n", self.0.display()),
        )
        .unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_storage-audit"))
            .arg(config)
            .args([
                "--key",
                &format!("{key:x}"),
                &expected
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                "--physical",
                &limit.to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record(key: u128, name: &str) -> Record {
    Record {
        key,
        ts_sec: 1,
        prev_addr: 0,
        len_bytes: 3,
        popularity: 1,
        name: name.into(),
        data: vec![42, 1, 7],
        flags: 0,
    }
}

#[test]
fn physical_audit_distinguishes_orphans_and_deleted_records_without_restoring_them() {
    let fixture = Fixture::new("history");
    let orphan = record(1, &format!("parse_{}", "λ".repeat(300)));
    let deleted = record(2, "parse_deleted");
    let rejected = record(3, "sub_1234");
    let live = Record {
        flags: dazhbog::engine::REC_FLAG_DECLARED_SIZE,
        ..record(4, "parse_live")
    };
    let mut snapshots = Vec::new();
    {
        let config = fixture.config();
        let rt = EngineRuntime::open(config.engine, config.scoring).unwrap();
        rt.segments.append(&orphan).unwrap();
        let head = rt.segments.append(&record(1, "parse_current")).unwrap();
        assert!(rt.index.upsert(1, head).is_ok());
        let old = rt.segments.append(&deleted).unwrap();
        let tombstone = Record {
            flags: 1,
            prev_addr: old,
            name: String::new(),
            ..deleted.clone()
        };
        assert!(rt
            .index
            .upsert(2, rt.segments.append(&tombstone).unwrap())
            .is_ok());
        rt.segments.append(&rejected).unwrap();
        assert!(rt
            .index
            .upsert(4, rt.segments.append(&live).unwrap())
            .is_ok());
        for key in [1, 2, 3, 4] {
            snapshots.push((key, rt.index.try_get(key).unwrap()));
        }
        rt.flush().unwrap();
    }
    for expected in [
        version_id(1, &orphan.name, &orphan.data),
        legacy_version_id(1, &orphan.name, &orphan.data),
    ] {
        let report = fixture.run(1, expected, 100);
        assert_eq!(report["expected_found"], false);
        assert_eq!(report["physical_scan"]["expected_matches"], 1);
        assert_eq!(
            report["physical_scan"]["outside_inspected_history_matches"],
            1
        );
        assert_eq!(report["physical_scan"]["valid_matching_records"], 2);
        assert_eq!(report["physical_scan"]["rows_scanned"], 6);
        assert_eq!(report["physical_scan"]["truncated"], false);
        assert_eq!(
            report["physical_scan"]["records"][0]["name_truncated"],
            true
        );
        assert_eq!(
            report["physical_scan"]["records"][0]["name"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            256
        );
    }
    let report = fixture.run(2, version_id(2, &deleted.name, &deleted.data), 100);
    assert_eq!(report["stop_reason"], "tombstone");
    assert_eq!(
        report["physical_scan"]["outside_inspected_history_matches"],
        1
    );
    let report = fixture.run(3, version_id(3, &rejected.name, &rejected.data), 100);
    assert_eq!(report["stop_reason"], "missing_index_entry");
    assert_eq!(report["physical_scan"]["records"][0]["rejected_name"], true);
    let report = fixture.run(4, version_id(4, &live.name, &live.data), 6);
    assert_eq!(report["expected_live"], true);
    assert_eq!(
        report["physical_scan"]["outside_inspected_history_matches"],
        0
    );
    assert_eq!(report["physical_scan"]["truncated"], false);
    let limited = fixture.run(4, version_id(4, &live.name, &live.data), 1);
    assert_eq!(limited["physical_scan"]["rows_scanned"], 1);
    assert_eq!(limited["physical_scan"]["expected_matches"], 0);
    assert_eq!(limited["physical_scan"]["truncated"], true);
    let config = fixture.config();
    let rt = EngineRuntime::open(config.engine, config.scoring).unwrap();
    for (key, address) in snapshots {
        assert_eq!(rt.index.try_get(key).unwrap(), address);
    }
    assert_eq!(rt.segments.get_record_count().unwrap(), 6);
}

#[test]
fn physical_audit_counts_invalid_rows_and_bounds_examples() {
    let fixture = Fixture::new("bounds");
    let candidate = record(1, "parse_packet");
    {
        let config = fixture.config();
        let rt = EngineRuntime::open(config.engine, config.scoring).unwrap();
        for _ in 0..66 {
            rt.segments.append(&candidate).unwrap();
        }
        let damaged = rt.segments.append(&candidate).unwrap();
        let tree = rt.segments.sled_db().open_tree("seg.00001").unwrap();
        let key = addr_off(damaged).to_be_bytes();
        let mut bytes = tree.get(key).unwrap().unwrap().to_vec();
        tree.insert(((1u64 << 40) - 1).to_be_bytes(), bytes.clone())
            .unwrap();
        tree.insert((1u64 << 40).to_be_bytes(), bytes.clone())
            .unwrap();
        bytes[8] ^= 1;
        tree.insert(key, bytes).unwrap();
        tree.insert(b"\0", b"bad offset").unwrap();
        tree.insert(1u64.to_be_bytes(), b"short").unwrap();
        rt.flush().unwrap();
    }
    let report = fixture.run(1, version_id(1, &candidate.name, &candidate.data), 100);
    let scan = &report["physical_scan"];
    assert_eq!(scan["rows_scanned"], 71);
    assert_eq!(scan["expected_matches"], 67);
    assert_eq!(scan["valid_matching_records"], 67);
    assert_eq!(scan["invalid_offsets"], 2);
    assert_eq!(scan["short_rows"], 1);
    assert_eq!(scan["invalid_matching_rows"], 1);
    assert_eq!(scan["records"].as_array().unwrap().len(), 64);
    assert_eq!(scan["examples_truncated"], true);
    assert_eq!(scan["snapshot_consistent"], false);
    assert_eq!(scan["nonmatching_records_validated"], false);
    let report = fixture.run(1, version_id(1, &candidate.name, &candidate.data), 1);
    assert_eq!(report["physical_scan"]["invalid_offsets"], 1);
    assert_eq!(report["physical_scan"]["rows_scanned"], 1);
    assert_eq!(report["physical_scan"]["truncated"], true);
}

#[test]
fn physical_audit_rejects_invalid_bounds_before_opening_storage() {
    for suffix in [
        vec!["--physical"],
        vec!["--physical", "0"],
        vec!["--physical", "100000001"],
        vec!["--physical", "-1"],
        vec!["--physical", "1", "extra"],
        vec!["--unknown"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_storage-audit"))
            .args(["nonexistent-config", "--key", "1", &"0".repeat(64)])
            .args(suffix)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("No such file"));
    }
}
