use dazhbog::{
    config::Config,
    db::{Database, PushContext},
    engine::EngineRuntime,
};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn evaluator_keeps_labels_out_of_selection_and_distinguishes_latest() -> io::Result<()> {
    let path = std::env::temp_dir().join(format!("dazhbog-symbol-eval-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    let fixture = Fixture(path);
    let mut cfg = Config::default();
    cfg.engine.data_dir = fixture.0.join("data").to_string_lossy().into_owned();
    {
        let db = Database::open_for_replay(Arc::new(cfg.clone())).await?;
        let mut ctx = PushContext {
            md5: Some([1; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        };
        db.push_with_ctx(
            &[
                (1, 1, 16, "parse_packet", &[]),
                (2, 1, 16, "encrypt_packet", &[]),
            ],
            &ctx,
        )
        .await?;
        ctx.md5 = Some([2; 16]);
        db.push_with_ctx(&[(1, 1, 16, "unrelated_decoder", &[])], &ctx)
            .await?;
        db.flush()?;
    }
    let config_path = fixture.0.join("config.toml");
    std::fs::write(
        &config_path,
        format!("engine.data_dir = {:?}\n", cfg.engine.data_dir),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_eval-symbol-labels"))
        .arg(&config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    for (key, name) in [(1, "parse_packet"), (2, "encrypt_packet")] {
        let row = serde_json::json!({
            "case_id":format!("{}:{key:032x}", "01".repeat(16)), "key":format!("{key:032x}"),
            "family":"synthetic_fixture", "partition":"test", "binary_md5":"01".repeat(16),
            "binary_sha256":"0".repeat(64), "fixture_sha256":"1".repeat(64), "address":"0x100", "size_bytes":"16",
            "expected_names":[name], "provenance":{"binary":"fixture.elf", "fixture_database":"fixture.sqlite3", "labels":"test oracle", "keys":"test keys"}
        });
        writeln!(stdin, "{row}")?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let modes = &rows.last().unwrap()["modes"];
    assert_eq!(
        modes["test/explicit_binary"],
        serde_json::json!({"cases":2,"available":2,"exact_name":2})
    );
    assert_eq!(
        modes["test/latest"],
        serde_json::json!({"cases":2,"available":2,"exact_name":1})
    );
    let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
    assert_eq!(rt.segments.get_record_count()?, 3);
    assert_eq!(rt.search.doc_count(), 2);
    Ok(())
}
