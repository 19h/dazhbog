use dazhbog::engine::ContextIndex;
use std::io;
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "dazhbog-binary-aliases-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn binary_alias_discovery_is_not_limited_to_255_builds() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let ctx = ContextIndex::open_or_create(&fixture.0)?;
    for build in 0..260u128 {
        ctx.record_binary_meta(build.to_be_bytes(), "shared-module.so", "", "", 1)?;
    }
    let matches = ctx.search_binary_meta("SHARED-module")?;
    assert_eq!(matches.len(), 260);
    let ids: std::collections::HashSet<_> = matches.iter().map(|meta| meta.md5).collect();
    assert_eq!(ids.len(), 260);
    ctx.flush()?;
    drop(ctx);
    let ctx = ContextIndex::open_ready(&fixture.0)?;
    assert_eq!(ctx.search_binary_meta("shared-module.so")?.len(), 260);
    drop(ctx);
    // Simulate the old dump: primary metadata still has all 260 builds, but the
    // legacy name list retained only 255. Opening does not scan to rebuild it.
    let legacy = {
        let mut bytes = vec![255];
        for build in 0..255u128 {
            bytes.extend(build.to_be_bytes());
        }
        bytes
    };
    {
        let raw = sled::open(fixture.0.join("context_db"))?;
        raw.drop_tree("binary_name_memberships_v1")?;
        raw.open_tree("binary_name_index")?
            .insert(b"shared-module.so", legacy.clone())?;
        raw.flush()?;
    }
    let ctx = ContextIndex::open_ready(&fixture.0)?;
    assert_eq!(ctx.search_binary_meta("shared-module.so")?.len(), 255);
    drop(ctx);
    {
        let raw = sled::open(fixture.0.join("context_db"))?;
        assert!(raw.open_tree("binary_name_memberships_v1")?.is_empty());
    }
    // Explicit preparation recovers primary names from metadata, preserving the
    // old list for compatibility. It cannot invent already-lost secondary aliases.
    let ctx = ContextIndex::open_or_create(&fixture.0)?;
    assert_eq!(ctx.search_binary_meta("shared-module.so")?.len(), 260);
    ctx.flush()?;
    drop(ctx);
    let raw = sled::open(fixture.0.join("context_db"))?;
    assert_eq!(
        raw.open_tree("binary_name_index")?
            .get(b"shared-module.so")?
            .unwrap()
            .as_ref(),
        legacy
    );
    assert_eq!(raw.open_tree("binary_name_memberships_v1")?.len(), 260);
    Ok(())
}

#[test]
fn old_secondary_aliases_merge_with_new_postings_without_startup_conversion() -> io::Result<()> {
    let fixture = Fixture::new()?;
    {
        let ctx = ContextIndex::open_or_create(&fixture.0)?;
        for binary in 1..=3u8 {
            ctx.record_binary_meta([binary; 16], "primary", "", "", 1)?;
        }
        ctx.flush()?;
    }
    // Legacy count + IDs, including a duplicate and historical trailing bytes.
    let legacy = [&[3][..], &[1; 16], &[2; 16], &[1; 16], &[99]].concat();
    {
        let raw = sled::open(fixture.0.join("context_db"))?;
        raw.drop_tree("binary_name_memberships_v1")?;
        raw.open_tree("binary_name_index")?
            .insert(b"secondary", legacy.clone())?;
        raw.flush()?;
    }
    let ctx = ContextIndex::open_ready(&fixture.0)?;
    assert_eq!(ctx.search_binary_meta("secondary")?.len(), 2);
    for binary in [2, 3] {
        ctx.record_binary_meta([binary; 16], "C:\\build\\SECONDARY", "", "", 2)?;
    }
    assert_eq!(ctx.search_binary_meta("/tmp/secondary")?.len(), 3);
    ctx.flush()?;
    drop(ctx);
    {
        let raw = sled::open(fixture.0.join("context_db"))?;
        assert_eq!(raw.open_tree("binary_name_memberships_v1")?.len(), 2);
        assert_eq!(
            raw.open_tree("binary_name_index")?
                .get(b"secondary")?
                .unwrap()
                .as_ref(),
            legacy
        );
    }
    assert_eq!(
        ContextIndex::open_ready(&fixture.0)?
            .search_binary_meta("secondary")?
            .len(),
        3
    );
    Ok(())
}

#[test]
fn alias_lookup_skips_missing_metadata_and_rejects_foreign_identity() -> io::Result<()> {
    let fixture = Fixture::new()?;
    {
        let ctx = ContextIndex::open_or_create(&fixture.0)?;
        ctx.record_binary_meta([1; 16], "primary", "", "", 1)?;
        ctx.flush()?;
    }
    {
        let raw = sled::open(fixture.0.join("context_db"))?;
        raw.open_tree("binary_name_memberships_v1")?
            .insert([b"primary\0".as_slice(), &[9; 16]].concat(), &[])?;
        raw.flush()?;
    }
    {
        let ctx = ContextIndex::open_ready(&fixture.0)?;
        assert_eq!(ctx.search_binary_meta("primary")?.len(), 1);
    }
    {
        let raw = sled::open(fixture.0.join("context_db"))?;
        let metadata = raw.open_tree("binary_meta")?;
        let mut row = metadata.get([1; 16])?.unwrap().to_vec();
        row[..16].copy_from_slice(&[2; 16]);
        metadata.insert([1; 16], row)?;
        raw.flush()?;
    }
    let ctx = ContextIndex::open_ready(&fixture.0)?;
    assert_eq!(
        ctx.search_binary_meta("primary").unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    Ok(())
}

#[test]
fn unicode_alias_truncation_preserves_utf8_at_the_byte_limit() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let ctx = ContextIndex::open_or_create(&fixture.0)?;
    let prefix = "é".repeat(127);
    let long = format!("{prefix}€suffix");
    ctx.record_binary_meta([1; 16], &long, "", "", 1)?;
    let meta = ctx.get_binary_meta(&[1; 16])?.unwrap();
    assert_eq!(meta.basename, prefix);
    assert_eq!(meta.basename.len(), 254);
    assert_eq!(ctx.search_binary_meta(&long)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn binary_search_pages_deduplicate_aliases_and_break_ties_by_identity() -> io::Result<()> {
    use dazhbog::{config::Config, db::Database, engine::EngineRuntime};
    use std::sync::Arc;
    let fixture = Fixture::new()?;
    let mut config = Config::default();
    config.engine.data_dir = fixture.0.to_string_lossy().into_owned();
    {
        let rt = EngineRuntime::open(config.engine.clone(), config.scoring.clone())?;
        for id in [2u128, 0, 1] {
            for alias in ["original", "secondary", "prefix-secondary-suffix"] {
                rt.ctx_index
                    .record_binary_meta(id.to_be_bytes(), alias, "", "", 1)?;
            }
        }
        rt.ctx_index
            .record_binary_meta(9u128.to_be_bytes(), "secondary-extension", "", "", 1)?;
        rt.flush()?;
    }
    drop(EngineRuntime::prepare(
        config.engine.clone(),
        config.scoring.clone(),
    )?);
    let db = Database::open(Arc::new(config)).await?;
    for query in ["secondary", "C:\\build\\SECONDARY"] {
        for page in 0..4 {
            let (rows, total) = db.search_binaries_paginated(query, page, 1).await?;
            assert_eq!(total, 4);
            assert_eq!(rows.len(), 1);
            let expected = if page == 3 { 9 } else { page };
            assert_eq!(rows[0].md5_hex, format!("{expected:032x}"));
        }
    }
    let (rows, total) = db.search_binaries_paginated("secondary", 4, 1).await?;
    assert!(rows.is_empty());
    assert_eq!(total, 4);
    Ok(())
}

#[test]
fn concurrent_secondary_aliases_preserve_every_binary() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let ctx = ContextIndex::open_or_create(&fixture.0)?;
    for binary in 0..16u8 {
        ctx.record_binary_meta([binary; 16], &format!("original-{binary}"), "", "", 1)?;
    }
    let start = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for binary in 0..16u8 {
            let ctx = &ctx;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                ctx.record_binary_meta([binary; 16], "secondary-alias", "", "", 2)
                    .unwrap();
            });
        }
    });
    assert_eq!(ctx.search_binary_meta("secondary-alias")?.len(), 16);
    for binary in 0..16u8 {
        assert_eq!(
            ctx.get_binary_meta(&[binary; 16])?.unwrap().basename,
            format!("original-{binary}")
        );
    }
    ctx.flush()?;
    drop(ctx);
    assert_eq!(
        ContextIndex::open_ready(&fixture.0)?
            .search_binary_meta("secondary-alias")?
            .len(),
        16
    );
    Ok(())
}
