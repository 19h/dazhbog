use dazhbog::config::Config;
use dazhbog::db::{Database, PushContext};
use dazhbog::engine::{SearchDocument, SearchIndex};
use dazhbog::protocol::lumina::MdKey;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("dazhbog_{label}_{nanos}"))
}

fn doc(
    key: u128,
    func_name: &str,
    prototype_tokens: &[&str],
    frame_tokens: &[&str],
    comment_tokens: &[&str],
    operand_tokens: &[&str],
    semantic_tokens: &[&str],
) -> SearchDocument {
    SearchDocument {
        key,
        func_name: func_name.to_string(),
        func_name_demangled: String::new(),
        lang: String::new(),
        binary_names: Vec::new(),
        origin_tokens: Vec::new(),
        prototype_tokens: prototype_tokens.iter().map(|s| s.to_string()).collect(),
        frame_tokens: frame_tokens.iter().map(|s| s.to_string()).collect(),
        comment_tokens: comment_tokens.iter().map(|s| s.to_string()).collect(),
        operand_tokens: operand_tokens.iter().map(|s| s.to_string()).collect(),
        semantic_tokens: semantic_tokens.iter().map(|s| s.to_string()).collect(),
        ts: 1,
    }
}

fn metadata_blob(cmt: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MdKey::Type.raw().to_le_bytes());
    out.extend_from_slice(&(5u32).to_le_bytes());
    out.extend_from_slice(&[1, b'i', b'n', b't', 0]);
    out.extend_from_slice(&MdKey::Fcmt.raw().to_le_bytes());
    out.extend_from_slice(&((cmt.len() + 1) as u32).to_le_bytes());
    out.extend_from_slice(cmt.as_bytes());
    out.push(0);
    out
}

#[test]
fn semantic_neighbor_search_prefers_related_functions() -> io::Result<()> {
    let dir = temp_dir("semantic_neighbors");
    let result = (|| -> io::Result<()> {
        let index = SearchIndex::open(&dir)?;
        let seed = doc(
            1,
            "parse_http_headers",
            &["http_request", "header_parser"],
            &["header_count"],
            &["parse_headers", "http_request"],
            &[],
            &["http", "request", "headers", "parser", "content_length"],
        );
        let related = doc(
            2,
            "decode_http_request_headers",
            &["http_request", "decode_headers"],
            &["header_index"],
            &["request_headers"],
            &[],
            &["http", "request", "headers", "decode", "parser"],
        );
        let unrelated = doc(
            3,
            "objc_selector_dispatch",
            &["objc_selector"],
            &["dispatch_slot"],
            &["retain_autorelease"],
            &["objc_msgsend"],
            &["objc", "selector", "dispatch", "retain", "autorelease"],
        );

        index.index_function_no_commit(&seed)?;
        index.index_function_no_commit(&related)?;
        index.index_function_no_commit(&unrelated)?;
        index.commit()?;

        let hits = index.semantic_neighbors(&seed, seed.key, 4)?;
        assert!(!hits.is_empty());
        assert_eq!(hits[0].key_hex, format!("{:032x}", related.key));
        assert!(hits
            .iter()
            .all(|hit| hit.key_hex != format!("{:032x}", seed.key)));
        Ok(())
    })();

    let _ = fs::remove_dir_all(&dir);
    result
}

#[tokio::test]
async fn semantic_neighbors_prefer_same_family_candidates() -> io::Result<()> {
    let dir = temp_dir("semantic_neighbors_db");
    let result = async {
        let mut cfg = Config {
            http: None,
            ..Default::default()
        };
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        let db = Database::open(Arc::new(cfg)).await?;

        let seed_key = 0x11u128;
        let same_family_key = 0x22u128;
        let cross_family_key = 0x33u128;
        let md5_seed = [0x11u8; 16];
        let md5_cross = [0x22u8; 16];

        let seed_blob = metadata_blob("parse http request headers and content length");
        let same_family_blob = metadata_blob("decode http request headers and body length");
        let cross_family_blob = metadata_blob("decode http request headers and body length");

        db.push_with_ctx(
            &[(
                seed_key,
                1,
                seed_blob.len() as u32,
                "parse_http_headers",
                &seed_blob,
            )],
            &PushContext {
                md5: Some(md5_seed),
                basename: Some("router-http.bin"),
                hostname: Some("ci-router"),
                origin_token: Some("router_http"),
            },
        )
        .await?;

        db.push_with_ctx(
            &[(
                same_family_key,
                1,
                same_family_blob.len() as u32,
                "decode_http_headers",
                &same_family_blob,
            )],
            &PushContext {
                md5: Some(md5_seed),
                basename: Some("router-http.bin"),
                hostname: Some("ci-router"),
                origin_token: Some("router_http"),
            },
        )
        .await?;

        db.push_with_ctx(
            &[(
                cross_family_key,
                1,
                cross_family_blob.len() as u32,
                "decode_http_headers_alt",
                &cross_family_blob,
            )],
            &PushContext {
                md5: Some(md5_cross),
                basename: Some("objc-ui.bin"),
                hostname: Some("ci-objc"),
                origin_token: Some("objc_ui"),
            },
        )
        .await?;

        let hits = db.semantic_neighbors_for_key(seed_key, 4, false).await?;
        assert!(!hits.is_empty());
        assert_eq!(hits[0].key_hex, format!("{:032x}", same_family_key));
        let rationale = hits[0]
            .semantic_neighbor
            .as_ref()
            .expect("neighbor rationale");
        assert!(rationale.family_score > 0.0);
        assert!(rationale.direct_binary_score > 0.0);

        let strict_hits = db.semantic_neighbors_for_key(seed_key, 4, true).await?;
        assert!(!strict_hits.is_empty());
        assert!(strict_hits
            .iter()
            .all(|hit| hit.key_hex != format!("{:032x}", cross_family_key)));
        Ok(())
    }
    .await;

    let _ = fs::remove_dir_all(&dir);
    result
}
