use dazhbog::config::Config;
use dazhbog::db::{Database, PushContext};
use dazhbog::engine::{SearchDocument, SearchIndex};
use dazhbog::protocol::lumina::{pack_dd, parse_metadata, MdKey};
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
    let mut out = pack_dd(MdKey::Fcmt.raw());
    out.extend(pack_dd((cmt.len() + 1) as u32));
    out.extend_from_slice(cmt.as_bytes());
    out.push(0);
    let parsed = parse_metadata(&out);
    assert!(parsed.errors.is_empty());
    assert_eq!(parsed.bytes_parsed, out.len());
    assert_eq!(parsed.fcmt.as_deref(), Some(cmt));
    out
}

#[test]
fn compound_metadata_terms_match_indexed_positions_without_fallback() -> io::Result<()> {
    for field in 0..6 {
        let dir = temp_dir("compound_neighbor_terms");
        let result = (|| -> io::Result<()> {
            let index = SearchIndex::open(&dir)?;
            let empty = |key| doc(key, "distinct", &[], &[], &[], &[], &[]);
            let set = |doc: &mut SearchDocument, terms: &[&str]| {
                let values = terms.iter().map(|s| s.to_string()).collect();
                match field {
                    0 => doc.prototype_tokens = values,
                    1 => doc.frame_tokens = values,
                    2 => doc.comment_tokens = values,
                    3 => doc.operand_tokens = values,
                    4 => doc.origin_tokens = values,
                    _ => doc.semantic_tokens = values,
                }
            };
            let mut seed = empty(1);
            set(&mut seed, &["packet_state", "sentinel"]);
            let cases: &[(u128, &[&str])] = &[
                (2, &["packet_state"]),
                // Guarantees a primary hit, disabling the old fallback which
                // otherwise hides the compound-term mismatch.
                (3, &["sentinel"]),
                (4, &["packet", "state"]),
                (5, &["state_packet"]),
                (6, &["packet_other_state"]),
                (7, &["PACKET_STATE"]),
                (8, &["packet"]),
            ];
            for &(key, terms) in cases {
                let mut candidate = empty(key);
                set(&mut candidate, terms);
                index.index_function_no_commit(&candidate)?;
            }
            index.index_function_no_commit(&seed)?;
            index.commit()?;
            drop(index);
            let index = SearchIndex::open(&dir)?;
            let mut keys: Vec<_> = index
                .semantic_neighbors(&seed, 1, 16)?
                .into_iter()
                .map(|hit| u128::from_str_radix(&hit.key_hex, 16).unwrap())
                .collect();
            keys.sort();
            assert_eq!(keys, vec![2, 3, 7], "metadata field {field}");
            let baseline = index.semantic_neighbors(&seed, 1, 16)?;
            set(&mut seed, &["packet_state", "PACKET_STATE", "sentinel"]);
            let duplicate = index.semantic_neighbors(&seed, 1, 16)?;
            assert_eq!(
                baseline
                    .iter()
                    .map(|hit| (&hit.key_hex, hit.score))
                    .collect::<Vec<_>>(),
                duplicate
                    .iter()
                    .map(|hit| (&hit.key_hex, hit.score))
                    .collect::<Vec<_>>()
            );
            Ok(())
        })();
        fs::remove_dir_all(&dir)?;
        result?;
    }
    Ok(())
}

#[test]
fn compound_query_expansion_is_bounded_without_prefix_matches() -> io::Result<()> {
    let dir = temp_dir("compound_neighbor_bounds");
    let result = (|| -> io::Result<()> {
        let index = SearchIndex::open(&dir)?;
        for count in [64, 65] {
            let compound = (0..count)
                .map(|i| format!("segment{i}"))
                .collect::<Vec<_>>()
                .join("_");
            let seed = doc(1, "alpha", &[], &[], &[], &[], &[&compound, "sentinel"]);
            let candidate = doc(2, "bravo", &[], &[], &[], &[], &[&compound]);
            let distractor = doc(3, "charlie", &[], &[], &[], &[], &["sentinel"]);
            index.index_function_no_commit(&candidate)?;
            index.index_function_no_commit(&distractor)?;
            index.commit()?;
            let hits = index.semantic_neighbors(&seed, 1, 8)?;
            assert!(hits.iter().any(|hit| hit.key_hex == format!("{:032x}", 3)));
            assert_eq!(
                hits.iter().any(|hit| hit.key_hex == format!("{:032x}", 2)),
                count == 64
            );
        }
        Ok(())
    })();
    fs::remove_dir_all(&dir)?;
    result
}

#[tokio::test]
async fn parsed_compound_comment_reaches_contextual_neighbor_reranking() -> io::Result<()> {
    let dir = temp_dir("compound_neighbor_context");
    let result = async {
        let mut cfg = Config {
            http: None,
            ..Default::default()
        };
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        let db = Database::open_for_replay(Arc::new(cfg)).await?;
        let binary = [0x55; 16];
        let ctx = PushContext {
            md5: Some(binary),
            basename: Some("packets.bin"),
            hostname: None,
            origin_token: None,
        };
        for (key, name, comment) in [
            (1, "alpha", "packet_state sentinel"),
            (2, "bravo", "packet_state"),
            (3, "charlie", "sentinel"),
        ] {
            let data = metadata_blob(comment);
            db.push_with_ctx(&[(key, 1, data.len() as u32, name, &data)], &ctx)
                .await?;
        }
        for identity in [None, Some(binary)] {
            let (candidates, hits) = db
                .semantic_neighbors_in_context(1, 8, true, 96, identity)
                .await?;
            assert!(candidates.contains(&2));
            let neighbor = hits
                .iter()
                .find(|hit| hit.key_hex == format!("{:032x}", 2))
                .unwrap();
            let rationale = neighbor.semantic_neighbor.as_ref().unwrap();
            assert!(rationale
                .shared_comment_tokens
                .iter()
                .any(|token| token == "packet_state"));
            assert!(rationale.direct_binary_score > 0.0);
        }
        Ok(())
    }
    .await;
    fs::remove_dir_all(&dir)?;
    result
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
async fn explicit_neighbor_family_is_not_limited_to_eight_references() -> io::Result<()> {
    let dir = temp_dir("neighbor_membership_prefix");
    let result = async {
        let mut cfg = Config {
            http: None,
            ..Default::default()
        };
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        // Replay opening avoids attaching this fixture's index to global metrics,
        // so dropping the database releases it before the CLI subprocess opens it.
        let db = Database::open_for_replay(Arc::new(cfg)).await?;
        let target = [0xff; 16];
        let blob = metadata_blob("decode orchid archive directory headers");
        let seed = (
            1,
            1,
            blob.len() as u32,
            "read_orchid_directory",
            blob.as_slice(),
        );
        let neighbor = (
            2,
            1,
            blob.len() as u32,
            "decode_orchid_directory",
            blob.as_slice(),
        );
        let anchor = (3, 1, 0, "open_orchid_archive", &[][..]);
        let context = |md5| PushContext {
            md5: Some(md5),
            basename: Some("orchid.bin"),
            hostname: None,
            origin_token: None,
        };
        db.push_with_ctx(&[seed, neighbor, anchor], &context(target))
            .await?;
        // Twelve closer siblings fill related-family discovery with two shared
        // keys each. They do not contain the neighbor being tested.
        for n in 20..32 {
            db.push_with_ctx(&[seed, anchor], &context([n; 16])).await?;
        }
        // These eight binaries contain only the neighbor. Their MD5s precede
        // the target, so the presentation prefix hides its direct membership.
        for n in 1..=8 {
            db.push_with_ctx(&[neighbor], &context([n; 16])).await?;
        }
        let refs = db.get_binary_refs_for_key(2, 8)?;
        assert_eq!(refs.len(), 8);
        assert!(refs.iter().all(|r| r.md5_hex != "ff".repeat(16)));
        let overlap = db.get_binary_overlap(target, 12).await?;
        assert_eq!(overlap.len(), 12);
        assert!(overlap.iter().all(|(_, shared)| *shared == 2));
        let (candidates, hits) = db
            .semantic_neighbors_in_context(1, 12, true, 96, Some(target))
            .await?;
        assert!(
            candidates.contains(&2),
            "the search stage must retrieve the neighbor"
        );
        let hit = hits
            .iter()
            .find(|h| h.key_hex == format!("{:032x}", 2))
            .expect("direct-family neighbor survives strict filtering");
        let rationale = hit.semantic_neighbor.as_ref().unwrap();
        assert!(rationale.direct_binary_score > 0.0);
        assert!(rationale
            .direct_family_binaries
            .iter()
            .any(|b| b.md5_hex == "ff".repeat(16)));
        // A different seed binary reaches the target through two shared bridge
        // keys. The neighbor belongs to the related binary, not the seed binary.
        let related_seed = (
            4,
            1,
            blob.len() as u32,
            "scan_orchid_directory",
            blob.as_slice(),
        );
        let bridge = (5, 1, 0, "close_orchid_archive", &[][..]);
        db.push_with_ctx(&[bridge], &context(target)).await?;
        db.push_with_ctx(&[related_seed, anchor, bridge], &context([0xfe; 16]))
            .await?;
        let (_, related_hits) = db
            .semantic_neighbors_in_context(4, 12, true, 96, None)
            .await?;
        let related_hit = related_hits
            .iter()
            .find(|h| h.key_hex == format!("{:032x}", 2))
            .expect("related family beyond the presentation prefix");
        let related_rationale = related_hit.semantic_neighbor.as_ref().unwrap();
        assert_eq!(related_rationale.direct_binary_score, 0.0);
        assert!(related_rationale.related_binary_score > 0.0);
        assert!(related_rationale
            .related_family_binaries
            .iter()
            .any(|b| b.md5_hex == "ff".repeat(16)));

        // A matching basename and lexical annotation do not establish membership.
        let isolated = (
            6,
            1,
            blob.len() as u32,
            "inspect_orchid_directory",
            blob.as_slice(),
        );
        db.push_with_ctx(&[isolated], &context([0xfd; 16])).await?;
        let (isolated_candidates, isolated_hits) = db
            .semantic_neighbors_in_context(6, 12, true, 96, Some([0xfd; 16]))
            .await?;
        assert!(isolated_candidates.contains(&2));
        assert!(isolated_hits.is_empty());
        let (_, loose_hits) = db
            .semantic_neighbors_in_context(6, 12, false, 96, Some([0xfd; 16]))
            .await?;
        let loose = loose_hits
            .iter()
            .find(|h| h.key_hex == format!("{:032x}", 2))
            .unwrap();
        assert_eq!(loose.semantic_neighbor.as_ref().unwrap().family_score, 0.0);
        db.flush()?;
        drop(db);

        // Exercise the real evaluation CLI with the same context and strictness.
        let config = dir.join("evaluation.toml");
        fs::write(
            &config,
            format!("engine.data_dir = \"{}\"\n", dir.display()),
        )?;
        let labels = dir.join("labels.jsonl");
        let cases = [
            ("direct", 1, 0xffu8),
            ("related", 1, 0xfe),
            ("isolated", 1, 0xfd),
        ];
        // The identical seed key must produce different strict-family results
        // under different IDs; ignoring binary_md5 cannot satisfy these checks.
        let rows: Vec<_> = cases
            .iter()
            .map(|(id, key, byte)| {
                serde_json::json!({
                    "case_id":id, "family":"synthetic-orchid", "partition":"test",
                    "provenance":"controlled membership fixture", "key":format!("{key:032x}"),
                    "binary_md5":format!("{byte:02x}").repeat(16), "strict_family":true,
                    "judgments":[{"key":format!("{:032x}", 2), "relevant":*id != "isolated"}]
                })
                .to_string()
            })
            .collect();
        fs::write(&labels, rows.join("\n"))?;
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_eval-neighbors"))
            .arg(config)
            .arg(labels)
            .arg("12")
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reports: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(reports.len(), 9);
        for report in reports {
            assert_eq!(report["strict_family"], true);
            assert!(report["binary_md5"].as_str().is_some());
            assert!(report["candidate_keys"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(format!("{:032x}", 2))));
            let found = report["returned_keys"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(format!("{:032x}", 2)));
            assert_eq!(found, report["case_id"] != "isolated");
        }
        Ok(())
    }
    .await;
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
