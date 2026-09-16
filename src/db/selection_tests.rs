use super::*;

#[test]
fn binary_context_completion_is_bounded_and_disabled_for_holdout() -> io::Result<()> {
    let dir =
        std::env::temp_dir().join(format!("dazhbog-context-completion-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let result = (|| -> io::Result<()> {
        let mut cfg = Config::default();
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
        for key in 1..=129 {
            rt.ctx_index
                .record_key_observation(key, [1; 16], None, 1, None)?;
        }
        let mut ctx = QueryContext {
            keys: &[999],
            requested_mdkeys: &[],
            md5: Some([1; 16]),
            basename: None,
            hostname: None,
            origin_token: None,
        };
        let (keys, completed) = complete_binary_context(&rt, &ctx, None, false)?;
        assert!(completed);
        assert_eq!(keys.len(), 129);
        assert_eq!(keys[0], 999);
        assert!(!keys.contains(&129));
        assert_eq!(
            keys.iter().copied().collect::<HashSet<_>>().len(),
            keys.len()
        );
        for stale in [false, true] {
            let (keys, completed) = complete_binary_context(&rt, &ctx, Some([1; 16]), stale)?;
            assert_eq!(&*keys, &[999]);
            assert!(!completed);
        }
        ctx.keys = &[1];
        assert!(matches!(
            complete_binary_context(&rt, &ctx, None, false)?,
            (std::borrow::Cow::Borrowed(_), false)
        ));
        let (keys, completed) = complete_binary_context(&rt, &ctx, None, true)?;
        assert!(completed);
        assert_eq!(keys.len(), 128);
        assert!(!keys.contains(&129));
        ctx.keys = &[];
        assert!(complete_binary_context(&rt, &ctx, None, true)?.0.is_empty());
        ctx.keys = &[999];
        ctx.md5 = None;
        assert!(matches!(
            complete_binary_context(&rt, &ctx, None, true)?,
            (std::borrow::Cow::Borrowed(_), false)
        ));
        ctx.md5 = Some([9; 16]);
        assert_eq!(&*complete_binary_context(&rt, &ctx, None, false)?.0, &[999]);
        rt.flush()?;
        drop(rt);
        {
            let raw = sled::open(dir.join("context_db"))?;
            let tree = raw.open_tree("key_md5")?;
            let key = [1u128.to_le_bytes().as_slice(), &[1; 16]].concat();
            let mut value = tree.get(&key)?.unwrap().to_vec();
            value[..4].copy_from_slice(&0u32.to_le_bytes());
            tree.insert(key, value)?;
            raw.flush()?;
        }
        let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
        ctx.md5 = Some([1; 16]);
        let (keys, completed) = complete_binary_context(&rt, &ctx, None, false)?;
        assert!(completed);
        assert_eq!(keys.len(), 128);
        assert!(!keys.contains(&1));
        // Rejected placeholders consume the physical enumeration budget.
        assert!(!keys.contains(&129));
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}

#[test]
fn head_probe_counts_rejected_physical_records_and_keeps_analysis_lazy() -> io::Result<()> {
    let dir = std::env::temp_dir().join(format!("dazhbog-head-probe-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let result = (|| -> io::Result<()> {
        let mut cfg = Config::default();
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
        let mut rec = Record {
            key: 1,
            ts_sec: 1,
            prev_addr: 0,
            len_bytes: 0,
            popularity: 1,
            name: "parse_previous".into(),
            data: vec![],
            flags: 0,
        };
        let previous = rt.segments.append(&rec)?;
        rt.index
            .upsert(1, previous)
            .map_err(|_| io::Error::other("index update"))?;
        let head = Database::collect_versions_bounded(&rt, 1, 1, &HashSet::new(), None, 1)?;
        assert_eq!(head.len(), 1);
        assert!(head[0].analysis.get().is_none());
        let wanted = HashSet::from([head[0].version_id]);
        rec.prev_addr = previous;
        rec.name = "sub_1234".into();
        rt.index
            .upsert(1, rt.segments.append(&rec)?)
            .map_err(|_| io::Error::other("index update"))?;
        assert!(Database::collect_versions_bounded(&rt, 1, 1, &wanted, None, 1)?.is_empty());
        assert!(Database::collect_versions_bounded(&rt, 1, 1, &wanted, None, 0)?.is_empty());
        assert!(Database::collect_versions_bounded(&rt, 1, 0, &wanted, None, 2)?.is_empty());
        let normal = Database::collect_versions_targeted(&rt, 1, 1, &wanted, None)?;
        assert_eq!(normal.len(), 1);
        assert!(normal[0].matches_id(wanted.iter().next().unwrap()));
        assert!(normal[0].analysis.get().is_none());
        rt.index
            .upsert(2, previous)
            .map_err(|_| io::Error::other("index update"))?;
        let error = Database::collect_versions_bounded(&rt, 2, 1, &HashSet::new(), None, 1)
            .err()
            .expect("foreign head must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}

#[test]
fn captured_name_quality_is_used_without_rereading_policy() {
    for quality in [0.25, -1.0] {
        let analysis =
            super::super::semantic::analyze_function_with_name_quality("sub_1", &[], quality);
        assert_eq!(analysis.quality_score, quality);
    }
}

#[test]
fn ineligible_population_cannot_change_compatible_variant_ranking() -> io::Result<()> {
    for dimension in ["timestamp", "observations", "diversity"] {
        let dir = std::env::temp_dir().join(format!(
            "dazhbog-population-{dimension}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&dir)?;
        let result = (|| -> io::Result<()> {
            let mut cfg = Config::default();
            cfg.engine.data_dir = dir.to_string_lossy().into_owned();
            if dimension == "observations" {
                cfg.scoring.w_stab = 2.0;
            }
            if dimension == "diversity" {
                cfg.scoring.w_stab = 0.0;
                cfg.scoring.w_rec = 0.25;
            }
            let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
            let make = |tag: u8, ts, obs, bins| {
                let rec = Record {
                    key: 1,
                    ts_sec: ts,
                    prev_addr: 0,
                    len_bytes: 3,
                    popularity: 1,
                    name: "parse_headers".into(),
                    data: vec![42, 1, tag],
                    flags: 0,
                };
                AnalyzedVersion {
                    version_id: version_id(1, &rec.name, &rec.data),
                    legacy_version_id: legacy_version_id(1, &rec.name, &rec.data),
                    rec,
                    binary_support: 0.0,
                    binary_match: 1.0,
                    binary_priority_floor: 1.0,
                    name_quality: 1.0,
                    analysis: OnceLock::new(),
                    batch_fingerprint: None,
                    stats: Some(crate::engine::VersionStats {
                        total_obs: obs,
                        num_binaries: bins,
                        first_ts_sec: ts,
                        last_ts_sec: ts,
                        top_md5s: vec![],
                    }),
                }
            };
            let base = vec![
                make(1, 1, 1000, if dimension == "diversity" { 1000 } else { 1 }),
                make(2, 2, 1, 1),
            ];
            for version in &base {
                rt.ctx_index.record_key_observation(
                    1,
                    [1; 16],
                    Some(version.version_id),
                    1,
                    None,
                )?;
            }
            rt.ctx_index
                .record_key_observation(1, [1; 16], Some([9; 32]), 2, None)?;
            let empty = HashMap::new();
            for mode in ["explicit", "inferred", "corroboration"] {
                let mut versions = base.clone();
                let ctx = CandidateScoringContext {
                    capture_candidates: true,
                    suppress_observation_priors: false,
                    contrastive_anchors: true,
                    key: 1,
                    md5: (mode == "explicit").then_some([1; 16]),
                    basename: None,
                    hostname: None,
                    origin_token: None,
                    requested_mdkeys: &[],
                    anchor_token_weights: &empty,
                    priority_anchor_weights: &empty,
                    corroboration_weights: &empty,
                    canonical_hint: None,
                };
                if mode == "corroboration" {
                    for version in &mut versions {
                        version.binary_priority_floor = 0.25;
                    }
                }
                let reference = select_from_versions(&rt, &versions, &ctx)?.unwrap();
                let mut unrelated = make(
                    3,
                    if dimension == "timestamp" {
                        u64::MAX
                    } else {
                        2
                    },
                    if dimension == "observations" {
                        u32::MAX
                    } else {
                        1
                    },
                    if dimension == "diversity" {
                        u32::MAX
                    } else {
                        1
                    },
                );
                unrelated.binary_match = if mode == "corroboration" { 0.5 } else { 0.0 };
                unrelated.binary_priority_floor = 0.0;
                versions.push(unrelated);
                let actual = select_from_versions(&rt, &versions, &ctx)?.unwrap();
                assert_eq!(
                    actual.base_version_id, reference.base_version_id,
                    "{dimension}/{mode}"
                );
                assert_eq!(actual.data, reference.data);
                assert_eq!(actual.score.to_bits(), reference.score.to_bits());
                assert_eq!(actual.margin.to_bits(), reference.margin.to_bits());
                assert_eq!(actual.entropy.to_bits(), reference.entropy.to_bits());
                assert_eq!(actual.candidate_version_ids.len(), 3);
                if mode != "corroboration" {
                    assert!(versions[2].analysis.get().is_none());
                }
            }
            Ok(())
        })();
        std::fs::remove_dir_all(dir)?;
        result?;
    }
    Ok(())
}

#[test]
fn eligibility_precedes_analysis_and_score_normalization() -> io::Result<()> {
    let dir = std::env::temp_dir().join(format!("dazhbog-lazy-selection-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let result = (|| -> io::Result<()> {
        let mut cfg = Config::default();
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        cfg.scoring.experimental_synthesis = true;
        let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
        let key = 17;
        let mut previous = 0;
        let mut ids = Vec::new();
        for (name, ts) in [("parse_orchid", 1), ("decode_quartz", 2)] {
            let rec = Record {
                key,
                ts_sec: ts,
                prev_addr: previous,
                len_bytes: 0,
                popularity: 1,
                name: name.into(),
                data: Vec::new(),
                flags: 0,
            };
            ids.push((
                version_id(key, name, &[]),
                legacy_version_id(key, name, &[]),
            ));
            previous = rt.segments.append(&rec)?;
        }
        rt.index
            .upsert(key, previous)
            .map_err(|_| io::Error::other("upsert"))?;
        for observed in [ids[0].0, ids[0].1] {
            rt.ctx_index
                .record_key_observation(key, [1; 16], Some(observed), 1, None)?;
            let versions =
                Database::collect_versions_targeted(&rt, key, 8, &HashSet::from([observed]), None)?;
            assert!(versions
                .iter()
                .all(|version| version.analysis.get().is_none()));
            let oracle_versions = versions.clone();
            let empty = HashMap::new();
            let mut ctx = CandidateScoringContext {
                capture_candidates: true,
                suppress_observation_priors: false,
                contrastive_anchors: true,
                key,
                md5: Some([1; 16]),
                basename: None,
                hostname: None,
                origin_token: None,
                requested_mdkeys: &[],
                anchor_token_weights: &empty,
                priority_anchor_weights: &empty,
                corroboration_weights: &empty,
                canonical_hint: Some(ids[1].0),
            };
            let mut oracle: Vec<_> = (0..oracle_versions.len()).collect();
            assert!(retain_binary_compatible_candidates(
                &rt,
                &oracle_versions,
                &ctx,
                &mut oracle
            )?);
            assert_eq!(oracle.len(), 1);
            // A one-candidate population has equal timestamp bounds and only
            // its own observation/diversity maxima, regardless of other records.
            let reference = &oracle_versions[oracle[0]];
            let stats = reference.stats.as_ref().unwrap();
            let score = score_candidate_version(
                &rt,
                reference,
                &ctx,
                reference.rec.ts_sec,
                reference.rec.ts_sec,
                stats.total_obs.max(1),
                stats.num_binaries.max(stats.top_md5s.len() as u32).max(1),
            )?;
            let selected = select_from_versions(&rt, &versions, &ctx)?.unwrap();
            assert_eq!(selected.name, "parse_orchid");
            assert_eq!(selected.base_version_id, reference.version_id);
            assert_eq!(selected.score.to_bits(), score.to_bits());
            assert!(!selected.used_synthesis);
            assert_eq!(selected.candidate_version_ids.len(), 2);
            for version in &versions {
                assert_eq!(
                    version.analysis.get().is_some(),
                    version.version_id == ids[0].0
                );
            }
            // Without explicit context both candidates remain eligible and must
            // still be analyzed; deferred analysis is not a semantic shortcut.
            ctx.md5 = None;
            select_from_versions(&rt, &versions, &ctx)?;
            assert!(versions
                .iter()
                .all(|version| version.analysis.get().is_some()));
        }
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}

#[test]
fn rejected_candidate_cannot_dilute_final_contrastive_evidence() -> io::Result<()> {
    use super::super::semantic::SemanticFingerprint;
    let dir =
        std::env::temp_dir().join(format!("dazhbog-anchor-population-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let result = (|| -> io::Result<()> {
        let mut cfg = Config::default();
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
        let fingerprint = |tokens: &[&str]| SemanticFingerprint {
            tokens: tokens.iter().map(|token| (*token).to_owned()).collect(),
            ..Default::default()
        };
        let make = |tag, tokens: &[&str], binary_match| {
            let rec = Record {
                key: 1,
                ts_sec: 1,
                prev_addr: 0,
                len_bytes: 3,
                popularity: 1,
                name: "parse_value".into(),
                data: vec![42, 1, tag],
                flags: 0,
            };
            AnalyzedVersion {
                version_id: version_id(1, &rec.name, &rec.data),
                legacy_version_id: legacy_version_id(1, &rec.name, &rec.data),
                rec,
                binary_support: 0.0,
                binary_match,
                binary_priority_floor: 0.25,
                name_quality: 1.0,
                analysis: OnceLock::new(),
                batch_fingerprint: Some(Box::new(fingerprint(tokens))),
                stats: None,
            }
        };
        // Isolate transient lexical evidence from the independent whole-token
        // witnesses required to relax binary priority. Both survivors have equal
        // structural/prior scores; the second has the 0.5 canonical bonus.
        let mut versions = vec![
            make(1, &["orchid", "shared"], 1.0),
            make(2, &["cobalt", "shared"], 1.0),
        ];
        let mut anchors = BatchAnchors::default();
        anchors.push(None);
        anchors.push(Some(&fingerprint(&["orchid", "shared", "quartz"])));
        let empty = HashMap::new();
        let weights = anchors.excluding(
            0,
            &versions
                .iter()
                .map(AnalyzedVersion::anchor_fingerprint)
                .collect::<Vec<_>>(),
        );
        let mut ctx = CandidateScoringContext {
            capture_candidates: true,
            suppress_observation_priors: false,
            contrastive_anchors: true,
            key: 1,
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
            requested_mdkeys: &[],
            anchor_token_weights: &weights,
            priority_anchor_weights: &empty,
            corroboration_weights: &empty,
            canonical_hint: Some(versions[1].version_id),
        };
        let reference = select_from_versions(&rt, &versions, &ctx)?.unwrap();
        assert_eq!(reference.base_version_id, versions[0].version_id);
        // This candidate passes the sensitivity floor but lacks independent
        // corroboration. It cannot be returned, nor should its quartz token and
        // absence of shared make either term dilute the surviving orchid vote.
        versions.push(make(3, &["quartz"], 0.5));
        let weights = anchors.excluding(
            0,
            &versions
                .iter()
                .map(AnalyzedVersion::anchor_fingerprint)
                .collect::<Vec<_>>(),
        );
        assert_eq!(weights.len(), 3);
        ctx.anchor_token_weights = &weights;
        let actual = select_from_versions(&rt, &versions, &ctx)?.unwrap();
        assert_eq!(actual.base_version_id, reference.base_version_id);
        assert_eq!(actual.score.to_bits(), reference.score.to_bits());
        assert_eq!(actual.margin.to_bits(), reference.margin.to_bits());
        assert_eq!(actual.entropy.to_bits(), reference.entropy.to_bits());
        assert_eq!(actual.data, reference.data);
        assert_eq!(actual.candidate_version_ids.len(), 3);
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}

#[test]
fn inferred_history_budget_is_shared_ordered_and_respects_identity_guards() -> io::Result<()> {
    let dir = std::env::temp_dir().join(format!("dazhbog-history-hints-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let result = (|| -> io::Result<()> {
        let mut cfg = Config::default();
        cfg.engine.data_dir = dir.to_string_lossy().into_owned();
        let hint = |key: u128, tag: u8| {
            let mut id = [0; 32];
            id[..16].copy_from_slice(&key.to_le_bytes());
            id[16] = tag;
            id
        };
        {
            let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
            for key in [1, 2] {
                let rec = Record {
                    key,
                    ts_sec: 1,
                    prev_addr: 0,
                    len_bytes: 0,
                    popularity: 1,
                    name: "parse_current".into(),
                    data: vec![],
                    flags: 0,
                };
                rt.index
                    .upsert(key, rt.segments.append(&rec)?)
                    .map_err(|_| io::Error::other("index update"))?;
            }
            for tag in 1..=65 {
                rt.ctx_index
                    .record_key_observation(1, [1; 16], Some(hint(1, tag)), 1, None)?;
            }
            rt.ctx_index
                .record_key_observation(1, [2; 16], Some(hint(1, 99)), 1, None)?;
            for tag in 1..=33 {
                for donor in 1..=2 {
                    if donor == 2 || tag <= 32 {
                        rt.ctx_index.record_key_observation(
                            2,
                            [donor; 16],
                            Some(hint(2, tag)),
                            1,
                            None,
                        )?;
                    }
                }
            }
            rt.flush()?;
        }
        {
            let raw = sled::open(dir.join("context_db"))?;
            let tree = raw.open_tree("binary_versions")?;
            // A malformed row beyond donor 1's 64-row allowance is uninspected.
            tree.insert([&[1; 16][..], &hint(1, 65)].concat(), &[0][..])?;
            // Exact/withheld donors must not enumerate their malformed prefix.
            for donor in [3, 4] {
                tree.insert(
                    [&[donor; 16][..], &1u128.to_le_bytes()].concat(),
                    &[0u8; 8][..],
                )?;
            }
            raw.flush()?;
        }
        let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
        let versions = Database::collect_versions_sync(&rt, 1, 1)?;
        let last = HashMap::from([([3; 16], versions[0].version_id)]);
        let mut ctx = QueryContext {
            keys: &[1],
            requested_mdkeys: &[],
            md5: None,
            basename: None,
            hostname: None,
            origin_token: None,
        };
        // Equal weights use MD5 order, independent of map insertion order.
        for order in [[1, 2, 3, 4], [4, 3, 2, 1]] {
            let weights: HashMap<_, _> = order.into_iter().map(|id| ([id; 16], 1.0)).collect();
            let targets = candidate_history::historical_targets(
                &rt,
                1,
                &versions,
                &weights,
                &last,
                &ctx,
                Some([4; 16]),
            )?;
            assert_eq!(targets, (1..=64).map(|tag| hint(1, tag)).collect());
            assert!(candidate_history::historical_targets(
                &rt,
                1,
                &[],
                &weights,
                &last,
                &ctx,
                None
            )?
            .is_empty());
        }
        // Force the exact and withheld guards to run before the budget is spent.
        let weights = HashMap::from([([3; 16], 3.0), ([4; 16], 4.0)]);
        assert!(candidate_history::historical_targets(
            &rt,
            1,
            &versions,
            &weights,
            &last,
            &ctx,
            Some([4; 16])
        )?
        .is_empty());
        assert!(candidate_history::historical_targets(
            &rt, 1, &versions, &weights, &last, &ctx, None
        )
        .is_err());
        ctx.md5 = Some([3; 16]);
        assert!(candidate_history::historical_targets(
            &rt, 1, &versions, &weights, &last, &ctx, None
        )?
        .is_empty());
        ctx.md5 = Some([4; 16]);
        assert!(candidate_history::historical_targets(
            &rt,
            1,
            &versions,
            &weights,
            &last,
            &ctx,
            Some([4; 16])
        )?
        .is_empty());
        ctx.md5 = None;
        let versions = Database::collect_versions_sync(&rt, 2, 1)?;
        let weights = HashMap::from([([1; 16], 2.0), ([2; 16], 1.0)]);
        let targets = candidate_history::historical_targets(
            &rt,
            2,
            &versions,
            &weights,
            &HashMap::new(),
            &ctx,
            None,
        )?;
        // The second donor's duplicate 32 rows consume the remaining allowance.
        assert_eq!(targets, (1..=32).map(|tag| hint(2, tag)).collect());
        let reverse_weights = HashMap::from([([1; 16], 1.0), ([2; 16], 2.0)]);
        let targets = candidate_history::historical_targets(
            &rt,
            2,
            &versions,
            &reverse_weights,
            &HashMap::new(),
            &ctx,
            None,
        )?;
        assert_eq!(targets, (1..=33).map(|tag| hint(2, tag)).collect());
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}
