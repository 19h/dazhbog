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
        let keys = complete_binary_context(&rt, &ctx, None)?;
        assert_eq!(keys.len(), 129);
        assert_eq!(keys[0], 999);
        assert!(!keys.contains(&129));
        assert_eq!(
            keys.iter().copied().collect::<HashSet<_>>().len(),
            keys.len()
        );
        assert_eq!(&*complete_binary_context(&rt, &ctx, Some([1; 16]))?, &[999]);
        ctx.keys = &[1];
        assert!(matches!(
            complete_binary_context(&rt, &ctx, None)?,
            std::borrow::Cow::Borrowed(_)
        ));
        ctx.keys = &[];
        assert!(complete_binary_context(&rt, &ctx, None)?.is_empty());
        ctx.keys = &[999];
        ctx.md5 = None;
        assert!(matches!(
            complete_binary_context(&rt, &ctx, None)?,
            std::borrow::Cow::Borrowed(_)
        ));
        ctx.md5 = Some([9; 16]);
        assert_eq!(&*complete_binary_context(&rt, &ctx, None)?, &[999]);
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
        let keys = complete_binary_context(&rt, &ctx, None)?;
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
fn captured_name_quality_is_used_without_rereading_policy() {
    for quality in [0.25, -1.0] {
        let analysis =
            super::super::semantic::analyze_function_with_name_quality("sub_1", &[], quality);
        assert_eq!(analysis.quality_score, quality);
    }
}

#[test]
fn eligibility_precedes_analysis_without_changing_scores_or_candidates() -> io::Result<()> {
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
            let (ts_min, ts_max, obs, bins) = version_population_bounds(&versions);
            // Reference order from before lazy analysis: score every candidate,
            // then apply identity eligibility and sort.
            let mut oracle = oracle_versions
                .iter()
                .enumerate()
                .map(|(index, version)| {
                    Ok((
                        index,
                        score_candidate_version(&rt, version, &ctx, ts_min, ts_max, obs, bins)?,
                    ))
                })
                .collect::<io::Result<Vec<_>>>()?;
            assert!(retain_binary_compatible_candidates(
                &rt,
                &oracle_versions,
                &ctx,
                &mut oracle
            )?);
            sort_candidate_scores(&oracle_versions, &mut oracle);
            assert_eq!(oracle.len(), 1);
            let selected =
                select_from_versions(&rt, &versions, &ctx, ts_min, ts_max, obs, bins)?.unwrap();
            assert_eq!(selected.name, "parse_orchid");
            assert_eq!(
                selected.base_version_id,
                oracle_versions[oracle[0].0].version_id
            );
            assert_eq!(selected.score.to_bits(), oracle[0].1.to_bits());
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
            select_from_versions(&rt, &versions, &ctx, ts_min, ts_max, obs, bins)?;
            assert!(versions
                .iter()
                .all(|version| version.analysis.get().is_some()));
        }
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}
