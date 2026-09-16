//! Independent donor evidence for identity-holdout candidate collection.
use crate::db::family::{MAX_INFERRED_DONORS, MAX_KEY_MEMBERSHIPS};
use crate::engine::{EngineRuntime, VersionStats};
use std::collections::{BTreeSet, HashMap};
use std::io;

pub(super) struct TransferProvenance {
    heldout: [u8; 16],
    observations: Vec<([u8; 16], Option<[u8; 32]>)>,
}

impl TransferProvenance {
    pub(super) fn new(
        rt: &EngineRuntime,
        key: u128,
        heldout: [u8; 16],
        inferred: &HashMap<[u8; 16], f64>,
    ) -> io::Result<Self> {
        if inferred.len() > MAX_INFERRED_DONORS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many inferred transfer donors",
            ));
        }
        let mut donors: BTreeSet<_> = inferred
            .iter()
            .filter(|(md5, weight)| **md5 != heldout && weight.is_finite() && **weight > 0.0)
            .map(|(md5, _)| *md5)
            .collect();
        if let Some(binaries) = rt
            .ctx_index
            .key_binary_memberships(key, MAX_KEY_MEMBERSHIPS + 1)?
        {
            donors.extend(binaries.into_iter().filter(|md5| *md5 != heldout));
        }
        let observations = donors
            .into_iter()
            .map(|md5| {
                let last = rt
                    .ctx_index
                    .get_positive_key_md5_stats(key, &md5)?
                    .map(|stats| stats.last_version_id)
                    .filter(|id| *id != [0; 32]);
                Ok((md5, last))
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            heldout,
            observations,
        })
    }

    pub(super) fn permits(
        &self,
        rt: &EngineRuntime,
        current: &[u8; 32],
        legacy: &[u8; 32],
        stats: &mut Option<VersionStats>,
    ) -> io::Result<bool> {
        if let Some(stats) = stats {
            stats
                .top_md5s
                .retain(|entry| entry.md5 != self.heldout && entry.obs_count > 0);
            if !stats.top_md5s.is_empty() {
                return Ok(true);
            }
        }
        for (md5, last) in &self.observations {
            if last.is_some_and(|id| id == *current || id == *legacy)
                || rt.ctx_index.binary_has_version(md5, current)?
                || rt.ctx_index.binary_has_version(md5, legacy)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::hash::{legacy_version_id, version_id};
    use crate::config::Config;

    #[test]
    fn donor_context_requires_variant_proof_and_preserves_holdout_bounds() -> io::Result<()> {
        let dir =
            std::env::temp_dir().join(format!("dazhbog-transfer-proof-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let result = (|| -> io::Result<()> {
            let mut cfg = Config::default();
            cfg.engine.data_dir = dir.to_string_lossy().into_owned();
            let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
            let current = version_id(1, "parse_headers", &[]);
            let legacy = legacy_version_id(1, "parse_headers", &[]);
            let other = version_id(1, "decode_pixels", &[]);
            let inferred = HashMap::from([([1; 16], 1.0), ([9; 16], 1.0)]);
            let proof = TransferProvenance::new(&rt, 1, [9; 16], &inferred)?;
            assert_eq!(proof.observations, vec![([1; 16], None)]);
            rt.ctx_index
                .record_key_observation(1, [9; 16], Some(current), 1, None)?;
            let mut stats = rt.ctx_index.get_version_stats(&current)?;
            let mut zero = stats.as_ref().unwrap().top_md5s[0].clone();
            zero.md5 = [1; 16];
            zero.obs_count = 0;
            stats.as_mut().unwrap().top_md5s.push(zero);
            assert!(!proof.permits(&rt, &current, &legacy, &mut stats)?);
            assert!(stats.unwrap().top_md5s.is_empty());
            rt.ctx_index
                .record_key_observation(1, [1; 16], Some(other), 1, None)?;
            // Relatedness and membership in this function are insufficient:
            // the donor must actually have observed this annotation.
            assert!(!proof.permits(&rt, &current, &legacy, &mut None)?);
            assert!(proof.permits(&rt, &other, &other, &mut None)?);
            rt.ctx_index
                .record_key_observation(1, [1; 16], Some(legacy), 1, None)?;
            let exact = TransferProvenance::new(&rt, 1, [9; 16], &inferred)?;
            assert_eq!(exact.observations, vec![([1; 16], Some(legacy))]);
            rt.ctx_index
                .record_key_observation(1, [1; 16], Some(other), 2, None)?;
            let historical = TransferProvenance::new(&rt, 1, [9; 16], &inferred)?;
            assert_eq!(historical.observations, vec![([1; 16], Some(other))]);
            assert!(historical.permits(&rt, &current, &legacy, &mut None)?);
            assert!(exact.permits(&rt, &current, &legacy, &mut None)?);
            let mut summary = rt.ctx_index.get_version_stats(&legacy)?;
            assert!(historical.permits(&rt, &current, &legacy, &mut summary)?);
            assert!(summary
                .unwrap()
                .top_md5s
                .iter()
                .all(|entry| entry.md5 != [9; 16]));
            let mut inferred: HashMap<_, _> = (0..MAX_INFERRED_DONORS as u128)
                .map(|id| (id.to_be_bytes(), 1.0))
                .collect();
            assert_eq!(
                TransferProvenance::new(&rt, 999, [9; 16], &inferred)?
                    .observations
                    .len(),
                MAX_INFERRED_DONORS
            );
            inferred.insert([255; 16], 1.0);
            assert_eq!(
                TransferProvenance::new(&rt, 999, [9; 16], &inferred)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            let invalid = HashMap::from([
                ([1; 16], 0.0),
                ([2; 16], -1.0),
                ([3; 16], f64::NAN),
                ([4; 16], f64::INFINITY),
            ]);
            assert!(TransferProvenance::new(&rt, 999, [9; 16], &invalid)?
                .observations
                .is_empty());
            Ok(())
        })();
        std::fs::remove_dir_all(dir)?;
        result
    }

    #[test]
    fn malformed_targeted_history_is_an_error_not_sharing() -> io::Result<()> {
        let dir =
            std::env::temp_dir().join(format!("dazhbog-transfer-corrupt-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let result = (|| -> io::Result<()> {
            let mut cfg = Config::default();
            cfg.engine.data_dir = dir.to_string_lossy().into_owned();
            let current = version_id(1, "parse_headers", &[]);
            let legacy = legacy_version_id(1, "parse_headers", &[]);
            {
                let rt = EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
                rt.ctx_index.record_key_observation(
                    1,
                    [1; 16],
                    Some(version_id(1, "other", &[])),
                    1,
                    None,
                )?;
                rt.flush()?;
            }
            {
                let raw = sled::open(dir.join("context_db"))?;
                raw.open_tree("binary_versions")?
                    .insert([&[1; 16][..], &current].concat(), &[1][..])?;
                raw.flush()?;
            }
            let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
            let proof = TransferProvenance::new(&rt, 1, [9; 16], &HashMap::from([([1; 16], 1.0)]))?;
            assert_eq!(
                proof
                    .permits(&rt, &current, &legacy, &mut None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            Ok(())
        })();
        std::fs::remove_dir_all(dir)?;
        result
    }
}
