//! Consistent per-key observation evidence and its bounded popularity projection.

use super::{
    binary_function_key, decode_key_bins, decode_key_md5_stats, encode_key_bins,
    encode_key_md5_stats, ContextIndex, KeyMd5Entry, KeyMd5Stats, MAX_MD5_PER_KEY,
};
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional};
use std::io;

fn invalid(message: &str) -> ConflictableTransactionError<io::Error> {
    ConflictableTransactionError::Abort(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn advance(
    raw: Option<sled::IVec>,
    version_id: Option<[u8; 32]>,
    ts_sec: u64,
) -> Result<KeyMd5Stats, ConflictableTransactionError<io::Error>> {
    let mut stats = match raw {
        Some(raw) => {
            decode_key_md5_stats(&raw).ok_or_else(|| invalid("invalid key observation"))?
        }
        None => KeyMd5Stats {
            obs_count: 0,
            last_ts_sec: 0,
            last_version_id: [0; 32],
        },
    };
    stats.obs_count = stats.obs_count.saturating_add(1);
    stats.last_ts_sec = ts_sec;
    if let Some(vid) = version_id {
        stats.last_version_id = vid;
    }
    Ok(stats)
}

fn rank_key(key: u128, popularity: u32) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[..4].copy_from_slice(&(u32::MAX - popularity).to_be_bytes());
    bytes[4..].copy_from_slice(&key.to_le_bytes());
    bytes
}

impl ContextIndex {
    /// One transaction owns paired observations, the retained binary summary and
    /// both popularity indexes. Other observation metadata is updated separately.
    pub(super) fn record_key_evidence(
        &self,
        key: u128,
        md5: [u8; 16],
        version_id: Option<[u8; 32]>,
        ts_sec: u64,
    ) -> io::Result<(Vec<KeyMd5Entry>, bool)> {
        let key_only = key.to_le_bytes();
        let mut forward_key = [0; 32];
        forward_key[..16].copy_from_slice(&key_only);
        forward_key[16..].copy_from_slice(&md5);
        let reverse_key = binary_function_key(&md5, key);
        (
            &self.t_key_md5,
            &self.t_binary_functions,
            &self.t_key_bins,
            &self.t_pop_val,
            &self.t_pop_rank,
        )
            .transaction(|(forward, reverse, summaries, popularity, ranks)| {
                let stats = advance(forward.get(forward_key.as_slice())?, version_id, ts_sec)?;
                let previous = reverse.get(reverse_key.as_slice())?;
                let new_function = previous.is_none();
                let reverse_stats = advance(previous, version_id, ts_sec)?;
                let mut bins = match summaries.get(key_only.as_slice())? {
                    Some(raw) => decode_key_bins(&raw)
                        .ok_or_else(|| invalid("invalid key binary summary"))?,
                    None => Vec::new(),
                };
                if let Some(entry) = bins.iter_mut().find(|entry| entry.md5 == md5) {
                    // Preserve stronger legacy summary evidence; the pair count
                    // includes observations made while absent from this list.
                    entry.obs_count = entry.obs_count.saturating_add(1).max(stats.obs_count);
                } else {
                    bins.push(KeyMd5Entry {
                        md5,
                        obs_count: stats.obs_count,
                    });
                }
                // Preserve the existing stable arrival-order tie policy.
                bins.sort_by_key(|entry| std::cmp::Reverse(entry.obs_count));
                bins.truncate(MAX_MD5_PER_KEY);
                let new_pop = bins
                    .iter()
                    .fold(0u32, |sum, entry| sum.saturating_add(entry.obs_count));
                let old_pop = match popularity.get(key_only.as_slice())? {
                    Some(raw) => u32::from_le_bytes(
                        raw.as_ref()
                            .try_into()
                            .map_err(|_| invalid("invalid key popularity"))?,
                    ),
                    None => 0,
                };
                if new_pop > old_pop {
                    if old_pop > 0 {
                        ranks.remove(rank_key(key, old_pop).as_slice())?;
                    }
                    ranks.insert(rank_key(key, new_pop).as_slice(), &[])?;
                    popularity.insert(key_only.as_slice(), &new_pop.to_le_bytes()[..])?;
                }
                forward.insert(forward_key.as_slice(), encode_key_md5_stats(&stats))?;
                reverse.insert(reverse_key.as_slice(), encode_key_md5_stats(&reverse_stats))?;
                summaries.insert(key_only.as_slice(), encode_key_bins(&bins))?;
                Ok((bins, new_function))
            })
            .map_err(|error| match error {
                TransactionError::Abort(error) => error,
                TransactionError::Storage(error) => io::Error::other(error),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    fn fixture(label: &str) -> io::Result<(std::path::PathBuf, ContextIndex)> {
        let path = std::env::temp_dir().join(format!(
            "dazhbog-key-observation-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path)?;
        let ctx = ContextIndex::open_or_create(&path)?;
        Ok((path, ctx))
    }

    #[test]
    fn omitted_key_donor_reenters_with_accumulated_evidence() -> io::Result<()> {
        let (path, ctx) = fixture("omission")?;
        for binary in 0..16 {
            for ts in 1..=2 {
                ctx.record_key_observation(1, [binary; 16], None, ts, None)?;
            }
        }
        ctx.record_key_observation(1, [16; 16], None, 1, None)?;
        assert!(!ctx
            .get_md5_bins_for_key(1)?
            .iter()
            .any(|e| e.md5 == [16; 16]));
        for ts in 2..=4 {
            ctx.record_key_observation(1, [16; 16], None, ts, None)?;
        }
        let bins = ctx.get_md5_bins_for_key(1)?;
        assert_eq!(bins.len(), 16);
        assert_eq!(bins[0].md5, [16; 16]);
        assert_eq!(bins[0].obs_count, 4);
        assert_eq!(ctx.get_top_popular_keys(10)?, vec![(1, 34)]);
        ctx.db.flush()?;
        drop(ctx);
        let ctx = ContextIndex::open_or_create(&path)?;
        assert_eq!(ctx.get_md5_bins_for_key(1)?[0].obs_count, 4);
        drop(ctx);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn concurrent_key_evidence_preserves_pair_counts_and_one_rank() -> io::Result<()> {
        let (path, ctx) = fixture("concurrent")?;
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| -> io::Result<()> {
            let threads: Vec<_> = (0..8)
                .map(|worker| {
                    let ctx = &ctx;
                    let start = &start;
                    scope.spawn(move || -> io::Result<()> {
                        start.wait();
                        // Two writers per binary and eight writers per key.
                        for ts in 1..=50 {
                            ctx.record_key_observation(
                                1,
                                [worker % 4; 16],
                                Some([ts as u8; 32]),
                                ts,
                                None,
                            )?;
                        }
                        Ok(())
                    })
                })
                .collect();
            for thread in threads {
                thread.join().unwrap()?;
            }
            Ok(())
        })?;
        for binary in 0..4 {
            let forward = ctx.get_key_md5_stats(1, &[binary; 16])?.unwrap();
            let reverse = ctx
                .t_binary_functions
                .get(binary_function_key(&[binary; 16], 1))?
                .unwrap();
            assert_eq!(forward.obs_count, 100);
            assert_eq!(encode_key_md5_stats(&forward), reverse.as_ref());
        }
        let bins = ctx.get_md5_bins_for_key(1)?;
        assert_eq!(bins.len(), 4);
        assert!(bins.iter().all(|entry| entry.obs_count == 100));
        assert_eq!(ctx.get_top_popular_keys(10)?, vec![(1, 400)]);
        drop(ctx);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn corrupt_key_evidence_aborts_without_partial_projection_writes() -> io::Result<()> {
        let (path, ctx) = fixture("corruption")?;
        let forward = [1u128.to_le_bytes(), [1; 16]].concat();
        let reverse = binary_function_key(&[1; 16], 1);
        let key = 1u128.to_le_bytes();
        let trees = [
            &ctx.t_key_md5,
            &ctx.t_binary_functions,
            &ctx.t_key_bins,
            &ctx.t_pop_val,
            &ctx.t_pop_rank,
        ];
        for (tree, row) in [
            (&ctx.t_key_md5, forward.as_slice()),
            (&ctx.t_binary_functions, reverse.as_slice()),
            (&ctx.t_key_bins, key.as_slice()),
            (&ctx.t_pop_val, key.as_slice()),
        ] {
            for tree in trees {
                tree.clear()?;
            }
            ctx.record_key_observation(1, [1; 16], None, 1, None)?;
            tree.insert(row, &[2])?;
            let snapshot = || -> io::Result<Vec<Vec<(sled::IVec, sled::IVec)>>> {
                trees
                    .iter()
                    .map(|tree| {
                        tree.iter()
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(io::Error::other)
                    })
                    .collect()
            };
            let before = snapshot()?;
            assert_eq!(
                ctx.record_key_observation(1, [1; 16], None, 2, None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(snapshot()?, before);
        }
        drop(ctx);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn popularity_saturates_and_unknown_version_preserves_identity() -> io::Result<()> {
        let (path, ctx) = fixture("saturation")?;
        let stats = KeyMd5Stats {
            obs_count: u32::MAX,
            last_ts_sec: 7,
            last_version_id: [9; 32],
        };
        ctx.t_key_md5.insert(
            [1u128.to_le_bytes(), [1; 16]].concat(),
            encode_key_md5_stats(&stats),
        )?;
        ctx.t_binary_functions.insert(
            binary_function_key(&[1; 16], 1),
            encode_key_md5_stats(&stats),
        )?;
        ctx.t_key_bins.insert(
            1u128.to_le_bytes(),
            encode_key_bins(&[
                KeyMd5Entry {
                    md5: [1; 16],
                    obs_count: u32::MAX,
                },
                KeyMd5Entry {
                    md5: [2; 16],
                    obs_count: 1,
                },
            ]),
        )?;
        ctx.record_key_observation(1, [1; 16], None, 3, None)?;
        let current = ctx.get_key_md5_stats(1, &[1; 16])?.unwrap();
        assert_eq!(current.obs_count, u32::MAX);
        assert_eq!(current.last_version_id, [9; 32]);
        // Preserve the existing arrival-order timestamp policy.
        assert_eq!(current.last_ts_sec, 3);
        assert_eq!(ctx.get_top_popular_keys(10)?, vec![(1, u32::MAX)]);
        ctx.record_key_observation(1, [1; 16], None, 4, None)?;
        assert_eq!(ctx.get_top_popular_keys(10)?, vec![(1, u32::MAX)]);
        drop(ctx);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn legacy_counts_are_not_summed_or_silently_repaired() -> io::Result<()> {
        let (path, ctx) = fixture("legacy")?;
        let forward = KeyMd5Stats {
            obs_count: 5,
            last_ts_sec: 1,
            last_version_id: [7; 32],
        };
        let reverse = KeyMd5Stats {
            obs_count: 2,
            last_ts_sec: 1,
            last_version_id: [8; 32],
        };
        ctx.t_key_md5.insert(
            [1u128.to_le_bytes(), [1; 16]].concat(),
            encode_key_md5_stats(&forward),
        )?;
        ctx.t_binary_functions.insert(
            binary_function_key(&[1; 16], 1),
            encode_key_md5_stats(&reverse),
        )?;
        ctx.t_key_bins.insert(
            1u128.to_le_bytes(),
            encode_key_bins(&[KeyMd5Entry {
                md5: [1; 16],
                obs_count: 9,
            }]),
        )?;
        assert!(!ctx.record_key_evidence(1, [1; 16], None, 2)?.1);
        let forward = ctx.get_key_md5_stats(1, &[1; 16])?.unwrap();
        let reverse = decode_key_md5_stats(
            &ctx.t_binary_functions
                .get(binary_function_key(&[1; 16], 1))?
                .unwrap(),
        )
        .unwrap();
        assert_eq!((forward.obs_count, reverse.obs_count), (6, 3));
        assert_eq!(forward.last_version_id, [7; 32]);
        assert_eq!(reverse.last_version_id, [8; 32]);
        assert_eq!(ctx.get_md5_bins_for_key(1)?[0].obs_count, 10);
        assert_eq!(ctx.get_top_popular_keys(10)?, vec![(1, 10)]);
        assert!(ctx.record_key_evidence(1, [2; 16], Some([9; 32]), 3)?.1);
        assert!(!ctx.record_key_evidence(1, [2; 16], Some([9; 32]), 3)?.1);
        drop(ctx);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}
