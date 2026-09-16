//! Binary evidence from independent function identities, not upload volume.
use std::collections::{BTreeMap, HashMap};

pub(crate) const MAX_KEY_MEMBERSHIPS: usize = 256;
pub(crate) const MAX_FAMILY_CANDIDATES: usize = 64;
const MAX_TARGET_FAMILY_CANDIDATES: usize = 64;

/// Each informative key contributes total mass one, divided over its binaries.
/// A truncated membership list is omitted: its apparent rarity is unknown.
pub(crate) struct BatchFamilyEvidence {
    memberships: BTreeMap<u128, Vec<[u8; 16]>>,
    ranked: Vec<([u8; 16], f64)>,
    mass: f64,
    influence: BTreeMap<[u8; 16], BinaryInfluence>,
}

#[derive(Default)]
struct BinaryInfluence {
    total: f64,
    count: usize,
    strongest: [Option<(u128, f64)>; 2],
}

impl BatchFamilyEvidence {
    pub(crate) fn new(rows: impl IntoIterator<Item = (u128, Vec<[u8; 16]>)>) -> Self {
        let mut memberships = BTreeMap::new();
        for (key, mut bins) in rows {
            bins.sort_unstable();
            bins.dedup();
            if !bins.is_empty() {
                memberships.entry(key).or_insert(bins);
            }
        }
        let mut influence = BTreeMap::<[u8; 16], BinaryInfluence>::new();
        for (key, bins) in &memberships {
            let weight = 1.0 / bins.len() as f64;
            for md5 in bins {
                let entry = influence.entry(*md5).or_default();
                entry.total += weight;
                entry.count += 1;
                if entry.strongest[0].is_none_or(|(_, w)| weight > w) {
                    entry.strongest[1] = entry.strongest[0];
                    entry.strongest[0] = Some((*key, weight));
                } else if entry.strongest[1].is_none_or(|(_, w)| weight > w) {
                    entry.strongest[1] = Some((*key, weight));
                }
            }
        }
        let mut ranked: Vec<_> = influence
            .iter()
            .map(|(md5, value)| (*md5, value.total))
            .collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Self {
            mass: memberships.len() as f64,
            memberships,
            ranked,
            influence,
        }
    }

    /// Complete query coverage keeps strict priority. For partial coverage,
    /// lower the score by its largest single remaining key contribution.
    /// This is a deterministic sensitivity bound, not statistical confidence.
    pub(crate) fn priority_floor(&self, key: u128, md5: &[u8; 16], weight: f64) -> f64 {
        let own = self.memberships.get(&key);
        let remaining = self.memberships.len() - usize::from(own.is_some());
        let Some(influence) = self.influence.get(md5).filter(|_| remaining > 0) else {
            return 0.0;
        };
        let own_match = own.is_some_and(|bins| bins.binary_search(md5).is_ok());
        if influence.count - usize::from(own_match) == remaining {
            return weight;
        }
        let largest = influence
            .strongest
            .iter()
            .flatten()
            .find(|(source, _)| *source != key)
            .map_or(0.0, |(_, w)| *w);
        (weight - largest / remaining as f64).max(0.0)
    }

    /// Leave the target out of both numerator and denominator. Retain the global
    /// top 64 plus up to 64 additional donors known to contain the target. Its
    /// membership admits candidates but contributes no evidence to their weight.
    /// O((D + C) log C + D log B) after sorting aggregate votes, for target degree
    /// D, per-list bound C and B distinct binaries. Omitted mass is not restored.
    pub(crate) fn excluding(&self, key: u128) -> HashMap<[u8; 16], f64> {
        use std::cmp::{Ordering, Reverse};
        use std::collections::BinaryHeap;
        #[derive(Clone, Copy, PartialEq)]
        struct Vote([u8; 16], f64);
        impl Eq for Vote {}
        impl PartialOrd for Vote {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for Vote {
            fn cmp(&self, other: &Self) -> Ordering {
                self.1
                    .total_cmp(&other.1)
                    .then_with(|| other.0.cmp(&self.0))
            }
        }
        fn retain_best(best: &mut BinaryHeap<Reverse<Vote>>, vote: Vote, limit: usize) {
            if best.len() < limit {
                best.push(Reverse(vote));
            } else if best.peek().is_some_and(|worst| vote > worst.0) {
                best.pop();
                best.push(Reverse(vote));
            }
        }
        let own = self.memberships.get(&key);
        let mass = self.mass - f64::from(own.is_some());
        if mass <= 0.0 {
            return HashMap::new();
        }
        let mut best = BinaryHeap::<Reverse<Vote>>::new();
        for &(md5, total) in &self.ranked {
            // Subtraction cannot increase a vote. Remaining totals are sorted.
            if best.len() == MAX_FAMILY_CANDIDATES
                && best.peek().is_some_and(|worst| Vote(md5, total) <= worst.0)
            {
                break;
            }
            let own_weight = own
                .filter(|bins| bins.binary_search(&md5).is_ok())
                .map_or(0.0, |bins| 1.0 / bins.len() as f64);
            let weight = (total - own_weight).max(0.0);
            if weight <= f64::EPSILON {
                continue;
            }
            retain_best(&mut best, Vote(md5, weight), MAX_FAMILY_CANDIDATES);
        }
        let mut selected: HashMap<_, _> = best
            .into_iter()
            .map(|Reverse(v)| (v.0, v.1 / mass))
            .collect();
        if let Some(own) = own.filter(|_| self.ranked.len() > MAX_FAMILY_CANDIDATES) {
            let mut additional = BinaryHeap::new();
            let own_weight = 1.0 / own.len() as f64;
            for md5 in own {
                if selected.contains_key(md5) {
                    continue;
                }
                let Some(influence) = self.influence.get(md5) else {
                    continue;
                };
                let weight = (influence.total - own_weight).max(0.0);
                if weight > f64::EPSILON {
                    retain_best(
                        &mut additional,
                        Vote(*md5, weight),
                        MAX_TARGET_FAMILY_CANDIDATES,
                    );
                }
            }
            selected.extend(additional.into_iter().map(|Reverse(v)| (v.0, v.1 / mass)));
        }
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_and_duplicate_keys_cannot_vote_for_themselves() {
        let rows = vec![(1, vec![[1; 16]]), (1, vec![[1; 16]]), (2, vec![[2; 16]])];
        let evidence = BatchFamilyEvidence::new(rows);
        assert_eq!(evidence.excluding(1), HashMap::from([([2; 16], 1.0)]));
        assert!(BatchFamilyEvidence::new([(1, vec![[1; 16]])])
            .excluding(1)
            .is_empty());
    }

    #[test]
    fn rare_keys_outweigh_ambiguous_keys_without_upload_counts() {
        let evidence =
            BatchFamilyEvidence::new([(1, vec![[1; 16], [2; 16], [3; 16]]), (2, vec![[2; 16]])]);
        let votes = evidence.excluding(99);
        assert!((votes[&[2; 16]] - 2.0 / 3.0).abs() < 1e-12);
        assert!((votes.values().sum::<f64>() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn target_membership_survives_unrelated_global_donors() {
        let evidence = BatchFamilyEvidence::new([
            (0, vec![[250; 16]]),
            (1, (0..64).map(|binary| [binary; 16]).collect()),
            (2, (128..=255).map(|binary| [binary; 16]).collect()),
        ]);
        let votes = evidence.excluding(0);
        assert_eq!(votes.len(), 65);
        for binary in 0..64 {
            assert!((votes[&[binary; 16]] - 1.0 / 128.0).abs() < 1e-12);
        }
        assert!((votes[&[250; 16]] - 1.0 / 256.0).abs() < 1e-12);
        assert!((votes.values().sum::<f64>() - (0.5 + 1.0 / 256.0)).abs() < 1e-12);
    }

    #[test]
    fn target_donor_expansion_is_bounded_ordered_and_excludes_self_evidence() {
        let mut rows = vec![
            (0, (127..=255).map(|binary| [binary; 16]).collect()),
            (1, (0..64).map(|binary| [binary; 16]).collect()),
            (2, (128..=255).map(|binary| [binary; 16]).collect()),
        ];
        let expected = BatchFamilyEvidence::new(rows.clone()).excluding(0);
        assert_eq!(expected.len(), 128);
        assert!(!expected.contains_key(&[127; 16]));
        for binary in 0..64 {
            assert!((expected[&[binary; 16]] - 1.0 / 128.0).abs() < 1e-12);
        }
        for binary in 128..192 {
            assert!((expected[&[binary; 16]] - 1.0 / 256.0).abs() < 1e-12);
        }
        assert!((expected.values().sum::<f64>() - 0.75).abs() < 1e-12);
        rows.reverse();
        for (_, bins) in &mut rows {
            bins.reverse();
        }
        rows.push(rows[0].clone());
        assert_eq!(BatchFamilyEvidence::new(rows).excluding(0), expected);
    }

    #[test]
    fn bounded_selection_matches_exhaustive_leave_one_out() {
        let rows: Vec<_> = (0u128..100)
            .map(|key| {
                (
                    key,
                    (0u8..120)
                        .filter(|b| (u128::from(*b) + key) % 7 < 3)
                        .map(|b| [b; 16])
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let evidence = BatchFamilyEvidence::new(rows.clone());
        for target in 0..100 {
            let mut oracle = BTreeMap::<[u8; 16], f64>::new();
            for (key, bins) in &rows {
                if *key != target {
                    for md5 in bins {
                        *oracle.entry(*md5).or_default() += 1.0 / bins.len() as f64;
                    }
                }
            }
            let mut oracle: Vec<_> = oracle.into_iter().collect();
            oracle.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let actual = evidence.excluding(target);
            let mut expected: HashMap<_, _> =
                oracle.iter().copied().take(MAX_FAMILY_CANDIDATES).collect();
            let own = &rows[target as usize].1;
            let additional: Vec<_> = oracle
                .iter()
                .copied()
                .filter(|(md5, weight)| {
                    *weight > f64::EPSILON && own.contains(md5) && !expected.contains_key(md5)
                })
                .take(MAX_TARGET_FAMILY_CANDIDATES)
                .collect();
            expected.extend(additional);
            assert_eq!(actual.len(), expected.len());
            for (md5, weight) in expected {
                assert!((actual[&md5] - weight / 99.0).abs() < 1e-12);
            }
        }
    }

    #[test]
    fn priority_floor_matches_exhaustive_single_key_influence() {
        let rows: Vec<_> = (0u128..25)
            .map(|key| {
                (
                    key,
                    (0u8..12)
                        .filter(|b| *b == 0 || (u128::from(*b) + key) % 5 < 2)
                        .map(|b| [b; 16])
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let evidence = BatchFamilyEvidence::new(rows.clone());
        for target in 0..26 {
            let others: Vec<_> = rows.iter().filter(|(key, _)| *key != target).collect();
            for (md5, weight) in evidence.excluding(target) {
                let contributions: Vec<_> = others
                    .iter()
                    .map(|(_, bins)| {
                        if bins.contains(&md5) {
                            1.0 / bins.len() as f64
                        } else {
                            0.0
                        }
                    })
                    .collect();
                let complete = contributions.iter().all(|w| *w > 0.0);
                let oracle = if complete {
                    weight
                } else {
                    (weight
                        - contributions.iter().copied().fold(0.0, f64::max) / others.len() as f64)
                        .max(0.0)
                };
                assert!((evidence.priority_floor(target, &md5, weight) - oracle).abs() < 1e-12);
            }
        }
        let one = BatchFamilyEvidence::new([(1, vec![[1; 16]])]);
        assert_eq!(one.priority_floor(1, &[1; 16], 0.0), 0.0);
        let sparse = BatchFamilyEvidence::new([(1, vec![[1; 16]]), (2, vec![[2; 16]])]);
        assert_eq!(sparse.priority_floor(99, &[1; 16], 0.5), 0.0);
    }
}
