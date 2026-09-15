//! Bounded process-local coverage cache. Persisted legacy facets are not trusted.
use crate::db::BinaryFacetSummary;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

const CAPACITY: usize = 64;
pub(crate) const MAX_FACET_KEYS: usize = 8192;

struct Entry {
    limit: usize,
    keys: HashSet<u128>,
    summary: BinaryFacetSummary,
}

#[derive(Default)]
struct State {
    generation: u64,
    writers: usize,
    disabled: bool,
    entries: HashMap<[u8; 16], Entry>,
    recent: VecDeque<[u8; 16]>,
}

#[derive(Default)]
pub(crate) struct FacetCache(Mutex<State>);

pub(crate) struct FacetMutation {
    cache: Arc<FacetCache>,
}

impl Drop for FacetMutation {
    fn drop(&mut self) {
        let mut state = self.cache.0.lock();
        state.writers = state.writers.saturating_sub(1);
    }
}

impl FacetCache {
    pub fn begin_mutation(
        self: &Arc<Self>,
        key: Option<u128>,
        binary: Option<[u8; 16]>,
    ) -> FacetMutation {
        let mut state = self.0.lock();
        state.generation = state.generation.saturating_add(1);
        state.writers = state.writers.saturating_add(1);
        if state.generation == u64::MAX || state.writers == usize::MAX {
            // Disable caching until restart instead of allowing a token to wrap.
            state.disabled = true;
            state.entries.clear();
            state.recent.clear();
        }
        state.entries.retain(|md5, entry| {
            binary != Some(*md5) && !key.is_some_and(|key| entry.keys.contains(&key))
        });
        let valid: HashSet<_> = state.entries.keys().copied().collect();
        state.recent.retain(|md5| valid.contains(md5));
        FacetMutation {
            cache: self.clone(),
        }
    }

    /// Existing unaffected entries remain usable during unrelated mutations.
    pub fn get(&self, md5: &[u8; 16], limit: Option<usize>) -> Option<BinaryFacetSummary> {
        let mut state = self.0.lock();
        if state.disabled {
            return None;
        }
        let entry = state.entries.get(md5)?;
        if limit.is_some_and(|limit| limit != entry.limit) {
            return None;
        }
        let summary = entry.summary.clone();
        state.recent.retain(|id| id != md5);
        state.recent.push_back(*md5);
        Some(summary)
    }

    pub fn read_token(&self) -> Option<u64> {
        let state = self.0.lock();
        (!state.disabled && state.writers == 0).then_some(state.generation)
    }

    pub fn publish(
        &self,
        md5: [u8; 16],
        limit: usize,
        token: Option<u64>,
        keys: Vec<u128>,
        summary: BinaryFacetSummary,
    ) -> bool {
        if keys.len() > MAX_FACET_KEYS {
            return false;
        }
        let mut state = self.0.lock();
        if state.disabled || state.writers != 0 || token != Some(state.generation) {
            return false;
        }
        state.entries.insert(
            md5,
            Entry {
                limit,
                keys: keys.into_iter().collect(),
                summary,
            },
        );
        state.recent.retain(|id| *id != md5);
        state.recent.push_back(md5);
        if state.entries.len() > CAPACITY {
            if let Some(oldest) = state.recent.pop_front() {
                state.entries.remove(&oldest);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(cache: &FacetCache, md5: u8, key: u128) {
        assert!(cache.publish(
            [md5; 16],
            10,
            cache.read_token(),
            vec![key],
            BinaryFacetSummary::default()
        ));
    }

    #[test]
    fn mutations_invalidate_dependencies_and_fence_publication() {
        let cache = Arc::new(FacetCache::default());
        insert(&cache, 1, 11);
        insert(&cache, 2, 22);
        let old_token = cache.read_token();
        let first = cache.begin_mutation(Some(11), None);
        let second = cache.begin_mutation(None, Some([3; 16]));
        assert!(cache.get(&[1; 16], None).is_none());
        assert!(cache.get(&[2; 16], Some(10)).is_some());
        assert!(cache.read_token().is_none());
        drop(first);
        assert!(!cache.publish(
            [1; 16],
            10,
            old_token,
            vec![11],
            BinaryFacetSummary::default()
        ));
        drop(second);
        assert!(!cache.publish(
            [1; 16],
            10,
            old_token,
            vec![11],
            BinaryFacetSummary::default()
        ));
        insert(&cache, 1, 11);
        assert!(cache.get(&[1; 16], Some(9)).is_none());
        let binary_change = cache.begin_mutation(Some(99), Some([1; 16]));
        assert!(cache.get(&[1; 16], None).is_none());
        drop(binary_change);
    }

    #[test]
    fn error_exit_releases_publication_fence() {
        let cache = Arc::new(FacetCache::default());
        let fail = || -> Result<(), ()> {
            let _guard = cache.begin_mutation(Some(1), None);
            Err(())
        };
        assert!(fail().is_err());
        insert(&cache, 1, 1);
    }

    #[test]
    fn capacity_and_overflow_are_bounded() {
        let cache = Arc::new(FacetCache::default());
        for i in 0..64 {
            insert(&cache, i, u128::from(i));
        }
        assert!(cache.get(&[0; 16], None).is_some());
        insert(&cache, 64, 64);
        assert!(cache.get(&[1; 16], None).is_none());
        assert!(cache.get(&[0; 16], None).is_some());
        assert!(!cache.publish(
            [65; 16],
            9000,
            cache.read_token(),
            vec![0; 8193],
            BinaryFacetSummary::default()
        ));
        cache.0.lock().generation = u64::MAX - 1;
        drop(cache.begin_mutation(None, None));
        assert!(cache.read_token().is_none());
        assert!(cache.get(&[0; 16], None).is_none());
    }
}
