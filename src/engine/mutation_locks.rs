//! Bounded in-process serialization for a key's multi-store mutation sequence.
use parking_lot::{Mutex, MutexGuard};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

const STRIPES: usize = 1024;

pub(crate) struct MutationLocks {
    hash: RandomState,
    locks: [Mutex<()>; STRIPES],
}

impl Default for MutationLocks {
    fn default() -> Self {
        Self {
            hash: RandomState::new(),
            locks: std::array::from_fn(|_| Mutex::new(())),
        }
    }
}

impl MutationLocks {
    fn stripe(&self, key: u128) -> usize {
        self.hash.hash_one(key) as usize % STRIPES
    }

    /// Acquire before reading the current head; keep through derived updates.
    /// Hold one key at a time, on a blocking worker, with no await inside.
    pub(crate) fn lock(&self, key: u128) -> MutexGuard<'_, ()> {
        self.locks[self.stripe(key)].lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_is_exclusive_while_other_stripes_can_progress() {
        let locks = MutationLocks::default();
        let key = 0x1234;
        let stripe = locks.stripe(key);
        let guard = locks.lock(key);
        assert!(locks.locks[stripe].try_lock().is_none());
        let other = (0..10_000u128)
            .find(|key| locks.stripe(*key) != stripe)
            .unwrap();
        let other_guard = locks.locks[locks.stripe(other)].try_lock().unwrap();
        drop(other_guard);
        drop(guard);
        assert!(locks.locks[stripe].try_lock().is_some());
    }
}
