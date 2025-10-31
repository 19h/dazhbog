use std::sync::atomic::{AtomicU64, Ordering};
use crate::engine::spin::SpinLock;
use crate::util::key_tag;

#[derive(Debug)]
pub struct Slot {
    pub tag: AtomicU64,  // 0 means empty
    pub addr: AtomicU64, // 0 means empty
}

pub struct Shard {
    lock: SpinLock,
    mask: usize,
    slots: Box<[Slot]>,
}

pub struct ShardedIndex {
    shards: Box<[Shard]>,
    shard_mask: usize,
}

impl ShardedIndex {
    pub fn new(capacity: usize, shard_count: usize) -> Self {
        assert!(capacity.is_power_of_two(), "index_capacity must be power of two");
        assert!(shard_count.is_power_of_two(), "shard_count must be power of two");
        let per = capacity / shard_count;
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            let n = per.max(1024).next_power_of_two();
            let mask = n - 1;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(Slot { tag: AtomicU64::new(0), addr: AtomicU64::new(0) });
            }
            shards.push(Shard { lock: SpinLock::new(), mask, slots: v.into_boxed_slice() });
        }
        Self { shards: shards.into_boxed_slice(), shard_mask: shard_count - 1 }
    }

    #[inline]
    fn shard_index(&self, tag: u64) -> usize { (tag as usize) & self.shard_mask }

    pub fn get(&self, key: u128) -> u64 {
        let tag = key_tag(key);
        let sidx = self.shard_index(tag);
        let shard = &self.shards[sidx];
        let mask = shard.mask;
        let mut idx = (tag as usize) & mask;
        let slots = &shard.slots;
        for _ in 0..=mask {
            let t = slots[idx].tag.load(Ordering::Acquire);
            if t == 0 { return 0; }
            if t == tag {
                let a = slots[idx].addr.load(Ordering::Acquire);
                if a != 0 { return a; }
            }
            idx = (idx + 1) & mask;
        }
        0
    }

    pub fn upsert(&self, key: u128, addr: u64) -> Option<u64> {
        let tag = key_tag(key);
        let sidx = self.shard_index(tag);
        let shard = &self.shards[sidx];
        let _g = shard.lock.lock();
        let mask = shard.mask;
        let mut idx = (tag as usize) & mask;
        let slots = &shard.slots;
        for _ in 0..=mask {
            let t = slots[idx].tag.load(Ordering::Acquire);
            if t == 0 || t == tag {
                if t == 0 {
                    slots[idx].tag.store(tag, Ordering::Release);
                }
                let old = slots[idx].addr.swap(addr, Ordering::AcqRel);
                return if old == 0 { None } else { Some(old) };
            }
            idx = (idx + 1) & mask;
        }
        // Should not happen with safe load factor; last resort overwrite
        let old = slots[idx].addr.swap(addr, Ordering::AcqRel);
        Some(old)
    }

    pub fn delete(&self, key: u128) -> Option<u64> {
        let tag = key_tag(key);
        let sidx = self.shard_index(tag);
        let shard = &self.shards[sidx];
        let _g = shard.lock.lock();
        let mask = shard.mask;
        let mut idx = (tag as usize) & mask;
        let slots = &shard.slots;
        for _ in 0..=mask {
            let t = slots[idx].tag.load(Ordering::Acquire);
            if t == 0 { return None; }
            if t == tag {
                let old = slots[idx].addr.swap(0, Ordering::AcqRel);
                return if old == 0 { None } else { Some(old) };
            }
            idx = (idx + 1) & mask;
        }
        None
    }
}
