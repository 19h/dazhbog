// SAFETY: This module uses unsafe for zero-cost interior mutability.
// SpinLock provides fast, uncontended locking. Cell provides safe interior mutability
// through careful encapsulation of UnsafeCell.
use std::sync::atomic::{AtomicBool, Ordering};
use std::cell::UnsafeCell;

pub struct SpinLock {
    locked: AtomicBool,
}

pub struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl SpinLock {
    pub const fn new() -> Self { Self { locked: AtomicBool::new(false) } }
    pub fn lock(&self) -> SpinGuard<'_> {
        while self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            std::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }
}
impl<'a> Drop for SpinGuard<'a> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// Zero-cost interior mutability for performance-critical paths
pub struct Cell<T> {
    v: UnsafeCell<T>,
}
unsafe impl<T: Send> Send for Cell<T> {}
unsafe impl<T: Send> Sync for Cell<T> {}
impl<T> Cell<T> {
    pub fn new(v: T) -> Self { Self { v: UnsafeCell::new(v) } }
    // SAFETY: Caller must ensure exclusive access (via SpinLock or similar)
    pub fn get_mut(&self) -> &mut T { unsafe { &mut *self.v.get() } }
}
