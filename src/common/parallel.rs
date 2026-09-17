//! Bounded fan-out for read scans over the embedded store.
//!
//! A neighbourhood scan visits thousands of independent keys, and the store is
//! a synchronous embedded engine: the work is bound by point reads, not by one
//! core. These helpers spread such a scan over scoped threads, so a scan never
//! outlives its caller and never allocates a pool per request.

use std::cell::Cell;
use std::io;
use std::num::NonZeroUsize;
use std::sync::OnceLock;

thread_local! {
    /// Set while a scan worker runs, so a scan started from inside another one
    /// stays on its worker instead of multiplying the fan-out.
    static IN_SCAN: Cell<bool> = const { Cell::new(false) };
}

/// Marks its thread as running a scan worker for as long as it lives.
struct ScanGuard(bool);

impl ScanGuard {
    fn enter() -> Self {
        Self(IN_SCAN.replace(true))
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        IN_SCAN.set(self.0);
    }
}

/// Threads a single scan may use. Reads are cheap individually, so the aim is
/// to saturate the store without starving the runtime that serves requests.
///
/// `DAZHBOG_SCAN_THREADS` overrides the default for a deployment that wants a
/// tighter bound; `1` makes every scan run on the calling thread.
fn scan_threads() -> usize {
    static THREADS: OnceLock<usize> = OnceLock::new();
    *THREADS.get_or_init(|| {
        std::env::var("DAZHBOG_SCAN_THREADS")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .filter(|threads| *threads > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(NonZeroUsize::get)
                    .unwrap_or(1)
            })
            .clamp(1, 16)
    })
}

/// Whether this thread is already running a scan worker.
///
/// A caller that would otherwise block on async work uses this to stay
/// sequential instead: see the nesting note on [`map_chunks_offthread`].
pub fn in_scan_worker() -> bool {
    IN_SCAN.get()
}

/// Split `items` into at most one chunk per scan thread, each at least
/// `min_chunk` long, and run `worker` over every chunk.
///
/// Results are returned in chunk order. A worker panic surfaces as an error
/// instead of unwinding the caller, so one bad key cannot take down a request.
/// A single chunk runs on the calling thread, with no thread spawned at all.
pub fn map_chunks<T, R, F>(items: &[T], min_chunk: usize, worker: F) -> io::Result<Vec<R>>
where
    T: Sync,
    R: Send,
    F: Fn(&[T]) -> io::Result<R> + Sync,
{
    map_chunks_inner(items, min_chunk, false, worker)
}

/// Like [`map_chunks`], but never runs a worker on the calling thread.
///
/// Use it when a worker blocks on async work: the caller may be a runtime
/// thread, and blocking one of those from inside the runtime panics.
///
/// Such a worker must not be reachable from inside another one: blocking on
/// async work enters the runtime on its thread, a nested scan folds into that
/// same thread, and blocking there a second time panics. Work that a scan
/// worker can reach therefore resolves its async parts outside the scan, as
/// coverage does.
pub fn map_chunks_offthread<T, R, F>(items: &[T], min_chunk: usize, worker: F) -> io::Result<Vec<R>>
where
    T: Sync,
    R: Send,
    F: Fn(&[T]) -> io::Result<R> + Sync,
{
    map_chunks_inner(items, min_chunk, true, worker)
}

fn map_chunks_inner<T, R, F>(
    items: &[T],
    min_chunk: usize,
    offthread: bool,
    worker: F,
) -> io::Result<Vec<R>>
where
    T: Sync,
    R: Send,
    F: Fn(&[T]) -> io::Result<R> + Sync,
{
    let min_chunk = min_chunk.max(1);
    let threads = scan_threads().min(items.len().div_ceil(min_chunk)).max(1);
    // A nested scan is already running on a worker: fanning out again would
    // multiply threads per request, and the worker is off the runtime anyway.
    let nested = IN_SCAN.get();
    if nested || ((threads == 1 || items.is_empty()) && !offthread) {
        let _guard = ScanGuard::enter();
        return Ok(vec![worker(items)?]);
    }
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        // `chunks` yields nothing for an empty input, which an off-thread
        // caller still expects to see answered once.
        let slices: Vec<&[T]> = if items.is_empty() {
            vec![items]
        } else {
            items.chunks(chunk).collect()
        };
        let worker = &worker;
        let handles: Vec<_> = slices
            .into_iter()
            .map(|slice| {
                scope.spawn(move || {
                    let _guard = ScanGuard::enter();
                    worker(slice)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| io::Error::other("parallel scan worker panicked"))?
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_cover_every_item_once_and_keep_order() {
        let items: Vec<usize> = (0..1000).collect();
        for min_chunk in [1usize, 7, 4096] {
            let parts = map_chunks(&items, min_chunk, |chunk| Ok(chunk.to_vec())).unwrap();
            assert_eq!(parts.concat(), items, "min_chunk {min_chunk}");
        }
        assert_eq!(
            map_chunks::<usize, usize, _>(&[], 4, |chunk| Ok(chunk.len())).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn a_nested_scan_stays_on_its_worker() {
        let items: Vec<usize> = (0..64).collect();
        let outer = map_chunks(&items, 1, |chunk| {
            let worker = std::thread::current().id();
            // Both entry points must fold into the running worker.
            let inner = map_chunks(chunk, 1, |inner| {
                assert_eq!(std::thread::current().id(), worker);
                Ok(inner.len())
            })?;
            let offthread = map_chunks_offthread(chunk, 1, |inner| {
                assert_eq!(std::thread::current().id(), worker);
                Ok(inner.len())
            })?;
            assert_eq!(inner.len(), 1, "a nested scan fanned out again");
            assert_eq!(offthread.len(), 1, "a nested scan fanned out again");
            Ok(chunk.len())
        })
        .unwrap();
        assert_eq!(outer.iter().sum::<usize>(), items.len());
        // The guard is unwound, so a later scan fans out as usual.
        assert!(
            map_chunks(&items, 1, |chunk| Ok(chunk.len()))
                .unwrap()
                .len()
                > 1
        );
    }

    #[test]
    fn offthread_chunks_never_run_on_the_caller() {
        let caller = std::thread::current().id();
        let items: Vec<usize> = (0..10).collect();
        for input in [&items[..], &[][..]] {
            let threads = map_chunks_offthread(input, 4, |chunk| {
                assert_ne!(std::thread::current().id(), caller);
                Ok(chunk.len())
            })
            .unwrap();
            assert_eq!(threads.iter().sum::<usize>(), input.len());
        }
    }

    #[test]
    fn worker_failure_and_panic_reach_the_caller() {
        let items: Vec<usize> = (0..64).collect();
        let err = map_chunks(&items, 1, |chunk| {
            if chunk.contains(&0) {
                return Err(io::Error::other("nope"));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "nope");
        let panicked = map_chunks(&items, 1, |chunk| {
            assert!(!chunk.contains(&0), "worker panic");
            Ok(())
        })
        .unwrap_err();
        assert!(panicked.to_string().contains("panicked"));
    }
}
