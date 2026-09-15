use super::{ContextIndex, OpenSegments, Record, ShardedIndex};
use crate::common::hash::version_id_matches;
use crate::db::semantic::is_rejected_function_name;
use std::{collections::HashSet, io};

pub(crate) const MAX_HISTORY_RECORDS: usize = 4096;

fn incomplete_history(
    newest: Option<Record>,
    key: u128,
    address: u64,
    error: io::Error,
) -> io::Result<Option<Record>> {
    if newest.is_some() {
        log::warn!("canonical history incomplete key={key:032x} address={address:016x}; using validated newest live record: {error}");
        Ok(newest)
    } else {
        Err(error)
    }
}

/// Resolve within one live history interval. A tombstone terminates that interval.
/// Work and visited-address memory are O(R) for R traversed records.
pub fn resolve_visible_record(
    segments: &OpenSegments,
    index: &ShardedIndex,
    context: &ContextIndex,
    key: u128,
    canonical: bool,
) -> io::Result<Option<Record>> {
    let preferred = if canonical {
        context.get_canonical_version(key)?.map(|v| v.version_id)
    } else {
        None
    };
    let mut addr = index.try_get(key)?;
    let mut seen = HashSet::new();
    let mut newest = None;
    while addr != 0 {
        if seen.len() >= MAX_HISTORY_RECORDS {
            return incomplete_history(
                newest,
                key,
                addr,
                io::Error::other("canonical history traversal limit exceeded"),
            );
        }
        if !seen.insert(addr) {
            return incomplete_history(
                newest,
                key,
                addr,
                io::Error::new(io::ErrorKind::InvalidData, "cyclic record history"),
            );
        }
        let rec = match segments.read_record(addr) {
            Ok(rec) => rec,
            Err(error) => return incomplete_history(newest, key, addr, error),
        };
        if rec.key != key {
            return incomplete_history(
                newest,
                key,
                addr,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                    "history key mismatch: requested={key:032x} stored={:032x} address={addr:016x}",
                    rec.key
                ),
                ),
            );
        }
        if rec.flags & 1 != 0 {
            break;
        }
        addr = rec.prev_addr;
        if is_rejected_function_name(&rec.name) {
            continue;
        }
        if preferred.is_none_or(|id| version_id_matches(&id, key, &rec.name, &rec.data)) {
            return Ok(Some(rec));
        }
        if newest.is_none() {
            newest = Some(rec);
        }
    }
    Ok(newest)
}
