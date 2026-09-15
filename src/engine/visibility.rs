use super::{ContextIndex, OpenSegments, Record, ShardedIndex};
use crate::common::hash::version_id;
use crate::db::semantic::is_rejected_function_name;
use std::{collections::HashSet, io};

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
    } else { None };
    let mut addr = index.get(key);
    let mut seen = HashSet::new();
    let mut newest = None;
    while addr != 0 {
        if !seen.insert(addr) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cyclic record history"));
        }
        let rec = segments.read_record(addr)?;
        if rec.key != key {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "history key mismatch"));
        }
        if rec.flags & 1 != 0 { break; }
        addr = rec.prev_addr;
        if is_rejected_function_name(&rec.name) { continue; }
        if preferred.is_none() || preferred == Some(version_id(key, &rec.name, &rec.data)) {
            return Ok(Some(rec));
        }
        if newest.is_none() { newest = Some(rec); }
    }
    Ok(newest)
}
