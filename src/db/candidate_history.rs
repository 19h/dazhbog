//! Bounded historical hints when a query binary or inferred donor has a stale
//! last-observation pointer. Hints never bypass validated live-history traversal.
use super::{version_observed_in, AnalyzedVersion, EngineRuntime, QueryContext};
use std::collections::{HashMap, HashSet};
use std::io;

const MAX_EXPLICIT_HISTORY_ROWS: usize = 64;
const MAX_INFERRED_HISTORY_ROWS: usize = 64;

pub(super) fn historical_targets(
    rt: &EngineRuntime,
    key: u128,
    versions: &[AnalyzedVersion],
    weights: &HashMap<[u8; 16], f64>,
    last_versions: &HashMap<[u8; 16], [u8; 32]>,
    ctx: &QueryContext<'_>,
    withheld: Option<[u8; 16]>,
) -> io::Result<HashSet<[u8; 32]>> {
    let mut targets = HashSet::new();
    if versions.is_empty() {
        return Ok(targets);
    }
    let retrieved = |id: &[u8; 32]| versions.iter().any(|version| version.matches_id(id));
    let has_last = |md5: &[u8; 16]| last_versions.get(md5).is_some_and(retrieved);
    let explicit = ctx.md5.filter(|_| withheld.is_none());
    if let Some(md5) = explicit {
        if has_last(&md5) {
            return Ok(targets);
        }
        targets.extend(
            rt.ctx_index
                .binary_function_versions(&md5, key, MAX_EXPLICIT_HISTORY_ROWS)?
                .into_iter()
                .filter(|id| !retrieved(id)),
        );
        // Known explicit history will exclude inferred-only candidates anyway.
        for version in versions {
            if version_observed_in(rt, version, &md5)? {
                return Ok(targets);
            }
        }
    }

    let mut donors: Vec<_> = weights
        .iter()
        .filter(|(md5, weight)| {
            Some(**md5) != withheld && Some(**md5) != explicit && **weight > 0.0
        })
        .collect();
    donors.sort_unstable_by(|(a, aw), (b, bw)| bw.total_cmp(aw).then_with(|| a.cmp(b)));
    let mut remaining = MAX_INFERRED_HISTORY_ROWS;
    for (md5, _) in donors {
        if remaining == 0 {
            break;
        }
        if has_last(md5) {
            continue;
        }
        let rows = rt.ctx_index.binary_function_versions(md5, key, remaining)?;
        // Charge physical rows, including aliases, already retrieved IDs and
        // hints that later prove unavailable. The budget is shared by all donors.
        remaining -= rows.len();
        targets.extend(rows.into_iter().filter(|id| !retrieved(id)));
    }
    Ok(targets)
}
