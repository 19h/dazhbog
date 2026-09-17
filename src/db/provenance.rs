//! Whether a stored name is credible for the requesting binary.
//!
//! A name stored for a pattern came from some program. Serving it to another
//! program is right only when that program is plausibly the same code: the
//! query explicitly identifies a binary that carries the name, a donor of the
//! name is substantially covered by the request (an older build of the same
//! application), or the name was observed independently by several unrelated
//! programs (library code). A name whose only observers are one program
//! family is that program's, and an unrelated requester is declined.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::engine::EngineRuntime;

use super::family::BatchFamilyEvidence;
use super::pattern::Provenance;

/// Keys sampled from the smaller of two binaries to estimate their overlap.
const FAMILY_PROBE_KEYS: usize = 64;
/// Point reads one request may spend on family probes before every further
/// pair is treated as unknown.
const FAMILY_PROBE_BUDGET: usize = 32_768;

pub(super) struct ProvenanceGate<'a> {
    rt: &'a EngineRuntime,
    /// Fraction of each donor's functions that the request's rare keys cover.
    coverage: HashMap<[u8; 16], f64>,
    /// Whether two binaries are one program family, memoized per request.
    related: RefCell<HashMap<([u8; 16], [u8; 16]), bool>>,
    probes: Cell<usize>,
}

impl<'a> ProvenanceGate<'a> {
    pub(super) fn new(rt: &'a EngineRuntime, family: &BatchFamilyEvidence) -> Self {
        let mut coverage = HashMap::new();
        for (md5, rare) in family.rare_counts() {
            if let Ok(Some(meta)) = rt.ctx_index.get_binary_meta(&md5) {
                if meta.function_count > 0 {
                    coverage.insert(md5, rare as f64 / meta.function_count as f64);
                }
            }
        }
        Self {
            rt,
            coverage,
            related: RefCell::new(HashMap::new()),
            probes: Cell::new(0),
        }
    }

    /// Judge a name observed by `observers` (strongest first) for a request
    /// whose own binary, when named, is already known to observe it.
    pub(super) fn check(
        &self,
        key: u128,
        observers: &[[u8; 16]],
        explicit: Option<[u8; 16]>,
    ) -> Provenance {
        if let Some(md5) = explicit {
            return Provenance::Explicit {
                md5_hex: hex(&md5),
            };
        }
        // An observation that echoed a served answer is not a witness.
        let observers: Vec<[u8; 16]> = observers
            .iter()
            .copied()
            .filter(|md5| !self.rt.ctx_index.is_echo(key, md5).unwrap_or(false))
            .collect();
        let observers = observers.as_slice();
        if observers.is_empty() {
            return Provenance::Unchecked;
        }
        let threshold = self.rt.scoring.related_donor_coverage;
        let related = observers
            .iter()
            .filter_map(|md5| self.coverage.get(md5).map(|c| (*md5, *c)))
            .filter(|(_, c)| *c >= threshold)
            .max_by(|a, b| a.1.total_cmp(&b.1));
        if let Some((md5, coverage)) = related {
            return Provenance::RelatedDonor {
                md5_hex: hex(&md5),
                coverage,
            };
        }
        let families = self.count_families(observers);
        if families >= self.rt.scoring.library_min_families {
            return Provenance::Library { families };
        }
        let home = self
            .rt
            .ctx_index
            .get_binary_meta(&observers[0])
            .ok()
            .flatten()
            .map(|meta| basename_only(&meta.basename))
            .unwrap_or_else(|| hex(&observers[0]));
        Provenance::Foreign { home, families }
    }

    /// Greedy clustering of observers into program families; an observer
    /// joins the first family whose representative shares enough of its
    /// functions, and an unknown relation joins rather than founds one.
    fn count_families(&self, observers: &[[u8; 16]]) -> usize {
        let mut representatives: Vec<[u8; 16]> = Vec::new();
        for observer in observers {
            let joins = representatives
                .iter()
                .any(|rep| self.same_family(rep, observer));
            if !joins {
                representatives.push(*observer);
            }
        }
        representatives.len()
    }

    fn same_family(&self, a: &[u8; 16], b: &[u8; 16]) -> bool {
        if a == b {
            return true;
        }
        let pair = if a < b { (*a, *b) } else { (*b, *a) };
        if let Some(known) = self.related.borrow().get(&pair) {
            return *known;
        }
        let verdict = self.probe_family(a, b).unwrap_or(true);
        self.related.borrow_mut().insert(pair, verdict);
        verdict
    }

    /// `Some(true)` when a sample of the smaller binary's functions is mostly
    /// present in the larger one; `None` when it cannot be told.
    fn probe_family(&self, a: &[u8; 16], b: &[u8; 16]) -> Option<bool> {
        let size = |md5: &[u8; 16]| {
            self.rt
                .ctx_index
                .get_binary_meta(md5)
                .ok()
                .flatten()
                .map(|meta| meta.function_count)
        };
        let (small, large) = match (size(a)?, size(b)?) {
            (sa, sb) if sa <= sb => (a, b),
            _ => (b, a),
        };
        if self.probes.get() + FAMILY_PROBE_KEYS > FAMILY_PROBE_BUDGET {
            return None;
        }
        let sample = self
            .rt
            .ctx_index
            .get_binary_function_keys(small, FAMILY_PROBE_KEYS)
            .ok()?;
        if sample.is_empty() {
            return None;
        }
        self.probes.set(self.probes.get() + sample.len());
        let mut shared = 0usize;
        for key in &sample {
            if self
                .rt
                .ctx_index
                .binary_contains_function(large, *key)
                .ok()?
            {
                shared += 1;
            }
        }
        Some(shared as f64 / sample.len() as f64 >= self.rt.scoring.family_overlap)
    }
}

fn hex(md5: &[u8; 16]) -> String {
    md5.iter().map(|b| format!("{b:02x}")).collect()
}

fn basename_only(name: &str) -> String {
    name.rsplit(['/', '\\']).next().unwrap_or(name).to_string()
}
