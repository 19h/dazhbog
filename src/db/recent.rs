//! Recent-submission feeds for the dashboard: the newest currently visible
//! function versions in physical append order, and binaries ordered by their
//! observation timestamps. Neither feed is a search or selection path.
use super::database::{basename_only, binary_summary_from_meta, hex_md5, short_md5};
use super::semantic::is_rejected_function_name_with;
use super::types::{BinarySummary, RecentBinaryOrder, RecentFunction, RecentScanStats};
use super::Database;
use crate::common::demangle::demangle;
use crate::common::{addr_off, addr_seg};
use crate::engine::{BinaryRefHit, EngineRuntime, MAX_HISTORY_RECORDS, REC_FLAG_DELETED};
use std::collections::{HashMap, HashSet};
use std::io;

/// Physical rows one recent-function scan may visit, including skipped rows.
pub const RECENT_FUNCTIONS_SCAN_BOUND: u64 = 4096;
/// Binary references attached to each recent function.
const RECENT_BINARY_REFS: usize = 12;

impl Database {
    /// The newest `limit` function versions that are currently visible, in
    /// reverse physical append order (descending segment, then offset).
    ///
    /// Each key appears at most once, at the physical row of its visible latest
    /// record: the first accepted-name record on the latest-pointer chain, as
    /// `get_latest` resolves it. A key whose newest physical row is a tombstone
    /// is hidden. A rejected-name or stale (not on the chain) newer row does not
    /// hide the older visible row of the same key; a chain that is missing,
    /// cyclic, cross-key, unreadable or longer than the traversal bound omits
    /// the key. At most `scan_bound` physical rows are visited;
    /// `RecentScanStats::truncated` reports that bound ending the scan early.
    /// Work is O(min(S, bound)) row reads plus, per first-seen key, one latest
    /// lookup and a chain walk that is normally zero reads (the row is the head)
    /// and at most `MAX_HISTORY_RECORDS` reads otherwise, plus one bounded
    /// binary-reference lookup per emitted item, for S physical rows. Memory is
    /// O(limit + visited keys).
    pub async fn recent_functions(
        &self,
        limit: usize,
    ) -> io::Result<(Vec<RecentFunction>, RecentScanStats)> {
        let rt = self.rt.clone();
        tokio::task::spawn_blocking(move || {
            Self::recent_functions_bounded(&rt, limit, RECENT_FUNCTIONS_SCAN_BOUND)
        })
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking: {e}")))?
    }

    pub(crate) fn recent_functions_bounded(
        rt: &EngineRuntime,
        limit: usize,
        scan_bound: u64,
    ) -> io::Result<(Vec<RecentFunction>, RecentScanStats)> {
        let mut stats = RecentScanStats::default();
        let mut items = Vec::new();
        if limit == 0 {
            return Ok((items, stats));
        }
        // Keys already resolved, and resolved keys whose visible row is older
        // than the row first encountered (rejected-name or stale newer rows).
        let mut seen: HashSet<u128> = HashSet::new();
        let mut wanted: HashMap<u128, u64> = HashMap::new();
        let mut failure: Option<io::Error> = None;
        rt.segments
            .for_each_record_newest_first(|seg, offset, rec| {
                if stats.scanned_records >= scan_bound {
                    stats.truncated = true;
                    return false;
                }
                stats.scanned_records += 1;
                let rec = match rec {
                    Ok(rec) => rec,
                    Err(e) => {
                        stats.invalid_records += 1;
                        log::debug!("recent scan skipped seg={seg} offset={offset}: {e}");
                        return true;
                    }
                };
                if let Some(&visible) = wanted.get(&rec.key) {
                    if !same_row(visible, seg, offset) {
                        return true;
                    }
                    wanted.remove(&rec.key);
                } else {
                    if !seen.insert(rec.key) {
                        return true;
                    }
                    if rec.flags & REC_FLAG_DELETED != 0 {
                        // The key's newest row is a tombstone: the key is hidden.
                        return true;
                    }
                    let head = match rt.index.try_get(rec.key) {
                        Ok(head) => head,
                        Err(e) => {
                            failure = Some(e);
                            return false;
                        }
                    };
                    let accepted =
                        !is_rejected_function_name_with(rt.cfg.name_rejection, &rec.name);
                    let visible = if head != 0 && same_row(head, seg, offset) && accepted {
                        Some(head)
                    } else {
                        visible_chain_addr(rt, rec.key, head)
                    };
                    match visible {
                        Some(addr) if same_row(addr, seg, offset) => {}
                        Some(addr) => {
                            wanted.insert(rec.key, addr);
                            return true;
                        }
                        None => return true,
                    }
                }
                let binaries = match binary_ref_hits(rt, rec.key, RECENT_BINARY_REFS) {
                    Ok(refs) => refs,
                    Err(e) => {
                        failure = Some(e);
                        return false;
                    }
                };
                let demangled = demangle(&rec.name);
                let (func_name_demangled, lang) = if demangled.demangled {
                    (Some(demangled.name), demangled.lang.map(str::to_string))
                } else {
                    (None, None)
                };
                items.push(RecentFunction {
                    key_hex: format!("{:032x}", rec.key),
                    func_name: rec.name,
                    func_name_demangled,
                    lang,
                    ts: rec.ts_sec,
                    popularity: rec.popularity,
                    data_size: rec.data.len(),
                    segment: seg,
                    binary_names: binaries.iter().map(|b| b.basename.clone()).collect(),
                    binaries,
                });
                items.len() < limit
            })?;
        if let Some(e) = failure {
            return Err(e);
        }
        Ok((items, stats))
    }

    /// The `limit` binaries with the newest `order` timestamp, descending, with
    /// ties broken by ascending MD5. Coverage comes from the facet cache only;
    /// `score` is always zero. Streams the whole binary metadata tree once.
    pub async fn recent_binaries(
        &self,
        limit: usize,
        order: RecentBinaryOrder,
    ) -> io::Result<Vec<BinarySummary>> {
        let rt = self.rt.clone();
        tokio::task::spawn_blocking(move || Self::recent_binaries_sync(&rt, limit, order))
            .await
            .map_err(|e| io::Error::other(format!("spawn_blocking: {e}")))?
    }

    pub(crate) fn recent_binaries_sync(
        rt: &EngineRuntime,
        limit: usize,
        order: RecentBinaryOrder,
    ) -> io::Result<Vec<BinarySummary>> {
        let metas = rt
            .ctx_index
            .recent_binary_metas(limit, order == RecentBinaryOrder::FirstSeen)?;
        metas
            .iter()
            .map(|meta| {
                let mut summary = binary_summary_from_meta(meta, 0.0);
                if let Some(facets) = rt.ctx_index.get_binary_facets(&meta.md5)? {
                    summary.apply_facets(facets);
                }
                Ok(summary)
            })
            .collect()
    }
}

fn same_row(addr: u64, seg: u16, offset: u64) -> bool {
    addr_seg(addr) == seg && addr_off(addr) == offset
}

/// Address of the first accepted-name record on the latest-pointer chain of
/// `key`, mirroring `get_latest` visibility: a tombstone, a missing or cross-key
/// record, a cycle, a read error or the `MAX_HISTORY_RECORDS` bound hides the
/// key. At most that many record reads.
fn visible_chain_addr(rt: &EngineRuntime, key: u128, head: u64) -> Option<u64> {
    let mut addr = head;
    let mut visited: HashSet<u64> = HashSet::new();
    while addr != 0 && visited.len() < MAX_HISTORY_RECORDS && visited.insert(addr) {
        let rec = match rt.segments.read_record(addr) {
            Ok(rec) if rec.key == key => rec,
            Ok(_) => return None,
            Err(e) => {
                log::debug!("recent scan cannot resolve key {key:032x} at {addr:016x}: {e}");
                return None;
            }
        };
        if rec.flags & REC_FLAG_DELETED != 0 {
            return None;
        }
        if !is_rejected_function_name_with(rt.cfg.name_rejection, &rec.name) {
            return Some(addr);
        }
        addr = rec.prev_addr;
    }
    None
}

fn binary_ref_hits(rt: &EngineRuntime, key: u128, limit: usize) -> io::Result<Vec<BinaryRefHit>> {
    Ok(rt
        .ctx_index
        .get_binary_refs_for_key(key, limit)?
        .into_iter()
        .map(|meta| {
            let basename = basename_only(&meta.basename);
            BinaryRefHit {
                md5_hex: hex_md5(&meta.md5),
                short_id: short_md5(&meta.md5),
                display_name: format!("{} · {}", basename, short_md5(&meta.md5)),
                basename,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::{FailureCache, PushContext};
    use crate::engine::Record;
    use std::sync::Arc;

    struct TemporaryStore(std::path::PathBuf);

    impl Drop for TemporaryStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store(label: &str) -> io::Result<(TemporaryStore, Database)> {
        let path =
            std::env::temp_dir().join(format!("dazhbog-recent-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path)?;
        let mut cfg = Config::default();
        cfg.engine.data_dir = path.to_string_lossy().into_owned();
        let cleanup = TemporaryStore(path);
        let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
        Ok((
            cleanup,
            Database {
                rt: Arc::new(rt),
                failure_cache: FailureCache::new(),
            },
        ))
    }

    async fn push(db: &Database, key: u128, name: &str, md5: Option<[u8; 16]>) -> io::Result<()> {
        let data = vec![1u8, 2, 3, key as u8];
        let items = [(key, 1u32, data.len() as u32, name, data.as_slice())];
        let ctx = PushContext {
            md5,
            basename: md5.map(|_| "app.exe"),
            hostname: None,
            origin_token: None,
        };
        let statuses = db.push_with_ctx(&items, &ctx).await?;
        // 1 = inserted, 0 = updated; 2 = rejected or identical (not stored).
        assert!(
            statuses == vec![1] || statuses == vec![0],
            "push of {name} was not stored: {statuses:?}"
        );
        Ok(())
    }

    fn names(items: &[RecentFunction]) -> Vec<&str> {
        items.iter().map(|item| item.func_name.as_str()).collect()
    }

    fn raw_record(key: u128, name: &str, prev_addr: u64) -> Record {
        Record {
            key,
            ts_sec: 1,
            prev_addr,
            len_bytes: 2,
            popularity: 0,
            name: name.to_string(),
            data: vec![9, 9],
            flags: 0,
        }
    }

    #[tokio::test]
    async fn recent_functions_follow_append_order_and_list_each_key_once() -> io::Result<()> {
        let (_cleanup, db) = store("order")?;
        push(&db, 1, "alpha_one", Some([0xa1; 16])).await?;
        push(&db, 2, "beta_two", None).await?;
        push(&db, 1, "alpha_one_revised", Some([0xa1; 16])).await?;

        let (items, stats) = db.recent_functions(10).await?;
        assert_eq!(names(&items), vec!["alpha_one_revised", "beta_two"]);
        assert_eq!(
            stats,
            RecentScanStats {
                scanned_records: 3,
                invalid_records: 0,
                truncated: false
            }
        );
        assert_eq!(items[0].key_hex, format!("{:032x}", 1));
        assert_eq!(items[0].data_size, 4);
        assert_eq!(items[0].binaries.len(), 1);
        assert_eq!(items[0].binaries[0].basename, "app.exe");
        assert_eq!(items[0].binary_names, vec!["app.exe"]);
        assert!(items[1].binaries.is_empty());

        let (one, stats) = db.recent_functions(1).await?;
        assert_eq!(names(&one), vec!["alpha_one_revised"]);
        assert_eq!(stats.scanned_records, 1);
        assert!(!stats.truncated);

        let (none, stats) = db.recent_functions(0).await?;
        assert!(none.is_empty());
        assert_eq!(stats, RecentScanStats::default());
        Ok(())
    }

    #[tokio::test]
    async fn recent_functions_hide_tombstones_but_not_rejected_or_stale_heads() -> io::Result<()> {
        let (_cleanup, db) = store("visibility")?;
        push(&db, 1, "kept_function", None).await?;
        push(&db, 2, "deleted_function", None).await?;
        push(&db, 3, "older_accepted", None).await?;
        push(&db, 4, "current_head", None).await?;
        assert_eq!(db.delete_keys(&[2]).await?, 1);

        // Key 3: a newer rejected-name head must not hide the older accepted row.
        let old_head = db.rt.index.try_get(3)?;
        let rejected = db
            .rt
            .segments
            .append(&raw_record(3, "sub_401000", old_head))?;
        match db.rt.index.upsert(3, rejected) {
            Ok(_) => {}
            Err(crate::engine::IndexError::Io(e)) => return Err(e),
            Err(crate::engine::IndexError::Full) => return Err(io::Error::other("index full")),
        }

        // Key 4: a newer row that is not the latest pointer is stale, not recent.
        db.rt
            .segments
            .append(&raw_record(4, "stale_never_indexed", 0))?;
        // Key 5: an orphan without any latest pointer is invisible.
        db.rt
            .segments
            .append(&raw_record(5, "orphan_without_index", 0))?;

        let (items, stats) = db.recent_functions(10).await?;
        assert_eq!(
            names(&items),
            vec!["current_head", "older_accepted", "kept_function"]
        );
        // 4 pushes + 1 tombstone + 3 raw rows.
        assert_eq!(stats.scanned_records, 8);
        assert_eq!(stats.invalid_records, 0);
        assert!(!stats.truncated);
        Ok(())
    }

    #[tokio::test]
    async fn recent_functions_report_scan_bound_and_undecodable_rows() -> io::Result<()> {
        let (_cleanup, db) = store("bounds")?;
        push(&db, 1, "first_pushed", None).await?;
        push(&db, 2, "second_pushed", None).await?;
        push(&db, 3, "third_pushed", None).await?;

        let (items, stats) = Database::recent_functions_bounded(&db.rt, 5, 2)?;
        assert_eq!(names(&items), vec!["third_pushed", "second_pushed"]);
        assert_eq!(
            stats,
            RecentScanStats {
                scanned_records: 2,
                invalid_records: 0,
                truncated: true
            }
        );
        // A bound equal to the row count is a complete scan.
        let (_, stats) = Database::recent_functions_bounded(&db.rt, 5, 3)?;
        assert!(!stats.truncated);

        // Rows the reader cannot decode are counted and skipped, newest first:
        // a short value at a high offset and a malformed 5-byte offset key.
        let tree = db.rt.segments.sled_db().open_tree("seg.00001")?;
        tree.insert((1u64 << 30).to_be_bytes(), b"garbage".as_slice())?;
        tree.insert([0xffu8; 5], b"garbage".as_slice())?;
        let (items, stats) = db.recent_functions(10).await?;
        assert_eq!(
            names(&items),
            vec!["third_pushed", "second_pushed", "first_pushed"]
        );
        assert_eq!(stats.scanned_records, 5);
        assert_eq!(stats.invalid_records, 2);
        assert!(!stats.truncated);
        Ok(())
    }

    #[tokio::test]
    async fn recent_binaries_order_by_selected_timestamp_with_md5_ties() -> io::Result<()> {
        let (_cleanup, db) = store("binaries")?;
        let ctx = &db.rt.ctx_index;
        let (a, b, c, d) = ([0x0a; 16], [0x0b; 16], [0x0c; 16], [0x0d; 16]);
        assert!(ctx.record_binary_meta(a, "/opt/a.exe", "host", "", 100)?);
        assert!(ctx.record_binary_meta(b, "b.exe", "host", "", 50)?);
        assert!(!ctx.record_binary_meta(b, "b.exe", "host", "", 300)?);
        assert!(ctx.record_binary_meta(c, "c.exe", "host", "", 200)?);
        assert!(ctx.record_binary_meta(d, "d.exe", "host", "", 200)?);

        let md5s = |rows: &[BinarySummary]| {
            rows.iter()
                .map(|row| row.md5_hex[..2].to_string())
                .collect::<Vec<_>>()
        };
        let last = db.recent_binaries(10, RecentBinaryOrder::LastSeen).await?;
        assert_eq!(md5s(&last), vec!["0b", "0c", "0d", "0a"]);
        assert_eq!(last[0].last_seen_ts, 300);
        assert_eq!(last[0].first_seen_ts, 50);
        assert_eq!(last[3].basename, "a.exe");
        assert!(last
            .iter()
            .all(|row| row.score == 0.0 && row.coverage.is_none()));

        let first = db.recent_binaries(10, RecentBinaryOrder::FirstSeen).await?;
        assert_eq!(md5s(&first), vec!["0c", "0d", "0a", "0b"]);

        let two = db.recent_binaries(2, RecentBinaryOrder::FirstSeen).await?;
        assert_eq!(md5s(&two), vec!["0c", "0d"]);
        assert!(db
            .recent_binaries(0, RecentBinaryOrder::LastSeen)
            .await?
            .is_empty());
        Ok(())
    }

    #[test]
    fn recent_binary_order_parses_only_documented_values() {
        assert_eq!(
            RecentBinaryOrder::parse("last_seen"),
            Some(RecentBinaryOrder::LastSeen)
        );
        assert_eq!(
            RecentBinaryOrder::parse("first_seen"),
            Some(RecentBinaryOrder::FirstSeen)
        );
        assert_eq!(RecentBinaryOrder::parse("LAST_SEEN"), None);
        assert_eq!(RecentBinaryOrder::parse(""), None);
    }
}
