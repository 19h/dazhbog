//! Exact per-tree cardinality and value bytes, committed with each mutation.
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional};
use std::{io, ops::Deref};

#[derive(Clone)]
pub(super) struct CountedTree {
    tree: sled::Tree,
    stats: sled::Tree,
    name: Vec<u8>,
}

fn decode(raw: &[u8]) -> sled::Result<(u64, u64)> {
    if raw.len() != 16 {
        return Err(sled::Error::Unsupported(
            "invalid tree statistics; run preparation".into(),
        ));
    }
    Ok((
        u64::from_le_bytes(raw[..8].try_into().unwrap()),
        u64::from_le_bytes(raw[8..].try_into().unwrap()),
    ))
}

fn encode(count: u64, bytes: u64) -> Vec<u8> {
    [count.to_le_bytes(), bytes.to_le_bytes()].concat()
}

impl CountedTree {
    pub fn open(db: &sled::Db, name: &[u8], prepare: bool) -> io::Result<Self> {
        let tree = db.open_tree(name)?;
        let stats = db.open_tree("__tree_stats_v1")?;
        match stats.get(name)? {
            Some(raw) if !prepare => {
                decode(&raw)?;
            }
            _ => {
                if !prepare && tree.first()?.is_some() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("missing statistics for {}; run dazhbog --prepare CONFIG on an offline copy", String::from_utf8_lossy(name))));
                }
                let (mut count, mut bytes) = (0u64, 0u64);
                for item in tree.iter() {
                    let (_, value) = item?;
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("count overflow"))?;
                    bytes = bytes
                        .checked_add(value.len() as u64)
                        .ok_or_else(|| io::Error::other("byte count overflow"))?;
                }
                stats.insert(name, encode(count, bytes))?;
            }
        }
        Ok(Self {
            tree,
            stats,
            name: name.to_vec(),
        })
    }

    pub fn totals(&self) -> io::Result<(u64, u64)> {
        let raw = self
            .stats
            .get(&self.name)?
            .ok_or_else(|| io::Error::other("missing tree statistics"))?;
        Ok(decode(&raw)?)
    }

    pub fn insert<K: AsRef<[u8]>, V: Into<sled::IVec>>(
        &self,
        key: K,
        value: V,
    ) -> sled::Result<Option<sled::IVec>> {
        self.replace(key.as_ref(), Some(value.into()))
    }

    pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> sled::Result<Option<sled::IVec>> {
        self.replace(key.as_ref(), None)
    }

    fn replace(&self, key: &[u8], value: Option<sled::IVec>) -> sled::Result<Option<sled::IVec>> {
        (&self.tree, &self.stats)
            .transaction(|(tree, stats)| {
                let raw = stats.get(self.name.as_slice())?.ok_or_else(|| {
                    ConflictableTransactionError::Abort(sled::Error::Unsupported(
                        "missing tree statistics".into(),
                    ))
                })?;
                let (count, bytes) = decode(&raw).map_err(ConflictableTransactionError::Abort)?;
                let old = tree.get(key)?;
                let count = count
                    .checked_sub(u64::from(old.is_some()))
                    .and_then(|n| n.checked_add(u64::from(value.is_some())));
                let bytes = bytes
                    .checked_sub(old.as_ref().map_or(0, |v| v.len() as u64))
                    .and_then(|n| n.checked_add(value.as_ref().map_or(0, |v| v.len() as u64)));
                let (Some(count), Some(bytes)) = (count, bytes) else {
                    return Err(ConflictableTransactionError::Abort(
                        sled::Error::Unsupported("tree statistics overflow".into()),
                    ));
                };
                match &value {
                    Some(value) => {
                        tree.insert(key, value.clone())?;
                    }
                    None => {
                        tree.remove(key)?;
                    }
                }
                stats.insert(self.name.as_slice(), encode(count, bytes))?;
                Ok(old)
            })
            .map_err(|e| match e {
                TransactionError::Abort(e) | TransactionError::Storage(e) => e,
            })
    }
}

impl Deref for CountedTree {
    type Target = sled::Tree;
    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_overwrites_keep_exact_counts() -> io::Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = CountedTree::open(&db, b"records", false)?;
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let tree = &tree;
                scope.spawn(move || {
                    for n in 0u64..100 {
                        tree.insert(n.to_be_bytes(), b"value").unwrap();
                    }
                });
            }
        });
        assert_eq!(tree.totals()?, (100, 500));
        for n in 0u64..50 {
            tree.remove(n.to_be_bytes())?;
        }
        assert_eq!(tree.totals()?, (50, 250));
        db.flush()?;
        assert_eq!(
            CountedTree::open(&db, b"records", false)?.totals()?,
            (50, 250)
        );
        Ok(())
    }

    #[test]
    fn old_tree_requires_explicit_preparation() -> io::Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        db.open_tree("records")?.insert(b"key", b"value")?;
        assert!(CountedTree::open(&db, b"records", false).is_err());
        assert_eq!(CountedTree::open(&db, b"records", true)?.totals()?, (1, 5));
        Ok(())
    }

    #[test]
    fn preparation_repairs_counters_after_legacy_raw_writes() -> io::Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        let counted = CountedTree::open(&db, b"records", false)?;
        counted.insert(b"first", b"one")?;
        db.open_tree("records")?.insert(b"second", b"two")?;
        assert_eq!(CountedTree::open(&db, b"records", true)?.totals()?, (2, 6));
        db.open_tree("__tree_stats_v1")?
            .insert(b"records", b"corrupt")?;
        assert!(CountedTree::open(&db, b"records", false).is_err());
        assert_eq!(CountedTree::open(&db, b"records", true)?.totals()?, (2, 6));
        Ok(())
    }
}
