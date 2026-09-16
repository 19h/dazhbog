//! Additive alias postings, with read compatibility for the legacy capped lists.
use std::collections::BTreeMap;
use std::io;

pub(super) struct BinaryNameIndex {
    legacy: sled::Tree,
    memberships: sled::Tree,
}

impl BinaryNameIndex {
    pub(super) fn open(db: &sled::Db) -> io::Result<Self> {
        Ok(Self {
            legacy: db.open_tree("binary_name_index")?,
            memberships: db.open_tree("binary_name_memberships_v1")?,
        })
    }

    /// One independently inserted key per normalized alias/binary pair. Repeated
    /// observations are idempotent and different binaries cannot overwrite a list.
    pub(super) fn record(&self, normalized: &str, md5: [u8; 16]) -> io::Result<()> {
        if normalized.is_empty() {
            return Ok(());
        }
        if normalized.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "binary alias exceeds 255 bytes",
            ));
        }
        let mut key = Vec::with_capacity(normalized.len() + 17);
        key.extend_from_slice(normalized.as_bytes());
        key.push(0);
        key.extend_from_slice(&md5);
        self.memberships.insert(key, &[])?;
        Ok(())
    }

    /// Merge old and new aliases without converting the old store at startup.
    /// IDs have a stable order and occur once even when many aliases match.
    pub(super) fn search(&self, query: &str) -> io::Result<Vec<([u8; 16], u8)>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let mut matches = BTreeMap::new();
        for item in self.legacy.iter() {
            let (raw_name, raw_md5s) = item?;
            let Ok(name) = std::str::from_utf8(&raw_name) else {
                continue;
            };
            if let Some(score) = alias_match_score(name, query) {
                // Preserve the old reader's empty/trailing-byte compatibility
                // and its treatment of undecodable legacy lists as absent.
                for md5 in decode_legacy_list(&raw_md5s).unwrap_or_default() {
                    retain_match(&mut matches, md5, score);
                }
            }
        }
        for item in self.memberships.iter() {
            let (key, value) = item?;
            let invalid = || {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid binary alias membership",
                )
            };
            if !(18..=272).contains(&key.len()) || !value.is_empty() {
                return Err(invalid());
            }
            let name_end = key.len() - 17;
            if key[name_end] != 0 {
                return Err(invalid());
            }
            let name = std::str::from_utf8(&key[..name_end]).map_err(|_| invalid())?;
            if let Some(score) = alias_match_score(name, query) {
                retain_match(
                    &mut matches,
                    key[name_end + 1..].try_into().map_err(|_| invalid())?,
                    score,
                );
            }
        }
        Ok(matches.into_iter().collect())
    }
}

fn alias_match_score(name: &str, query: &str) -> Option<u8> {
    if name == query {
        Some(100)
    } else if name.starts_with(query) {
        Some(70)
    } else if name.contains(query) {
        Some(40)
    } else {
        None
    }
}

fn retain_match(matches: &mut BTreeMap<[u8; 16], u8>, md5: [u8; 16], score: u8) {
    matches
        .entry(md5)
        .and_modify(|previous| *previous = (*previous).max(score))
        .or_insert(score);
}

fn decode_legacy_list(bytes: &[u8]) -> Option<Vec<[u8; 16]>> {
    let Some((&count, bytes)) = bytes.split_first() else {
        return Some(Vec::new());
    };
    Some(
        bytes
            .get(..usize::from(count) * 16)?
            .as_chunks::<16>()
            .0
            .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strongest_alias_match_survives_legacy_and_posting_duplicates() -> io::Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        let index = BinaryNameIndex::open(&db)?;
        index
            .legacy
            .insert(b"module", [&[1][..], &[7; 16]].concat())?;
        index.record("module-extension", [7; 16])?;
        index.record("prefix-module", [7; 16])?;
        index.record("module-extension", [8; 16])?;
        assert_eq!(index.search("module")?, vec![([7; 16], 100), ([8; 16], 70)]);
        index
            .legacy
            .insert(b"malformed-module", [&[2][..], &[0; 16]].concat())?;
        index.legacy.insert(b"empty-module", &[])?;
        assert_eq!(index.search("module")?.len(), 2);
        Ok(())
    }

    #[test]
    fn postings_validate_layout_and_keep_fixed_width_identity() -> io::Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        let index = BinaryNameIndex::open(&db)?;
        for name in ["module", "mod\0ule", "μodule"] {
            for md5 in [[0; 16], [255; 16]] {
                index.record(name, md5)?;
                index.record(name, md5)?;
            }
        }
        assert_eq!(index.memberships.len(), 6);
        assert_eq!(index.search("ule")?, vec![([0; 16], 40), ([255; 16], 40)]);
        assert_eq!(index.search("mod\0")?, vec![([0; 16], 70), ([255; 16], 70)]);
        assert_eq!(
            index.search("module")?,
            vec![([0; 16], 100), ([255; 16], 100)]
        );
        assert!(index.search("")?.is_empty());
        index.record("", [1; 16])?;
        assert_eq!(index.memberships.len(), 6);
        index.record(&"a".repeat(255), [1; 16])?;
        assert!(index.record(&"a".repeat(256), [1; 16]).is_err());
        for (key, value) in [
            (vec![0; 17], vec![]),
            (vec![0; 273], vec![]),
            ([b"x!".as_slice(), &[0; 16]].concat(), vec![]),
            ([&[255, 0][..], &[0; 16]].concat(), vec![]),
            ([b"x\0".as_slice(), &[0; 16]].concat(), vec![1]),
        ] {
            index.memberships.insert(&key, value)?;
            assert_eq!(
                index.search("unrelated").unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            index.memberships.remove(key)?;
        }
        Ok(())
    }
}
