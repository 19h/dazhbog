//! Bounded vocabulary for retrieving noncanonical live annotations.
use crate::common::{hash::version_id, neighbor::is_generic_neighbor_token};
use crate::config::NameRejection;
use crate::db::semantic::{build_fingerprint, is_rejected_function_name_with};
use crate::engine::{OpenSegments, ShardedIndex, MAX_HISTORY_RECORDS};
use crate::protocol::lumina::parse_metadata;
use std::{
    collections::{BTreeSet, HashSet},
    io,
};

const MAX_TERMS: usize = 8192;
const MAX_TERM_BYTES: usize = 256;
const TERMS_PER_VARIANT: usize = 64;

/// Newest-first, limited to the current live interval. This is retrieval evidence,
/// never a replacement annotation or a change to canonical search fields.
pub(crate) fn variant_vocabulary(
    segments: &OpenSegments,
    index: &ShardedIndex,
    key: u128,
    canonical_tokens: &[String],
    canonical_version: [u8; 32],
    policy: NameRejection,
) -> io::Result<Vec<String>> {
    let canonical: HashSet<_> = canonical_tokens.iter().collect();
    let mut address = index.try_get(key)?;
    let mut addresses = HashSet::new();
    // The canonical annotation was already analyzed for the main document.
    let mut versions = HashSet::from([canonical_version]);
    let mut terms = BTreeSet::new();
    while address != 0 && addresses.len() < MAX_HISTORY_RECORDS {
        if !addresses.insert(address) {
            log::warn!("variant vocabulary stopped at cyclic history key={key:032x}");
            break;
        }
        let record = match segments.read_record(address) {
            Ok(record) if record.key == key => record,
            result => {
                let error = match result {
                    Err(error) => error,
                    Ok(_) => {
                        io::Error::new(io::ErrorKind::InvalidData, "variant history key mismatch")
                    }
                };
                if addresses.len() == 1 {
                    return Err(error);
                }
                log::warn!(
                    "variant vocabulary stopped at invalid ancestry key={key:032x}: {error}"
                );
                break;
            }
        };
        if record.flags & 1 != 0 {
            break;
        }
        address = record.prev_addr;
        if is_rejected_function_name_with(policy, &record.name)
            || !versions.insert(version_id(key, &record.name, &record.data))
        {
            continue;
        }
        let metadata = parse_metadata(&record.data);
        let fingerprint = build_fingerprint(&record.name, &metadata);
        let eligible: Vec<_> = fingerprint
            .tokens
            .into_iter()
            .filter(|token| {
                token.len() <= MAX_TERM_BYTES
                    && !canonical.contains(token)
                    && !is_generic_neighbor_token(token)
            })
            .collect();
        for token in super::index::best_neighbor_tokens(&eligible, TERMS_PER_VARIANT) {
            terms.insert(token);
            if terms.len() == MAX_TERMS {
                return Ok(terms.into_iter().collect());
            }
        }
    }
    Ok(terms.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        engine::{EngineRuntime, Record},
        protocol::lumina::{pack_dd, MdKey},
    };

    #[test]
    fn vocabulary_respects_history_and_term_bounds() -> io::Result<()> {
        let path = std::env::temp_dir().join(format!("dazhbog-vocabulary-{}", std::process::id()));
        std::fs::create_dir(&path)?;
        let result = (|| -> io::Result<()> {
            let mut cfg = Config::default();
            cfg.engine.data_dir = path.to_string_lossy().into_owned();
            let rt = EngineRuntime::open(cfg.engine, cfg.scoring)?;
            let append = |key, previous, text: &str, flags| -> io::Result<u64> {
                let mut data = pack_dd(MdKey::Fcmt.raw());
                data.extend(pack_dd((text.len() + 1) as u32));
                data.extend(text.as_bytes());
                data.push(0);
                let rec = Record {
                    key,
                    ts_sec: 1,
                    prev_addr: previous,
                    len_bytes: data.len() as u32,
                    popularity: 1,
                    name: "active".into(),
                    data,
                    flags,
                };
                let address = rt.segments.append(&rec)?;
                assert!(rt.index.upsert(key, address).is_ok());
                Ok(address)
            };
            let canonical = vec!["active".to_string()];
            let foreign = append(2, 0, "poison", 0)?;
            let good = append(1, foreign, "orchid", 0)?;
            assert_eq!(
                variant_vocabulary(
                    &rt.segments,
                    &rt.index,
                    1,
                    &canonical,
                    [0; 32],
                    rt.cfg.name_rejection
                )?,
                vec!["orchid"]
            );
            assert!(rt.index.upsert(1, foreign).is_ok());
            assert_eq!(
                variant_vocabulary(
                    &rt.segments,
                    &rt.index,
                    1,
                    &canonical,
                    [0; 32],
                    rt.cfg.name_rejection
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
            let deleted = append(1, good, "", 1)?;
            append(1, deleted, "quartz", 0)?;
            assert_eq!(
                variant_vocabulary(
                    &rt.segments,
                    &rt.index,
                    1,
                    &canonical,
                    [0; 32],
                    rt.cfg.name_rejection
                )?,
                vec!["quartz"]
            );
            let terms = (0..65)
                .map(|i| format!("token{i:03}"))
                .collect::<Vec<_>>()
                .join(" ");
            let first = append(1, 0, &terms, 0)?;
            append(1, first, &terms, 0)?;
            let vocabulary = variant_vocabulary(
                &rt.segments,
                &rt.index,
                1,
                &canonical,
                [0; 32],
                rt.cfg.name_rejection,
            )?;
            assert_eq!(vocabulary.len(), 64);
            assert!(!vocabulary.iter().any(|token| token == "token064"));
            let allowed = "a".repeat(256);
            append(1, 0, &format!("{allowed} {}", "b".repeat(257)), 0)?;
            assert_eq!(
                variant_vocabulary(
                    &rt.segments,
                    &rt.index,
                    1,
                    &canonical,
                    [0; 32],
                    rt.cfg.name_rejection
                )?,
                vec![allowed]
            );
            let mut previous = 0;
            for variant in 0..129 {
                let text = (0..64)
                    .map(|term| format!("v{variant:03}t{term:03}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                previous = append(1, previous, &text, 0)?;
            }
            let vocabulary = variant_vocabulary(
                &rt.segments,
                &rt.index,
                1,
                &canonical,
                [0; 32],
                rt.cfg.name_rejection,
            )?;
            assert_eq!(vocabulary.len(), MAX_TERMS);
            assert!(!vocabulary.iter().any(|token| token.starts_with("v000")));
            let mut previous = append(1, 0, "poison", 0)?;
            for _ in 0..MAX_HISTORY_RECORDS {
                previous = append(1, previous, "orchid", 0)?;
            }
            assert_eq!(
                variant_vocabulary(
                    &rt.segments,
                    &rt.index,
                    1,
                    &canonical,
                    [0; 32],
                    rt.cfg.name_rejection
                )?,
                vec!["orchid"]
            );
            Ok(())
        })();
        std::fs::remove_dir_all(path)?;
        result
    }
}
