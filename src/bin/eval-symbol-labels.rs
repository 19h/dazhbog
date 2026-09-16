//! Independent name agreement: labels never enter selection or database mutation.
use dazhbog::{
    config::Config,
    db::{Database, QueryContext, SelectedVariant},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{self, Read},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: String,
    family: String,
    partition: String,
    key: String,
    binary_md5: String,
    binary_sha256: String,
    fixture_sha256: String,
    address: String,
    size_bytes: String,
    expected_names: Vec<String>,
    provenance: Provenance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    binary: String,
    fixture_database: String,
    labels: String,
    keys: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate(cases: &[Case]) -> io::Result<()> {
    if cases.is_empty() || cases.len() > 65536 {
        return Err(invalid("require 1..=65536 cases"));
    }
    let mut ids = HashSet::new();
    let mut families = HashMap::new();
    let mut binaries = HashMap::new();
    for case in cases {
        if !hex(&case.key, 32)
            || !hex(&case.binary_md5, 32)
            || !hex(&case.binary_sha256, 64)
            || !hex(&case.fixture_sha256, 64)
            || case.case_id != format!("{}:{}", case.binary_md5, case.key)
            || !ids.insert((
                case.binary_md5.to_ascii_lowercase(),
                case.key.to_ascii_lowercase(),
            ))
            || case.family.trim().is_empty()
            || !matches!(case.partition.as_str(), "development" | "test")
            || case.expected_names.is_empty()
            || case.expected_names.iter().any(|n| n.trim().is_empty())
            || case
                .address
                .strip_prefix("0x")
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .is_none()
            || case.size_bytes.parse::<u32>().ok().is_none_or(|n| n == 0)
            || [
                &case.provenance.binary,
                &case.provenance.fixture_database,
                &case.provenance.labels,
                &case.provenance.keys,
            ]
            .iter()
            .any(|s| s.trim().is_empty())
        {
            return Err(invalid("invalid/duplicate label identity or provenance"));
        }
        if families
            .insert(&case.family, &case.partition)
            .is_some_and(|p| p != &case.partition)
        {
            return Err(invalid("source family crosses development/test partition"));
        }
        let identity = (&case.binary_sha256, &case.family, &case.partition);
        if binaries
            .insert(case.binary_md5.to_ascii_lowercase(), identity)
            .is_some_and(|old| old != identity)
        {
            return Err(invalid("binary identity/provenance conflict"));
        }
    }
    Ok(())
}

#[derive(Default, serde::Serialize)]
struct Counts {
    cases: usize,
    available: usize,
    exact_name: usize,
}

fn observe(counts: &mut Counts, case: &Case, name: Option<&str>) {
    counts.cases += 1;
    counts.available += usize::from(name.is_some());
    counts.exact_name +=
        usize::from(name.is_some_and(|n| case.expected_names.iter().any(|e| e == n)));
}

/// Positive matches establish candidate presence; a bounded history miss does
/// not establish absence. Probe errors must not change selection or its counts.
async fn disagreement(db: &Database, case: &Case, selected: &SelectedVariant) -> serde_json::Value {
    let key = u128::from_str_radix(&case.key, 16).expect("validated key");
    let history = match db.get_history(key, 64).await {
        Ok(history) => {
            let mut names = HashSet::new();
            let mut expected_name_seen = false;
            let mut expected_candidate_seen = false;
            for (_, name, data) in &history {
                names.insert(name.as_str());
                if case.expected_names.contains(name) {
                    expected_name_seen = true;
                    expected_candidate_seen |= selected
                        .contains_version(&dazhbog::common::hash::version_id(key, name, data));
                }
            }
            let mut names: Vec<_> = names.into_iter().collect();
            names.sort_unstable();
            let distinct_names = names.len();
            names.truncate(32);
            serde_json::json!({"returned_versions":history.len(), "return_limit":64, "expected_name_seen":expected_name_seen,
                "expected_candidate_seen":expected_candidate_seen, "distinct_names":distinct_names, "names":names,
                "absence_established":false})
        }
        Err(error) => serde_json::json!({"error":error.to_string(), "absence_established":false}),
    };
    serde_json::json!({"kind":"disagreement", "case_id":case.case_id, "key":case.key,
        "binary_md5":case.binary_md5, "expected_names":case.expected_names, "selected_name":selected.name,
        "candidate_count":selected.candidate_version_ids.len(), "synthesized":selected.used_synthesis,
        "binary_match":selected.binary_match, "history":history})
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let diagnostics = args.len() == 2 && args[1] == "--disagreements";
    if args.len() != 1 && !diagnostics {
        return Err(invalid(
            "usage: eval-symbol-labels CONFIG [--disagreements] < LABELS.jsonl; use an offline copy",
        ));
    }
    let mut input = String::new();
    io::stdin()
        .lock()
        .take(64 * 1024 * 1024 + 1)
        .read_to_string(&mut input)?;
    if input.len() > 64 * 1024 * 1024 {
        return Err(invalid("label input exceeds 64 MiB"));
    }
    let mut cases = Vec::new();
    for line in input.lines() {
        if cases.len() == 65536 {
            return Err(invalid("too many cases"));
        }
        cases.push(serde_json::from_str::<Case>(line).map_err(io::Error::other)?);
    }
    validate(&cases)?;
    let db = Database::open_for_replay(Arc::new(Config::load(&args[0])?)).await?;
    let mut groups: BTreeMap<&str, Vec<&Case>> = BTreeMap::new();
    for case in &cases {
        groups.entry(&case.binary_md5).or_default().push(case);
    }
    let mut totals: BTreeMap<String, Counts> = BTreeMap::new();
    for (md5_hex, group) in groups {
        let md5 = u128::from_str_radix(md5_hex, 16)
            .map_err(io::Error::other)?
            .to_be_bytes();
        let keys: Vec<_> = group
            .iter()
            .map(|c| u128::from_str_radix(&c.key, 16).map_err(io::Error::other))
            .collect::<io::Result<_>>()?;
        // Only function identities and (in explicit mode) binary identity cross
        // this boundary. No expected name, source address, size or provenance.
        for (mode, identity) in [("explicit_binary", Some(md5)), ("inferred_batch", None)] {
            let selected = db
                .select_variant_details(&QueryContext {
                    keys: &keys,
                    requested_mdkeys: &[],
                    md5: identity,
                    basename: None,
                    hostname: None,
                    origin_token: None,
                })
                .await?;
            if selected.len() != group.len() {
                return Err(io::Error::other("selection cardinality mismatch"));
            }
            let mut counts = Counts::default();
            for (case, selected) in group.iter().zip(&selected) {
                let name = selected.as_ref().map(|v| v.name.as_str());
                observe(&mut counts, case, name);
                if diagnostics && mode == "explicit_binary" {
                    if let Some(selected) = selected
                        .as_ref()
                        .filter(|s| !case.expected_names.contains(&s.name))
                    {
                        println!("{}", disagreement(&db, case, selected).await);
                    }
                }
                observe(
                    totals
                        .entry(format!("{}/{mode}", case.partition))
                        .or_default(),
                    case,
                    name,
                );
            }
            println!(
                "{}",
                serde_json::json!({"kind":"binary", "binary_md5":md5_hex, "family":group[0].family, "partition":group[0].partition, "mode":mode, "counts":counts})
            );
        }
        for mode in ["latest", "canonical"] {
            let mut counts = Counts::default();
            for (case, key) in group.iter().zip(&keys) {
                let selected = if mode == "latest" {
                    db.get_latest(*key).await?
                } else {
                    db.get_canonical(*key).await?
                };
                let name = selected.as_ref().map(|v| v.name.as_str());
                observe(&mut counts, case, name);
                observe(
                    totals
                        .entry(format!("{}/{mode}", case.partition))
                        .or_default(),
                    case,
                    name,
                );
            }
            println!(
                "{}",
                serde_json::json!({"kind":"binary", "binary_md5":md5_hex, "family":group[0].family, "partition":group[0].partition, "mode":mode, "counts":counts})
            );
        }
    }
    println!("{}", serde_json::json!({"kind":"total", "modes":totals}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn case() -> Case {
        Case {
            case_id: format!("{}:{}", "1".repeat(32), "2".repeat(32)),
            family: "fixture".into(),
            partition: "test".into(),
            key: "2".repeat(32),
            binary_md5: "1".repeat(32),
            binary_sha256: "3".repeat(64),
            fixture_sha256: "4".repeat(64),
            address: "0x123".into(),
            size_bytes: "16".into(),
            expected_names: vec!["first".into(), "alias".into()],
            provenance: Provenance {
                binary: "binary.elf".into(),
                fixture_database: "fixture.sqlite3".into(),
                labels: "ELF symbols".into(),
                keys: "hash mapping".into(),
            },
        }
    }
    #[test]
    fn aliases_absence_and_wrong_names_have_distinct_denominators() {
        let mut counts = Counts::default();
        for name in [None, Some("alias"), Some("wrong")] {
            observe(&mut counts, &case(), name);
        }
        assert_eq!(
            (counts.cases, counts.available, counts.exact_name),
            (3, 2, 1)
        );
    }
    #[test]
    fn duplicate_identity_and_partition_leakage_fail_before_open() {
        assert!(validate(&[case()]).is_ok());
        assert!(validate(&[case(), case()]).is_err());
        let mut other = case();
        other.binary_md5 = "5".repeat(32);
        other.case_id = format!("{}:{}", other.binary_md5, other.key);
        other.partition = "development".into();
        assert!(validate(&[case(), other]).is_err());
        let mut conflict = case();
        conflict.key = "6".repeat(32);
        conflict.case_id = format!("{}:{}", conflict.binary_md5, conflict.key);
        conflict.binary_sha256 = "7".repeat(64);
        assert!(validate(&[case(), conflict]).is_err());
    }
}
