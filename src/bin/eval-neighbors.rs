//! Evaluate externally judged neighbors on an offline prepared database copy.
use dazhbog::{config::Config, db::Database};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, BufReader},
    sync::Arc,
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: String,
    family: String,
    partition: String,
    provenance: String,
    key: String,
    judgments: Vec<Judgment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Judgment {
    key: String,
    relevant: bool,
}

fn parse_key(key: &str) -> io::Result<u128> {
    if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "keys must be 32 hexadecimal digits",
        ));
    }
    u128::from_str_radix(key, 16).map_err(io::Error::other)
}

fn validate(cases: &[Case]) -> io::Result<()> {
    let mut families = HashMap::new();
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    for case in cases {
        if case.case_id.trim().is_empty()
            || case.family.trim().is_empty()
            || case.provenance.trim().is_empty()
            || !matches!(case.partition.as_str(), "development" | "test")
            || !ids.insert(&case.case_id)
            || !keys.insert(parse_key(&case.key)?)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or duplicate case identity/provenance/partition",
            ));
        }
        if families
            .insert(&case.family, &case.partition)
            .is_some_and(|old| old != &case.partition)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a source family occurs in both development and test partitions",
            ));
        }
        let mut judged = HashSet::new();
        for judgment in &case.judgments {
            let key = parse_key(&judgment.key)?;
            if key == parse_key(&case.key)? || !judged.insert(key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "self or duplicate judgment",
                ));
            }
        }
    }
    if cases.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty corpus"));
    }
    Ok(())
}

fn metrics(
    candidates: &[u128],
    returned: &[u128],
    judgments: &HashMap<u128, bool>,
) -> serde_json::Value {
    let positives = judgments.values().filter(|v| **v).count();
    let candidate_set: HashSet<_> = candidates.iter().collect();
    let candidate_relevant = judgments
        .iter()
        .filter(|(k, v)| **v && candidate_set.contains(k))
        .count();
    let judged = returned
        .iter()
        .filter(|key| judgments.contains_key(key))
        .count();
    let relevant = returned
        .iter()
        .filter(|key| judgments.get(key) == Some(&true))
        .count();
    let ratio = |n: usize, d: usize| (d != 0).then(|| n as f64 / d as f64);
    serde_json::json!({
        "candidate_count": candidates.len(), "returned_count": returned.len(),
        "judged_returned": judged, "relevant_returned": relevant,
        "judgment_coverage": ratio(judged, returned.len()),
        "precision": if judged == returned.len() { ratio(relevant, returned.len()) } else { None },
        "judged_precision": ratio(relevant, judged),
        "labeled_recall": ratio(relevant, positives),
        "candidate_labeled_recall": ratio(candidate_relevant, positives),
    })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let config = args
        .next()
        .ok_or_else(|| io::Error::other("usage: eval-neighbors CONFIG LABELS.jsonl [K]"))?;
    let labels = args
        .next()
        .ok_or_else(|| io::Error::other("missing label corpus"))?;
    let k: usize = args
        .next()
        .map_or(Ok(12), |s| s.parse().map_err(io::Error::other))?;
    if !(1..=96).contains(&k) || args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "K must be 1..=96; unexpected arguments",
        ));
    }
    let cases: Vec<Case> = BufReader::new(File::open(labels)?)
        .lines()
        .map(|line| serde_json::from_str(&line?).map_err(io::Error::other))
        .collect::<io::Result<_>>()?;
    validate(&cases)?;
    // No source names or generated tokens are used as relevance labels.
    let db = Database::open_for_replay(Arc::new(Config::load(&config)?)).await?;
    for case in cases {
        let key = parse_key(&case.key)?;
        let judgments: HashMap<u128, bool> = case
            .judgments
            .iter()
            .map(|j| Ok((parse_key(&j.key)?, j.relevant)))
            .collect::<io::Result<_>>()?;
        for budget in [96, 192, 384] {
            let start = Instant::now();
            let (candidates, hits) = db
                .semantic_neighbors_with_budget(key, k, false, budget)
                .await?;
            let returned = hits
                .iter()
                .map(|h| parse_key(&h.key_hex))
                .collect::<io::Result<Vec<_>>>()?;
            println!(
                "{}",
                serde_json::json!({
                    "case_id": case.case_id, "family":case.family, "partition":case.partition,
                    "provenance":case.provenance, "budget":budget, "k":k,
                    "elapsed_s":start.elapsed().as_secs_f64(),
                    "metrics":metrics(&candidates, &returned, &judgments),
                })
            );
        }
    }
    db.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unjudged_hits_are_not_counted_as_negatives() {
        let m = metrics(&[1, 2, 3], &[1, 3], &HashMap::from([(1, true), (2, true)]));
        assert!(m["precision"].is_null());
        assert_eq!(m["judgment_coverage"], 0.5);
        assert_eq!(m["labeled_recall"], 0.5);
        assert_eq!(m["candidate_labeled_recall"], 1.0);
    }
    #[test]
    fn families_cannot_leak_across_partitions() {
        let case = |id: &str, partition: &str, key| Case {
            case_id: id.into(),
            family: "fixture".into(),
            partition: partition.into(),
            provenance: "synthetic validation fixture".into(),
            key: format!("{key:032x}"),
            judgments: vec![],
        };
        assert!(validate(&[case("a", "development", 1), case("b", "test", 2)]).is_err());
        assert!(validate(&[case("a", "test", 1), case("b", "test", 2)]).is_ok());
    }
}
