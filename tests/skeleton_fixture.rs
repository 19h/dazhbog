//! Classification of the captured `binaryninja` pull, replayed offline.
//!
//! `research/fixtures/binaryninja-pull-16752.analysis.jsonl` records, per
//! served position, every stored candidate of the key with the number of
//! binaries observing it. That is all the classifier needs, so the split of
//! the real request into specific keys, template members and coincidences
//! is checked without a database. The test is skipped when the capture is
//! not present.

use dazhbog::db::{classify_names, CandidateName, ClassifyParams, PatternClass};
use std::collections::BTreeMap;

const FIXTURE: &str = "research/fixtures/binaryninja-pull-16752.analysis.jsonl";

struct Key {
    binary_count: usize,
    variants: Vec<(String, u32)>,
}

fn load() -> Option<BTreeMap<String, Key>> {
    let text = std::fs::read_to_string(FIXTURE).ok()?;
    let mut keys = BTreeMap::new();
    for line in text.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let key = row["key_hex"].as_str().unwrap().to_string();
        keys.entry(key).or_insert_with(|| Key {
            binary_count: row["binary_count"].as_u64().unwrap() as usize,
            variants: row["variants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["name"].as_str().unwrap().to_string(),
                        v["num_binaries"].as_u64().unwrap() as u32,
                    )
                })
                .collect(),
        });
    }
    Some(keys)
}

fn classify(key: &Key) -> dazhbog::db::Classification {
    let candidates: Vec<CandidateName<'_>> = key
        .variants
        .iter()
        .map(|(name, num_binaries)| CandidateName {
            name,
            num_binaries: *num_binaries,
            declared_size: None,
        })
        .collect();
    classify_names(
        &candidates,
        Some(key.binary_count),
        &ClassifyParams {
            skeleton_min_share: 0.6,
            generic_min_binaries: 8,
            trivial_body_bytes: 0,
            class_hole_members: vec!["qt_metacall".into(), "qt_static_metacall".into()],
        },
    )
}

#[test]
fn captured_binaryninja_pull_splits_into_the_expected_classes() {
    let Some(keys) = load() else {
        eprintln!("skipping: {FIXTURE} not present");
        return;
    };
    assert_eq!(keys.len(), 543, "distinct served keys in the capture");

    let expect = |prefix: &str, class: PatternClass, skeleton: Option<&str>| {
        let (hex, key) = keys
            .iter()
            .find(|(hex, _)| hex.starts_with(prefix))
            .unwrap_or_else(|| panic!("key {prefix} in fixture"));
        let read = classify(key);
        assert_eq!(read.class, class, "{hex}: {read:?}");
        assert_eq!(read.skeleton.as_deref(), skeleton, "{hex}");
    };
    // 602 functions of the binary share this pattern; every candidate is
    // `__func<λ>::target(type_info const&)` from another program.
    expect(
        "78d8befa",
        PatternClass::TemplateMember,
        Some("std::__1::__function::__func<?>::target(std::type_info const&) const"),
    );
    // 280 and 124 functions: `__func<λ>::__clone()` from node, livox, Hdc…
    expect(
        "ab5ec0e7",
        PatternClass::TemplateMember,
        Some("std::__1::__function::__func<?>::__clone() const"),
    );
    expect(
        "98a3bcbb",
        PatternClass::TemplateMember,
        Some("std::__1::__function::__func<?>::__clone() const"),
    );
    // 31 candidates, all `QCallableObject<void (T::*)(), List<>, void>::impl`.
    expect(
        "0daa72bf",
        PatternClass::TemplateMember,
        Some("QtPrivate::QCallableObject<?>::impl(int, QtPrivate::QSlotObjectBase*, QObject*, void**, bool*)"),
    );
    // Trivial destructors of unrelated classes on a body seen in 71 binaries.
    expect("310cc83d", PatternClass::Coincidence, None);
    // A drone app's moc-generated signal emitter: one name, one family.
    expect("2a0131d0", PatternClass::Specific, None);

    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for key in keys.values() {
        let read = classify(key);
        let distinct = key
            .variants
            .iter()
            .map(|(name, _)| name)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if distinct == 1 {
            assert_eq!(read.class, PatternClass::Specific);
        }
        if read.class == PatternClass::TemplateMember {
            let skeleton = read.skeleton.as_deref().expect("skeleton");
            assert!(skeleton.contains("<?>"), "{skeleton}");
        }
        *counts
            .entry(match read.class {
                PatternClass::Specific => "specific",
                PatternClass::Disagreement => "disagreement",
                PatternClass::TemplateMember => "template",
                PatternClass::Coincidence => "coincidence",
            })
            .or_default() += 1;
    }
    eprintln!("class split over {} keys: {counts:?}", keys.len());
    let template = counts.get("template").copied().unwrap_or(0);
    let coincidence = counts.get("coincidence").copied().unwrap_or(0);
    let specific = counts.get("specific").copied().unwrap_or(0);
    assert!((55..=140).contains(&template), "template members: {template}");
    assert!((30..=90).contains(&coincidence), "coincidences: {coincidence}");
    assert!(specific >= 305, "specific keys: {specific}");
    assert_eq!(counts.values().sum::<usize>(), keys.len());
}
