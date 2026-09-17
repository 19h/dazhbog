//! What a requested pattern can identify, and what was served for it.
//!
//! A Lumina pattern hashes a function body with relocations masked, so one
//! key can stand for many functions: every specialization of a template
//! thunk, every moc-generated dispatcher of one shape, every trivial
//! destructor. The decision recorded here says how the selector read the
//! key and why it answered the way it did, so a served name can be audited
//! against the alternatives instead of taken on faith.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::common::skeleton::{is_trivial_member, skeleton_of, strip_ida_duplicate_suffix};

/// Why a position received no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DeclineReason {
    /// The same pattern matched more functions of the requesting binary than
    /// `scoring.max_key_repeats` allows; one name cannot be right for all of
    /// them.
    Repeated,
    /// The winning name belongs to one program family that the request is
    /// not related to.
    ForeignSpecific,
    /// Unrelated names on a widely shared trivial body: nothing to serve.
    Coincidence,
    /// A template member whose skeleton could not be rendered, or skeleton
    /// answers are disabled.
    TemplateNoSkeleton,
}

/// Agreement of the declared prototype across a template member's
/// specializations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TypeConsensus {
    /// No candidate carries a prototype.
    Absent,
    /// Every typed candidate carries the same declared (`userti`) prototype.
    Declared,
    /// The prototypes agree but are decompiler guesses.
    Guessed,
    /// The prototypes differ.
    Disagree,
}

/// Why a served name is believed to apply to the requesting binary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Provenance {
    /// No judgement was made (declined earlier, no candidates, or a path
    /// without batch evidence).
    Unchecked,
    /// The request named a binary that observed this name.
    Explicit { md5_hex: String },
    /// A donor of the name is substantially covered by the request.
    RelatedDonor { md5_hex: String, coverage: f64 },
    /// The name was observed by several unrelated program families.
    Library { families: usize },
    /// The name is one program family's, and the request is not related.
    Foreign { home: String, families: usize },
}

/// The form of the answer that reached the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ServedForm {
    /// One stored record, name and metadata as pushed.
    Verbatim,
    /// The template member the pattern identifies, with a placeholder for
    /// the specialization and only metadata every specialization shares.
    Skeleton,
    /// A specialization resolved from a neighbouring function of the request
    /// that a donor of it also carries; served verbatim.
    Corroborated,
    Declined(DeclineReason),
}

/// How a specialization was pinned to the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Specialization {
    pub donor_md5_hex: String,
    pub sibling_key_hex: String,
    pub sibling_position: u32,
    pub sibling_name: String,
}

/// What the stored candidates of a key say about the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum PatternClass {
    /// One name: the pattern has a single known identity.
    Specific,
    /// Several names without common structure on a key seen in few
    /// binaries: ordinary disagreement between uploads.
    Disagreement,
    /// Every candidate is the same template member with a different
    /// argument: the pattern identifies the member, not a specialization.
    TemplateMember,
    /// Several unrelated names on a widely shared body: nothing about the
    /// function is knowable from the pattern.
    Coincidence,
}

/// One stored name of a key, as the classifier sees it.
#[derive(Debug, Clone)]
pub struct CandidateName<'a> {
    pub name: &'a str,
    /// Binaries that observed this exact variant; at least one is assumed.
    pub num_binaries: u32,
    /// Declared function size when the record carries one.
    pub declared_size: Option<u32>,
}

/// Thresholds for `classify_names`.
#[derive(Debug, Clone)]
pub struct ClassifyParams {
    /// Share of the key's binary weight the heaviest skeleton group needs.
    pub skeleton_min_share: f64,
    /// Binary count from which a multi-name key without common structure is
    /// a coincidence rather than a disagreement.
    pub generic_min_binaries: usize,
    /// Declared size at or below which a disputed body is trivial; zero
    /// disables the size signal.
    pub trivial_body_bytes: u32,
    /// Members of non-template classes whose body does not depend on the
    /// class (moc dispatchers): candidates differing only in the class form
    /// a class-hole skeleton `?::member(…)`.
    pub class_hole_members: Vec<String>,
}

/// `Class::member(args)` split into its class and the rest, when the name
/// is a member of a plain (non-template, non-namespaced) class.
fn class_hole_parts(display: &str) -> Option<(&str, &str)> {
    let head_end = display.find('(').unwrap_or(display.len());
    let head = &display[..head_end];
    if head.contains('<') || head.contains('>') {
        return None;
    }
    let sep = head.find("::")?;
    let class = &head[..sep];
    if class.is_empty()
        || !class.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || head[sep + 2..].contains("::")
    {
        return None;
    }
    Some((class, &display[sep + 2..]))
}

/// The classifier's reading of one key.
#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    pub class: PatternClass,
    /// Distinct names after collision-suffix normalization.
    pub distinct_names: usize,
    /// The shared skeleton of a template member, in display form.
    pub skeleton: Option<String>,
    /// Weight share of the heaviest skeleton group.
    pub skeleton_share: f64,
    /// Number of distinct skeleton groups (undecodable names count singly).
    pub skeleton_groups: usize,
}

#[derive(Default)]
struct Group {
    weight: f64,
    placeholders: u8,
    names: BTreeMap<String, f64>,
    trivial_weight: f64,
}

/// Read the candidates of one key. Weight is the number of observing
/// binaries per variant, so a specialization pushed from many programs
/// counts for more than one pushed once.
pub fn classify_names(
    candidates: &[CandidateName<'_>],
    binary_count: Option<usize>,
    params: &ClassifyParams,
) -> Classification {
    let mut name_weight: BTreeMap<&str, f64> = BTreeMap::new();
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut undecoded = 0usize;
    let mut total = 0.0;
    let mut trivial_total = 0.0;
    let mut smallest_size: Option<u32> = None;
    for candidate in candidates {
        let weight = f64::from(candidate.num_binaries.max(1));
        total += weight;
        let normalized = strip_ida_duplicate_suffix(candidate.name).unwrap_or(candidate.name);
        *name_weight.entry(normalized).or_default() += weight;
        if let Some(size) = candidate.declared_size {
            smallest_size = Some(smallest_size.map_or(size, |s| s.min(size)));
        }
        let skeleton = skeleton_of(candidate.name);
        let trivial = is_trivial_member(candidate.name, skeleton.as_ref().map(|s| s.text.as_str()));
        if trivial {
            trivial_total += weight;
        }
        match skeleton {
            Some(skeleton) => {
                // A moc dispatcher of a plain class is the same body for
                // every class: group such members with the class blanked.
                let (text, placeholders) = match class_hole_parts(&skeleton.text) {
                    Some((_, rest))
                        if skeleton.template_placeholders == 0
                            && params.class_hole_members.iter().any(|member| {
                                rest.starts_with(member.as_str())
                                    && rest[member.len()..].starts_with('(')
                            }) =>
                    {
                        (format!("?::{rest}"), 1)
                    }
                    _ => (skeleton.text, skeleton.template_placeholders),
                };
                let group = groups.entry(text).or_default();
                group.weight += weight;
                group.placeholders = placeholders;
                *group.names.entry(normalized.to_string()).or_default() += weight;
                if trivial {
                    group.trivial_weight += weight;
                }
            }
            None => undecoded += 1,
        }
    }
    let distinct_names = name_weight.len();
    let skeleton_groups = groups.len() + undecoded;
    let top_group = groups
        .iter()
        .max_by(|a, b| a.1.weight.total_cmp(&b.1.weight).then_with(|| b.0.cmp(a.0)));
    let (skeleton_share, top_skeleton) = match top_group {
        Some((text, group)) if total > 0.0 => (group.weight / total, Some((text, group))),
        _ => (0.0, None),
    };
    let top_name_share = name_weight
        .values()
        .copied()
        .fold(0.0f64, f64::max)
        / total.max(f64::MIN_POSITIVE);

    let widely_shared = binary_count.is_none_or(|count| count >= params.generic_min_binaries);
    let trivial_share = trivial_total / total.max(f64::MIN_POSITIVE);
    let class = if distinct_names <= 1 {
        PatternClass::Specific
    } else if top_skeleton.is_some_and(|(_, group)| qualifies_as_member(group, skeleton_share, params))
    {
        PatternClass::TemplateMember
    } else if groups.len() == 1
        && undecoded == 0
        && top_skeleton.is_some_and(|(_, group)| group.placeholders == 0)
    {
        // Only abi tags or collision suffixes told the names apart.
        PatternClass::Specific
    } else if widely_shared && trivial_share >= 0.75 {
        // Destructors and assignments of unrelated classes on a body shared
        // by many programs: one of them being pushed more often than the
        // others (or echoed back by clients) does not make it identifying.
        PatternClass::Coincidence
    } else if top_name_share >= params.skeleton_min_share {
        // One well-attested name beside stray pushes.
        PatternClass::Specific
    } else {
        // Several unrelated names on a key seen in few binaries is ordinary
        // disagreement unless the bodies themselves are trivial.
        let trivial_body = params.trivial_body_bytes > 0
            && smallest_size.is_some_and(|size| size <= params.trivial_body_bytes);
        let trivial_names = skeleton_groups >= 4 && trivial_share >= 0.75;
        if widely_shared || (skeleton_groups >= 3 && (trivial_body || trivial_names)) {
            PatternClass::Coincidence
        } else {
            PatternClass::Disagreement
        }
    };
    Classification {
        class,
        distinct_names,
        skeleton: match class {
            PatternClass::TemplateMember => top_skeleton.map(|(text, _)| text.clone()),
            _ => None,
        },
        skeleton_share,
        skeleton_groups,
    }
}

/// A group is a template member when it dominates the key, blanks at least
/// one argument, holds several specializations, and the specializations
/// beyond the heaviest one carry real weight — one stray push next to a
/// well-attested name does not turn that name into a hole.
fn qualifies_as_member(group: &Group, share: f64, params: &ClassifyParams) -> bool {
    if group.placeholders == 0 || share < params.skeleton_min_share || group.names.len() < 2 {
        return false;
    }
    let heaviest = group.names.values().copied().fold(0.0f64, f64::max);
    let others = group.weight - heaviest;
    others >= (0.05 * group.weight).max(2.0) || group.names.len() >= 3
}

/// Per-key selection outcome with the evidence behind it.
#[derive(Debug, Clone, Serialize)]
pub struct KeyDecision {
    /// Request positions that carried this key.
    pub repeat_count: u32,
    pub served: ServedForm,
    pub provenance: Provenance,
    pub class: PatternClass,
    /// Display form of the served or withheld skeleton.
    pub skeleton: Option<String>,
    pub type_consensus: Option<TypeConsensus>,
    pub specialized_by: Option<Specialization>,
}

impl Default for KeyDecision {
    fn default() -> Self {
        Self {
            repeat_count: 1,
            served: ServedForm::Verbatim,
            provenance: Provenance::Unchecked,
            class: PatternClass::Specific,
            skeleton: None,
            type_consensus: None,
            specialized_by: None,
        }
    }
}

impl KeyDecision {
    pub fn declined(repeat_count: u32, reason: DeclineReason) -> Self {
        Self {
            repeat_count,
            served: ServedForm::Declined(reason),
            ..Self::default()
        }
    }

    pub fn is_declined(&self) -> bool {
        matches!(self.served, ServedForm::Declined(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ClassifyParams {
        ClassifyParams {
            skeleton_min_share: 0.6,
            generic_min_binaries: 8,
            trivial_body_bytes: 0,
            class_hole_members: vec!["qt_metacall".into(), "qt_static_metacall".into()],
        }
    }

    fn names<'a>(rows: &[(&'a str, u32)]) -> Vec<CandidateName<'a>> {
        rows.iter()
            .map(|(name, weight)| CandidateName {
                name,
                num_binaries: *weight,
                declared_size: None,
            })
            .collect()
    }

    const CLONE_A: &str = "_ZNKSt3__110__function6__funcIZN1A1fEvE3$_0NS_9allocatorIS3_EEFvvEE7__cloneEv";
    const CLONE_B: &str = "_ZNKSt3__110__function6__funcIZN1B1gEvE3$_0NS_9allocatorIS3_EEFvvEE7__cloneEv";
    const CLONE_C: &str = "_ZNKSt3__110__function6__funcIZN1C1hEvE3$_0NS_9allocatorIS3_EEFvvEE7__cloneEv";

    #[test]
    fn single_and_suffixed_names_are_specific() {
        let one = classify_names(&names(&[("_ZN3foo3barEv", 5)]), Some(3), &params());
        assert_eq!(one.class, PatternClass::Specific);
        assert_eq!(one.distinct_names, 1);
        let suffixed = classify_names(
            &names(&[("_ZN3foo3barEv", 5), ("_ZN3foo3barEv_0", 1)]),
            Some(6),
            &params(),
        );
        assert_eq!(suffixed.class, PatternClass::Specific);
        assert_eq!(suffixed.distinct_names, 1);
    }

    #[test]
    fn specializations_of_one_member_form_a_template_member() {
        let three = classify_names(
            &names(&[(CLONE_A, 3), (CLONE_B, 1), (CLONE_C, 1)]),
            Some(5),
            &params(),
        );
        assert_eq!(three.class, PatternClass::TemplateMember);
        assert_eq!(
            three.skeleton.as_deref(),
            Some("std::__1::__function::__func<?>::__clone() const")
        );
        assert_eq!(three.distinct_names, 3);
        // Two specializations with weight behind both also qualify.
        let two = classify_names(&names(&[(CLONE_A, 3), (CLONE_B, 2)]), Some(5), &params());
        assert_eq!(two.class, PatternClass::TemplateMember);
        // A single stray push beside a well-attested name does not.
        let stray = classify_names(&names(&[(CLONE_A, 95), (CLONE_B, 1)]), Some(96), &params());
        assert_eq!(stray.class, PatternClass::Specific);
        assert!(stray.skeleton.is_none());
    }

    #[test]
    fn unrelated_names_split_by_ubiquity() {
        let dtors = names(&[
            ("_ZN4node10permission12FSPermission9RadixTreeD2Ev", 14),
            ("_ZN10polynomial12tmp_monomialD1Ev", 10),
            ("_ZNSt3__110__function6__funcIZN1A1fEvE3$_0NS_9allocatorIS3_EEFvvEED2Ev", 3),
            ("_ZN5boost6detail7tss_ptrD1Ev", 1),
        ]);
        let wide = classify_names(&dtors, Some(71), &params());
        assert_eq!(wide.class, PatternClass::Coincidence);
        assert!(wide.skeleton.is_none());
        let capped = classify_names(&dtors, None, &params());
        assert_eq!(capped.class, PatternClass::Coincidence);
        let narrow = classify_names(
            &names(&[("_ZN3foo3barEv", 1), ("_ZN3baz3quxEv", 1)]),
            Some(2),
            &params(),
        );
        assert_eq!(narrow.class, PatternClass::Disagreement);
        // Trivial bodies from several unrelated programs are a coincidence
        // even on a key seen in few binaries.
        let trivial = classify_names(&dtors, Some(4), &params());
        assert_eq!(trivial.class, PatternClass::Coincidence);
    }

    #[test]
    fn moc_dispatchers_of_different_classes_form_a_class_hole_member() {
        let metacalls = names(&[
            ("_ZN10VehicleLed11qt_metacallEN11QMetaObject4CallEiPPv", 1),
            ("_ZN17ELinkCommunicator11qt_metacallEN11QMetaObject4CallEiPPv", 1),
            ("_ZN6Camera11qt_metacallEN11QMetaObject4CallEiPPv", 1),
        ]);
        let read = classify_names(&metacalls, Some(3), &params());
        assert_eq!(read.class, PatternClass::TemplateMember);
        assert_eq!(
            read.skeleton.as_deref(),
            Some("?::qt_metacall(QMetaObject::Call, int, void**)")
        );
        // Destructors and ordinary members are not on the list.
        let dtors = names(&[("_ZN1AD1Ev", 1), ("_ZN1BD1Ev", 1), ("_ZN1CD1Ev", 1)]);
        assert_ne!(
            classify_names(&dtors, Some(3), &params()).class,
            PatternClass::TemplateMember
        );
        let signals = names(&[
            ("_ZN16ClientController16getStatusMessageERK13QJsonDocument", 1),
            ("_ZN16ClientController15setNodesMessageERK13QJsonDocument", 1),
            ("_ZN6Camera13paramsChangedERK12CameraParams", 1),
        ]);
        assert_ne!(
            classify_names(&signals, Some(3), &params()).class,
            PatternClass::TemplateMember
        );
    }

    #[test]
    fn one_dominant_name_stays_specific_and_mixed_keys_fall_through() {
        let dominant = classify_names(
            &names(&[("_ZN3foo3barEv", 9), ("_ZN3baz3quxEv", 1)]),
            Some(10),
            &params(),
        );
        assert_eq!(dominant.class, PatternClass::Specific);
        // A weak template group inside an unrelated majority is not a member.
        let mixed = classify_names(
            &names(&[
                ("_ZN1AD1Ev", 14),
                ("_ZN1BD1Ev", 10),
                (CLONE_A, 2),
                (CLONE_B, 1),
            ]),
            Some(27),
            &params(),
        );
        assert_eq!(mixed.class, PatternClass::Coincidence);
    }
}
