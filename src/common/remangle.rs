//! A servable name for a template member whose specialization is unknown.
//!
//! IDA accepts mangled names and demangles them itself, but rejects
//! demangled text carrying a hole. The skeleton of a template member is
//! therefore served as a *mangled* name whose class template argument list is
//! replaced by one placeholder type: `__func<__lumina_T>::__clone() const`
//! instead of `__func<node::LoadEnvironment…::$_0, …>::__clone() const`.
//!
//! The Itanium substitution table makes textual splicing fragile — every
//! component inside the removed argument list occupied a numbered slot that
//! later `S<n>_` references may point at — so a splice is only ever offered
//! after a round trip: the result must demangle, and its skeleton must equal
//! the skeleton of the original with the placeholder in the hole. Anything
//! else is rejected, and the caller falls back.

use super::demangle::demangle;
use super::skeleton::{skeletonize_display, SkeletonName};

/// Skip a `<len><identifier>` source name (with any abi tags) at `i`.
fn skip_source_name(bytes: &[u8], mut i: usize) -> Option<usize> {
    let start = i;
    while matches!(bytes.get(i), Some(c) if c.is_ascii_digit()) {
        i += 1;
    }
    if i == start {
        return None;
    }
    let len: usize = std::str::from_utf8(&bytes[start..i]).ok()?.parse().ok()?;
    i = i.checked_add(len)?;
    if i > bytes.len() {
        return None;
    }
    while bytes.get(i) == Some(&b'B') {
        i = skip_source_name(bytes, i + 1)?;
    }
    Some(i)
}

/// Skip a substitution (`S_`, `S<seq>_`), the `St` abbreviation, or a
/// template parameter (`T_`, `T<n>_`) at `i`.
fn skip_reference(bytes: &[u8], mut i: usize) -> Option<usize> {
    let lead = *bytes.get(i)?;
    i += 1;
    if lead == b'S' && matches!(bytes.get(i), Some(b't' | b'a' | b'b' | b's' | b'i' | b'o' | b'd')) {
        return Some(i + 1);
    }
    while matches!(bytes.get(i), Some(c) if c.is_ascii_digit() || c.is_ascii_uppercase()) {
        i += 1;
    }
    (bytes.get(i) == Some(&b'_')).then_some(i + 1)
}

/// Index one past the `E` closing the delimited production opened at `i`
/// (`I`, `N`, `Z`, `L`, `X`, `J`, `F`, `Dt`, `DT`), skipping source names,
/// substitutions and template parameters as units.
fn skip_delimited(bytes: &[u8], mut i: usize) -> Option<usize> {
    let mut depth = 0usize;
    loop {
        match *bytes.get(i)? {
            b'0'..=b'9' => i = skip_source_name(bytes, i)?,
            b'S' | b'T' => i = skip_reference(bytes, i)?,
            b'I' | b'N' | b'Z' | b'L' | b'X' | b'J' | b'F' => {
                depth += 1;
                i += 1;
            }
            b'D' if matches!(bytes.get(i + 1), Some(b't' | b'T')) => {
                depth += 1;
                i += 2;
            }
            b'E' => {
                depth = depth.checked_sub(1)?;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
}

/// Locate the class prefix's single top-level template argument list in an
/// Itanium nested name: `_Z N [K|V|r]* <prefix components> I … E <member> E`.
///
/// Returns the byte range of the `I … E` list including its delimiters.
fn class_template_span(mangled: &str) -> Option<std::ops::Range<usize>> {
    let bytes = mangled.as_bytes();
    let mut i = if let Some(rest) = mangled.strip_prefix("__Z") {
        mangled.len() - rest.len()
    } else if let Some(rest) = mangled.strip_prefix("_Z") {
        mangled.len() - rest.len()
    } else {
        return None;
    };
    if bytes.get(i) != Some(&b'N') {
        return None;
    }
    i += 1;
    while matches!(bytes.get(i), Some(b'K' | b'V' | b'r')) {
        i += 1;
    }
    let mut list: Option<std::ops::Range<usize>> = None;
    loop {
        match *bytes.get(i)? {
            b'0'..=b'9' => i = skip_source_name(bytes, i)?,
            b'S' => i = skip_reference(bytes, i)?,
            b'I' => {
                if list.is_some() {
                    return None;
                }
                let end = skip_delimited(bytes, i)?;
                list = Some(i..end);
                i = end;
            }
            b'C' | b'D' => {
                // Constructor or destructor member closes the nested name.
                return (bytes.get(i + 1).is_some_and(|c| c.is_ascii_digit())
                    && bytes.get(i + 2) == Some(&b'E'))
                .then_some(list?);
            }
            b'E' => return list,
            _ => return None,
        }
    }
}

/// The mangled name with its class template argument list replaced by the
/// placeholder type, verified by demangling. `placeholder` must be a plain
/// identifier.
pub fn splice_placeholder_template(
    mangled: &str,
    skeleton: &SkeletonName,
    placeholder: &str,
) -> Option<String> {
    if skeleton.template_placeholders == 0 || !is_identifier(placeholder) {
        return None;
    }
    let span = class_template_span(mangled)?;
    let spliced = format!(
        "{}I{}{}E{}",
        &mangled[..span.start],
        placeholder.len(),
        placeholder,
        &mangled[span.end..]
    );
    verify_round_trip(&spliced, &skeleton.text, placeholder)
}

/// The mangled name of a member of a non-template class with the class
/// replaced by the placeholder: `VehicleLed::qt_metacall(…)` becomes
/// `__lumina_T::qt_metacall(…)`. Only the two-component shape
/// `_Z N <class> <member> E <params>` is accepted.
pub fn splice_placeholder_class(
    mangled: &str,
    skeleton_text: &str,
    placeholder: &str,
) -> Option<String> {
    if !is_identifier(placeholder) {
        return None;
    }
    let bytes = mangled.as_bytes();
    let prefix = if mangled.starts_with("__ZN") {
        4
    } else if mangled.starts_with("_ZN") {
        3
    } else {
        return None;
    };
    let mut i = prefix;
    while matches!(bytes.get(i), Some(b'K' | b'V' | b'r')) {
        i += 1;
    }
    let class_start = i;
    let class_end = skip_source_name(bytes, class_start)?;
    // The member must be a plain source name that closes the nested name.
    let member_end = skip_source_name(bytes, class_end)?;
    if bytes.get(member_end) != Some(&b'E') {
        return None;
    }
    let spliced = format!(
        "{}{}{}{}",
        &mangled[..class_start],
        placeholder.len(),
        placeholder,
        &mangled[class_end..]
    );
    verify_round_trip(&spliced, skeleton_text, placeholder)
}

fn is_identifier(placeholder: &str) -> bool {
    !placeholder.is_empty()
        && placeholder
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Accept a spliced name only if it demangles and every hole of the skeleton
/// comes back as the placeholder, with the rest of the text untouched.
fn verify_round_trip(spliced: &str, skeleton_text: &str, placeholder: &str) -> Option<String> {
    let decoded = demangle(spliced);
    if !decoded.demangled {
        return None;
    }
    let produced = skeletonize_display(&decoded.name);
    let hole = format!("<{placeholder}>");
    let class_hole = format!("{placeholder}::");
    let filled = produced.text.replace(&hole, "<?>");
    let filled = if let Some(rest) = filled.strip_prefix(&class_hole) {
        format!("?::{rest}")
    } else {
        filled
    };
    (filled == skeleton_text && produced.blanked_args.iter().all(|arg| arg == placeholder))
        .then(|| spliced.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::skeleton::skeleton_of;

    const PLACEHOLDER: &str = "__lumina_T";

    fn splice(mangled: &str) -> Option<String> {
        splice_placeholder_template(mangled, &skeleton_of(mangled).unwrap(), PLACEHOLDER)
    }

    #[test]
    fn std_function_thunks_splice_and_round_trip() {
        let target = "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info";
        let spliced = splice(target).unwrap();
        assert_eq!(
            spliced,
            "__ZNKSt3__110__function6__funcI10__lumina_TE6targetERKSt9type_info"
        );
        assert_eq!(
            demangle(&spliced).name,
            "std::__1::__function::__func<__lumina_T>::target(std::type_info const&) const"
        );
        let clone = "_ZNKSt3__110__function6__funcIZN4node15LoadEnvironmentEPNS2_11EnvironmentEE3$_0NS_9allocatorIS5_EEFvvEE7__cloneEv";
        assert_eq!(
            splice(clone).unwrap(),
            "_ZNKSt3__110__function6__funcI10__lumina_TE7__cloneEv"
        );
        let dtor = "_ZNSt3__110__function6__funcIZN1A1fEvE3$_0NS_9allocatorIS3_EEFvvEED1Ev";
        assert_eq!(
            splice(dtor).unwrap(),
            "_ZNSt3__110__function6__funcI10__lumina_TED1Ev"
        );
    }

    #[test]
    fn qt_slot_object_keeps_the_member_signature() {
        let impl_ = "__ZN9QtPrivate15QCallableObjectIM7ELoggerFvvENS_4ListIJEEEvE4implEiPNS_15QSlotObjectBaseEP7QObjectPPvPb";
        let spliced = splice(impl_).unwrap();
        assert_eq!(
            spliced,
            "__ZN9QtPrivate15QCallableObjectI10__lumina_TE4implEiPNS_15QSlotObjectBaseEP7QObjectPPvPb"
        );
        assert_eq!(
            demangle(&spliced).name,
            "QtPrivate::QCallableObject<__lumina_T>::impl(int, QtPrivate::QSlotObjectBase*, QObject*, void**, bool*)"
        );
    }

    #[test]
    fn parameters_echoing_the_class_argument_splice_when_the_round_trip_holds() {
        // `__value_func<F>::swap(__value_func<F>&)`: the parameter refers back
        // to the class, so both holes must come out as the placeholder.
        let swap = "__ZNSt3__110__function12__value_funcIFvyEE4swapB8ne200100ERS3_";
        let spliced = splice(swap).unwrap();
        assert_eq!(
            demangle(&spliced).name,
            "std::__1::__function::__value_func<__lumina_T>::swap[abi:ne200100](std::__1::__function::__value_func<__lumina_T>&)"
        );
    }

    #[test]
    fn non_template_class_members_splice_the_class() {
        let metacall = "__ZN10VehicleLed11qt_metacallEN11QMetaObject4CallEiPPv";
        let spliced = splice_placeholder_class(
            metacall,
            "?::qt_metacall(QMetaObject::Call, int, void**)",
            PLACEHOLDER,
        )
        .unwrap();
        assert_eq!(spliced, "__ZN10__lumina_T11qt_metacallEN11QMetaObject4CallEiPPv");
        assert_eq!(
            demangle(&spliced).name,
            "__lumina_T::qt_metacall(QMetaObject::Call, int, void**)"
        );
        // Namespaced classes and template classes are not this shape.
        assert!(splice_placeholder_class(
            "_ZN4node10permission12FSPermission9RadixTreeD2Ev",
            "?::~RadixTree()",
            PLACEHOLDER
        )
        .is_none());
        assert!(splice_placeholder_class(
            "__ZN9QtPrivate15QCallableObjectIM7ELoggerFvvENS_4ListIJEEEvE4implEiPNS_15QSlotObjectBaseEP7QObjectPPvPb",
            "?::impl(int, QtPrivate::QSlotObjectBase*, QObject*, void**, bool*)",
            PLACEHOLDER
        )
        .is_none());
    }

    #[test]
    fn shapes_outside_the_grammar_are_refused() {
        // The parameter's argument list shifts a substitution that the
        // round trip cannot reconcile with the skeleton.
        let tree = "_ZNSt3__16__treeIPN8aletheia8VariableENS_4lessIS3_EENS_9allocatorIS3_EEE7destroyEPNS_11__tree_nodeIS3_PvEE";
        assert!(splice(tree).is_none());
        // Template member function, not a class template member.
        let emplace = "_ZNSt3__114__split_bufferIPPN6fuzzer7FuzzJobENS_9allocatorIS4_EEE12emplace_backIJRS4_EEEvDpOT_";
        assert!(splice(emplace).is_none());
        // Not a specialization at all.
        let plain = "_ZN3foo3barEv";
        assert!(splice(plain).is_none());
        // A bad placeholder is refused before any splicing.
        let skeleton = skeleton_of(
            "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info",
        )
        .unwrap();
        assert!(splice_placeholder_template(
            "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info",
            &skeleton,
            "not an identifier"
        )
        .is_none());
    }
}
