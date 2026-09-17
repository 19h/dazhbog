//! Resolving a template member's specialization from the request itself.
//!
//! IDA sends patterns in address order, and a compiler emits the thunks of
//! one specialization next to each other: `__func<X>::__clone`,
//! `__func<X>::destroy`, `__func<X>::target` and the specialization's own
//! `operator()` sit within a few functions of one another. The thunks share
//! a pattern with every other program's `X`; the `operator()` does not. So
//! when a donor that carries candidate `<X>::member` also carries a rare
//! neighbour of the position being answered, and that neighbour's stored
//! name mentions `X`, the requester's specialization is `X` and the verbatim
//! candidate can be served. Otherwise the skeleton stands.

use std::collections::HashSet;

use crate::common::demangle::demangle;
use crate::common::neighbor::is_generic_neighbor_token;

/// Words too common in template arguments to identify a specialization.
const ARGUMENT_STOPWORDS: &[&str] = &[
    "std", "__1", "__ndk1", "allocator", "void", "const", "char", "int", "long", "short",
    "unsigned", "signed", "bool", "float", "double", "function", "list", "qtprivate",
    "basic_string", "char_traits", "shared_ptr", "unique_ptr", "vector", "operator", "lambda",
    "anonymous", "namespace",
];

/// Identifier tokens of a blanked template argument that could name the
/// specialization: `void (VehicleLed::*)()` → `{vehicleled}`,
/// `node::LoadEnvironment(node::Environment*)::$_0` → `{node, loadenvironment,
/// environment}`.
pub fn specialization_tokens(argument: &str) -> HashSet<String> {
    argument
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .map(str::to_ascii_lowercase)
        .filter(|token| {
            token.len() >= 3
                && !token.chars().all(|c| c.is_ascii_digit() || c == '_')
                && !ARGUMENT_STOPWORDS.contains(&token.as_str())
                && !is_generic_neighbor_token(token)
        })
        .collect()
}

/// Whether a neighbour's stored name mentions every token of a
/// specialization.
pub fn name_mentions(neighbour_name: &str, tokens: &HashSet<String>) -> bool {
    if tokens.is_empty() {
        return false;
    }
    let decoded = demangle(neighbour_name);
    let haystack = if decoded.demangled {
        decoded.name.to_ascii_lowercase()
    } else {
        neighbour_name.to_ascii_lowercase()
    };
    let words: HashSet<String> = haystack
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .map(str::to_string)
        .collect();
    tokens.iter().all(|token| words.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_name_the_specialization_not_the_scaffolding() {
        let tokens = specialization_tokens(
            "node::LoadEnvironment(node::Environment*)::$_0, std::__1::allocator<node::LoadEnvironment(node::Environment*)::$_0>, void ()",
        );
        assert_eq!(
            tokens,
            HashSet::from(["node".into(), "loadenvironment".into(), "environment".into()])
        );
        assert_eq!(
            specialization_tokens("void (VehicleLed::*)(), QtPrivate::List<>, void"),
            HashSet::from(["vehicleled".into()])
        );
        assert!(specialization_tokens("int, std::__1::allocator<int>").is_empty());
    }

    #[test]
    fn neighbours_are_matched_on_whole_words_of_their_demangled_name() {
        let tokens = specialization_tokens("Alpha::run()::$_0, std::__1::allocator<Alpha::run()::$_0>, void ()");
        assert!(name_mentions(
            "_ZNKSt3__110__function6__funcIZN5Alpha3runEvE3$_0NS_9allocatorIS3_EEFvvEEclEv",
            &tokens
        ));
        assert!(name_mentions("_ZN5Alpha3runEv", &tokens));
        assert!(!name_mentions("_ZN4Beta3runEv", &tokens));
        assert!(!name_mentions("_ZN12Alphabetical3runEv", &tokens));
        assert!(!name_mentions("anything", &HashSet::new()));
    }
}
