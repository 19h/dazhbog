//! Name normalization for patterns that stand for many functions.
//!
//! IDA keeps function names unique per database: when a name is applied to
//! a second function it appends `_0`, `_1`, … Names pushed from such a
//! database therefore carry a suffix that is not part of the symbol, breaks
//! demangling and splits one symbol into several stored variants.
//!
//! A template member's machine code is the same for every specialization
//! whenever the body depends only on the shape of the argument (a type_info
//! relocation, a pointer-to-member loaded from the object, an element size),
//! so one Lumina pattern collects `__func<A>::__clone`, `__func<B>::__clone`,
//! … from every program. The *skeleton* of such a name is the demangled text
//! with every top-level template argument list replaced by `<?>`; candidates
//! of one key that share a skeleton are specializations of one member, and
//! the skeleton is what the pattern actually identifies.

use super::demangle::demangle;

/// A demangled name with its specialization arguments blanked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonName {
    /// Canonical text with `<?>` for each top-level template argument list
    /// and `?λ` for each closure outside such a list.
    pub text: String,
    /// Number of `<?>` holes; zero means the name is not a specialization.
    pub template_placeholders: u8,
    /// Closures blanked outside template lists; these never make a name a
    /// template member on their own.
    pub lambda_placeholders: u8,
    /// The blanked argument lists, in order, for hole filling.
    pub blanked_args: Vec<String>,
}

/// The skeleton of a stored name: collision suffix stripped, demangled and
/// blanked. `None` when the name does not demangle, so a plain name can
/// never be mistaken for a template member.
pub fn skeleton_of(name: &str) -> Option<SkeletonName> {
    let stem = strip_ida_duplicate_suffix(name).unwrap_or(name);
    let decoded = demangle(stem);
    if !decoded.demangled || decoded.name.is_empty() {
        return None;
    }
    Some(skeletonize_display(&decoded.name))
}

/// Operators whose symbols would otherwise be read as brackets, longest
/// first so `<<=` is not split into `<<` and `=`.
const OPERATORS: &[&str] = &[
    "<=>", "->*", "<<=", ">>=", "<<", ">>", "<=", ">=", "->", "<", ">", "()", "[]", "\"\"",
];
const SENTINEL_BASE: u32 = 0xE000;

/// Blank the specialization arguments of a demangled name.
///
/// Steps: protect `operator<`-style symbols, drop `[abi:…]` tags, replace
/// every template argument list that is not nested in another one by `<?>`,
/// replace closures outside such lists by `?λ`, blank echoes of blanked
/// arguments in the parameter list (`emplace_back<X&>(X&)` →
/// `emplace_back<?>(?)`), and canonicalize spacing.
pub fn skeletonize_display(display: &str) -> SkeletonName {
    let protected = protect_operators(display);
    let untagged = strip_abi_tags(&protected);
    let chars: Vec<char> = untagged.chars().collect();
    let mut blanked_args = Vec::new();
    let (blanked, template_placeholders) = blank_template_lists(&chars, &mut blanked_args);
    let (blanked, lambda_placeholders) = blank_closures(&blanked);
    let echoed = blank_argument_echoes(&blanked, &blanked_args);
    let text = restore_operators(&canonical_spacing(&echoed));
    SkeletonName {
        text,
        template_placeholders,
        lambda_placeholders,
        blanked_args,
    }
}

fn protect_operators(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("operator") {
        out.push_str(&rest[..at + "operator".len()]);
        rest = &rest[at + "operator".len()..];
        if let Some((index, op)) = OPERATORS
            .iter()
            .enumerate()
            .find(|(_, op)| rest.starts_with(*op))
        {
            out.push(char::from_u32(SENTINEL_BASE + index as u32).unwrap());
            rest = &rest[op.len()..];
        }
    }
    out.push_str(rest);
    out
}

fn restore_operators(s: &str) -> String {
    s.chars()
        .map(|c| {
            let code = c as u32;
            if (SENTINEL_BASE..SENTINEL_BASE + OPERATORS.len() as u32).contains(&code) {
                OPERATORS[(code - SENTINEL_BASE) as usize].to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn strip_abi_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("[abi:") {
        out.push_str(&rest[..at]);
        match rest[at..].find(']') {
            Some(end) => rest = &rest[at + end + 1..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn opens_template_list(s: &[char], i: usize) -> bool {
    i > 0 && matches!(s[i - 1], c if c.is_alphanumeric() || c == '_' || c == '$' || c == '>' || c == ')')
}

/// Replace each template argument list not nested in another by `<?>`.
fn blank_template_lists(s: &[char], args: &mut Vec<String>) -> (String, u8) {
    let mut out = String::with_capacity(s.len());
    let mut holes = 0u8;
    let mut i = 0;
    while i < s.len() {
        if s[i] == '<' && opens_template_list(s, i) {
            let mut depth = 0i32;
            let mut j = i;
            let mut closed = false;
            while j < s.len() {
                match s[j] {
                    '<' => depth += 1,
                    '>' if j > 0 && s[j - 1] == '-' => {}
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            closed = true;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if closed {
                let inner: String = s[i + 1..j].iter().collect();
                args.push(inner.trim().to_string());
                out.push_str("<?>");
                holes = holes.saturating_add(1);
                i = j + 1;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    (out, holes)
}

/// Replace closures written outside template lists by `?λ`: razgad's
/// `{lambda(int)#1}` and `{unnamed type#1}`, c++filt's `'lambda2'(expr*)`,
/// clang's `(lambda at file.cpp:63:3)`, `$_15`, and MSVC's `<lambda_1a2b>`.
fn blank_closures(s: &str) -> (String, u8) {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut count = 0u8;
    let mut i = 0;
    while i < chars.len() {
        let rest: String = chars[i..].iter().take(12).collect();
        let span = if rest.starts_with("{lambda") || rest.starts_with("{unnamed") {
            balanced_span(&chars, i, '{', '}')
        } else if rest.starts_with("'lambda") {
            quoted_lambda_span(&chars, i)
        } else if rest.starts_with("(lambda at ") {
            balanced_span(&chars, i, '(', ')')
        } else if rest.starts_with("$_") && chars.get(i + 2).is_some_and(|c| c.is_ascii_digit()) {
            let mut j = i + 2;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            Some(j)
        } else if rest.starts_with("<lambda_") {
            balanced_span(&chars, i, '<', '>')
        } else {
            None
        };
        match span {
            Some(end) => {
                out.push_str("?λ");
                count = count.saturating_add(1);
                i = end;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    (out, count)
}

/// Index one past the bracket matching the opener at `start`.
fn balanced_span(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0i32;
    for (j, &c) in chars.iter().enumerate().skip(start) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(j + 1);
            }
        }
    }
    None
}

/// `'lambda'(args)` / `'lambdaN'(args)`: the quoted word plus its parameter
/// list when one follows.
fn quoted_lambda_span(chars: &[char], start: usize) -> Option<usize> {
    let close = chars[start + 1..].iter().position(|&c| c == '\'')? + start + 1;
    let after = close + 1;
    if chars.get(after) == Some(&'(') {
        balanced_span(chars, after, '(', ')')
    } else {
        Some(after)
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == ':' || c == '$'
}

/// Replace whole-token occurrences of each blanked argument (longest first)
/// by `?`, so a dependent parameter type reads as the hole it refers to.
fn blank_argument_echoes(s: &str, args: &[String]) -> String {
    let mut ordered: Vec<&String> = args.iter().filter(|a| a.len() >= 3).collect();
    ordered.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let mut text = s.to_string();
    for arg in ordered {
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some(at) = rest.find(arg.as_str()) {
            let before = rest[..at].chars().next_back();
            let after = rest[at + arg.len()..].chars().next();
            let bounded = !before.is_some_and(is_ident) && !after.is_some_and(is_ident);
            out.push_str(&rest[..at]);
            if bounded {
                out.push('?');
            } else {
                out.push_str(arg);
            }
            rest = &rest[at + arg.len()..];
        }
        out.push_str(rest);
        text = out;
    }
    text
}

fn canonical_spacing(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space {
            let last = out.chars().next_back();
            let drop = matches!(c, '*' | '&' | ',' | ')' | '>')
                || matches!(last, Some('(') | Some('<') | None);
            if !drop {
                out.push(' ');
            }
            pending_space = false;
        }
        out.push(c);
    }
    out
}

/// Whether a name denotes a body that is trivial by construction — a
/// destructor, a copy assignment, a static initializer, an allocator
/// release — so that agreement on it says nothing about the program.
pub fn is_trivial_member(raw_name: &str, skeleton_text: Option<&str>) -> bool {
    if raw_name.starts_with("_GLOBAL__sub_I_")
        || raw_name.starts_with("__GLOBAL__sub_I_")
        || raw_name.ends_with("D0Ev")
        || raw_name.ends_with("D1Ev")
        || raw_name.ends_with("D2Ev")
        || raw_name.contains("drop_in_place")
    {
        return true;
    }
    let Some(text) = skeleton_text else {
        return false;
    };
    let head = text.split('(').next().unwrap_or(text);
    let leaf = head.rsplit("::").next().unwrap_or(head).trim();
    leaf.starts_with('~')
        || leaf == "operator="
        || leaf == "destroy_deallocate"
        || leaf.starts_with("drop_in_place")
}

/// The IDA duplicate-name suffix removed, when the name carries one.
///
/// A trailing `_<digits>` (at most four groups of at most four digits) is a
/// collision suffix only if the remainder is a decodable mangled name that
/// demangles at least as completely as the full string does. Demanglers
/// tolerate trailing junk — `_ZN3foo3barEv_0` still decodes, but to
/// `foo::bar` instead of `foo::bar()` — so the comparison, not the failure,
/// is the signal. `crc_32` and `foo_1` have no decodable stem and are left
/// alone; the shortest qualifying stem wins when several groups stack.
pub fn strip_ida_duplicate_suffix(name: &str) -> Option<&str> {
    let full = demangle(name);
    let mut best: Option<&str> = None;
    let mut best_len = if full.demangled { full.name.len() } else { 0 };
    let mut stem = name;
    for _ in 0..4 {
        let Some(shorter) = trim_suffix_group(stem) else {
            break;
        };
        stem = shorter;
        if stem.is_empty() {
            break;
        }
        let bare = demangle(stem);
        if bare.demangled && bare.name.len() >= best_len {
            best_len = bare.name.len();
            best = Some(stem);
        }
    }
    best
}

/// `name` without one trailing `_<1..=4 digits>` group.
fn trim_suffix_group(name: &str) -> Option<&str> {
    let bytes = name.as_bytes();
    let mut end = bytes.len();
    let mut digits = 0;
    while end > 0 && bytes[end - 1].is_ascii_digit() {
        end -= 1;
        digits += 1;
    }
    if digits == 0 || digits > 4 || end == 0 || bytes[end - 1] != b'_' {
        return None;
    }
    Some(&name[..end - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ida_collision_suffix_only_when_it_breaks_a_mangled_name() {
        assert_eq!(
            strip_ida_duplicate_suffix("__ZNSt16invalid_argumentC1EPKc_12"),
            Some("__ZNSt16invalid_argumentC1EPKc")
        );
        assert_eq!(
            strip_ida_duplicate_suffix(
                "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info_0"
            ),
            Some(
                "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info"
            )
        );
        assert_eq!(
            strip_ida_duplicate_suffix("_ZN3foo3barEv_0_1"),
            Some("_ZN3foo3barEv")
        );
    }

    fn text(display: &str) -> String {
        skeletonize_display(display).text
    }

    #[test]
    fn std_function_thunks_share_one_skeleton_across_closure_spellings() {
        let expected = "std::__1::__function::__func<?>::__clone() const";
        for display in [
            "std::__1::__function::__func<livox::MultipleIOBase::WakeUpInit()::$_0, std::__1::allocator<livox::MultipleIOBase::WakeUpInit()::$_0>, void ()>::__clone() const",
            "std::__1::__function::__func<node::(anonymous namespace)::FdEntry::ReaderImpl::DrainAndClose()::{lambda(unsigned long long)#1}, std::__1::allocator<node::(anonymous namespace)::FdEntry::ReaderImpl::DrainAndClose()::{lambda(unsigned long long)#1}>, void (unsigned long long)>::__clone() const",
            "std::__1::__function::__func<mbp_basic_tg::impl::apply()::'lambda2'(expr*), std::__1::allocator<mbp_basic_tg::impl::apply()::'lambda2'(expr*)>, void (expr*)>::__clone() const",
            "std::__1::__function::__func<(lambda at /home/u/x.cpp:63:3), std::__1::allocator<(lambda at /home/u/x.cpp:63:3)>, long ()>::__clone() const",
            "std::__1::__function::__func<Foo::removeSlot(int, std::__1::function<void ()>, bool)::$_15::operator()() const::{lambda()#1}, std::__1::allocator<Foo::removeSlot(int, std::__1::function<void ()>, bool)::$_15::operator()() const::{lambda()#1}>, void ()>::__clone() const",
        ] {
            let skeleton = skeletonize_display(display);
            assert_eq!(skeleton.text, expected, "{display}");
            assert_eq!(skeleton.template_placeholders, 1);
        }
        assert_eq!(
            text("std::__1::__function::__func<synopsia_set_address_callback::$_0, std::__1::allocator<synopsia_set_address_callback::$_0>, void (unsigned long long)>::target(std::type_info const&) const"),
            text("std::__1::__function::__func<X::$_0, std::__1::allocator<X::$_0>, void ()>::target(std::type_info const &) const"),
        );
    }

    #[test]
    fn qt_slot_objects_and_containers_blank_to_their_member() {
        let skeleton = skeletonize_display(
            "QtPrivate::QCallableObject<void (ELogger::*)(), QtPrivate::List<>, void>::impl(int, QtPrivate::QSlotObjectBase*, QObject*, void**, bool*)",
        );
        assert_eq!(
            skeleton.text,
            "QtPrivate::QCallableObject<?>::impl(int, QtPrivate::QSlotObjectBase*, QObject*, void**, bool*)"
        );
        assert_eq!(skeleton.blanked_args, vec!["void (ELogger::*)(), QtPrivate::List<>, void"]);
        let tree = skeletonize_display(
            "std::__1::__tree<aletheia::Variable*, std::__1::less<aletheia::Variable*>, std::__1::allocator<aletheia::Variable*>>::destroy(std::__1::__tree_node<aletheia::Variable*, void*>*)",
        );
        assert_eq!(
            tree.text,
            "std::__1::__tree<?>::destroy(std::__1::__tree_node<?>*)"
        );
        assert_eq!(tree.template_placeholders, 2);
        assert_eq!(
            text("void std::__1::__split_buffer<fuzzer::FuzzJob**, std::__1::allocator<fuzzer::FuzzJob**>>::emplace_back<fuzzer::FuzzJob**&>(fuzzer::FuzzJob**&)"),
            "void std::__1::__split_buffer<?>::emplace_back<?>(?)"
        );
        assert_eq!(
            text("std::__1::vector<Foo, std::__1::allocator<Foo>>::~vector[abi:ne200100]()"),
            "std::__1::vector<?>::~vector()"
        );
        let plain = skeletonize_display("std::__1::__throw_length_error[abi:nqe220106](char const*)");
        assert_eq!(plain.text, "std::__1::__throw_length_error(char const*)");
        assert_eq!(plain.template_placeholders, 0);
        assert_eq!(text("A<B<C>>::f(D<E>)"), "A<?>::f(D<?>)");
        assert_eq!(text("Q<decltype(0)>::f()"), "Q<?>::f()");
    }

    #[test]
    fn operators_and_non_template_names_keep_their_brackets() {
        assert_eq!(text("Foo::operator<(Foo const&) const"), "Foo::operator<(Foo const&) const");
        assert_eq!(text("Bar<int>::operator<<(std::ostream&)"), "Bar<?>::operator<<(std::ostream&)");
        assert_eq!(text("Baz<X>::operator->() const"), "Baz<?>::operator->() const");
        assert_eq!(
            text("Q<int>::operator<=>(Q<int> const&) const"),
            "Q<?>::operator<=>(Q<?> const&) const"
        );
        for display in [
            "_GLOBAL__sub_I_IpAddress.cpp",
            "main",
            "-[NSUserDefaults saveArrayValue:forKey:]",
            "node::crypto::CheckPrimeConfig::~CheckPrimeConfig()",
        ] {
            let skeleton = skeletonize_display(display);
            assert_eq!(skeleton.text, display);
            assert_eq!(skeleton.template_placeholders, 0);
        }
        let msvc = skeletonize_display(
            "public: static void __cdecl QtPrivate::QCallableObject<void (__cdecl ELogger::*)(void),struct QtPrivate::List<>,void>::impl(int,class QtPrivate::QSlotObjectBase *,class QObject *,void * *,bool *)",
        );
        assert_eq!(
            msvc.text,
            "public: static void __cdecl QtPrivate::QCallableObject<?>::impl(int,class QtPrivate::QSlotObjectBase*,class QObject*,void**,bool*)"
        );
        let lambda = skeletonize_display("`anonymous namespace'::<lambda_a1b2>::operator()(void) const");
        assert_eq!(lambda.template_placeholders, 0);
        assert_eq!(lambda.lambda_placeholders, 1);
        let own = skeletonize_display(
            "node::(anonymous namespace)::FdEntry::ReaderImpl::DrainAndClose()::{lambda(unsigned long long)#1}::operator()(unsigned long long) const",
        );
        assert_eq!(own.template_placeholders, 0);
        assert_eq!(own.lambda_placeholders, 1);
    }

    #[test]
    fn skeleton_of_strips_suffix_and_rejects_plain_names() {
        let with_suffix = skeleton_of(
            "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info_0",
        )
        .unwrap();
        let bare = skeleton_of(
            "__ZNKSt3__110__function6__funcIZ29synopsia_set_address_callbackE3$_0NS_9allocatorIS2_EEFvyEE6targetERKSt9type_info",
        )
        .unwrap();
        assert_eq!(with_suffix, bare);
        assert_eq!(
            bare.text,
            "std::__1::__function::__func<?>::target(std::type_info const&) const"
        );
        assert!(skeleton_of("sub_401000").is_none());
        assert!(skeleton_of("crc_32").is_none());
    }

    #[test]
    fn trivial_members_are_recognized() {
        assert!(is_trivial_member("_ZN4node10permission12FSPermission9RadixTreeD2Ev", None));
        assert!(is_trivial_member("_GLOBAL__sub_I_IpAddress.cpp", None));
        assert!(is_trivial_member(
            "x",
            Some("polynomial::tmp_monomial::~tmp_monomial()")
        ));
        assert!(is_trivial_member("x", Some("A::operator=(A const&)")));
        assert!(!is_trivial_member(
            "_ZN3foo3barEv",
            Some("std::__1::__function::__func<?>::__clone() const")
        ));
    }

    #[test]
    fn leaves_plain_and_intact_names_alone() {
        for name in [
            "foo_1",
            "crc_32",
            "sub_401000",
            "sub_1",
            "_ZN3foo3barEv",
            "_ZZN4node3fooEvE_8__invokeES2_i",
            "_ZN4core3ptr13drop_in_place17h2263e5174690862cE",
            "_GLOBAL__sub_I_IpAddress.cpp",
            "",
            "_",
        ] {
            assert_eq!(strip_ida_duplicate_suffix(name), None, "{name}");
        }
    }
}
