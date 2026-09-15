//! Shared precision filter for candidate retrieval and neighbor reranking.
//! The sorted union preserves both historical generic-token exclusions.

const GENERIC_NEIGHBOR_TOKENS: &[&str] = &[
    "0ca",
    "__cdecl",
    "__cxx11",
    "__dst",
    "__fastcall",
    "__formal",
    "__hidden",
    "__int16",
    "__int64",
    "__return_ptr",
    "__src",
    "__stdcall",
    "__struct_ptr",
    "__thiscall",
    "__usercall",
    "__userpurge",
    "__vectorcall",
    "_lambda_1_",
    "aarch64",
    "aeaa",
    "aeaaxxz",
    "aeaufframe",
    "aeav",
    "aebv",
    "amd64",
    "arg",
    "argloc",
    "args",
    "argsize",
    "arm",
    "arm64",
    "avx",
    "back_chain",
    "backend",
    "bool",
    "byte",
    "bytes",
    "case",
    "cases",
    "cdecl",
    "char",
    "cold",
    "common",
    "const",
    "context",
    "default",
    "defaults",
    "deleting",
    "dispatch",
    "dispatcher",
    "double",
    "dword",
    "emulator",
    "engine",
    "entry",
    "err",
    "error",
    "errors",
    "far",
    "fastcall",
    "field",
    "fields",
    "float",
    "frame",
    "frontend",
    "frregs",
    "frsize",
    "func",
    "function",
    "generic",
    "handler",
    "impl",
    "int",
    "internal",
    "jumptable",
    "loc",
    "long",
    "manager",
    "mips",
    "module",
    "near",
    "neon",
    "null",
    "offset",
    "oword",
    "param",
    "params",
    "peav",
    "ppc",
    "ptr",
    "qeaa",
    "qeaaxxz",
    "qeav",
    "qeax",
    "qeba",
    "qword",
    "ref",
    "ret",
    "retstr",
    "return",
    "sapeavuclass",
    "sapeavuscriptstruct",
    "saved_r4",
    "saxpeavuobject",
    "sender_sp",
    "short",
    "signed",
    "size",
    "sse",
    "stack",
    "state",
    "stdcall",
    "struct",
    "sub",
    "switch",
    "table",
    "this",
    "thiscall",
    "type",
    "u20",
    "u7b",
    "u7d",
    "ueaa",
    "ueaapeaxi",
    "ueaaxxz",
    "ueba",
    "uint",
    "ulong",
    "unsigned",
    "usercall",
    "userpurge",
    "ushort",
    "uuu",
    "v_0",
    "var",
    "vectorcall",
    "vfmember",
    "void",
    "word",
    "x64",
    "x86",
    "x86_64",
    "yapeavuclass",
    "yapeavufunction",
    "zzappendmembergetprev",
];

pub(crate) fn is_generic_neighbor_token(token: &str) -> bool {
    let raw_lower = token.trim().to_ascii_lowercase();
    let normalized = normalize_neighbor_token(token);
    normalized.len() < 3
        || normalized.chars().all(|ch| ch.is_ascii_digit())
        || GENERIC_NEIGHBOR_TOKENS
            .binary_search(&raw_lower.as_str())
            .is_ok()
        || GENERIC_NEIGHBOR_TOKENS
            .binary_search(&normalized.as_str())
            .is_ok()
        || (raw_lower.starts_with("__") && normalized.ends_with("call"))
        || is_arch_neighbor_token(&normalized)
        || is_register_neighbor_token(&normalized)
        || is_simd_neighbor_token(&raw_lower)
}

fn normalize_neighbor_token(token: &str) -> String {
    token
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .to_ascii_lowercase()
}

fn is_arch_neighbor_token(token: &str) -> bool {
    matches!(
        token,
        "x86" | "x64" | "x86_64" | "amd64" | "arm" | "arm64" | "aarch64" | "mips" | "ppc"
    )
}

fn is_register_neighbor_token(token: &str) -> bool {
    matches!(
        token,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "bp"
            | "sp"
            | "lr"
            | "pc"
            | "fp"
    ) || token
        .strip_prefix('r')
        .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
        .unwrap_or(false)
        || token
            .strip_prefix('x')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || token
            .strip_prefix('w')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
}

fn is_simd_neighbor_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("__m") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generic_tokens_are_sorted_and_normalization_keeps_prefix_semantics() {
        assert!(GENERIC_NEIGHBOR_TOKENS.windows(2).all(|p| p[0] < p[1]));
        for token in [
            "__m128",
            "__M256",
            "__customcall",
            "r15",
            "w10",
            "X86_64",
            "stack",
            "func",
            "bytes",
        ] {
            assert!(is_generic_neighbor_token(token), "{token}");
        }
        for token in [
            "http_request",
            "inflate_block",
            "m128_reader",
            "my_call",
            "r15_value",
        ] {
            assert!(!is_generic_neighbor_token(token), "{token}");
        }
    }
}
