//! Search-related type definitions.

use serde::Serialize;

/// Binary reference attached to a function hit.
#[derive(Debug, Clone, Serialize)]
pub struct BinaryRefHit {
    pub md5_hex: String,
    pub short_id: String,
    pub basename: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticNeighborRationale {
    pub family_score: f32,
    pub direct_binary_score: f32,
    pub related_binary_score: f32,
    pub lexical_prior: f32,
    pub semantic_overlap: f32,
    pub prototype_overlap: f32,
    pub frame_overlap: f32,
    pub comment_overlap: f32,
    pub operand_overlap: f32,
    pub origin_overlap: f32,
    pub binary_name_overlap: f32,
    pub candidate_consistency: f32,
    pub language_match: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_semantic_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_prototype_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_frame_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_comment_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_operand_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_family_binaries: Vec<BinaryRefHit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_family_binaries: Vec<BinaryRefHit>,
}

/// Document for search indexing.
#[derive(Debug, Clone)]
pub struct SearchDocument {
    pub key: u128,
    pub func_name: String,
    /// Pre-computed demangled name (empty string if not demangled).
    pub func_name_demangled: String,
    /// Detected language from demangling (empty string if not detected).
    pub lang: String,
    pub binary_names: Vec<String>,
    pub origin_tokens: Vec<String>,
    pub prototype_tokens: Vec<String>,
    pub frame_tokens: Vec<String>,
    pub comment_tokens: Vec<String>,
    pub operand_tokens: Vec<String>,
    pub semantic_tokens: Vec<String>,
    /// Bounded union of live variant tokens; used only for neighbor retrieval.
    pub variant_tokens: Vec<String>,
    pub ts: u64,
}

/// Search result hit.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub key_hex: String,
    pub func_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub func_name_demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    pub binary_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<BinaryRefHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_neighbor: Option<SemanticNeighborRationale>,
    pub ts: u64,
    pub score: f32,
}

impl SearchHit {
    /// Create a new SearchHit with pre-computed demangled name
    pub fn new_with_demangled(
        key_hex: String,
        func_name: String,
        func_name_demangled: String,
        lang: String,
        binary_names: Vec<String>,
        ts: u64,
        score: f32,
    ) -> Self {
        let (func_name_demangled, lang) = if func_name_demangled.is_empty() {
            (None, None)
        } else {
            (
                Some(func_name_demangled),
                if lang.is_empty() { None } else { Some(lang) },
            )
        };

        Self {
            key_hex,
            func_name,
            func_name_demangled,
            lang,
            binary_names,
            binaries: Vec::new(),
            semantic_neighbor: None,
            ts,
            score,
        }
    }
}
