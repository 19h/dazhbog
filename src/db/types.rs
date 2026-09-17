//! Database type definitions.

use serde::Serialize;

/// Latest function metadata from the database.
#[derive(Debug, Clone)]
pub struct FuncLatest {
    pub popularity: u32,
    /// Declared function size from the push (`func_info_t.size`). Legacy records
    /// without `REC_FLAG_DECLARED_SIZE` report the metadata length here.
    pub len_bytes: u32,
    pub ts_sec: u64,
    pub name: String,
    pub data: Vec<u8>,
}

/// Context information for push operations.
#[derive(Clone, Debug)]
pub struct PushContext<'a> {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub origin_token: Option<&'a str>,
}

/// Owned version of PushContext for use in spawn_blocking.
#[derive(Clone, Debug)]
pub struct OwnedPushContext {
    pub md5: Option<[u8; 16]>,
    pub basename: Option<String>,
    pub hostname: Option<String>,
    pub origin_token: Option<String>,
}

/// Context information for query operations.
#[derive(Clone, Debug)]
pub struct QueryContext<'a> {
    pub keys: &'a [u128],
    pub requested_mdkeys: &'a [u32],
    pub md5: Option<[u8; 16]>,
    pub basename: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub origin_token: Option<&'a str>,
}

/// Selected payload plus retrieval diagnostics. Scores are not probabilities.
/// `base_version_id` identifies the stored donor before shaping or synthesis.
/// Margin and entropy describe the eligible pool after binary filtering; neither
/// measures uncertainty about inferred binary identity.
#[derive(Debug, Clone)]
pub struct SelectedVariant {
    pub popularity: u32,
    /// Declared function size of the selected donor (see `FuncLatest::len_bytes`).
    pub func_size: u32,
    /// Timestamp of the selected stored donor, in Unix seconds.
    pub ts_sec: u64,
    pub name: String,
    pub data: Vec<u8>,
    pub score: f64,
    pub margin: f64,
    pub entropy: f64,
    pub used_synthesis: bool,
    pub base_version_id: [u8; 32],
    pub candidate_version_ids: Vec<[u8; 32]>,
    /// Read aliases in the same candidate order; aliases are not extra variants.
    pub base_legacy_version_id: [u8; 32],
    pub candidate_legacy_version_ids: Vec<[u8; 32]>,
    /// Conserved inferred-binary evidence mass, not calibrated probability.
    pub binary_support: f64,
    pub candidate_binary_support: Vec<f64>,
    /// Strongest individual binary match; siblings cannot multiply this value.
    pub binary_match: f64,
    /// Configured inferred cutoff before explicit-ID and semantic overrides.
    pub binary_priority_floor: f64,
    pub candidate_binary_match: Vec<f64>,
}

impl SelectedVariant {
    pub fn matches_version(&self, id: &[u8; 32]) -> bool {
        *id == self.base_version_id || *id == self.base_legacy_version_id
    }

    pub fn contains_version(&self, id: &[u8; 32]) -> bool {
        self.candidate_version_ids.contains(id) || self.candidate_legacy_version_ids.contains(id)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReplayRequestMode {
    Full,
    Structure,
    Comments,
    Operands,
}

#[derive(Debug, Clone)]
pub struct ReplayCaseOptions {
    pub request_mode: ReplayRequestMode,
    pub max_versions: usize,
}

#[derive(Debug, Clone)]
pub struct ReplaySelectorResult {
    pub base_version_id: [u8; 32],
    pub name: String,
    pub data: Vec<u8>,
    pub score: f64,
    pub margin: f64,
    pub entropy: f64,
    pub used_synthesis: bool,
}

#[derive(Debug, Clone)]
pub struct ReplayCaseResult {
    pub key: u128,
    pub holdout_version_id: [u8; 32],
    pub holdout_name: String,
    pub holdout_data: Vec<u8>,
    pub requested_mdkeys: Vec<u32>,
    pub candidate_count: usize,
    pub baseline: ReplaySelectorResult,
    pub semantic: ReplaySelectorResult,
}

/// Summary row for binary search and binary detail views.
#[derive(Debug, Clone, Serialize)]
pub struct BinarySummary {
    pub md5_hex: String,
    pub short_id: String,
    pub basename: String,
    pub display_name: String,
    pub hostname: String,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
    pub obs_count: u64,
    pub function_count: u64,
    pub version_count: u64,
    pub host_count: u64,
    pub typed_functions: u64,
    pub commented_functions: u64,
    pub switch_functions: u64,
    pub coverage: Option<BinaryFacetSummary>,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BinaryFacetSummary {
    /// Examined prefix size, including unavailable annotations; percentage denominator.
    pub function_count: u64,
    pub key_limit: usize,
    pub truncated: bool,
    pub unavailable_functions: u64,
    /// Selected annotations that do not exactly match the last observed version.
    pub fallback_functions: u64,
    pub typed_functions: u64,
    pub framed_functions: u64,
    pub commented_functions: u64,
    pub switch_functions: u64,
    pub parse_partial_functions: u64,
    pub demangled_functions: u64,
    pub cached_at_ts: u64,
}

impl BinarySummary {
    pub(super) fn apply_facets(&mut self, facets: BinaryFacetSummary) {
        self.typed_functions = facets.typed_functions;
        self.commented_functions = facets.commented_functions;
        self.switch_functions = facets.switch_functions;
        self.coverage = Some(facets);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryCompareVariant {
    pub name: String,
    pub ts: u64,
    pub richness_score: usize,
    /// Current-format ID of the stored donor, before optional synthesis.
    pub version_id: String,
    pub matches_last_observation: bool,
    pub used_synthesis: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryCompareItem {
    pub key_hex: String,
    /// Compatibility summary: left selection when available, otherwise right.
    pub name: String,
    pub ts: u64,
    pub rarity_score: usize,
    pub richness_score: usize,
    pub left: Option<BinaryCompareVariant>,
    pub right: Option<BinaryCompareVariant>,
    pub left_member: bool,
    pub right_member: bool,
    /// same, different, unjudged (parse failure), or unavailable (missing side).
    pub annotation_relation: String,
    pub changed_metadata_keys: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryCompareBucket {
    pub label: String,
    pub items: Vec<BinaryCompareItem>,
}

/// One symbol shared by two binaries, with how widely it occurs elsewhere.
#[derive(Debug, Clone, Serialize)]
pub struct SharedFunctionSample {
    pub key_hex: String,
    pub name: String,
    pub name_demangled: Option<String>,
    /// Binaries observed carrying this key, counted up to `binary_count_cap`.
    pub binary_count: usize,
    pub binary_count_capped: bool,
}

/// An inferred shared component, named after a symbol prefix or namespace.
#[derive(Debug, Clone, Serialize)]
pub struct SharedComponent {
    pub token: String,
    pub functions: usize,
    /// Median binaries-per-symbol for this token: low means a private component.
    pub median_binary_count: usize,
}

/// Evidence for what code two binaries have in common.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SharedCodeProfile {
    /// Keys of the probed (left) binary examined; bounded prefix.
    pub probed_keys: usize,
    pub probe_limit: usize,
    /// Left keys beyond the probe bound, so counts read as a sample.
    pub truncated: bool,
    pub shared_keys: usize,
    pub scored_keys: usize,
    pub named_keys: usize,
    pub binary_count_cap: usize,
    pub components: Vec<SharedComponent>,
    pub samples: Vec<SharedFunctionSample>,
}

/// One binary the batch-level vote judges the query to come from.
/// `share` is this batch's evidence mass, not a calibrated probability.
#[derive(Debug, Clone, Serialize)]
pub struct InferredBinary {
    pub md5_hex: String,
    pub basename: String,
    pub share: f64,
    /// Requested keys this binary carries.
    pub keys_supported: usize,
    pub function_count: u64,
}

/// One stored variant of a key, with the binaries that observed it.
/// Diagnostics for offline selector analysis; not part of any served response.
#[derive(Debug, Clone, Serialize)]
pub struct VariantInfo {
    pub version_id_hex: String,
    pub name: String,
    /// The name with any IDA collision suffix removed.
    pub normalized_name: String,
    /// Demangled name with specialization arguments blanked; `None` when the
    /// name does not demangle.
    pub skeleton: Option<String>,
    pub ts_sec: u64,
    pub data_len: usize,
    pub declared_size: u32,
    pub total_obs: u32,
    pub num_binaries: u32,
    /// Observing binaries, strongest first; bounded by the stored top list.
    pub top_binaries: Vec<VariantBinary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariantBinary {
    pub md5_hex: String,
    pub basename: String,
    pub obs_count: u32,
    /// The binary's observation followed the server serving this name to a
    /// client: not independent evidence for the name.
    pub echo: bool,
}

/// Everything the selector can see for one key, flattened for inspection.
#[derive(Debug, Clone, Serialize)]
pub struct VariantInventory {
    pub key_hex: String,
    /// Binaries carrying this key, counted up to the requested cap.
    pub binary_count: usize,
    /// True when the count stopped at the cap, so `binary_count` is a floor.
    pub binary_count_capped: bool,
    /// Raw membership rows under the key prefix, including zero-observation
    /// placeholders. Membership retrieval bounds this, not `binary_count`.
    pub membership_rows: usize,
    /// Whether this key can contribute evidence to batch binary inference.
    pub votes_in_inference: bool,
    /// What the candidates say the pattern identifies.
    pub classification: super::pattern::Classification,
    pub variants: Vec<VariantInfo>,
}
