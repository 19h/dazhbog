//! Database module for function metadata storage.
//!
//! This module provides:
//! - `Database` - Main database handle
//! - `FailureCache` - Cache for upstream fetch failures
//! - `upstream` - Upstream server communication
//! - Types: `FuncLatest`, `PushContext`, `QueryContext`

mod anchors;
mod database;
mod evaluation;
mod failure_cache;
mod family;
pub mod semantic;
mod types;
pub mod upstream;

pub use database::Database;
pub use evaluation::{
    BinaryEvaluation, FrameMetadataSummary, MetadataComparison, MetadataSummary,
    ObservedVariantEvaluation,
};
pub use failure_cache::FailureCache;
pub use types::{
    BinaryCompareBucket, BinaryCompareItem, BinaryCompareVariant, BinaryFacetSummary,
    BinarySummary, FuncLatest, InferredBinary, PushContext, QueryContext, ReplayCaseOptions,
    ReplayCaseResult,
    ReplayRequestMode, ReplaySelectorResult, SelectedVariant, SharedCodeProfile, SharedComponent,
    SharedFunctionSample, VariantBinary, VariantInfo, VariantInventory,
};
