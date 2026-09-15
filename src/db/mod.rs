//! Database module for function metadata storage.
//!
//! This module provides:
//! - `Database` - Main database handle
//! - `FailureCache` - Cache for upstream fetch failures
//! - `upstream` - Upstream server communication
//! - Types: `FuncLatest`, `PushContext`, `QueryContext`

mod database;
mod failure_cache;
mod family;
pub mod semantic;
mod types;
pub mod upstream;

pub use database::Database;
pub use failure_cache::FailureCache;
pub use types::{
    BinaryCompareBucket, BinaryCompareItem, BinaryFacetSummary, BinarySummary, FuncLatest,
    PushContext, QueryContext, ReplayCaseOptions, ReplayCaseResult, ReplayRequestMode,
    ReplaySelectorResult,
};
