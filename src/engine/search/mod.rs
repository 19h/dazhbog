//! Full-text search module for function metadata.
//!
//! This module provides:
//! - `SearchIndex` - Tantivy-based search index
//! - `SearchDocument` - Document structure for indexing
//! - `SearchHit` - Search result structure
//! - `rebuild_from_engine` - Rebuild index from engine data

mod index;
mod rebuild;
mod types;
mod variants;
pub(crate) use variants::variant_vocabulary;

pub use index::SearchIndex;
#[allow(unused_imports)]
pub use rebuild::{
    rebuild_from_engine, rebuild_from_engine_with_policy, rebuild_from_engine_with_progress,
    RebuildProgress, RebuildProgressPhase, SearchRebuildSummary,
};
pub use types::{BinaryRefHit, SearchDocument, SearchHit, SemanticNeighborRationale};
