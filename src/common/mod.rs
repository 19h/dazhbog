//! Common utilities shared across the codebase.
//!
//! This module provides foundational types and functions used throughout dazhbog:
//! - Error types for unified error handling
//! - Time utilities for timestamp operations
//! - Hash functions (CRC32C, wyhash)
//! - Address packing/unpacking for segment storage
//! - Symbol demangling (C++, Rust, Swift, Go, D, etc.)

pub mod addr;
pub mod demangle;
pub mod error;
pub mod hash;
pub(crate) mod neighbor;
pub mod time;

// Re-export commonly used items for convenience
pub use addr::{addr_off, addr_seg, pack_addr};
pub use demangle::{demangle, demangle_simple, is_mangled, DemangleResult};
pub use error::CodecError;
pub use hash::{crc32c, crc32c_legacy, version_id, wyhash64};
pub use time::now_ts_sec;
