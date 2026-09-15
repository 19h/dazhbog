//! Frame reading with budget management.
//!
//! Handles the multi-protocol frame format used by both Lumina and RPC protocols.

use std::io;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

use super::budget::{Budget, OwnedFrame};

/// Check if the first bytes look like a TLS ClientHello.
///
/// TLS record format:
/// - Byte 0: ContentType (0x16 = Handshake)
/// - Byte 1: Major version (0x03)
/// - Byte 2: Minor version (0x00=SSLv3, 0x01=TLS1.0, 0x02=TLS1.1, 0x03=TLS1.2/1.3)
/// - Bytes 3-4: Record length
fn looks_like_tls_handshake(head: &[u8; 4]) -> bool {
    head[0] == 0x16 && head[1] == 0x03 && head[2] <= 0x04
}

/// Read a frame with budget-limited memory allocation.
///
/// Supports both legacy Lumina protocol and new RPC protocol:
/// - Legacy (Lumina): length field is payload size
/// - New (RPC): length field includes the type byte
///
/// # Arguments
/// * `r` - Async reader
/// * `is_legacy` - Protocol mode: Some(true) for Lumina, Some(false) for RPC, None to auto-detect
/// * `max_len_field` - Maximum allowed value for the length field
/// * `conn_budget` - Per-connection memory budget
/// * `global_budget` - Global memory budget across all connections
pub async fn read_multiproto_bounded<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    is_legacy: Option<bool>,
    max_len_field: usize,
    conn_budget: &Arc<Budget>,
    global_budget: &Arc<Budget>,
) -> io::Result<OwnedFrame> {
    let mut head = [0u8; 5];

    // Read 4-byte length field
    r.read_exact(&mut head[..4]).await?;
    let len_field = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;

    if len_field > max_len_field {
        // Check if this looks like a TLS handshake attempt
        if looks_like_tls_handshake(&[head[0], head[1], head[2], head[3]]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS handshake detected but server has TLS disabled - client should set LUMINA_TLS=false",
            ));
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }

    // Read 1-byte message type
    r.read_exact(&mut head[4..5]).await?;
    let typ = head[4];

    // Auto-detect protocol if not specified
    // 0x0d is the Lumina HELLO message type
    let is_legacy_final = if let Some(b) = is_legacy {
        b
    } else {
        typ == 0x0d
    };

    // Calculate payload size based on protocol
    let to_read_payload = if is_legacy_final {
        // Legacy: length is payload size
        len_field
    } else {
        // New: length includes type byte
        if len_field == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid length"));
        }
        len_field - 1
    };

    // Calculate total buffer size (type byte + payload)
    let total_buf = 1usize
        .checked_add(to_read_payload)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?;

    // Reserve memory from per-connection budget
    let g1 = conn_budget
        .try_reserve(total_buf)
        .ok_or_else(|| io::Error::other("per-connection memory budget exceeded"))?;

    // Reserve memory from global budget
    let g2 = global_budget
        .try_reserve(total_buf)
        .ok_or_else(|| io::Error::other("global memory budget exceeded"))?;

    // Allocate buffer and read payload
    let mut data = vec![0u8; total_buf];
    data[0] = typ;
    r.read_exact(&mut data[1..]).await?;

    Ok(OwnedFrame::new(data, g1, g2))
}
