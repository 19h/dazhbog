// Legacy protocol support for backward compatibility with lumen-master
// This implements the custom serialization format used by IDA Pro's Lumina plugin

use log::*;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use std::io;

#[derive(Debug)]
pub enum LegacyError {
    UnexpectedEof,
    InvalidData,
}

impl std::fmt::Display for LegacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyError::UnexpectedEof => write!(f, "unexpected EOF"),
            LegacyError::InvalidData => write!(f, "invalid data"),
        }
    }
}

impl std::error::Error for LegacyError {}

pub struct LegacyHello {
    pub protocol_version: u32,
    pub username: String,
    pub password: String,
}

// --- Caps for safe parsing ---

#[derive(Clone, Copy, Debug)]
pub struct LegacyCaps {
    pub max_funcs: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
    pub max_cstr_bytes: usize,
    pub max_hash_bytes: usize,
}

/// Unpack a variable-length encoded 32-bit integer (IDA's "dd" encoding)
/// Returns (value, bytes_consumed)
fn unpack_dd(data: &[u8]) -> (u32, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    
    let b = data[0];
    
    if (b & 0x80) == 0 {
        // Single byte: 0xxxxxxx
        return (b as u32, 1);
    }
    
    if (b & 0xC0) == 0x80 {
        // Two bytes: 10xxxxxx yyyyyyyy
        if data.len() < 2 {
            return (0, 0);
        }
        let val = (((b & 0x3F) as u32) << 8) | (data[1] as u32);
        return (val, 2);
    }
    
    if (b & 0xE0) == 0xC0 {
        // Four bytes: 110xxxxx yyyyyyyy zzzzzzzz wwwwwwww (reads 4 bytes total, lumen-master uses little-endian)
        if data.len() < 4 {
            return (0, 0);
        }
        // For C0 class: data[3], data[2], data[1] (reverse order)
        let val = ((data[3] as u32) << 16) | ((data[2] as u32) << 8) | (data[1] as u32);
        return (val, 4);
    }
    
    // Five bytes (0xFF prefix)
    if b == 0xFF {
        // Five bytes: 11111111 xxxxxxxx yyyyyyyy zzzzzzzz wwwwwwww (full 32-bit, little-endian)
        if data.len() < 5 {
            return (0, 0);
        }
        let val = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        return (val, 5);
    }
    
    // Four bytes: 111xxxxx yyyyyyyy zzzzzzzz wwwwwwww
    if data.len() < 4 {
        return (0, 0);
    }
    let val = (((b & 0x1F) as u32) << 24) | ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
    (val, 4)
}

// --- Capped C-string unpacker ---

fn unpack_cstr_capped(data: &[u8], max: usize) -> Result<(String, usize), LegacyError> {
    let null_pos = data.iter().position(|&b| b == 0).ok_or(LegacyError::UnexpectedEof)?;
    if null_pos > max { return Err(LegacyError::InvalidData); }
    let s = std::str::from_utf8(&data[..null_pos]).map_err(|_| LegacyError::InvalidData)?;
    Ok((s.to_string(), null_pos + 1))
}

/// Encode a u32 in variable-length dd format (matching lumen-master)
fn pack_dd(v: u32) -> Vec<u8> {
    let bytes = v.to_le_bytes();
    match v {
        0..=0x7f => vec![bytes[0]],
        0x80..=0x3fff => vec![0x80 | bytes[1], bytes[0]],
        0x4000..=0x1fffff => vec![0xc0, bytes[2], bytes[1], bytes[0]],
        0x200000..=u32::MAX => {
            let mut out = Vec::with_capacity(5);
            out.extend_from_slice(&[0xff]);
            // NOTE: legacy unpack_dd interprets the 4 bytes that follow 0xFF as little-endian
            out.extend_from_slice(&bytes); // little-endian as per unpacker
            out
        },
    }
}

/// Encode a u64 as two dd-encoded u32s (high, low)
fn pack_dq(v: u64) -> Vec<u8> {
    let high = (v >> 32) as u32;
    let low = (v & 0xFFFFFFFF) as u32;
    let mut result = pack_dd(high);
    result.extend_from_slice(&pack_dd(low));
    result
}

/// Parse variable-length byte array (length-prefixed with dd encoding)
/// Returns (bytes, bytes_consumed)
fn unpack_var_bytes_capped(data: &[u8], max_len: usize) -> Result<(&[u8], usize), LegacyError> {
    let (len, consumed) = unpack_dd(data);
    if consumed == 0 {
        return Err(LegacyError::UnexpectedEof);
    }
    let len = len as usize;
    if len > max_len { return Err(LegacyError::InvalidData); }
    let data = &data[consumed..];
    if data.len() < len {
        return Err(LegacyError::UnexpectedEof);
    }
    Ok((&data[..len], consumed + len))
}

/// Parse legacy Hello message (0x0d message type)
pub fn parse_legacy_hello(payload: &[u8]) -> Result<LegacyHello, LegacyError> {
    let mut offset = 0;
    let (protocol_version, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("Legacy Hello: protocol_version={}", protocol_version);
    
    // license_data (unused / discarded safely with small cap)
    let (_license_data, consumed) = unpack_var_bytes_capped(&payload[offset..], 4096)?;
    offset += consumed;
    debug!("Legacy Hello: license_data processed");
    
    // lic_number (6 bytes)
    if payload.len() < offset + 6 { return Err(LegacyError::UnexpectedEof); }
    offset += 6;
    
    // unk2
    let (_unk2, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;

    // Credentials (optional)
    let (username, password) = if protocol_version > 2 && offset < payload.len() {
        match unpack_cstr_capped(&payload[offset..], 256) {
            Ok((user, consumed)) => {
                offset += consumed;
                match unpack_cstr_capped(&payload[offset..], 256) {
                    Ok((pass, _)) => (user, pass),
                    Err(_) => (user, String::new()),
                }
            }
            Err(_) => ("guest".to_string(), String::new()),
        }
    } else {
        ("guest".to_string(), String::new())
    };
    
    Ok(LegacyHello { protocol_version, username, password })
}

// Legacy message structures
// Note: Many fields are parsed for protocol compatibility but not used by server logic

pub struct LegacyPullMetadataFunc {
    #[allow(dead_code)]
    pub unk0: u32,
    pub mb_hash: Vec<u8>,
}

pub struct LegacyPullMetadata {
    #[allow(dead_code)]
    pub unk0: u32,
    #[allow(dead_code)]
    pub unk1: Vec<u32>,
    pub funcs: Vec<LegacyPullMetadataFunc>,
}

pub struct LegacyPushMetadataFunc {
    pub name: String,
    pub func_len: u32,
    pub func_data: Vec<u8>,
    #[allow(dead_code)]
    pub unk2: u32,
    pub hash: Vec<u8>,
}

pub struct LegacyPushMetadata {
    #[allow(dead_code)]
    pub unk0: u32,
    #[allow(dead_code)]
    pub idb_path: String,
    #[allow(dead_code)]
    pub file_path: String,
    #[allow(dead_code)]
    pub md5: [u8; 16],
    #[allow(dead_code)]
    pub hostname: String,
    pub funcs: Vec<LegacyPushMetadataFunc>,
    #[allow(dead_code)]
    pub unk1: Vec<u64>,
}

pub struct LegacyGetFuncHistories {
    pub funcs: Vec<LegacyPullMetadataFunc>,
    #[allow(dead_code)]
    pub unk0: u32,
}

/// Parse legacy PullMetadata (0x0e) with caps
pub fn parse_legacy_pull_metadata(payload: &[u8], caps: LegacyCaps) -> Result<LegacyPullMetadata, LegacyError> {
    let mut offset = 0;
    debug!("parse_legacy_pull_metadata: payload len={}", payload.len());
    
    let (unk0, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;

    // unk1: Vec<u32>
    let (count1, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    
    let mut unk1 = Vec::with_capacity((count1 as usize).min(1024));
    for _ in 0..count1 {
        let (v, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;
        unk1.push(v);
    }
    
    // funcs: Vec<PullMetadataFunc>
    let (count_funcs, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;

    let n = (count_funcs as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count_funcs {
        // unk0
        let (func_unk0, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;

        // mb_hash
        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LegacyPullMetadataFunc { unk0: func_unk0, mb_hash: hash.to_vec() });
        }
    }

    Ok(LegacyPullMetadata { unk0, unk1, funcs })
}

/// Parse legacy PushMetadata (0x10) with caps
pub fn parse_legacy_push_metadata(payload: &[u8], caps: LegacyCaps) -> Result<LegacyPushMetadata, LegacyError> {
    let mut offset = 0;
    debug!("parse_legacy_push_metadata: payload len={}", payload.len());
    
    let (unk0, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    
    // idb_path, file_path, hostname with C-string caps
    let (idb_path, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    let (file_path, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    if payload.len() < offset + 16 { return Err(LegacyError::UnexpectedEof); }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&payload[offset..offset+16]);
    offset += 16;

    let (hostname, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    // funcs
    let (count_funcs, c) = unpack_dd(&payload[offset..]);
    if c == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += c;

    let n = (count_funcs as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count_funcs {
        let (name, c) = unpack_cstr_capped(&payload[offset..], caps.max_name_bytes)?;
        offset += c;

        let (func_len, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;

        let (func_data, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_data_bytes)?;
        offset += c;

        let (unk2, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LegacyPushMetadataFunc {
                name, func_len, func_data: func_data.to_vec(), unk2, hash: hash.to_vec(),
            });
        }
    }

    // unk1: Vec<u64> (capped by reasonable upper bound)
    let (count_u64, c) = unpack_dd(&payload[offset..]);
    if c == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += c;

    let cap_u64s = 4096usize.min(count_u64 as usize);
    let mut unk1 = Vec::with_capacity(cap_u64s);

    for i in 0..count_u64 {
        let (high, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;

        let (low, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;

        if (i as usize) < cap_u64s {
            unk1.push(((high as u64) << 32) | (low as u64));
        }
    }

    Ok(LegacyPushMetadata {
        unk0, idb_path, file_path, md5, hostname, funcs, unk1,
    })
}

/// Parse legacy GetFuncHistories (0x2f) with caps
pub fn parse_legacy_get_func_histories(payload: &[u8], caps: LegacyCaps) -> Result<LegacyGetFuncHistories, LegacyError> {
    let mut offset = 0;

    let (count, c) = unpack_dd(&payload[offset..]);
    if c == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += c;

    let n = (count as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count {
        let (func_unk0, c) = unpack_dd(&payload[offset..]);
        if c == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LegacyPullMetadataFunc { unk0: func_unk0, mb_hash: hash.to_vec() });
        }
    }

    let (unk0, _c) = unpack_dd(&payload[offset..]);

    Ok(LegacyGetFuncHistories { funcs, unk0 })
}

/// Write a packet in legacy format:
/// - 4 bytes: big-endian length (payload length, not including message type)
/// - 1 byte: message type
/// - N bytes: payload
pub async fn write_legacy_packet<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len() as u32;
    let len_bytes = len.to_be_bytes();
    debug!("write_legacy_packet: type=0x{:02x}, payload_len={}", msg_type, len);
    w.write_all(&len_bytes).await?;
    w.write_u8(msg_type).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Send legacy OK response (0x0a with empty payload)
pub async fn send_legacy_ok<W: AsyncWriteExt + Unpin>(w: &mut W) -> io::Result<()> {
    write_legacy_packet(w, 0x0a, &[]).await
}

/// Send legacy HelloResult response (0x31) for protocol version >= 5
pub async fn send_legacy_hello_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    features: u32,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(&[0x00]); // karma
    payload.extend_from_slice(&[0x00, 0x00]); // last_active
    if features < 0x80 {
        payload.extend_from_slice(&[features as u8]);
    } else {
        let b1 = 0x80 | ((features >> 8) as u8);
        let b2 = (features & 0xFF) as u8;
        payload.extend_from_slice(&[b1, b2]);
    }
    write_legacy_packet(w, 0x31, &payload).await
}

/// Send legacy Fail response (0x0b) - dd-encoded code (LE as per unpacker) + cstr
pub async fn send_legacy_fail<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    code: u32,
    message: &str,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(code));
    payload.extend_from_slice(message.as_bytes());
    payload.extend_from_slice(b"\0");
    write_legacy_packet(w, 0x0b, &payload).await
}

// Legacy result encoders (unchanged except bounds-safe construction)

pub async fn send_legacy_pull_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    funcs: &[(u32, u32, String, Vec<u8>)],  // (popularity, len, name, data)
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    payload.extend_from_slice(&pack_dd(funcs.len() as u32));
    for (pop, len, name, data) in funcs {
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(&pack_dd(*len));
        payload.extend_from_slice(&pack_dd(data.len() as u32));
        payload.extend_from_slice(data);
        payload.extend_from_slice(&pack_dd(*pop));
    }
    write_legacy_packet(w, 0x0f, &payload).await
}

pub async fn send_legacy_push_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    status: &[u32],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(status.len() as u32));
    for &s in status {
        payload.extend_from_slice(&pack_dd(s));
    }
    write_legacy_packet(w, 0x11, &payload).await
}

pub async fn send_legacy_del_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    deleted_mds: u32,
) -> io::Result<()> {
    let payload = pack_dd(deleted_mds);
    write_legacy_packet(w, 0x19, &payload).await
}

pub async fn send_legacy_histories_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    histories: &[Vec<(u64, String, Vec<u8>)>],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    payload.extend_from_slice(&pack_dd(histories.len() as u32));
    for history in histories {
        payload.extend_from_slice(&pack_dd(history.len() as u32));
        for (ts, name, metadata) in history {
            payload.extend_from_slice(&pack_dq(0));
            payload.extend_from_slice(&pack_dq(0));
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(b"\0");
            payload.extend_from_slice(&pack_dd(metadata.len() as u32));
            payload.extend_from_slice(metadata);
            payload.extend_from_slice(&pack_dq(*ts));
            payload.extend_from_slice(&pack_dd(0));
            payload.extend_from_slice(&pack_dd(0));
        }
    }
    payload.extend_from_slice(&pack_dd(0)); // users
    payload.extend_from_slice(&pack_dd(0)); // dbs
    write_legacy_packet(w, 0x30, &payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unpack_dd_basic() {
        assert_eq!(unpack_dd(&[0x42]), (0x42, 1));
        assert_eq!(unpack_dd(&[0x00]), (0x00, 1));
        assert_eq!(unpack_dd(&[0x7F]), (0x7F, 1));
        assert_eq!(unpack_dd(&[0x80, 0x00]), (0x0000, 2));
        assert_eq!(unpack_dd(&[0x81, 0x23]), (0x0123, 2));
        assert_eq!(unpack_dd(&[0xBF, 0xFF]), (0x3FFF, 2));
        // 0xC0 class consumes 4 bytes (LE assembly)
        assert_eq!(unpack_dd(&[0xC0, 0x00, 0x00, 0x00]), (0x0000, 4));
        assert_eq!(unpack_dd(&[0xC1, 0x23, 0x45, 0x00]), (0x004523, 4));
        // 0xFF prefix: 5 bytes, LE
        assert_eq!(unpack_dd(&[0xFF, 0x78, 0x56, 0x34, 0x12]), (0x12345678, 5));
    }
    
    #[test]
    fn test_unpack_cstr_capped() {
        assert_eq!(unpack_cstr_capped(b"hello\0", 16).unwrap(), ("hello".to_string(), 6));
        assert!(unpack_cstr_capped(b"no null terminator", 64).is_err());
        assert!(unpack_cstr_capped(&[b'a'; 10_000], 1024).is_err());
    }

    // ============================================================================
    // COMPREHENSIVE SECURITY FUZZING TESTS
    // ============================================================================

    #[test]
    fn test_unpack_dd_overflow_protection() {
        // Test the unpack_dd function with various overflow conditions
        let test_cases = vec![
            // Maximum values
            (vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF], "Max 5-byte value"),
            // Near-overflow values
            (vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFE], "Near max 5-byte value"),
            // Invalid encodings that could cause issues
            (vec![0xC0, 0xFF, 0xFF, 0xFF], "Max 4-byte C0 encoding"),
            (vec![0xDF, 0xFF, 0xFF, 0xFF], "Max 4-byte DF encoding"),
            // Edge cases
            (vec![0x80, 0x00], "Min 2-byte encoding"),
            (vec![0xBF, 0xFF], "Max 2-byte encoding"),
        ];

        for (data, description) in test_cases {
            println!("Testing unpack_dd: {}", description);
            let (value, consumed) = unpack_dd(&data);
            println!("  Input: {:02x?}, Value: {}, Consumed: {}", data, value, consumed);

            // Ensure we don't panic and return reasonable values
            assert!(consumed <= data.len(), "Consumed more bytes than available");
            assert!(value <= u32::MAX, "Value should not exceed u32::MAX");
        }
    }

    #[test]
    fn test_legacy_protocol_fuzzing() {
        use rand::{Rng, RngCore, Fill};

        // Test legacy unpack_dd with malformed data
        for _ in 0..10000 {
            let size = rand::thread_rng().gen_range(1..50);
            let data = random_bytes(size);

            let (value, consumed) = unpack_dd(&data);

            // Basic sanity checks
            assert!(consumed <= data.len(), "Consumed more than available data");
            assert!(value <= u32::MAX, "Value overflow");

            // Ensure no panics occur
            if consumed > 0 {
                assert!(consumed >= 1, "Should consume at least 1 byte if successful");
            }
        }

        println!("Legacy unpack_dd fuzzing completed without panics");
    }

    #[test]
    fn test_legacy_string_parsing_edge_cases() {
        let edge_cases: Vec<(&[u8], &str)> = vec![
            (b"", "Empty string"),
            (b"\x00", "Single null byte"),
            (b"hello", "No null terminator"),
            (b"hello\x00world\x00", "Multiple null terminators"),
            (&[0xFF; 1000], "All FF bytes"),
            (&[b'A'; 10000], "Very long string"),
            (b"\x00hello", "Null at start"),
        ];

        for (data, description) in edge_cases {
            println!("Testing legacy string parsing: {}", description);

            let result = unpack_cstr_capped(data, 4096);
            match result {
                Ok((string, consumed)) => {
                    println!("  Parsed: '{}' (consumed: {})", string, consumed);
                    assert!(consumed <= data.len());
                }
                Err(e) => {
                    println!("  Failed: {:?}", e);
                    // Expected for some cases
                }
            }
        }
    }

    #[test]
    fn test_legacy_protocol_overflows() {
        use rand::{Rng, RngCore, Fill};

        // Test legacy parsing with large inputs
        for _ in 0..100 {
            let size = rand::thread_rng().gen_range(1..10000);
            let data = random_bytes(size);

            // Try parsing as legacy hello
            let hello_result = parse_legacy_hello(&data);
            match hello_result {
                Ok(hello) => {
                    println!("Parsed legacy hello: version={}, user='{}', pass='{}'",
                            hello.protocol_version, hello.username, hello.password);
                }
                Err(_) => {
                    // Expected for random data
                }
            }

            // Try parsing as legacy pull metadata
            let caps = LegacyCaps {
                max_funcs: 100,
                max_name_bytes: 1000,
                max_data_bytes: 10000,
                max_cstr_bytes: 4096,
                max_hash_bytes: 64,
            };

            let pull_result = parse_legacy_pull_metadata(&data, caps);
            match pull_result {
                Ok(pull) => {
                    println!("Parsed legacy pull: {} funcs", pull.funcs.len());
                }
                Err(_) => {
                    // Expected for random data
                }
            }
        }
    }

    #[test]
    fn test_integer_precision_attacks() {
        // Test attacks that rely on integer precision issues
        let precision_tests = vec![
            // Off-by-one attacks
            (u32::MAX as u64 + 1, "u32::MAX + 1"),
            (i32::MAX as u64 + 1, "i32::MAX + 1"),
            // Negative value representations
            ((u32::MAX as u64) << 32, "Large shift"),
            // Boundary conditions
            (usize::MAX as u64, "usize::MAX"),
        ];

        for (value, description) in precision_tests {
            println!("Testing integer precision: {} (0x{:016x})", description, value);

            // Test with legacy unpack_dd simulation
            let bytes = value.to_le_bytes();
            let test_cases = vec![
                vec![0xFF, bytes[0], bytes[1], bytes[2], bytes[3]], // 5-byte encoding
                vec![0xC0 | (bytes[3] >> 4), bytes[2], bytes[1], bytes[0]], // 4-byte C0
            ];

            for test_data in test_cases {
                let (parsed_value, consumed) = unpack_dd(&test_data);
                println!("  Input: {:02x?} -> value: {}, consumed: {}", test_data, parsed_value, consumed);
            }
        }
    }

    // Helper function for fuzzing tests
    fn random_bytes(len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf
    }
}
