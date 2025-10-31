// Legacy protocol support for backward compatibility with lumen-master
// This implements the custom serialization format used by IDA Pro's Lumina plugin

use log::*;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        // Little-endian: val[0] = data[3], val[1] = data[2], val[2] = data[1], val[3] = b & 0x1F
        let val = u32::from_le_bytes([data[3], data[2], data[1], b & 0x1F]);
        return (val, 4);
    }
    
    // Five bytes (0xFF prefix)
    if b == 0xFF {
        // Five bytes: 11111111 xxxxxxxx yyyyyyyy zzzzzzzz wwwwwwww (full 32-bit, little-endian)
        if data.len() < 5 {
            return (0, 0);
        }
        let val = u32::from_le_bytes([data[4], data[3], data[2], data[1]]);
        return (val, 5);
    }
    
    // Four bytes: 111xxxxx yyyyyyyy zzzzzzzz wwwwwwww
    if data.len() < 4 {
        return (0, 0);
    }
    let val = (((b & 0x1F) as u32) << 24) | ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
    (val, 4)
}

/// Encode a u32 in variable-length dd format (matching lumen-master)
fn pack_dd(v: u32) -> Vec<u8> {
    let bytes = v.to_le_bytes();
    match v {
        0..=0x7f => {
            // Single byte: 0xxxxxxx (7 bits)
            vec![bytes[0]]
        },
        0x80..=0x3fff => {
            // Two bytes: 10xxxxxx yyyyyyyy (14 bits)
            vec![0x80 | bytes[1], bytes[0]]
        },
        0x4000..=0x1fffff => {
            // Four bytes: 11000000 yyyyyyyy zzzzzzzz wwwwwwww (21 bits, little-endian)
            vec![0xc0, bytes[2], bytes[1], bytes[0]]
        },
        0x200000..=u32::MAX => {
            // Five bytes: 11111111 followed by 4-byte little-endian
            vec![0xff, bytes[3], bytes[2], bytes[1], bytes[0]]
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

/// Parse null-terminated C string
/// Returns (string, bytes_consumed)
fn unpack_cstr(data: &[u8]) -> Result<(String, usize), LegacyError> {
    let null_pos = data.iter().position(|&b| b == 0);
    match null_pos {
        Some(pos) => {
            let s = std::str::from_utf8(&data[..pos])
                .map_err(|_| LegacyError::InvalidData)?
                .to_string();
            Ok((s, pos + 1))
        }
        None => Err(LegacyError::UnexpectedEof),
    }
}

/// Parse variable-length byte array (length-prefixed with dd encoding)
/// Returns (bytes, bytes_consumed)
fn unpack_var_bytes(data: &[u8]) -> Result<(&[u8], usize), LegacyError> {
    let (len, consumed) = unpack_dd(data);
    if consumed == 0 {
        return Err(LegacyError::UnexpectedEof);
    }
    
    let len = len as usize;
    let data = &data[consumed..];
    
    if data.len() < len {
        return Err(LegacyError::UnexpectedEof);
    }
    
    Ok((&data[..len], consumed + len))
}

/// Parse legacy Hello message (0x0d message type)
/// The format after the 0x0d byte is:
/// - protocol_version: u32 (dd-encoded)
/// - license_data: bytes (dd-length-prefixed)
/// - lic_number: 6 bytes
/// - unk2: u32 (dd-encoded)
/// - Optional (if protocol_version > 2):
///   - username: cstr
///   - password: cstr
pub fn parse_legacy_hello(payload: &[u8]) -> Result<LegacyHello, LegacyError> {
    let mut offset = 0;
    
    // Parse protocol_version (dd-encoded u32)
    let (protocol_version, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LegacyError::UnexpectedEof);
    }
    offset += consumed;
    debug!("Legacy Hello: protocol_version={}", protocol_version);
    
    // Parse license_data (length-prefixed bytes)
    let (license_data, consumed) = unpack_var_bytes(&payload[offset..])?;
    offset += consumed;
    debug!("Legacy Hello: license_data len={}", license_data.len());
    
    // Parse lic_number (6 bytes)
    if payload.len() < offset + 6 {
        return Err(LegacyError::UnexpectedEof);
    }
    offset += 6;
    
    // Parse unk2 (dd-encoded u32)
    let (unk2, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LegacyError::UnexpectedEof);
    }
    offset += consumed;
    debug!("Legacy Hello: unk2={}", unk2);
    
    // Parse credentials if protocol_version > 2 and there are remaining bytes
    let (username, password) = if protocol_version > 2 && offset < payload.len() {
        // Try to parse credentials, but don't fail if they're not present
        match unpack_cstr(&payload[offset..]) {
            Ok((user, consumed)) => {
                offset += consumed;
                // Try to parse password
                match unpack_cstr(&payload[offset..]) {
                    Ok((pass, _consumed)) => {
                        debug!("Legacy Hello: username={}, password present={}", user, !pass.is_empty());
                        (user, pass)
                    }
                    Err(_) => {
                        debug!("Legacy Hello: username={}, no password field", user);
                        (user, String::new())
                    }
                }
            }
            Err(_) => {
                debug!("Legacy Hello: no credentials in payload, using default guest");
                ("guest".to_string(), String::new())
            }
        }
    } else {
        debug!("Legacy Hello: protocol_version <= 2 or no remaining bytes, using default guest credentials");
        ("guest".to_string(), String::new())
    };
    
    Ok(LegacyHello {
        protocol_version,
        username,
        password,
    })
}

/// Read a packet in legacy format:
/// - 4 bytes: big-endian length (payload length, not including message type)
/// - 1 byte: message type
/// - N bytes: payload (length bytes)
/// Returns: Vec where [0] is message type and [1..] is payload
pub async fn read_legacy_packet<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    // Read 4-byte length + 1-byte code
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    
    let code = head[4];
    let buf_len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    debug!("Legacy read_packet: len={}, code=0x{:02x}, head bytes: {:02x?}", buf_len, code, &head);
    
    if buf_len < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload size is too small",
        ));
    }
    
    if buf_len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload size exceeds maximum",
        ));
    }
    
    // Read payload (buf_len bytes)
    let mut data = vec![0u8; buf_len + 1];
    data[0] = code;
    r.read_exact(&mut data[1..]).await?;
    
    Ok(data)
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
    
    debug!("write_legacy_packet: type=0x{:02x}, payload_len={}, wire: [{:02x} {:02x} {:02x} {:02x}] [{:02x}] + {} payload bytes",
        msg_type, len, len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3], msg_type, len);
    
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
/// Payload format:
/// - license_info.id: cstr
/// - license_info.name: cstr  
/// - license_info.email: cstr
/// - username: cstr
/// - karma: u32 (dd-encoded)
/// - last_active: u64 (two dd-encoded u32s)
/// - features: u32 (dd-encoded)
pub async fn send_legacy_hello_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    features: u32,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    
    // license_info.id (empty)
    payload.extend_from_slice(b"\0");
    // license_info.name (empty)
    payload.extend_from_slice(b"\0");
    // license_info.email (empty)
    payload.extend_from_slice(b"\0");
    // username (empty)
    payload.extend_from_slice(b"\0");
    // karma: 0 (single byte dd encoding)
    payload.extend_from_slice(&[0x00]);
    // last_active: 0 (two u32s, both 0)
    payload.extend_from_slice(&[0x00, 0x00]);
    // features (single byte if < 128)
    if features < 0x80 {
        payload.extend_from_slice(&[features as u8]);
    } else {
        // Two-byte encoding
        let b1 = 0x80 | ((features >> 8) as u8);
        let b2 = (features & 0xFF) as u8;
        payload.extend_from_slice(&[b1, b2]);
    }
    
    debug!("Sending HelloResult: features={}, payload len={}, payload: {:02x?}", features, payload.len(), &payload[..]);
    write_legacy_packet(w, 0x31, &payload).await
}

/// Send legacy Fail response (0x0b)
/// Payload format:
/// - code: u32 (dd-encoded)
/// - message: cstr
pub async fn send_legacy_fail<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    code: u32,
    message: &str,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    
    // Encode code (dd encoding)
    if code < 0x80 {
        payload.extend_from_slice(&[code as u8]);
    } else if code < 0x4000 {
        let b1 = 0x80 | ((code >> 8) as u8);
        let b2 = (code & 0xFF) as u8;
        payload.extend_from_slice(&[b1, b2]);
    } else {
        // For simplicity, use 5-byte encoding for larger values
        payload.extend_from_slice(&[0xFF]);
        payload.extend_from_slice(&code.to_be_bytes());
    }
    
    // Add message as cstr
    payload.extend_from_slice(message.as_bytes());
    payload.extend_from_slice(b"\0");
    
    write_legacy_packet(w, 0x0b, &payload).await
}

// Legacy message structures
pub struct LegacyPullMetadataFunc {
    pub unk0: u32,
    pub mb_hash: Vec<u8>,
}

pub struct LegacyPullMetadata {
    pub unk0: u32,
    pub unk1: Vec<u32>,
    pub funcs: Vec<LegacyPullMetadataFunc>,
}

pub struct LegacyPushMetadataFunc {
    pub name: String,
    pub func_len: u32,
    pub func_data: Vec<u8>,
    pub unk2: u32,
    pub hash: Vec<u8>,
}

pub struct LegacyPushMetadata {
    pub unk0: u32,
    pub idb_path: String,
    pub file_path: String,
    pub md5: [u8; 16],
    pub hostname: String,
    pub funcs: Vec<LegacyPushMetadataFunc>,
    pub unk1: Vec<u64>,
}

pub struct LegacyGetFuncHistories {
    pub funcs: Vec<LegacyPullMetadataFunc>,
    pub unk0: u32,
}

/// Parse legacy PullMetadata (0x0e)
pub fn parse_legacy_pull_metadata(payload: &[u8]) -> Result<LegacyPullMetadata, LegacyError> {
    let mut offset = 0;
    debug!("parse_legacy_pull_metadata: payload len={}", payload.len());
    if log::log_enabled!(log::Level::Debug) {
        let dump_len = payload.len().min(256);
        debug!("  First {} bytes: {:02x?}", dump_len, &payload[..dump_len]);
    }
    
    // unk0: u32
    let (unk0, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("  unk0={}, offset={}", unk0, offset);
    
    // unk1: Vec<u32>
    let (count, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("  unk1 count={}, offset={}", count, offset);
    
    let mut unk1 = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (v, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        unk1.push(v);
    }
    debug!("  unk1 parsed, offset={}", offset);
    
    // funcs: Vec<PullMetadataFunc>
    let (count, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("  funcs count={}, offset={}", count, offset);
    
    let mut funcs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        // unk0: u32
        let (func_unk0, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        
        // mb_hash: bytes
        let (hash, consumed) = unpack_var_bytes(&payload[offset..])?;
        offset += consumed;
        
        funcs.push(LegacyPullMetadataFunc {
            unk0: func_unk0,
            mb_hash: hash.to_vec(),
        });
    }
    
    debug!("  funcs parsed after count-based parsing, offset={}/{}", offset, payload.len());
    
    // IDA sends more functions than the count indicates - keep parsing until EOF
    if offset < payload.len() {
        warn!("Continuing to parse {} remaining bytes as additional functions", payload.len() - offset);
        while offset < payload.len() {
            // Try to parse unk0
            let (_, consumed) = unpack_dd(&payload[offset..]);
            if consumed == 0 { break; }
            offset += consumed;
            
            // Try to parse hash
            match unpack_var_bytes(&payload[offset..]) {
                Ok((hash, consumed)) => {
                    offset += consumed;
                    funcs.push(LegacyPullMetadataFunc {
                        unk0: 0,
                        mb_hash: hash.to_vec(),
                    });
                },
                Err(_) => break,
            }
            
            if funcs.len() % 10000 == 0 {
                debug!("  parsed {} total funcs so far, offset={}", funcs.len(), offset);
            }
        }
    }
    
    debug!("  final parsed funcs count={}, offset={}/{}", funcs.len(), offset, payload.len());
    Ok(LegacyPullMetadata { unk0, unk1, funcs })
}

/// Parse legacy PushMetadata (0x10)
pub fn parse_legacy_push_metadata(payload: &[u8]) -> Result<LegacyPushMetadata, LegacyError> {
    let mut offset = 0;
    debug!("parse_legacy_push_metadata: payload len={}", payload.len());
    if log::log_enabled!(log::Level::Debug) {
        let dump_len = payload.len().min(256);
        debug!("  First {} bytes: {:02x?}", dump_len, &payload[..dump_len]);
    }
    
    // unk0: u32
    let (unk0, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("  unk0={}, offset={}", unk0, offset);
    
    // idb_path: cstr
    let (idb_path, consumed) = unpack_cstr(&payload[offset..])?;
    offset += consumed;
    debug!("  idb_path='{}', offset={}", idb_path, offset);
    
    // file_path: cstr
    let (file_path, consumed) = unpack_cstr(&payload[offset..])?;
    offset += consumed;
    debug!("  file_path='{}', offset={}", file_path, offset);
    
    // md5: [u8; 16]
    if payload.len() < offset + 16 { return Err(LegacyError::UnexpectedEof); }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&payload[offset..offset+16]);
    offset += 16;
    debug!("  md5={:02x?}, offset={}", &md5[..], offset);
    
    // hostname: cstr
    let (hostname, consumed) = unpack_cstr(&payload[offset..])?;
    offset += consumed;
    debug!("  hostname='{}', offset={}", hostname, offset);
    
    // funcs: Vec<PushMetadataFunc>
    let (count, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("  funcs count={}, offset={}", count, offset);
    
    let mut funcs = Vec::with_capacity(count as usize);
    for i in 0..count {
        if i < 5 || i % 1000 == 0 {
            debug!("  parsing func {}/{}, offset={}", i, count, offset);
        }
        
        // name: cstr
        let (name, consumed) = unpack_cstr(&payload[offset..])?;
        offset += consumed;
        
        // func_len: u32
        let (func_len, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        
        // func_data: bytes
        let (func_data, consumed) = unpack_var_bytes(&payload[offset..])?;
        offset += consumed;
        
        // unk2: u32
        let (unk2, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        
        // hash: bytes
        let (hash, consumed) = unpack_var_bytes(&payload[offset..])?;
        offset += consumed;
        
        if i < 5 {
            debug!("    func[{}]: name='{}', len={}, data_len={}, hash_len={}", 
                   i, &name, func_len, func_data.len(), hash.len());
        }
        
        funcs.push(LegacyPushMetadataFunc {
            name,
            func_len,
            func_data: func_data.to_vec(),
            unk2,
            hash: hash.to_vec(),
        });
    }
    
    debug!("  funcs parsed, offset={}", offset);
    
    // unk1: Vec<u64>
    let (count, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    debug!("  unk1 count={}, offset={}", count, offset);
    
    let mut unk1 = Vec::with_capacity(count as usize);
    for _ in 0..count {
        // u64 as two u32s
        let (high, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        
        let (low, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        
        unk1.push(((high as u64) << 32) | (low as u64));
    }
    
    debug!("  unk1 parsed, final offset={}/{}", offset, payload.len());
    
    Ok(LegacyPushMetadata {
        unk0,
        idb_path,
        file_path,
        md5,
        hostname,
        funcs,
        unk1,
    })
}

/// Parse legacy GetFuncHistories (0x2f)
pub fn parse_legacy_get_func_histories(payload: &[u8]) -> Result<LegacyGetFuncHistories, LegacyError> {
    let mut offset = 0;
    
    // funcs: Vec<PullMetadataFunc>
    let (count, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
    offset += consumed;
    
    let mut funcs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (func_unk0, consumed) = unpack_dd(&payload[offset..]);
        if consumed == 0 { return Err(LegacyError::UnexpectedEof); }
        offset += consumed;
        
        let (hash, consumed) = unpack_var_bytes(&payload[offset..])?;
        offset += consumed;
        
        funcs.push(LegacyPullMetadataFunc {
            unk0: func_unk0,
            mb_hash: hash.to_vec(),
        });
    }
    
    // unk0: u32
    let (unk0, _consumed) = unpack_dd(&payload[offset..]);
    
    Ok(LegacyGetFuncHistories { funcs, unk0 })
}

/// Encode legacy PullMetadataResult (0x0f)
pub async fn send_legacy_pull_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    funcs: &[(u32, u32, String, Vec<u8>)],  // (popularity, len, name, data)
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    
    // statuses array
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    
    // funcs array
    payload.extend_from_slice(&pack_dd(funcs.len() as u32));
    for (pop, len, name, data) in funcs {
        // Correct order per lumen-master: name, len, mb_data, popularity
        // name as cstr
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b"\0");
        // len
        payload.extend_from_slice(&pack_dd(*len));
        // data as length-prefixed bytes
        payload.extend_from_slice(&pack_dd(data.len() as u32));
        payload.extend_from_slice(data);
        // popularity
        payload.extend_from_slice(&pack_dd(*pop));
    }
    
    if log::log_enabled!(log::Level::Debug) && payload.len() <= 512 {
        debug!("PullResult payload ({} bytes): {:02x?}", payload.len(), &payload[..]);
    } else if log::log_enabled!(log::Level::Debug) {
        debug!("PullResult payload first 256 bytes: {:02x?}", &payload[..256.min(payload.len())]);
    }
    write_legacy_packet(w, 0x0f, &payload).await
}

/// Encode legacy PushMetadataResult (0x11)
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

/// Encode legacy DelHistoryResult (0x19)
pub async fn send_legacy_del_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    deleted_mds: u32,
) -> io::Result<()> {
    let payload = pack_dd(deleted_mds);
    write_legacy_packet(w, 0x19, &payload).await
}

/// Encode legacy GetFuncHistoriesResult (0x30)
pub async fn send_legacy_histories_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    histories: &[Vec<(u64, String, Vec<u8>)>],  // Vec of histories, each history is (timestamp, name, metadata)
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    
    // statuses
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    
    // histories
    payload.extend_from_slice(&pack_dd(histories.len() as u32));
    for history in histories {
        payload.extend_from_slice(&pack_dd(history.len() as u32));
        for (ts, name, metadata) in history {
            // unk0, unk1 = 0
            payload.extend_from_slice(&pack_dq(0));
            payload.extend_from_slice(&pack_dq(0));
            // name
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(b"\0");
            // metadata
            payload.extend_from_slice(&pack_dd(metadata.len() as u32));
            payload.extend_from_slice(metadata);
            // timestamp
            payload.extend_from_slice(&pack_dq(*ts));
            // author_idx, idb_path_idx
            payload.extend_from_slice(&pack_dd(0));
            payload.extend_from_slice(&pack_dd(0));
        }
    }
    
    // users array (empty)
    payload.extend_from_slice(&pack_dd(0));
    // dbs array (empty)
    payload.extend_from_slice(&pack_dd(0));
    
    write_legacy_packet(w, 0x30, &payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unpack_dd() {
        // Single byte
        assert_eq!(unpack_dd(&[0x42]), (0x42, 1));
        assert_eq!(unpack_dd(&[0x00]), (0x00, 1));
        assert_eq!(unpack_dd(&[0x7F]), (0x7F, 1));
        
        // Two bytes
        assert_eq!(unpack_dd(&[0x80, 0x00]), (0x0000, 2));
        assert_eq!(unpack_dd(&[0x81, 0x23]), (0x0123, 2));
        assert_eq!(unpack_dd(&[0xBF, 0xFF]), (0x3FFF, 2));
        
        // Three bytes
        assert_eq!(unpack_dd(&[0xC0, 0x00, 0x00]), (0x0000, 3));
        assert_eq!(unpack_dd(&[0xC1, 0x23, 0x45]), (0x012345, 3));
    }
    
    #[test]
    fn test_unpack_cstr() {
        assert_eq!(unpack_cstr(b"hello\0").unwrap(), ("hello".to_string(), 6));
        assert_eq!(unpack_cstr(b"guest\0password\0").unwrap(), ("guest".to_string(), 6));
        assert!(unpack_cstr(b"no null terminator").is_err());
    }
}
