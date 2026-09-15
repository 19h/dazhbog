//! Lumina protocol message parsers.

use super::types::*;
use super::wire::*;
use crate::common::error::LuminaError;
use log::*;

/// Parse a Lumina Hello message into raw form (for debug dumps).
pub fn parse_lumina_hello_raw(payload: &[u8]) -> Result<LuminaHelloRaw, LuminaError> {
    let mut offset = 0;
    let (protocol_version, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += consumed;

    let (key, consumed) = unpack_var_bytes_capped(&payload[offset..], 16384)?;
    let key = key.to_vec();
    offset += consumed;

    if payload.len() < offset + 6 {
        return Err(LuminaError::UnexpectedEof);
    }
    let mut license_id = [0u8; 6];
    license_id.copy_from_slice(&payload[offset..offset + 6]);
    offset += 6;

    let (_record_conv, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += consumed;

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

    Ok(LuminaHelloRaw {
        protocol_version,
        key,
        license_id,
        username,
        password,
    })
}

/// Parse a Lumina Hello message.
pub fn parse_lumina_hello(payload: &[u8]) -> Result<LuminaHello, LuminaError> {
    let raw = parse_lumina_hello_raw(payload)?;
    debug!(
        "Lumina Hello: protocol_version={}, license_id={}",
        raw.protocol_version,
        raw.license_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    Ok(LuminaHello {
        protocol_version: raw.protocol_version,
        license_id: raw.license_id,
        username: raw.username,
        password: raw.password,
    })
}

/// Parse a Lumina PullMetadata message.
pub fn parse_lumina_pull_metadata(
    payload: &[u8],
    caps: LuminaCaps,
) -> Result<LuminaPullMetadata, LuminaError> {
    let mut offset = 0;
    debug!("parse_lumina_pull_metadata: payload len={}", payload.len());

    let (flags, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += consumed;

    let (count1, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += consumed;

    let mut keys = Vec::with_capacity((count1 as usize).min(1024));
    for _ in 0..count1 {
        let (v, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;
        keys.push(v);
    }

    let (count_funcs, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += consumed;

    let n = (count_funcs as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count_funcs {
        let (pattern_type, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LuminaPullMetadataFunc {
                flags: pattern_type,
                mb_hash: hash.to_vec(),
            });
        }
    }

    Ok(LuminaPullMetadata { flags, keys, funcs })
}

/// Parse a Lumina PushMetadata message.
pub fn parse_lumina_push_metadata(
    payload: &[u8],
    caps: LuminaCaps,
) -> Result<LuminaPushMetadata, LuminaError> {
    let mut offset = 0;
    debug!("parse_lumina_push_metadata: payload len={}", payload.len());

    let (flags, consumed) = unpack_dd(&payload[offset..]);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += consumed;

    let (idb_path, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    let (file_path, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    if payload.len() < offset + 16 {
        return Err(LuminaError::UnexpectedEof);
    }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&payload[offset..offset + 16]);
    offset += 16;

    let (hostname, c) = unpack_cstr_capped(&payload[offset..], caps.max_cstr_bytes)?;
    offset += c;

    let (count_funcs, c) = unpack_dd(&payload[offset..]);
    if c == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += c;

    if count_funcs as usize > caps.max_funcs {
        log::warn!(
            "Push request contains {} functions but limit is {}",
            count_funcs,
            caps.max_funcs
        );
        return Err(LuminaError::InvalidData);
    }

    let n = count_funcs as usize;
    let mut funcs = Vec::with_capacity(n);

    for _ in 0..count_funcs {
        let (name, c) = unpack_cstr_capped(&payload[offset..], caps.max_name_bytes)?;
        offset += c;

        let (func_len, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;

        let (func_data, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_data_bytes)?;
        offset += c;

        let (record_conv, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        funcs.push(LuminaPushMetadataFunc {
            name,
            func_len,
            func_data: func_data.to_vec(),
            record_conv,
            hash: hash.to_vec(),
        });
    }

    let (count_u64, c) = unpack_dd(&payload[offset..]);
    if c == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += c;

    let cap_u64s = 4096usize.min(count_u64 as usize);
    let mut keys = Vec::with_capacity(cap_u64s);

    for i in 0..count_u64 {
        let (low, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;

        let (high, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;

        if (i as usize) < cap_u64s {
            keys.push(((high as u64) << 32) | (low as u64));
        }
    }

    Ok(LuminaPushMetadata {
        flags,
        idb_path,
        file_path,
        md5,
        hostname,
        funcs,
        keys,
    })
}

/// Parse a Lumina GetFuncHistories message.
pub fn parse_lumina_get_func_histories(
    payload: &[u8],
    caps: LuminaCaps,
) -> Result<LuminaGetFuncHistories, LuminaError> {
    let mut offset = 0;

    let (count, c) = unpack_dd(&payload[offset..]);
    if c == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    offset += c;

    let n = (count as usize).min(caps.max_funcs);
    let mut funcs = Vec::with_capacity(n);

    for i in 0..count {
        let (pattern_type, c) = unpack_dd(&payload[offset..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        offset += c;

        let (hash, c) = unpack_var_bytes_capped(&payload[offset..], caps.max_hash_bytes)?;
        offset += c;

        if (i as usize) < n {
            funcs.push(LuminaPullMetadataFunc {
                flags: pattern_type,
                mb_hash: hash.to_vec(),
            });
        }
    }

    let (flags, _c) = unpack_dd(&payload[offset..]);

    Ok(LuminaGetFuncHistories { funcs, flags })
}

/// Decode a Lumina Fail message payload (0x0b): returns (code, message).
pub fn decode_lumina_fail(payload: &[u8]) -> Result<(u32, String), LuminaError> {
    let (code, consumed) = unpack_dd(payload);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    let msg_bytes = &payload[consumed..];
    let null_pos = msg_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(msg_bytes.len());
    let message = std::str::from_utf8(&msg_bytes[..null_pos])
        .unwrap_or("<invalid utf8>")
        .to_string();
    Ok((code, message))
}

/// Decode a PullResult payload (0x0f): returns (statuses, funcs).
pub fn decode_lumina_pull_result(payload: &[u8]) -> Result<PullResult, LuminaError> {
    let mut off = 0usize;
    let (n_status, c) = unpack_dd(&payload[off..]);
    if c == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    off += c;
    let mut statuses = Vec::with_capacity(n_status as usize);
    for _ in 0..n_status {
        let (s, c) = unpack_dd(&payload[off..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        off += c;
        statuses.push(s);
    }
    let (n_funcs, c) = unpack_dd(&payload[off..]);
    if c == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    off += c;

    let mut funcs = Vec::with_capacity(n_funcs as usize);
    for _ in 0..n_funcs {
        // cstr name
        let (name, _c) = {
            let null_pos = payload[off..]
                .iter()
                .position(|&b| b == 0)
                .ok_or(LuminaError::UnexpectedEof)?;
            let s = std::str::from_utf8(&payload[off..off + null_pos])
                .map_err(|_| LuminaError::InvalidData)?
                .to_string();
            off += null_pos + 1;
            (s, null_pos + 1)
        };
        let (decl_len, c) = unpack_dd(&payload[off..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        off += c;
        let (meta_len, c) = unpack_dd(&payload[off..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        off += c;
        if payload.len() < off + (meta_len as usize) {
            return Err(LuminaError::UnexpectedEof);
        }
        let data = payload[off..off + (meta_len as usize)].to_vec();
        off += meta_len as usize;
        let (pop, c) = unpack_dd(&payload[off..]);
        if c == 0 {
            return Err(LuminaError::UnexpectedEof);
        }
        off += c;
        funcs.push((pop, decl_len, name, data));
    }
    Ok((statuses, funcs))
}
