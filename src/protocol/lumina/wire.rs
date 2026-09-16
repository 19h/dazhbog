//! Wire format utilities for Lumina protocol.
//!
//! Implements IDA's variable-length integer encoding and C-string handling.

use crate::common::error::LuminaError;

/// Unpack a variable-length 16-bit integer (IDA format).
pub fn unpack_dw(data: &[u8]) -> (u16, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let mut x = data[0] as u16;
    let mut consumed = 1;
    if (x & 0x80) != 0 {
        if (x & 0xC0) == 0xC0 {
            if data.len() < 3 {
                return (0, 0); // Need 2 more bytes
            }
            let xh = data[1] as u16;
            let xl = data[2] as u16;
            x = (xh << 8) | xl;
            consumed += 2;
        } else {
            if data.len() < 2 {
                return (0, 0); // Need 1 more byte
            }
            x = ((x << 8) | (data[1] as u16)) & !0x8000;
            consumed += 1;
        }
    }
    (x, consumed)
}

/// Unpack a variable-length 32-bit integer (IDA `unpack_dd` format).
///
/// Lead byte selects the width:
/// - `0x00..=0x7F`: 1 byte, value is the byte
/// - `0x80..=0xBF`: 2 bytes, `((b & 0x7F) << 8) | d1`
/// - `0xC0..=0xDF`: 4 bytes, `((b & 0x3F) << 24) | (d1 << 16) | (d2 << 8) | d3`
/// - `0xE0..=0xFF`: 5 bytes, next four bytes big-endian
///
/// Returns `(0, 0)` on truncated input.
pub fn unpack_dd(data: &[u8]) -> (u32, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let b = data[0];
    if (b & 0x80) == 0 {
        return (b as u32, 1);
    }
    if (b & 0xC0) != 0xC0 {
        if data.len() < 2 {
            return (0, 0);
        }
        let val = (((b & 0x7F) as u32) << 8) | (data[1] as u32);
        return (val, 2);
    }
    if (b & 0xE0) == 0xE0 {
        if data.len() < 5 {
            return (0, 0);
        }
        let val = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        return (val, 5);
    }
    if data.len() < 4 {
        return (0, 0);
    }
    let val = (((b & 0x3F) as u32) << 24)
        | ((data[1] as u32) << 16)
        | ((data[2] as u32) << 8)
        | (data[3] as u32);
    (val, 4)
}

/// Pack a variable-length 32-bit integer (IDA `pack_dd` format).
///
/// Canonical widths used by IDA:
/// - `0x00..=0x7F`: 1 byte
/// - `0x80..=0x3FFF`: 2 bytes, `v | 0x8000` big-endian
/// - `0x4000..=0x1FFFFFFF`: 4 bytes, `(v >> 16) | 0xC000` big-endian, then low 16 bits big-endian
/// - `0x20000000..`: `0xFF` then 4 bytes big-endian
pub fn pack_dd(v: u32) -> Vec<u8> {
    match v {
        0..=0x7f => vec![v as u8],
        0x80..=0x3fff => vec![0x80 | ((v >> 8) as u8), (v & 0xff) as u8],
        0x4000..=0x1fff_ffff => vec![
            0xc0 | ((v >> 24) as u8),
            ((v >> 16) & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            (v & 0xff) as u8,
        ],
        _ => vec![
            0xff,
            ((v >> 24) & 0xff) as u8,
            ((v >> 16) & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            (v & 0xff) as u8,
        ],
    }
}

/// Pack a Lumina `index_t` (signed 32-bit) as `pack_dd(x + 1)`, so `-1` becomes `0`.
pub fn pack_index(x: i32) -> Vec<u8> {
    pack_dd((x as u32).wrapping_add(1))
}

/// Unpack a Lumina `index_t`: `unpack_dd() - 1`.
pub fn unpack_index(data: &[u8]) -> (i32, usize) {
    let (v, c) = unpack_dd(data);
    if c == 0 {
        return (0, 0);
    }
    (v.wrapping_sub(1) as i32, c)
}

/// Pack a variable-length 64-bit integer as dd(low) + dd(high).
///
/// NOTE: pack_dq must encode the low 32 bits first, then the high 32 bits,
/// matching how IDA expects dd(low) followed by dd(high).
pub fn pack_dq(v: u64) -> Vec<u8> {
    let low = (v & 0xFFFF_FFFF) as u32;
    let high = (v >> 32) as u32;
    let mut result = pack_dd(low);
    result.extend_from_slice(&pack_dd(high));
    result
}

/// Unpack a variable-length 64-bit integer as dd(low) + dd(high).
pub fn unpack_dq(data: &[u8]) -> (u64, usize) {
    let (low, c1) = unpack_dd(data);
    if c1 == 0 {
        return (0, 0);
    }
    let (high, c2) = unpack_dd(&data[c1..]);
    if c2 == 0 {
        return (0, 0);
    }
    let val = ((high as u64) << 32) | (low as u64);
    (val, c1 + c2)
}

/// Pack an ea64 address as unpack_dq() + 1.
pub fn pack_ea64(v: u64) -> Vec<u8> {
    pack_dq(v.wrapping_add(1))
}

/// Unpack an ea64 address, which is unpack_dq() - 1.
pub fn unpack_ea64(data: &[u8]) -> (u64, usize) {
    let (val, c) = unpack_dq(data);
    if c == 0 {
        return (0, 0);
    }
    (val.wrapping_sub(1), c)
}

/// Unpack a null-terminated C-string with maximum length check.
pub fn unpack_cstr_capped(data: &[u8], max: usize) -> Result<(String, usize), LuminaError> {
    let null_pos = data
        .iter()
        .position(|&b| b == 0)
        .ok_or(LuminaError::UnexpectedEof)?;
    if null_pos > max {
        return Err(LuminaError::InvalidData);
    }
    let s = std::str::from_utf8(&data[..null_pos]).map_err(|_| LuminaError::InvalidData)?;
    Ok((s.to_string(), null_pos + 1))
}

/// Unpack variable-length bytes with maximum length check.
pub fn unpack_var_bytes_capped(data: &[u8], max_len: usize) -> Result<(&[u8], usize), LuminaError> {
    let (len, consumed) = unpack_dd(data);
    if consumed == 0 {
        return Err(LuminaError::UnexpectedEof);
    }
    let len = len as usize;
    if len > max_len {
        return Err(LuminaError::InvalidData);
    }
    let data = &data[consumed..];
    if data.len() < len {
        return Err(LuminaError::UnexpectedEof);
    }
    Ok((&data[..len], consumed + len))
}

/// Pack variable-length bytes as dd(len) + bytes.
#[allow(dead_code)]
pub fn pack_var_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.extend_from_slice(&pack_dd(bytes.len() as u32));
    out.extend_from_slice(bytes);
    out
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
        assert_eq!(unpack_dd(&[0xC0, 0x00, 0x00, 0x00]), (0x00000000, 4));
        assert_eq!(unpack_dd(&[0xC1, 0x23, 0x45, 0x00]), (0x01234500, 4));
        assert_eq!(unpack_dd(&[0xFF, 0x78, 0x56, 0x34, 0x12]), (0x78563412, 5));
        // Any lead byte in 0xE0..=0xFF selects the 5-byte form (IDA unpack_dd).
        assert_eq!(unpack_dd(&[0xE0, 0x01, 0x02, 0x03, 0x04]), (0x01020304, 5));
        assert_eq!(unpack_dd(&[0xE3, 0x01, 0x02, 0x03, 0x04]), (0x01020304, 5));
        // 4-byte form carries 30 bits.
        assert_eq!(unpack_dd(&[0xDF, 0xFF, 0xFF, 0xFF]), (0x1FFFFFFF, 4));
        // Truncated inputs.
        assert_eq!(unpack_dd(&[0xE0, 0x01, 0x02, 0x03]), (0, 0));
        assert_eq!(unpack_dd(&[0xC0, 0x01]), (0, 0));
        assert_eq!(unpack_dd(&[0x80]), (0, 0));
    }

    #[test]
    fn test_pack_dd_canonical() {
        // Width boundaries of the IDA encoder.
        assert_eq!(pack_dd(0x7F), vec![0x7F]);
        assert_eq!(pack_dd(0x80), vec![0x80, 0x80]);
        assert_eq!(pack_dd(0x3FFF), vec![0xBF, 0xFF]);
        assert_eq!(pack_dd(0x4000), vec![0xC0, 0x00, 0x40, 0x00]);
        assert_eq!(pack_dd(0x200000), vec![0xC0, 0x20, 0x00, 0x00]);
        assert_eq!(pack_dd(0x1FFFFFFF), vec![0xDF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(pack_dd(0x20000000), vec![0xFF, 0x20, 0x00, 0x00, 0x00]);
        assert_eq!(pack_dd(0xFFFFFFFE), vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
        for v in [
            0u32, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0x1FFFFFFF, 0x20000000,
            0x7FFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF,
        ] {
            let enc = pack_dd(v);
            assert_eq!(unpack_dd(&enc), (v, enc.len()), "round trip {v:#x}");
        }
    }

    #[test]
    fn test_pack_index() {
        assert_eq!(pack_index(-1), vec![0x00]);
        assert_eq!(pack_index(0), vec![0x01]);
        assert_eq!(pack_index(5), vec![0x06]);
        assert_eq!(unpack_index(&[0x00]), (-1, 1));
        assert_eq!(unpack_index(&[0x06]), (5, 1));
    }

    #[test]
    fn test_unpack_cstr_capped() {
        assert_eq!(
            unpack_cstr_capped(b"hello\0", 16).unwrap(),
            ("hello".to_string(), 6)
        );
        assert!(unpack_cstr_capped(b"no null terminator", 64).is_err());
        assert!(unpack_cstr_capped(&[b'a'; 10_000], 1024).is_err());
    }

    #[test]
    fn test_pack_dq_low_then_high() {
        let v: u64 = 0x11223344_55667788;
        let enc = pack_dq(v);
        let (lo, c1) = unpack_dd(&enc[..]);
        let (hi, _c2) = unpack_dd(&enc[c1..]);
        assert_eq!(lo, 0x55667788);
        assert_eq!(hi, 0x11223344);
    }
}
