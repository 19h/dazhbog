//! Hash functions, including canonical CRC32C and historical checksum compatibility.

const fn crc_table(polynomial: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { polynomial } else { 0 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const TABLE_REF: [u32; 256] = crc_table(0x82F63B78);
const TABLE_LEGACY: [u32; 256] = crc_table(0x1EDC6F41);

fn checksum(mut crc: u32, data: &[u8], table: &[u32; 256]) -> u32 {
    crc = !crc;
    for &byte in data {
        crc = (crc >> 8) ^ table[((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    !crc
}

/// CRC-32C with the reflected Castagnoli polynomial. Supports incremental seeds.
pub fn crc32c(crc: u32, data: &[u8]) -> u32 {
    checksum(crc, data, &TABLE_REF)
}

/// Historical LSB-first use of the non-reflected polynomial; read compatibility only.
pub fn crc32c_legacy(crc: u32, data: &[u8]) -> u32 {
    checksum(crc, data, &TABLE_LEGACY)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;
    fn bitwise(seed: u32, bytes: &[u8], polynomial: u32) -> u32 {
        let mut crc = !seed;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 == 1 { polynomial } else { 0 };
            }
        }
        !crc
    }
    #[test]
    fn both_variants_match_bitwise_oracles_and_chunked_updates() {
        let input: Vec<u8> = (0..=255).collect();
        for size in 0..=256 {
            let bytes = &input[..size];
            for (fun, polynomial) in [
                (crc32c as fn(u32, &[u8]) -> u32, 0x82F63B78),
                (crc32c_legacy, 0x1EDC6F41),
            ] {
                assert_eq!(fun(0, bytes), bitwise(0, bytes, polynomial));
                let cut = size / 2;
                assert_eq!(fun(fun(0, &bytes[..cut]), &bytes[cut..]), fun(0, bytes));
            }
        }
    }
}

/// Fast 64-bit hash function (wyhash variant).
#[inline]
pub fn wyhash64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

/// Hash a key for sharding purposes.
#[allow(dead_code)]
#[inline]
pub fn key_tag(key: u128) -> u64 {
    let lo = key as u64;
    let hi = (key >> 64) as u64;
    wyhash64(lo ^ hi)
}

/// Compute a hash of a byte slice into a u64.
#[inline]
fn hash_bytes64(b: &[u8]) -> u64 {
    // Simple streaming mix into a u64 seed
    let mut h: u64 = 0x9e3779b185ebca87;
    let mut i = 0usize;
    while i + 8 <= b.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i..i + 8]);
        let v = u64::from_le_bytes(w);
        h = h.wrapping_add(v);
        h = wyhash64(h);
        i += 8;
    }
    if i < b.len() {
        let mut tail = [0u8; 8];
        let remain = &b[i..];
        tail[..remain.len()].copy_from_slice(remain);
        let v = u64::from_le_bytes(tail);
        h = h.wrapping_add(v);
        h = wyhash64(h);
    }
    h ^ (b.len() as u64)
}

/// Stable version identifier: 16-byte key (LE) + 8-byte hash(name) + 8-byte hash(data).
pub fn version_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&key.to_le_bytes());
    let name_hash = wyhash64(hash_bytes64(name.as_bytes()));
    let data_hash = wyhash64(hash_bytes64(data));
    out[16..24].copy_from_slice(&name_hash.to_le_bytes());
    out[24..32].copy_from_slice(&data_hash.to_le_bytes());
    out
}

/// Historical 64-bit little-endian writer identity. Read compatibility only.
pub fn legacy_version_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    super::legacy_version::version_id(key, name, data)
}

/// Test a persisted ID against both supported writers without changing raw data.
pub fn version_id_matches(id: &[u8; 32], key: u128, name: &str, data: &[u8]) -> bool {
    *id == version_id(key, name, data) || *id == legacy_version_id(key, name, data)
}

/// Format bytes as a hex dump for debugging.
pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    let limit = data.len().min(max_bytes);
    let mut result = String::new();

    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        result.push_str(&format!("{:04x}: ", i * 16));

        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x} ", byte));
        }

        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        result.push_str(" |");

        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }

        result.push_str("|\n");
    }

    if data.len() > max_bytes {
        result.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
    }

    result
}
