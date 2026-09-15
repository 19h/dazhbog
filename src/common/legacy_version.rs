//! Compatibility with database.rs::version_id from commit 8e1ffd2.
//!
//! That writer used DefaultHasher with Rust Hash on 64-bit little-endian hosts.
//! Pin its byte feed and SipHash-1-3 here: neither Hash nor DefaultHasher promises
//! a stable persisted encoding. This is a read alias, never a new-write identity.

pub(super) fn version_id(key: u128, name: &str, data: &[u8]) -> [u8; 32] {
    let key_bytes = key.to_le_bytes();
    let data_len = (data.len() as u64).to_le_bytes();
    let bytes = key_bytes
        .iter()
        .chain(name.as_bytes())
        .chain(&[0xff])
        .chain(&data_len)
        .chain(data)
        .copied();
    let hash = sip13(bytes);
    let mut out = [0; 32];
    out[..16].copy_from_slice(&key_bytes);
    out[16..24].copy_from_slice(&hash.to_le_bytes());
    out[24..].copy_from_slice(&(name.len() as u64).to_le_bytes());
    out
}

fn round(s: &mut [u64; 4]) {
    s[0] = s[0].wrapping_add(s[1]);
    s[1] = s[1].rotate_left(13) ^ s[0];
    s[0] = s[0].rotate_left(32);
    s[2] = s[2].wrapping_add(s[3]);
    s[3] = s[3].rotate_left(16) ^ s[2];
    s[0] = s[0].wrapping_add(s[3]);
    s[3] = s[3].rotate_left(21) ^ s[0];
    s[2] = s[2].wrapping_add(s[1]);
    s[1] = s[1].rotate_left(17) ^ s[2];
    s[2] = s[2].rotate_left(32);
}

/// Zero-key SipHash-1-3; O(B) time and O(1) extra memory for B input bytes.
fn sip13(bytes: impl Iterator<Item = u8>) -> u64 {
    let mut s = [
        0x736f6d6570736575,
        0x646f72616e646f6d,
        0x6c7967656e657261,
        0x7465646279746573,
    ];
    let mut length = 0u8;
    let mut tail = 0u64;
    for byte in bytes {
        tail |= u64::from(byte) << ((length & 7) * 8);
        length = length.wrapping_add(1);
        if length & 7 == 0 {
            s[3] ^= tail;
            round(&mut s);
            s[0] ^= tail;
            tail = 0;
        }
    }
    tail |= u64::from(length) << 56;
    s[3] ^= tail;
    round(&mut s);
    s[0] ^= tail;
    s[2] ^= 0xff;
    for _ in 0..3 {
        round(&mut s);
    }
    s[0] ^ s[1] ^ s[2] ^ s[3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_writer_fixtures() {
        // Frozen after comparison with the independent historical writer below.
        assert_eq!(
            version_id(0, "", b""),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7d, 0x79, 0xbe, 0x5f, 0x8b, 0x33,
                0x25, 0x76, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            version_id(u128::MAX, "Δ解析\0fn", b"\0\xffmetadata"),
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                0x0f, 0xfe, 0xd3, 0x3a, 0xb2, 0x1f, 0xcd, 0x01, 11, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    // Independent historical writer, restricted to the platform it encoded.
    #[cfg(all(target_pointer_width = "64", target_endian = "little"))]
    #[test]
    fn matches_historical_writer_at_word_and_length_boundaries() {
        use std::hash::{Hash, Hasher};
        for key in [0, 1, u128::MAX, 0x123456789abcdef01122334455667788] {
            for name in ["", "a", "abcdefgh", "abcdefghi", "Δ解析\0fn"] {
                for len in 0..=513 {
                    let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    key.hash(&mut h);
                    name.hash(&mut h);
                    data.hash(&mut h);
                    let actual = version_id(key, name, &data);
                    assert_eq!(actual[..16], key.to_le_bytes());
                    assert_eq!(actual[16..24], h.finish().to_le_bytes());
                    assert_eq!(actual[24..], (name.len() as u64).to_le_bytes());
                }
            }
        }
    }
}
