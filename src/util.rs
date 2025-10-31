pub fn now_ts_sec() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[inline]
pub const fn pack_addr(seg_id: u16, offset: u64, flags: u8) -> u64 {
    ((seg_id as u64) << 48) | ((offset & ((1u64<<40)-1)) << 8) | (flags as u64)
}
#[inline]
pub const fn addr_seg(addr: u64) -> u16 { (addr >> 48) as u16 }
#[inline]
pub const fn addr_off(addr: u64) -> u64 { (addr >> 8) & ((1u64<<40)-1) }
#[inline]
pub const fn addr_flags(addr: u64) -> u8 { (addr & 0xFF) as u8 }

#[inline]
pub fn wyhash64(mut x: u64) -> u64 {
    // Small, fast 64-bit mixer
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

#[inline]
pub fn key_tag(key: u128) -> u64 {
    let lo = key as u64;
    let hi = (key >> 64) as u64;
    wyhash64(lo ^ hi)
}

pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    let limit = data.len().min(max_bytes);
    let mut result = String::new();
    
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        result.push_str(&format!("{:04x}: ", i * 16));
        
        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' '); // Extra space in the middle
            }
            result.push_str(&format!("{:02x} ", byte));
        }
        
        // Pad remaining space if chunk < 16 bytes
        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }
        
        result.push_str(" |");
        
        // ASCII representation
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
