// Table-driven CRC32C (Castagnoli) implementation with unsafe optimization
// SAFETY: This module uses unsafe for performance-critical CRC computation.
// The table is initialized once and accessed read-only afterward.
const POLY: u32 = 0x1EDC6F41;
static mut TABLE: [u32;256] = [0;256];
static INIT: std::sync::Once = std::sync::Once::new();

fn init_table() {
    unsafe {
        for i in 0..256 {
            let mut crc = i as u32;
            for _ in 0..8 {
                if (crc & 1) != 0 { crc = (crc >> 1) ^ POLY; } else { crc >>= 1; }
            }
            TABLE[i] = crc;
        }
    }
}

pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    INIT.call_once(init_table);
    crc = !crc;
    for &b in data {
        let idx = (crc ^ (b as u32)) & 0xFF;
        // SAFETY: table initialized once, idx always < 256
        let t = unsafe { TABLE[idx as usize] };
        crc = (crc >> 8) ^ t;
    }
    !crc
}
