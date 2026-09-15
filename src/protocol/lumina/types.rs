//! Lumina protocol type definitions.

/// (popularity, metadata byte count, symbol name, raw metadata).
pub type FunctionPayload = (u32, u32, String, Vec<u8>);
pub type PullResult = (Vec<u32>, Vec<FunctionPayload>);
/// (name, size, metadata, pattern type/data, frequency, host, path, MD5, address).
pub type PopResult = (
    String,
    u32,
    Vec<u8>,
    u32,
    Vec<u8>,
    u32,
    String,
    String,
    [u8; 16],
    u64,
);

/// Sentinel license ID that marks a connection as read-only (no database mutations).
///
/// When a Lumina client sends this 6-byte license ID in the hello handshake,
/// the server will serve pull/hist/info/stats requests normally but will silently
/// reject all push, delete, and context-recording operations.
///
/// Value: `FF-FFFF-FF00-00` — the `0xFF` prefix byte is outside the range used by
/// real IDA license IDs, and the trailing null bytes create a visually distinctive
/// pattern that cannot be produced by accident.
pub const READONLY_LICENSE_ID: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];

/// Hello message from client.
pub struct LuminaHello {
    pub protocol_version: u32,
    pub license_id: [u8; 6],
    pub username: String,
    pub password: String,
}

impl LuminaHello {
    /// Returns `true` if the client presented the read-only sentinel license ID.
    pub fn is_readonly(&self) -> bool {
        self.license_id == READONLY_LICENSE_ID
    }
}

/// Raw hello data for debug dumps.
pub struct LuminaHelloRaw {
    pub protocol_version: u32,
    pub key: Vec<u8>,
    pub license_id: [u8; 6],
    pub username: String,
    pub password: String,
}

/// Capability limits for protocol parsing.
#[derive(Clone, Copy, Debug)]
pub struct LuminaCaps {
    pub max_funcs: usize,
    pub max_name_bytes: usize,
    pub max_data_bytes: usize,
    pub max_cstr_bytes: usize,
    pub max_hash_bytes: usize,
}

impl Default for LuminaCaps {
    fn default() -> Self {
        Self {
            max_funcs: 524288,
            max_name_bytes: 65535,
            max_data_bytes: 8 * 1024 * 1024,
            max_cstr_bytes: 4096,
            max_hash_bytes: 64,
        }
    }
}

/// Function entry in PullMetadata request.
pub struct LuminaPullMetadataFunc {
    #[allow(dead_code)]
    pub flags: u32,
    pub mb_hash: Vec<u8>,
}

/// PullMetadata request.
pub struct LuminaPullMetadata {
    #[allow(dead_code)]
    pub flags: u32,
    #[allow(dead_code)]
    pub keys: Vec<u32>,
    pub funcs: Vec<LuminaPullMetadataFunc>,
}

/// Function entry in PushMetadata request.
pub struct LuminaPushMetadataFunc {
    pub name: String,
    pub func_len: u32,
    pub func_data: Vec<u8>,
    #[allow(dead_code)]
    pub record_conv: u32,
    pub hash: Vec<u8>,
}

/// PushMetadata request.
pub struct LuminaPushMetadata {
    #[allow(dead_code)]
    pub flags: u32,
    #[allow(dead_code)]
    pub idb_path: String,
    pub file_path: String,
    pub md5: [u8; 16],
    pub hostname: String,
    pub funcs: Vec<LuminaPushMetadataFunc>,
    #[allow(dead_code)]
    pub keys: Vec<u64>,
}

/// GetFuncHistories request.
pub struct LuminaGetFuncHistories {
    pub funcs: Vec<LuminaPullMetadataFunc>,
    #[allow(dead_code)]
    pub flags: u32,
}

/// User License Info struct.
#[derive(Default)]
pub struct UserLicenseInfo {
    pub id: String,
    pub name: String,
    pub email: String,
}

/// Lumina User struct.
#[derive(Default)]
pub struct LuminaUser {
    pub license_info: UserLicenseInfo,
    pub name: String,
    pub karma: i32,
    pub last_active: u64,
    pub features: u32,
}

/// Lumina Server Info struct.
pub struct LuminaServerInfo {
    pub macaddr: String,
    pub verstr: String,
    pub start_time: u64,
    pub current_time: u64,
}

/// Peer connection info struct.
pub struct PeerConn {
    pub session_id: u32,
    pub peer_name: String,
    pub user: LuminaUser,
    pub established: u64,
}

/// Lumina overall stats structure.
pub struct LuminaStats {
    pub user: LuminaUser,
    pub nfuncs: u64,
    pub npushes: u64,
    pub nhist_recs: u64,
    pub nidbs: u64,
    pub ninput_files: u64,
}

/// Helper enum for response codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum LuminaOpRes {
    BadPtn = -3,
    NotFound = -2,
    Error = -1,
    Ok = 0,
    Added = 1,
}

impl LuminaOpRes {
    pub fn as_u32(self) -> u32 {
        (self as i32) as u32
    }
}
