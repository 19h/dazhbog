//! Lumina protocol type definitions.

/// (frequency, declared function size in bytes, symbol name, raw metadata).
///
/// The second field is `func_info_t.size` (the pushed function size), not the
/// metadata length, which is encoded separately as the blob's length prefix.
pub type FunctionPayload = (u32, u32, String, Vec<u8>);

/// Highest Lumina protocol version this server implements (`PROTOCOL_VERSION`).
pub const PROTOCOL_VERSION: u32 = 6;
/// `pattern_type_t::PAT_TYPE_MD5`; the only pattern type the reference accepts.
pub const PAT_TYPE_MD5: u32 = 1;
/// `pull_md.flags`: do not increase the frequency counter.
pub const PULL_MD_SEEN_FILE: u32 = 0x02;
/// `push_md.flags` low nibble selects the conflict mode.
pub const PMF_PUSH_MODE_MASK: u32 = 0xF;
pub const PMF_PUSH_OVERRIDE_IF_BETTER_OR_DIFFERENT: u32 = 0x0;
pub const PMF_PUSH_OVERRIDE: u32 = 0x1;
pub const PMF_PUSH_DO_NOT_OVERRIDE: u32 = 0x2;
pub const PMF_PUSH_MERGE: u32 = 0x3;
/// `get_func_histories.flags` / `filters_t.flags` bits.
pub const BOPF_DETAILS: u32 = 0x2;
pub const BOPF_LAST_FUNC_RECORD: u32 = 0x8;
/// `lumina_user_t.features` bits.
pub const UF_IS_ADMIN: u32 = 0x1;
pub const UF_CAN_DEL_HISTORY: u32 = 0x2;
/// `mdkey_t::MDK_LAST`: metadata keys must be in `1..MDK_LAST`.
pub const MDK_LAST: u32 = 12;
/// Reference caps `get_pop.nresults` at 100.
pub const GET_POP_MAX_RESULTS: u32 = 100;
/// `rpc_fail.result` value the reference server uses.
pub const RPC_FAIL_RESULT: u32 = u32::MAX;
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

/// `pattern_id_t` entry in PullMetadata / GetFuncHistories requests.
pub struct LuminaPullMetadataFunc {
    /// `pattern_type_t`; only `PAT_TYPE_MD5` is valid.
    pub pattern_type: u32,
    pub mb_hash: Vec<u8>,
}

impl LuminaPullMetadataFunc {
    /// The 16-byte MD5 pattern as a big-endian key, or `None` when the pattern
    /// is not a valid MD5 pattern (`PDRES_BADPTN`).
    pub fn md5_key(&self) -> Option<u128> {
        if self.pattern_type != PAT_TYPE_MD5 || self.mb_hash.len() != 16 {
            return None;
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.mb_hash);
        Some(u128::from_be_bytes(b))
    }
}

/// PullMetadata request.
pub struct LuminaPullMetadata {
    pub flags: u32,
    /// Requested `mdkey_t` values; empty means "all metadata".
    pub keys: Vec<u32>,
    pub funcs: Vec<LuminaPullMetadataFunc>,
}

/// `func_info_and_pattern_t` entry in PushMetadata request.
pub struct LuminaPushMetadataFunc {
    pub name: String,
    /// `func_info_t.size`: function size in bytes.
    pub func_len: u32,
    pub func_data: Vec<u8>,
    /// `pattern_id_t.type`.
    pub pattern_type: u32,
    pub hash: Vec<u8>,
}

impl LuminaPushMetadataFunc {
    pub fn md5_key(&self) -> Option<u128> {
        if self.pattern_type != PAT_TYPE_MD5 || self.hash.len() != 16 {
            return None;
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.hash);
        Some(u128::from_be_bytes(b))
    }
}

/// PushMetadata request.
pub struct LuminaPushMetadata {
    pub flags: u32,
    pub idb_path: String,
    pub file_path: String,
    pub md5: [u8; 16],
    pub hostname: String,
    pub funcs: Vec<LuminaPushMetadataFunc>,
    /// Function start addresses (`ea64vec_t`), one per entry; `u64::MAX` is BADADDR.
    pub ea64s: Vec<u64>,
}

/// GetFuncHistories request.
pub struct LuminaGetFuncHistories {
    pub funcs: Vec<LuminaPullMetadataFunc>,
    pub flags: u32,
}

/// `filters_t` as sent by `del_history` / `show_history`.
#[derive(Default, Debug, Clone)]
pub struct LuminaFilters {
    pub flags: u32,
    pub license_id: Vec<String>,
    pub time_ranges: Vec<(u64, u64)>,
    pub history_id_ranges: Vec<(u64, u64)>,
    pub idbs: Vec<String>,
    pub inputs: Vec<String>,
    pub funcs: Vec<String>,
    pub usernames: Vec<String>,
    pub input_hashes: Vec<[u8; 16]>,
    pub calcrel_hashes: Vec<[u8; 16]>,
    pub push_id_ranges: Vec<(u64, u64)>,
    pub max_entries: u64,
}

impl LuminaFilters {
    /// True when any selector other than `calcrel_hashes` is set.
    pub fn has_unsupported_selectors(&self) -> bool {
        !self.license_id.is_empty()
            || !self.time_ranges.is_empty()
            || !self.history_id_ranges.is_empty()
            || !self.idbs.is_empty()
            || !self.inputs.is_empty()
            || !self.funcs.is_empty()
            || !self.usernames.is_empty()
            || !self.input_hashes.is_empty()
            || !self.push_id_ranges.is_empty()
    }
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
