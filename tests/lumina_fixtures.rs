//! Byte-for-byte compatibility tests against packets exchanged with a
//! Hex-Rays Lumina server.
//!
//! Each fixture is the packet payload (after the 4-byte length and 1-byte code).
//! Hello packets are not embedded because they carry license material; the
//! session tests use a synthetic hello instead. Paths and hostnames inside the
//! push request were replaced by neutral values of the same layout.

use dazhbog::config::{Config, Engine};
use dazhbog::db::Database;
use dazhbog::net::budget::Budget;
use dazhbog::net::handler::handle_client;
use dazhbog::protocol::lumina::{
    build_lumina_hello_payload, decode_lumina_fail, decode_lumina_pull_result, pack_dd, pack_ea64,
    parse_lumina_del_history, parse_lumina_pull_metadata, parse_lumina_push_metadata,
    read_lumina_packet, send_lumina_fail, send_lumina_pull_result, send_lumina_push_result,
    validate_push, write_lumina_packet, LuminaCaps, LuminaOpRes, BOPF_DETAILS,
    BOPF_LAST_FUNC_RECORD, PAT_TYPE_MD5, RPC_FAIL_RESULT,
};
use rand::RngExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

// ---------------------------------------------------------------------------
// Captured payloads (hex), protocol v6 server.
// ---------------------------------------------------------------------------

const V4_PUSH_REQ: &[&str] = &[
    "002f776f726b2f6d656469756d5f656c662e696462002f776f726b2f70635f647761726664756d702e656c660080d6c6",
    "2267db6581167f2cee5bcbafe5776f726b73746174696f6e0001616464725f6d61705f6372656174655f656e74727900",
    "6680b9012f000c300a3d0f416464725f4d61705f456e747279033d0f44776172665f556e7369676e65640a3200026b05",
    "6e616d650965390001000405736b003d0f44776172665f556e7369676e656400001900000900736d70000a3d0f416464",
    "725f4d61705f456e74727900002d0055000000000100020500704100000500704500000500736e616d65000a32000049",
    "00550000000001000205000a1f00031003b0030b03b0030b0f0b030b0db003b003b0080b06b00db008b00ab00110182e",
    "9d3097eb4e5fcac78c2bdbcac64301c804953500",
];
const V4_PUSH_RESP: &[&str] = &["0101"];
const V4_PULL_REQ: &[&str] = &["0100010110182e9d3097eb4e5fcac78c2bdbcac643"];
const V4_PULL_RESP: &[&str] = &[
    "010001616464725f6d61705f6372656174655f656e747279006680b9012f000c300a3d0f416464725f4d61705f456e74",
    "7279033d0f44776172665f556e7369676e65640a3200026b056e616d650965390001000405736b003d0f44776172665f",
    "556e7369676e656400001900000900736d70000a3d0f416464725f4d61705f456e74727900002d005500000000010002",
    "0500704100000500704500000500736e616d65000a3200004900550000000001000205000a1f00031003b0030b03b003",
    "0b0f0b030b0db003b003b0080b06b00db008b00ab000",
];
const V3_PULL_REQ: &[&str] = &[
    "010027011006d824d9ec47bbca3cef51413602926b011057c5b8853a29445597b9813dd268a28a01106e09dcc506d046",
    "680fe81ce5c3e811b20110c2b293dfcad5df7925073c09216c1ba501101317dcf3f273ead0f959f1002947ec0f0110b1",
    "ec55c8e77f518adc7b2b75bdd9510a01108a311f960062380434f28f59ee3561f00110cefc7f6b2b9aac96cc4d2f5e45",
    "85932c0110dd6d48a1961195c09c71ec33376b214b0110d6c3f7996c2f54ea4d709dfbede1b4a901109531394b2cd95b",
    "1a9dbdbec88b11edb201108a7176156c1f9599a5e26825a1c00ed80110fc11a660f437aa462be945180e0874df0110f1",
    "b6a7e432ea50ef2e594f3379cba98f01104e520da610a72d4254a45b1e6780cc91011003a711e0f27017f1fc01803eee",
    "ba6ee90110630913f953032f2cbdba7f176f9818a901107a8dd05a0b5f021f7cfef69ce3cb831f01106cdf35c7a3f209",
    "19d77a15f0e1f84a7f011086f77dc88093775b27e8c14b2b8656f10110fe9aa6b338b66e6570c7769003169b990110e9",
    "111547795281944808b09d86824c6901106e89e8486b15b2657d40a3205cf133f3011091e7927d9494feb869bf745aa6",
    "320ec5011037ed0ec118465f5ab1d1e85d815c17ba011046848211c5eb0ae501af1fc0f5cce29c01101eef5baba3c220",
    "d602972c8b486db9cb0110a88bbac84d775dfcf039ee1598b4ae03011066fee7417d0b17cdffe6bcbdf9a5f836011090",
    "13fef486bf3b5eeaf49b882ec518dd0110edbd1d5aee3fd8c56ac166ca642cbc630110cb2685f5e99cb9158fd0fc6b99",
    "5b77880110d0d8222d3eccd10e8d87198f4b9fc88c0110de596b0100f02b78cfefc380a3a2277401101216a3c7885c87",
    "04fa2d1c022ea8b9870110db738e1c84ea7401c4022a10bf34e16f011036c2416e1c22c5ae2d4b5d7b218beef3011001",
    "c33e1ff1d87d8731f4e96f2eca0b7a011029002cb72479700acb0a5cf544c467a5",
];
const V3_PULL_RESP: &[&str] = &[
    "27fffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffeffff",
    "fffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffe",
    "fffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffeffffff",
    "fffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffefffffffffeff",
    "fffffffe00",
];
const HELO80_FAIL: &[&str] = &[
    "ffffffffff4c756d696e612070726f746f636f6c2076657273696f6e206e6f7420636f6d70617469626c652077697468",
    "2073657276657200",
];

fn hex(parts: &[&str]) -> Vec<u8> {
    let joined: String = parts.concat();
    (0..joined.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&joined[i..i + 2], 16).unwrap())
        .collect()
}

/// The pattern pushed and pulled in `simple_v4`.
const V4_HASH: [u8; 16] = [
    0x18, 0x2E, 0x9D, 0x30, 0x97, 0xEB, 0x4E, 0x5F, 0xCA, 0xC7, 0x8C, 0x2B, 0xDB, 0xCA, 0xC6, 0x43,
];

struct MockStream(Vec<u8>);

impl AsyncWrite for MockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.0.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn frame(code: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.push(code);
    out.extend_from_slice(payload);
    out
}

fn test_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "dazhbog_fixture_{}_{}",
        name,
        rand::rng().random::<u64>()
    ));
    if path.exists() {
        std::fs::remove_dir_all(&path).unwrap();
    }
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn test_config(data_dir: &Path) -> Config {
    let engine = Engine {
        name_rejection: dazhbog::config::NameRejection::Prefixes,
        data_dir: data_dir.to_str().unwrap().to_string(),
        segment_bytes: 16 * 1024 * 1024,
        shard_count: 4,
        index_capacity: 1024 * 1024,
        sync_interval_ms: 100,
        compaction_check_ms: 1000,
        use_mmap_reads: false,
        deduplicate_on_startup: false,
        index_dir: Some(data_dir.join("index").to_str().unwrap().to_string()),
        index_memtable_max_entries: 1000,
        index_block_entries: 16,
        index_level0_compact_trigger: 4,
    };
    Config {
        engine,
        ..Config::default()
    }
}

type Packet = (u8, Vec<u8>);

/// A connected Lumina client talking to an in-process `handle_client`.
struct Session {
    client: tokio::io::DuplexStream,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Session {
    async fn open(cfg: Config, db: Arc<Database>, hello: &[u8]) -> (Self, Packet) {
        let cfg = Arc::new(cfg);
        let (mut client, server_stream) = tokio::io::duplex(4 * 1024 * 1024);
        let budget = Arc::new(Budget::new(cfg.limits.global_inflight_bytes));
        let server = tokio::spawn(handle_client(server_stream, cfg, db, budget));
        write_lumina_packet(&mut client, 0x0d, hello).await.unwrap();
        let reply = read_lumina_packet(&mut client, 64 * 1024 * 1024)
            .await
            .unwrap();
        (Session { client, server }, reply)
    }

    async fn call(&mut self, code: u8, payload: &[u8]) -> Packet {
        write_lumina_packet(&mut self.client, code, payload)
            .await
            .unwrap();
        read_lumina_packet(&mut self.client, 64 * 1024 * 1024)
            .await
            .unwrap()
    }

    async fn close(self) {
        drop(self.client);
        let _ = self.server.await;
    }
}

fn hello_v(version: u32, username: &str) -> Vec<u8> {
    build_lumina_hello_payload(
        version,
        b"not-a-license",
        [1, 2, 3, 4, 5, 6],
        username,
        "",
        0,
    )
}

fn pull_payload(flags: u32, patterns: &[(u32, &[u8])]) -> Vec<u8> {
    let mut p = pack_dd(flags);
    p.extend(pack_dd(0));
    p.extend(pack_dd(patterns.len() as u32));
    for (ty, data) in patterns {
        p.extend(pack_dd(*ty));
        p.extend(pack_dd(data.len() as u32));
        p.extend_from_slice(data);
    }
    p
}

/// `(name, declared size, metadata, pattern type, pattern bytes)`.
type PushFunc<'a> = (&'a str, u32, &'a [u8], u32, &'a [u8]);

fn push_payload(flags: u32, funcs: &[PushFunc<'_>], eas: &[u64]) -> Vec<u8> {
    let mut p = pack_dd(flags);
    p.extend_from_slice(b"/tmp/test.idb\0/tmp/test.bin\0");
    p.extend_from_slice(&[0xAB; 16]);
    p.extend_from_slice(b"testhost\0");
    p.extend(pack_dd(funcs.len() as u32));
    for (name, size, md, ty, hash) in funcs {
        p.extend_from_slice(name.as_bytes());
        p.push(0);
        p.extend(pack_dd(*size));
        p.extend(pack_dd(md.len() as u32));
        p.extend_from_slice(md);
        p.extend(pack_dd(*ty));
        p.extend(pack_dd(hash.len() as u32));
        p.extend_from_slice(hash);
    }
    p.extend(pack_dd(eas.len() as u32));
    for ea in eas {
        p.extend(pack_ea64(*ea));
    }
    p
}

fn hist_payload(patterns: &[[u8; 16]], flags: u32) -> Vec<u8> {
    let mut p = pack_dd(patterns.len() as u32);
    for h in patterns {
        p.extend(pack_dd(PAT_TYPE_MD5));
        p.extend(pack_dd(16));
        p.extend_from_slice(h);
    }
    p.extend(pack_dd(flags));
    p
}

fn del_payload(flags: u32, hashes: &[[u8; 16]]) -> Vec<u8> {
    let mut p = pack_dd(flags);
    for _ in 0..8 {
        p.extend(pack_dd(0)); // license_id, time_ranges, history_id_ranges, idbs, inputs, funcs, usernames, input_hashes
    }
    p.extend(pack_dd(hashes.len() as u32));
    for h in hashes {
        p.extend_from_slice(h);
    }
    p.extend(pack_dd(0)); // push_id_ranges
    p.extend(pack_dd(0));
    p.extend(pack_dd(0)); // max_entries (dq)
    p
}

fn fcmt_metadata(text: &str) -> Vec<u8> {
    let mut md = pack_dd(3);
    let bytes = text.as_bytes();
    md.extend(pack_dd(bytes.len() as u32));
    md.extend_from_slice(bytes);
    md
}

// ---------------------------------------------------------------------------
// 1. Captured requests parse to the values the reference decoded.
// ---------------------------------------------------------------------------

#[test]
fn captured_push_request_parses() {
    let msg = parse_lumina_push_metadata(&hex(V4_PUSH_REQ), LuminaCaps::default()).unwrap();
    assert_eq!(msg.flags, 0);
    assert_eq!(msg.idb_path, "/work/medium_elf.idb");
    assert_eq!(msg.file_path, "/work/pc_dwarfdump.elf");
    assert_eq!(msg.md5[..4], [0x80, 0xD6, 0xC6, 0x22]);
    assert_eq!(msg.hostname, "workstation");
    assert_eq!(msg.funcs.len(), 1);
    let f = &msg.funcs[0];
    assert_eq!(f.name, "addr_map_create_entry");
    assert_eq!(f.func_len, 0x66);
    assert_eq!(f.func_data.len(), 0xB9);
    assert_eq!(f.pattern_type, PAT_TYPE_MD5);
    assert_eq!(f.hash, V4_HASH);
    assert_eq!(msg.ea64s, vec![0x8049534]);
    assert!(validate_push(&msg).is_ok());
}

#[test]
fn captured_pull_requests_parse() {
    let msg = parse_lumina_pull_metadata(&hex(V4_PULL_REQ), LuminaCaps::default()).unwrap();
    assert_eq!(msg.flags, 1);
    assert!(msg.keys.is_empty());
    assert_eq!(msg.funcs.len(), 1);
    assert_eq!(msg.funcs[0].pattern_type, PAT_TYPE_MD5);
    assert_eq!(msg.funcs[0].mb_hash, V4_HASH);

    let msg = parse_lumina_pull_metadata(&hex(V3_PULL_REQ), LuminaCaps::default()).unwrap();
    assert_eq!(msg.flags, 1);
    assert_eq!(msg.funcs.len(), 39);
    assert!(msg
        .funcs
        .iter()
        .all(|f| f.pattern_type == PAT_TYPE_MD5 && f.mb_hash.len() == 16));
}

#[test]
fn captured_del_history_filters_round_trip() {
    let payload = del_payload(BOPF_LAST_FUNC_RECORD, &[V4_HASH, [7u8; 16]]);
    let f = parse_lumina_del_history(&payload, LuminaCaps::default()).unwrap();
    assert_eq!(f.flags, BOPF_LAST_FUNC_RECORD);
    assert_eq!(f.calcrel_hashes, vec![V4_HASH, [7u8; 16]]);
    assert!(!f.has_unsupported_selectors());
}

// ---------------------------------------------------------------------------
// 2. Builders reproduce the captured server bytes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn builders_match_captured_replies() {
    let mut out = MockStream(Vec::new());
    send_lumina_push_result(&mut out, &[LuminaOpRes::Added.as_u32()])
        .await
        .unwrap();
    assert_eq!(out.0, frame(0x11, &hex(V4_PUSH_RESP)));

    let mut out = MockStream(Vec::new());
    let codes = vec![LuminaOpRes::NotFound.as_u32(); 39];
    send_lumina_pull_result(&mut out, &codes, &[])
        .await
        .unwrap();
    assert_eq!(out.0, frame(0x0f, &hex(V3_PULL_RESP)));

    let mut out = MockStream(Vec::new());
    send_lumina_fail(
        &mut out,
        RPC_FAIL_RESULT,
        "Lumina protocol version not compatible with server",
    )
    .await
    .unwrap();
    assert_eq!(out.0, frame(0x0b, &hex(HELO80_FAIL)));
    let (code, msg) = decode_lumina_fail(&hex(HELO80_FAIL)).unwrap();
    assert_eq!(code, u32::MAX);
    assert_eq!(msg, "Lumina protocol version not compatible with server");
}

// ---------------------------------------------------------------------------
// 3. End-to-end sessions through handle_client.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn captured_push_then_pull_reproduces_reference_bytes() {
    let dir = test_dir("v4_session");
    let cfg = test_config(&dir);
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, hello) = Session::open(cfg, db, &hello_v(6, "guest")).await;
    assert_eq!(hello.0, 0x31, "v6 client expects helo_result");

    let (code, payload) = s.call(0x10, &hex(V4_PUSH_REQ)).await;
    assert_eq!((code, payload), (0x11, hex(V4_PUSH_RESP)));

    // First pull: size 0x66, metadata passthrough, frequency 0 (read before bump).
    let (code, payload) = s.call(0x0e, &hex(V4_PULL_REQ)).await;
    assert_eq!(code, 0x0f);
    assert_eq!(payload, hex(V4_PULL_RESP));

    // Second pull: frequency was bumped to 1 by the first pull.
    let (code, payload) = s.call(0x0e, &hex(V4_PULL_REQ)).await;
    assert_eq!(code, 0x0f);
    let mut expected = hex(V4_PULL_RESP);
    *expected.last_mut().unwrap() = 1;
    assert_eq!(payload, expected);

    // PULL_MD_SEEN_FILE: reported, not bumped.
    let seen = pull_payload(0x02, &[(PAT_TYPE_MD5, &V4_HASH)]);
    let (_, payload) = s.call(0x0e, &seen).await;
    assert_eq!(*payload.last().unwrap(), 2);
    let (_, payload) = s.call(0x0e, &seen).await;
    assert_eq!(*payload.last().unwrap(), 2);

    // Re-pushing the same content answers PDRES_OK, not ADDED.
    let (code, payload) = s.call(0x10, &hex(V4_PUSH_REQ)).await;
    assert_eq!((code, payload), (0x11, vec![0x01, 0x00]));

    s.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn pull_codes_are_positional_with_bad_patterns() {
    let dir = test_dir("pull_codes");
    let cfg = test_config(&dir);
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, _) = Session::open(cfg, db, &hello_v(6, "")).await;
    let (code, _) = s.call(0x10, &hex(V4_PUSH_REQ)).await;
    assert_eq!(code, 0x11);

    let unknown = [0x55u8; 16];
    let short = [0x55u8; 15];
    let req = pull_payload(
        0,
        &[
            (0, &V4_HASH),          // wrong pattern type -> BADPTN
            (PAT_TYPE_MD5, &short), // wrong length -> BADPTN
            (PAT_TYPE_MD5, &unknown),
            (PAT_TYPE_MD5, &V4_HASH),
        ],
    );
    let (code, payload) = s.call(0x0e, &req).await;
    assert_eq!(code, 0x0f);
    let (codes, funcs) = decode_lumina_pull_result(&payload).unwrap();
    assert_eq!(
        codes,
        vec![
            LuminaOpRes::BadPtn.as_u32(),
            LuminaOpRes::BadPtn.as_u32(),
            LuminaOpRes::NotFound.as_u32(),
            LuminaOpRes::Ok.as_u32(),
        ]
    );
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].2, "addr_map_create_entry");
    assert_eq!(funcs[0].1, 0x66, "size field is the declared function size");

    // Over-cap requests are refused, never truncated.
    let (code, _) = s
        .call(0x0e, &pull_payload(0, &[(PAT_TYPE_MD5, &V4_HASH[..]); 5]))
        .await;
    assert_eq!(code, 0x0f);
    s.close().await;

    let dir2 = test_dir("pull_codes_cap");
    let mut cfg = test_config(&dir2);
    cfg.limits.max_pull_items = 2;
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, _) = Session::open(cfg, db, &hello_v(6, "guest")).await;
    let (code, _) = s
        .call(0x0e, &pull_payload(0, &[(PAT_TYPE_MD5, &V4_HASH[..]); 3]))
        .await;
    assert_eq!(code, 0x0b);
    s.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

#[tokio::test]
async fn push_codes_keep_positions_and_validate_request() {
    let dir = test_dir("push_codes");
    let cfg = test_config(&dir);
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, _) = Session::open(cfg, db, &hello_v(6, "guest")).await;

    let md = fcmt_metadata("comment");
    let k1 = [0x11u8; 16];
    let k3 = [0x33u8; 16];
    let bad = [0x22u8; 15];
    let req = push_payload(
        0,
        &[
            ("first_func", 10, &md, PAT_TYPE_MD5, &k1),
            ("bad_pattern", 10, &md, PAT_TYPE_MD5, &bad),
            ("third_func", 10, &md, PAT_TYPE_MD5, &k3),
        ],
        &[0x1000, 0x2000, 0x3000],
    );
    let (code, payload) = s.call(0x10, &req).await;
    assert_eq!(code, 0x11);
    let mut expected = pack_dd(3);
    expected.extend(pack_dd(LuminaOpRes::Added.as_u32()));
    expected.extend(pack_dd(LuminaOpRes::BadPtn.as_u32()));
    expected.extend(pack_dd(LuminaOpRes::Added.as_u32()));
    assert_eq!(payload, expected);

    // Updated content -> PDRES_OK (0), unchanged -> 0.
    let md2 = fcmt_metadata("better comment");
    let req = push_payload(
        0,
        &[
            ("first_func", 10, &md2, PAT_TYPE_MD5, &k1),
            ("third_func", 10, &md, PAT_TYPE_MD5, &k3),
        ],
        &[0x1000, 0x3000],
    );
    let (_, payload) = s.call(0x10, &req).await;
    assert_eq!(payload, vec![0x02, 0x00, 0x00]);

    // PMF_PUSH_DO_NOT_OVERRIDE keeps the stored version.
    let md3 = fcmt_metadata("ignored");
    let req = push_payload(2, &[("first_func", 10, &md3, PAT_TYPE_MD5, &k1)], &[0x1000]);
    let (_, payload) = s.call(0x10, &req).await;
    assert_eq!(payload, vec![0x01, 0x00]);
    let (_, payload) = s.call(0x0e, &pull_payload(0, &[(PAT_TYPE_MD5, &k1)])).await;
    let (_, funcs) = decode_lumina_pull_result(&payload).unwrap();
    assert_eq!(funcs[0].3, md2);
    assert_eq!(funcs[0].1, 10);

    // Whole-request validation failures answer rpc_fail with the reference text.
    let req = push_payload(
        0,
        &[("first_func", 10, &md, PAT_TYPE_MD5, &k1)],
        &[0x1000, 0x2000],
    );
    let (code, payload) = s.call(0x10, &req).await;
    assert_eq!(code, 0x0b);
    assert_eq!(
        decode_lumina_fail(&payload).unwrap().1,
        "Bad addresses count"
    );

    let req = push_payload(0, &[("bad\u{e9}", 10, &md, PAT_TYPE_MD5, &k1)], &[0x1000]);
    let (code, payload) = s.call(0x10, &req).await;
    assert_eq!(code, 0x0b);
    assert_eq!(decode_lumina_fail(&payload).unwrap().1, "Invalid metadata");

    let mut bad_md = pack_dd(12); // MDK_LAST
    bad_md.extend(pack_dd(1));
    bad_md.push(0);
    let req = push_payload(
        0,
        &[("first_func", 10, &bad_md, PAT_TYPE_MD5, &k1)],
        &[0x1000],
    );
    let (code, payload) = s.call(0x10, &req).await;
    assert_eq!(code, 0x0b);
    assert_eq!(decode_lumina_fail(&payload).unwrap().1, "Invalid metadata");

    s.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn histories_index_vector_maps_each_pattern() {
    let dir = test_dir("hist");
    let cfg = test_config(&dir);
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, _) = Session::open(cfg, db, &hello_v(6, "guest")).await;

    let k1 = [0x11u8; 16];
    let k2 = [0x22u8; 16];
    let unknown = [0x33u8; 16];
    let md = fcmt_metadata("v1");
    let req = push_payload(
        0,
        &[
            ("alpha", 8, &md, PAT_TYPE_MD5, &k1),
            ("beta", 8, &md, PAT_TYPE_MD5, &k2),
        ],
        &[0x1000, 0x2000],
    );
    s.call(0x10, &req).await;
    let md2 = fcmt_metadata("v2");
    s.call(
        0x10,
        &push_payload(
            0,
            &[("beta_renamed", 8, &md2, PAT_TYPE_MD5, &k2)],
            &[0x2000],
        ),
    )
    .await;

    let (code, payload) = s
        .call(0x2f, &hist_payload(&[unknown, k2, k1], BOPF_DETAILS))
        .await;
    assert_eq!(code, 0x30);
    // pattern_idx_to_entries_idx = [-1, 0, 1] packed as dd(idx + 1); 2 histories,
    // the first (k2) with 2 entries newest first.
    assert_eq!(&payload[..5], &[0x03, 0x00, 0x01, 0x02, 0x02]);
    assert_eq!(payload[5], 0x02);
    // entry: dq id(0) = 00 00, ea64 BADADDR = 00 00, then the newest name.
    assert_eq!(&payload[6..10], &[0, 0, 0, 0]);
    assert!(payload[10..].starts_with(b"beta_renamed\0"));

    // Without BOPF_DETAILS the metadata bytevec is empty.
    let (_, without) = s.call(0x2f, &hist_payload(&[k1], 0)).await;
    // n_idx, idx, n_hist, n_entries, then dq id (2) + ea64 (2), then the name.
    let name_end = 4 + 4 + "alpha\0".len();
    assert_eq!(&without[..2], &[0x01, 0x01]);
    assert_eq!(without[name_end], 0x00, "empty metadata");
    s.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn del_history_reverts_the_last_change() {
    let dir = test_dir("del");
    let mut cfg = test_config(&dir);
    cfg.lumina.allow_deletes = true;
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, hello) = Session::open(cfg, db, &hello_v(6, "guest")).await;
    assert_eq!(hello.0, 0x31);
    assert_eq!(
        *hello.1.last().unwrap(),
        0x02,
        "UF_CAN_DEL_HISTORY advertised"
    );

    let k = [0x44u8; 16];
    s.call(
        0x10,
        &push_payload(
            0,
            &[("old_name", 8, &fcmt_metadata("a"), PAT_TYPE_MD5, &k)],
            &[0x10],
        ),
    )
    .await;
    s.call(
        0x10,
        &push_payload(
            0,
            &[("new_name", 8, &fcmt_metadata("b"), PAT_TYPE_MD5, &k)],
            &[0x10],
        ),
    )
    .await;

    let (code, payload) = s
        .call(0x18, &del_payload(BOPF_LAST_FUNC_RECORD, &[k]))
        .await;
    assert_eq!((code, payload), (0x19, vec![0x01]));
    let (_, payload) = s.call(0x0e, &pull_payload(0, &[(PAT_TYPE_MD5, &k)])).await;
    let (codes, funcs) = decode_lumina_pull_result(&payload).unwrap();
    assert_eq!(codes, vec![0]);
    assert_eq!(funcs[0].2, "old_name");

    let (code, payload) = s
        .call(0x18, &del_payload(BOPF_LAST_FUNC_RECORD, &[k]))
        .await;
    assert_eq!((code, payload), (0x19, vec![0x01]));
    let (_, payload) = s.call(0x0e, &pull_payload(0, &[(PAT_TYPE_MD5, &k)])).await;
    let (codes, funcs) = decode_lumina_pull_result(&payload).unwrap();
    assert_eq!(codes, vec![LuminaOpRes::NotFound.as_u32()]);
    assert!(funcs.is_empty());

    // Nothing left to delete.
    let (code, payload) = s
        .call(0x18, &del_payload(BOPF_LAST_FUNC_RECORD, &[k]))
        .await;
    assert_eq!((code, payload), (0x19, vec![0x00]));
    s.close().await;

    // Deletes disabled: reference wording, and no UF_CAN_DEL_HISTORY bit.
    let dir2 = test_dir("del_disabled");
    let cfg = test_config(&dir2);
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();
    let (mut s, hello) = Session::open(cfg, db, &hello_v(6, "guest")).await;
    assert_eq!(*hello.1.last().unwrap(), 0x00);
    let (code, payload) = s
        .call(0x18, &del_payload(BOPF_LAST_FUNC_RECORD, &[k]))
        .await;
    assert_eq!(code, 0x0b);
    assert_eq!(decode_lumina_fail(&payload).unwrap().1, "Unknown command");
    s.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

#[tokio::test]
async fn hello_policy_matches_reference() {
    let dir = test_dir("hello");
    let cfg = test_config(&dir);
    let db = Database::open(Arc::new(cfg.clone())).await.unwrap();

    // Newer than PROTOCOL_VERSION: rpc_fail with the reference message.
    let (s, reply) = Session::open(cfg.clone(), db.clone(), &hello_v(7, "guest")).await;
    assert_eq!(reply.0, 0x0b);
    let (code, msg) = decode_lumina_fail(&reply.1).unwrap();
    assert_eq!(code, u32::MAX);
    assert_eq!(msg, "This server doesn't support version 7");
    s.close().await;

    // Empty username (IDA default without user@host) is accepted.
    let (s, reply) = Session::open(cfg.clone(), db.clone(), &hello_v(6, "")).await;
    assert_eq!(reply.0, 0x31);
    s.close().await;

    // Other usernames are refused unless accept_any_username is set.
    let (s, reply) = Session::open(cfg.clone(), db.clone(), &hello_v(6, "alice")).await;
    assert_eq!(reply.0, 0x0b);
    s.close().await;
    let mut open_cfg = cfg.clone();
    open_cfg.lumina.accept_any_username = true;
    let (s, reply) = Session::open(open_cfg, db.clone(), &hello_v(6, "alice")).await;
    assert_eq!(reply.0, 0x31);
    s.close().await;

    // v4 clients get a bare rpc_ok.
    let (s, reply) = Session::open(cfg.clone(), db.clone(), &hello_v(4, "")).await;
    assert_eq!(reply, (0x0a, Vec::new()));
    s.close().await;

    // Malformed hello is answered in Lumina framing.
    let cfg_arc = Arc::new(cfg);
    let (mut client, server_stream) = tokio::io::duplex(1 << 20);
    let budget = Arc::new(Budget::new(cfg_arc.limits.global_inflight_bytes));
    let server = tokio::spawn(handle_client(server_stream, cfg_arc, db, budget));
    write_lumina_packet(&mut client, 0x0d, &[0x06, 0x80])
        .await
        .unwrap();
    let (code, payload) = read_lumina_packet(&mut client, 1 << 20).await.unwrap();
    assert_eq!(code, 0x0b);
    assert_eq!(decode_lumina_fail(&payload).unwrap().1, "invalid hello");
    drop(client);
    let _ = server.await;
    std::fs::remove_dir_all(&dir).unwrap();
}
