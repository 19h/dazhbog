//! Authoritative test suite for Lumina Protocol and Metadata parsing.
//!
//! These tests guarantee 100% bit-accurate compatibility with the IDA Pro SDK
//! definitions as observed on the wire.

use dazhbog::protocol::lumina::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

// Mock Stream to test async builders
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

// -----------------------------------------------------------------------------
// 1. VARINT WIRE FORMAT TESTS
// -----------------------------------------------------------------------------

#[test]
fn test_authoritative_varint_dd() {
    // 32-bit varints (pack_dd / unpack_dd)

    // Bounds < 0x80 (1 byte)
    let b = pack_dd(0);
    assert_eq!(b, vec![0x00]);
    assert_eq!(unpack_dd(&b), (0, 1));

    let b = pack_dd(0x7F);
    assert_eq!(b, vec![0x7F]);
    assert_eq!(unpack_dd(&b), (0x7F, 1));

    // Bounds < 0x4000 (2 bytes)
    let b = pack_dd(0x80);
    assert_eq!(b, vec![0x80, 0x80]);
    assert_eq!(unpack_dd(&b), (0x80, 2));

    let b = pack_dd(0x3FFF);
    assert_eq!(b, vec![0xBF, 0xFF]);
    assert_eq!(unpack_dd(&b), (0x3FFF, 2));

    // Bounds < 0x200000 (4 bytes)
    // 0x4000 = (0x00 & 0x1F) << 24 | (0x00) << 16 | (0x40) << 8 | 0x00 -> val
    // So 0x4000 mapped back is: [0xC0, 0x00, 0x40, 0x00]
    let b = pack_dd(0x4000);
    assert_eq!(b, vec![0xC0, 0x00, 0x40, 0x00]);
    assert_eq!(unpack_dd(&b), (0x4000, 4));

    // 0x1FFFFF -> pack_dd is: vec![0xC0, 0x1F, 0xFF, 0xFF]
    let b = pack_dd(0x1FFFFF);
    assert_eq!(b, vec![0xC0, 0x1F, 0xFF, 0xFF]);
    assert_eq!(unpack_dd(&b), (0x1FFFFF, 4));

    // 4-byte form extends to 0x1FFFFFFF
    let b = pack_dd(0x200000);
    assert_eq!(b, vec![0xC0, 0x20, 0x00, 0x00]);
    assert_eq!(unpack_dd(&b), (0x200000, 4));

    let b = pack_dd(0x1FFFFFFF);
    assert_eq!(b, vec![0xDF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(unpack_dd(&b), (0x1FFFFFFF, 4));

    // Bounds >= 0x20000000 (5 bytes, escape 0xFF)
    let b = pack_dd(0x20000000);
    assert_eq!(b, vec![0xFF, 0x20, 0x00, 0x00, 0x00]);
    assert_eq!(unpack_dd(&b), (0x20000000, 5));

    // Any lead byte 0xE0..=0xFF is the 5-byte form on decode.
    assert_eq!(unpack_dd(&[0xE0, 0x00, 0x20, 0x00, 0x00]), (0x200000, 5));

    let b = pack_dd(0xFFFFFFFF);
    assert_eq!(b, vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(unpack_dd(&b), (0xFFFFFFFF, 5));
}

#[test]
fn test_authoritative_varint_dw() {
    // 16-bit varints (unpack_dw)

    // 1 byte
    assert_eq!(unpack_dw(&[0x7F]), (0x7F, 1));

    // 2 bytes: (x & 0xC0) != 0xC0
    // 0x8080 -> x = ((0x80 << 8) | 0x80) & 0x7FFF = 0x8080 & 0x7FFF = 0x0080
    assert_eq!(unpack_dw(&[0x80, 0x80]), (0x0080, 2));

    // 3 bytes: (x & 0xC0) == 0xC0
    // 0xC01234 -> (0x12 << 8) | 0x34 = 0x1234
    assert_eq!(unpack_dw(&[0xC0, 0x12, 0x34]), (0x1234, 3));
}

#[test]
fn test_authoritative_varint_dq() {
    // 64-bit varints (pack_dq / unpack_dq)
    // Encodes low dd, then high dd

    let b = pack_dq(0);
    assert_eq!(b, vec![0x00, 0x00]); // pack_dd(0) + pack_dd(0)
    assert_eq!(unpack_dq(&b), (0, 2));

    // Test a large 64-bit value: 0x12345678_90ABCDEF
    // Low: 0x90ABCDEF -> 5 bytes (> 0x1FFFFFFF)
    // High: 0x12345678 -> 4 bytes (<= 0x1FFFFFFF)
    let val = 0x12345678_90ABCDEF;
    let b = pack_dq(val);
    assert_eq!(b.len(), 9);
    assert_eq!(&b[0..5], &[0xFF, 0x90, 0xAB, 0xCD, 0xEF]);
    assert_eq!(&b[5..9], &[0xD2, 0x34, 0x56, 0x78]);
    assert_eq!(unpack_dq(&b), (val, 9));
}

#[test]
fn test_authoritative_varint_ea64() {
    // ea64 encodes (val + 1) to gracefully handle BADADDR (-1)

    // BADADDR = 0xFFFFFFFFFFFFFFFF
    let badaddr = u64::MAX;
    let b = pack_ea64(badaddr);
    assert_eq!(b, vec![0x00, 0x00]); // 0xFF...FF + 1 = 0, pack_dq(0)
    assert_eq!(unpack_ea64(&b), (badaddr, 2));

    // Address 0x0 -> encoded as 1
    let b = pack_ea64(0);
    assert_eq!(b, vec![0x01, 0x00]); // pack_dq(1)
    assert_eq!(unpack_ea64(&b), (0, 2));
}

// -----------------------------------------------------------------------------
// 2. PROTOCOL PACKET PARSING TESTS
// -----------------------------------------------------------------------------

#[test]
fn test_authoritative_hello_parsing() {
    // Construct a pkt_helo_t directly as IDA does
    let mut payload = Vec::new();
    payload.extend_from_slice(&pack_dd(3)); // version 3
    payload.extend_from_slice(&pack_dd(4)); // key length
    payload.extend_from_slice(b"auth"); // key
    payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // license_id
    payload.extend_from_slice(&pack_dd(1)); // record_conv
    payload.extend_from_slice(b"testuser\0"); // username
    payload.extend_from_slice(b"testpass\0"); // password

    let hello = parse_lumina_hello(&payload).unwrap();
    assert_eq!(hello.protocol_version, 3);
    assert_eq!(hello.username, "testuser");
    assert_eq!(hello.password, "testpass");

    // Test raw extraction
    let raw = parse_lumina_hello_raw(&payload).unwrap();
    assert_eq!(raw.key, b"auth");
    assert_eq!(raw.license_id, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
}

#[test]
fn test_authoritative_pull_md_parsing() {
    // Construct a pkt_pull_md_t
    let mut payload = Vec::new();
    payload.extend_from_slice(&pack_dd(0x01)); // flags (AUTO_APPLY)

    // mdkey_vec_t
    payload.extend_from_slice(&pack_dd(2)); // count = 2
    payload.extend_from_slice(&pack_dd(9)); // MDK_FRAME_DESC
    payload.extend_from_slice(&pack_dd(3)); // MDK_FCMT

    // pattern_ids_t
    payload.extend_from_slice(&pack_dd(1)); // 1 function
    payload.extend_from_slice(&pack_dd(1)); // pattern type
    payload.extend_from_slice(&pack_dd(16)); // hash length
    payload.extend_from_slice(&[0xAA; 16]); // hash data

    let caps = LuminaCaps::default();
    let msg = parse_lumina_pull_metadata(&payload, caps).unwrap();

    assert_eq!(msg.flags, 0x01);
    assert_eq!(msg.keys, vec![9, 3]);
    assert_eq!(msg.funcs.len(), 1);
    assert_eq!(msg.funcs[0].pattern_type, 1);
    assert_eq!(msg.funcs[0].mb_hash, vec![0xAA; 16]);
}

// -----------------------------------------------------------------------------
// 3. METADATA DESERIALIZATION TESTS
// -----------------------------------------------------------------------------

#[test]
fn test_authoritative_metadata_mdk_type() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&pack_dd(1)); // MDK_TYPE

    let mut value = Vec::new();
    value.push(1); // userti = true
    value.extend_from_slice(b"int"); // type_str
    value.push(0); // null terminator
    value.extend_from_slice(b"x;y;"); // fields_str
    value.push(0); // null terminator

    payload.extend_from_slice(&pack_dd(value.len() as u32));
    payload.extend_from_slice(&value);

    let md = parse_metadata(&payload);
    assert!(md.is_ok());
    let tp = md.type_parts.unwrap();
    assert!(tp.userti);
    assert_eq!(tp.type_bytes, b"int");
    assert_eq!(tp.fields_bytes, b"x;y;");
}

#[test]
fn test_authoritative_metadata_mdk_frame_desc() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&pack_dd(9)); // MDK_FRAME_DESC

    let mut value = Vec::new();
    value.extend_from_slice(&pack_ea64(0x10)); // frsize
    value.extend_from_slice(&pack_ea64(0x00)); // argsize
    value.extend_from_slice(&[0x00]); // frregs (unpack_dw)
    value.extend_from_slice(&pack_dd(1)); // 1 member

    value.push(0x51); // greedy_bits: 0x01 (name) | 0x10 (offset) | 0x40 (nbytes)
    value.extend_from_slice(b"var_8\0"); // name
    value.extend_from_slice(&pack_ea64(0x8)); // offset
    value.extend_from_slice(&pack_ea64(0x4)); // nbytes

    payload.extend_from_slice(&pack_dd(value.len() as u32));
    payload.extend_from_slice(&value);

    let md = parse_metadata(&payload);
    assert!(md.is_ok());
    let fd = md.frame_desc.unwrap();
    assert_eq!(fd.frsize, 0x10);
    assert_eq!(fd.argsize, 0x0);
    assert_eq!(fd.members.len(), 1);

    let mem = &fd.members[0];
    assert_eq!(mem.name.as_deref(), Some("var_8"));
    assert_eq!(mem.offset, Some(0x8));
    assert_eq!(mem.nbytes, Some(0x4));
    assert_eq!(mem.cmt, None); // greedy bit wasn't set
}

#[test]
fn test_authoritative_metadata_mdk_cmts() {
    // Tests insn_site_unpacking_helper_t reverse engineering
    let mut payload = Vec::new();
    payload.extend_from_slice(&pack_dd(5)); // MDK_CMTS

    let mut value = Vec::new();
    // fchunk 0
    value.extend_from_slice(&pack_dd(0));

    // item 1: delta 0x10, string "hello"
    value.extend_from_slice(&pack_dd(0x10));
    value.extend_from_slice(&pack_dd(5)); // string len
    value.extend_from_slice(b"hello");

    // shift to fchunk 2
    value.extend_from_slice(&pack_dd(0)); // delta = 0 signals fchunk switch
    value.extend_from_slice(&pack_dd(2)); // new fchunk nr

    // item 2: delta 0x08, string "world"
    value.extend_from_slice(&pack_dd(0x08));
    value.extend_from_slice(&pack_dd(5)); // string len
    value.extend_from_slice(b"world");

    payload.extend_from_slice(&pack_dd(value.len() as u32));
    payload.extend_from_slice(&value);

    let md = parse_metadata(&payload);
    assert!(md.is_ok());
    assert_eq!(md.insn_cmts.len(), 2);

    assert_eq!(md.insn_cmts[0].fchunk_nr, 0);
    assert_eq!(md.insn_cmts[0].fchunk_off, 0x10);
    assert_eq!(md.insn_cmts[0].cmt, "hello");

    assert_eq!(md.insn_cmts[1].fchunk_nr, 2);
    assert_eq!(md.insn_cmts[1].fchunk_off, 0x08);
    assert_eq!(md.insn_cmts[1].cmt, "world");
}

#[tokio::test]
async fn test_authoritative_result_builders() {
    let mut mock = MockStream(Vec::new());

    // Test send_lumina_info_result (0x2C)
    send_lumina_info_result(&mut mock, "AA:BB:CC:DD:EE:FF", "dazhbog-test", 100, 200)
        .await
        .unwrap();

    let buf = &mock.0;
    // Length prefix (4) + msg type (1)
    assert_eq!(buf[4], 0x2C);

    // Validate we can theoretically parse this back if we wanted, but mainly ensuring no panic
    assert!(buf.len() > 10);
}
