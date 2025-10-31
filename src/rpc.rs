use bytes::{BytesMut, BufMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::codec::*;

pub const MSG_HELLO: u8 = 0x01;
pub const MSG_HELLO_OK: u8 = 0x02;
pub const MSG_FAIL: u8 = 0x03;
pub const MSG_OK: u8 = 0x04;
pub const MSG_PULL: u8 = 0x10;
pub const MSG_PULL_OK: u8 = 0x11;
pub const MSG_PUSH: u8 = 0x12;
pub const MSG_PUSH_OK: u8 = 0x13;
pub const MSG_DEL: u8 = 0x14;
pub const MSG_DEL_OK: u8 = 0x15;
pub const MSG_HIST: u8 = 0x16;
pub const MSG_HIST_OK: u8 = 0x17;

#[derive(Debug)]
pub struct HelloReq { pub protocol_version: u32, pub username: String, pub password: String }
#[derive(Debug)]
pub struct HelloOk { pub features: u32 }

pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
    log::debug!("Starting read_frame, max allowed size: {}", max);
    let mut lenbuf = [0u8; 4];
    if let Err(e) = r.read_exact(&mut lenbuf).await {
        log::debug!("Failed to read frame length: {}", e);
        return Err(e);
    }
    // Wire protocol uses big-endian (network byte order) for length prefix
    let len = u32::from_be_bytes(lenbuf) as usize;
    log::debug!("Read frame length: {}", len);
    if len > max {
        log::debug!("Frame length {} exceeds maximum allowed {}", len, max);
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    if let Err(e) = r.read_exact(&mut buf).await {
        log::debug!("Failed to read frame payload: {}", e);
        return Err(e);
    }
    log::debug!("Successfully read frame payload of {} bytes", len);
    Ok(buf)
}

pub async fn write_all<W: AsyncWriteExt + Unpin>(w: &mut W, buf: &[u8]) -> std::io::Result<()> {
    w.write_all(buf).await?;
    w.flush().await
}

pub fn encode_ok() -> BytesMut {
    frame(MSG_OK, &[])
}

pub fn encode_fail(code: u32, msg: &str) -> BytesMut {
    let mut p = BytesMut::with_capacity(4 + 4 + msg.len());
    p.put_u32_le(code);
    put_str(&mut p, msg);
    frame(MSG_FAIL, &p)
}
pub fn encode_hello_ok(features: u32) -> BytesMut {
    let mut p = BytesMut::with_capacity(4);
    p.put_u32_le(features);
    frame(MSG_HELLO_OK, &p)
}
pub fn decode_hello(payload: &[u8]) -> Result<HelloReq, CodecError> {
    let mut p = payload;
    if p.len() < 4 { return Err(CodecError::Short); }
    let pv = u32::from_le_bytes(p[0..4].try_into().unwrap());
    p = &p[4..];
    let user = get_str(&mut p)?;
    let pass = get_str(&mut p)?;
    Ok(HelloReq { protocol_version: pv, username: user, password: pass })
}

pub fn encode_pull_ok(status: &[u32], funcs: &[(u32,u32,String,Vec<u8>)]) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(status.len() as u32);
    for s in status { p.put_u32_le(*s); }
    p.put_u32_le(funcs.len() as u32);
    for (pop,len,name,data) in funcs {
        p.put_u32_le(*pop);
        p.put_u32_le(*len);
        put_str(&mut p, name);
        put_bytes(&mut p, data);
    }
    frame(MSG_PULL_OK, &p)
}

pub fn decode_pull(payload: &[u8]) -> Result<Vec<u128>, CodecError> {
    let mut p = payload;
    if p.len() < 4 { return Err(CodecError::Short); }
    let n = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;
    p = &p[4..];
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(get_u128_le(&mut p)?);
    }
    Ok(v)
}

pub struct PushItem { pub key: u128, pub popularity: u32, pub len_bytes: u32, pub name: String, pub data: Vec<u8> }
pub fn decode_push(payload: &[u8]) -> Result<Vec<PushItem>, CodecError> {
    let mut p = payload;
    if p.len() < 4 { return Err(CodecError::Short); }
    let n = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;
    p = &p[4..];
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let key = get_u128_le(&mut p)?;
        if p.len() < 8 { return Err(CodecError::Short); }
        let popularity = u32::from_le_bytes(p[0..4].try_into().unwrap());
        let len_bytes = u32::from_le_bytes(p[4..8].try_into().unwrap());
        p = &p[8..];
        let name = get_str(&mut p)?;
        let data = get_bytes(&mut p)?;
        v.push(PushItem { key, popularity, len_bytes, name, data });
    }
    Ok(v)
}
pub fn encode_push_ok(status: &[u32]) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(status.len() as u32);
    for s in status { p.put_u32_le(*s); }
    frame(MSG_PUSH_OK, &p)
}

pub fn decode_del(payload: &[u8]) -> Result<Vec<u128>, CodecError> {
    decode_pull(payload)
}
pub fn encode_del_ok(deleted: u32) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(deleted);
    frame(MSG_DEL_OK, &p)
}

pub fn decode_hist(payload: &[u8]) -> Result<(u32, Vec<u128>), CodecError> {
    let mut p = payload;
    if p.len() < 8 { return Err(CodecError::Short); }
    let limit = u32::from_le_bytes(p[0..4].try_into().unwrap());
    let n = u32::from_le_bytes(p[4..8].try_into().unwrap()) as usize;
    p = &p[8..];
    let mut v = Vec::with_capacity(n);
    for _ in 0..n { v.push(get_u128_le(&mut p)?); }
    Ok((limit, v))
}
pub fn encode_hist_ok(status: &[u32], logs: &[Vec<(u64,String,Vec<u8>)>]) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(status.len() as u32);
    for s in status { p.put_u32_le(*s); }
    p.put_u32_le(logs.len() as u32);
    for log in logs {
        p.put_u32_le(log.len() as u32);
        for (ts, name, data) in log {
            p.put_u64_le(*ts);
            put_str(&mut p, name);
            put_bytes(&mut p, data);
        }
    }
    frame(MSG_HIST_OK, &p)
}
