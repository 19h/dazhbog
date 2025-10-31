use bytes::{BufMut, BytesMut};

#[derive(Debug)]
pub enum CodecError { Short, Malformed(&'static str) }

pub fn put_u128_le(dst: &mut BytesMut, v: u128) {
    dst.put_u64_le(v as u64);
    dst.put_u64_le((v >> 64) as u64);
}
pub fn get_u128_le(src: &mut &[u8]) -> Result<u128, CodecError> {
    if src.len() < 16 { return Err(CodecError::Short); }
    let lo = u64::from_le_bytes(src[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(src[8..16].try_into().unwrap());
    *src = &src[16..];
    Ok((hi as u128) << 64 | (lo as u128))
}

pub fn put_str(dst: &mut BytesMut, s: &str) {
    dst.put_u32_le(s.len() as u32);
    dst.extend_from_slice(s.as_bytes());
}
pub fn get_str(src: &mut &[u8]) -> Result<String, CodecError> {
    if src.len() < 4 { return Err(CodecError::Short); }
    let len = u32::from_le_bytes(src[0..4].try_into().unwrap()) as usize;
    *src = &src[4..];
    if src.len() < len { return Err(CodecError::Short); }
    let s = std::str::from_utf8(&src[..len]).map_err(|_| CodecError::Malformed("utf8"))?;
    *src = &src[len..];
    Ok(s.to_string())
}

pub fn put_bytes(dst: &mut BytesMut, b: &[u8]) {
    dst.put_u32_le(b.len() as u32);
    dst.extend_from_slice(b);
}
pub fn get_bytes(src: &mut &[u8]) -> Result<Vec<u8>, CodecError> {
    if src.len() < 4 { return Err(CodecError::Short); }
    let len = u32::from_le_bytes(src[0..4].try_into().unwrap()) as usize;
    *src = &src[4..];
    if src.len() < len { return Err(CodecError::Short); }
    let v = src[..len].to_vec();
    *src = &src[len..];
    Ok(v)
}

pub fn frame(msg_type: u8, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + 1 + payload.len());
    // Wire protocol uses big-endian (network byte order) for length prefix
    buf.put_u32((1 + payload.len()) as u32);
    buf.put_u8(msg_type);
    buf.extend_from_slice(payload);
    buf
}

pub fn split_frame(buf: &[u8]) -> Result<(u8, &[u8]), CodecError> {
    if buf.len() < 5 { return Err(CodecError::Short); }
    // Wire protocol uses big-endian (network byte order) for length prefix
    let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    if buf.len() < 4 + len { return Err(CodecError::Short); }
    let msg_type = buf[4];
    let payload = &buf[5..(4+len)];
    Ok((msg_type, payload))
}
