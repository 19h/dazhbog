use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Minimal frame encoder matching dazhbog's protocol
fn frame(msg_type: u8, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + 1 + payload.len());
    // Wire protocol uses big-endian (network byte order) for length prefix
    buf.put_u32((1 + payload.len()) as u32);
    buf.put_u8(msg_type);
    buf.extend_from_slice(payload);
    buf
}

fn encode_hello(protocol_version: u32, username: &str, password: &str) -> BytesMut {
    let mut p = BytesMut::new();
    p.put_u32_le(protocol_version);
    // username
    p.put_u32_le(username.len() as u32);
    p.extend_from_slice(username.as_bytes());
    // password
    p.put_u32_le(password.len() as u32);
    p.extend_from_slice(password.as_bytes());
    frame(0x01, &p)
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut lenbuf = [0u8; 4];
    r.read_exact(&mut lenbuf).await?;
    // Wire protocol uses big-endian (network byte order) for length prefix
    let len = u32::from_be_bytes(lenbuf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[tokio::test]
async fn test_protocol_v3_handshake() {
    // Ensure server is running on localhost:1234 (adjust as needed)
    let mut stream = match TcpStream::connect("127.0.0.1:1234").await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Server not running on 127.0.0.1:1234, skipping test");
            return;
        }
    };

    // Send HELLO v3
    let hello = encode_hello(3, "guest", "");
    stream.write_all(&hello).await.unwrap();
    stream.flush().await.unwrap();

    // Read response
    let response = read_frame(&mut stream).await.unwrap();
    assert!(!response.is_empty(), "Empty response");
    
    let msg_type = response[0];
    let payload = &response[1..];
    
    // For protocol v3, expect MSG_OK (0x04) with empty payload
    assert_eq!(msg_type, 0x04, "Expected MSG_OK (0x04) for protocol v3");
    assert_eq!(payload.len(), 0, "Expected empty payload for protocol v3");
    
    println!("✓ Protocol v3 handshake successful");
}

#[tokio::test]
async fn test_protocol_v6_handshake() {
    let mut stream = match TcpStream::connect("127.0.0.1:1234").await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Server not running on 127.0.0.1:1234, skipping test");
            return;
        }
    };

    // Send HELLO v6
    let hello = encode_hello(6, "guest", "");
    stream.write_all(&hello).await.unwrap();
    stream.flush().await.unwrap();

    // Read response
    let response = read_frame(&mut stream).await.unwrap();
    assert!(!response.is_empty(), "Empty response");
    
    let msg_type = response[0];
    let payload = &response[1..];
    
    // For protocol v6, expect MSG_HELLO_OK (0x02) with u32 features
    assert_eq!(msg_type, 0x02, "Expected MSG_HELLO_OK (0x02) for protocol v6");
    assert_eq!(payload.len(), 4, "Expected 4-byte features payload for protocol v6");
    
    let features = u32::from_le_bytes(payload.try_into().unwrap());
    println!("✓ Protocol v6 handshake successful, features: 0x{:08x}", features);
}

#[tokio::test]
async fn test_pull_nonexistent_key() {
    let mut stream = match TcpStream::connect("127.0.0.1:1234").await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Server not running on 127.0.0.1:1234, skipping test");
            return;
        }
    };

    // Handshake first (v5)
    let hello = encode_hello(5, "guest", "");
    stream.write_all(&hello).await.unwrap();
    let _response = read_frame(&mut stream).await.unwrap();

    // Send PULL request for non-existent key
    let mut pull_payload = BytesMut::new();
    pull_payload.put_u32_le(1); // 1 key
    pull_payload.put_u64_le(0xDEADBEEF); // key low
    pull_payload.put_u64_le(0xCAFEBABE); // key high
    
    let pull_frame = frame(0x10, &pull_payload);
    stream.write_all(&pull_frame).await.unwrap();
    stream.flush().await.unwrap();

    // Read PULL_OK response
    let response = read_frame(&mut stream).await.unwrap();
    assert!(!response.is_empty(), "Empty response");
    
    let msg_type = response[0];
    assert_eq!(msg_type, 0x11, "Expected MSG_PULL_OK (0x11)");
    
    let payload = &response[1..];
    assert!(payload.len() >= 8, "Payload too short");
    
    let n_status = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    assert_eq!(n_status, 1, "Expected 1 status entry");
    
    let status = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    assert_eq!(status, 1, "Expected status=1 (not found)");
    
    println!("✓ PULL for non-existent key correctly returned status=1");
}
