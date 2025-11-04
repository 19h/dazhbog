//! Boundary condition and edge case testing for dazhbog server
//!
//! This module tests various edge cases and boundary conditions that could
//! reveal security issues or robustness problems.

use std::time::Duration;
use tokio::time::timeout;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::{Rng, RngCore};

async fn connect_to_server() -> Option<TcpStream> {
    match timeout(Duration::from_secs(1), TcpStream::connect("127.0.0.1:20667")).await {
        Ok(Ok(stream)) => Some(stream),
        _ => {
            eprintln!("Server not running on 127.0.0.1:20667, skipping boundary tests");
            None
        }
    }
}

fn encode_hello(protocol_version: u32, username: &str, password: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&protocol_version.to_le_bytes());
    // username
    p.extend_from_slice(&(username.len() as u32).to_le_bytes());
    p.extend_from_slice(username.as_bytes());
    // password
    p.extend_from_slice(&(password.len() as u32).to_le_bytes());
    p.extend_from_slice(password.as_bytes());

    let mut frame = Vec::new();
    frame.extend_from_slice(&((1 + p.len()) as u32).to_be_bytes()); // Length
    frame.push(0x01); // Message type (HELLO)
    frame.extend_from_slice(&p);
    frame
}

async fn read_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    timeout_ms: u64,
) -> std::io::Result<usize> {
    match timeout(Duration::from_millis(timeout_ms), reader.read(buf)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout")),
    }
}

fn raw_frame(len_field: u32, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 1 + payload.len());
    buf.extend_from_slice(&len_field.to_be_bytes()); // Length field
    buf.push(msg_type);
    buf.extend_from_slice(payload);
    buf
}

#[tokio::test]
async fn test_numeric_boundaries() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Create long strings with proper lifetimes
    let single_char_username = "A".repeat(1);
    let max_username = "A".repeat(u16::MAX as usize);
    let max_password = "B".repeat(u16::MAX as usize);

    // Test various numeric boundary conditions
    let boundary_tests = vec![
        // Protocol version boundaries
        (0u32, "guest", "", "Protocol version 0"),
        (1u32, "guest", "", "Protocol version 1 (very old)"),
        (u32::MAX, "guest", "", "Maximum protocol version"),
        // Username/password length boundaries
        (5u32, "", "", "Empty username/password"),
        (5u32, &single_char_username, "", "1-character username"),
        (5u32, &max_username, "", "Maximum username length"),
        (5u32, "", &max_password, "Maximum password length"),
        // Special protocol versions
        (0xFFFFFFFF, "guest", "", "All bits set in version"),
        (0x80000000, "guest", "", "High bit set in version"),
    ];

    for (version, username, password, description) in boundary_tests {
        println!("Testing numeric boundary: {}", description);

        let hello = encode_hello(version, username, password);
        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&hello)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = vec![0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 1000).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out");
            }
        }
    }
}

#[tokio::test]
async fn test_unicode_and_encoding_edges() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Create strings with proper lifetimes
    let high_unicode = format!("High Unicode: {}", '\u{10FFFF}');

    // Test various Unicode and encoding edge cases
    let encoding_tests = vec![
        // Unicode characters
        ("test", "Unicode: 🚀", "Unicode emoji"),
        ("test", "Unicode: 中文", "Unicode Chinese"),
        ("test", "Unicode: русский", "Unicode Russian"),
        ("test", "Unicode: 🔥💯", "Unicode symbols"),
        // Control characters
        ("test", "Control: \x00\x01\x02", "Control characters in password"),
        ("Control: \n\r\t", "test", "Control characters in username"),
        // High Unicode codepoints
        ("test", &high_unicode, "Highest Unicode codepoint"),
        // Mixed encodings (invalid UTF-8 would be handled by Rust's UTF-8 validation)
        ("test", "Valid UTF-8: café", "Valid UTF-8"),
    ];

    for (username, password, description) in encoding_tests {
        println!("Testing encoding: {}", description);

        let hello = encode_hello(5, username, password);
        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&hello)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = vec![0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 1000).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out");
            }
        }
    }
}

#[tokio::test]
async fn test_frame_size_edge_cases() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    let mut rng = rand::thread_rng();

    // Test various frame size edge cases
    let frame_size_tests = vec![
        // Zero length frame
        (0u32, 0x01, vec![], "Zero length frame"),
        // Very small frames
        (1u32, 0x01, vec![], "Minimum frame length"),
        (2u32, 0x01, vec![0x00], "Frame with 1 byte data"),
        // Boundary size frames
        (4u32, 0x01, vec![0x00, 0x00, 0x00], "4-byte frame boundary"),
        (5u32, 0x01, vec![0x00, 0x00, 0x00, 0x00], "5-byte frame boundary"),
        // Large but valid frames
        (1000u32, 0x01, vec![0xAA; 999], "Large valid frame"),
        // Random size frames
        {
            let size = rng.gen_range(1..1000);
            (size, 0x01, vec![0xBB; size as usize - 1], "Random size frame")
        },
    ];

    for (len_field, msg_type, payload, description) in frame_size_tests {
        println!("Testing frame size: {} (len={}, type=0x{:02x}, payload={})",
                description, len_field, msg_type, payload.len());

        let frame = raw_frame(len_field, msg_type, &payload);
        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = vec![0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 1000).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out");
            }
        }
    }
}

#[tokio::test]
async fn test_timing_and_race_conditions() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test timing-related edge cases
    println!("Testing timing and potential race conditions...");

    // Rapid fire multiple messages
    for i in 0..50 {
        let hello = encode_hello(5, "guest", "");
        let write_result = timeout(
            Duration::from_millis(10), // Very short timeout
            stream.write_all(&hello)
        ).await;

        if write_result.is_err() {
            println!("  Write {} failed due to timeout", i);
            break;
        }

        // Try to read immediately without waiting
        let mut buf = [0u8; 64];
        let _ = read_with_timeout(&mut stream, &mut buf, 5).await;

        // No delay - fire next message immediately
    }

    println!("Timing test completed");
}

#[tokio::test]
async fn test_state_machine_edges() {
    // Test state machine edge cases by sending messages out of order
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    let state_tests = vec![
        // Send multiple hellos
        vec![
            raw_frame(10, 0x01, b"hello1"),
            raw_frame(10, 0x01, b"hello2"),
            raw_frame(10, 0x01, b"hello3"),
        ],
        // Send commands before hello
        vec![
            raw_frame(10, 0x10, b"pull"),
            raw_frame(10, 0x20, b"push"),
            raw_frame(10, 0x01, b"hello"), // Hello last
        ],
        // Mixed message types
        vec![
            raw_frame(5, 0x01, b"hi"),
            raw_frame(5, 0xFF, b"invalid"),
            raw_frame(5, 0x00, b"zero"),
            raw_frame(5, 0x01, b"hi2"),
        ],
        // Very rapid state changes
        {
            let mut messages = vec![];
            for i in 0..20 {
                let msg_type = (i % 5) + 1; // Cycle through message types
                messages.push(raw_frame(5, msg_type, &[i as u8]));
            }
            messages
        },
    ];

    for (test_id, messages) in state_tests.into_iter().enumerate() {
        println!("Testing state machine edges: test {}", test_id);

        for message in messages {
            let write_result = timeout(
                Duration::from_millis(200),
                stream.write_all(&message)
            ).await;

            match write_result {
                Ok(Ok(_)) => {
                    let mut buf = [0u8; 256];
                    let _ = read_with_timeout(&mut stream, &mut buf, 200).await;
                }
                Ok(Err(e)) => {
                    println!("  Write failed: {:?}", e);
                    break;
                }
                Err(_) => {
                    println!("  Write timed out");
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn test_resource_exhaustion_edges() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test resource exhaustion at boundaries
    let exhaustion_tests = vec![
        // Maximum connections would be tested separately
        // Here we test per-connection resource limits
        ("Many small messages", (0..1000).map(|i| raw_frame(5, 0x01, &[i as u8])).collect()),
        ("Alternating large/small", vec![
            raw_frame(1000, 0x01, &vec![0xAA; 999]),
            raw_frame(5, 0x01, &[0xBB]),
            raw_frame(1000, 0x01, &vec![0xCC; 999]),
            raw_frame(5, 0x01, &[0xDD]),
        ]),
        ("Maximum message size boundary", vec![
            raw_frame(65535, 0x01, &vec![0xFF; 65534]), // Near max u16
        ]),
    ];

    for (description, messages) in exhaustion_tests {
        println!("Testing resource exhaustion: {}", description);

        for message in messages {
            let write_result = timeout(
                Duration::from_millis(500),
                stream.write_all(&message)
            ).await;

            match write_result {
                Ok(Ok(_)) => {
                    let mut buf = vec![0u8; 1024];
                    let _ = read_with_timeout(&mut stream, &mut buf, 500).await;
                }
                Ok(Err(e)) => {
                    println!("  Write failed: {:?}", e);
                    break;
                }
                Err(_) => {
                    println!("  Write timed out");
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn test_endianness_and_byte_order() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test byte order edge cases
    let endian_tests = vec![
        // Wrong endianness in length field
        {
            let mut frame = Vec::new();
            frame.extend_from_slice(&10u32.to_le_bytes()); // Wrong endianness
            frame.push(0x01);
            frame.extend_from_slice(b"test");
            frame
        },
        // Mixed endianness
        {
            let mut frame = Vec::new();
            frame.extend_from_slice(&10u16.to_be_bytes()); // Partial wrong endianness
            frame.extend_from_slice(&20u16.to_le_bytes());
            frame.push(0x01);
            frame.extend_from_slice(b"mixed");
            frame
        },
        // Byte order in payload
        encode_hello(u32::from_le_bytes([0xFF, 0x00, 0x00, 0x00]), "test", "pass"), // Little endian version
        encode_hello(u32::from_be_bytes([0x00, 0x00, 0x00, 0xFF]), "test", "pass"), // Big endian version
    ];

    for (test_id, message) in endian_tests.into_iter().enumerate() {
        println!("Testing endianness: test {}", test_id);

        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&message)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = vec![0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 1000).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out");
            }
        }
    }
}

#[tokio::test]
async fn test_memory_alignment_and_layout() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test messages that might reveal memory layout issues
    let layout_tests = vec![
        // Messages sized to test alignment
        raw_frame(8, 0x01, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]), // 8-byte aligned
        raw_frame(16, 0x01, &vec![0x10; 15]), // 16-byte aligned
        raw_frame(32, 0x01, &vec![0x20; 31]), // 32-byte aligned
        raw_frame(64, 0x01, &vec![0x40; 63]), // 64-byte aligned
        // Messages with specific patterns that might cause issues
        raw_frame(13, 0x01, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0x00, 0xFF]), // Magic values
        raw_frame(7, 0x01, &[0x00; 6]), // All zeros
        raw_frame(9, 0x01, &[0xFF; 8]), // All ones
    ];

    for (test_id, message) in layout_tests.into_iter().enumerate() {
        println!("Testing memory layout: test {} (size: {})", test_id, message.len());

        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&message)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = vec![0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 1000).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out");
            }
        }
    }
}

#[tokio::test]
async fn test_error_recovery_and_robustness() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test error recovery by sending invalid data followed by valid data
    let recovery_tests = vec![
        // Invalid data followed by valid hello
        vec![
            raw_frame(u32::MAX, 0xFF, &vec![0xFF; 1000]), // Completely invalid
            encode_hello(5, "guest", ""), // Valid hello
        ],
        // Partial messages followed by complete ones
        vec![
            vec![0x00, 0x00, 0x00], // Partial length field
            encode_hello(5, "guest", ""), // Complete message
        ],
        // Corrupted messages mixed with valid ones
        vec![
            raw_frame(10, 0x01, b"corrupted"), // Corrupted hello
            encode_hello(5, "guest", ""), // Valid hello
            raw_frame(5, 0x10, &[0x00]), // Valid pull request
        ],
    ];

    for (test_id, message_sequence) in recovery_tests.into_iter().enumerate() {
        println!("Testing error recovery: test {}", test_id);

        for message in message_sequence {
            let write_result = timeout(
                Duration::from_millis(1000),
                stream.write_all(&message)
            ).await;

            match write_result {
                Ok(Ok(_)) => {
                    let mut buf = vec![0u8; 1024];
                    let _ = read_with_timeout(&mut stream, &mut buf, 1000).await;
                }
                Ok(Err(e)) => {
                    println!("  Write failed: {:?}", e);
                }
                Err(_) => {
                    println!("  Write timed out");
                }
            }
        }
    }
}
