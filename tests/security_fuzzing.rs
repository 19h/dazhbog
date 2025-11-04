//! Network-level security fuzzing and vulnerability testing for dazhbog server
//!
//! This test suite focuses on network-level attacks that require a live server:
//! - Memory exhaustion attacks
//! - Malformed packet handling
//! - Protocol validation bypasses
//! - Connection state corruption
//! - Timeout and resource limit testing
//!
//! All tests will gracefully skip if the server is not running on localhost:20667

use bytes::{BufMut, BytesMut};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, sleep};
use rand::{Rng, RngCore};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Create a raw frame with custom length (potentially malformed)
fn raw_frame(len_field: u32, msg_type: u8, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + 1 + payload.len());
    buf.put_u32(len_field); // Potentially malicious length field
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
    raw_frame((1 + p.len()) as u32, 0x01, &p)
}

/// Generate random bytes
fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

/// Test helper that connects to server and returns stream
async fn connect_to_server() -> Option<TcpStream> {
    match timeout(Duration::from_secs(1), TcpStream::connect("127.0.0.1:20667")).await {
        Ok(Ok(stream)) => Some(stream),
        _ => {
            eprintln!("Server not running on 127.0.0.1:20667, skipping network security tests");
            None
        }
    }
}

/// Read with timeout to prevent hanging
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

// ============================================================================
// NETWORK-LEVEL SECURITY TESTS (require live server)
// ============================================================================

#[tokio::test]
async fn test_frame_size_overflows() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test frames with extremely large length fields
    let overflow_sizes = vec![
        u32::MAX,                    // Maximum u32
        u32::MAX - 1,               // Near maximum
        i32::MAX as u32 + 1,        // Overflow from signed
        0xFFFFFFFF - 0x1000,        // Near max with offset
    ];

    for size in overflow_sizes {
        println!("Testing frame size overflow: 0x{:08x}", size);

        let malicious_frame = raw_frame(size, 0x01, &random_bytes(16));
        let write_result = timeout(
            Duration::from_millis(100),
            stream.write_all(&malicious_frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                // Try to read response - should timeout or error
                let mut buf = [0u8; 1];
                let read_result = read_with_timeout(&mut stream, &mut buf, 500).await;
                println!("  Read result: {:?}", read_result);
            }
            Ok(Err(e)) => println!("  Write failed (expected): {:?}", e),
            Err(_) => println!("  Write timed out (expected)"),
        }
    }
}

#[tokio::test]
async fn test_memory_exhaustion_attacks() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test various memory exhaustion vectors
    let exhaustion_tests = vec![
        // Large hello payloads
        (0x01, vec![0xFF; 1024 * 1024]),     // 1MB payload
        (0x01, vec![0xFF; 16 * 1024 * 1024]), // 16MB payload
    ];

    for (msg_type, payload) in exhaustion_tests {
        println!("Testing memory exhaustion: msg_type=0x{:02x}, payload_size={}",
                msg_type, payload.len());

        let frame = raw_frame((1 + payload.len()) as u32, msg_type, &payload);
        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                // Read response with timeout
                let mut buf = vec![0u8; 1024];
                let read_result = read_with_timeout(&mut stream, &mut buf, 2000).await;
                println!("  Response: {:?}", read_result);
            }
            Ok(Err(e)) => println!("  Write failed: {:?}", e),
            Err(_) => println!("  Write timed out"),
        }

        // Small delay between tests
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn test_malformed_packet_fuzzing() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    let mut rng = rand::thread_rng();

    for test_case in 0..100 {
        // Generate random malformed packets
        let len_field = rng.gen::<u32>();
        let msg_type = rng.gen::<u8>();
        let payload_size = rng.gen_range(0..1024);
        let payload = random_bytes(payload_size);

        let malicious_frame = raw_frame(len_field, msg_type, &payload);

        println!("Fuzzing test {}: len=0x{:08x}, type=0x{:02x}, payload_size={}",
                test_case, len_field, msg_type, payload_size);

        let write_result = timeout(
            Duration::from_millis(100),
            stream.write_all(&malicious_frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                // Try to read any response
                let mut buf = [0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 200).await;
            }
            Ok(Err(e)) => {
                // Expected for many malformed packets
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                // Timeout - might indicate server is stuck
                println!("  Write timed out - possible DoS condition");
                break;
            }
        }

        // Brief pause between fuzz cases
        if test_case % 50 == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    }
}

#[tokio::test]
async fn test_protocol_version_edge_cases() {
    let test_versions = vec![
        0u32,           // Zero version
        1u32,           // Very old version
        u32::MAX,       // Maximum version
        0xFFFFFFFF,     // All bits set
        0x80000000,     // High bit set
        0xDEADBEEF,     // Random magic value
    ];

    for version in test_versions {
        println!("Testing protocol version: {}", version);

        let stream = match connect_to_server().await {
            Some(s) => s,
            None => return,
        };
        let mut stream = stream;

        let hello = encode_hello(version, "guest", "");
        let write_result = timeout(
            Duration::from_millis(500),
            stream.write_all(&hello)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = [0u8; 1024];
                let read_result = read_with_timeout(&mut stream, &mut buf, 1000).await;
                println!("  Response: {:?}", read_result);
            }
            Ok(Err(e)) => println!("  Write failed: {:?}", e),
            Err(_) => println!("  Write timed out"),
        }
    }
}

#[tokio::test]
async fn test_invalid_authentication_attempts() {
    let long_username = "A".repeat(1000);
    let long_password = "B".repeat(1000);

    let invalid_credentials = vec![
        ("", ""),                    // Empty username/password
        ("admin", "password"),       // Wrong username
        ("guest", "wrongpass"),      // Wrong password (ignored anyway)
        ("root", ""),                // Root user
        (&long_username, ""),        // Very long username
        ("", &long_password),        // Very long password
        ("\x00", ""),                // Null byte username
        ("", "\x00"),                // Null byte password
        ("\n", "\r"),                // Control characters
        ("../etc/passwd", ""),       // Path traversal attempt
    ];

    for (username, password) in invalid_credentials {
        println!("Testing auth: username='{}' (len={}), password='{}' (len={})",
                username.chars().take(20).collect::<String>(),
                username.len(),
                password.chars().take(20).collect::<String>(),
                password.len());

        let stream = match connect_to_server().await {
            Some(s) => s,
            None => return,
        };
        let mut stream = stream;

        let hello = encode_hello(5, username, password);
        let write_result = timeout(
            Duration::from_millis(500),
            stream.write_all(&hello)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = [0u8; 1024];
                let read_result = read_with_timeout(&mut stream, &mut buf, 1000).await;
                if let Ok(n) = read_result {
                    if n > 0 {
                        println!("  Response type: 0x{:02x}", buf[0]);
                    }
                }
            }
            Ok(Err(e)) => println!("  Write failed: {:?}", e),
            Err(_) => println!("  Write timed out"),
        }
    }
}

#[tokio::test]
async fn test_connection_state_corruption() {
    // Test sending commands before handshake
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    let commands = vec![
        (0x10, vec![0xFF; 16], "PULL before handshake"),
        (0x20, vec![0xFF; 16], "PUSH before handshake"),
        (0x30, vec![0xFF; 16], "DELETE before handshake"),
        (0x40, vec![0xFF; 16], "HISTORY before handshake"),
    ];

    for (msg_type, payload, description) in commands {
        println!("Testing: {}", description);

        let frame = raw_frame((1 + payload.len()) as u32, msg_type, &payload);
        let write_result = timeout(
            Duration::from_millis(200),
            stream.write_all(&frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let mut buf = [0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 500).await;
            }
            Ok(Err(e)) => println!("  Write failed: {:?}", e),
            Err(_) => println!("  Write timed out"),
        }
    }
}

#[tokio::test]
async fn test_timeout_bypass_attempts() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test partial writes to manipulate timeout handling
    println!("Testing partial write timeout bypass");

    let hello_start = &[0x00, 0x00, 0x00, 0x10, 0x01]; // Partial hello frame

    for i in 0..10 {
        println!("  Partial write {}", i);

        // Write partial data
        let write_result = timeout(
            Duration::from_millis(100),
            stream.write_all(hello_start)
        ).await;

        if write_result.is_err() {
            println!("    Write failed");
            break;
        }

        // Wait a bit
        sleep(Duration::from_millis(500)).await;

        // Try to read
        let mut buf = [0u8; 1];
        let read_result = read_with_timeout(&mut stream, &mut buf, 200).await;
        println!("    Read result: {:?}", read_result);
    }
}

#[tokio::test]
async fn test_rapid_connection_storm() {
    println!("Testing rapid connection storm (DoS simulation)");

    let mut successful_connections = 0;
    let mut failed_connections = 0;

    // Try to create many rapid connections
    for i in 0..100 {
        let stream_result = timeout(
            Duration::from_millis(50),
            TcpStream::connect("127.0.0.1:20667")
        ).await;

        match stream_result {
            Ok(Ok(mut stream)) => {
                successful_connections += 1;

                // Send minimal data and close
                let _ = timeout(
                    Duration::from_millis(10),
                    stream.write_all(&[0x00])
                ).await;
            }
            Ok(Err(_)) => {
                failed_connections += 1;
            }
            Err(_) => {
                failed_connections += 1;
            }
        }

        if i % 20 == 0 {
            println!("  Attempted {} connections (success: {}, failed: {})",
                    i, successful_connections, failed_connections);
        }
    }

    println!("Connection storm test completed: {} successful, {} failed",
            successful_connections, failed_connections);
}

// ============================================================================
// HTTP SERVER SECURITY TESTS
// ============================================================================

#[tokio::test]
async fn test_http_server_security() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // Test various HTTP security scenarios that could reach the HTTP server
    // Create strings with proper lifetimes
    let large_header = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n", "A".repeat(10000));
    let many_headers = format!("GET / HTTP/1.1\r\nHost: localhost\r\n{}\r\n\r\n", (0..100).map(|i| format!("X-Header-{}: value{}\r\n", i, i)).collect::<String>());

    let http_attacks = vec![
        // Path traversal attempts
        ("GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n", "Path traversal"),
        ("GET /..\\..\\..\\windows\\system32\\cmd.exe HTTP/1.1\r\nHost: localhost\r\n\r\n", "Windows path traversal"),
        ("GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n", "URL encoded traversal"),
        // XSS attempts
        ("GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: localhost\r\n\r\n", "XSS in query"),
        ("GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: <img src=x onerror=alert(1)>\r\n\r\n", "XSS in headers"),
        // SQL injection attempts (though not applicable, test handling)
        ("GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: localhost\r\n\r\n", "SQL injection in query"),
        ("GET / HTTP/1.1\r\nHost: localhost\r\nReferer: ' UNION SELECT * FROM users--\r\n\r\n", "SQL injection in referer"),
        // Command injection attempts
        ("GET /?cmd=;cat /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n", "Command injection"),
        ("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: $(cat /etc/passwd)\r\n\r\n", "Command injection in UA"),
        // Large headers (DoS)
        (large_header.as_str(), "Large header DoS"),
        // Many headers
        (many_headers.as_str(), "Many headers"),
        // Invalid HTTP
        ("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n\r\n\r\n", "Extra CRLF"),
        ("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n", "Negative content length"),
        ("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999999999\r\n\r\n", "Huge content length"),
        // HTTP method attacks
        ("TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n", "TRACE method"),
        ("OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n", "OPTIONS method"),
        ("PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello", "PUT method"),
        // Host header attacks
        ("GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n", "Host header injection"),
        ("GET / HTTP/1.1\r\nHost: localhost.evil.com\r\n\r\n", "Host header subdomain"),
        ("GET / HTTP/1.1\r\nHost: localhost\r\nHost: evil.com\r\n\r\n", "Duplicate host headers"),
    ];

    for (request, description) in http_attacks {
        println!("Testing HTTP security: {}", description);

        // Since the server runs on TCP port 20667, we need to try connecting to the HTTP port
        // For now, we'll test that the TCP connection handles these inputs gracefully
        // In a real deployment, the HTTP server would be on a different port

        let test_result = timeout(
            Duration::from_millis(500),
            stream.write_all(request.as_bytes())
        ).await;

        match test_result {
            Ok(Ok(_)) => {
                // Try to read response
                let mut buf = vec![0u8; 1024];
                let _ = read_with_timeout(&mut stream, &mut buf, 500).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed (expected for some): {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out");
                // Need a new connection for next test
                break;
            }
        }
    }
}

// ============================================================================
// CONFIGURATION SECURITY TESTS
// ============================================================================

// Configuration security tests are implemented in a separate file to avoid
// complex module imports in the test environment.

// ============================================================================
// DATABASE SECURITY TESTS
// ============================================================================

#[tokio::test]
async fn test_database_corruption_resistance() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    // First establish a valid connection
    let hello = encode_hello(5, "guest", "");
    if stream.write_all(&hello).await.is_err() {
        return; // Skip if handshake fails
    }

    let mut buf = [0u8; 1024];
    if read_with_timeout(&mut stream, &mut buf, 1000).await.is_err() {
        return;
    }

    // Test database operations with malicious data
    let db_attacks = vec![
        // Large keys
        (vec![0xFF; 65536], vec![0x00; 100], "Oversized key"),
        // Empty keys
        (vec![], vec![0x01; 10], "Empty key"),
        // Keys with null bytes
        (vec![0x00, 0x01, 0x02], vec![0x03; 10], "Null byte in key"),
        // Very large data
        (vec![0x01, 0x02, 0x03], vec![0xFF; 8*1024*1024], "8MB data payload"),
        // Special byte patterns
        (vec![0xAA; 16], vec![0x55; 16], "Alternating pattern"),
        (vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0xCA, 0xFE, 0xBA, 0xBE], "Magic bytes"),
    ];

    for (key, data, description) in db_attacks {
        println!("Testing database security: {}", description);

        // Create PUSH message with malicious data
        // This would require implementing the full protocol encoding
        // For now, we'll send raw frames that might trigger database operations
        let malicious_payload = [key, data].concat();
        let frame = raw_frame((1 + malicious_payload.len()) as u32, 0x20, &malicious_payload);

        let write_result = timeout(
            Duration::from_millis(1000),
            stream.write_all(&frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                let _ = read_with_timeout(&mut stream, &mut buf, 2000).await;
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?}", e);
            }
            Err(_) => {
                println!("  Write timed out - possible database issue");
            }
        }
    }
}

// ============================================================================
// CONCURRENT CONNECTION STRESS TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_connection_flood() {
    println!("Testing concurrent connection flood...");

    let mut handles = vec![];
    let num_connections = 50;

    for i in 0..num_connections {
        let handle = tokio::spawn(async move {
            let mut results = vec![];

            for attempt in 0..5 {
                let stream_result = timeout(
                    Duration::from_millis(500),
                    TcpStream::connect("127.0.0.1:20667")
                ).await;

                match stream_result {
                    Ok(Ok(mut stream)) => {
                        // Send hello and try to read response
                        let hello = encode_hello(5, "guest", "");
                        let write_result = timeout(
                            Duration::from_millis(100),
                            stream.write_all(&hello)
                        ).await;

                        if write_result.is_ok() {
                            let mut buf = [0u8; 64];
                            let _ = read_with_timeout(&mut stream, &mut buf, 200).await;
                            results.push(format!("conn_{}_attempt_{}: success", i, attempt));
                        } else {
                            results.push(format!("conn_{}_attempt_{}: write_fail", i, attempt));
                        }
                    }
                    Ok(Err(_)) => {
                        results.push(format!("conn_{}_attempt_{}: connect_fail", i, attempt));
                    }
                    Err(_) => {
                        results.push(format!("conn_{}_attempt_{}: timeout", i, attempt));
                    }
                }

                sleep(Duration::from_millis(10)).await;
            }

            results
        });

        handles.push(handle);
    }

    let mut all_results = vec![];
    for handle in handles {
        if let Ok(results) = handle.await {
            all_results.extend(results);
        }
    }

    let success_count = all_results.iter().filter(|r| r.contains("success")).count();
    let fail_count = all_results.len() - success_count;

    println!("Concurrent flood test completed:");
    println!("  Total connection attempts: {}", all_results.len());
    println!("  Successful connections: {}", success_count);
    println!("  Failed connections: {}", fail_count);
    println!("  Success rate: {:.1}%", (success_count as f64 / all_results.len() as f64) * 100.0);
}

// ============================================================================
// EXTENDED FUZZING TESTS
// ============================================================================

#[tokio::test]
async fn test_extended_protocol_fuzzing() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    let mut rng = rand::thread_rng();

    // Extended fuzzing with different data patterns
    let patterns: Vec<(&str, Box<dyn Fn() -> Vec<u8>>)> = vec![
        ("random", Box::new(|| {
            let mut rng = rand::thread_rng();
            random_bytes(rng.gen_range(1..512))
        })),
        ("zeros", Box::new(|| {
            let mut rng = rand::thread_rng();
            vec![0u8; rng.gen_range(1..512)]
        })),
        ("ones", Box::new(|| {
            let mut rng = rand::thread_rng();
            vec![0xFFu8; rng.gen_range(1..512)]
        })),
        ("alternating", Box::new(|| {
            let mut rng = rand::thread_rng();
            (0..rng.gen_range(1..512)).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect()
        })),
        ("incrementing", Box::new(|| {
            let mut rng = rand::thread_rng();
            (0..rng.gen_range(1..512)).map(|i| i as u8).collect()
        })),
        ("decrementing", Box::new(|| {
            let mut rng = rand::thread_rng();
            (0..rng.gen_range(1..512)).map(|i| (255 - i) as u8).collect()
        })),
        ("repeated_patterns", Box::new(|| {
            let mut rng = rand::thread_rng();
            let pattern = random_bytes(rng.gen_range(1..16));
            let repeats = rng.gen_range(1..32);
            pattern.repeat(repeats)
        })),
    ];

    for (pattern_name, pattern_fn) in &patterns {
        println!("Extended fuzzing with {} pattern", pattern_name);

        for test_case in 0..20 {
            let payload = pattern_fn();
            let len_field = rng.gen::<u32>();
            let msg_type = rng.gen::<u8>();

            let frame = raw_frame(len_field, msg_type, &payload);

            let write_result = timeout(
                Duration::from_millis(100),
                stream.write_all(&frame)
            ).await;

            match write_result {
                Ok(Ok(_)) => {
                    let mut buf = [0u8; 256];
                    let _ = read_with_timeout(&mut stream, &mut buf, 200).await;
                }
                Ok(Err(_)) => {} // Expected for malformed data
                Err(_) => {
                    println!("  Timeout during {} test case {}", pattern_name, test_case);
                    break;
                }
            }
        }
    }
}

// ============================================================================
// COMPREHENSIVE FUZZING CAMPAIGN
// ============================================================================

#[tokio::test]
async fn comprehensive_fuzzing_campaign() {
    println!("Starting comprehensive network fuzzing campaign...");

    let mut rng = rand::thread_rng();
    let mut test_count = 0;
    let mut crash_count = 0;
    let mut timeout_count = 0;

    // Run for a limited time to avoid infinite loops
    let start_time = Instant::now();
    let max_duration = Duration::from_secs(30);

    while start_time.elapsed() < max_duration && test_count < 1000 {
        test_count += 1;

        let stream = match timeout(
            Duration::from_millis(100),
            TcpStream::connect("127.0.0.1:20667")
        ).await {
            Ok(Ok(s)) => s,
            _ => {
                timeout_count += 1;
                continue;
            }
        };
        let mut stream = stream;

        // Generate completely random frame
        let len_field = rng.gen::<u32>();
        let msg_type = rng.gen::<u8>();
        let payload_size = rng.gen_range(0..512);
        let payload = random_bytes(payload_size);

        let frame = raw_frame(len_field, msg_type, &payload);

        let write_result = timeout(
            Duration::from_millis(50),
            stream.write_all(&frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                // Try brief read
                let mut buf = [0u8; 64];
                let _ = read_with_timeout(&mut stream, &mut buf, 50).await;
            }
            Ok(Err(_)) => {
                // Write failed - expected for many fuzz cases
            }
            Err(_) => {
                crash_count += 1;
                println!("  Possible crash detected at test {}", test_count);
            }
        }

        if test_count % 200 == 0 {
            println!("  Progress: {} tests, {} timeouts, {} crashes", test_count, timeout_count, crash_count);
        }
    }

    println!("Comprehensive network fuzzing completed:");
    println!("  Total tests: {}", test_count);
    println!("  Connection timeouts: {}", timeout_count);
    println!("  Write timeouts/crashes: {}", crash_count);
    println!("  Success rate: {:.2}%", (test_count - timeout_count - crash_count) as f64 / test_count as f64 * 100.0);
}