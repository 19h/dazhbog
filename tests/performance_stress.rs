//! Performance and stress testing for dazhbog server
//!
//! This module tests the server's performance under various stress conditions,
//! including high load, memory pressure, and concurrent operations.

use std::time::{Duration, Instant};
use tokio::time::{timeout, sleep};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use std::sync::Arc;
use rand::{Rng, RngCore};

async fn connect_to_server() -> Option<TcpStream> {
    match timeout(Duration::from_secs(1), TcpStream::connect("127.0.0.1:20667")).await {
        Ok(Ok(stream)) => Some(stream),
        _ => {
            eprintln!("Server not running on 127.0.0.1:20667, skipping performance tests");
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

#[tokio::test]
async fn test_sustained_high_load() {
    println!("Testing sustained high load...");

    let semaphore = Arc::new(Semaphore::new(100)); // Limit concurrent connections
    let mut handles = vec![];
    let test_duration = Duration::from_secs(30);
    let start_time = Instant::now();

    let mut total_requests = 0u64;
    let mut successful_requests = 0u64;
    let mut failed_requests = 0u64;

    // Spawn workers that continuously make requests
    for worker_id in 0..20 {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let mut local_success = 0u64;
            let mut local_fail = 0u64;

            loop {
                let _permit = sem.acquire().await.unwrap();

                match TcpStream::connect("127.0.0.1:20667").await {
                    Ok(mut stream) => {
                        // Send hello
                        let hello = encode_hello(5, "guest", "");
                        if stream.write_all(&hello).await.is_ok() {
                            let mut buf = [0u8; 64];
                            if read_with_timeout(&mut stream, &mut buf, 500).await.is_ok() {
                                local_success += 1;
                            } else {
                                local_fail += 1;
                            }
                        } else {
                            local_fail += 1;
                        }
                    }
                    Err(_) => {
                        local_fail += 1;
                    }
                }

                drop(_permit);

                // Small delay between requests
                sleep(Duration::from_millis(10)).await;

                // Check if test duration exceeded
                if start_time.elapsed() >= test_duration {
                    break;
                }
            }

            (local_success, local_fail)
        });

        handles.push(handle);
    }

    // Wait for all workers to complete
    for handle in handles {
        if let Ok((success, fail)) = handle.await {
            successful_requests += success;
            failed_requests += fail;
        }
    }

    total_requests = successful_requests + failed_requests;

    println!("Sustained load test completed:");
    println!("  Duration: {:?}", test_duration);
    println!("  Total requests: {}", total_requests);
    println!("  Successful: {} ({:.1}%)", successful_requests,
             (successful_requests as f64 / total_requests as f64) * 100.0);
    println!("  Failed: {} ({:.1}%)", failed_requests,
             (failed_requests as f64 / total_requests as f64) * 100.0);
    println!("  Requests/second: {:.1}", total_requests as f64 / test_duration.as_secs_f64());
}

#[tokio::test]
async fn test_memory_pressure_simulation() {
    println!("Testing memory pressure simulation...");

    let mut handles = vec![];
    let num_clients = 50;

    for client_id in 0..num_clients {
        let handle = tokio::spawn(async move {
            let mut results = vec![];

            for request_id in 0..10 {
                let stream_result = timeout(
                    Duration::from_millis(1000),
                    TcpStream::connect("127.0.0.1:20667")
                ).await;

                match stream_result {
                    Ok(Ok(mut stream)) => {
                        // Send increasingly large payloads to simulate memory pressure
                        let payload_size = 1024 * (request_id + 1); // 1KB to 10KB
                        let large_data = vec![client_id as u8; payload_size];

                        // Create a message with large data
                        let mut message = Vec::new();
                        message.extend_from_slice(&((1 + large_data.len()) as u32).to_be_bytes());
                        message.push(0x01); // Message type
                        message.extend_from_slice(&large_data);

                        let start_time = Instant::now();
                        let write_result = timeout(
                            Duration::from_millis(2000),
                            stream.write_all(&message)
                        ).await;

                        let response_time = start_time.elapsed();

                        match write_result {
                            Ok(Ok(_)) => {
                                let mut buf = vec![0u8; 1024];
                                let read_result = read_with_timeout(&mut stream, &mut buf, 2000).await;
                                if read_result.is_ok() {
                                    results.push(format!("req_{}_{}: success_{}ms",
                                                       client_id, request_id, response_time.as_millis()));
                                } else {
                                    results.push(format!("req_{}_{}: read_fail_{}ms",
                                                       client_id, request_id, response_time.as_millis()));
                                }
                            }
                            Ok(Err(_)) => {
                                results.push(format!("req_{}_{}: write_fail_{}ms",
                                                   client_id, request_id, response_time.as_millis()));
                            }
                            Err(_) => {
                                results.push(format!("req_{}_{}: timeout_{}ms",
                                                   client_id, request_id, response_time.as_millis()));
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        results.push(format!("req_{}_{}: connect_fail", client_id, request_id));
                    }
                    Err(_) => {
                        results.push(format!("req_{}_{}: connect_timeout", client_id, request_id));
                    }
                }

                // Progressive delay to avoid overwhelming
                sleep(Duration::from_millis((50 * (request_id + 1)) as u64)).await;
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

    println!("Memory pressure test completed:");
    println!("  Total operations: {}", all_results.len());
    println!("  Successful: {} ({:.1}%)", success_count,
             (success_count as f64 / all_results.len() as f64) * 100.0);
    println!("  Failed: {} ({:.1}%)", fail_count,
             (fail_count as f64 / all_results.len() as f64) * 100.0);
}

#[tokio::test]
async fn test_connection_churn() {
    println!("Testing connection churn (rapid connect/disconnect)...");

    let mut total_connections = 0u64;
    let mut successful_handshakes = 0u64;
    let test_duration = Duration::from_secs(15);
    let start_time = Instant::now();

    while start_time.elapsed() < test_duration {
        total_connections += 1;

        let stream_result = timeout(
            Duration::from_millis(200),
            TcpStream::connect("127.0.0.1:20667")
        ).await;

        match stream_result {
            Ok(Ok(mut stream)) => {
                // Quick handshake attempt
                let hello = encode_hello(5, "guest", "");
                if timeout(
                    Duration::from_millis(100),
                    stream.write_all(&hello)
                ).await.is_ok() {
                    successful_handshakes += 1;
                }
                // Immediately close connection (drop stream)
            }
            Ok(Err(_)) => {
                // Connection failed
            }
            Err(_) => {
                // Connection timeout
            }
        }

        // Minimal delay between connections
        sleep(Duration::from_millis(1)).await;
    }

    println!("Connection churn test completed:");
    println!("  Duration: {:?}", test_duration);
    println!("  Total connection attempts: {}", total_connections);
    println!("  Successful handshakes: {} ({:.1}%)", successful_handshakes,
             (successful_handshakes as f64 / total_connections as f64) * 100.0);
    println!("  Connections/second: {:.1}", total_connections as f64 / test_duration.as_secs_f64());
}

#[tokio::test]
async fn test_gradual_load_increase() {
    println!("Testing gradual load increase...");

    let mut current_concurrency = 1;
    let max_concurrency = 64;
    let step_duration = Duration::from_secs(2);

    while current_concurrency <= max_concurrency {
        println!("Testing with {} concurrent connections...", current_concurrency);

        let mut handles = vec![];
        let start_time = Instant::now();

        // Spawn concurrent workers
        for worker_id in 0..current_concurrency {
            let handle = tokio::spawn(async move {
                let mut success_count = 0;
                let mut fail_count = 0;

                let end_time = start_time + step_duration;
                while Instant::now() < end_time {
                    let stream_result = timeout(
                        Duration::from_millis(500),
                        TcpStream::connect("127.0.0.1:20667")
                    ).await;

                    match stream_result {
                        Ok(Ok(mut stream)) => {
                            let hello = encode_hello(5, "guest", "");
                            if stream.write_all(&hello).await.is_ok() {
                                let mut buf = [0u8; 64];
                                if read_with_timeout(&mut stream, &mut buf, 300).await.is_ok() {
                                    success_count += 1;
                                } else {
                                    fail_count += 1;
                                }
                            } else {
                                fail_count += 1;
                            }
                        }
                        Ok(Err(_)) => {
                            fail_count += 1;
                        }
                        Err(_) => {
                            fail_count += 1;
                        }
                    }

                    sleep(Duration::from_millis(10)).await;
                }

                (success_count, fail_count)
            });

            handles.push(handle);
        }

        // Wait for step to complete
        sleep(step_duration).await;

        // Collect results
        let mut total_success = 0;
        let mut total_fail = 0;

        for handle in handles {
            if let Ok((success, fail)) = handle.await {
                total_success += success;
                total_fail += fail;
            }
        }

        let total_requests = total_success + total_fail;
        let success_rate = if total_requests > 0 {
            (total_success as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        println!("  Concurrency {}: {} requests, {:.1}% success rate",
                current_concurrency, total_requests, success_rate);

        // Stop if success rate drops too low
        if success_rate < 50.0 && current_concurrency > 1 {
            println!("  Success rate dropped below 50%, stopping load increase");
            break;
        }

        current_concurrency *= 2;
        sleep(Duration::from_millis(500)).await; // Brief pause between steps
    }

    println!("Gradual load increase test completed at concurrency level: {}", current_concurrency / 2);
}

#[tokio::test]
async fn test_large_payload_handling() {
    let stream = match connect_to_server().await {
        Some(s) => s,
        None => return,
    };
    let mut stream = stream;

    println!("Testing large payload handling...");

    let payload_sizes = vec![
        64 * 1024,        // 64KB
        512 * 1024,       // 512KB
        1024 * 1024,      // 1MB
        2 * 1024 * 1024,  // 2MB (if supported)
    ];

    for &size in &payload_sizes {
        println!("Testing payload size: {} bytes", size);

        // First do a successful handshake
        let hello = encode_hello(5, "guest", "");
        if stream.write_all(&hello).await.is_err() {
            println!("  Handshake failed, skipping");
            continue;
        }

        let mut buf = [0u8; 1024];
        if read_with_timeout(&mut stream, &mut buf, 1000).await.is_err() {
            println!("  Handshake response failed, skipping");
            continue;
        }

        // Generate large payload
        let large_payload = vec![0xAA; size];

        // Create message frame
        let mut message = Vec::new();
        message.extend_from_slice(&((1 + large_payload.len()) as u32).to_be_bytes());
        message.push(0x20); // PUSH message type
        message.extend_from_slice(&large_payload);

        let start_time = Instant::now();
        let write_result = timeout(
            Duration::from_millis(5000), // Longer timeout for large payloads
            stream.write_all(&message)
        ).await;

        let write_time = start_time.elapsed();

        match write_result {
            Ok(Ok(_)) => {
                println!("  Write successful in {:?}", write_time);
                // Try to read response
                let read_start = Instant::now();
                let read_result = read_with_timeout(&mut stream, &mut buf, 5000).await;
                let read_time = read_start.elapsed();

                match read_result {
                    Ok(n) => println!("  Read {} bytes in {:?}", n, read_time),
                    Err(e) => println!("  Read failed: {:?} after {:?}", e, read_time),
                }
            }
            Ok(Err(e)) => {
                println!("  Write failed: {:?} after {:?}", e, write_time);
            }
            Err(_) => {
                println!("  Write timed out after {:?}", write_time);
            }
        }

        // Need a new connection for next test
        break; // Only test one size per connection to avoid issues
    }
}

#[tokio::test]
async fn test_timeout_behavior_under_load() {
    println!("Testing timeout behavior under load...");

    let semaphore = Arc::new(Semaphore::new(10)); // Limited concurrency
    let mut handles = vec![];

    // Test with slow operations that might trigger timeouts
    for worker_id in 0..20 {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let mut timeout_count = 0;
            let mut success_count = 0;

            for _attempt in 0..10 {
                let _permit = sem.acquire().await.unwrap();

                let stream_result = timeout(
                    Duration::from_millis(1000), // Shorter timeout to test timeout handling
                    TcpStream::connect("127.0.0.1:20667")
                ).await;

                match stream_result {
                    Ok(Ok(mut stream)) => {
                        // Send hello and wait for response with short timeout
                        let hello = encode_hello(5, "guest", "");
                        let write_result = timeout(
                            Duration::from_millis(200),
                            stream.write_all(&hello)
                        ).await;

                        if write_result.is_ok() {
                            let mut buf = [0u8; 64];
                            let read_result = timeout(
                                Duration::from_millis(100), // Very short read timeout
                                stream.read(&mut buf)
                            ).await;

                            match read_result {
                                Ok(Ok(_)) => success_count += 1,
                                Ok(Err(_)) => timeout_count += 1,
                                Err(_) => timeout_count += 1, // tokio timeout
                            }
                        } else {
                            timeout_count += 1;
                        }
                    }
                    Ok(Err(_)) => {
                        timeout_count += 1;
                    }
                    Err(_) => {
                        timeout_count += 1; // Connection timeout
                    }
                }

                drop(_permit);
                sleep(Duration::from_millis(50)).await;
            }

            (success_count, timeout_count)
        });

        handles.push(handle);
    }

    let mut total_success = 0;
    let mut total_timeout = 0;

    for handle in handles {
        if let Ok((success, timeout)) = handle.await {
            total_success += success;
            total_timeout += timeout;
        }
    }

    let total_operations = total_success + total_timeout;

    println!("Timeout behavior test completed:");
    println!("  Total operations: {}", total_operations);
    println!("  Successful: {} ({:.1}%)", total_success,
             (total_success as f64 / total_operations as f64) * 100.0);
    println!("  Timeouts: {} ({:.1}%)", total_timeout,
             (total_timeout as f64 / total_operations as f64) * 100.0);
}

#[tokio::test]
async fn test_resource_leak_detection() {
    println!("Testing for resource leaks under sustained load...");

    let test_duration = Duration::from_secs(10);
    let start_time = Instant::now();
    let mut connection_count = 0u64;

    while start_time.elapsed() < test_duration {
        let stream_result = timeout(
            Duration::from_millis(100),
            TcpStream::connect("127.0.0.1:20667")
        ).await;

        if let Ok(Ok(mut stream)) = stream_result {
            connection_count += 1;

            // Send minimal data and close
            let hello = encode_hello(5, "guest", "");
            let _ = timeout(
                Duration::from_millis(50),
                stream.write_all(&hello)
            ).await;

            // Connection is automatically closed when stream is dropped
        }

        // Small delay to avoid overwhelming
        sleep(Duration::from_millis(5)).await;
    }

    println!("Resource leak test completed:");
    println!("  Duration: {:?}", test_duration);
    println!("  Connections created: {}", connection_count);
    println!("  Connections/second: {:.1}", connection_count as f64 / test_duration.as_secs_f64());
    println!("  Note: Monitor server resources (memory, file handles) externally");
}
