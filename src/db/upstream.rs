//! Upstream server communication for function metadata forwarding.

use crate::api::metrics::METRICS;
use crate::config::Upstream;
use crate::protocol::lumina;
use log::*;
use std::io;
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector;

/// Result element for each requested key: Some(pop,len,name,data) when found.
pub type UpItem = Option<(u32, u32, String, Vec<u8>)>;

/// Connection wrapper for upstream servers.
enum UpstreamConn {
    Plain(TcpStream),
    Tls(tokio_native_tls::TlsStream<TcpStream>),
}

impl UpstreamConn {
    async fn write(&mut self, typ: u8, payload: &[u8]) -> io::Result<()> {
        match self {
            UpstreamConn::Plain(s) => lumina::write_lumina_packet(s, typ, payload).await,
            UpstreamConn::Tls(s) => lumina::write_lumina_packet(s, typ, payload).await,
        }
    }
    async fn read(&mut self, max_len: usize) -> io::Result<(u8, Vec<u8>)> {
        match self {
            UpstreamConn::Plain(s) => lumina::read_lumina_packet(s, max_len).await,
            UpstreamConn::Tls(s) => lumina::read_lumina_packet(s, max_len).await,
        }
    }
}

/// Connect to upstream server (plain TCP or TLS with optional insecure verification).
async fn connect(up: &Upstream) -> io::Result<UpstreamConn> {
    let addr = format!("{}:{}", up.host, up.port);
    debug!("upstream: connecting to {}", addr);
    let stream = tokio::time::timeout(
        std::time::Duration::from_millis(up.timeout_ms),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
    debug!("upstream: TCP connection established");

    if up.use_tls {
        debug!(
            "upstream: initiating TLS handshake (insecure_no_verify={})",
            up.insecure_no_verify
        );
        let mut builder = native_tls::TlsConnector::builder();
        if up.insecure_no_verify {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        let connector = builder
            .build()
            .map_err(|e| io::Error::other(format!("tls build: {e}")))?;
        let connector = TlsConnector::from(connector);
        let domain = up.host.as_str();
        let tls = tokio::time::timeout(
            std::time::Duration::from_millis(up.timeout_ms),
            connector.connect(domain, stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timeout"))?
        .map_err(|e| io::Error::other(format!("tls handshake: {e}")))?;
        debug!("upstream: TLS handshake complete");
        Ok(UpstreamConn::Tls(tls))
    } else {
        Ok(UpstreamConn::Plain(stream))
    }
}

/// Parse license ID from JSON (format: "XX-YYYY-ZZZZ-WW" -> [0xXX, 0xYY, 0xYY, 0xZZ, 0xZZ, 0xWW]).
fn parse_license_id(json_data: &[u8]) -> io::Result<[u8; 6]> {
    let json_str = std::str::from_utf8(json_data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("license not UTF-8: {}", e),
        )
    })?;

    // Find "id" field in licenses array (first occurrence after "licenses")
    if let Some(licenses_pos) = json_str.find(r#""licenses""#) {
        let search_from = &json_str[licenses_pos..];
        // Look for "id" field with optional whitespace: "id": "..."
        for line in search_from.lines() {
            if line.contains(r#""id""#) {
                // Extract value after "id":
                if let Some(colon_pos) = line.find(':') {
                    let after_colon = &line[colon_pos + 1..].trim_start();
                    if let Some(quoted) = after_colon.strip_prefix('"') {
                        if let Some(end_quote) = quoted.find('"') {
                            let id_str = &quoted[..end_quote];
                            // Parse format like "96-4406-9EB7-5F"
                            let hex_only: String =
                                id_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                            if hex_only.len() == 12 {
                                let mut lic_id = [0u8; 6];
                                for i in 0..6 {
                                    let hex_byte = &hex_only[i * 2..i * 2 + 2];
                                    lic_id[i] = u8::from_str_radix(hex_byte, 16).map_err(|e| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!("bad hex in license ID: {}", e),
                                        )
                                    })?;
                                }
                                debug!(
                                    "upstream: parsed license ID from '{}': {:02X?}",
                                    id_str, lic_id
                                );
                                return Ok(lic_id);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "could not find license ID in JSON",
    ))
}

/// Perform a Lumina hello to upstream.
async fn upstream_handshake(conn: &mut UpstreamConn, up: &Upstream) -> io::Result<()> {
    let lic_bytes: Vec<u8> = if let Some(ref path) = up.license_path {
        std::fs::read(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to read license file '{}': {}", path, e),
            )
        })?
    } else {
        Vec::new()
    };

    let lic_id = if !lic_bytes.is_empty() {
        parse_license_id(&lic_bytes)?
    } else {
        [0u8; 6]
    };

    let payload = lumina::build_lumina_hello_payload(
        up.hello_protocol_version,
        &lic_bytes,
        lic_id,
        "guest",
        "",
        0,
    );
    debug!(
        "upstream: sending hello (protocol_version={}, license_len={})",
        up.hello_protocol_version,
        lic_bytes.len()
    );
    tokio::time::timeout(
        std::time::Duration::from_millis(up.timeout_ms),
        conn.write(0x0d, &payload),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hello write timeout"))??;
    debug!("upstream: waiting for hello response");
    let (typ, pl) = tokio::time::timeout(
        std::time::Duration::from_millis(up.timeout_ms),
        conn.read(1 << 20),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hello read timeout"))??; // accept up to 1 MiB hello reply
    debug!(
        "upstream: received hello response type=0x{:02x}, len={}",
        typ,
        pl.len()
    );

    // Check for failure response
    if typ == 0x0b {
        match lumina::decode_lumina_fail(&pl) {
            Ok((code, msg)) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("upstream rejected hello: code={}, message={}", code, msg),
                ));
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "upstream rejected hello with type 0x0b (failed to decode message)".to_string(),
                ));
            }
        }
    }

    // Expected success response is 0x31
    if typ != 0x31 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("upstream hello: unexpected response type 0x{:02x}", typ),
        ));
    }

    Ok(())
}

/// Fetch missing items from upstream servers. Returns vector aligned to `keys`.
/// Tries servers in priority order (lower priority number = higher priority).
/// Stops querying once all functions are found or all servers are exhausted.
pub async fn fetch_from_upstreams(
    upstreams: &[Upstream],
    keys: &[u128],
) -> io::Result<Vec<UpItem>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    // Filter and sort enabled upstreams by priority
    let mut sorted_upstreams: Vec<_> = upstreams.iter().filter(|up| up.enabled).collect();
    sorted_upstreams.sort_by_key(|up| up.priority);

    if sorted_upstreams.is_empty() {
        debug!("upstream: no enabled upstreams configured");
        return Ok(vec![None; keys.len()]);
    }

    debug!(
        "upstream: fetch_from_upstreams called for {} keys, trying {} servers in priority order",
        keys.len(),
        sorted_upstreams.len()
    );

    // Track results for all keys
    let mut results: Vec<UpItem> = vec![None; keys.len()];

    // Try each upstream server in priority order
    for (server_idx, up) in sorted_upstreams.iter().enumerate() {
        // Find which keys are still missing
        let mut missing_keys = Vec::new();
        let mut missing_positions = Vec::new();

        for (i, item) in results.iter().enumerate() {
            if item.is_none() {
                missing_keys.push(keys[i]);
                missing_positions.push(i);
            }
        }

        if missing_keys.is_empty() {
            debug!(
                "upstream: all functions found after {} server(s)",
                server_idx
            );
            break;
        }

        debug!(
            "upstream: querying server {} (priority={}, host={}:{}) for {} missing keys",
            server_idx,
            up.priority,
            up.host,
            up.port,
            missing_keys.len()
        );

        METRICS.inc_upstream_requests();

        // Fetch from this upstream
        match fetch_from_single_upstream(up, &missing_keys).await {
            Ok(fetched) => {
                let mut found_count = 0;
                for (j, item) in fetched.into_iter().enumerate() {
                    if let Some(func_data) = item {
                        let original_idx = missing_positions[j];
                        results[original_idx] = Some(func_data);
                        found_count += 1;
                    }
                }
                debug!(
                    "upstream: server {} returned {} functions",
                    server_idx, found_count
                );
                METRICS.inc_upstream_fetched(found_count);
            }
            Err(e) => {
                METRICS.inc_upstream_errors();
                warn!(
                    "upstream: server {} ({}:{}) failed: {}",
                    server_idx, up.host, up.port, e
                );
                // Continue to next server
            }
        }
    }

    Ok(results)
}

/// Fetch missing items from a single upstream server. Returns vector aligned to `keys`.
async fn fetch_from_single_upstream(up: &Upstream, keys: &[u128]) -> io::Result<Vec<UpItem>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    let batch = up.batch_max.max(1);
    let mut results: Vec<UpItem> = vec![None; keys.len()];

    let mut start = 0usize;
    while start < keys.len() {
        let end = (start + batch).min(keys.len());
        let slice = &keys[start..end];

        // Build hashes array (big-endian)
        let mut arr = Vec::<[u8; 16]>::with_capacity(slice.len());
        for &k in slice {
            arr.push(k.to_be_bytes());
        }
        let pull_payload = lumina::build_pull_metadata_payload(&arr);

        // Connect and handshake per batch to simplify code and resource usage
        let mut conn = match connect(up).await {
            Ok(c) => c,
            Err(e) => {
                METRICS.inc_upstream_errors();
                warn!("upstream connect failed: {}", e);
                // keep None for these entries; try next batch
                start = end;
                continue;
            }
        };
        if let Err(e) = upstream_handshake(&mut conn, up).await {
            METRICS.inc_upstream_errors();
            warn!("upstream handshake failed: {}", e);
            start = end;
            continue;
        }

        // Send PullMetadata (0x0e)
        debug!(
            "upstream: sending PullMetadata for {} keys (payload {} bytes)",
            slice.len(),
            pull_payload.len()
        );
        let write_result = tokio::time::timeout(
            std::time::Duration::from_millis(up.timeout_ms),
            conn.write(0x0e, &pull_payload),
        )
        .await;
        if let Err(e) = write_result {
            METRICS.inc_upstream_errors();
            warn!("upstream write pull timeout: {}", e);
            start = end;
            continue;
        }
        if let Err(e) = write_result.unwrap() {
            METRICS.inc_upstream_errors();
            warn!("upstream write pull failed: {}", e);
            start = end;
            continue;
        }

        // Read PullResult (0x0f)
        debug!("upstream: waiting for PullResult response");
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(up.timeout_ms),
            conn.read(64 * 1024 * 1024),
        )
        .await;
        let (typ, payload) = match read_result {
            Ok(Ok(v)) => {
                debug!(
                    "upstream: received response type=0x{:02x}, payload {} bytes",
                    v.0,
                    v.1.len()
                );
                v
            }
            Ok(Err(e)) => {
                METRICS.inc_upstream_errors();
                warn!("upstream read pull failed: {} (io kind: {:?})", e, e.kind());
                start = end;
                continue;
            }
            Err(_) => {
                METRICS.inc_upstream_errors();
                warn!("upstream read pull timeout");
                start = end;
                continue;
            }
        };
        if typ != 0x0f {
            METRICS.inc_upstream_errors();
            warn!("upstream unexpected msg type: 0x{:02x}", typ);
            start = end;
            continue;
        }

        match lumina::decode_lumina_pull_result(&payload) {
            Ok((statuses, funcs)) => {
                debug!(
                    "upstream: decoded pull result: {} statuses, {} funcs",
                    statuses.len(),
                    funcs.len()
                );
                // Map funcs back to request order: functions correspond to statuses==0 in order
                let mut fidx = 0usize;
                let mut found_count = 0;
                for i in 0..statuses.len().min(slice.len()) {
                    if statuses[i] == 0 {
                        if let Some((pop, len, name, data)) = funcs.get(fidx).cloned() {
                            results[start + i] = Some((pop, len, name, data));
                            found_count += 1;
                        }
                        fidx = fidx.saturating_add(1);
                    }
                }
                debug!("upstream: mapped {} functions to results", found_count);
                METRICS.inc_upstream_fetched(found_count as u64);
            }
            Err(e) => {
                METRICS.inc_upstream_errors();
                warn!("upstream decode pull result failed: {:?}", e);
            }
        }

        start = end;
    }

    Ok(results)
}
