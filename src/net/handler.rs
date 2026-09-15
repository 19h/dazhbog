//! Client connection handler.
//!
//! Handles the main request/response loop for connected clients,
//! supporting both Lumina and RPC protocols.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::*;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::api::metrics::METRICS;
use crate::common::hash::hex_dump;
use crate::config::Config;
use crate::db::semantic::is_rejected_function_name;
use crate::db::Database;
use crate::protocol::lumina::{self, LuminaCaps};
use crate::protocol::rpc::{
    decode_del, decode_hello, decode_hist, decode_pull, decode_push, encode_del_ok, encode_fail,
    encode_hello_ok, encode_hist_ok, encode_ok, encode_pull_ok, encode_push_ok, HelloReq, PushCaps,
    MSG_DEL, MSG_HELLO, MSG_HIST, MSG_PULL, MSG_PUSH,
};

use super::budget::Budget;
use super::frame::read_multiproto_bounded;

/// Write all bytes to the stream.
#[inline]
pub async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> io::Result<()> {
    write_all_chunked(w, buf).await
}

/// Write bytes in chunks with yield points to prevent worker thread starvation.
///
/// When writing large responses (e.g., megabytes of Lumina metadata), this function
/// breaks the write into chunks and yields to the tokio runtime between chunks.
/// This ensures that other tasks (like HTTP requests) can be processed even when
/// multiple large writes are in progress.
async fn write_all_chunked<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> io::Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

    if buf.len() <= CHUNK_SIZE {
        // Small write, no need to chunk
        return w.write_all(buf).await;
    }

    // Large write - chunk it and yield between chunks
    let mut offset = 0;
    while offset < buf.len() {
        let end = (offset + CHUNK_SIZE).min(buf.len());
        w.write_all(&buf[offset..end]).await?;
        offset = end;

        // Yield to the runtime to allow other tasks to run
        // This is critical to prevent worker thread starvation
        if offset < buf.len() {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

/// Handle a single client connection.
///
/// Performs protocol handshake and then enters the main request/response loop.
/// Supports both Lumina (IDA Pro native) and RPC (simplified) protocols.
pub async fn handle_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    cfg: Arc<Config>,
    db: Arc<Database>,
    global_budget: Arc<Budget>,
) -> io::Result<()> {
    let conn_budget = Arc::new(Budget::new(cfg.limits.per_connection_inflight_bytes));

    // Read hello frame with timeout
    let hello_frame = match timeout(
        Duration::from_millis(cfg.limits.hello_timeout_ms),
        read_multiproto_bounded(
            &mut stream,
            None,
            cfg.limits.max_hello_frame_bytes,
            &conn_budget,
            &global_budget,
        ),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            METRICS
                .timeouts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
    };

    let hello_bytes = hello_frame.as_slice();
    debug!("Received hello message, {} bytes", hello_bytes.len());

    if log_enabled!(log::Level::Debug) {
        debug!("Hello frame hex dump:\n{}", hex_dump(hello_bytes, 256));
    }

    if hello_bytes.is_empty() {
        write_all(&mut stream, &encode_fail(0, "bad sequence")).await?;
        return Ok(());
    }

    let msg_type = hello_bytes[0];
    let payload = &hello_bytes[1..];

    const LUMINA_MSG_HELLO: u8 = 0x0d;
    let is_lumina = msg_type == LUMINA_MSG_HELLO;

    // Debug: dump hello message to file if enabled (only for Lumina protocol)
    if cfg.debug.dump_hello && is_lumina {
        if let Ok(raw) = lumina::parse_lumina_hello_raw(payload) {
            // Only dump if license is at least 128 bytes
            if raw.key.len() >= 128 {
                use std::io::Write;
                let hash = {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut hasher = DefaultHasher::new();
                    raw.key.hash(&mut hasher);
                    hasher.finish()
                };
                let filename = format!("{:016x}.txt", hash);
                let path = std::path::Path::new(&cfg.debug.dump_hello_dir).join(&filename);
                if let Err(e) = std::fs::create_dir_all(&cfg.debug.dump_hello_dir) {
                    warn!("Failed to create dump directory: {}", e);
                } else if let Ok(mut f) = std::fs::File::create(&path) {
                    let id_hex = raw
                        .license_id
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                    let content = format!(
                        "ID: {}\n\nLicense:\n\n{}\n\nCredentials: {} / {}\n",
                        id_hex,
                        String::from_utf8_lossy(&raw.key),
                        raw.username,
                        raw.password
                    );
                    if let Err(e) = f.write_all(content.as_bytes()) {
                        warn!("Failed to write hello dump: {}", e);
                    } else {
                        debug!("Dumped hello message to {:?}", path);
                    }
                }
            }
        }
    }

    // Parse hello message based on protocol
    let hello = if is_lumina {
        debug!("Detected Lumina Hello message (0x0d)");
        match lumina::parse_lumina_hello(payload) {
            Ok(v) => {
                let read_only = v.is_readonly();
                HelloReq {
                    protocol_version: v.protocol_version,
                    username: v.username,
                    password: v.password,
                    read_only,
                }
            }
            Err(e) => {
                error!("Failed to parse Lumina Hello: {}", e);
                write_all(&mut stream, &encode_fail(0, "invalid hello")).await?;
                return Ok(());
            }
        }
    } else if msg_type == MSG_HELLO {
        debug!("Detected new Hello message (0x01)");
        match decode_hello(payload) {
            Ok(v) => v,
            Err(_) => {
                write_all(&mut stream, &encode_fail(0, "invalid hello")).await?;
                return Ok(());
            }
        }
    } else {
        error!("Unknown Hello message type: 0x{:02x}", msg_type);
        write_all(&mut stream, &encode_fail(0, "bad sequence")).await?;
        return Ok(());
    };

    debug!(
        "Hello request: protocol_version={}, username={}",
        hello.protocol_version, hello.username
    );

    // Track protocol version metrics
    if hello.protocol_version <= 4 {
        METRICS
            .lumina_v0_4
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        METRICS
            .lumina_v5p
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    // Validate credentials
    if hello.username != "guest" {
        let msg = format!(
            "{}: invalid username or password. Try logging in with `guest` instead.",
            cfg.lumina.server_name
        );
        if is_lumina {
            lumina::send_lumina_fail(&mut stream, 1, &msg).await?;
        } else {
            write_all(&mut stream, &encode_fail(1, &msg)).await?;
        }
        return Ok(());
    }

    let read_only = hello.read_only;
    if read_only {
        info!(
            "Read-only session: client presented READONLY_LICENSE_ID (all mutations will be suppressed)"
        );
    }

    // Send hello response
    if is_lumina {
        if hello.protocol_version <= 4 {
            lumina::send_lumina_ok(&mut stream).await?;
        } else {
            let mut features = 0u32;
            if cfg.lumina.allow_deletes {
                features |= 0x02;
            }
            lumina::send_lumina_hello_result(&mut stream, features).await?;
        }
    } else {
        if hello.protocol_version <= 4 {
            write_all(&mut stream, &encode_ok()).await?;
        } else {
            let mut features = 0u32;
            if cfg.lumina.allow_deletes {
                features |= 0x02;
            }
            write_all(&mut stream, &encode_hello_ok(features)).await?;
        }
    }

    // Main request/response loop
    loop {
        let frame = if is_lumina {
            match timeout(
                Duration::from_millis(cfg.limits.command_timeout_ms),
                read_multiproto_bounded(
                    &mut stream,
                    Some(true),
                    cfg.limits.max_cmd_frame_bytes,
                    &conn_budget,
                    &global_budget,
                ),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => {
                    error!("read error: {}", e);
                    return Ok(());
                }
                Err(_) => {
                    METRICS
                        .timeouts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    lumina::send_lumina_fail(
                        &mut stream,
                        0,
                        &format!("{} client idle for too long.\n", cfg.lumina.server_name),
                    )
                    .await
                    .ok();
                    return Ok(());
                }
            }
        } else {
            match timeout(
                Duration::from_millis(cfg.limits.command_timeout_ms),
                read_multiproto_bounded(
                    &mut stream,
                    Some(false),
                    cfg.limits.max_cmd_frame_bytes,
                    &conn_budget,
                    &global_budget,
                ),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => {
                    error!("read error: {}", e);
                    return Ok(());
                }
                Err(_) => {
                    METRICS
                        .timeouts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    write_all(
                        &mut stream,
                        &encode_fail(
                            0,
                            &format!("{} client idle for too long.\n", cfg.lumina.server_name),
                        ),
                    )
                    .await
                    .ok();
                    return Ok(());
                }
            }
        };

        let frame_bytes = frame.as_slice();

        if frame_bytes.is_empty() {
            let msg = format!("{}: error: invalid data.\n", cfg.lumina.server_name);
            if is_lumina {
                lumina::send_lumina_fail(&mut stream, 0, &msg).await?;
            } else {
                write_all(&mut stream, &encode_fail(0, &msg)).await?;
            }
            continue;
        }

        let typ = frame_bytes[0];
        let pld = &frame_bytes[1..];

        debug!(
            "Incoming message: type=0x{:02x}, payload_size={}",
            typ,
            pld.len()
        );

        if is_lumina {
            handle_lumina_command(&mut stream, &cfg, &db, typ, pld, read_only).await?;
        } else {
            handle_rpc_command(&mut stream, &cfg, &db, typ, pld, read_only).await?;
        }
    }
}

/// Handle a Lumina protocol command.
async fn handle_lumina_command<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    typ: u8,
    pld: &[u8],
    read_only: bool,
) -> io::Result<()> {
    debug!("Lumina command received: 0x{:02x}", typ);

    match typ {
        0x0e => handle_lumina_pull(stream, cfg, db, pld).await,
        0x10 => handle_lumina_push(stream, cfg, db, pld, read_only).await,
        0x12 => handle_lumina_get_pop(stream, cfg, db, pld).await,
        0x18 => handle_lumina_del(stream, cfg, read_only).await,
        0x2b => handle_lumina_info(stream, cfg).await,
        0x2d => handle_lumina_stats(stream, cfg, db).await,
        0x2f => handle_lumina_hist(stream, cfg, db, pld).await,
        _ => {
            warn!("Unknown Lumina command: 0x{:02x}", typ);
            lumina::send_lumina_fail(
                stream,
                0,
                &format!("{}: Unknown command.", cfg.lumina.server_name),
            )
            .await
        }
    }
}

/// Handle Lumina PullMetadata (0x0e) command.
async fn handle_lumina_pull<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
) -> io::Result<()> {
    let caps = LuminaCaps {
        max_funcs: cfg.limits.max_pull_items,
        max_name_bytes: cfg.limits.max_name_bytes,
        max_data_bytes: cfg.limits.max_data_bytes,
        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
    };

    let pull_msg = match lumina::parse_lumina_pull_metadata(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina PullMetadata: {}", e);
            return lumina::send_lumina_fail(stream, 0, "invalid pull").await;
        }
    };

    // Collect keys in request order
    let mut keys: Vec<u128> = Vec::with_capacity(pull_msg.funcs.len());
    for func in &pull_msg.funcs {
        if func.mb_hash.len() != 16 {
            keys.push(0);
        } else {
            let key = u128::from_be_bytes([
                func.mb_hash[0],
                func.mb_hash[1],
                func.mb_hash[2],
                func.mb_hash[3],
                func.mb_hash[4],
                func.mb_hash[5],
                func.mb_hash[6],
                func.mb_hash[7],
                func.mb_hash[8],
                func.mb_hash[9],
                func.mb_hash[10],
                func.mb_hash[11],
                func.mb_hash[12],
                func.mb_hash[13],
                func.mb_hash[14],
                func.mb_hash[15],
            ]);
            keys.push(key);
        }
    }

    let qctx = crate::db::QueryContext {
        keys: &keys,
        requested_mdkeys: &pull_msg.keys,
        md5: None,
        basename: None,
        hostname: None,
        origin_token: None,
    };
    let selected = match db.select_versions_for_batch(&qctx).await {
        Ok(v) => v,
        Err(e) => {
            error!("scoring error: {}", e);
            // Fallback to legacy latest-per-key
            let mut v = Vec::with_capacity(keys.len());
            for &k in &keys {
                v.push(db.get_latest(k).await.ok().flatten().map(|f| {
                    let data =
                        crate::db::semantic::shape_metadata_for_request(&f.data, &pull_msg.keys);
                    let data = if pull_msg.keys.is_empty() {
                        f.data
                    } else {
                        data
                    };
                    (f.popularity, data.len() as u32, f.name, data)
                }));
            }
            v
        }
    };

    let mut maybe_funcs: Vec<Option<(u32, u32, String, Vec<u8>)>> = selected;
    let mut statuses: Vec<u32> = maybe_funcs
        .iter()
        .map(|o| if o.is_some() { 0 } else { 0xFFFFFFFE })
        .collect();

    METRICS.inc_queried_funcs(keys.len() as u64);

    // Upstream fetch for remaining misses
    if !cfg.upstreams.is_empty() {
        let mut missing_keys = Vec::new();
        let mut missing_pos = Vec::new();
        for (i, (&k, st)) in keys.iter().zip(statuses.iter()).enumerate() {
            if k != 0 && *st == 0xFFFFFFFE {
                missing_keys.push(k);
                missing_pos.push(i);
            }
        }
        if !missing_keys.is_empty() {
            match crate::db::upstream::fetch_from_upstreams(&cfg.upstreams, &missing_keys).await {
                Ok(fetched) => {
                    let mut new_inserts_owned: Vec<(u128, u32, u32, String, Vec<u8>)> = Vec::new();
                    for (j, item) in fetched.into_iter().enumerate() {
                        let idx = missing_pos[j];
                        if let Some((pop, len, name, data)) = item {
                            if is_rejected_function_name(&name) {
                                debug!(
                                    "upstream returned rejected generated name '{}' for key {:032x}; treating as missing",
                                    name,
                                    missing_keys[j]
                                );
                                continue;
                            }
                            statuses[idx] = 0;
                            new_inserts_owned.push((
                                missing_keys[j],
                                pop,
                                len,
                                name.clone(),
                                data.clone(),
                            ));
                            let shaped = crate::db::semantic::shape_metadata_for_request(&data, &pull_msg.keys);
                            maybe_funcs[idx] = Some((pop, shaped.len() as u32, name, shaped));

                        }
                    }
                    // Always cache upstream results locally — even for read-only sessions.
                    // db.push() uses a null context so no client-relationship records are
                    // created; this just caches the raw function metadata to avoid
                    // hammering the upstream on subsequent requests.
                    let new_inserts: Vec<(u128, u32, u32, &str, &[u8])> = new_inserts_owned
                        .iter()
                        .map(|(k, p, l, n, d)| (*k, *p, *l, n.as_str(), d.as_slice()))
                        .collect();
                    if !new_inserts.is_empty() {
                        match db.push(&new_inserts).await {
                            Ok(st) => {
                                let new_funcs = st.iter().filter(|&&v| v == 1).count() as u64;
                                let updated_funcs = st.iter().filter(|&&v| v == 0).count() as u64;
                                METRICS.inc_pushes(new_funcs + updated_funcs);
                                METRICS.inc_new_funcs(new_funcs);
                            }
                            Err(e) => {
                                error!("db push after upstream: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("upstream pull failed: {}", e);
                }
            }
        }
    }

    let mut found_list = Vec::new();
    for it in maybe_funcs.into_iter() {
        if let Some(v) = it {
            found_list.push(v);
        }
    }

    METRICS.inc_pulls(found_list.len() as u64);
    debug!(
        "Lumina PULL response: {} found, {} not found",
        found_list.len(),
        statuses.iter().filter(|&&s| s == 0xFFFFFFFE).count()
    );
    lumina::send_lumina_pull_result(stream, &statuses, &found_list).await
}

/// Handle Lumina PushMetadata (0x10) command.
async fn handle_lumina_push<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
    read_only: bool,
) -> io::Result<()> {
    let caps = LuminaCaps {
        max_funcs: cfg.limits.max_push_items,
        max_name_bytes: cfg.limits.max_name_bytes,
        max_data_bytes: cfg.limits.max_data_bytes,
        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
    };

    let push_msg = match lumina::parse_lumina_push_metadata(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina PushMetadata: {}", e);
            return lumina::send_lumina_fail(stream, 0, "invalid push").await;
        }
    };

    debug!("Lumina PUSH request: {} items", push_msg.funcs.len());

    // Read-only sessions: accept the push message but discard it.
    // Return all-zeros status (every item "unchanged") so the client doesn't retry.
    if read_only {
        debug!(
            "Read-only session: suppressing push of {} items",
            push_msg.funcs.len()
        );
        let fake_status: Vec<u32> = vec![0; push_msg.funcs.len()];
        return lumina::send_lumina_push_result(stream, &fake_status).await;
    }

    // Print push request metadata
    println!("\n=== PUSH REQUEST ===");
    println!("IDB Path:     {}", push_msg.idb_path);
    println!("File Path:    {}", push_msg.file_path);
    println!(
        "MD5:          {}",
        push_msg
            .md5
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!("Functions:    {}", push_msg.funcs.len());
    println!("===================\n");

    let mut inlined: Vec<(u128, u32, u32, &str, &[u8])> = Vec::with_capacity(push_msg.funcs.len());
    for func in &push_msg.funcs {
        if func.hash.len() != 16 {
            error!("Invalid hash length: {}", func.hash.len());
            continue;
        }
        let key = u128::from_be_bytes([
            func.hash[0],
            func.hash[1],
            func.hash[2],
            func.hash[3],
            func.hash[4],
            func.hash[5],
            func.hash[6],
            func.hash[7],
            func.hash[8],
            func.hash[9],
            func.hash[10],
            func.hash[11],
            func.hash[12],
            func.hash[13],
            func.hash[14],
            func.hash[15],
        ]);
        inlined.push((key, 0, func.func_len, &func.name, &func.func_data));
    }

    // Extract binary context
    let basename = std::path::Path::new(&push_msg.file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let origin_token =
        crate::db::semantic::normalize_origin_token(if push_msg.idb_path.is_empty() {
            &push_msg.file_path
        } else {
            &push_msg.idb_path
        });
    let ctx = crate::db::PushContext {
        md5: Some(push_msg.md5),
        basename: Some(basename),
        hostname: Some(push_msg.hostname.as_str()),
        origin_token: Some(origin_token.as_str()),
    };

    match db.push_with_ctx(&inlined, &ctx).await {
        Ok(status) => {
            let new_funcs = status.iter().filter(|&&v| v == 1).count() as u64;
            let updated_funcs = status.iter().filter(|&&v| v == 0).count() as u64;
            let skipped_funcs = status.iter().filter(|&&v| v == 2).count() as u64;

            METRICS.inc_pushes(new_funcs + updated_funcs);
            METRICS.inc_new_funcs(new_funcs);

            debug!(
                "Lumina PUSH response: {} new, {} updated, {} unchanged",
                new_funcs, updated_funcs, skipped_funcs
            );

            let lumina_status: Vec<u32> =
                status.iter().map(|&s| if s == 2 { 0 } else { 1 }).collect();
            lumina::send_lumina_push_result(stream, &lumina_status).await
        }
        Err(e) => {
            error!("db push: {}", e);
            lumina::send_lumina_fail(
                stream,
                0,
                &format!(
                    "{}: db error; please try again later",
                    cfg.lumina.server_name
                ),
            )
            .await
        }
    }
}

/// Handle Lumina GetPop (0x12) command.
async fn handle_lumina_get_pop<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    _cfg: &Config,
    db: &Database,
    pld: &[u8],
) -> io::Result<()> {
    // pkt_get_pop_t parses exactly one varint `nresults`
    let (nresults, _) = lumina::unpack_dd(pld);
    let limit = (nresults as usize).clamp(1, 1000);
    debug!("Lumina GET_POP request: {} results", limit);

    match db.get_popular_functions(limit).await {
        Ok(results) => {
            // Map db results to (name, size, metadata, type, pattern, freq, host, path, md5, ea)
            // But we don't store ea64, md5, or host per popular function currently easily in index,
            // so we might need to send empty/dummy values for the pop-specific fields, or fetch them.
            // For now, we'll send dummy context info if needed, or query it.
            let mapped: Vec<_> = results
                .into_iter()
                .map(|f| {
                    (
                        f.name,
                        f.len_bytes,
                        f.data,
                        0,          // pattern_type unknown
                        Vec::new(), // pattern data
                        f.popularity,
                        String::new(), // hostname
                        String::new(), // path
                        [0u8; 16],     // md5
                        0u64,          // ea64
                    )
                })
                .collect();
            lumina::send_lumina_pop_result(stream, &mapped).await
        }
        Err(e) => {
            error!("get_popular failed: {}", e);
            lumina::send_lumina_fail(stream, 0, "db error").await
        }
    }
}

/// Handle Lumina GetInfo (0x2b) command.
async fn handle_lumina_info<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    _cfg: &Config,
) -> io::Result<()> {
    debug!("Lumina GET_INFO request");

    // Hardcode a default MAC and version if needed
    let start_time = METRICS
        .start_time
        .load(std::sync::atomic::Ordering::Relaxed);
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    lumina::send_lumina_info_result(
        stream,
        "00:00:00:00:00:00",
        &format!("dazhbog-{}", env!("CARGO_PKG_VERSION")),
        start_time,
        current_time,
    )
    .await
}

/// Handle Lumina GetStats (0x2d) command.
async fn handle_lumina_stats<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    _db: &Database,
) -> io::Result<()> {
    debug!("Lumina GET_STATS request");

    // Gather stats
    let nfuncs = METRICS
        .total_records
        .load(std::sync::atomic::Ordering::Relaxed);
    let npushes = METRICS.pushes.load(std::sync::atomic::Ordering::Relaxed);
    let nidbs = METRICS
        .unique_binaries
        .load(std::sync::atomic::Ordering::Relaxed);

    let mut user = lumina::LuminaUser::default();
    user.name = "global".to_string();
    if cfg.lumina.allow_deletes {
        user.features = 0x2; // UF_CAN_DEL_HISTORY
    }

    let stats = vec![lumina::LuminaStats {
        user,
        nfuncs,
        npushes,
        nhist_recs: nfuncs, // Rough estimate
        nidbs,
        ninput_files: nidbs,
    }];

    lumina::send_lumina_stats_result(stream, &stats).await
}

/// Handle Lumina DelHistory (0x18) command.
async fn handle_lumina_del<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    read_only: bool,
) -> io::Result<()> {
    if read_only || !cfg.lumina.allow_deletes {
        if read_only {
            debug!("Read-only session: rejecting delete request");
        }
        return lumina::send_lumina_fail(
            stream,
            2,
            &format!(
                "{}: Delete command is disabled on this server.",
                cfg.lumina.server_name
            ),
        )
        .await;
    }
    debug!("Lumina DEL request (not fully implemented)");
    lumina::send_lumina_del_result(stream, 0).await
}

/// Handle Lumina GetFuncHistories (0x2f) command.
async fn handle_lumina_hist<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
) -> io::Result<()> {
    let caps = LuminaCaps {
        max_funcs: cfg.limits.max_hist_items,
        max_name_bytes: cfg.limits.max_name_bytes,
        max_data_bytes: cfg.limits.max_data_bytes,
        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
    };

    let hist_msg = match lumina::parse_lumina_get_func_histories(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina GetFuncHistories: {}", e);
            return lumina::send_lumina_fail(stream, 0, "invalid hist").await;
        }
    };

    debug!("Lumina HIST request: {} keys", hist_msg.funcs.len());

    let limit = if cfg.lumina.get_history_limit == 0 {
        0
    } else {
        cfg.lumina.get_history_limit
    };
    if limit == 0 {
        return lumina::send_lumina_fail(
            stream,
            4,
            &format!(
                "{}: function histories are disabled on this server.",
                cfg.lumina.server_name
            ),
        )
        .await;
    }

    let mut statuses = Vec::new();
    let mut histories = Vec::new();

    for func in &hist_msg.funcs {
        if func.mb_hash.len() != 16 {
            statuses.push(0);
            continue;
        }
        let key = u128::from_be_bytes([
            func.mb_hash[0],
            func.mb_hash[1],
            func.mb_hash[2],
            func.mb_hash[3],
            func.mb_hash[4],
            func.mb_hash[5],
            func.mb_hash[6],
            func.mb_hash[7],
            func.mb_hash[8],
            func.mb_hash[9],
            func.mb_hash[10],
            func.mb_hash[11],
            func.mb_hash[12],
            func.mb_hash[13],
            func.mb_hash[14],
            func.mb_hash[15],
        ]);

        match db.get_history(key, limit).await {
            Ok(hist) if !hist.is_empty() => {
                statuses.push(1);
                let hist_tuples: Vec<(u64, String, Vec<u8>)> = hist
                    .into_iter()
                    .map(|(ts, name, data)| (ts as u64, name, data))
                    .collect();
                histories.push(hist_tuples);
            }
            Ok(_) => {
                statuses.push(0);
            }
            Err(e) => {
                error!("db hist: {}", e);
                return lumina::send_lumina_fail(
                    stream,
                    3,
                    &format!("{}: db error", cfg.lumina.server_name),
                )
                .await;
            }
        }
    }

    debug!("Lumina HIST response: {} histories found", histories.len());
    lumina::send_lumina_histories_result(stream, &statuses, &histories).await
}

/// Handle an RPC protocol command.
async fn handle_rpc_command<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    typ: u8,
    pld: &[u8],
    read_only: bool,
) -> io::Result<()> {
    let msg_start = Instant::now();

    match typ {
        MSG_PULL => handle_rpc_pull(stream, cfg, db, pld, msg_start).await,
        MSG_PUSH => handle_rpc_push(stream, cfg, db, pld, msg_start, read_only).await,
        MSG_DEL => handle_rpc_del(stream, cfg, db, pld, msg_start, read_only).await,
        MSG_HIST => handle_rpc_hist(stream, cfg, db, pld, msg_start).await,
        _ => {
            debug!(
                "Unknown message type: 0x{:02x}, payload size: {} (took {:?})",
                typ,
                pld.len(),
                msg_start.elapsed()
            );
            if log_enabled!(log::Level::Debug) && !pld.is_empty() {
                debug!("Unknown message payload hex dump:\n{}", hex_dump(pld, 256));
            }
            write_all(
                stream,
                &encode_fail(0, &format!("{}: invalid data.\n", cfg.lumina.server_name)),
            )
            .await
        }
    }
}

/// Handle RPC PULL command.
async fn handle_rpc_pull<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
    msg_start: Instant,
) -> io::Result<()> {
    let keys = match decode_pull(pld, cfg.limits.max_pull_items) {
        Ok(v) => v,
        Err(e) => {
            error!("decode_pull: {:?}", e);
            return write_all(stream, &encode_fail(0, "invalid pull")).await;
        }
    };

    debug!("PULL request: {} keys", keys.len());
    METRICS.inc_queried_funcs(keys.len() as u64);

    let empty_requested_mdkeys: [u32; 0] = [];
    let qctx = crate::db::QueryContext {
        keys: &keys,
        requested_mdkeys: &empty_requested_mdkeys,
        md5: None,
        basename: None,
        hostname: None,
        origin_token: None,
    };
    let selected = match db.select_versions_for_batch(&qctx).await {
        Ok(v) => v,
        Err(e) => {
            error!("scoring error: {}", e);
            let mut v = Vec::with_capacity(keys.len());
            for &k in &keys {
                v.push(
                    db.get_latest(k)
                        .await
                        .ok()
                        .flatten()
                        .map(|f| (f.popularity, f.len_bytes, f.name, f.data)),
                );
            }
            v
        }
    };

    let mut maybe_funcs: Vec<Option<(u32, u32, String, Vec<u8>)>> = selected;
    let mut statuses: Vec<u32> = maybe_funcs
        .iter()
        .map(|o| if o.is_some() { 0 } else { 0xFFFFFFFE })
        .collect();

    // Upstream fetch for misses
    if !cfg.upstreams.is_empty() {
        let mut missing_keys = Vec::new();
        let mut missing_pos = Vec::new();
        for (i, (&k, st)) in keys.iter().zip(statuses.iter()).enumerate() {
            if *st == 0xFFFFFFFE {
                // Skip keys that are in the failure cache
                if !db.failure_cache.is_failed(k) {
                    missing_keys.push(k);
                    missing_pos.push(i);
                }
            }
        }
        if !missing_keys.is_empty() {
            debug!(
                "Upstream fetch: {} keys (after filtering failure cache)",
                missing_keys.len()
            );
            match crate::db::upstream::fetch_from_upstreams(&cfg.upstreams, &missing_keys).await {
                Ok(fetched) => {
                    let mut new_inserts_owned: Vec<(u128, u32, u32, String, Vec<u8>)> = Vec::new();
                    for (j, item) in fetched.into_iter().enumerate() {
                        let idx = missing_pos[j];
                        let key = missing_keys[j];
                        if let Some((pop, len, name, data)) = item {
                            if is_rejected_function_name(&name) {
                                debug!(
                                    "upstream returned rejected generated name '{}' for key {:032x}; treating as missing",
                                    name,
                                    key
                                );
                                continue;
                            }
                            statuses[idx] = 0;
                            new_inserts_owned.push((key, pop, len, name.clone(), data.clone()));
                            maybe_funcs[idx] = Some((pop, len, name, data));
                        } else {
                            // Not found in upstream - add to failure cache
                            db.failure_cache.insert(key);
                        }
                    }
                    // Always cache upstream results locally — even for read-only sessions.
                    // db.push() uses a null context so no client-relationship records are
                    // created; this just caches the raw function metadata to avoid
                    // hammering the upstream on subsequent requests.
                    let new_inserts: Vec<(u128, u32, u32, &str, &[u8])> = new_inserts_owned
                        .iter()
                        .map(|(k, p, l, n, d)| (*k, *p, *l, n.as_str(), d.as_slice()))
                        .collect();
                    if !new_inserts_owned.is_empty() {
                        match db.push(&new_inserts).await {
                            Ok(st) => {
                                let new_funcs = st.iter().filter(|&&v| v == 1).count() as u64;
                                let updated_funcs = st.iter().filter(|&&v| v == 0).count() as u64;
                                METRICS.inc_pushes(new_funcs + updated_funcs);
                                METRICS.inc_new_funcs(new_funcs);
                            }
                            Err(e) => {
                                error!("db push after upstream: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("upstream pull failed: {}", e);
                }
            }
        }
    }

    let mut found = Vec::new();
    for it in maybe_funcs.into_iter() {
        if let Some(v) = it {
            found.push(v);
        }
    }

    METRICS.inc_pulls(found.len() as u64);
    debug!(
        "PULL response: {} found, {} not found (took {:?})",
        found.len(),
        statuses.iter().filter(|&&s| s == 0xFFFFFFFE).count(),
        msg_start.elapsed()
    );
    write_all(stream, &encode_pull_ok(&statuses, &found)).await
}

/// Handle RPC PUSH command.
async fn handle_rpc_push<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
    msg_start: Instant,
    read_only: bool,
) -> io::Result<()> {
    let caps = PushCaps {
        max_items: cfg.limits.max_push_items,
        max_name_bytes: cfg.limits.max_name_bytes,
        max_data_bytes: cfg.limits.max_data_bytes,
    };

    let items = match decode_push(pld, &caps) {
        Ok(v) => v,
        Err(e) => {
            error!("decode_push: {:?}", e);
            return write_all(stream, &encode_fail(0, "invalid push")).await;
        }
    };

    debug!("PUSH request: {} items", items.len());

    // Read-only sessions: accept the push message but discard it.
    // Return all-unchanged statuses so the client doesn't retry.
    if read_only {
        debug!(
            "Read-only session: suppressing push of {} items (took {:?})",
            items.len(),
            msg_start.elapsed()
        );
        let fake_status: Vec<u32> = vec![2; items.len()];
        return write_all(stream, &encode_push_ok(&fake_status)).await;
    }

    if log_enabled!(log::Level::Debug) {
        for (i, item) in items.iter().enumerate().take(5) {
            debug!(
                "  Item[{}]: key=0x{:032x}, pop={}, len={}, name='{}'",
                i, item.key, item.popularity, item.len_bytes, item.name
            );
            debug!("    Data hex dump:\n{}", hex_dump(&item.data, 128));
        }
        if items.len() > 5 {
            debug!("  ... and {} more items", items.len() - 5);
        }
    }

    let mut inlined: Vec<(u128, u32, u32, &str, &[u8])> = Vec::with_capacity(items.len());
    for it in &items {
        inlined.push((it.key, it.popularity, it.len_bytes, &it.name, &it.data));
    }

    let res = db.push(&inlined).await;

    match res {
        Ok(status) => {
            let new_funcs = status.iter().filter(|&&v| v == 1).count() as u64;
            let updated_funcs = status.iter().filter(|&&v| v == 0).count() as u64;
            let skipped_funcs = status.iter().filter(|&&v| v == 2).count() as u64;
            METRICS.inc_pushes(new_funcs + updated_funcs);
            METRICS.inc_new_funcs(new_funcs);

            // Remove successfully pushed keys from failure cache
            for it in &items {
                db.failure_cache.remove(it.key);
            }

            debug!(
                "PUSH response: {} new, {} updated, {} unchanged (took {:?})",
                new_funcs,
                updated_funcs,
                skipped_funcs,
                msg_start.elapsed()
            );
            write_all(stream, &encode_push_ok(&status)).await
        }
        Err(e) => {
            error!("db push: {}", e);
            write_all(
                stream,
                &encode_fail(
                    0,
                    &format!(
                        "{}: db error; please try again later..\n",
                        cfg.lumina.server_name
                    ),
                ),
            )
            .await
        }
    }
}

/// Handle RPC DEL command.
async fn handle_rpc_del<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
    msg_start: Instant,
    read_only: bool,
) -> io::Result<()> {
    if read_only || !cfg.lumina.allow_deletes {
        if read_only {
            debug!("Read-only session: rejecting delete request");
        }
        return write_all(
            stream,
            &encode_fail(
                2,
                &format!(
                    "{}: Delete command is disabled on this server.",
                    cfg.lumina.server_name
                ),
            ),
        )
        .await;
    }

    let keys = match decode_del(pld, cfg.limits.max_del_items) {
        Ok(v) => v,
        Err(e) => {
            error!("decode_del: {:?}", e);
            return write_all(stream, &encode_fail(0, "invalid del")).await;
        }
    };

    debug!("DEL request: {} keys", keys.len());

    match db.delete_keys(&keys).await {
        Ok(n) => {
            debug!(
                "DEL response: {} keys deleted (took {:?})",
                n,
                msg_start.elapsed()
            );
            write_all(stream, &encode_del_ok(n)).await
        }
        Err(e) => {
            error!("db del: {}", e);
            write_all(
                stream,
                &encode_fail(
                    3,
                    &format!(
                        "{}: db error, please try again later.",
                        cfg.lumina.server_name
                    ),
                ),
            )
            .await
        }
    }
}

/// Handle RPC HIST command.
async fn handle_rpc_hist<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
    msg_start: Instant,
) -> io::Result<()> {
    let (limit_req, keys) = match decode_hist(pld, cfg.limits.max_hist_items) {
        Ok(v) => v,
        Err(e) => {
            error!("decode_hist: {:?}", e);
            return write_all(stream, &encode_fail(0, "invalid hist")).await;
        }
    };

    debug!("HIST request: limit={}, {} keys", limit_req, keys.len());

    let limit = if cfg.lumina.get_history_limit == 0 {
        0
    } else {
        cfg.lumina.get_history_limit.min(limit_req)
    };
    if limit == 0 {
        return write_all(
            stream,
            &encode_fail(
                4,
                &format!(
                    "{}: function histories are disabled on this server.",
                    cfg.lumina.server_name
                ),
            ),
        )
        .await;
    }

    let mut statuses = Vec::with_capacity(keys.len());
    let mut logs = Vec::new();

    for k in keys {
        match db.get_history(k, limit).await {
            Ok(v) if !v.is_empty() => {
                statuses.push(1);
                logs.push(v);
            }
            Ok(_) => {
                statuses.push(0);
            }
            Err(e) => {
                error!("db hist: {}", e);
                return write_all(
                    stream,
                    &encode_fail(
                        3,
                        &format!(
                            "{}: db error, please try again later.",
                            cfg.lumina.server_name
                        ),
                    ),
                )
                .await;
            }
        }
    }

    let found_histories = logs.len();
    debug!(
        "HIST response: {} histories found (took {:?})",
        found_histories,
        msg_start.elapsed()
    );
    write_all(stream, &encode_hist_ok(&statuses, &logs)).await
}
