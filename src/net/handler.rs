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
use crate::db::Database;
use crate::protocol::lumina::{self, LuminaCaps, LuminaOpRes};
use crate::protocol::rpc::{
    decode_del, decode_hello, decode_hist, decode_pull, decode_push, encode_del_ok, encode_fail,
    encode_hello_ok, encode_hist_ok, encode_ok, encode_pull_ok, encode_push_ok, HelloReq, PushCaps,
    MSG_DEL, MSG_HELLO, MSG_HIST, MSG_PULL, MSG_PUSH,
};

use super::budget::Budget;

type FunctionPayload = (u32, u32, String, Vec<u8>);
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
                lumina::send_lumina_fail(&mut stream, lumina::RPC_FAIL_RESULT, "invalid hello")
                    .await?;
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

    // The reference refuses clients newer than its own protocol version.
    if hello.protocol_version > lumina::PROTOCOL_VERSION {
        let msg = format!(
            "This server doesn't support version {}",
            hello.protocol_version
        );
        if is_lumina {
            lumina::send_lumina_fail(&mut stream, lumina::RPC_FAIL_RESULT, &msg).await?;
        } else {
            write_all(&mut stream, &encode_fail(1, &msg)).await?;
        }
        return Ok(());
    }

    // Validate credentials. The reference noauth server accepts any username;
    // IDA sends an empty one unless `user@host` was configured.
    let username_ok =
        cfg.lumina.accept_any_username || hello.username.is_empty() || hello.username == "guest";
    if !username_ok {
        let msg = format!(
            "{}: invalid username or password. Try logging in with `guest` instead.",
            cfg.lumina.server_name
        );
        if is_lumina {
            lumina::send_lumina_fail(&mut stream, lumina::RPC_FAIL_RESULT, &msg).await?;
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

    // Send hello response. `helo_result` exists since protocol version 5.
    let mut features = 0u32;
    if cfg.lumina.allow_deletes && !read_only {
        features |= lumina::UF_CAN_DEL_HISTORY;
    }
    if is_lumina {
        if hello.protocol_version <= 4 {
            lumina::send_lumina_ok(&mut stream).await?;
        } else {
            lumina::send_lumina_hello_result(&mut stream, features).await?;
        }
    } else if hello.protocol_version <= 4 {
        write_all(&mut stream, &encode_ok()).await?;
    } else {
        write_all(&mut stream, &encode_hello_ok(features)).await?;
    }

    // Main request/response loop
    loop {
        if METRICS
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
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
        0x18 => handle_lumina_del(stream, cfg, db, pld, read_only).await,
        0x2b => handle_lumina_info(stream, cfg).await,
        0x2d => handle_lumina_stats(stream, cfg, db).await,
        0x2f => handle_lumina_hist(stream, cfg, db, pld).await,
        _ => {
            warn!("Unknown Lumina command: 0x{:02x}", typ);
            lumina::send_lumina_fail(
                stream,
                lumina::RPC_FAIL_RESULT,
                &format!("Unhandled packet type: {}", typ),
            )
            .await
        }
    }
}

fn lumina_caps(cfg: &Config, max_funcs: usize) -> LuminaCaps {
    LuminaCaps {
        max_funcs,
        max_name_bytes: cfg.limits.max_name_bytes,
        max_data_bytes: cfg.limits.max_data_bytes,
        max_cstr_bytes: cfg.limits.lumina_max_cstr_bytes,
        max_hash_bytes: cfg.limits.lumina_max_hash_bytes,
    }
}

/// Resolve `keys` locally, then from upstreams for the misses; `slots` receives
/// the payload per key position. Shared by the Lumina and RPC pull paths.
async fn resolve_pull_keys(
    cfg: &Config,
    db: &Database,
    keys: &[u128],
    requested_mdkeys: &[u32],
) -> Vec<Option<FunctionPayload>> {
    let qctx = crate::db::QueryContext {
        keys,
        requested_mdkeys,
        md5: None,
        basename: None,
        hostname: None,
        origin_token: None,
    };
    let mut slots: Vec<Option<FunctionPayload>> = match db.select_versions_for_batch(&qctx).await {
        Ok(v) => v,
        Err(e) => {
            error!("scoring error: {}", e);
            // Fallback to legacy latest-per-key
            let mut v = Vec::with_capacity(keys.len());
            for &k in keys {
                v.push(db.get_latest(k).await.ok().flatten().map(|f| {
                    let data = if requested_mdkeys.is_empty() {
                        f.data
                    } else {
                        crate::db::semantic::shape_metadata_for_request(&f.data, requested_mdkeys)
                    };
                    (f.popularity, f.len_bytes, f.name, data)
                }));
            }
            v
        }
    };

    METRICS.inc_queried_funcs(keys.len() as u64);

    if cfg.upstreams.is_empty() {
        return slots;
    }

    let mut missing_keys = Vec::new();
    let mut missing_pos = Vec::new();
    for (i, (&k, slot)) in keys.iter().zip(slots.iter()).enumerate() {
        if slot.is_none() && !db.failure_cache.is_failed(k) {
            missing_keys.push(k);
            missing_pos.push(i);
        }
    }
    if missing_keys.is_empty() {
        return slots;
    }
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
                    if db.rejects_function_name(&name) {
                        debug!(
                            "upstream returned rejected generated name '{}' for key {:032x}; treating as missing",
                            name,
                            key
                        );
                        continue;
                    }
                    new_inserts_owned.push((key, pop, len, name.clone(), data.clone()));
                    let shaped = if requested_mdkeys.is_empty() {
                        data
                    } else {
                        crate::db::semantic::shape_metadata_for_request(&data, requested_mdkeys)
                    };
                    slots[idx] = Some((pop, len, name, shaped));
                } else {
                    db.failure_cache.insert(key);
                }
            }
            // Always cache upstream results locally, even for read-only sessions:
            // db.push() uses a null context so no client-relationship records are
            // created; this only avoids hammering the upstream again.
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
    slots
}

/// Record the versions served verbatim, keyed by what the client will hold:
/// the served name and blob. Skeleton answers carry the placeholder and are
/// refused on push anyway, so they are not recorded.
async fn note_served_versions(
    cfg: &Config,
    db: &Database,
    keys: &[u128],
    slots: &[Option<FunctionPayload>],
) {
    if !cfg.scoring.served_log {
        return;
    }
    let placeholder = cfg.scoring.skeleton_placeholder.as_str();
    let entries: Vec<(u128, [u8; 32])> = slots
        .iter()
        .zip(keys)
        .filter_map(|(slot, &key)| {
            let (_, _, name, data) = slot.as_ref()?;
            if !placeholder.is_empty() && name.contains(placeholder) {
                return None;
            }
            Some((key, crate::common::hash::version_id(key, name, data)))
        })
        .collect();
    if let Err(e) = db.note_served(entries).await {
        warn!("served log update failed: {}", e);
    }
}

/// Replace the popularity slot of each hit with the Lumina pull frequency
/// (`func_freqs.counter`), read before the increment; bump unless `seen_file`.
/// A key answered at several positions of one request is one pull: it is
/// counted once and every position receives the same value.
async fn apply_pull_frequencies(
    db: &Database,
    keys: &[u128],
    slots: &mut [Option<FunctionPayload>],
    seen_file: bool,
) {
    let mut hit_keys = Vec::new();
    let mut hit_pos: Vec<Vec<usize>> = Vec::new();
    let mut hit_index = std::collections::HashMap::new();
    for (i, slot) in slots.iter().enumerate() {
        if slot.is_some() {
            let j = *hit_index.entry(keys[i]).or_insert_with(|| {
                hit_keys.push(keys[i]);
                hit_pos.push(Vec::new());
                hit_keys.len() - 1
            });
            hit_pos[j].push(i);
        }
    }
    if hit_keys.is_empty() {
        return;
    }
    match db.note_pull_hits(&hit_keys, !seen_file).await {
        Ok(freqs) => {
            for (j, freq) in freqs.into_iter().enumerate() {
                for &i in &hit_pos[j] {
                    if let Some(slot) = slots[i].as_mut() {
                        slot.0 = freq;
                    }
                }
            }
        }
        Err(e) => warn!("pull frequency update failed: {}", e),
    }
}

/// Handle Lumina PullMetadata (0x0e) command.
async fn handle_lumina_pull<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
) -> io::Result<()> {
    let caps = lumina_caps(cfg, cfg.limits.max_pull_items);

    let pull_msg = match lumina::parse_lumina_pull_metadata(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina PullMetadata: {}", e);
            return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, "invalid pull").await;
        }
    };

    // One code per request pattern, in request order. Invalid patterns get
    // PDRES_BADPTN without a lookup; valid ones are resolved by position.
    let n = pull_msg.funcs.len();
    let mut statuses: Vec<u32> = vec![LuminaOpRes::NotFound.as_u32(); n];
    let mut keys: Vec<u128> = Vec::with_capacity(n);
    let mut key_pos: Vec<usize> = Vec::with_capacity(n);
    for (i, func) in pull_msg.funcs.iter().enumerate() {
        match func.md5_key() {
            Some(key) => {
                keys.push(key);
                key_pos.push(i);
            }
            None => statuses[i] = LuminaOpRes::BadPtn.as_u32(),
        }
    }

    let mut slots = resolve_pull_keys(cfg, db, &keys, &pull_msg.keys).await;
    let seen_file = pull_msg.flags & lumina::PULL_MD_SEEN_FILE != 0;
    apply_pull_frequencies(db, &keys, &mut slots, seen_file).await;
    note_served_versions(cfg, db, &keys, &slots).await;

    if cfg.debug.dump_pull {
        dump_pull_exchange(cfg, pld, &pull_msg, &keys, &key_pos, &slots);
    }

    let mut found_list = Vec::new();
    for (j, slot) in slots.into_iter().enumerate() {
        if let Some(payload) = slot {
            statuses[key_pos[j]] = LuminaOpRes::Ok.as_u32();
            found_list.push(payload);
        }
    }

    METRICS.inc_pulls(found_list.len() as u64);
    debug!(
        "Lumina PULL response: {} found, {} not found, {} bad patterns",
        found_list.len(),
        statuses
            .iter()
            .filter(|&&s| s == LuminaOpRes::NotFound.as_u32())
            .count(),
        statuses
            .iter()
            .filter(|&&s| s == LuminaOpRes::BadPtn.as_u32())
            .count()
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
    let caps = lumina_caps(cfg, cfg.limits.max_push_items);

    let push_msg = match lumina::parse_lumina_push_metadata(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina PushMetadata: {}", e);
            return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, "invalid push").await;
        }
    };

    // Whole-request validation, as the reference does before touching any entry.
    if let Err(msg) = lumina::validate_push(&push_msg) {
        debug!("Lumina PUSH rejected: {}", msg);
        return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, msg).await;
    }

    info!(
        "Lumina PUSH: {} functions from {} (input {}, md5 {})",
        push_msg.funcs.len(),
        push_msg.hostname,
        push_msg.file_path,
        push_msg
            .md5
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    let n = push_msg.funcs.len();
    // Read-only sessions: accept the push message but discard it.
    // Every entry reports PDRES_OK ("already present") so the client doesn't retry.
    if read_only {
        debug!("Read-only session: suppressing push of {} items", n);
        let codes = vec![LuminaOpRes::Ok.as_u32(); n];
        return lumina::send_lumina_push_result(stream, &codes).await;
    }

    let mode = push_msg.flags & lumina::PMF_PUSH_MODE_MASK;
    let do_not_override = mode == lumina::PMF_PUSH_DO_NOT_OVERRIDE;
    if mode == lumina::PMF_PUSH_MERGE {
        debug!("PMF_PUSH_MERGE requested; treated as override-if-different (reference: no-op)");
    }

    // One code per entry, in request order; invalid patterns keep their slot.
    let mut codes: Vec<u32> = vec![LuminaOpRes::Ok.as_u32(); n];
    let mut inlined: Vec<(u128, u32, u32, &str, &[u8])> = Vec::with_capacity(n);
    let mut inlined_pos: Vec<usize> = Vec::with_capacity(n);
    for (i, func) in push_msg.funcs.iter().enumerate() {
        match func.md5_key() {
            Some(key) => {
                inlined.push((key, 0, func.func_len, &func.name, &func.func_data));
                inlined_pos.push(i);
            }
            None => codes[i] = LuminaOpRes::BadPtn.as_u32(),
        }
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

    let status = if inlined.is_empty() {
        Vec::new()
    } else {
        match db.push_with_ctx_mode(&inlined, &ctx, do_not_override).await {
            Ok(status) => status,
            Err(e) => {
                error!("db push: {}", e);
                return lumina::send_lumina_fail(
                    stream,
                    lumina::RPC_FAIL_RESULT,
                    &format!(
                        "{}: db error; please try again later",
                        cfg.lumina.server_name
                    ),
                )
                .await;
            }
        }
    };

    let new_funcs = status.iter().filter(|&&v| v == 1).count() as u64;
    let updated_funcs = status.iter().filter(|&&v| v == 0).count() as u64;
    let skipped_funcs = status.iter().filter(|&&v| v == 2).count() as u64;
    METRICS.inc_pushes(new_funcs + updated_funcs);
    METRICS.inc_new_funcs(new_funcs);
    for &(key, ..) in &inlined {
        db.failure_cache.remove(key);
    }

    // Reference codes: new -> PDRES_ADDED, updated or unchanged -> PDRES_OK.
    for (j, &st) in status.iter().enumerate() {
        codes[inlined_pos[j]] = if st == 1 {
            LuminaOpRes::Added.as_u32()
        } else {
            LuminaOpRes::Ok.as_u32()
        };
    }

    debug!(
        "Lumina PUSH response: {} new, {} updated, {} unchanged, {} bad patterns",
        new_funcs,
        updated_funcs,
        skipped_funcs,
        n - inlined.len()
    );
    lumina::send_lumina_push_result(stream, &codes).await
}

/// Handle Lumina GetPop (0x12) command.
async fn handle_lumina_get_pop<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    _cfg: &Config,
    db: &Database,
    pld: &[u8],
) -> io::Result<()> {
    // pkt_get_pop_t parses exactly one varint `nresults`; the reference caps it at 100.
    let (nresults, _) = lumina::unpack_dd(pld);
    let limit = nresults.min(lumina::GET_POP_MAX_RESULTS) as usize;
    debug!("Lumina GET_POP request: {} results", limit);

    let results = match db.get_popular_functions(limit).await {
        Ok(v) => v,
        Err(e) => {
            error!("get_popular failed: {}", e);
            return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, "db error").await;
        }
    };
    let keys: Vec<u128> = results.iter().map(|(k, _)| *k).collect();
    let freqs = db
        .note_pull_hits(&keys, false)
        .await
        .unwrap_or_else(|_| vec![0; keys.len()]);

    let mut mapped: Vec<lumina::PopResult> = Vec::with_capacity(results.len());
    for ((key, f), freq) in results.into_iter().zip(freqs) {
        // Provenance: first binary this function was observed in.
        let (path, hostname, md5) = db
            .get_pop_provenance(key)
            .unwrap_or_else(|| (String::new(), String::new(), [0u8; 16]));
        mapped.push((
            f.name,
            f.len_bytes,
            f.data,
            0, // pattern type: the reference leaves PAT_TYPE_UNKNOWN here
            key.to_be_bytes().to_vec(),
            freq,
            hostname,
            path,
            md5,
            u64::MAX, // ea unknown -> BADADDR
        ));
    }
    lumina::send_lumina_pop_result(stream, &mapped).await
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

    let user = lumina::LuminaUser {
        name: "global".to_string(),
        features: if cfg.lumina.allow_deletes {
            lumina::UF_CAN_DEL_HISTORY
        } else {
            0
        },
        ..lumina::LuminaUser::default()
    };

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
///
/// IDA sends `filters_t { flags: BOPF_LAST_FUNC_RECORD, calcrel_hashes }` and
/// expects `ndeleted` to equal the number of hashes. With the flag the last
/// change of each function is undone; without it the whole history is removed.
async fn handle_lumina_del<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
    read_only: bool,
) -> io::Result<()> {
    if read_only {
        debug!("Read-only session: rejecting delete request");
        return lumina::send_lumina_fail(
            stream,
            lumina::RPC_FAIL_RESULT,
            &format!(
                "{}: Delete command is disabled on this server.",
                cfg.lumina.server_name
            ),
        )
        .await;
    }
    if !cfg.lumina.allow_deletes {
        // Reference wording for users without UF_CAN_DEL_HISTORY.
        return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, "Unknown command").await;
    }

    let caps = lumina_caps(cfg, cfg.limits.max_del_items);
    let filters = match lumina::parse_lumina_del_history(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina DelHistory: {}", e);
            return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, "invalid del").await;
        }
    };
    if filters.has_unsupported_selectors() {
        return lumina::send_lumina_fail(
            stream,
            lumina::RPC_FAIL_RESULT,
            &format!(
                "{}: only calcrel_hashes filters are supported for deletion",
                cfg.lumina.server_name
            ),
        )
        .await;
    }

    let keys: Vec<u128> = filters
        .calcrel_hashes
        .iter()
        .map(|h| u128::from_be_bytes(*h))
        .collect();
    let last_only = filters.flags & lumina::BOPF_LAST_FUNC_RECORD != 0;
    debug!(
        "Lumina DEL request: {} keys (last_record_only={})",
        keys.len(),
        last_only
    );
    let result = if last_only {
        db.revert_last_versions(&keys).await
    } else {
        db.delete_keys(&keys).await
    };
    match result {
        Ok(n) => lumina::send_lumina_del_result(stream, n).await,
        Err(e) => {
            error!("db del: {}", e);
            lumina::send_lumina_fail(
                stream,
                lumina::RPC_FAIL_RESULT,
                &format!("{}: db error", cfg.lumina.server_name),
            )
            .await
        }
    }
}

/// Handle Lumina GetFuncHistories (0x2f) command.
async fn handle_lumina_hist<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
    db: &Database,
    pld: &[u8],
) -> io::Result<()> {
    let caps = lumina_caps(cfg, cfg.limits.max_hist_items);

    let hist_msg = match lumina::parse_lumina_get_func_histories(pld, caps) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Lumina GetFuncHistories: {}", e);
            return lumina::send_lumina_fail(stream, lumina::RPC_FAIL_RESULT, "invalid hist").await;
        }
    };

    debug!("Lumina HIST request: {} keys", hist_msg.funcs.len());

    let limit = cfg.lumina.get_history_limit;
    if limit == 0 {
        return lumina::send_lumina_fail(
            stream,
            lumina::RPC_FAIL_RESULT,
            &format!(
                "{}: function histories are disabled on this server.",
                cfg.lumina.server_name
            ),
        )
        .await;
    }
    let details = hist_msg.flags & lumina::BOPF_DETAILS != 0;

    // pattern_idx_to_entries_idx: index into `histories` per request pattern, -1 if none.
    let mut indices: Vec<i32> = Vec::with_capacity(hist_msg.funcs.len());
    let mut histories: Vec<Vec<(u64, String, Vec<u8>)>> = Vec::new();

    for func in &hist_msg.funcs {
        let Some(key) = func.md5_key() else {
            indices.push(-1);
            continue;
        };

        match db.get_history(key, limit).await {
            Ok(hist) if !hist.is_empty() => {
                indices.push(histories.len() as i32);
                histories.push(hist);
            }
            Ok(_) => indices.push(-1),
            Err(e) => {
                error!("db hist: {}", e);
                return lumina::send_lumina_fail(
                    stream,
                    lumina::RPC_FAIL_RESULT,
                    &format!("{}: db error", cfg.lumina.server_name),
                )
                .await;
            }
        }
    }

    debug!("Lumina HIST response: {} histories found", histories.len());
    lumina::send_lumina_histories_result(stream, &indices, &histories, details).await
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

    let mut slots = resolve_pull_keys(cfg, db, &keys, &[]).await;
    apply_pull_frequencies(db, &keys, &mut slots, false).await;

    let statuses: Vec<u32> = slots
        .iter()
        .map(|o| {
            if o.is_some() {
                LuminaOpRes::Ok.as_u32()
            } else {
                LuminaOpRes::NotFound.as_u32()
            }
        })
        .collect();
    let found: Vec<FunctionPayload> = slots.into_iter().flatten().collect();

    METRICS.inc_pulls(found.len() as u64);
    debug!(
        "PULL response: {} found, {} not found (took {:?})",
        found.len(),
        statuses
            .iter()
            .filter(|&&s| s == LuminaOpRes::NotFound.as_u32())
            .count(),
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

/// Record one Lumina pull exchange: the raw request payload, replayable as a
/// fixture, and one JSON line per requested pattern with the served answer.
/// Best effort; dump failures never affect the response.
fn dump_pull_exchange(
    cfg: &Config,
    payload: &[u8],
    pull_msg: &lumina::LuminaPullMetadata,
    keys: &[u128],
    key_pos: &[usize],
    slots: &[Option<FunctionPayload>],
) {
    use std::io::Write;

    let dir = std::path::Path::new(&cfg.debug.dump_pull_dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!("pull dump: create {:?}: {}", dir, e);
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let stem = format!("pull-{}-{}", stamp, pull_msg.funcs.len());

    if let Err(e) = std::fs::write(dir.join(format!("{}.bin", stem)), payload) {
        warn!("pull dump: write request: {}", e);
        return;
    }

    let file = match std::fs::File::create(dir.join(format!("{}.jsonl", stem))) {
        Ok(f) => f,
        Err(e) => {
            warn!("pull dump: create result file: {}", e);
            return;
        }
    };
    let mut out = std::io::BufWriter::new(file);

    let mdkeys: Vec<String> = pull_msg.keys.iter().map(|k| k.to_string()).collect();
    let header = format!(
        "{{\"kind\":\"pull_request\",\"ts_ms\":{},\"flags\":{},\"mdkeys\":[{}],\"patterns\":{},\"payload_bytes\":{}}}\n",
        stamp,
        pull_msg.flags,
        mdkeys.join(","),
        pull_msg.funcs.len(),
        payload.len()
    );
    if let Err(e) = out.write_all(header.as_bytes()) {
        warn!("pull dump: write header: {}", e);
        return;
    }

    for (j, slot) in slots.iter().enumerate() {
        let line = match slot {
            Some((pop, size, name, data)) => format!(
                "{{\"i\":{},\"key\":\"{:032x}\",\"status\":\"ok\",\"name\":{},\"popularity\":{},\"func_size\":{},\"data_len\":{}{}}}\n",
                key_pos[j],
                keys[j],
                json_string(name),
                pop,
                size,
                data.len(),
                if cfg.debug.dump_pull_payloads {
                    format!(",\"data\":\"{}\"", hex_string(data))
                } else {
                    String::new()
                }
            ),
            None => format!(
                "{{\"i\":{},\"key\":\"{:032x}\",\"status\":\"notfound\"}}\n",
                key_pos[j], keys[j]
            ),
        };
        if let Err(e) = out.write_all(line.as_bytes()) {
            warn!("pull dump: write result: {}", e);
            return;
        }
    }
    if let Err(e) = out.flush() {
        warn!("pull dump: flush: {}", e);
        return;
    }
    info!(
        "pull dump: {} patterns written to {:?}",
        pull_msg.funcs.len(),
        dir.join(format!("{}.*", stem))
    );
}

/// Minimal JSON string literal; symbol names may carry any byte sequence.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex_string(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
