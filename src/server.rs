use crate::{rpc::*, config::Config, db::Database, metrics::METRICS, util::hex_dump, legacy};
use log::*;
use std::{io, sync::Arc, time::{Duration, Instant}};
use tokio::{
    net::TcpListener,
    time::timeout,
};

async fn handle_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    cfg: Arc<Config>,
    db: Arc<Database>,
) -> io::Result<()> {
    // Hello - peek first to detect protocol type, then read with appropriate reader
    // For legacy protocol, we need to use read_legacy_packet from the start
    let hello_bytes = match timeout(Duration::from_millis(cfg.limits.hello_timeout_ms), legacy::read_legacy_packet(&mut stream, 4*1024*1024)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            METRICS.timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
    };
    debug!("Received hello message, {} bytes", hello_bytes.len());
    if log_enabled!(log::Level::Debug) {
        debug!("Hello frame hex dump:\n{}", hex_dump(&hello_bytes, 256));
    }
    if hello_bytes.is_empty() {
        write_all(&mut stream, &encode_fail(0, "bad sequence")).await?;
        return Ok(());
    }
    let msg_type = hello_bytes[0];
    let payload = &hello_bytes[1..];
    
    // Handle both legacy (0x0d) and new (0x01) protocol
    const LEGACY_MSG_HELLO: u8 = 0x0d;
    let hello = if msg_type == LEGACY_MSG_HELLO {
        // Legacy protocol from lumen-master / IDA Pro
        debug!("Detected legacy Hello message (0x0d)");
        match legacy::parse_legacy_hello(payload) {
            Ok(v) => {
                debug!("Legacy Hello parsed: protocol_version={}, username={}", v.protocol_version, v.username);
                HelloReq {
                    protocol_version: v.protocol_version,
                    username: v.username,
                    password: v.password,
                }
            },
            Err(e) => {
                error!("Failed to parse legacy Hello: {}", e);
                write_all(&mut stream, &encode_fail(0, "invalid hello")).await?;
                return Ok(());
            }
        }
    } else if msg_type == MSG_HELLO {
        // New protocol
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
    debug!("Hello request: protocol_version={}, username={}", hello.protocol_version, hello.username);
    if hello.protocol_version <= 4 {
        METRICS.lumina_v0_4.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        METRICS.lumina_v5p.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if hello.username != "guest" {
        if msg_type == LEGACY_MSG_HELLO {
            legacy::send_legacy_fail(&mut stream, 1, &format!("{}: invalid username or password. Try logging in with `guest` instead.", cfg.lumina.server_name)).await?;
        } else {
            write_all(&mut stream, &encode_fail(1, &format!("{}: invalid username or password. Try logging in with `guest` instead.", cfg.lumina.server_name))).await?;
        }
        return Ok(());
    }
    // Protocol split: ≤4 expects empty OK; ≥5 expects HelloResult{features}
    if msg_type == LEGACY_MSG_HELLO {
        // Legacy client - send legacy format responses
        debug!("Sending legacy protocol response");
        if hello.protocol_version <= 4 {
            legacy::send_legacy_ok(&mut stream).await?;
        } else {
            let mut features = 0u32;
            if cfg.lumina.allow_deletes { features |= 0x02; }
            legacy::send_legacy_hello_result(&mut stream, features).await?;
        }
    } else {
        // New protocol client
        if hello.protocol_version <= 4 {
            write_all(&mut stream, &encode_ok()).await?;
        } else {
            let mut features = 0u32;
            if cfg.lumina.allow_deletes { features |= 0x02; }
            write_all(&mut stream, &encode_hello_ok(features)).await?;
        }
    }

    // Command loop - use appropriate frame reader based on protocol
    let is_legacy = msg_type == LEGACY_MSG_HELLO;
    loop {
        let frame = if is_legacy {
            match timeout(Duration::from_millis(cfg.limits.command_timeout_ms), legacy::read_legacy_packet(&mut stream, 128*1024*1024)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => { error!("read error: {}", e); return Ok(()); },
                Err(_) => {
                    METRICS.timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    legacy::send_legacy_fail(&mut stream, 0, &format!("{} client idle for too long.\n", cfg.lumina.server_name)).await.ok();
                    return Ok(());
                }
            }
        } else {
            match timeout(Duration::from_millis(cfg.limits.command_timeout_ms), read_frame(&mut stream, 128*1024*1024)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => { error!("read error: {}", e); return Ok(()); },
                Err(_) => {
                    METRICS.timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    write_all(&mut stream, &encode_fail(0, &format!("{} client idle for too long.\n", cfg.lumina.server_name))).await.ok();
                    return Ok(());
                }
            }
        };
        if frame.is_empty() {
            if is_legacy {
                legacy::send_legacy_fail(&mut stream, 0, &format!("{}: error: invalid data.\n", cfg.lumina.server_name)).await?;
            } else {
                write_all(&mut stream, &encode_fail(0, &format!("{}: error: invalid data.\n", cfg.lumina.server_name))).await?;
            }
            continue;
        }
        let typ = frame[0];
        let pld = &frame[1..];
        debug!("Incoming message: type=0x{:02x}, payload_size={}", typ, pld.len());
        
        // Handle legacy protocol commands
        if is_legacy {
            debug!("Legacy command received: 0x{:02x}", typ);
            match typ {
                0x0e => { // PullMetadata
                    let pull_msg = match legacy::parse_legacy_pull_metadata(pld) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to parse legacy PullMetadata: {}", e);
                            legacy::send_legacy_fail(&mut stream, 0, "invalid pull").await?;
                            continue;
                        }
                    };
                    debug!("Legacy PULL request: {} keys", pull_msg.funcs.len());
                    METRICS.queried_funcs.fetch_add(pull_msg.funcs.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    
                    let mut statuses = Vec::with_capacity(pull_msg.funcs.len());
                    let mut found = Vec::new();
                    
                    for func in &pull_msg.funcs {
                        // Convert 16-byte hash to u128 key
                        if func.mb_hash.len() != 16 {
                            statuses.push(1);
                            continue;
                        }
                        let key = u128::from_be_bytes([
                            func.mb_hash[0], func.mb_hash[1], func.mb_hash[2], func.mb_hash[3],
                            func.mb_hash[4], func.mb_hash[5], func.mb_hash[6], func.mb_hash[7],
                            func.mb_hash[8], func.mb_hash[9], func.mb_hash[10], func.mb_hash[11],
                            func.mb_hash[12], func.mb_hash[13], func.mb_hash[14], func.mb_hash[15],
                        ]);
                        
                        match db.get_latest(key).await {
                            Ok(Some(f)) => {
                                statuses.push(0);
                                found.push((f.popularity, f.len_bytes, f.name, f.data));
                            },
                            Ok(None) => { statuses.push(1); },
                            Err(e) => {
                                error!("db pull: {}", e);
                                statuses.push(1);
                            }
                        }
                    }
                    
                    METRICS.pulls.fetch_add(found.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    debug!("Legacy PULL response: {} found, {} not found", found.len(), statuses.iter().filter(|&&s| s == 1).count());
                    legacy::send_legacy_pull_result(&mut stream, &statuses, &found).await?;
                },
                0x10 => { // PushMetadata
                    let push_msg = match legacy::parse_legacy_push_metadata(pld) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to parse legacy PushMetadata: {}", e);
                            legacy::send_legacy_fail(&mut stream, 0, "invalid push").await?;
                            continue;
                        }
                    };
                    debug!("Legacy PUSH request: {} items", push_msg.funcs.len());
                    
                    let mut inlined: Vec<(u128, u32, u32, &str, &[u8])> = Vec::with_capacity(push_msg.funcs.len());
                    for func in &push_msg.funcs {
                        // Convert 16-byte hash to u128 key
                        if func.hash.len() != 16 {
                            error!("Invalid hash length: {}", func.hash.len());
                            continue;
                        }
                        let key = u128::from_be_bytes([
                            func.hash[0], func.hash[1], func.hash[2], func.hash[3],
                            func.hash[4], func.hash[5], func.hash[6], func.hash[7],
                            func.hash[8], func.hash[9], func.hash[10], func.hash[11],
                            func.hash[12], func.hash[13], func.hash[14], func.hash[15],
                        ]);
                        inlined.push((key, 0, func.func_len, &func.name, &func.func_data));
                    }
                    
                    match db.push(&inlined).await {
                        Ok(status) => {
                            let new_funcs = status.iter().filter(|&&v| v > 0).count() as u64;
                            METRICS.pushes.fetch_add(status.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            METRICS.new_funcs.fetch_add(new_funcs, std::sync::atomic::Ordering::Relaxed);
                            debug!("Legacy PUSH response: {} new, {} unchanged", new_funcs, status.iter().filter(|&&v| v == 0).count());
                            legacy::send_legacy_push_result(&mut stream, &status).await?;
                        },
                        Err(e) => {
                            error!("db push: {}", e);
                            legacy::send_legacy_fail(&mut stream, 0, &format!("{}: db error; please try again later", cfg.lumina.server_name)).await?;
                        }
                    }
                },
                0x18 => { // DelHistory
                    if !cfg.lumina.allow_deletes {
                        legacy::send_legacy_fail(&mut stream, 2, &format!("{}: Delete command is disabled on this server.", cfg.lumina.server_name)).await?;
                        continue;
                    }
                    // For now, just return success with 0 deleted
                    debug!("Legacy DEL request (not fully implemented)");
                    legacy::send_legacy_del_result(&mut stream, 0).await?;
                },
                0x2f => { // GetFuncHistories
                    let hist_msg = match legacy::parse_legacy_get_func_histories(pld) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Failed to parse legacy GetFuncHistories: {}", e);
                            legacy::send_legacy_fail(&mut stream, 0, "invalid hist").await?;
                            continue;
                        }
                    };
                    debug!("Legacy HIST request: {} keys", hist_msg.funcs.len());
                    
                    let limit = if cfg.lumina.get_history_limit == 0 { 0 } else { cfg.lumina.get_history_limit };
                    if limit == 0 {
                        legacy::send_legacy_fail(&mut stream, 4, &format!("{}: function histories are disabled on this server.", cfg.lumina.server_name)).await?;
                        continue;
                    }
                    
                    let mut statuses = Vec::new();
                    let mut histories = Vec::new();
                    
                    for func in &hist_msg.funcs {
                        if func.mb_hash.len() != 16 {
                            statuses.push(0);
                            continue;
                        }
                        let key = u128::from_be_bytes([
                            func.mb_hash[0], func.mb_hash[1], func.mb_hash[2], func.mb_hash[3],
                            func.mb_hash[4], func.mb_hash[5], func.mb_hash[6], func.mb_hash[7],
                            func.mb_hash[8], func.mb_hash[9], func.mb_hash[10], func.mb_hash[11],
                            func.mb_hash[12], func.mb_hash[13], func.mb_hash[14], func.mb_hash[15],
                        ]);
                        
                        match db.get_history(key, limit).await {
                            Ok(hist) if !hist.is_empty() => {
                                statuses.push(1);
                                let hist_tuples: Vec<(u64, String, Vec<u8>)> = hist.into_iter()
                                    .map(|(ts, name, data)| (ts as u64, name, data))
                                    .collect();
                                histories.push(hist_tuples);
                            },
                            Ok(_) => { statuses.push(0); },
                            Err(e) => {
                                error!("db hist: {}", e);
                                legacy::send_legacy_fail(&mut stream, 3, &format!("{}: db error", cfg.lumina.server_name)).await?;
                                return Ok(());
                            }
                        }
                    }
                    
                    debug!("Legacy HIST response: {} histories found", histories.len());
                    legacy::send_legacy_histories_result(&mut stream, &statuses, &histories).await?;
                },
                _ => {
                    warn!("Unknown legacy command: 0x{:02x}", typ);
                    legacy::send_legacy_fail(&mut stream, 0, &format!("{}: Unknown command.", cfg.lumina.server_name)).await?;
                    continue;
                }
            }
            continue; // Process next command
        }
        
        // New protocol commands
        let msg_start = Instant::now();
        match typ {
            MSG_PULL => {
                let keys = match decode_pull(pld) { Ok(v) => v, Err(_) => {
                    write_all(&mut stream, &encode_fail(0, "invalid pull")).await?; continue;
                }};
                debug!("PULL request: {} keys", keys.len());
                if log_enabled!(log::Level::Debug) {
                    for (i, key) in keys.iter().enumerate().take(10) {
                        debug!("  Key[{}]: 0x{:032x}", i, key);
                    }
                    if keys.len() > 10 {
                        debug!("  ... and {} more keys", keys.len() - 10);
                    }
                }
                METRICS.queried_funcs.fetch_add(keys.len() as u64, std::sync::atomic::Ordering::Relaxed);
                let mut statuses = Vec::with_capacity(keys.len());
                let mut found = Vec::new();
                for k in keys {
                    match db.get_latest(k).await {
                        Ok(Some(f)) => {
                            statuses.push(0);
                            found.push((f.popularity, f.len_bytes, f.name, f.data));
                        },
                        Ok(None) => { statuses.push(1); },
                        Err(e) => { error!("db pull: {}", e); statuses.push(1); }
                    }
                }
                METRICS.pulls.fetch_add(found.len() as u64, std::sync::atomic::Ordering::Relaxed);
                debug!("PULL response: {} found, {} not found (took {:?})", found.len(), statuses.iter().filter(|&&s| s == 1).count(), msg_start.elapsed());
                write_all(&mut stream, &encode_pull_ok(&statuses, &found)).await?;
            },
            MSG_PUSH => {
                let items = match decode_push(pld) { Ok(v) => v, Err(_) => {
                    write_all(&mut stream, &encode_fail(0, "invalid push")).await?; continue;
                }};
                debug!("PUSH request: {} items", items.len());
                if log_enabled!(log::Level::Debug) {
                    for (i, item) in items.iter().enumerate().take(5) {
                        debug!("  Item[{}]: key=0x{:032x}, pop={}, len={}, name='{}'", 
                               i, item.key, item.popularity, item.len_bytes, item.name);
                        debug!("    Data hex dump:\n{}", hex_dump(&item.data, 128));
                    }
                    if items.len() > 5 {
                        debug!("  ... and {} more items", items.len() - 5);
                    }
                }
                let mut inlined: Vec<(u128,u32,u32,&str,&[u8])> = Vec::with_capacity(items.len());
                for it in &items {
                    inlined.push((it.key, it.popularity, it.len_bytes, &it.name, &it.data));
                }
                let res = db.push(&inlined).await;
                match res {
                    Ok(status) => {
                        let new_funcs = status.iter().filter(|&&v| v>0).count() as u64;
                        let updated_funcs = status.iter().filter(|&&v| v == 0).count() as u64;
                        METRICS.pushes.fetch_add(status.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        METRICS.new_funcs.fetch_add(new_funcs, std::sync::atomic::Ordering::Relaxed);
                        debug!("PUSH response: {} new, {} unchanged (took {:?})", new_funcs, updated_funcs, msg_start.elapsed());
                        write_all(&mut stream, &encode_push_ok(&status)).await?;
                    },
                    Err(e) => {
                        error!("db push: {}", e);
                        write_all(&mut stream, &encode_fail(0, &format!("{}: db error; please try again later..\n", cfg.lumina.server_name))).await?;
                    }
                }
            },
            MSG_DEL => {
                if !cfg.lumina.allow_deletes {
                    write_all(&mut stream, &encode_fail(2, &format!("{}: Delete command is disabled on this server.", cfg.lumina.server_name))).await?;
                    continue;
                }
                let keys = match decode_del(pld) { Ok(v) => v, Err(_) => {
                    write_all(&mut stream, &encode_fail(0, "invalid del")).await?; continue;
                }};
                debug!("DEL request: {} keys", keys.len());
                if log_enabled!(log::Level::Debug) {
                    for (i, key) in keys.iter().enumerate().take(10) {
                        debug!("  Key[{}]: 0x{:032x}", i, key);
                    }
                    if keys.len() > 10 {
                        debug!("  ... and {} more keys", keys.len() - 10);
                    }
                }
                match db.delete_keys(&keys).await {
                    Ok(n) => { 
                        debug!("DEL response: {} keys deleted (took {:?})", n, msg_start.elapsed());
                        write_all(&mut stream, &encode_del_ok(n)).await?; 
                    },
                    Err(e) => {
                        error!("db del: {}", e);
                        write_all(&mut stream, &encode_fail(3, &format!("{}: db error, please try again later.", cfg.lumina.server_name))).await?;
                    }
                }
            },
            MSG_HIST => {
                let (limit_req, keys) = match decode_hist(pld) { Ok(v) => v, Err(_) => {
                    write_all(&mut stream, &encode_fail(0, "invalid hist")).await?; continue;
                }};
                debug!("HIST request: limit={}, {} keys", limit_req, keys.len());
                if log_enabled!(log::Level::Debug) {
                    for (i, key) in keys.iter().enumerate().take(10) {
                        debug!("  Key[{}]: 0x{:032x}", i, key);
                    }
                    if keys.len() > 10 {
                        debug!("  ... and {} more keys", keys.len() - 10);
                    }
                }
                let limit = if cfg.lumina.get_history_limit == 0 { 0 } else { cfg.lumina.get_history_limit.min(limit_req) };
                if limit == 0 {
                    write_all(&mut stream, &encode_fail(4, &format!("{}: function histories are disabled on this server.", cfg.lumina.server_name))).await?;
                    continue;
                }
                let mut statuses = Vec::with_capacity(keys.len());
                let mut logs = Vec::new();
                for k in keys {
                    match db.get_history(k, limit).await {
                        Ok(v) if !v.is_empty() => { statuses.push(1); logs.push(v); },
                        Ok(_) => { statuses.push(0); },
                        Err(e) => {
                            error!("db hist: {}", e);
                            write_all(&mut stream, &encode_fail(3, &format!("{}: db error, please try again later.", cfg.lumina.server_name))).await?;
                            continue;
                        }
                    }
                }
                let found_histories = logs.len();
                debug!("HIST response: {} histories found (took {:?})", found_histories, msg_start.elapsed());
                write_all(&mut stream, &encode_hist_ok(&statuses, &logs)).await?;
            },
            _ => {
                debug!("Unknown message type: 0x{:02x}, payload size: {} (took {:?})", typ, pld.len(), msg_start.elapsed());
                if log_enabled!(log::Level::Debug) && !pld.is_empty() {
                    debug!("Unknown message payload hex dump:\n{}", hex_dump(pld, 256));
                }
                write_all(&mut stream, &encode_fail(0, &format!("{}: invalid data.\n", cfg.lumina.server_name))).await?;
            }
        }
    }
}

pub async fn serve_binary_rpc(cfg: Arc<Config>, db: Arc<Database>) {
    let listener = TcpListener::bind(&cfg.lumina.bind_addr).await.expect("bind failed");
    let mut tls_acceptor = None;
    if cfg.lumina.use_tls {
        let tls = cfg.lumina.tls.as_ref().expect("tls config missing");
        let mut crt = std::fs::read(&tls.pkcs12_path).expect("read pkcs12 file");
        let pass = std::env::var(&tls.env_password_var).unwrap_or_default();
        let id = native_tls::Identity::from_pkcs12(&crt, &pass).expect("parse pkcs12");
        crt.iter_mut().for_each(|b| *b = 0); // zeroize
        let mut builder = native_tls::TlsAcceptor::builder(id);
        if tls.min_protocol_sslv3 {
            builder.min_protocol_version(Some(native_tls::Protocol::Sslv3));
        }
        let acc = builder.build().expect("tls build");
        tls_acceptor = Some(tokio_native_tls::TlsAcceptor::from(acc));
    }
    info!("binary RPC listening on {} secure={}", listener.local_addr().unwrap(), tls_acceptor.is_some());

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => { error!("accept: {}", e); continue; }
        };
        if METRICS.active_connections.load(std::sync::atomic::Ordering::Relaxed) as usize >= cfg.limits.max_active_conns {
            debug!("refusing connection {}; too many", addr);
            drop(socket);
            continue;
        }
        METRICS.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let cfg = cfg.clone();
        let db = db.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            debug!("New connection from {}", addr);
            let res = if let Some(acc) = acceptor {
                match tokio::time::timeout(std::time::Duration::from_millis(cfg.limits.tls_handshake_timeout_ms), acc.accept(socket)).await {
                    Ok(Ok(s)) => {
                        debug!("TLS handshake completed for {}", addr);
                        handle_client(s, cfg, db).await
                    },
                    Ok(Err(e)) => { debug!("tls accept {}: {}", addr, e); Ok(()) },
                    Err(_) => { debug!("tls handshake timeout {}", addr); Ok(()) },
                }
            } else {
                handle_client(socket, cfg, db).await
            };
            if let Err(e) = res { 
                debug!("connection {} ended: {}", addr, e); 
            } else {
                debug!("connection {} closed cleanly", addr);
            }
            METRICS.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
