//! TCP server for binary RPC protocol.
//!
//! Handles connection acceptance, TLS negotiation, protocol detection,
//! and dispatching to the appropriate handler (HTTP/HTTP2 or binary RPC).
//!
//! ## HTTP/2 Support
//!
//! HTTP/2 is supported in multiple ways:
//! 1. **h2c (cleartext)**: Detected via HTTP/2 connection preface ("PRI *")
//! 2. **h2 (TLS with ALPN)**: Negotiated during TLS handshake using rustls
//! 3. **h2 (TLS without ALPN)**: Auto-detected after TLS with native-tls

use std::sync::Arc;
use std::time::Duration;

use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener as TokioTcpListener;

use crate::api::http::{handle_http_connection, handle_http_connection_with_protocol};
use crate::api::metrics::METRICS;
use crate::config::Config;
use crate::db::Database;

use super::budget::Budget;
use super::handler::handle_client;
use super::peekable::PeekableStream;
use super::protocol::{
    looks_like_any_http, looks_like_http, looks_like_http2_preface, looks_like_tls_client_hello,
};
use super::tls::{build_tls_acceptor, NegotiatedProtocol, TlsAcceptor};

/// Detected protocol type from peeked bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DetectedProtocol {
    /// HTTP/1.x request detected
    Http1,
    /// HTTP/2 connection preface detected (h2c)
    Http2,
    /// Binary Lumina protocol
    Binary,
}

/// Detect protocol from header bytes.
fn detect_protocol(hdr: &[u8]) -> DetectedProtocol {
    if looks_like_http2_preface(hdr) {
        DetectedProtocol::Http2
    } else if looks_like_http(hdr) {
        DetectedProtocol::Http1
    } else {
        DetectedProtocol::Binary
    }
}

/// Handle a connection after protocol detection.
async fn handle_detected<S>(
    socket: S,
    protocol: DetectedProtocol,
    cfg: Arc<Config>,
    db: Arc<Database>,
    global_budget: Arc<Budget>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match protocol {
        DetectedProtocol::Http1 | DetectedProtocol::Http2 => {
            debug!("routing to HTTP handler (detected: {:?})", protocol);
            // Use auto builder which handles both HTTP/1.1 and HTTP/2
            handle_http_connection(socket, db).await
        }
        DetectedProtocol::Binary => handle_client(socket, cfg, db, global_budget).await,
    }
}

/// Handle a TLS connection with ALPN-negotiated protocol.
async fn handle_tls_with_alpn<S>(
    tls_stream: S,
    alpn_protocol: NegotiatedProtocol,
    cfg: Arc<Config>,
    db: Arc<Database>,
    global_budget: Arc<Budget>,
    addr: std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match alpn_protocol {
        NegotiatedProtocol::H2 => {
            debug!("{}: HTTP/2 via ALPN", addr);
            handle_http_connection_with_protocol(tls_stream, db, alpn_protocol).await
        }
        NegotiatedProtocol::Http1 => {
            debug!("{}: HTTP/1.1 via ALPN", addr);
            handle_http_connection_with_protocol(tls_stream, db, alpn_protocol).await
        }
        NegotiatedProtocol::None => {
            // No ALPN, need to detect protocol from data
            // This is the fallback path for native-tls or when client doesn't support ALPN
            handle_tls_no_alpn(tls_stream, cfg, db, global_budget, addr).await
        }
    }
}

/// Handle a TLS connection without ALPN (native-tls or no client ALPN).
///
/// We need to peek at the decrypted stream to detect the protocol.
async fn handle_tls_no_alpn<S>(
    mut tls_stream: S,
    cfg: Arc<Config>,
    db: Arc<Database>,
    global_budget: Arc<Budget>,
    addr: std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read first bytes from decrypted stream to detect protocol
    let sniff_deadline = Duration::from_millis(cfg.limits.hello_timeout_ms);
    let mut peek_buf = [0u8; 6];
    match tokio::time::timeout(sniff_deadline, tls_stream.read(&mut peek_buf)).await {
        Err(_) => {
            debug!("{}: TLS protocol sniff timeout", addr);
            Ok(())
        }
        Ok(Ok(n)) if n >= 4 => {
            let protocol = detect_protocol(&peek_buf[..n]);
            debug!("{}: detected {:?} over TLS (no ALPN)", addr, protocol);
            // Wrap stream with peeked bytes prepended
            let wrapped = PeekableStream::new(tls_stream, peek_buf[..n].to_vec());
            handle_detected(wrapped, protocol, cfg, db, global_budget).await
        }
        Ok(Ok(_)) => {
            debug!("{}: TLS stream closed early", addr);
            Ok(())
        }
        Ok(Err(e)) => {
            debug!("{}: TLS read error: {}", addr, e);
            Ok(())
        }
    }
}

/// Start the binary RPC server.
///
/// Listens on the configured address and accepts connections.
/// Supports automatic TLS/cleartext detection when TLS is enabled.
/// Also supports HTTP/1.1 and HTTP/2 requests on the same port.
///
/// ## Protocol Detection Flow
///
/// ```text
/// TCP Accept
///     |
///     v
/// Peek 6 bytes ─────────────────────────┐
///     |                                   |
///     ├─ TLS ClientHello? ───> TLS Accept |
///     |     |                             |
///     |     ├─ ALPN = h2 ───> HTTP/2 handler
///     |     ├─ ALPN = http/1.1 ───> HTTP/1.1 handler
///     |     └─ No ALPN ───> Peek decrypted ──┐
///     |                                      |
///     v                                      v
/// Protocol Detection ────────────────────────┘
///     |
///     ├─ "PRI *" (HTTP/2 h2c) ───> Auto HTTP handler
///     ├─ HTTP method ───> Auto HTTP handler
///     └─ Binary frame ───> Lumina RPC handler
/// ```
pub async fn serve_binary_rpc(cfg: Arc<Config>, db: Arc<Database>) {
    let listener = TokioTcpListener::bind(&cfg.lumina.bind_addr)
        .await
        .expect("bind failed");

    let global_budget = Arc::new(Budget::new(cfg.limits.global_inflight_bytes));

    // Set up TLS acceptor if configured
    let tls_acceptor = if cfg.lumina.use_tls {
        let tls = cfg.lumina.tls.as_ref().expect("tls config missing");
        Some(build_tls_acceptor(tls))
    } else {
        None
    };

    let tls_type = match &tls_acceptor {
        Some(TlsAcceptor::Rustls(_)) => "rustls+ALPN",
        Some(TlsAcceptor::Native(_)) => "native-tls",
        None => "disabled",
    };

    info!(
        "listening on {} (TLS={}, HTTP/1.1+HTTP/2=enabled)",
        listener.local_addr().unwrap(),
        tls_type
    );

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("accept: {}", e);
                continue;
            }
        };

        // Check connection limit
        if METRICS
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed) as usize
            >= cfg.limits.max_active_conns
        {
            debug!("refusing connection {}; too many", addr);
            drop(socket);
            continue;
        }

        METRICS
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let cfg = cfg.clone();
        let db = db.clone();
        let acceptor = tls_acceptor.clone();
        let global_budget = global_budget.clone();

        tokio::spawn(async move {
            debug!("New connection from {}", addr);

            let res = if let Some(acc) = acceptor {
                // TLS mode: sniff first bytes to detect TLS vs cleartext vs HTTP
                let sniff_deadline = Duration::from_millis(cfg.limits.tls_handshake_timeout_ms);
                let sniff_result = tokio::time::timeout(sniff_deadline, async {
                    socket.readable().await.ok();
                    let mut hdr = [0u8; 6];
                    match socket.peek(&mut hdr).await {
                        Ok(n) if n >= 4 => Some(hdr),
                        Ok(_) => None,
                        Err(_) => None,
                    }
                })
                .await;

                let hdr = match sniff_result {
                    Ok(Some(h)) => h,
                    _ => {
                        debug!("{}: failed to sniff protocol header", addr);
                        METRICS
                            .active_connections
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                };

                if looks_like_tls_client_hello(&hdr) {
                    debug!("{}: sniffed TLS ClientHello; upgrading connection", addr);
                    let handshake_timeout =
                        Duration::from_millis(cfg.limits.tls_handshake_timeout_ms);

                    match &acc {
                        TlsAcceptor::Rustls(rustls_acc) => {
                            // Rustls with ALPN support
                            match tokio::time::timeout(handshake_timeout, rustls_acc.accept(socket))
                                .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    debug!("TLS handshake completed for {} (rustls)", addr);
                                    // Get ALPN result from the connection
                                    let alpn = tls_stream.get_ref().1.alpn_protocol();
                                    let negotiated = NegotiatedProtocol::from_alpn(alpn);
                                    debug!("{}: ALPN negotiated: {:?}", addr, negotiated);
                                    handle_tls_with_alpn(
                                        tls_stream,
                                        negotiated,
                                        cfg,
                                        db,
                                        global_budget,
                                        addr,
                                    )
                                    .await
                                }
                                Ok(Err(e)) => {
                                    debug!("rustls accept {}: {}", addr, e);
                                    Ok(())
                                }
                                Err(_) => {
                                    debug!("tls handshake timeout {}", addr);
                                    Ok(())
                                }
                            }
                        }
                        TlsAcceptor::Native(native_acc) => {
                            // Native-tls without ALPN support
                            match tokio::time::timeout(handshake_timeout, native_acc.accept(socket))
                                .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    debug!(
                                        "TLS handshake completed for {} (native-tls, no ALPN)",
                                        addr
                                    );
                                    handle_tls_no_alpn(tls_stream, cfg, db, global_budget, addr)
                                        .await
                                }
                                Ok(Err(e)) => {
                                    debug!("native-tls accept {}: {}", addr, e);
                                    Ok(())
                                }
                                Err(_) => {
                                    debug!("tls handshake timeout {}", addr);
                                    Ok(())
                                }
                            }
                        }
                    }
                } else if looks_like_any_http(&hdr) {
                    // Cleartext HTTP (HTTP/1.1 or HTTP/2 h2c) on TLS-enabled port
                    let protocol = detect_protocol(&hdr);
                    debug!("{}: cleartext {:?} request detected", addr, protocol);
                    handle_detected(socket, protocol, cfg, db, global_budget).await
                } else {
                    // Cleartext binary protocol
                    debug!("{}: cleartext binary protocol detected", addr);
                    handle_detected(socket, DetectedProtocol::Binary, cfg, db, global_budget).await
                }
            } else {
                // No TLS configured: detect HTTP vs binary
                let sniff_deadline = Duration::from_millis(cfg.limits.hello_timeout_ms);
                let mut hdr = [0u8; 6];
                let protocol = match tokio::time::timeout(sniff_deadline, async {
                    socket.readable().await.ok();
                    socket.peek(&mut hdr).await
                })
                .await
                {
                    Ok(Ok(n)) if n >= 4 => detect_protocol(&hdr),
                    _ => DetectedProtocol::Binary,
                };
                if protocol != DetectedProtocol::Binary {
                    debug!("{}: {:?} request detected", addr, protocol);
                }
                handle_detected(socket, protocol, cfg, db, global_budget).await
            };

            if let Err(e) = res {
                let msg = e.to_string();
                if msg.contains("TLS handshake detected") {
                    warn!("connection {} ended: {}", addr, msg);
                } else {
                    debug!("connection {} ended: {}", addr, msg);
                }
            } else {
                debug!("connection {} closed cleanly", addr);
            }

            METRICS
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
