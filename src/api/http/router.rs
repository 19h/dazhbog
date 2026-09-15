//! HTTP router and server setup.
//!
//! Supports both HTTP/1.1 and HTTP/2 on the same port using hyper-util's
//! auto connection builder for automatic protocol detection.

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use log::*;
use std::{convert::Infallible, io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener as TokioTcpListener;

use crate::config::Config;
use crate::db::Database;
use crate::net::tls::NegotiatedProtocol;

use super::handlers::{
    handle_binary_compare, handle_binary_detail, handle_binary_functions, handle_binary_graph,
    handle_binary_overlap, handle_function_detail, handle_function_neighbors, handle_search,
    json_response, metrics_snapshot,
};
use super::templates::HOME;
use crate::api::metrics::METRICS;

/// Route HTTP requests to appropriate handlers.
async fn router(
    db: Arc<Database>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method();

    let resp = match (method, path.as_str()) {
        (&Method::GET, "/") => {
            let mut r = Response::new(Full::new(Bytes::from_static(HOME.as_bytes())));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            r
        }
        (&Method::GET, "/api/search") => handle_search(db.clone(), req).await,
        (&Method::GET, "/api/metrics") => json_response(&metrics_snapshot(), StatusCode::OK),
        (&Method::GET, "/metrics") => {
            let s = METRICS.render_prometheus();
            let mut r = Response::new(Full::new(Bytes::from(s)));
            *r.status_mut() = StatusCode::OK;
            r
        }
        (&Method::GET, p) if p.starts_with("/api/function/") && p.ends_with("/neighbors") => {
            let key_hex = &p["/api/function/".len()..p.len() - "/neighbors".len()];
            handle_function_neighbors(db.clone(), key_hex, req).await
        }
        (&Method::GET, p) if p.starts_with("/api/function/") => {
            let key_hex = &p["/api/function/".len()..];
            handle_function_detail(db.clone(), key_hex).await
        }
        (&Method::GET, p) if p.starts_with("/api/binary/") && p.ends_with("/functions") => {
            let md5_hex = &p["/api/binary/".len()..p.len() - "/functions".len()];
            handle_binary_functions(db.clone(), md5_hex, req).await
        }
        (&Method::GET, p) if p.starts_with("/api/binary/") && p.ends_with("/overlap") => {
            let md5_hex = &p["/api/binary/".len()..p.len() - "/overlap".len()];
            handle_binary_overlap(db.clone(), md5_hex, req).await
        }
        (&Method::GET, p) if p.starts_with("/api/binary/") && p.ends_with("/graph") => {
            let md5_hex = &p["/api/binary/".len()..p.len() - "/graph".len()];
            handle_binary_graph(db.clone(), md5_hex, req).await
        }
        (&Method::GET, p) if p.starts_with("/api/binary-compare/") => {
            let rest = &p["/api/binary-compare/".len()..];
            if let Some((left, right)) = rest.split_once('/') {
                handle_binary_compare(db.clone(), left, right, req).await
            } else {
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("invalid compare path")))
                    .unwrap()
            }
        }
        (&Method::GET, p) if p.starts_with("/api/binary/") => {
            let md5_hex = &p["/api/binary/".len()..];
            handle_binary_detail(db.clone(), md5_hex).await
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    };

    Ok(resp)
}

/// Handle an HTTP connection with automatic HTTP/1.1 and HTTP/2 detection.
///
/// This is the preferred handler that uses hyper-util's auto builder to
/// automatically detect and serve both HTTP/1.1 and HTTP/2 (h2c) connections.
/// For HTTP/2 over TLS (h2), the protocol should be negotiated via ALPN.
pub async fn handle_http_connection<S>(stream: S, db: Arc<Database>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    AutoBuilder::new(TokioExecutor::new())
        .serve_connection(io, service_fn(move |req| router(db.clone(), req)))
        .await
        .map_err(|e| io::Error::other(format!("http error: {}", e)))
}

/// Handle an HTTP connection when we know the protocol from ALPN negotiation.
///
/// When TLS ALPN has negotiated the protocol, we can skip auto-detection and
/// use the appropriate HTTP/1.1 or HTTP/2 handler directly for efficiency.
pub async fn handle_http_connection_with_protocol<S>(
    stream: S,
    db: Arc<Database>,
    protocol: NegotiatedProtocol,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| router(db.clone(), req));

    match protocol {
        NegotiatedProtocol::H2 => {
            debug!("serving HTTP/2 connection (ALPN negotiated)");
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
                .map_err(|e| io::Error::other(format!("http2 error: {}", e)))
        }
        NegotiatedProtocol::Http1 => {
            debug!("serving HTTP/1.1 connection (ALPN negotiated)");
            http1::Builder::new()
                .serve_connection(io, svc)
                .await
                .map_err(|e| io::Error::other(format!("http1 error: {}", e)))
        }
        NegotiatedProtocol::None => {
            // No ALPN, use auto-detection
            debug!("serving HTTP connection (auto-detection)");
            AutoBuilder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
                .map_err(|e| io::Error::other(format!("http error: {}", e)))
        }
    }
}

/// Start the standalone HTTP server.
///
/// This server runs on a dedicated port and supports both HTTP/1.1 and HTTP/2 (h2c).
/// For HTTP/2 over TLS, use the main Lumina port with TLS and ALPN enabled.
pub async fn serve_http(cfg: Arc<Config>, db: Arc<Database>) {
    if let Some(http) = &cfg.http {
        let addr: std::net::SocketAddr = http.bind_addr.parse().expect("invalid http bind addr");
        let listener = TokioTcpListener::bind(&addr).await.expect("failed to bind");
        info!("http listening on {} (HTTP/1.1 + HTTP/2 h2c)", addr);
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                biased;
                _ = crate::api::metrics::shutdown_requested() => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                result = listener.accept() => result,
            };
            let (stream, peer) = match accepted {
                Ok(x) => x,
                Err(e) => {
                    error!("accept error: {}", e);
                    continue;
                }
            };
            let db = db.clone();
            connections.spawn(async move {
                if let Err(e) = handle_http_connection(stream, db).await {
                    debug!("http connection error from {}: {}", peer, e);
                }
            });
        }
        drop(listener);
        if tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.shutdown().await;
        }
    }
}
