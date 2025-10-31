use crate::{config::Config, db::Database, metrics::METRICS};
use hyper::{Request, Response, Method, StatusCode, body::Incoming};
use http_body_util::Full;
use bytes::Bytes;
use std::{convert::Infallible, sync::Arc};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;
use log::*;

const HOME: &str = r#"<!doctype html>
<html><head><title>lumen</title></head>
<body>
<h3>lumen</h3>
<p>Ultra-fast private Lumina server.</p>
<p>Metrics at <a href="/metrics">/metrics</a>.</p>
</body></html>"#;

async fn router(_db: Arc<Database>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(Response::new(Full::new(Bytes::from(HOME)))),
        (&Method::GET, "/metrics") => {
            let s = METRICS.render_prometheus();
            let mut r = Response::new(Full::new(Bytes::from(s)));
            *r.status_mut() = StatusCode::OK;
            Ok(r)
        },
        _ => Ok(Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::from("not found"))).unwrap()),
    }
}

pub async fn serve_http(cfg: Arc<Config>, db: Arc<Database>) {
    if let Some(http) = &cfg.http {
        let addr: std::net::SocketAddr = http.bind_addr.parse().expect("invalid http bind addr");
        let listener = TcpListener::bind(&addr).await.expect("failed to bind");
        info!("http listening on {}", addr);
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    error!("accept error: {}", e);
                    continue;
                }
            };
            let db = db.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| router(db.clone(), req)))
                    .await
                {
                    error!("http connection error: {}", e);
                }
            });
        }
    }
}
