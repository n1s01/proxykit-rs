//! Loopback HTTP proxy for browsers and for clients that only accept a proxy
//! URL (Chromium `--proxy-server`, `reqwest::Proxy::all`, curl `-x`).
//!
//! ```no_run
//! # async fn run(dialer: proxykit::Dialer) -> proxykit::Result<()> {
//! let relay = proxykit::relay::start(dialer, Default::default())?;
//! println!("--proxy-server={}", relay.url());
//! // ...
//! relay.close().await;
//! # Ok(()) }
//! ```
//!
//! The relay listens only on `127.0.0.1` on a random port and sends
//! credentials only to the upstream proxy. It has no local authentication:
//! any local process can use it. It is a local adapter, not a network service.

use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    error::{BoxError, Result},
    http::{http_client, Connect, HttpClient, ProxyConnector},
    spec::{parse_target, Protocol, Spec},
};

/// Bounds request setup and concurrent upstream work.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Active upstream requests and tunnels; 0 uses 128.
    pub max_concurrent: usize,
    /// Time allowed for request headers; `None` uses 5 seconds.
    pub header_timeout: Option<Duration>,
}

/// A running relay. Dropping it stops accepting and aborts active work in the
/// background; [`close`](Relay::close) does the same and waits for it.
pub struct Relay {
    addr: SocketAddr,
    token: CancellationToken,
    tracker: TaskTracker,
}

struct State {
    dialer: Arc<dyn Connect>,
    client: HttpClient<Incoming>,
    sem: Arc<Semaphore>,
    token: CancellationToken,
    tracker: TaskTracker,
}

type RelayBody = BoxBody<Bytes, BoxError>;

/// Starts the relay on `127.0.0.1:0`. Must be called within a Tokio runtime.
/// HTTP requests and CONNECT tunnels (HTTPS, WebSocket inside CONNECT) go
/// through `dialer`; `Upgrade` requests outside CONNECT are refused.
pub fn start(dialer: impl Connect, opts: Options) -> Result<Relay> {
    let max = if opts.max_concurrent == 0 { 128 } else { opts.max_concurrent };
    let header_timeout = opts.header_timeout.filter(|t| !t.is_zero()).unwrap_or(Duration::from_secs(5));
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let addr = listener.local_addr()?;
    let token = CancellationToken::new();
    let tracker = TaskTracker::new();
    let dialer: Arc<dyn Connect> = Arc::new(dialer);
    let state = Arc::new(State {
        client: http_client(ProxyConnector::new(dialer.clone())),
        dialer,
        sem: Arc::new(Semaphore::new(max)),
        token: token.clone(),
        tracker: tracker.clone(),
    });
    tracker.spawn(accept_loop(listener, state, header_timeout));
    Ok(Relay { addr, token, tracker })
}

impl Relay {
    /// `http://127.0.0.1:PORT`, suitable for `--proxy-server`; no credentials.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops the listener, pending requests and active tunnels, and waits for
    /// all of them to finish.
    pub async fn close(self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.token.cancel();
        self.tracker.close();
    }
}

async fn accept_loop(listener: TcpListener, state: Arc<State>, header_timeout: Duration) {
    loop {
        let stream = tokio::select! {
            _ = state.token.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(_) => continue,
            },
        };
        let state = state.clone();
        let token = state.token.clone();
        state.tracker.clone().spawn(async move {
            let service = service_fn(move |req| handle(state.clone(), req));
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .max_buf_size(64 << 10)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::select! {
                _ = token.cancelled() => {}
                _ = conn => {}
            }
        });
    }
}

fn text(status: StatusCode, msg: &'static str) -> Response<RelayBody> {
    let body = Full::new(Bytes::from_static(msg.as_bytes())).map_err(|never| match never {}).boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/plain; charset=utf-8"));
    resp
}

async fn handle(state: Arc<State>, req: Request<Incoming>) -> Result<Response<RelayBody>, Infallible> {
    if state.token.is_cancelled() {
        return Ok(text(StatusCode::SERVICE_UNAVAILABLE, "relay closed"));
    }
    let permit = tokio::select! {
        _ = state.token.cancelled() => return Ok(text(StatusCode::SERVICE_UNAVAILABLE, "relay closed")),
        p = state.sem.clone().acquire_owned() => match p {
            Ok(p) => p,
            Err(_) => return Ok(text(StatusCode::SERVICE_UNAVAILABLE, "relay closed")),
        },
    };
    if req.method() == Method::CONNECT {
        return Ok(connect(state, req, permit).await);
    }
    Ok(forward(state, req, permit).await)
}

fn valid_target(addr: &str) -> bool {
    match parse_target(addr) {
        Ok((host, port)) => Spec::new(Protocol::Http, host, port).validate().is_ok(),
        Err(_) => false,
    }
}

async fn connect(state: Arc<State>, mut req: Request<Incoming>, permit: OwnedSemaphorePermit) -> Response<RelayBody> {
    let target = match req.uri().authority() {
        Some(a) if !a.as_str().contains('@') && valid_target(a.as_str()) => a.as_str().to_string(),
        _ => return text(StatusCode::BAD_REQUEST, "invalid CONNECT target"),
    };
    let upstream = tokio::select! {
        _ = state.token.cancelled() => return text(StatusCode::SERVICE_UNAVAILABLE, "relay closed"),
        up = state.dialer.connect_io(&target) => match up {
            Ok(up) => up,
            Err(_) => return text(StatusCode::BAD_GATEWAY, "upstream connection failed"),
        },
    };
    let on_upgrade = hyper::upgrade::on(&mut req);
    let token = state.token.clone();
    state.tracker.spawn(async move {
        let _permit = permit;
        let client = tokio::select! {
            _ = token.cancelled() => return,
            upgraded = on_upgrade => match upgraded {
                Ok(u) => TokioIo::new(u),
                Err(_) => return,
            },
        };
        // One finished direction closes both sides; no TCP half-close.
        tokio::select! {
            _ = token.cancelled() => {}
            _ = pipe(client, upstream) => {}
        }
    });
    Response::new(http_body_util::Empty::new().map_err(|never| match never {}).boxed())
}

async fn pipe<A, B>(a: A, b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::select! {
        _ = tokio::io::copy(&mut ar, &mut bw) => {}
        _ = tokio::io::copy(&mut br, &mut aw) => {}
    }
}

async fn forward(state: Arc<State>, req: Request<Incoming>, permit: OwnedSemaphorePermit) -> Response<RelayBody> {
    let uri = req.uri();
    let authority_ok = uri.authority().is_some_and(|a| !a.as_str().contains('@'));
    if uri.scheme_str() != Some("http") || !authority_ok || req.headers().contains_key(header::UPGRADE) {
        return text(StatusCode::BAD_REQUEST, "expected absolute HTTP URL or CONNECT");
    }
    let host = uri.host().unwrap_or_default().trim_start_matches('[').trim_end_matches(']');
    let port = uri.port_u16().unwrap_or(80);
    if !valid_target(&crate::spec::join_host_port(host, port)) {
        return text(StatusCode::BAD_REQUEST, "invalid target");
    }
    let (mut parts, body) = req.into_parts();
    strip_hop_headers(&mut parts.headers);
    let out = Request::from_parts(parts, body);
    let resp = tokio::select! {
        _ = state.token.cancelled() => return text(StatusCode::SERVICE_UNAVAILABLE, "relay closed"),
        r = state.client.request(out) => match r {
            Ok(r) => r,
            Err(_) => return text(StatusCode::BAD_GATEWAY, "upstream connection failed"),
        },
    };
    let (mut parts, body) = resp.into_parts();
    strip_hop_headers(&mut parts.headers);
    Response::from_parts(parts, PermitBody { inner: body, _permit: permit }.boxed())
}

fn strip_hop_headers(h: &mut HeaderMap) {
    let listed: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        h.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        h.remove(name);
    }
}

/// Holds the concurrency permit until the response body has been streamed.
struct PermitBody {
    inner: Incoming,
    _permit: OwnedSemaphorePermit,
}

impl Body for PermitBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(&mut self.inner).poll_frame(cx).map_err(|e| Box::new(e) as BoxError)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
