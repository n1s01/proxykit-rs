use std::{
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::Engine as _;
use bytes::Bytes;
use rustls::{pki_types::ServerName, ClientConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};
use tokio_rustls::TlsConnector;

use crate::{
    bypass::{bypass_forward, BypassOptions},
    error::{Error, ErrorKind, Result, Stage},
    io::{BoxIo, Io, Tunnel},
    spec::{parse_target, Protocol, Spec},
    tls,
};

pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Future returned by a [`Forward`] dialer.
pub type ForwardFuture = Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>>;

/// Opens only the TCP connection to the proxy (`host:port`). Inject interface
/// binding, DNS policy, tracing or test transports here. Dropping the future
/// must abort the attempt.
#[derive(Clone)]
pub struct Forward(Arc<dyn Fn(String) -> ForwardFuture + Send + Sync>);

impl Forward {
    pub fn new<F, Fut, S>(f: F) -> Forward
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<S>> + Send + 'static,
        S: Io,
    {
        Forward(Arc::new(move |addr| {
            let fut = f(addr);
            Box::pin(async move { Ok(Box::new(fut.await?) as BoxIo) })
        }))
    }

    /// The default: the operating system route, TCP_NODELAY and 30 s keepalive.
    pub fn system() -> Forward {
        Forward::new(|addr: String| async move {
            let stream = TcpStream::connect(addr).await?;
            tune_tcp(&stream);
            Ok(stream)
        })
    }

    pub fn dial(&self, addr: String) -> ForwardFuture {
        (self.0)(addr)
    }
}

impl fmt::Debug for Forward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Forward(..)")
    }
}

pub(crate) fn tune_tcp(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Proxy connection setup and proxy-side TLS.
#[derive(Clone, Debug, Default)]
pub struct DialOptions {
    /// Bounds the entire setup: TCP, proxy TLS, authentication and CONNECT.
    /// `None` uses 10 seconds. Returned tunnels have no imposed deadline.
    pub timeout: Option<Duration>,
    /// Opens the TCP connection to the proxy. `None` uses the system route.
    pub forward: Option<Forward>,
    /// Routes the connection to the proxy through a physical interface,
    /// around VPN/WARP tunnels. Mutually exclusive with `forward`.
    pub bypass: Option<BypassOptions>,
    /// TLS to HTTPS proxies (not to the target). `None` verifies against the
    /// bundled Mozilla roots. ALPN is always forced to `http/1.1`.
    pub tls: Option<Arc<ClientConfig>>,
}

/// A resolved, configured proxy. Cheap to clone and safe to share between
/// tasks; it owns no open resources and needs no close.
#[derive(Clone)]
pub struct Dialer {
    inner: Arc<Inner>,
}

struct Inner {
    spec: Spec,
    timeout: Duration,
    forward: Forward,
    tls: Arc<ClientConfig>,
    server_name: Option<ServerName<'static>>,
}

impl fmt::Debug for Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialer").field("spec", &self.inner.spec).field("timeout", &self.inner.timeout).finish()
    }
}

impl Dialer {
    /// Validates and snapshots a resolved configuration; no network I/O.
    pub fn new(spec: Spec, opts: DialOptions) -> Result<Dialer> {
        spec.validate()?;
        if spec.protocol == Protocol::Auto {
            return Err(Error::new(ErrorKind::Unresolved));
        }
        let timeout = opts.timeout.filter(|t| !t.is_zero()).unwrap_or(DEFAULT_TIMEOUT);
        let forward = match (opts.bypass, opts.forward) {
            (Some(_), Some(_)) => return Err(Error::invalid("forward and bypass are mutually exclusive")),
            (Some(bypass), None) => bypass_forward(bypass)?,
            (None, Some(forward)) => forward,
            (None, None) => Forward::system(),
        };
        let base = opts.tls.unwrap_or_else(tls::default_client_config);
        let server_name = match spec.protocol {
            Protocol::Https => Some(tls::server_name(&spec.host)?),
            _ => None,
        };
        Ok(Dialer {
            inner: Arc::new(Inner {
                spec,
                timeout,
                forward,
                tls: tls::with_alpn(&base, &[b"http/1.1"]),
                server_name,
            }),
        })
    }

    /// The resolved endpoint, including credentials.
    pub fn spec(&self) -> &Spec {
        &self.inner.spec
    }

    /// Opens a tunnel to `target` (`host:port`, IPv6 bracketed), completing
    /// proxy TLS, authentication and CONNECT before returning. SOCKS5 sends
    /// domain names to the proxy. There is never a direct fallback.
    pub async fn connect(&self, target: &str) -> Result<Tunnel> {
        self.connect_until(target, None).await
    }

    /// Like [`connect`](Self::connect), additionally bounded by `deadline`.
    pub(crate) async fn connect_until(&self, target: &str, deadline: Option<Instant>) -> Result<Tunnel> {
        let (host, port) = parse_target(target)?;
        let own = Instant::now() + self.inner.timeout;
        let deadline = deadline.map_or(own, |d| d.min(own));
        let stage = AtomicU8::new(Stage::Dial as u8);
        let protocol = self.inner.spec.protocol;
        match tokio::time::timeout_at(deadline, self.handshake(target, &host, port, &stage)).await {
            Ok(result) => result,
            Err(_) => Err(Error::new_op(Stage::from_u8(stage.load(Ordering::Relaxed)), protocol, 0, ErrorKind::Timeout, None)),
        }
    }

    async fn handshake(&self, target: &str, host: &str, port: u16, stage: &AtomicU8) -> Result<Tunnel> {
        let spec = &self.inner.spec;
        let p = spec.protocol;
        let mut io = self.inner.forward.dial(spec.address()).await.map_err(|e| Error::io_at(Stage::Dial, p, e))?;
        if let Some(name) = &self.inner.server_name {
            stage.store(Stage::ProxyTls as u8, Ordering::Relaxed);
            let tls = TlsConnector::from(self.inner.tls.clone())
                .connect(name.clone(), io)
                .await
                .map_err(|e| Error::io_at(Stage::ProxyTls, p, e))?;
            io = Box::new(tls);
        }
        match p {
            Protocol::Http | Protocol::Https => http_connect(io, spec, target, stage).await,
            Protocol::Socks5 => socks_connect(io, spec, host, port, stage).await,
            Protocol::Auto => Err(Error::new(ErrorKind::Unresolved)),
        }
    }
}

const MAX_CONNECT_HEADERS: usize = 64 << 10;

async fn http_connect(mut io: BoxIo, spec: &Spec, target: &str, stage: &AtomicU8) -> Result<Tunnel> {
    let p = spec.protocol;
    stage.store(Stage::Connect as u8, Ordering::Relaxed);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if spec.has_auth() {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", spec.username, spec.password));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    let io_err = |e| Error::io_at(Stage::Connect, p, e);
    io.write_all(req.as_bytes()).await.map_err(io_err)?;
    io.flush().await.map_err(io_err)?;
    // Bound untrusted headers; bytes after them already belong to the tunnel.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = io.read(&mut chunk).await.map_err(io_err)?;
        if n == 0 {
            return Err(io_err(io::ErrorKind::UnexpectedEof.into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 100];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                let code = resp.code.unwrap_or(0);
                if (200..300).contains(&code) {
                    return Ok(Tunnel::new(io, Bytes::copy_from_slice(&buf[len..])));
                }
                if code == 407 {
                    return Err(Error::new_op(Stage::Auth, p, code, ErrorKind::Auth, None));
                }
                return Err(Error::new_op(Stage::Connect, p, code, ErrorKind::Rejected, None));
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_CONNECT_HEADERS => continue,
            Ok(httparse::Status::Partial) => {
                return Err(Error::invalid("CONNECT response headers exceed limit").at(Stage::Connect, p, 0))
            }
            Err(e) => return Err(Error::new_op(Stage::Connect, p, 0, ErrorKind::Protocol, Some(Box::new(e)))),
        }
    }
}

async fn socks_connect(mut io: BoxIo, spec: &Spec, host: &str, port: u16, stage: &AtomicU8) -> Result<Tunnel> {
    let p = spec.protocol;
    let fail = |stage: Stage, code: u16, kind: ErrorKind| Error::new_op(stage, p, code, kind, None);
    let io_at = |stage: Stage| move |e| Error::io_at(stage, p, e);

    stage.store(Stage::Negotiation as u8, Ordering::Relaxed);
    let greeting: &[u8] = if spec.has_auth() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    io.write_all(greeting).await.map_err(io_at(Stage::Negotiation))?;
    io.flush().await.map_err(io_at(Stage::Negotiation))?;
    let mut reply = [0u8; 2];
    io.read_exact(&mut reply).await.map_err(io_at(Stage::Negotiation))?;
    if reply[0] != 5 {
        return Err(fail(Stage::Negotiation, 0, ErrorKind::Protocol));
    }
    match reply[1] {
        0 => {}
        2 => {
            if !spec.has_auth() {
                return Err(fail(Stage::Auth, 0, ErrorKind::Auth));
            }
            stage.store(Stage::Auth as u8, Ordering::Relaxed);
            let mut auth = Vec::with_capacity(3 + spec.username.len() + spec.password.len());
            auth.push(1);
            auth.push(spec.username.len() as u8);
            auth.extend_from_slice(spec.username.as_bytes());
            auth.push(spec.password.len() as u8);
            auth.extend_from_slice(spec.password.as_bytes());
            io.write_all(&auth).await.map_err(io_at(Stage::Auth))?;
            io.flush().await.map_err(io_at(Stage::Auth))?;
            io.read_exact(&mut reply).await.map_err(io_at(Stage::Auth))?;
            if reply[0] != 1 {
                return Err(fail(Stage::Auth, 0, ErrorKind::Protocol));
            }
            if reply[1] != 0 {
                return Err(fail(Stage::Auth, reply[1] as u16, ErrorKind::Auth));
            }
        }
        255 => return Err(fail(Stage::Auth, 0, ErrorKind::Auth)),
        code => return Err(fail(Stage::Negotiation, code as u16, ErrorKind::Protocol)),
    }

    stage.store(Stage::Connect as u8, Ordering::Relaxed);
    let mut packet = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            // Go's To4 treats IPv4-mapped addresses as IPv4.
            Some(v4) => {
                packet.push(1);
                packet.extend_from_slice(&v4.octets());
            }
            None => {
                packet.push(4);
                packet.extend_from_slice(&ip.octets());
            }
        },
        Err(_) => {
            if host.len() > 255 {
                return Err(Error::invalid("SOCKS target domain length").at(Stage::Connect, p, 0));
            }
            packet.push(3);
            packet.push(host.len() as u8);
            packet.extend_from_slice(host.as_bytes());
        }
    }
    packet.extend_from_slice(&port.to_be_bytes());
    io.write_all(&packet).await.map_err(io_at(Stage::Connect))?;
    io.flush().await.map_err(io_at(Stage::Connect))?;
    let mut header = [0u8; 4];
    io.read_exact(&mut header).await.map_err(io_at(Stage::Connect))?;
    if header[0] != 5 || header[2] != 0 {
        return Err(fail(Stage::Connect, 0, ErrorKind::Protocol));
    }
    if header[1] != 0 {
        return Err(fail(Stage::Connect, header[1] as u16, ErrorKind::Rejected));
    }
    let n = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            io.read_exact(&mut len).await.map_err(io_at(Stage::Connect))?;
            if len[0] == 0 {
                return Err(fail(Stage::Connect, 0, ErrorKind::Protocol));
            }
            len[0] as usize
        }
        _ => return Err(fail(Stage::Connect, 0, ErrorKind::Protocol)),
    };
    let mut rest = vec![0u8; n + 2];
    io.read_exact(&mut rest).await.map_err(io_at(Stage::Connect))?;
    Ok(Tunnel::new(io, Bytes::new()))
}
