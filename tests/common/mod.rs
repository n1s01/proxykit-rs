#![allow(dead_code)]

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use base64::Engine as _;
use proxykit::{
    http_body_util::Full,
    hyper::{self, body::Bytes, Request, Response},
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;

pub async fn listen() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, addr)
}

/// Echoes everything back.
pub async fn echo_server() -> SocketAddr {
    let (l, addr) = listen().await;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Accepts connections and never answers.
pub async fn silent_server() -> SocketAddr {
    let (l, addr) = listen().await;
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    addr
}

pub type Seen = Arc<Mutex<Vec<String>>>;

/// Minimal SOCKS5 server (RFC 1928/1929) recording requested targets.
pub async fn socks5_proxy(auth: Option<(&'static str, &'static str)>) -> (SocketAddr, Seen) {
    let (l, addr) = listen().await;
    let seen: Seen = Arc::default();
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let _ = socks5_session(s, auth, record).await;
            });
        }
    });
    (addr, seen)
}

async fn socks5_session(mut s: TcpStream, auth: Option<(&str, &str)>, seen: Seen) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    match auth {
        None => s.write_all(&[5, 0]).await?,
        Some((user, pass)) => {
            if !methods.contains(&2) {
                s.write_all(&[5, 0xFF]).await?;
                return Ok(());
            }
            s.write_all(&[5, 2]).await?;
            let ver = s.read_u8().await?;
            let ulen = s.read_u8().await? as usize;
            let mut u = vec![0u8; ulen];
            s.read_exact(&mut u).await?;
            let plen = s.read_u8().await? as usize;
            let mut p = vec![0u8; plen];
            s.read_exact(&mut p).await?;
            let ok = ver == 1 && u == user.as_bytes() && p == pass.as_bytes();
            s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
            if !ok {
                return Ok(());
            }
        }
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            format!("[{}]", std::net::Ipv6Addr::from(b))
        }
        _ => {
            let n = s.read_u8().await? as usize;
            let mut b = vec![0u8; n];
            s.read_exact(&mut b).await?;
            String::from_utf8_lossy(&b).into_owned()
        }
    };
    let port = s.read_u16().await?;
    let target = format!("{host}:{port}");
    seen.lock().unwrap().push(target.clone());
    match TcpStream::connect(target).await {
        Ok(mut up) => {
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
            let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
        }
        Err(_) => s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
    }
    Ok(())
}

#[derive(Clone, Default)]
pub struct HttpProxyOptions {
    pub auth: Option<(&'static str, &'static str)>,
    pub tls: Option<TlsAcceptor>,
    /// Bytes sent right after the 200 reply, before any target data.
    pub suffix: &'static [u8],
}

/// HTTP CONNECT proxy, optionally behind TLS (an HTTPS proxy).
pub async fn http_proxy(opts: HttpProxyOptions) -> SocketAddr {
    let (l, addr) = listen().await;
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let opts = opts.clone();
            tokio::spawn(async move {
                match &opts.tls {
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(s).await {
                            let _ = http_session(tls, &opts).await;
                        }
                    }
                    None => {
                        let _ = http_session(s, &opts).await;
                    }
                }
            });
        }
    });
    addr
}

async fn http_session<S>(mut s: S, opts: &HttpProxyOptions) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await? == 0 {
            return Ok(());
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (method, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default().to_string());
    if method != "CONNECT" {
        s.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Ok(());
    }
    if let Some((user, pass)) = opts.auth {
        let want = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")));
        let ok = lines.any(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:") && l[20..].trim() == want);
        if !ok {
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n").await?;
            return Ok(());
        }
    }
    match TcpStream::connect(&target).await {
        Ok(mut up) => {
            let mut reply = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
            reply.extend_from_slice(opts.suffix);
            s.write_all(&reply).await?;
            let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
        }
        Err(_) => s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?,
    }
    Ok(())
}

/// A self-signed certificate for 127.0.0.1/localhost and a client config trusting it.
pub fn tls_pair() -> (TlsAcceptor, Arc<ClientConfig>) {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let server = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    (TlsAcceptor::from(Arc::new(server)), proxykit::tls::client_config_with_roots(roots))
}

async fn route(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, body): (u16, Bytes) = match req.uri().path() {
        "/" => (200, Bytes::from_static(b"ok")),
        "/204" => (204, Bytes::new()),
        "/404" => (404, Bytes::from_static(b"missing")),
        "/redirect" => (302, Bytes::new()),
        "/big" => (200, Bytes::from(vec![7u8; 1 << 20])),
        "/geo" => (200, Bytes::from_static(br#"{"ip":"192.0.2.7","country":"nl"}"#)),
        _ => (404, Bytes::new()),
    };
    let mut resp = Response::new(Full::new(body));
    *resp.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    if status == 302 {
        resp.headers_mut().insert("location", "/".parse().unwrap());
    }
    Ok(resp)
}

/// HTTP origin with fixed routes; optionally HTTPS.
pub async fn origin(tls: Option<TlsAcceptor>) -> SocketAddr {
    let (l, addr) = listen().await;
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(route);
                let builder = hyper::server::conn::http1::Builder::new();
                match tls {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(s).await {
                            let _ = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
                        }
                    }
                    None => {
                        let _ = builder.serve_connection(hyper_util::rt::TokioIo::new(s), service).await;
                    }
                }
            });
        }
    });
    addr
}
