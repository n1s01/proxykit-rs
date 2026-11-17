//! Minimal A-record resolver over sockets bound to the physical interface:
//! plain UDP (TCP on truncation) and DNS over TLS.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use futures_util::{stream::FuturesUnordered, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};
use tokio_rustls::TlsConnector;

use super::{sys, Bypass};
use crate::tls;

pub(super) enum DnsError {
    NotFound,
    Other(io::Error),
}

impl From<io::Error> for DnsError {
    fn from(e: io::Error) -> DnsError {
        DnsError::Other(e)
    }
}

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn bad(msg: &'static str) -> DnsError {
    DnsError::Other(io::Error::new(io::ErrorKind::InvalidData, msg))
}

fn query_id() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::getrandom(&mut b);
    u16::from_be_bytes(b)
}

fn build_query(id: u16, host: &str) -> Result<Vec<u8>, DnsError> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // recursion desired
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(bad("DNS label"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&TYPE_A.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(q)
}

fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let len = *msg.get(pos).ok_or_else(|| bad("truncated name"))?;
        match len {
            0 => return Ok(pos + 1),
            l if l & 0xC0 == 0xC0 => return Ok(pos + 2),
            l => pos += 1 + l as usize,
        }
    }
}

fn read_u16(msg: &[u8], pos: usize) -> Result<u16, DnsError> {
    msg.get(pos..pos + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).ok_or_else(|| bad("truncated message"))
}

/// Returns addresses and the truncation flag.
fn parse_response(id: u16, msg: &[u8]) -> Result<(Vec<IpAddr>, bool), DnsError> {
    if msg.len() < 12 || read_u16(msg, 0)? != id || msg[2] & 0x80 == 0 {
        return Err(bad("unexpected DNS response"));
    }
    let truncated = msg[2] & 0x02 != 0;
    match msg[3] & 0x0F {
        0 => {}
        3 => return Err(DnsError::NotFound),
        _ => return Err(bad("DNS server failure")),
    }
    let questions = read_u16(msg, 4)?;
    let answers = read_u16(msg, 6)?;
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..answers {
        pos = skip_name(msg, pos)?;
        let rtype = read_u16(msg, pos)?;
        let class = read_u16(msg, pos + 2)?;
        let len = read_u16(msg, pos + 8)? as usize;
        pos += 10;
        let data = msg.get(pos..pos + len).ok_or_else(|| bad("truncated record"))?;
        if rtype == TYPE_A && class == CLASS_IN && len == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])));
        }
        pos += len;
    }
    if ips.is_empty() && !truncated {
        return Err(DnsError::NotFound);
    }
    Ok((ips, truncated))
}

fn bind_if_remote<S: sys::AsSocket>(b: &Bypass, socket: &S, server: SocketAddr) -> io::Result<()> {
    if server.ip().is_loopback() {
        return Ok(());
    }
    sys::bind(socket, server.is_ipv6(), &b.pick()?)
}

async fn udp_query(b: &Bypass, server: SocketAddr, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let socket = UdpSocket::bind(local).await?;
    bind_if_remote(b, &socket, server)?;
    socket.connect(server).await?;
    let id = query_id();
    socket.send(&build_query(id, host)?).await?;
    let mut buf = [0u8; 1500];
    loop {
        let n = socket.recv(&mut buf).await?;
        match parse_response(id, &buf[..n]) {
            Ok((_, true)) => return tcp_query(b, server, host).await,
            Ok((ips, false)) => return Ok(ips),
            // Stray datagrams with another id are ignored.
            Err(DnsError::Other(e)) if e.kind() == io::ErrorKind::InvalidData && read_u16(&buf[..n], 0).ok() != Some(id) => {}
            Err(e) => return Err(e),
        }
    }
}

async fn tcp_query(b: &Bypass, server: SocketAddr, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let socket = if server.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    bind_if_remote(b, &socket, server)?;
    let mut stream = socket.connect(server).await?;
    stream_query(&mut stream, host).await
}

/// Length-prefixed exchange used by DNS over TCP and DNS over TLS.
async fn stream_query<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let id = query_id();
    let q = build_query(id, host)?;
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    stream.write_all(&framed).await?;
    stream.flush().await?;
    let len = stream.read_u16().await? as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    parse_response(id, &msg).map(|(ips, _)| ips)
}

pub(super) async fn lookup_plain(b: &Bypass, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let mut last = DnsError::Other(io::ErrorKind::TimedOut.into());
    for _ in 0..b.dns.len().max(2) {
        let server = b.next_server();
        match tokio::time::timeout(Duration::from_millis(800), udp_query(b, server, host)).await {
            Ok(Err(DnsError::NotFound)) => return Err(DnsError::NotFound),
            Ok(Ok(ips)) => return Ok(ips),
            Ok(Err(e)) => last = e,
            Err(_) => last = DnsError::Other(io::ErrorKind::TimedOut.into()),
        }
    }
    Err(last)
}

/// Every server is tried at once on port 853 and the first handshake wins:
/// networks commonly drop DoT to one provider.
pub(super) async fn lookup_tls(b: &Bypass, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let config = tls::default_client_config();
    let mut racing = FuturesUnordered::new();
    for server in &b.dns {
        let addr = SocketAddr::new(server.ip(), 853);
        let config = config.clone();
        racing.push(async move {
            let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            bind_if_remote(b, &socket, addr)?;
            let stream = tokio::time::timeout(Duration::from_secs(5), socket.connect(addr))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            let name = tls::server_name(&addr.ip().to_string()).map_err(io::Error::other)?;
            TlsConnector::from(config).connect(name, stream).await
        });
    }
    let mut last = io::Error::new(io::ErrorKind::NotConnected, "no DNS over TLS server");
    while let Some(r) = racing.next().await {
        match r {
            Ok(mut stream) => {
                drop(racing);
                return stream_query(&mut stream, host).await;
            }
            Err(e) => last = e,
        }
    }
    Err(DnsError::Other(last))
}
