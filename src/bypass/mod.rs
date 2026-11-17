//! VPN/WARP bypass: binds connections to a physical interface.

mod dns;
mod sys;

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use futures_util::{stream::FuturesUnordered, StreamExt};
use tokio::{
    net::{TcpSocket, TcpStream},
    time::Instant,
};

use crate::{
    dial::{tune_tcp, Forward},
    error::{Error, ErrorKind, Result},
    spec::{parse_port, split_host_port},
};

/// Routes connections to the proxy through a physical network interface,
/// skipping VPN/WARP tunnels (TUN). There is deliberately no fallback through
/// the tunnel: without a physical interface the dial fails with
/// `ErrorKind::NoInterface`. Loopback addresses are never bound.
#[derive(Clone, Debug, Default)]
pub struct BypassOptions {
    /// Pins an interface by name. Empty selects a running interface with a MAC
    /// address, broadcast and a routable IPv4 address whose name does not look
    /// like a tunnel or a virtual switch (macOS: `en*`).
    pub interface: String,
    /// `ip:port` resolvers queried over the same interface, round-robin.
    /// Under a VPN the system resolver may return tunnel-only (fake-ip)
    /// addresses. Empty uses 1.1.1.1, 8.8.8.8 and 77.88.8.8. When plain DNS
    /// gets no answer, the same servers are asked over TLS on port 853.
    pub dns: Vec<String>,
}

/// Whether interface binding exists on this platform (macOS and Linux).
/// Elsewhere `Dialer::new` rejects `DialOptions::bypass` with
/// `ErrorKind::BypassUnsupported`.
pub fn bypass_supported() -> bool {
    sys::SUPPORTED
}

const DEFAULT_DNS: [&str; 3] = ["1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"];

/// The bound forward dialer behind `DialOptions::bypass`, for connections
/// that are not proxy tunnels, such as diagnostics (Go `BypassDialContext`).
pub fn bypass_forward(opts: BypassOptions) -> Result<Forward> {
    if !sys::SUPPORTED {
        return Err(Error::new(ErrorKind::BypassUnsupported));
    }
    let raw: Vec<String> = if opts.dns.is_empty() {
        DEFAULT_DNS.iter().map(|s| s.to_string()).collect()
    } else {
        opts.dns
    };
    let mut dns = Vec::with_capacity(raw.len());
    for server in &raw {
        let (host, port) = split_host_port(server).ok_or_else(|| Error::invalid("bypass DNS requires ip:port"))?;
        let ip: IpAddr = host.parse().map_err(|_| Error::invalid("bypass DNS requires ip:port"))?;
        dns.push(SocketAddr::new(ip, parse_port(port)?));
    }
    let bypass = Arc::new(Bypass {
        iface: opts.interface,
        dns,
        next: AtomicUsize::new(0),
        dot: AtomicBool::new(false),
    });
    Ok(Forward::new(move |addr: String| {
        let bypass = bypass.clone();
        async move { bypass.dial(&addr).await }
    }))
}

struct Bypass {
    iface: String,
    dns: Vec<SocketAddr>,
    next: AtomicUsize,
    /// Plain DNS was blocked and DNS over TLS answered last time.
    dot: AtomicBool,
}

fn crate_err(kind: ErrorKind) -> io::Error {
    io::Error::other(Error::new(kind))
}

impl Bypass {
    async fn dial(&self, addr: &str) -> io::Result<TcpStream> {
        let (host, port) =
            split_host_port(addr).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address requires host:port"))?;
        let port: u16 = port.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "port"))?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.connect(SocketAddr::new(ip, port)).await;
        }
        let ips = self.lookup(host).await?;
        self.dial_first(&ips, port).await
    }

    /// Connects to whichever address answers first. A new attempt starts every
    /// 250 ms or as soon as one fails, so an address that silently drops
    /// packets costs a fraction of a second instead of the whole deadline.
    async fn dial_first(&self, ips: &[IpAddr], port: u16) -> io::Result<TcpStream> {
        let mut pending = FuturesUnordered::new();
        let mut started = 0;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "host has no addresses");
        let next = tokio::time::sleep(Duration::ZERO);
        tokio::pin!(next);
        loop {
            if started == ips.len() && pending.is_empty() {
                return Err(last);
            }
            tokio::select! {
                _ = &mut next, if started < ips.len() => {
                    pending.push(self.connect(SocketAddr::new(ips[started], port)));
                    started += 1;
                    next.as_mut().reset(Instant::now() + Duration::from_millis(250));
                }
                Some(r) = pending.next(), if !pending.is_empty() => match r {
                    Ok(stream) => return Ok(stream),
                    Err(e) => {
                        last = e;
                        next.as_mut().reset(Instant::now());
                    }
                },
            }
        }
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        if !addr.ip().is_loopback() {
            let iface = self.pick()?;
            sys::bind(&socket, addr.is_ipv6(), &iface)?;
        }
        let stream = socket.connect(addr).await?;
        tune_tcp(&stream);
        Ok(stream)
    }

    /// Evaluated per connection: interfaces come and go with Wi-Fi and VPN.
    fn pick(&self) -> io::Result<sys::Iface> {
        let ifaces = sys::interfaces()?;
        if !self.iface.is_empty() {
            return ifaces
                .into_iter()
                .find(|i| i.name == self.iface && i.up)
                .ok_or_else(|| crate_err(ErrorKind::NoInterface));
        }
        ifaces
            .into_iter()
            .find(|i| {
                i.up && i.running
                    && !i.loopback
                    && !i.point_to_point
                    && sys::physical_name(&i.name)
                    // TUN adapters are layer 3: no MAC and no broadcast. This
                    // catches tunnels whatever the VPN client named them.
                    && i.has_mac
                    && i.broadcast
                    && i.has_ipv4
            })
            .ok_or_else(|| crate_err(ErrorKind::NoInterface))
    }

    /// Resolves over the physical interface. VPN clients in strict-route mode
    /// drop plain DNS outside the tunnel, so DNS over TLS is the second try;
    /// whichever worked last goes first next time.
    async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let secure_first = self.dot.load(Ordering::Relaxed);
        let order = if secure_first { [true, false] } else { [false, true] };
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out");
        for (i, secure) in order.into_iter().enumerate() {
            let attempt = async {
                if secure {
                    dns::lookup_tls(self, host).await
                } else {
                    dns::lookup_plain(self, host).await
                }
            };
            let outcome = if i == 0 {
                // Blocked DNS is silent; leave time for the other transport.
                tokio::time::timeout(Duration::from_secs(2), attempt)
                    .await
                    .unwrap_or_else(|_| Err(dns::DnsError::Other(io::ErrorKind::TimedOut.into())))
            } else {
                attempt.await
            };
            match outcome {
                Ok(ips) => {
                    self.dot.store(secure, Ordering::Relaxed);
                    return Ok(ips);
                }
                Err(dns::DnsError::NotFound) => return Err(io::Error::new(io::ErrorKind::NotFound, "no such host")),
                Err(dns::DnsError::Other(e)) => last = e,
            }
        }
        Err(last)
    }

    fn next_server(&self) -> SocketAddr {
        self.dns[self.next.fetch_add(1, Ordering::Relaxed) % self.dns.len()]
    }
}
