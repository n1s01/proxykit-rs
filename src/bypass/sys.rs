//! Platform layer: interface enumeration and socket binding.
//! macOS: `IP_BOUND_IF`, interfaces `en*`. Linux: `SO_BINDTODEVICE`.

use std::io;

#[cfg(unix)]
pub(crate) use std::os::fd::AsFd as AsSocket;

#[cfg(not(unix))]
pub(crate) trait AsSocket {}
#[cfg(not(unix))]
impl<T> AsSocket for T {}

pub(crate) const SUPPORTED: bool = cfg!(any(target_os = "macos", target_os = "linux"));

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub(crate) struct Iface {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub broadcast: bool,
    pub has_mac: bool,
    /// A routable (non link-local) IPv4 address.
    pub has_ipv4: bool,
}

#[cfg(unix)]
pub(crate) fn interfaces() -> io::Result<Vec<Iface>> {
    use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};

    let mut out: Vec<Iface> = Vec::new();
    for ifa in getifaddrs().map_err(io::Error::from)? {
        let pos = match out.iter().position(|i| i.name == ifa.interface_name) {
            Some(p) => p,
            None => {
                let index = nix::net::if_::if_nametoindex(ifa.interface_name.as_str()).unwrap_or(0);
                out.push(Iface { name: ifa.interface_name.clone(), index, ..Iface::default() });
                out.len() - 1
            }
        };
        let iface = &mut out[pos];
        let flags = ifa.flags;
        iface.up = flags.contains(InterfaceFlags::IFF_UP);
        iface.running = flags.contains(InterfaceFlags::IFF_RUNNING);
        iface.loopback = flags.contains(InterfaceFlags::IFF_LOOPBACK);
        iface.point_to_point = flags.contains(InterfaceFlags::IFF_POINTOPOINT);
        iface.broadcast = flags.contains(InterfaceFlags::IFF_BROADCAST);
        if let Some(addr) = ifa.address {
            if let Some(link) = addr.as_link_addr() {
                if link.addr().is_some() {
                    iface.has_mac = true;
                }
            }
            if let Some(sin) = addr.as_sockaddr_in() {
                let ip = sin.ip();
                if !ip.is_link_local() {
                    iface.has_ipv4 = true;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(not(unix))]
pub(crate) fn interfaces() -> io::Result<Vec<Iface>> {
    Ok(Vec::new())
}

#[cfg(target_os = "macos")]
pub(crate) fn physical_name(name: &str) -> bool {
    // Wi-Fi and Ethernet; VPN tunnels are utun*.
    name.starts_with("en")
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn physical_name(name: &str) -> bool {
    !virtual_name(name)
}

/// Tunnel, bridge and hypervisor adapters by name.
#[allow(dead_code)]
pub(crate) fn virtual_name(name: &str) -> bool {
    const MARKS: &[&str] = &[
        "tun", "tap", "wg", "ppp", "warp", "vpn", "wireguard", "tailscale", "zerotier", "zt", "xray", "v2ray",
        "sing-box", "clash", "mihomo", "hiddify", "nekoray", "outline", "nordlynx", "ipsec", "docker", "veth", "br-",
        "virbr", "vmnet", "vmware", "virtual", "vethernet", "hyper-v", "loopback", "bluetooth",
    ];
    let name = name.to_lowercase();
    MARKS.iter().any(|m| name.contains(m))
}

#[cfg(target_os = "macos")]
pub(crate) fn bind<S: AsSocket>(socket: &S, ipv6: bool, iface: &Iface) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(iface.index);
    let sock = socket2::SockRef::from(socket);
    if ipv6 {
        sock.bind_device_by_index_v6(index)
    } else {
        sock.bind_device_by_index_v4(index)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn bind<S: AsSocket>(socket: &S, _ipv6: bool, iface: &Iface) -> io::Result<()> {
    socket2::SockRef::from(socket).bind_device(Some(iface.name.as_bytes()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn bind<S: AsSocket>(_: &S, _: bool, _: &Iface) -> io::Result<()> {
    Err(io::Error::other(crate::Error::new(crate::ErrorKind::BypassUnsupported)))
}
