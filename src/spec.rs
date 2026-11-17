use std::{fmt, net::IpAddr, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, ErrorKind, Result};

/// Wire protocol used to reach a proxy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Unknown yet; resolved by [`detect`](crate::detect) when needed.
    #[default]
    Auto,
    Http,
    Https,
    Socks5,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Auto => "auto",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Socks5 => "socks5",
        }
    }

    /// Normalizes a scheme, including `socks` and `socks5h` aliases.
    /// An empty string means `Auto`; unknown schemes return `ErrorKind::Protocol`.
    pub fn parse(raw: &str) -> Result<Protocol> {
        match raw.to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Protocol::Auto),
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            "socks" | "socks5" | "socks5h" => Ok(Protocol::Socks5),
            _ => Err(Error::new(ErrorKind::Protocol)),
        }
    }

    /// True for HTTP, HTTPS and SOCKS5.
    pub fn is_concrete(self) -> bool {
        self != Protocol::Auto
    }
}

impl FromStr for Protocol {
    type Err = Error;
    fn from_str(s: &str) -> Result<Protocol> {
        Protocol::parse(s)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Protocol {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Protocol, D::Error> {
        let raw = Option::<String>::deserialize(d)?.unwrap_or_default();
        Protocol::parse(&raw).map_err(|_| de::Error::custom("unsupported proxy protocol"))
    }
}

/// A proxy endpoint. `Display` and `Debug` redact credentials;
/// [`Spec::url`] and serde serialization intentionally contain them.
/// SOCKS5 always sends target domain names to the proxy (remote DNS).
#[derive(Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Spec {
    #[serde(default)]
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

impl Spec {
    pub fn new(protocol: Protocol, host: impl Into<String>, port: u16) -> Spec {
        Spec { protocol, host: host.into(), port, ..Spec::default() }
    }

    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Spec {
        self.username = username.into();
        self.password = password.into();
        self
    }

    /// `host:port`, with brackets around IPv6 addresses.
    pub fn address(&self) -> String {
        join_host_port(&self.host, self.port)
    }

    pub fn has_auth(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }

    /// Explicit credential-bearing export, e.g. `socks5://user:pass@host:1080`.
    /// Credentials are percent-escaped; [`parse`](crate::parse) reads it back.
    pub fn url(&self) -> String {
        let mut out = format!("{}://", self.protocol);
        if self.has_auth() {
            out.push_str(&escape_userinfo(&self.username));
            out.push(':');
            out.push_str(&escape_userinfo(&self.password));
            out.push('@');
        }
        out.push_str(&self.address());
        out
    }

    /// Permits `Auto`; [`Dialer::new`](crate::Dialer::new) requires a concrete protocol.
    pub fn validate(&self) -> Result<()> {
        validate_host(&self.host)?;
        if self.port == 0 {
            return Err(Error::invalid("port must be in 1..65535"));
        }
        if self.username.contains(['\r', '\n', '\0']) || self.password.contains(['\r', '\n', '\0']) {
            return Err(Error::invalid("control characters in credentials"));
        }
        if self.has_auth()
            && self.protocol == Protocol::Socks5
            && (!(1..=255).contains(&self.username.len())
                || !(1..=255).contains(&self.password.len()))
        {
            return Err(Error::invalid("SOCKS5 username and password must each be 1..255 bytes"));
        }
        if self.has_auth()
            && matches!(self.protocol, Protocol::Http | Protocol::Https)
            && self.username.contains(':')
        {
            return Err(Error::invalid("HTTP Basic username contains a colon"));
        }
        Ok(())
    }

    /// Validates and lower-cases DNS names, like the parsers do.
    pub(crate) fn validated(mut self) -> Result<Spec> {
        self.validate()?;
        if self.host.parse::<IpAddr>().is_err() {
            self.host = self.host.to_ascii_lowercase();
        }
        Ok(self)
    }
}

impl fmt::Display for Spec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = if self.has_auth() { "REDACTED@" } else { "" };
        write!(f, "{}://{}{}", self.protocol, auth, self.address())
    }
}

impl fmt::Debug for Spec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Spec {
    type Err = Error;
    fn from_str(s: &str) -> Result<Spec> {
        crate::parse(s)
    }
}

pub(crate) fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn validate_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.contains(['[', ']', '/', '@', '?', '#', '%', '\\'])
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::invalid("host"));
    }
    let is_ip = host.parse::<IpAddr>().is_ok();
    if host.contains(':') && !is_ip {
        return Err(Error::invalid("IPv6 address"));
    }
    if is_ip {
        return Ok(());
    }
    if host.len() > 253 {
        return Err(Error::invalid("host length"));
    }
    for label in host.strip_suffix('.').unwrap_or(host).split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 || b[0] == b'-' || b[b.len() - 1] == b'-' {
            return Err(Error::invalid("DNS label"));
        }
        if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
            return Err(Error::invalid("host must be ASCII DNS or IP; convert IDNs to punycode"));
        }
    }
    Ok(())
}

pub(crate) fn parse_port(raw: &str) -> Result<u16> {
    if raw.is_empty() || !raw.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::invalid("port"));
    }
    match raw.parse::<u32>() {
        Ok(n @ 1..=65535) => Ok(n as u16),
        _ => Err(Error::invalid("port must be in 1..65535")),
    }
}

/// Go `net.SplitHostPort`.
pub(crate) fn split_host_port(hostport: &str) -> Option<(&str, &str)> {
    let i = hostport.rfind(':')?;
    let (host, j, k);
    if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        if end + 1 == hostport.len() || end + 1 != i {
            return None;
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return None;
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains('[') || hostport[k..].contains(']') {
        return None;
    }
    Some((host, &hostport[i + 1..]))
}

/// Validates a `host:port` target; IPv6 must be bracketed.
pub(crate) fn parse_target(addr: &str) -> Result<(String, u16)> {
    let (host, port) = split_host_port(addr).ok_or_else(|| Error::invalid("target requires host:port"))?;
    if addr.starts_with('[') && (host.parse::<IpAddr>().is_err() || !host.contains(':')) {
        return Err(Error::invalid("brackets require an IPv6 address"));
    }
    validate_host(host)?;
    Ok((host.to_string(), parse_port(port)?))
}

/// Escapes userinfo like Go `url.UserPassword(...).String()`.
fn escape_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~$&+,;=".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
