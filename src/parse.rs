use std::{borrow::Cow, fmt, net::IpAddr};

use crate::{
    error::{Error, ErrorKind, Result},
    spec::{parse_port, parse_target, Protocol, Spec},
};

/// Field order and separators of a compact proxy string, e.g.
/// `"host@port:pass:login"`. Fields: `host`/`ip`, `port`,
/// `user`/`username`/`login`, `pass`/`password`. A single `@` may join an
/// adjacent host and port, or divide a credential pair from an endpoint pair;
/// all other fields use `:`. The empty layout means automatic detection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Layout(Cow<'static, str>);

impl Layout {
    /// Automatic: conventional orders first, others only when unambiguous.
    pub const AUTO: Layout = Layout(Cow::Borrowed(""));
    pub const HOST_PORT_USER_PASS: Layout = Layout(Cow::Borrowed("host:port:user:pass"));
    pub const USER_PASS_HOST_PORT: Layout = Layout(Cow::Borrowed("user:pass:host:port"));

    pub const fn new(layout: &'static str) -> Layout {
        Layout(Cow::Borrowed(layout))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_auto(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for Layout {
    fn from(s: &str) -> Layout {
        Layout(Cow::Owned(s.to_string()))
    }
}

impl From<String> for Layout {
    fn from(s: String) -> Layout {
        Layout(Cow::Owned(s))
    }
}

impl fmt::Display for Layout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Explicit defaults for otherwise underspecified inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOptions {
    /// Protocol assigned to inputs without a scheme. `Auto` by default.
    pub default_protocol: Protocol,
    /// Explicit field order; [`Layout::AUTO`] by default.
    pub layout: Layout,
}

/// Parses one endpoint without guessing an absent wire protocol.
pub fn parse(raw: &str) -> Result<Spec> {
    parse_with(raw, &ParseOptions::default())
}

/// Accepts standard URLs and compact `:`-separated fields; `@` may separate
/// host and port, or credentials and endpoint as in `user:pass@host:port` and
/// `host:port@user:pass`. A non-empty layout defines field order and exact
/// separators, including after a protocol prefix. URL credentials use percent
/// escaping; compact and explicit-layout credentials are literal.
pub fn parse_with(raw: &str, opts: &ParseOptions) -> Result<Spec> {
    let layout = validate_options(opts)?;
    let mut protocol = opts.default_protocol;
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::invalid("empty input"));
    }
    let mut body = raw;
    let mut prefixed = false;
    if let Some(at) = raw.find("://") {
        prefixed = true;
        let p = Protocol::parse(&raw[..at])?;
        if p != Protocol::Auto {
            protocol = p;
        }
        body = &raw[at + 3..];
    }
    if let Some(layout) = layout {
        return parse_fields(body, protocol, &layout);
    }
    // A valid URL has declared field roles. Never reinterpret failed
    // credentials on a valid authority as a different endpoint.
    if prefixed {
        match parse_url(raw, protocol) {
            Ok(spec) => return Ok(spec),
            Err(url_err) => {
                if let Some(at) = body.rfind('@') {
                    let tail = &body[at + 1..];
                    if parse_target(tail.strip_suffix('/').unwrap_or(tail)).is_ok() {
                        return Err(url_err);
                    }
                }
                if body.contains(['/', '?', '#', '%']) {
                    return Err(url_err);
                }
            }
        }
    }
    parse_auto_fields(body, protocol)
}

pub(crate) fn validate_options(opts: &ParseOptions) -> Result<Option<FieldLayout>> {
    if opts.layout.is_auto() {
        Ok(None)
    } else {
        parse_layout(opts.layout.as_str()).map(Some)
    }
}

/// A one-based line number paired with its parsing error.
#[derive(Clone, Debug)]
pub struct LineError {
    pub line: usize,
    pub error: Error,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.error)
    }
}

impl std::error::Error for LineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Parses a list, one proxy per line. Preserves order and duplicates; empty
/// lines and lines starting with `#` are skipped. Secrets are never echoed.
pub fn parse_lines(text: &str, opts: &ParseOptions) -> (Vec<Spec>, Vec<LineError>) {
    let mut specs = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_with(line, opts) {
            Ok(s) => specs.push(s),
            Err(error) => errors.push(LineError { line: i + 1, error }),
        }
    }
    (specs, errors)
}

// ---------------------------------------------------------------------------
// URL form

fn url_err() -> Error {
    Error::invalid("URL syntax or escaping")
}

fn parse_url(raw: &str, default_protocol: Protocol) -> Result<Spec> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(url_err());
    }
    let at = raw.find("://").ok_or_else(url_err)?;
    let mut protocol = Protocol::parse(&raw[..at])?;
    if protocol == Protocol::Auto {
        protocol = default_protocol;
    }
    let rest = &raw[at + 3..];
    if rest.contains(['?', '#']) {
        return Err(Error::invalid("URL must contain only a proxy authority"));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if !path.is_empty() && path != "/" {
        return Err(Error::invalid("URL must contain only a proxy authority"));
    }
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    let (host, port) = parse_target(hostport)
        .map_err(|_| Error::invalid("URL requires an explicit port and bracketed IPv6"))?;
    let mut spec = Spec { protocol, host, port, ..Spec::default() };
    if let Some(info) = userinfo {
        if !valid_userinfo(info) {
            return Err(url_err());
        }
        let (user, pass) = info.split_once(':').unwrap_or((info, ""));
        spec.username = unescape(user)?;
        spec.password = unescape(pass)?;
    }
    spec.validated()
}

fn valid_userinfo(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&b))
}

fn unescape(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            match (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                _ => return Err(url_err()),
            }
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| url_err())
}

// ---------------------------------------------------------------------------
// Compact fields

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Host,
    Port,
    User,
    Pass,
}

impl Field {
    fn is_endpoint(self) -> bool {
        matches!(self, Field::Host | Field::Port)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FieldLayout {
    fields: Vec<Field>,
    separators: Vec<u8>,
}

/// Validates a tiny declarative format, not a regular expression.
fn parse_layout(layout: &str) -> Result<FieldLayout> {
    let (words, separators) = split_fields(layout).map_err(|_| Error::invalid("layout syntax"))?;
    let mut seen = [false; 4];
    let mut fields = Vec::with_capacity(words.len());
    for word in words {
        let field = match word.trim().to_ascii_lowercase().as_str() {
            "host" | "ip" => Field::Host,
            "port" => Field::Port,
            "user" | "username" | "login" => Field::User,
            "pass" | "password" => Field::Pass,
            _ => return Err(Error::invalid("unknown layout field")),
        };
        if seen[field as usize] {
            return Err(Error::invalid("duplicate layout field"));
        }
        seen[field as usize] = true;
        fields.push(field);
    }
    if !seen[Field::Host as usize] || !seen[Field::Port as usize] {
        return Err(Error::invalid("layout requires host and port"));
    }
    if !valid_separators(&fields, &separators) {
        return Err(Error::invalid("@ must separate host and port, or credentials and endpoint"));
    }
    Ok(FieldLayout { fields, separators })
}

/// Allows a single `@`, either joining the endpoint pair or dividing a
/// credential pair from an adjacent host and port.
fn valid_separators(fields: &[Field], separators: &[u8]) -> bool {
    let mut at = None;
    for (i, s) in separators.iter().enumerate() {
        if *s == b'@' {
            if at.is_some() {
                return false;
            }
            at = Some(i);
        }
    }
    let Some(at) = at else { return true };
    if fields[at].is_endpoint() && fields[at + 1].is_endpoint() {
        return true;
    }
    at == 1
        && fields.len() == 4
        && fields[0].is_endpoint() == fields[1].is_endpoint()
        && fields[2].is_endpoint() == fields[3].is_endpoint()
}

/// Splits into two to four fields, keeping bracketed IPv6 addresses intact.
/// Empty credentials are meaningful, so fields are neither trimmed nor dropped.
fn split_fields(raw: &str) -> Result<(Vec<&str>, Vec<u8>)> {
    let b = raw.as_bytes();
    let mut fields = Vec::with_capacity(4);
    let mut separators = Vec::with_capacity(3);
    let mut start = 0;
    let mut bracket = false;
    for i in 0..b.len() {
        match b[i] {
            b'[' if i == start => bracket = true,
            b']' if bracket => {
                bracket = false;
                if i + 1 < b.len() && b[i + 1] != b':' && b[i + 1] != b'@' {
                    return Err(Error::invalid("characters after bracketed field"));
                }
            }
            b':' | b'@' if !bracket => {
                if separators.len() == 3 {
                    return Err(Error::invalid("expected two to four proxy fields"));
                }
                fields.push(&raw[start..i]);
                separators.push(b[i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if bracket {
        return Err(Error::invalid("unclosed bracketed field"));
    }
    fields.push(&raw[start..]);
    if fields.len() < 2 {
        return Err(Error::invalid("expected two to four proxy fields"));
    }
    Ok((fields, separators))
}

fn field_spec(values: &[&str], fields: &[Field], protocol: Protocol) -> Result<Spec> {
    let mut spec = Spec { protocol, ..Spec::default() };
    for (value, field) in values.iter().zip(fields) {
        let mut value = *value;
        match field {
            Field::Host => {
                if let Some(inner) = value.strip_prefix('[') {
                    value = inner.strip_suffix(']').ok_or_else(|| Error::invalid("bracketed host"))?;
                    if value.parse::<IpAddr>().is_err() || !value.contains(':') {
                        return Err(Error::invalid("brackets require an IPv6 address"));
                    }
                } else if value.contains(':') {
                    return Err(Error::invalid("IPv6 requires brackets"));
                }
                spec.host = value.to_string();
            }
            Field::Port => spec.port = parse_port(value)?,
            Field::User => spec.username = value.to_string(),
            Field::Pass => spec.password = value.to_string(),
        }
    }
    spec.validated()
}

fn parse_fields(raw: &str, protocol: Protocol, layout: &FieldLayout) -> Result<Spec> {
    let (values, separators) = split_fields(raw)?;
    if values.len() != layout.fields.len() || separators != layout.separators {
        return Err(Error::invalid("input does not match layout"));
    }
    field_spec(&values, &layout.fields, protocol)
}

fn parse_auto_fields(raw: &str, protocol: Protocol) -> Result<Spec> {
    if raw.contains(':') && raw.parse::<IpAddr>().is_ok() {
        return Err(Error::invalid("IPv6 requires brackets and a port"));
    }
    let (values, separators) = split_fields(raw)?;
    let mut candidates: Vec<Spec> = Vec::new();
    let add = |fields: &[Field], candidates: &mut Vec<Spec>| {
        if !valid_separators(fields, &separators) {
            return;
        }
        if let Ok(spec) = field_spec(&values, fields, protocol) {
            if !candidates.contains(&spec) {
                candidates.push(spec);
            }
        }
    };
    use Field::*;
    if values.len() == 4 {
        // user:pass@host:port is the URL authority order, so it wins over the
        // reversed host:port@user:pass reading when both happen to be valid.
        if separators[1] == b'@' {
            add(&[User, Pass, Host, Port], &mut candidates);
            if candidates.len() == 1 {
                return Ok(candidates.remove(0));
            }
        }
        add(&[Host, Port, User, Pass], &mut candidates);
        add(&[User, Pass, Host, Port], &mut candidates);
        if !candidates.is_empty() {
            return unique(candidates);
        }
    }
    // Enumerate endpoint positions without guessing from port numbers or
    // credential spelling. Remaining credentials follow input order (user,
    // then password); a different order requires an explicit layout.
    for host in 0..values.len() {
        for port in 0..values.len() {
            if host == port {
                continue;
            }
            let mut credential = User;
            let fields: Vec<Field> = (0..values.len())
                .map(|i| {
                    if i == host {
                        Host
                    } else if i == port {
                        Port
                    } else {
                        let f = credential;
                        credential = Pass;
                        f
                    }
                })
                .collect();
            add(&fields, &mut candidates);
        }
    }
    unique(candidates)
}

fn unique(mut candidates: Vec<Spec>) -> Result<Spec> {
    match candidates.len() {
        0 => Err(Error::invalid("proxy fields; specify a layout")),
        1 => Ok(candidates.remove(0)),
        _ => Err(Error::new(ErrorKind::Ambiguous)),
    }
}
