use std::{error::Error as StdError, fmt, io, sync::Arc};

use serde::{Serialize, Serializer};

use crate::{detect::Attempt, spec::Protocol};

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Boxed error accepted from user callbacks (geolocation, custom dialers).
pub type BoxError = Box<dyn StdError + Send + Sync>;

/// Category of a failure. It mirrors the sentinel errors of the Go package
/// (`ErrInvalid`, `ErrAuth`, ...) plus transport-level categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid proxy configuration, input or option.
    Invalid,
    /// Several readings of a compact string are possible; specify a layout.
    Ambiguous,
    /// Unsupported or unexpected proxy protocol.
    Protocol,
    /// The protocol is still `Auto` where a concrete one is required.
    Unresolved,
    /// The proxy rejected the credentials.
    Auth,
    /// The proxy rejected the target.
    Rejected,
    /// The target answered with a status outside the accepted list.
    Status,
    /// VPN bypass found no usable physical interface.
    NoInterface,
    /// Interface binding is unavailable on this platform.
    BypassUnsupported,
    /// A deadline expired.
    Timeout,
    /// The operation lost a race (protocol discovery) or was stopped.
    Canceled,
    /// Socket-level failure.
    Io,
    /// TLS handshake or certificate failure.
    Tls,
    /// HTTP framing or transport failure.
    Http,
    /// No candidate protocol established a tunnel; see [`Error::attempts`].
    Detection,
}

impl ErrorKind {
    fn message(self) -> &'static str {
        match self {
            ErrorKind::Invalid => "invalid proxy configuration",
            ErrorKind::Ambiguous => "ambiguous proxy format; specify a layout or use a URL",
            ErrorKind::Protocol => "unsupported or unexpected proxy protocol",
            ErrorKind::Unresolved => "proxy protocol must be resolved before dialing",
            ErrorKind::Auth => "proxy authentication failed",
            ErrorKind::Rejected => "proxy rejected the target",
            ErrorKind::Status => "unexpected target HTTP status",
            ErrorKind::NoInterface => "no active physical network interface",
            ErrorKind::BypassUnsupported => "VPN bypass is not supported on this platform",
            ErrorKind::Timeout => "deadline exceeded",
            ErrorKind::Canceled => "operation canceled",
            ErrorKind::Io => "network error",
            ErrorKind::Tls => "TLS error",
            ErrorKind::Http => "HTTP error",
            ErrorKind::Detection => "no candidate established a proxy tunnel",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Phase of a proxied operation that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Dial,
    ProxyTls,
    Negotiation,
    Auth,
    Connect,
    TargetTls,
    Http,
    Geo,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Dial => "dial",
            Stage::ProxyTls => "proxy_tls",
            Stage::Negotiation => "negotiation",
            Stage::Auth => "auth",
            Stage::Connect => "connect",
            Stage::TargetTls => "target_tls",
            Stage::Http => "http",
            Stage::Geo => "geo",
        }
    }

    pub(crate) fn from_u8(v: u8) -> Stage {
        match v {
            0 => Stage::Dial,
            1 => Stage::ProxyTls,
            2 => Stage::Negotiation,
            3 => Stage::Auth,
            4 => Stage::Connect,
            5 => Stage::TargetTls,
            6 => Stage::Http,
            _ => Stage::Geo,
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Stage {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// The failing phase of a proxied operation (Go `OpError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op {
    pub stage: Stage,
    pub protocol: Protocol,
    /// HTTP status or SOCKS5 reply code, depending on `protocol`; 0 when absent.
    pub status_code: u16,
}

/// The crate error. `Display` never contains credentials, URLs or remote text;
/// the underlying cause is available through [`std::error::Error::source`]
/// and `Debug`, which may include details from custom dialers.
#[derive(Clone)]
pub struct Error {
    inner: Arc<Inner>,
}

struct Inner {
    kind: ErrorKind,
    detail: Option<&'static str>,
    op: Option<Op>,
    source: Option<Arc<dyn StdError + Send + Sync>>,
    attempts: Vec<Attempt>,
}

impl Error {
    pub(crate) fn build(
        kind: ErrorKind,
        detail: Option<&'static str>,
        op: Option<Op>,
        source: Option<Arc<dyn StdError + Send + Sync>>,
        attempts: Vec<Attempt>,
    ) -> Error {
        Error { inner: Arc::new(Inner { kind, detail, op, source, attempts }) }
    }

    pub fn new(kind: ErrorKind) -> Error {
        Error::build(kind, None, None, None, Vec::new())
    }

    /// Wraps an arbitrary cause with a category.
    pub fn with_source(kind: ErrorKind, source: impl Into<BoxError>) -> Error {
        Error::build(kind, None, None, Some(Arc::from(source.into())), Vec::new())
    }

    pub(crate) fn invalid(detail: &'static str) -> Error {
        Error::build(ErrorKind::Invalid, Some(detail), None, None, Vec::new())
    }

    pub(crate) fn new_op(
        stage: Stage,
        protocol: Protocol,
        status_code: u16,
        kind: ErrorKind,
        source: Option<BoxError>,
    ) -> Error {
        Error::build(
            kind,
            None,
            Some(Op { stage, protocol, status_code }),
            source.map(Arc::from),
            Vec::new(),
        )
    }

    /// Converts an error into a stage-tagged one, keeping kind, detail and cause.
    pub(crate) fn at(self, stage: Stage, protocol: Protocol, status_code: u16) -> Error {
        if self.inner.op.is_some() {
            return self;
        }
        Error::build(
            self.inner.kind,
            self.inner.detail,
            Some(Op { stage, protocol, status_code }),
            self.inner.source.clone(),
            self.inner.attempts.clone(),
        )
    }

    pub(crate) fn io_at(stage: Stage, protocol: Protocol, e: io::Error) -> Error {
        Error::from(e).at(stage, protocol, 0)
    }

    pub(crate) fn detection(attempts: Vec<Attempt>) -> Error {
        Error::build(ErrorKind::Detection, None, None, None, attempts)
    }

    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    /// Fixed explanatory text for `Invalid` errors, e.g. "port must be in 1..65535".
    pub fn detail(&self) -> Option<&'static str> {
        self.inner.detail
    }

    pub fn op(&self) -> Option<&Op> {
        self.inner.op.as_ref()
    }

    pub fn stage(&self) -> Option<Stage> {
        self.inner.op.map(|o| o.stage)
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.inner.op.map(|o| o.protocol)
    }

    pub fn status_code(&self) -> Option<u16> {
        self.inner.op.map(|o| o.status_code).filter(|c| *c != 0)
    }

    /// Every candidate's observation for `Detection` errors; empty otherwise.
    pub fn attempts(&self) -> &[Attempt] {
        &self.inner.attempts
    }

    /// Like Go `errors.Is`: matches this error's kind or, for detection
    /// failures, the kind of any attempt.
    pub fn is(&self, kind: ErrorKind) -> bool {
        self.inner.kind == kind
            || self.inner.attempts.iter().any(|a| a.error.as_ref().is_some_and(|e| e.is(kind)))
    }

    /// Recognizes deadlines anywhere in the error, like Go `IsTimeout`.
    pub fn is_timeout(&self) -> bool {
        self.is(ErrorKind::Timeout)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i = &self.inner;
        if let Some(op) = i.op {
            if op.status_code != 0 {
                write!(f, "proxykit: {} ({}, status {})", op.stage, op.protocol, op.status_code)?;
            } else {
                write!(f, "proxykit: {} ({}) failed", op.stage, op.protocol)?;
            }
            write!(f, ": {}", i.kind)?;
        } else if i.kind == ErrorKind::Detection {
            f.write_str("proxykit: no candidate established a proxy tunnel")?;
        } else {
            write!(f, "{}", i.kind)?;
        }
        if let Some(detail) = i.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i = &self.inner;
        let mut d = f.debug_struct("Error");
        d.field("kind", &i.kind);
        if let Some(detail) = i.detail {
            d.field("detail", &detail);
        }
        if let Some(op) = &i.op {
            d.field("op", op);
        }
        if let Some(source) = &i.source {
            d.field("source", source);
        }
        if !i.attempts.is_empty() {
            d.field("attempts", &i.attempts);
        }
        d.finish()
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner.source.as_deref().map(|s| s as &(dyn StdError + 'static))
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        let kind = if e.kind() == io::ErrorKind::TimedOut {
            ErrorKind::Timeout
        } else if e.get_ref().is_some_and(|inner| inner.is::<rustls::Error>()) {
            ErrorKind::Tls
        } else if e.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            // A crate error tunneled through io::Error by a custom transport.
            let inner = e.into_inner().expect("checked above");
            return *inner.downcast::<Error>().expect("checked above");
        } else {
            ErrorKind::Io
        };
        Error::with_source(kind, e)
    }
}
