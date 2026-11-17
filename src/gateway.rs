//! Rotating (backconnect) proxy parameters encoded in credentials, e.g.
//! `acct1-country-RU-session-ab12cd34ef-time-1440`. No network, no state.
//!
//! ```
//! use std::time::Duration;
//! use proxykit::gateway::{self, Params, NOVA};
//!
//! let spec = proxykit::parse("http://acct1-country-RU-session-ab12cd34ef-time-1440:secret@gw.example:6969")?;
//! let (base, params) = NOVA.split(&spec)?;
//! assert_eq!(base.username, "acct1");
//! assert_eq!(params.ttl, Duration::from_secs(24 * 3600));
//!
//! let sticky = NOVA.apply(&base, &Params {
//!     country: "DE".into(),
//!     session: gateway::new_session(),
//!     ttl: Duration::from_secs(30 * 60),
//! })?;
//! # Ok::<(), proxykit::Error>(())
//! ```

use std::{borrow::Cow, time::Duration};

use crate::{
    dial::Dialer,
    error::{Error, Result},
    new::{dialer_for, Options},
    parse::parse_with,
    spec::Spec,
};

/// How one provider encodes parameters into credentials: a tag followed by
/// its value. An empty tag means the provider has no such parameter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Format {
    /// Joins the base, tags and values. Empty uses `-`.
    pub separator: Cow<'static, str>,
    pub country: Cow<'static, str>,
    pub session: Cow<'static, str>,
    pub ttl: Cow<'static, str>,
    /// Unit of the number after the TTL tag. Zero uses one minute.
    pub ttl_unit: Duration,
    /// Tags live in the password instead of the username.
    pub in_password: bool,
}

/// NovaProxy: `country`, `session`, `time` in minutes.
pub const NOVA: Format = Format {
    separator: Cow::Borrowed(""),
    country: Cow::Borrowed("country"),
    session: Cow::Borrowed("session"),
    ttl: Cow::Borrowed("time"),
    ttl_unit: Duration::ZERO,
    in_password: false,
};

/// Provider parameters of one endpoint. Values are literal: country case is
/// whatever the provider expects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params {
    pub country: String,
    /// Pins the exit address. Empty means a new address per connection.
    pub session: String,
    /// Sticky session lifetime; zero leaves it to the provider.
    pub ttl: Duration,
}

impl Params {
    /// Whether the exit address is pinned to a session.
    pub fn sticky(&self) -> bool {
        !self.session.is_empty()
    }
}

impl Format {
    /// The endpoint without the tags of this format, and their values. The
    /// first token is always the base; unknown tokens stay in place.
    pub fn split(&self, spec: &Spec) -> Result<(Spec, Params)> {
        let (sep, unit) = self.settings()?;
        let (rest, params) = self.scan(self.field(spec), sep, unit)?;
        Ok((self.with_field(spec, rest.join(sep)), params))
    }

    /// The endpoint carrying exactly `p`: tags already present are replaced or
    /// removed, so an empty `session` turns a sticky endpoint into a rotating
    /// one. Unknown tokens are kept.
    pub fn apply(&self, spec: &Spec, p: &Params) -> Result<Spec> {
        let (sep, unit) = self.settings()?;
        let (mut rest, _) = self.scan(self.field(spec), sep, unit)?;
        if rest[0].is_empty() {
            return Err(Error::invalid("tagged credential is empty"));
        }
        if !p.ttl.is_zero() && p.session.is_empty() {
            return Err(Error::invalid("session TTL requires a session"));
        }
        if p.ttl.as_nanos() % unit.as_nanos() != 0 {
            return Err(Error::invalid("session TTL is not a multiple of the format unit"));
        }
        let ttl = if p.ttl.is_zero() { String::new() } else { (p.ttl.as_nanos() / unit.as_nanos()).to_string() };
        for (tag, value) in [(&self.country, &p.country), (&self.session, &p.session), (&self.ttl, &ttl)] {
            if value.is_empty() {
                continue;
            }
            if tag.is_empty() {
                return Err(Error::invalid("format has no tag for a requested parameter"));
            }
            if value.contains(sep) || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error::invalid("parameter value contains a separator or space"));
            }
            rest.push(tag.to_string());
            rest.push(value.clone());
        }
        let out = self.with_field(spec, rest.join(sep));
        out.validate()?;
        Ok(out)
    }

    /// Parses a plain provider line such as `host:port:user:pass`, applies `p`
    /// and returns a ready dialer; `dialer.spec()` is the finished endpoint.
    /// A TTL without a session gets a fresh [`new_session`]. Like
    /// [`proxykit::new`](crate::new), input without a protocol is resolved by
    /// discovery against `opts.target`.
    pub async fn dialer(&self, input: &str, mut p: Params, opts: Options) -> Result<Dialer> {
        let spec = parse_with(input, &opts.parse)?;
        if !p.ttl.is_zero() && p.session.is_empty() {
            p.session = new_session();
        }
        let spec = self.apply(&spec, &p)?;
        dialer_for(spec, opts).await
    }

    fn settings(&self) -> Result<(&str, Duration)> {
        let sep: &str = if self.separator.is_empty() { "-" } else { &self.separator };
        let unit = if self.ttl_unit.is_zero() { Duration::from_secs(60) } else { self.ttl_unit };
        let tags = [&self.country, &self.session, &self.ttl];
        let mut named = false;
        for (i, tag) in tags.iter().enumerate() {
            if tag.is_empty() {
                continue;
            }
            named = true;
            if tag.contains(sep) {
                return Err(Error::invalid("format tag contains the separator"));
            }
            if tags[..i].contains(tag) {
                return Err(Error::invalid("duplicate format tag"));
            }
        }
        if !named {
            return Err(Error::invalid("format names no tags"));
        }
        Ok((sep, unit))
    }

    fn field<'a>(&self, spec: &'a Spec) -> &'a str {
        if self.in_password {
            &spec.password
        } else {
            &spec.username
        }
    }

    fn with_field(&self, spec: &Spec, value: String) -> Spec {
        let mut out = spec.clone();
        if self.in_password {
            out.password = value;
        } else {
            out.username = value;
        }
        out
    }

    /// Separates the tags of this format from every other token, preserving order.
    fn scan(&self, field: &str, sep: &str, unit: Duration) -> Result<(Vec<String>, Params)> {
        let tokens: Vec<&str> = field.split(sep).collect();
        let mut rest = vec![tokens[0].to_string()];
        let mut p = Params::default();
        let mut seen = [false; 3];
        let mut i = 1;
        while i < tokens.len() {
            let token = tokens[i];
            let kind = if token.is_empty() {
                None
            } else if token == self.country {
                Some(0)
            } else if token == self.session {
                Some(1)
            } else if token == self.ttl {
                Some(2)
            } else {
                None
            };
            let Some(kind) = kind else {
                rest.push(token.to_string());
                i += 1;
                continue;
            };
            if seen[kind] {
                return Err(Error::invalid("repeated credential tag"));
            }
            seen[kind] = true;
            i += 1;
            let value = match tokens.get(i) {
                Some(v) if !v.is_empty() => *v,
                _ => return Err(Error::invalid("credential tag without a value")),
            };
            match kind {
                0 => p.country = value.to_string(),
                1 => p.session = value.to_string(),
                _ => p.ttl = parse_ttl(value, unit)?,
            }
            i += 1;
        }
        Ok((rest, p))
    }
}

fn parse_ttl(raw: &str, unit: Duration) -> Result<Duration> {
    if raw.is_empty() || !raw.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::invalid("session TTL"));
    }
    let n: u128 = raw.parse().map_err(|_| Error::invalid("session TTL"))?;
    let nanos = n.checked_mul(unit.as_nanos()).filter(|v| n >= 1 && *v <= i64::MAX as u128);
    match nanos {
        Some(v) => Ok(Duration::from_nanos(v as u64)),
        None => Err(Error::invalid("session TTL")),
    }
}

const SESSION_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// A random ten-character session identifier. Panics only if the system
/// random source fails.
pub fn new_session() -> String {
    let mut b = [0u8; 10];
    getrandom::getrandom(&mut b).expect("gateway: system random source");
    b.iter().map(|v| SESSION_ALPHABET[*v as usize % SESSION_ALPHABET.len()] as char).collect()
}
