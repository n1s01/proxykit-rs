use std::{fmt, time::Duration};

use futures_util::{stream::FuturesUnordered, StreamExt};
use tokio::time::Instant;

use crate::{
    dial::{DialOptions, Dialer, DEFAULT_TIMEOUT},
    error::{Error, ErrorKind, Result},
    parse::{parse_with, ParseOptions},
    spec::{parse_target, Protocol, Spec},
};

/// Bounded protocol discovery against an explicit target.
#[derive(Clone, Debug, Default)]
pub struct DetectOptions {
    /// Must reflect the intended use, e.g. a Telegram DC `ip:port`.
    pub target: String,
    /// Empty tries SOCKS5, HTTP and HTTPS concurrently. On a proxy that serves
    /// several protocols the first successful tunnel wins; pin the protocol
    /// explicitly if preference matters. At most three sockets are opened.
    pub candidates: Vec<Protocol>,
    /// `None` uses 10 seconds.
    pub timeout: Option<Duration>,
    /// Connections to the proxy during discovery.
    pub dial: DialOptions,
}

/// The completed observation for one candidate protocol.
#[derive(Clone)]
pub struct Attempt {
    pub protocol: Protocol,
    pub duration: Duration,
    /// `None` when this candidate opened the tunnel.
    pub error: Option<Error>,
}

impl fmt::Debug for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attempt")
            .field("protocol", &self.protocol)
            .field("duration", &self.duration)
            .field("error", &self.error.as_ref().map(|e| e.to_string()))
            .finish()
    }
}

/// The resolved endpoint and every attempt in candidate order.
#[derive(Clone, Debug)]
pub struct Detection {
    pub proxy: Spec,
    pub attempts: Vec<Attempt>,
}

/// Requires `Auto`; authenticates and opens a tunnel to `opts.target` for
/// each candidate. A SOCKS greeting or an HTTP status line alone is never
/// success. Losing attempts are dropped before return. On failure the error
/// has kind `Detection` and carries all attempts ([`Error::attempts`]).
pub async fn detect(spec: &Spec, opts: DetectOptions) -> Result<Detection> {
    spec.validate()?;
    if spec.protocol != Protocol::Auto {
        return Err(Error::invalid("detect requires Auto; explicit protocols are never overridden"));
    }
    parse_target(&opts.target)?;
    let candidates = if opts.candidates.is_empty() {
        vec![Protocol::Socks5, Protocol::Http, Protocol::Https]
    } else {
        opts.candidates.clone()
    };
    if candidates.len() > 3 {
        return Err(Error::invalid("too many detection candidates"));
    }
    for (i, p) in candidates.iter().enumerate() {
        if *p == Protocol::Auto || candidates[..i].contains(p) {
            return Err(Error::invalid("invalid or duplicate detection candidate"));
        }
    }
    let timeout = opts.timeout.filter(|t| !t.is_zero()).unwrap_or(DEFAULT_TIMEOUT);
    let deadline = Instant::now() + timeout;
    let started = Instant::now();

    let mut attempts: Vec<Option<Attempt>> = vec![None; candidates.len()];
    let mut running = FuturesUnordered::new();
    for (i, protocol) in candidates.iter().copied().enumerate() {
        let candidate = Spec { protocol, ..spec.clone() };
        let dial = opts.dial.clone();
        let target = opts.target.clone();
        running.push(async move {
            let begun = Instant::now();
            let outcome = match Dialer::new(candidate.clone(), dial) {
                Ok(d) => d.connect_until(&target, Some(deadline)).await.map(drop),
                Err(e) => Err(e),
            };
            (i, candidate, Attempt { protocol, duration: begun.elapsed(), error: outcome.err() })
        });
    }
    let mut winner = None;
    while let Some((i, candidate, attempt)) = running.next().await {
        let won = attempt.error.is_none();
        attempts[i] = Some(attempt);
        if won {
            winner = Some(candidate);
            break;
        }
    }
    drop(running);
    let attempts: Vec<Attempt> = attempts
        .into_iter()
        .zip(&candidates)
        .map(|(a, p)| {
            a.unwrap_or_else(|| Attempt {
                protocol: *p,
                duration: started.elapsed(),
                error: Some(Error::new(ErrorKind::Canceled)),
            })
        })
        .collect();
    match winner {
        Some(proxy) => Ok(Detection { proxy, attempts }),
        None => Err(Error::detection(attempts)),
    }
}

/// Parses input and discovers only a missing protocol. An explicit protocol
/// is returned without opening a connection; this is not a health check.
pub async fn resolve(input: &str, parse: &ParseOptions, detect_opts: DetectOptions) -> Result<Spec> {
    let spec = parse_with(input, parse)?;
    if spec.protocol != Protocol::Auto {
        return Ok(spec);
    }
    Ok(detect(&spec, detect_opts).await?.proxy)
}
