use std::{
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use serde::{Serialize, Serializer};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use url::{Position, Url};

use crate::{
    dial::{DialOptions, Dialer},
    error::{Error, ErrorKind, Result, Stage},
    io::BoxIo,
    spec::{join_host_port, parse_port, parse_target, validate_host, Spec},
    tls,
};

/// Target and depth of a reachability check. Exactly one of `target` and
/// `url` is required.
#[derive(Clone, Debug, Default)]
pub struct CheckOptions {
    /// `host:port`: TCP through the proxy, full handshake and CONNECT.
    pub target: String,
    /// `http(s)://...`: GET with target TLS for https; 2xx expected.
    pub url: String,
    /// Target TLS. With `target` it adds a TLS handshake to the target (use
    /// [`tls::default_client_config`] for public certificates); with `url` it
    /// replaces the default verification.
    pub tls: Option<Arc<ClientConfig>>,
    /// Bounds the whole check; `None` uses 10 seconds.
    pub timeout: Option<Duration>,
    /// Accepted HTTP statuses; empty means 200..=299. Redirects are not followed.
    pub status_codes: Vec<u16>,
}

impl CheckOptions {
    /// TCP check of `host:port`.
    pub fn target(target: impl Into<String>) -> CheckOptions {
        CheckOptions { target: target.into(), ..CheckOptions::default() }
    }

    /// HTTP check of an `http(s)` URL.
    pub fn url(url: impl Into<String>) -> CheckOptions {
        CheckOptions { url: url.into(), ..CheckOptions::default() }
    }

    pub fn with_tls(mut self, config: Arc<ClientConfig>) -> CheckOptions {
        self.tls = Some(config);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> CheckOptions {
        self.timeout = Some(timeout);
        self
    }
}

/// Tunnel setup and total durations, reported separately. Durations serialize
/// as nanoseconds and `started_at` as RFC 3339, like the Go package. `proxy`
/// contains credentials when serialized.
#[derive(Clone, Debug, Serialize)]
pub struct CheckResult {
    pub proxy: Spec,
    pub target: String,
    #[serde(serialize_with = "ser_time")]
    pub started_at: SystemTime,
    #[serde(serialize_with = "ser_nanos")]
    pub tunnel_latency: Duration,
    #[serde(serialize_with = "ser_nanos")]
    pub duration: Duration,
    /// HTTP status of URL checks; 0 when absent.
    #[serde(skip_serializing_if = "is_zero")]
    pub status_code: u16,
    pub ok: bool,
}

impl CheckResult {
    pub(crate) fn empty(proxy: Spec) -> CheckResult {
        CheckResult {
            proxy,
            target: String::new(),
            started_at: SystemTime::now(),
            tunnel_latency: Duration::ZERO,
            duration: Duration::ZERO,
            status_code: 0,
            ok: false,
        }
    }
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

pub(crate) fn ser_nanos<S: Serializer>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_nanos().min(u64::MAX as u128) as u64)
}

pub(crate) fn ser_time<S: Serializer>(t: &SystemTime, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(&humantime::format_rfc3339_nanos(*t))
}

/// Download measurement of [`speed_test`](crate::speed_test).
#[derive(Clone, Debug, Default, Serialize)]
pub struct SpeedResult {
    pub bytes: u64,
    #[serde(serialize_with = "ser_nanos")]
    pub duration: Duration,
    pub bytes_per_second: f64,
    pub megabits_per_second: f64,
    /// True when the body ended or `max_bytes` was reached; false when
    /// `max_duration` or `timeout` stopped the download early.
    pub complete: bool,
}

pub(crate) struct SpeedLimits {
    pub max_bytes: u64,
    pub max_duration: Duration,
}

/// Tests a resolved proxy with default connection settings. For a custom
/// route, proxy TLS or VPN bypass, build a [`Dialer`] and use its `check`.
pub async fn check(spec: &Spec, opts: CheckOptions) -> Result<CheckResult> {
    Dialer::new(spec.clone(), DialOptions::default())?.check(opts).await
}

impl Dialer {
    /// Checks reachability through the same route and settings as
    /// [`connect`](Self::connect). A failed target check is not proof that the
    /// proxy is dead; [`Error::stage`] tells proxy failures from target ones.
    pub async fn check(&self, opts: CheckOptions) -> Result<CheckResult> {
        let (result, outcome) = self.check_full(&opts).await;
        outcome.map(|_| result)
    }

    /// Check that always returns the populated result next to the outcome.
    pub(crate) async fn check_full(&self, opts: &CheckOptions) -> (CheckResult, Result<()>) {
        let mut result = CheckResult::empty(self.spec().clone());
        let mut speed = SpeedResult::default();
        let started = Instant::now();
        let outcome = self.run_check(opts, None, &mut result, &mut speed).await;
        if result.duration.is_zero() {
            result.duration = started.elapsed();
        }
        (result, outcome)
    }

    pub(crate) async fn run_check(
        &self,
        opts: &CheckOptions,
        speed: Option<SpeedLimits>,
        result: &mut CheckResult,
        speed_out: &mut SpeedResult,
    ) -> Result<()> {
        let started_check = Instant::now();
        result.started_at = SystemTime::now();
        let (target, url) = check_target(opts)?;
        result.target = target.clone();
        if opts.status_codes.iter().any(|c| !(100..=599).contains(c)) {
            return Err(Error::invalid("HTTP status code"));
        }
        let timeout = opts.timeout.filter(|t| !t.is_zero()).unwrap_or(Duration::from_secs(10));
        let deadline = started_check + timeout;
        let protocol = self.spec().protocol;

        let started = Instant::now();
        let tunnel = self.connect_until(&target, Some(deadline)).await;
        result.tunnel_latency = started.elapsed();
        let tunnel: BoxIo = Box::new(tunnel?);

        let stage = AtomicU8::new(Stage::TargetTls as u8);
        let work = async {
            let Some(url) = url else {
                if let Some(config) = &opts.tls {
                    let (host, _) = parse_target(&target)?;
                    TlsConnector::from(config.clone())
                        .connect(tls::server_name(&host)?, tunnel)
                        .await
                        .map_err(|e| Error::io_at(Stage::TargetTls, protocol, e))?;
                }
                result.ok = true;
                return Ok(());
            };
            let host = url_host(&url);
            let io: BoxIo = if url.scheme() == "https" {
                let base = opts.tls.clone().unwrap_or_else(tls::default_client_config);
                let config = tls::with_alpn(&base, &[b"http/1.1"]);
                let stream = TlsConnector::from(config)
                    .connect(tls::server_name(host)?, tunnel)
                    .await
                    .map_err(|e| Error::io_at(Stage::TargetTls, protocol, e))?;
                Box::new(stream)
            } else {
                tunnel
            };
            stage.store(Stage::Http as u8, Ordering::Relaxed);
            let http_err = |e: hyper::Error| Error::new_op(Stage::Http, protocol, 0, ErrorKind::Http, Some(Box::new(e)));
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(64 << 10)
                .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
                .await
                .map_err(http_err)?;
            let driver = AbortOnDrop(tokio::spawn(async move {
                let _ = conn.await;
            }));
            let mut host_header = host.to_string();
            if host.contains(':') {
                host_header = format!("[{host}]");
            }
            if let Some(port) = url.port() {
                host_header = format!("{host_header}:{port}");
            }
            let mut req = http::Request::get(&url[Position::BeforePath..Position::AfterQuery])
                .header(http::header::HOST, host_header)
                .header(http::header::USER_AGENT, concat!("proxykit-rs/", env!("CARGO_PKG_VERSION")));
            if speed.is_some() {
                // Measure wire bytes: no transparent compression.
                req = req.header(http::header::ACCEPT_ENCODING, "identity");
            }
            let req = req.body(Empty::new()).map_err(|_| Error::invalid("check request"))?;
            let resp = sender.send_request(req).await.map_err(http_err)?;
            let status = resp.status().as_u16();
            result.status_code = status;
            let ok = if opts.status_codes.is_empty() {
                (200..300).contains(&status)
            } else {
                opts.status_codes.contains(&status)
            };
            if !ok {
                return Err(Error::new_op(Stage::Http, protocol, status, ErrorKind::Status, None));
            }
            // Headers are a successful health check; the body is read only
            // for a speed measurement.
            result.ok = true;
            result.duration = started_check.elapsed();
            if let Some(limits) = speed {
                *speed_out = download(resp.into_body(), &limits, deadline, protocol).await?;
            }
            drop(driver);
            Ok(())
        };
        match tokio::time::timeout_at(deadline, work).await {
            Ok(r) => r,
            Err(_) => Err(Error::new_op(Stage::from_u8(stage.load(Ordering::Relaxed)), protocol, 0, ErrorKind::Timeout, None)),
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn url_host(url: &Url) -> &str {
    let host = url.host_str().unwrap_or_default();
    host.trim_start_matches('[').trim_end_matches(']')
}

fn check_target(opts: &CheckOptions) -> Result<(String, Option<Url>)> {
    if opts.target.is_empty() == opts.url.is_empty() {
        return Err(Error::invalid("provide exactly one of target and url"));
    }
    if !opts.target.is_empty() {
        parse_target(&opts.target)?;
        return Ok((opts.target.clone(), None));
    }
    let url = Url::parse(&opts.url).map_err(|_| Error::invalid("check URL syntax"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid("check URL requires http(s), no credentials or fragment"));
    }
    let host = url_host(&url);
    validate_host(host)?;
    let port = url.port_or_known_default().unwrap_or(80);
    parse_port(&port.to_string())?;
    Ok((join_host_port(host, port), Some(url)))
}

/// Reads the body until EOF, `max_bytes` or the earlier of `max_duration`
/// and the overall deadline. A timeout after some bytes is a partial result.
async fn download(
    mut body: Incoming,
    limits: &SpeedLimits,
    deadline: Instant,
    protocol: crate::Protocol,
) -> Result<SpeedResult> {
    let started = Instant::now();
    let read_deadline = deadline.min(started + limits.max_duration);
    let mut n = 0u64;
    let outcome = tokio::time::timeout_at(read_deadline, read_body(&mut body, limits.max_bytes, &mut n)).await;
    let elapsed = started.elapsed();
    let mut result = SpeedResult { bytes: n, duration: elapsed, ..SpeedResult::default() };
    if !elapsed.is_zero() {
        result.bytes_per_second = n as f64 / elapsed.as_secs_f64();
        result.megabits_per_second = result.bytes_per_second * 8.0 / 1e6;
    }
    match outcome {
        Ok(Ok(())) => {
            result.complete = true;
            Ok(result)
        }
        Ok(Err(e)) => Err(Error::new_op(Stage::Http, protocol, 0, ErrorKind::Http, Some(Box::new(e)))),
        Err(_) if n > 0 => Ok(result),
        Err(_) => Err(Error::new_op(Stage::Http, protocol, 0, ErrorKind::Timeout, None)),
    }
}

async fn read_body(body: &mut Incoming, max: u64, n: &mut u64) -> std::result::Result<(), hyper::Error> {
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            *n += data.len() as u64;
            if *n >= max {
                *n = max;
                return Ok(());
            }
        }
    }
    Ok(())
}
