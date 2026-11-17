use std::{sync::Arc, time::Duration};

use rustls::ClientConfig;
use serde::Serialize;
use tokio::time::Instant;

use crate::{
    check::{CheckOptions, CheckResult, SpeedLimits, SpeedResult},
    dial::{DialOptions, Dialer},
    error::{Error, Result},
    spec::Spec,
};

/// Combined reachability and download-speed test of one HTTP endpoint.
#[derive(Clone, Debug, Default)]
pub struct SpeedTestOptions {
    /// The `http(s)` endpoint to download; required. Redirects are not followed.
    pub url: String,
    /// TLS to the target.
    pub tls: Option<Arc<ClientConfig>>,
    /// Bounds the whole test including the download; `None` uses 15 seconds.
    pub timeout: Option<Duration>,
    /// Accepted statuses; empty means 200..=299.
    pub status_codes: Vec<u16>,
    /// Caps the downloaded body; `None` uses 10 MiB.
    pub max_bytes: Option<u64>,
    /// Caps the download separately from `timeout`; `None` uses 10 seconds.
    /// A partial measurement is still reported when time runs out.
    pub max_duration: Option<Duration>,
}

impl SpeedTestOptions {
    pub fn url(url: impl Into<String>) -> SpeedTestOptions {
        SpeedTestOptions { url: url.into(), ..SpeedTestOptions::default() }
    }
}

/// Health check plus measured download speed. `health.proxy` contains
/// credentials when serialized.
#[derive(Clone, Debug, Serialize)]
pub struct SpeedTestResult {
    pub health: CheckResult,
    pub speed: SpeedResult,
}

/// Checks one proxy and measures throughput from `opts.url` through it, with
/// default connection settings. For a custom route, proxy TLS or VPN bypass,
/// build a [`Dialer`] and call its `speed_test`.
pub async fn speed_test(spec: &Spec, opts: SpeedTestOptions) -> Result<SpeedTestResult> {
    Dialer::new(spec.clone(), DialOptions::default())?.speed_test(opts).await
}

impl Dialer {
    /// One tunnel: the status response is the health check, then the body is
    /// read on the same tunnel for the speed. Compression is disabled, so the
    /// bytes counted are the bytes that crossed the proxy.
    pub async fn speed_test(&self, opts: SpeedTestOptions) -> Result<SpeedTestResult> {
        if opts.url.is_empty() {
            return Err(Error::invalid("speed test requires URL"));
        }
        let limits = SpeedLimits {
            max_bytes: opts.max_bytes.filter(|n| *n > 0).unwrap_or(10 << 20),
            max_duration: opts.max_duration.filter(|d| !d.is_zero()).unwrap_or(Duration::from_secs(10)),
        };
        let check = CheckOptions {
            url: opts.url,
            tls: opts.tls,
            timeout: Some(opts.timeout.filter(|d| !d.is_zero()).unwrap_or(Duration::from_secs(15))),
            status_codes: opts.status_codes,
            ..CheckOptions::default()
        };
        let mut health = CheckResult::empty(self.spec().clone());
        let mut speed = SpeedResult::default();
        let started = Instant::now();
        let outcome = self.run_check(&check, Some(limits), &mut health, &mut speed).await;
        if health.duration.is_zero() {
            health.duration = started.elapsed();
        }
        outcome.map(|_| SpeedTestResult { health, speed })
    }
}
