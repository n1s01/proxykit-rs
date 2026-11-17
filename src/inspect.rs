use std::{
    fmt,
    future::Future,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use futures_util::future::BoxFuture;
use http_body_util::{BodyExt, Limited};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    check::{ser_nanos, ser_time, CheckOptions},
    detect::{detect, DetectOptions},
    dial::{DialOptions, Dialer},
    error::{BoxError, Error, ErrorKind, Result, Stage},
    http::HttpClient,
    spec::{Protocol, Spec},
};

/// Exit address of a proxy as seen by a geolocation service.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Geo {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// Upper-case ISO 3166-1 alpha-2 code.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country: String,
}

/// Looks up the exit address. Every request made with the client travels
/// through the inspected proxy, so the service sees what the target would.
#[derive(Clone)]
pub struct GeoLookup(Arc<dyn Fn(HttpClient) -> BoxFuture<'static, Result<Geo, BoxError>> + Send + Sync>);

impl GeoLookup {
    pub fn new<F, Fut>(f: F) -> GeoLookup
    where
        F: Fn(HttpClient) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Geo, BoxError>> + Send + 'static,
    {
        GeoLookup(Arc::new(move |client| Box::pin(f(client))))
    }

    /// The default: <https://ipwho.is/>, the only third-party request the
    /// crate makes on its own.
    pub fn ip_who_is() -> GeoLookup {
        GeoLookup::new(ip_who_is)
    }
}

impl fmt::Debug for GeoLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GeoLookup(..)")
    }
}

/// What [`inspect`] measures and where.
#[derive(Clone, Debug, Default)]
pub struct InspectOptions {
    /// `host:port` used for discovery and latency: the host the application
    /// will actually reach through the proxy.
    pub target: String,
    /// Bounds discovery and the latency measurement; `None` uses 10 seconds.
    pub timeout: Option<Duration>,
    /// Discovery candidates for `Auto`; empty tries SOCKS5, HTTP, HTTPS.
    pub candidates: Vec<Protocol>,
    /// Connections to the proxy. `Dialer::inspect` ignores it and `candidates`.
    pub dial: DialOptions,
    /// `None` uses [`GeoLookup::ip_who_is`].
    pub geo: Option<GeoLookup>,
    /// Disables the geolocation request entirely.
    pub skip_geo: bool,
    /// Bounds the lookup separately; `None` uses 5 seconds.
    pub geo_timeout: Option<Duration>,
}

/// Everything [`inspect`] learned about one proxy. `proxy` contains
/// credentials when serialized; durations serialize as nanoseconds.
#[derive(Clone, Debug, Serialize)]
pub struct Info {
    /// Concrete protocol once discovery succeeded.
    pub proxy: Spec,
    pub target: String,
    #[serde(serialize_with = "ser_time")]
    pub started_at: SystemTime,
    /// One tunnel to the target: TCP to the proxy, proxy TLS, authentication
    /// and CONNECT. Other discovery attempts and the lookup are excluded.
    #[serde(serialize_with = "ser_nanos")]
    pub latency: Duration,
    #[serde(flatten)]
    pub geo: Geo,
    /// A failed lookup; the proxy is still usable, so it does not fail `inspect`.
    #[serde(skip)]
    pub geo_error: Option<Error>,
    /// The whole inspection, including the lookup.
    #[serde(serialize_with = "ser_nanos")]
    pub duration: Duration,
}

/// Resolves the protocol when it is `Auto`, measures tunnel latency to
/// `opts.target` and looks up the exit country. An error means no tunnel to
/// the target could be opened.
pub async fn inspect(spec: &Spec, opts: InspectOptions) -> Result<Info> {
    if spec.protocol != Protocol::Auto {
        return Dialer::new(spec.clone(), opts.dial.clone())?.inspect(opts).await;
    }
    let started = Instant::now();
    let mut info = Info::new(spec.clone(), &opts.target);
    let found = detect(
        spec,
        DetectOptions {
            target: opts.target.clone(),
            candidates: opts.candidates.clone(),
            timeout: opts.timeout,
            dial: opts.dial.clone(),
        },
    )
    .await?;
    let dialer = Dialer::new(found.proxy.clone(), opts.dial.clone())?;
    info.proxy = found.proxy.clone();
    // The winning attempt already is one clean tunnel to the target.
    if let Some(a) = found.attempts.iter().find(|a| a.protocol == found.proxy.protocol) {
        info.latency = a.duration;
    }
    dialer.geo(&mut info, &opts).await?;
    info.duration = started.elapsed();
    Ok(info)
}

impl Info {
    fn new(proxy: Spec, target: &str) -> Info {
        Info {
            proxy,
            target: target.to_string(),
            started_at: SystemTime::now(),
            latency: Duration::ZERO,
            geo: Geo::default(),
            geo_error: None,
            duration: Duration::ZERO,
        }
    }
}

impl Dialer {
    /// Latency and exit country through this configured dialer.
    pub async fn inspect(&self, opts: InspectOptions) -> Result<Info> {
        let started = Instant::now();
        let mut info = Info::new(self.spec().clone(), &opts.target);
        let check = CheckOptions { target: opts.target.clone(), timeout: opts.timeout, ..CheckOptions::default() };
        let result = self.check(check).await?;
        info.latency = result.tunnel_latency;
        self.geo(&mut info, &opts).await?;
        info.duration = started.elapsed();
        Ok(info)
    }

    async fn geo(&self, info: &mut Info, opts: &InspectOptions) -> Result<()> {
        if opts.skip_geo {
            return Ok(());
        }
        let timeout = opts.geo_timeout.filter(|t| !t.is_zero()).unwrap_or(Duration::from_secs(5));
        let lookup = opts.geo.clone().unwrap_or_else(GeoLookup::ip_who_is);
        let outcome = tokio::time::timeout(timeout, (lookup.0)(self.http_client())).await;
        let protocol = self.spec().protocol;
        match outcome {
            Ok(Ok(mut geo)) => {
                geo.country = geo.country.to_ascii_uppercase();
                info.geo = geo;
            }
            Ok(Err(e)) => info.geo_error = Some(Error::new_op(Stage::Geo, protocol, 0, ErrorKind::Http, Some(e))),
            Err(_) => info.geo_error = Some(Error::new_op(Stage::Geo, protocol, 0, ErrorKind::Timeout, None)),
        }
        Ok(())
    }
}

/// Default lookup: asks <https://ipwho.is/> through the proxy.
pub async fn ip_who_is(client: HttpClient) -> Result<Geo, BoxError> {
    let resp = client.get(http::Uri::from_static("https://ipwho.is/")).await?;
    if resp.status() != http::StatusCode::OK {
        return Err(Box::new(Error::new_op(Stage::Geo, Protocol::Auto, resp.status().as_u16(), ErrorKind::Status, None)));
    }
    let body = Limited::new(resp.into_body(), 64 << 10).collect().await?.to_bytes();
    #[derive(Deserialize)]
    struct Answer {
        #[serde(default)]
        success: bool,
        #[serde(default)]
        ip: String,
        #[serde(default)]
        country_code: String,
    }
    let a: Answer = serde_json::from_slice(&body)?;
    if !a.success || a.country_code.len() != 2 || a.ip.parse::<IpAddr>().is_err() {
        return Err(Box::new(Error::invalid("geolocation response")));
    }
    Ok(Geo { ip: a.ip, country: a.country_code.to_ascii_uppercase() })
}
