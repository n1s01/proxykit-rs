//! Proxy parsing, protocol detection, cancellable TCP tunnels, HTTP clients,
//! reachability and speed checks, VPN bypass and a loopback relay for
//! browsers. HTTP CONNECT, HTTPS CONNECT and SOCKS5 CONNECT. A Rust port of
//! the Go package [`github.com/n1s01/proxykit`](https://github.com/n1s01/proxykit).
//!
//! ```text
//! string → proxykit::new → Dialer → TCP tunnel / HTTP client / browser relay
//!              │             └── check → result + typed error
//!              └── parse → detect (only for an unknown protocol)
//! ```
//!
//! ```no_run
//! # async fn run() -> proxykit::Result<()> {
//! use proxykit::{CheckOptions, Options};
//!
//! let proxy = proxykit::new("user:pass:proxy.example@1080", Options {
//!     target: "web.telegram.org:443".into(),
//!     ..Default::default()
//! }).await?;
//! let result = proxy.check(CheckOptions::url("https://web.telegram.org/")).await?;
//! println!("{}: tunnel={:?}, total={:?}", proxy.spec(), result.tunnel_latency, result.duration);
//! # Ok(()) }
//! ```
//!
//! Parsing never performs network I/O. An endpoint without a protocol stays
//! `Auto` until resolved; dialing never falls back to a direct route.
//! Cancellation is Rust-native: drop the future, or wrap it in
//! `tokio::time::timeout`. Applications own storage, scheduling, rotation and
//! health policy.
//!
//! [`relay`] adapts a dialer to a local HTTP proxy for browsers (or any
//! client that only takes a proxy URL); [`gateway`] reads and writes
//! rotating-proxy parameters encoded in credentials.

mod batch;
mod bypass;
mod check;
mod detect;
mod dial;
mod error;
mod http;
mod inspect;
mod io;
mod json;
mod new;
mod parse;
mod spec;
mod speed;

pub mod gateway;
pub mod relay;
pub mod tls;

pub use batch::{check_all, check_stream, BatchOptions, CheckOutcome};
pub use bypass::{bypass_forward, bypass_supported, BypassOptions};
pub use check::{check, CheckOptions, CheckResult, SpeedResult};
pub use detect::{detect, resolve, Attempt, DetectOptions, Detection};
pub use dial::{DialOptions, Dialer, Forward, ForwardFuture};
pub use error::{BoxError, Error, ErrorKind, Op, Result, Stage};
pub use http::{connect_fn, http_client, Connect, HttpClient, HttpStream, ProxyConnector};
pub use inspect::{inspect, ip_who_is, Geo, GeoLookup, Info, InspectOptions};
pub use io::{BoxIo, Io, Tunnel};
pub use json::parse_json;
pub use new::{new, Options};
pub use parse::{parse, parse_lines, parse_with, Layout, LineError, ParseOptions};
pub use spec::{Protocol, Spec};
pub use speed::{speed_test, SpeedTestOptions, SpeedTestResult};

// Re-exported so users need no version-matched direct dependencies.
pub use {http_body_util, hyper, rustls};
