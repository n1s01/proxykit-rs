mod common;

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use common::*;
use futures_util::StreamExt;
use proxykit::{
    http_body_util::BodyExt, BatchOptions, CheckOptions, DetectOptions, DialOptions, Dialer, ErrorKind, Forward, Geo,
    GeoLookup, InspectOptions, Options, Protocol, Spec, SpeedTestOptions, Stage,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn local(protocol: Protocol, addr: std::net::SocketAddr) -> Spec {
    Spec::new(protocol, "127.0.0.1", addr.port())
}

async fn assert_echo(d: &Dialer, target: &str, payload: &[u8]) {
    let mut t = d.connect(target).await.unwrap_or_else(|e| panic!("connect via {}: {e:?}", d.spec()));
    t.write_all(payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    t.read_exact(&mut back).await.unwrap();
    assert_eq!(back, payload);
}

#[tokio::test]
async fn socks5_tunnels_with_and_without_auth_and_remote_dns() {
    let echo = echo_server().await;
    let (open, seen) = socks5_proxy(None).await;
    let d = Dialer::new(local(Protocol::Socks5, open), DialOptions::default()).unwrap();
    assert_echo(&d, &echo.to_string(), b"hello").await;
    // Domain names go to the proxy, not to the local resolver.
    assert_echo(&d, &format!("localhost:{}", echo.port()), b"dns").await;
    assert!(seen.lock().unwrap().iter().any(|t| t.starts_with("localhost:")));

    let (authed, _) = socks5_proxy(Some(("alice", "s3cret"))).await;
    let ok = Dialer::new(local(Protocol::Socks5, authed).with_auth("alice", "s3cret"), DialOptions::default()).unwrap();
    assert_echo(&ok, &echo.to_string(), &vec![9u8; 200 * 1024]).await;

    let bad = Dialer::new(local(Protocol::Socks5, authed).with_auth("alice", "wrong"), DialOptions::default()).unwrap();
    let e = bad.connect(&echo.to_string()).await.unwrap_err();
    assert_eq!((e.kind(), e.stage()), (ErrorKind::Auth, Some(Stage::Auth)));
    assert!(!e.to_string().contains("wrong"));
}

#[tokio::test]
async fn http_connect_auth_rejection_and_buffered_bytes() {
    let echo = echo_server().await;
    let proxy = http_proxy(HttpProxyOptions { auth: Some(("u", "p")), suffix: b"EARLY", ..Default::default() }).await;
    let d = Dialer::new(local(Protocol::Http, proxy).with_auth("u", "p"), DialOptions::default()).unwrap();
    let mut t = d.connect(&echo.to_string()).await.unwrap();
    let mut early = [0u8; 5];
    t.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"EARLY", "bytes after the CONNECT reply belong to the tunnel");
    t.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    t.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");

    let bad = Dialer::new(local(Protocol::Http, proxy).with_auth("u", "x"), DialOptions::default()).unwrap();
    let e = bad.connect(&echo.to_string()).await.unwrap_err();
    assert_eq!((e.kind(), e.stage(), e.status_code()), (ErrorKind::Auth, Some(Stage::Auth), Some(407)));

    let closed = silent_port().await;
    let e = d.connect(&format!("127.0.0.1:{closed}")).await.unwrap_err();
    assert_eq!((e.kind(), e.stage(), e.status_code()), (ErrorKind::Rejected, Some(Stage::Connect), Some(502)));
}

/// A port with nothing listening.
async fn silent_port() -> u16 {
    let (l, addr) = listen().await;
    drop(l);
    addr.port()
}

#[tokio::test]
async fn https_proxy_verifies_certificates() {
    let echo = echo_server().await;
    let (acceptor, trust) = tls_pair();
    let proxy = http_proxy(HttpProxyOptions { tls: Some(acceptor), ..Default::default() }).await;
    let spec = local(Protocol::Https, proxy);
    let d = Dialer::new(spec.clone(), DialOptions { tls: Some(trust), ..Default::default() }).unwrap();
    assert_echo(&d, &echo.to_string(), b"over tls").await;

    let untrusted = Dialer::new(spec, DialOptions::default()).unwrap();
    let e = untrusted.connect(&echo.to_string()).await.unwrap_err();
    assert_eq!((e.kind(), e.stage()), (ErrorKind::Tls, Some(Stage::ProxyTls)));
}

#[tokio::test]
async fn detect_and_new_resolve_protocol() {
    let echo = echo_server().await;
    let (socks, _) = socks5_proxy(None).await;
    let http = http_proxy(HttpProxyOptions::default()).await;
    let target = echo.to_string();

    let found = proxykit::detect(&local(Protocol::Auto, socks), DetectOptions { target: target.clone(), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(found.proxy.protocol, Protocol::Socks5);
    assert_eq!(found.attempts.len(), 3);

    let d = proxykit::new(&format!("127.0.0.1:{}", http.port()), Options { target: target.clone(), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(d.spec().protocol, Protocol::Http);
    assert_echo(&d, &target, b"auto").await;

    // Explicit protocols never touch the network.
    let d = proxykit::new("socks5://127.0.0.1:1", Options::default()).await.unwrap();
    assert_eq!(d.spec().protocol, Protocol::Socks5);
    assert_eq!(proxykit::new("127.0.0.1:1", Options::default()).await.unwrap_err().kind(), ErrorKind::Invalid);

    let (authed, _) = socks5_proxy(Some(("a", "b"))).await;
    let e = proxykit::detect(&local(Protocol::Auto, authed).with_auth("a", "zz"), DetectOptions { target, ..Default::default() })
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Detection);
    assert_eq!(e.attempts().len(), 3);
    assert!(e.is(ErrorKind::Auth));
}

#[tokio::test]
async fn checks_target_url_status_and_tls() {
    let (socks, _) = socks5_proxy(None).await;
    let d = Dialer::new(local(Protocol::Socks5, socks), DialOptions::default()).unwrap();
    let web = origin(None).await;

    let r = d.check(CheckOptions::target(web.to_string())).await.unwrap();
    assert!(r.ok && r.tunnel_latency <= r.duration);

    let r = d.check(CheckOptions::url(format!("http://{web}/"))).await.unwrap();
    assert_eq!((r.ok, r.status_code), (true, 200));

    let e = d.check(CheckOptions::url(format!("http://{web}/404"))).await.unwrap_err();
    assert_eq!((e.kind(), e.stage(), e.status_code()), (ErrorKind::Status, Some(Stage::Http), Some(404)));

    let e = d.check(CheckOptions::url(format!("http://{web}/redirect"))).await.unwrap_err();
    assert_eq!(e.status_code(), Some(302), "redirects are not followed");
    let r = d
        .check(CheckOptions { url: format!("http://{web}/redirect"), status_codes: vec![302], ..Default::default() })
        .await
        .unwrap();
    assert_eq!(r.status_code, 302);

    let (acceptor, trust) = tls_pair();
    let secure = origin(Some(acceptor)).await;
    let r = d.check(CheckOptions::url(format!("https://127.0.0.1:{}/204", secure.port())).with_tls(trust.clone())).await.unwrap();
    assert_eq!(r.status_code, 204);
    let r = d.check(CheckOptions::target(secure.to_string()).with_tls(trust)).await.unwrap();
    assert!(r.ok);
    let e = d.check(CheckOptions::target(secure.to_string()).with_tls(proxykit::tls::default_client_config())).await.unwrap_err();
    assert_eq!((e.kind(), e.stage()), (ErrorKind::Tls, Some(Stage::TargetTls)));

    assert_eq!(d.check(CheckOptions::default()).await.unwrap_err().kind(), ErrorKind::Invalid);
    let json = serde_json::to_value(d.check(CheckOptions::target(web.to_string())).await.unwrap()).unwrap();
    assert!(json["tunnel_latency"].is_u64() && json["started_at"].is_string());
}

#[tokio::test]
async fn speed_test_reads_body_through_tunnel() {
    let http = http_proxy(HttpProxyOptions::default()).await;
    let web = origin(None).await;
    let spec = local(Protocol::Http, http);
    let r = proxykit::speed_test(&spec, SpeedTestOptions::url(format!("http://{web}/big"))).await.unwrap();
    assert!(r.health.ok);
    assert_eq!(r.speed.bytes, 1 << 20);
    assert!(r.speed.complete && r.speed.bytes_per_second > 0.0);

    let capped = SpeedTestOptions { max_bytes: Some(1000), ..SpeedTestOptions::url(format!("http://{web}/big")) };
    let r = proxykit::speed_test(&spec, capped).await.unwrap();
    assert_eq!((r.speed.bytes, r.speed.complete), (1000, true));
}

#[tokio::test]
async fn batch_preserves_order() {
    let echo = echo_server().await;
    let (socks, _) = socks5_proxy(None).await;
    let dead = silent_port().await;
    let specs = vec![local(Protocol::Socks5, socks), Spec::new(Protocol::Socks5, "127.0.0.1", dead), local(Protocol::Socks5, socks)];
    let opts = BatchOptions { check: CheckOptions::target(echo.to_string()), concurrency: 2, ..Default::default() };
    let out = proxykit::check_all(&specs, opts.clone()).await;
    let ok: Vec<bool> = out.iter().map(|o| o.error.is_none()).collect();
    assert_eq!(ok, [true, false, true]);
    assert_eq!(out[1].error.as_ref().unwrap().stage(), Some(Stage::Dial));
    assert_eq!(out[1].result.proxy.port, dead);

    let mut seen: Vec<usize> = proxykit::check_stream(specs, opts).map(|(i, _)| i).collect().await;
    seen.sort();
    assert_eq!(seen, [0, 1, 2]);
}

#[tokio::test]
async fn setup_timeout_reports_stage() {
    let silent = silent_server().await;
    for (protocol, stage) in [(Protocol::Socks5, Stage::Negotiation), (Protocol::Http, Stage::Connect)] {
        let d = Dialer::new(local(protocol, silent), DialOptions { timeout: Some(Duration::from_millis(200)), ..Default::default() })
            .unwrap();
        let started = std::time::Instant::now();
        let e = d.connect("example.test:443").await.unwrap_err();
        assert!(e.is_timeout(), "{e:?}");
        assert_eq!(e.stage(), Some(stage));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}

#[tokio::test]
async fn custom_forward_and_http_client() {
    let (socks, _) = socks5_proxy(None).await;
    let web = origin(None).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let forward = Forward::new(move |addr: String| {
        counter.fetch_add(1, Ordering::SeqCst);
        async move { TcpStream::connect(addr).await }
    });
    let d = Dialer::new(local(Protocol::Socks5, socks), DialOptions { forward: Some(forward), ..Default::default() }).unwrap();
    let client = d.http_client();
    let resp = client.get(format!("http://{web}/").parse().unwrap()).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
    assert!(calls.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn inspect_measures_latency_and_geo_through_proxy() {
    let (socks, seen) = socks5_proxy(None).await;
    let web = origin(None).await;
    let geo_url = format!("http://{web}/geo");
    let lookup = GeoLookup::new(move |client| {
        let url = geo_url.clone();
        async move {
            let resp = client.get(url.parse()?).await?;
            let body = resp.into_body().collect().await?.to_bytes();
            let v: serde_json::Value = serde_json::from_slice(&body)?;
            Ok(Geo { ip: v["ip"].as_str().unwrap_or_default().into(), country: v["country"].as_str().unwrap_or_default().into() })
        }
    });
    let opts = InspectOptions { target: web.to_string(), geo: Some(lookup), ..Default::default() };
    let info = proxykit::inspect(&local(Protocol::Auto, socks), opts).await.unwrap();
    assert_eq!(info.proxy.protocol, Protocol::Socks5);
    assert_eq!(info.geo, Geo { ip: "192.0.2.7".into(), country: "NL".into() });
    assert!(info.geo_error.is_none() && info.latency > Duration::ZERO);
    assert!(seen.lock().unwrap().len() >= 2, "geo lookup went through the proxy");

    let skip = InspectOptions { target: web.to_string(), skip_geo: true, ..Default::default() };
    let info = proxykit::inspect(&local(Protocol::Socks5, socks), skip).await.unwrap();
    assert!(info.geo.country.is_empty() && info.geo_error.is_none());
}

#[tokio::test]
async fn relay_serves_http_and_connect() {
    let echo = echo_server().await;
    let web = origin(None).await;
    let (socks, _) = socks5_proxy(None).await;
    let d = Dialer::new(local(Protocol::Socks5, socks), DialOptions::default()).unwrap();
    let relay = proxykit::relay::start(d, Default::default()).unwrap();
    assert!(relay.url().starts_with("http://127.0.0.1:"));

    let mut c = TcpStream::connect(relay.addr()).await.unwrap();
    c.write_all(format!("GET http://{web}/ HTTP/1.1\r\nHost: {web}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    c.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("ok"));

    let mut c = TcpStream::connect(relay.addr()).await.unwrap();
    c.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(c.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    c.write_all(b"through relay").await.unwrap();
    let mut back = [0u8; 13];
    c.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"through relay");

    let mut bad = TcpStream::connect(relay.addr()).await.unwrap();
    bad.write_all(b"GET /relative HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut resp = String::new();
    bad.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    tokio::time::timeout(Duration::from_secs(5), relay.close()).await.expect("close interrupts the open tunnel");
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await.unwrap().unwrap_or(0);
    assert_eq!(n, 0, "tunnel closed with the relay");
}

#[tokio::test]
async fn bypass_options_are_validated() {
    let both = DialOptions { forward: Some(Forward::system()), bypass: Some(Default::default()), ..Default::default() };
    let e = Dialer::new(Spec::new(Protocol::Socks5, "127.0.0.1", 1080), both).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Invalid);

    if !proxykit::bypass_supported() {
        let e = proxykit::bypass_forward(Default::default()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BypassUnsupported);
        return;
    }
    let bad_dns = proxykit::BypassOptions { dns: vec!["dns.example:53".into()], ..Default::default() };
    assert_eq!(proxykit::bypass_forward(bad_dns).unwrap_err().kind(), ErrorKind::Invalid);

    // Loopback proxies are never bound, so bypass works against local fixtures.
    let echo = echo_server().await;
    let (socks, _) = socks5_proxy(None).await;
    let d = Dialer::new(local(Protocol::Socks5, socks), DialOptions { bypass: Some(Default::default()), ..Default::default() })
        .unwrap();
    assert_echo(&d, &echo.to_string(), b"bypass").await;

    let pinned = proxykit::BypassOptions { interface: "definitely-not-an-interface0".into(), ..Default::default() };
    let forward = proxykit::bypass_forward(pinned).unwrap();
    let err = forward.dial("192.0.2.1:9".into()).await.err().expect("unknown interface");
    assert_eq!(proxykit::Error::from(err).kind(), ErrorKind::NoInterface);
}
