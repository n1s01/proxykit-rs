//! HTTP client through a proxy. Set PROXY_URL and TARGET_URL.
//!
//!     PROXY_URL='http://user:pass@host:3128' TARGET_URL='https://example.com/' cargo run --example http

use proxykit::{http_body_util::BodyExt, CheckOptions, Options};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::env::var("PROXY_URL").map_err(|_| "set PROXY_URL")?;
    let url = std::env::var("TARGET_URL").map_err(|_| "set TARGET_URL")?;
    let uri: proxykit::hyper::Uri = url.parse()?;
    let target = format!("{}:{}", uri.host().unwrap_or_default(), uri.port_u16().unwrap_or(443));
    let proxy = proxykit::new(&input, Options { target, ..Default::default() }).await?;

    let health = proxy.check(CheckOptions::url(url.clone())).await?;
    println!("{}: status {} tunnel {:?} total {:?}", proxy.spec(), health.status_code, health.tunnel_latency, health.duration);

    let client = proxy.http_client();
    let resp = client.get(uri).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    println!("GET {url}: {status}, {} bytes", body.len());
    Ok(())
}
