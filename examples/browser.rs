//! Loopback relay for Chromium or any client that only takes a proxy URL.
//! Set PROXY_URL (and TARGET for proxies without a scheme).
//!
//!     PROXY_URL='socks5://user:pass@host:1080' cargo run --example browser
//!     chromium --proxy-server=http://127.0.0.1:PORT

use proxykit::Options;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::env::var("PROXY_URL").map_err(|_| "set PROXY_URL")?;
    let target = std::env::var("TARGET").unwrap_or_else(|_| "web.telegram.org:443".into());
    let proxy = proxykit::new(&input, Options { target, ..Default::default() }).await?;
    let relay = proxykit::relay::start(proxy, Default::default())?;
    println!("--proxy-server={}", relay.url());
    println!("Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    relay.close().await;
    Ok(())
}
