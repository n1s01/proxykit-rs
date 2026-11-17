//! TCP tunnel. Set PROXY_URL and TARGET_ADDR (host:port).
//!
//!     PROXY_URL='socks5://user:pass@host:1080' TARGET_ADDR='149.154.167.50:443' cargo run --example tcp

use std::time::Duration;

use proxykit::Options;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (input, target) = match (std::env::var("PROXY_URL"), std::env::var("TARGET_ADDR")) {
        (Ok(i), Ok(t)) => (i, t),
        _ => return Err("set PROXY_URL and TARGET_ADDR".into()),
    };
    let proxy = tokio::time::timeout(
        Duration::from_secs(10),
        proxykit::new(&input, Options { target: target.clone(), ..Default::default() }),
    )
    .await??;
    let tunnel = proxy.connect(&target).await?;
    // Pass `tunnel` (AsyncRead + AsyncWrite) to your protocol; it belongs to the caller.
    println!("tunnel established via {} ({tunnel:?})", proxy.spec());
    Ok(())
}
