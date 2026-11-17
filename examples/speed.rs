//! Health and download speed. Set PROXY_URL and TARGET_URL.
//!
//!     PROXY_URL='socks5://user:pass@host:1080' TARGET_URL='https://speed.example/10mb' cargo run --example speed

use proxykit::SpeedTestOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec = proxykit::parse(&std::env::var("PROXY_URL").map_err(|_| "set PROXY_URL")?)?;
    let url = std::env::var("TARGET_URL").map_err(|_| "set TARGET_URL")?;
    let r = proxykit::speed_test(&spec, SpeedTestOptions::url(url)).await?;
    println!(
        "{}: ok={} status={} tunnel={:?}\n{} bytes in {:?}: {:.2} Mbit/s (complete={})",
        spec,
        r.health.ok,
        r.health.status_code,
        r.health.tunnel_latency,
        r.speed.bytes,
        r.speed.duration,
        r.speed.megabits_per_second,
        r.speed.complete
    );
    Ok(())
}
