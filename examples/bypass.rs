//! Checks that the VPN bypass leaves through the physical interface. Run it
//! with the VPN switched on: the normal route shows the VPN address, the
//! bypass route the real one. Optional args: [--iface NAME] [proxy].
//!
//!     cargo run --example bypass -- --iface en0 socks5://user:pass@host:1080

use proxykit::{BypassOptions, DialOptions, Forward, InspectOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Plain-HTTP IP echo, so the check needs nothing but a TCP stream.
const IP_HOST: &str = "api.ipify.org";

async fn public_ip(forward: &Forward) -> Result<String, Box<dyn std::error::Error>> {
    let mut s = forward.dial(format!("{IP_HOST}:80")).await?;
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {IP_HOST}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).await?;
    Ok(resp.rsplit("\r\n\r\n").next().unwrap_or_default().trim().to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut opts = BypassOptions::default();
    let mut proxy = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iface" => opts.interface = args.next().ok_or("--iface needs a name")?,
            other => proxy = Some(other.to_string()),
        }
    }
    println!("bypass supported: {}", proxykit::bypass_supported());
    let bound = proxykit::bypass_forward(opts.clone())?;

    let normal = public_ip(&Forward::system()).await;
    let bypass = public_ip(&bound).await;
    println!("[1] normal route: {}", normal.as_ref().map_or_else(|e| format!("error: {e}"), |ip| ip.clone()));
    println!("[2] bypass route: {}", bypass.as_ref().map_or_else(|e| format!("error: {e}"), |ip| ip.clone()));
    match (&normal, &bypass) {
        (_, Err(_)) => println!("RESULT: FAIL - the bypass route could not connect."),
        (Err(_), Ok(_)) => println!("RESULT: OK - the bypass route works while the normal route is down."),
        (Ok(a), Ok(b)) if a != b => println!("RESULT: OK - the bypass route leaves through a different address."),
        _ => println!("RESULT: INCONCLUSIVE - both routes show the same address (is the VPN on?)."),
    }

    if let Some(raw) = proxy {
        let spec = proxykit::parse(&raw)?;
        let info = proxykit::inspect(&spec, InspectOptions {
            target: "web.telegram.org:443".into(),
            dial: DialOptions { bypass: Some(opts), ..Default::default() },
            ..Default::default()
        })
        .await?;
        println!("proxy {}: latency {:?}, exit {} {}", info.proxy, info.latency, info.geo.ip, info.geo.country);
    }
    Ok(())
}
