use crate::{
    detect::{detect, DetectOptions},
    dial::{DialOptions, Dialer},
    error::Result,
    parse::{parse_with, ParseOptions},
    spec::{Protocol, Spec},
};

/// Parsing, connection setup and optional discovery in one value.
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub parse: ParseOptions,
    pub dial: DialOptions,
    /// Required only when the input has no explicit protocol.
    pub target: String,
    /// Discovery candidates; empty tries SOCKS5, HTTP and HTTPS.
    pub candidates: Vec<Protocol>,
}

/// Parses `input` and returns a ready [`Dialer`]. Explicit protocols need no
/// network I/O; `Auto` is discovered against `opts.target` over the same route
/// and TLS settings as traffic. Store the resolved protocol
/// (`dialer.spec().url()`) to skip discovery next time.
pub async fn new(input: &str, opts: Options) -> Result<Dialer> {
    let spec = parse_with(input, &opts.parse)?;
    dialer_for(spec, opts).await
}

pub(crate) async fn dialer_for(mut spec: Spec, opts: Options) -> Result<Dialer> {
    if spec.protocol == Protocol::Auto {
        spec = detect(
            &spec,
            DetectOptions {
                target: opts.target,
                candidates: opts.candidates,
                timeout: opts.dial.timeout,
                dial: opts.dial.clone(),
            },
        )
        .await?
        .proxy;
    }
    Dialer::new(spec, opts.dial)
}
