use futures_util::{stream, Stream, StreamExt};

use crate::{
    check::{CheckOptions, CheckResult},
    dial::{DialOptions, Dialer},
    error::Error,
    spec::Spec,
};

/// An individual check result and its failure, if any.
#[derive(Clone, Debug)]
pub struct CheckOutcome {
    pub result: CheckResult,
    pub error: Option<Error>,
}

/// Target checks, connection setup and the worker limit for batches.
#[derive(Clone, Debug, Default)]
pub struct BatchOptions {
    pub check: CheckOptions,
    pub dial: DialOptions,
    /// Parallel checks; 0 uses 16.
    pub concurrency: usize,
}

/// Checks proxies with bounded parallelism and preserves input order.
/// Dropping the future cancels the remaining checks.
pub async fn check_all(specs: &[Spec], opts: BatchOptions) -> Vec<CheckOutcome> {
    let n = concurrency(&opts);
    stream::iter(specs.iter().cloned().map(|spec| check_one(spec, opts.clone()))).buffered(n).collect().await
}

/// Like [`check_all`], but yields `(index, outcome)` as each check finishes,
/// for progress reporting. Stop consuming to cancel the rest.
pub fn check_stream(specs: Vec<Spec>, opts: BatchOptions) -> impl Stream<Item = (usize, CheckOutcome)> {
    let n = concurrency(&opts);
    stream::iter(specs.into_iter().enumerate().map(move |(i, spec)| {
        let opts = opts.clone();
        async move { (i, check_one(spec, opts).await) }
    }))
    .buffer_unordered(n)
}

fn concurrency(opts: &BatchOptions) -> usize {
    if opts.concurrency == 0 {
        16
    } else {
        opts.concurrency
    }
}

async fn check_one(spec: Spec, opts: BatchOptions) -> CheckOutcome {
    match Dialer::new(spec.clone(), opts.dial) {
        Ok(dialer) => {
            let (result, outcome) = dialer.check_full(&opts.check).await;
            CheckOutcome { result, error: outcome.err() }
        }
        Err(e) => CheckOutcome { result: CheckResult::empty(spec), error: Some(e) },
    }
}
