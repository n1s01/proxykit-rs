use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::Uri;
use http_body_util::Full;
use hyper_util::{
    client::legacy::{
        connect::{Connected, Connection},
        Client,
    },
    rt::{TokioExecutor, TokioIo},
};
use rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::{
    dial::Dialer,
    error::{BoxError, Error, Result},
    io::{BoxIo, Io},
    spec::join_host_port,
    tls,
};

/// Anything that opens an authenticated tunnel to `host:port` (Go
/// `ContextDialer`). Implemented by [`Dialer`]; wrap a closure with
/// [`connect_fn`]. The HTTP client and the relay depend only on this.
pub trait Connect: Send + Sync + 'static {
    fn connect_io<'a>(&'a self, target: &'a str) -> BoxFuture<'a, Result<BoxIo>>;
}

impl Connect for Dialer {
    fn connect_io<'a>(&'a self, target: &'a str) -> BoxFuture<'a, Result<BoxIo>> {
        Box::pin(async move { Ok(Box::new(self.connect(target).await?) as BoxIo) })
    }
}

impl<T: Connect + ?Sized> Connect for Arc<T> {
    fn connect_io<'a>(&'a self, target: &'a str) -> BoxFuture<'a, Result<BoxIo>> {
        (**self).connect_io(target)
    }
}

/// Adapts a closure `Fn(String) -> impl Future<Output = Result<impl Io>>` to [`Connect`].
pub fn connect_fn<F, Fut, S>(f: F) -> impl Connect
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send + 'static,
    S: Io,
{
    struct FnConnect<F>(F);
    impl<F, Fut, S> Connect for FnConnect<F>
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S>> + Send + 'static,
        S: Io,
    {
        fn connect_io<'a>(&'a self, target: &'a str) -> BoxFuture<'a, Result<BoxIo>> {
            let fut = (self.0)(target.to_string());
            Box::pin(async move { Ok(Box::new(fut.await?) as BoxIo) })
        }
    }
    FnConnect(f)
}

/// A hyper connector that opens every connection through a proxy tunnel and
/// adds target TLS for `https` URIs. No environment proxy variables, no direct
/// fallback; plain `http` requests also use CONNECT, so the proxy must allow
/// it for port 80 as well.
#[derive(Clone)]
pub struct ProxyConnector {
    dialer: Arc<dyn Connect>,
    tls: Arc<ClientConfig>,
}

impl ProxyConnector {
    pub fn new(dialer: impl Connect) -> ProxyConnector {
        ProxyConnector {
            dialer: Arc::new(dialer),
            tls: tls::with_alpn(&tls::default_client_config(), &[b"h2", b"http/1.1"]),
        }
    }

    /// Target TLS configuration. ALPN `h2`/`http/1.1` is set when empty.
    pub fn with_tls(mut self, config: Arc<ClientConfig>) -> ProxyConnector {
        self.tls = if config.alpn_protocols.is_empty() {
            tls::with_alpn(&config, &[b"h2", b"http/1.1"])
        } else {
            config
        };
        self
    }
}

impl tower_service::Service<Uri> for ProxyConnector {
    type Response = HttpStream;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpStream>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let dialer = self.dialer.clone();
        let config = self.tls.clone();
        Box::pin(async move {
            let https = match uri.scheme_str() {
                Some("https") => true,
                Some("http") => false,
                _ => return Err(Error::invalid("URI scheme must be http or https")),
            };
            let host = uri.host().ok_or_else(|| Error::invalid("URI host"))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
            let io = dialer.connect_io(&join_host_port(host, port)).await?;
            if !https {
                return Ok(HttpStream { io: TokioIo::new(io), h2: false });
            }
            let tls = TlsConnector::from(config).connect(tls::server_name(host)?, io).await.map_err(Error::from)?;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            Ok(HttpStream { io: TokioIo::new(Box::new(tls)), h2 })
        })
    }
}

/// Connection produced by [`ProxyConnector`].
pub struct HttpStream {
    io: TokioIo<BoxIo>,
    h2: bool,
}

impl Connection for HttpStream {
    fn connected(&self) -> Connected {
        let c = Connected::new();
        if self.h2 {
            c.negotiated_h2()
        } else {
            c
        }
    }
}

impl hyper::rt::Read for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for HttpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// HTTP/1.1 + HTTP/2 client whose every connection goes through the proxy.
/// `client.get(uri)` works out of the box; read bodies with
/// [`http_body_util::BodyExt`].
pub type HttpClient<B = Full<Bytes>> = Client<ProxyConnector, B>;

/// Builds an [`HttpClient`] over any tunnel dialer, with pooled keep-alive
/// connections (90 s idle, 10 per host).
pub fn http_client<B>(connector: ProxyConnector) -> HttpClient<B>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .build(connector)
}

impl Dialer {
    /// A fresh HTTP client using this dialer for every connection.
    pub fn http_client(&self) -> HttpClient {
        http_client(self.connector())
    }

    /// A hyper connector for building a custom client.
    pub fn connector(&self) -> ProxyConnector {
        ProxyConnector::new(self.clone())
    }
}
