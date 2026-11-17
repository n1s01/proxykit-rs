use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Any async byte stream usable as a transport.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// Type-erased stream: TCP, TLS over TCP, or a user-supplied transport.
pub type BoxIo = Box<dyn Io>;

/// An established tunnel to the target, owned by the caller. Authentication
/// and CONNECT are complete; dropping it closes the connection. No deadline is
/// imposed after setup: wrap reads in `tokio::time::timeout` when needed.
pub struct Tunnel {
    io: BoxIo,
    /// Bytes the proxy sent right after its CONNECT reply; they belong to the tunnel.
    prefix: Bytes,
}

impl Tunnel {
    pub(crate) fn new(io: BoxIo, prefix: Bytes) -> Tunnel {
        Tunnel { io, prefix }
    }

    /// Erases the type, e.g. for APIs that take a [`BoxIo`].
    pub fn boxed(self) -> BoxIo {
        Box::new(self)
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel").field("buffered", &self.prefix.len()).finish()
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}
