//! Bounded protobuf Chunk framing over standard, uncompressed gRPC messages.
use bytes::{Buf, Bytes};
use prost::Message;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const CONNECT_PATH: &str = "/rvnx.Tunnel/Connect";
pub const DOWNLOAD_PATH: &str = "/rvnx.Tunnel/Download";
const CHUNK: usize = 32 * 1024;
const MAX_MESSAGE: usize = CHUNK + 16;
#[derive(Clone, PartialEq, Message)]
pub struct Chunk {
    #[prost(bytes = "bytes", tag = "1")]
    pub data: Bytes,
}

pub fn encode(data: &[u8]) -> Bytes {
    let chunk = Chunk {
        data: Bytes::copy_from_slice(data),
    };
    let mut out = Vec::with_capacity(5 + chunk.encoded_len());
    out.push(0);
    out.extend_from_slice(&(chunk.encoded_len() as u32).to_be_bytes());
    chunk.encode(&mut out).expect("Vec grows");
    out.into()
}

pub struct GrpcStream<S> {
    inner: S,
    header: [u8; 5],
    header_len: usize,
    body: Vec<u8>,
    body_len: usize,
    pending: Bytes,
    outgoing: Bytes,
}
impl<S> GrpcStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 5],
            header_len: 0,
            body: Vec::new(),
            body_len: 0,
            pending: Bytes::new(),
            outgoing: Bytes::new(),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for GrpcStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.pending.is_empty() {
                let n = buf.remaining().min(this.pending.len());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            while this.header_len < 5 {
                let mut read = ReadBuf::new(&mut this.header[this.header_len..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let n = read.filled().len();
                if n == 0 {
                    return Poll::Ready(if this.header_len == 0 {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::UnexpectedEof.into())
                    });
                }
                this.header_len += n;
                if this.header_len == 5 {
                    let len = u32::from_be_bytes(this.header[1..].try_into().unwrap()) as usize;
                    if this.header[0] != 0 || len > MAX_MESSAGE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unsupported gRPC compression or oversized message",
                        )));
                    }
                    this.body.resize(len, 0);
                    this.body_len = 0;
                }
            }
            while this.body_len < this.body.len() {
                let mut read = ReadBuf::new(&mut this.body[this.body_len..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let n = read.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.body_len += n;
            }
            this.pending = Chunk::decode(this.body.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .data;
            this.header_len = 0;
        }
    }
}
impl<S: AsyncWrite + Unpin> GrpcStream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outgoing.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.outgoing))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.outgoing.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for GrpcStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        let n = data.len().min(CHUNK);
        if n != 0 {
            this.outgoing = encode(&data[..n]);
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "tests/grpc.rs"]
mod tests;
