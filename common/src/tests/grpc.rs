use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn fragmented_full_duplex_and_half_close() {
    let (a, b) = tokio::io::duplex(7);
    let writer = tokio::spawn(async move {
        let mut a = GrpcStream::new(a);
        a.write_all(&vec![19; 100_001]).await.unwrap();
        a.shutdown().await.unwrap();
        let mut reply = Vec::new();
        a.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"ok");
    });
    let mut b = GrpcStream::new(b);
    let mut data = Vec::new();
    b.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, vec![19; 100_001]);
    b.write_all(b"ok").await.unwrap();
    b.shutdown().await.unwrap();
    writer.await.unwrap();
}
#[tokio::test]
async fn rejects_truncated_compressed_and_oversized_records() {
    for bytes in [
        vec![0, 0],
        vec![0, 0, 0, 0, 3, 10],
        vec![1, 0, 0, 0, 0],
        vec![0, 0, 1, 0, 0],
    ] {
        let mut stream = GrpcStream::new(bytes.as_slice());
        assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
    }
    let mut empty = GrpcStream::new(&b"\0\0\0\0\0"[..]);
    assert_eq!(empty.read_to_end(&mut Vec::new()).await.unwrap(), 0);
}

struct ZeroWriter;
impl AsyncWrite for ZeroWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn zero_length_operations_and_write_zero_are_handled() {
    let mut reader = GrpcStream::new(&b"malformed"[..]);
    assert_eq!(reader.read(&mut []).await.unwrap(), 0);
    let mut writer = GrpcStream::new(ZeroWriter);
    assert_eq!(writer.write(&[]).await.unwrap(), 0);
    assert_eq!(writer.write(b"x").await.unwrap(), 1);
    assert_eq!(
        writer.flush().await.unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(
        writer.write(b"next").await.unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(
        writer.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
}

#[tokio::test]
async fn invalid_protobuf_and_underlying_write_errors_are_propagated() {
    let mut stream = GrpcStream::new(&b"\0\0\0\0\x01\x0f"[..]);
    assert_eq!(
        stream.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let (writer, peer) = tokio::io::duplex(16);
    drop(peer);
    let mut writer = GrpcStream::new(writer);
    writer.write_all(b"hello").await.unwrap();
    assert_eq!(
        writer.flush().await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn cancelling_partial_reads_preserves_frame_header_and_body() {
    let encoded = encode(b"model-token");
    for split in [1, 4, 6, encoded.len() - 1] {
        let (io, mut peer) = tokio::io::duplex(128);
        let mut stream = GrpcStream::new(io);
        peer.write_all(&encoded[..split]).await.unwrap();
        let mut byte = [0; 1];
        let mut read = Box::pin(stream.read(&mut byte));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(std::future::Future::poll(read.as_mut(), cx)))
                .await
                .is_pending()
        );
        drop(read);
        peer.write_all(&encoded[split..]).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut decoded = Vec::new();
        stream.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(decoded, b"model-token");
    }
}

#[tokio::test]
async fn cancelling_partial_flush_preserves_queued_bytes_and_next_message() {
    let (io, peer) = tokio::io::duplex(3);
    let mut stream = GrpcStream::new(io);
    stream.write_all(b"first").await.unwrap();
    let mut flush = Box::pin(stream.flush());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(std::future::Future::poll(flush.as_mut(), cx)))
            .await
            .is_pending()
    );
    drop(flush);
    let reader = tokio::spawn(async move {
        let mut peer = GrpcStream::new(peer);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    stream.write_all(b"second").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(reader.await.unwrap(), b"firstsecond");
}

struct ReadFailure {
    prefix: std::io::Cursor<Vec<u8>>,
}
impl AsyncRead for ReadFailure {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = self.prefix.position() as usize;
        if start == self.prefix.get_ref().len() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let n = buf.remaining().min(self.prefix.get_ref().len() - start);
        buf.put_slice(&self.prefix.get_ref()[start..start + n]);
        self.prefix.set_position((start + n) as u64);
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn underlying_read_errors_propagate_in_both_header_and_body() {
    let encoded = encode(b"token");
    for split in [0, 2, 6] {
        let mut stream = GrpcStream::new(ReadFailure {
            prefix: std::io::Cursor::new(encoded[..split].to_vec()),
        });
        assert_eq!(
            stream.read(&mut [0; 16]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }
}
