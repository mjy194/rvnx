//! Authenticated HTTP/2 request/response bodies form independent duplex streams.
//! No RVNX parser runs before HTTP authentication. HTTP/1 visitors see a normal 404.
use std::{
    convert::Infallible,
    future::poll_fn,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
};

use anyhow::{Context as _, Result, ensure};
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use http::{
    Request, Response, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{Mutex, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    grpc::{self, GrpcStream},
    protocol::{Control, send_control},
    transport::{CONNECT_TIMEOUT, IDLE_TIMEOUT, connect},
};

const PATH: &str = "/api/stream";
const STREAM_WINDOW: u32 = 256 * 1024;
// Enough connection credit for every allowed stream's individual window:
// stalled streams cannot consume the credit reserved for a responsive stream.
const MAX_STREAMS: u32 = 128;
const CONNECTION_WINDOW: u32 = STREAM_WINDOW * MAX_STREAMS;
const CHUNK: usize = 32 * 1024;
const NOT_FOUND: &[u8] = b"Not Found\n";

struct Driver {
    task: Option<JoinHandle<()>>,
    drain_on_drop: bool,
}
impl Driver {
    fn is_finished(&self) -> bool {
        self.task.as_ref().unwrap().is_finished()
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        let mut task = self.task.take().unwrap();
        if self.drain_on_drop {
            // A single-use stream can finish with END_STREAM still queued. Let
            // h2 flush and close after its final handles drop, with a bounded wait.
            tokio::spawn(async move {
                if timeout(CONNECT_TIMEOUT, &mut task).await.is_err() {
                    task.abort();
                }
            });
        } else {
            task.abort();
        }
    }
}

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type Tunnel = Box<dyn Duplex>;

pub struct H2Stream {
    grpc_response: bool,
    check_trailers: bool,
    eof: bool,
    recv: RecvStream,
    send: SendStream<Bytes>,
    pending: Bytes,
    closed: bool,
    // An old pool connection may be draining after GOAWAY. Keep its driver alive.
    _driver: Option<Arc<Driver>>,
}

impl H2Stream {
    fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            grpc_response: false,
            check_trailers: false,
            eof: false,
            pending: Bytes::new(),
            closed: false,
            _driver: None,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.eof {
            return Poll::Ready(Ok(()));
        }
        while self.pending.is_empty() {
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => self.pending = data,
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => {
                    if self.check_trailers {
                        let trailers =
                            ready!(self.recv.poll_trailers(cx)).map_err(io::Error::other)?;
                        if trailers
                            .as_ref()
                            .and_then(|h| h.get("grpc-status"))
                            .is_none_or(|v| v != "0")
                        {
                            return Poll::Ready(Err(io::Error::other(
                                "missing or unsuccessful gRPC status",
                            )));
                        }
                    }
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        let len = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending[..len]);
        self.pending.advance(len);
        // Release credit only as the consumer reads, never for queued unread data.
        self.recv
            .flow_control()
            .release_capacity(len)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = data.len().min(CHUNK);
        self.send.reserve_capacity(wanted);
        while self.send.capacity() == 0 {
            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let len = wanted.min(self.send.capacity());
        self.send
            .send_data(Bytes::copy_from_slice(&data[..len]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(len))
    }
    // h2's connection driver flushes queued DATA independently; it has no per-stream flush API.
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            if self.grpc_response {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                self.send
                    .send_trailers(trailers)
                    .map_err(io::Error::other)?;
            } else {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(io::Error::other)?;
            }
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
pub(crate) struct Connection {
    pub capacity: Arc<AtomicUsize>,
    sender: h2::client::SendRequest<Bytes>,
    driver: Arc<Driver>,
}

impl Connection {
    pub fn finished(&self) -> bool {
        self.driver.is_finished()
    }
}

pub struct HttpsTransport {
    tls: TlsConnector,
    server: String,
    server_name: String,
    authorization: HeaderValue,
    slots: Vec<Mutex<Option<Connection>>>,
    next: AtomicUsize,
}

impl HttpsTransport {
    pub fn new(
        tls: TlsConnector,
        server: String,
        server_name: String,
        token: &str,
        pool_size: Option<usize>,
    ) -> Result<Self> {
        if let Some(size) = pool_size {
            ensure!((1..=32).contains(&size), "pool size must be in 1..=32");
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true); // HPACK must not index the credential.
        Ok(Self {
            tls,
            server,
            server_name,
            authorization,
            slots: (0..pool_size.unwrap_or(0))
                .map(|_| Mutex::new(None))
                .collect(),
            next: AtomicUsize::new(0),
        })
    }

    async fn establish(&self) -> Result<Connection> {
        self.establish_at(&self.server).await
    }

    pub(crate) async fn establish_at(&self, address: &str) -> Result<Connection> {
        let tls = connect(&self.tls, address, &self.server_name).await?;
        ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "server did not negotiate HTTP/2"
        );
        let (sender, mut connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_send_buffer_size(CHUNK)
            .max_header_list_size(8192)
            .handshake(tls)
            .await?;
        let capacity = Arc::new(AtomicUsize::new(0));
        let observed = capacity.clone();
        let driver = Arc::new(Driver {
            task: Some(tokio::spawn(async move {
                let _ = poll_fn(|cx| {
                    use std::future::Future;
                    let result = Pin::new(&mut connection).poll(cx);
                    observed.store(connection.max_concurrent_send_streams(), Ordering::Relaxed);
                    result
                })
                .await;
            })),
            drain_on_drop: self.slots.is_empty(),
        });
        Ok(Connection {
            sender,
            driver,
            capacity,
        })
    }

    async fn connection(
        &self,
        slot: usize,
    ) -> Result<(h2::client::SendRequest<Bytes>, Arc<Driver>)> {
        let mut entry = self.slots[slot].lock().await;
        if entry.as_ref().is_none_or(|c| c.driver.is_finished()) {
            *entry = Some(self.establish().await?);
        }
        let entry = entry.as_ref().unwrap();
        Ok((entry.sender.clone(), entry.driver.clone()))
    }

    pub async fn warm(&self) -> Result<()> {
        for slot in 0..self.slots.len() {
            timeout(CONNECT_TIMEOUT, self.connection(slot)).await??;
        }
        Ok(())
    }

    async fn discard_connection(&self, slot: usize, driver: &Arc<Driver>) {
        let mut entry = self.slots[slot].lock().await;
        // Another opener may already have replaced the failed connection.
        if entry
            .as_ref()
            .is_some_and(|c| Arc::ptr_eq(&c.driver, driver))
        {
            *entry = None;
        }
    }

    pub async fn open(&self, hello: Control) -> Result<Tunnel> {
        timeout(CONNECT_TIMEOUT, async {
            let slot = if self.slots.is_empty() {
                None
            } else {
                Some(self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len())
            };
            let (mut sender, driver) = if let Some(slot) = slot {
                self.connection(slot).await?
            } else {
                let connection = self.establish().await?;
                (connection.sender, connection.driver)
            };
            if let Err(error) = poll_fn(|cx| sender.poll_ready(cx)).await {
                if let Some(slot) = slot {
                    self.discard_connection(slot, &driver).await;
                }
                return Err(error.into());
            }
            let request = Request::builder()
                .method("POST")
                .uri(format!("https://{}{PATH}", self.server))
                .header(AUTHORIZATION, self.authorization.clone())
                .header("content-type", "application/octet-stream")
                .body(())?;
            let (response, mut send) = sender.send_request(request, false)?;
            // Pipeline the small initial message with HEADERS; avoid an extra RTT.
            let mut bytes = Vec::new();
            send_control(&mut bytes, hello).await?;
            send.send_data(Bytes::from(bytes), false)?;
            let response = response.await?;
            ensure!(
                response.status() == StatusCode::OK,
                "HTTPS request rejected ({})",
                response.status()
            );
            let mut stream = H2Stream::new(response.into_body(), send);
            stream._driver = Some(driver);
            Ok(Box::new(stream) as Tunnel)
        })
        .await
        .context("HTTPS stream open timed out")?
    }
    async fn grpc_request(
        &self,
        connection: &Connection,
        path: &str,
        data: &[u8],
        end: bool,
    ) -> Result<GrpcStream<H2Stream>> {
        let mut sender = connection.sender.clone();
        poll_fn(|cx| sender.poll_ready(cx)).await?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://{}{path}", self.server))
            .header(AUTHORIZATION, self.authorization.clone())
            .header("content-type", "application/grpc+proto")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity")
            .header("cache-control", "no-store")
            .body(())?;
        let (response, mut send) = sender.send_request(request, false)?;
        send.send_data(grpc::encode(data), end)?;
        let response = response.await?;
        ensure!(
            response.status() == StatusCode::OK,
            "gRPC request rejected ({})",
            response.status()
        );
        ensure!(
            response
                .headers()
                .get("content-type")
                .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc")),
            "invalid gRPC response content type"
        );
        ensure!(
            response
                .headers()
                .get("grpc-encoding")
                .is_none_or(|v| v == "identity"),
            "unsupported gRPC encoding"
        );
        if let Some(status) = response.headers().get("grpc-status") {
            ensure!(status == "0", "gRPC request failed ({status:?})");
        }
        let mut stream = H2Stream::new(response.into_body(), send);
        stream.closed = end;
        stream.check_trailers = true;
        stream._driver = Some(connection.driver.clone());
        Ok(GrpcStream::new(stream))
    }

    pub(crate) async fn open_grpc(
        &self,
        connection: &Connection,
        hello: Control,
    ) -> Result<Tunnel> {
        timeout(CONNECT_TIMEOUT, async {
            let mut bytes = Vec::new();
            send_control(&mut bytes, hello).await?;
            Ok(Box::new(
                self.grpc_request(connection, grpc::CONNECT_PATH, &bytes, false)
                    .await?,
            ) as Tunnel)
        })
        .await
        .context("gRPC stream open timed out")?
    }

    pub(crate) async fn download(
        &self,
        connection: &Connection,
        bytes: usize,
        deadline: std::time::Duration,
    ) -> Result<f64> {
        timeout(deadline, async {
            let start = Instant::now();
            let mut stream = self
                .grpc_request(
                    connection,
                    grpc::DOWNLOAD_PATH,
                    &(bytes as u32).to_be_bytes(),
                    true,
                )
                .await?;
            let mut received = 0usize;
            let mut buffer = [0u8; CHUNK];
            loop {
                let n = stream.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                received += n;
                ensure!(received <= bytes, "probe returned excess payload");
            }
            ensure!(received == bytes, "incomplete probe payload");
            Ok(received as f64 * 8.0 / start.elapsed().as_secs_f64() / 1_000_000.0)
        })
        .await
        .context("gRPC download timed out")?
    }
}

fn authorized(request: &Request<RecvStream>, token: &str) -> bool {
    let supplied = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "))
        .unwrap_or_default();
    let valid = bool::from(supplied.ct_eq(token.as_bytes()));
    valid && request.method() == http::Method::POST
}

/// Owns the HTTP connection until closure. All accepted streams are authenticated.
pub async fn serve(
    stream: TcpStream,
    tls: TlsAcceptor,
    token: &str,
    accepted: mpsc::Sender<Tunnel>,
    probes: Option<Arc<Semaphore>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let tls = timeout(CONNECT_TIMEOUT, tls.accept(stream)).await??;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        let service =
            hyper::service::service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("content-type", "text/plain; charset=utf-8")
                        .body(Full::new(Bytes::from_static(NOT_FOUND)))
                        .unwrap(),
                )
            });
        timeout(
            CONNECT_TIMEOUT,
            hyper::server::conn::http1::Builder::new()
                .max_buf_size(8192)
                .serve_connection(TokioIo::new(tls), service),
        )
        .await??;
        return Ok(());
    }
    serve_h2(tls, token, accepted, probes).await
}

// Separate TLS establishment from HTTP/2 dispatch so backpressure and protocol
// failures can also be exercised over deterministic in-memory connections.
async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    token: &str,
    accepted: mpsc::Sender<Tunnel>,
    probes: Option<Arc<Semaphore>>,
) -> Result<()> {
    let mut connection = timeout(
        CONNECT_TIMEOUT,
        h2::server::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_concurrent_streams(MAX_STREAMS)
            .max_header_list_size(8192)
            .max_send_buffer_size(CHUNK)
            .handshake::<_, Bytes>(stream),
    )
    .await??;
    let unauthenticated_deadline = Instant::now() + IDLE_TIMEOUT;
    let mut authenticated = false;
    let mut downloads = JoinSet::new();
    loop {
        // Invalid requests cannot extend the lifetime of an unauthenticated
        // connection. Authorized long-lived streams continue driving DATA.
        let incoming = if authenticated {
            connection.accept().await
        } else {
            timeout_at(unauthenticated_deadline, connection.accept()).await?
        };
        let Some(incoming) = incoming else {
            return Ok(());
        };
        let (request, mut response) = incoming?;
        while downloads.try_join_next().is_some() {}
        let path = request.uri().path();
        let grpc = matches!(path, grpc::CONNECT_PATH | grpc::DOWNLOAD_PATH)
            && request.headers().get("content-type").is_some_and(|v| {
                matches!(
                    v.as_bytes(),
                    b"application/grpc" | b"application/grpc+proto"
                )
            });
        let probe = grpc && path == grpc::DOWNLOAD_PATH;
        let route = path == PATH || (grpc && (!probe || probes.is_some()));
        if !authorized(&request, token) || !route {
            let headers = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "text/plain; charset=utf-8")
                .header("content-length", NOT_FOUND.len())
                .body(())?;
            response
                .send_response(headers, false)?
                .send_data(Bytes::from_static(NOT_FOUND), true)?;
            continue;
        }
        authenticated = true;
        if probe {
            let permit = probes.as_ref().unwrap().clone().try_acquire_owned();
            let headers = Response::builder()
                .header("content-type", "application/grpc+proto")
                .header("cache-control", "no-store")
                .body(())?;
            let mut send = response.send_response(headers, false)?;
            match permit {
                Ok(permit) => {
                    let mut stream = H2Stream::new(request.into_body(), send);
                    stream.grpc_response = true;
                    downloads.spawn(async move {
                        let _permit = permit;
                        let _ = timeout(std::time::Duration::from_secs(60), async {
                            let mut stream = GrpcStream::new(stream);
                            let bytes = stream.read_u32().await? as usize;
                            ensure!(bytes <= 16 * 1024 * 1024, "probe exceeds size limit");
                            let mut extra = [0; 1];
                            ensure!(stream.read(&mut extra).await? == 0, "invalid probe request");
                            let mut block = [0u8; CHUNK];
                            // No compressible zero payload or cached object can inflate a score.
                            {
                                use rand::RngCore;
                                rand::rng().fill_bytes(&mut block);
                            }
                            let mut remaining = bytes;
                            while remaining > 0 {
                                let n = remaining.min(block.len());
                                stream.write_all(&block[..n]).await?;
                                remaining -= n;
                            }
                            stream.shutdown().await?;
                            Ok::<_, anyhow::Error>(())
                        })
                        .await;
                    });
                }
                Err(_) => {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", HeaderValue::from_static("8"));
                    send.send_trailers(trailers)?;
                }
            }
            continue;
        }
        // Never wait for application capacity here: this task drives every stream.
        let Ok(permit) = accepted.try_reserve() else {
            response.send_response(
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(())?,
                true,
            )?;
            continue;
        };
        let send = response.send_response(
            Response::builder()
                .header(
                    "content-type",
                    if grpc {
                        "application/grpc+proto"
                    } else {
                        "application/octet-stream"
                    },
                )
                .body(())?,
            false,
        )?;
        let mut stream = H2Stream::new(request.into_body(), send);
        stream.grpc_response = grpc;
        permit.send(if grpc {
            Box::new(GrpcStream::new(stream)) as Tunnel
        } else {
            Box::new(stream) as Tunnel
        });
    }
}

/// Keep HTTP serving and application dispatch separate so backpressure on one
/// tunnel can never prevent the HTTP/2 driver from processing other streams.
pub async fn dispatch<F, Fut>(
    stream: TcpStream,
    tls: TlsAcceptor,
    token: String,
    probes: Option<Arc<Semaphore>>,
    handler: F,
) -> Result<()>
where
    F: Fn(Tunnel) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel(128);
    let server = serve(stream, tls, &token, tx, probes);
    tokio::pin!(server);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = &mut server => return result,
            Some(stream) = rx.recv() => { tasks.spawn(handler(stream)); }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

#[cfg(test)]
#[path = "tests/https_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "tests/https.rs"]
mod tests;
