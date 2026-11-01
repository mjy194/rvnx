use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use rvnx_common::{
    config::{self, Protocol, ServerConfig, ServerProxy},
    https::{self, Tunnel},
    protocol::{Control, Frame, MAX_DATAGRAM, VERSION, read_control, send_control},
    transport::{CONNECT_TIMEOUT, heartbeat_delay, queue, server_tls, spawn_reader, spawn_writer},
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, interval, sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

type Tickets = Arc<Mutex<HashMap<String, oneshot::Sender<Tunnel>>>>;

#[derive(Parser)]
#[command(version, about = "RVNX — Veils Network eXposure server")]
struct Args {
    #[arg(short, long, default_value = "srv.toml")]
    config: PathBuf,
    /// Validate configuration and TLS files, then exit.
    #[arg(long)]
    check: bool,
}

struct State {
    config: ServerConfig,
    probes: Option<Arc<Semaphore>>,
    active: Mutex<HashSet<String>>,
    tickets: Tickets,
}

struct Registration {
    state: Arc<State>,
    name: String,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.state.active.lock().unwrap().remove(&self.name);
        info!(proxy = %self.name, "mapping disconnected");
    }
}

struct TicketGuard {
    tickets: Tickets,
    ticket: String,
}

impl Drop for TicketGuard {
    fn drop(&mut self) {
        self.tickets.lock().unwrap().remove(&self.ticket);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rvnx_common::init_logging();
    let args = Args::parse();
    let config: ServerConfig = config::load(&args.config)?;
    config.validate()?;
    let tls = server_tls(&config.tls_cert, &config.tls_key).context("TLS configuration failed")?;
    if args.check {
        info!("configuration is valid");
        return Ok(());
    }
    let listener = TcpListener::bind(config.bind).await?;
    info!(bind = %config.bind, "RVNX server listening (HTTPS)");
    let state = Arc::new(State {
        probes: config.cf_probe_enabled.then(|| Arc::new(Semaphore::new(4))),
        config,
        active: Mutex::new(HashSet::new()),
        tickets: Arc::new(Mutex::new(HashMap::new())),
    });
    let limit = Arc::new(Semaphore::new(512));
    let mut connections = JoinSet::new();
    // Keep one signal subscription alive across accepts/completions. Recreating
    // ctrl_c() in each select can lose a signal between receiver lifetimes.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { warn!(%error, "connection task failed"); }
            }
            incoming = listener.accept() => {
                let (stream, peer) = incoming?;
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    debug!(%peer, "connection limit reached");
                    continue;
                };
                let state = state.clone();
                let tls = tls.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(stream, tls, state).await {
                        debug!(%peer, error = %format!("{error:#}"), "connection ended");
                    }
                });
            }
        }
    }
    connections.shutdown().await;
    info!("RVNX server stopped");
    Ok(())
}

async fn reject(stream: &mut Tunnel, message: &str) -> Result<()> {
    let _ = timeout(
        CONNECT_TIMEOUT,
        send_control(
            stream,
            Control::Error {
                message: message.into(),
            },
        ),
    )
    .await;
    bail!("{message}")
}

async fn handle_connection(stream: TcpStream, tls: TlsAcceptor, state: Arc<State>) -> Result<()> {
    let handler_state = state.clone();
    https::dispatch(
        stream,
        tls,
        state.config.auth_tokens(),
        state.probes.clone(),
        move |tunnel| {
            let state = handler_state.clone();
            async move {
                if let Err(error) = handle_tunnel(tunnel, state).await {
                    debug!(%error, "authenticated tunnel ended");
                }
            }
        },
    )
    .await
}

async fn handle_tunnel(mut tunnel: Tunnel, state: Arc<State>) -> Result<()> {
    let hello = timeout(CONNECT_TIMEOUT, read_control(&mut tunnel)).await??;
    match hello {
        Control::Attach { ticket } => {
            let sender = state.tickets.lock().unwrap().remove(&ticket);
            let Some(sender) = sender else {
                return reject(&mut tunnel, "invalid or expired ticket").await;
            };
            timeout(CONNECT_TIMEOUT, send_control(&mut tunnel, Control::Ready)).await??;
            ensure!(
                sender.send(tunnel).is_ok(),
                "public connection already closed"
            );
            Ok(())
        }
        Control::Register {
            version,
            proxy,
            protocol,
        } => {
            if version != VERSION {
                return reject(&mut tunnel, "unsupported protocol version").await;
            }
            let Some(mapping) = state
                .config
                .proxies
                .iter()
                .find(|p| p.name == proxy)
                .cloned()
            else {
                return reject(&mut tunnel, "proxy is not configured on server").await;
            };
            let expected = match mapping.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };
            if protocol != expected {
                return reject(&mut tunnel, "proxy protocol mismatch").await;
            }
            let registered = state.active.lock().unwrap().insert(proxy.clone());
            if !registered {
                return reject(&mut tunnel, "proxy is already connected").await;
            }
            let _registration = Registration {
                state: state.clone(),
                name: proxy,
            };
            match mapping.protocol {
                Protocol::Tcp => serve_tcp(tunnel, mapping, state.tickets.clone()).await,
                Protocol::Udp => serve_udp(tunnel, mapping).await,
            }
        }
        _ => reject(&mut tunnel, "expected register or attach").await,
    }
}

async fn serve_tcp(mut tunnel: Tunnel, mapping: ServerProxy, tickets: Tickets) -> Result<()> {
    let listener = match TcpListener::bind(mapping.bind).await {
        Ok(listener) => listener,
        Err(_) => return reject(&mut tunnel, "cannot bind configured TCP port").await,
    };
    timeout(CONNECT_TIMEOUT, send_control(&mut tunnel, Control::Ready)).await??;
    info!(proxy = %mapping.name, bind = %mapping.bind, "TCP mapping ready");
    let (reader, writer) = tokio::io::split(tunnel);
    let (mut rx, _reader_task) = spawn_reader(reader);
    let (tx, _writer_task) = spawn_writer(writer);
    let heartbeat = sleep(heartbeat_delay());
    tokio::pin!(heartbeat);
    let mut transfers = JoinSet::new();
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (stream, peer) = incoming?;
                if transfers.len() >= mapping.max_connections {
                    debug!(%peer, "TCP mapping connection limit reached");
                    continue;
                }
                let tickets = tickets.clone();
                let tx = tx.clone();
                transfers.spawn(async move {
                    if let Err(error) = forward_tcp(stream, tickets, tx, Duration::from_secs(mapping.connection_wait_secs)).await {
                        debug!(%peer, error = %format!("{error:#}"), "TCP transfer ended");
                    }
                });
            }
            Some(result) = transfers.join_next(), if !transfers.is_empty() => {
                if let Err(error) = result { debug!(%error, "TCP transfer task failed"); }
            }
            frame = rx.recv() => {
                match frame.context("tunnel reader closed")?? {
                    Frame::Control(Control::Ping) => queue(&tx, Frame::Control(Control::Pong)).await?,
                    Frame::Control(Control::Pong) => {}
                    Frame::Control(Control::Cancel { ticket }) => { tickets.lock().unwrap().remove(&ticket); }
                    _ => bail!("unexpected TCP control frame"),
                }
            }
            _ = &mut heartbeat => {
                queue(&tx, Frame::Control(Control::Ping)).await?;
                heartbeat.as_mut().reset(Instant::now() + heartbeat_delay());
            },
        }
    }
}

async fn forward_tcp(
    mut public: TcpStream,
    tickets: Tickets,
    tx: mpsc::Sender<Frame>,
    wait: Duration,
) -> Result<()> {
    public.set_nodelay(true)?;
    let ticket: String = rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let (sender, receiver) = oneshot::channel();
    tickets.lock().unwrap().insert(ticket.clone(), sender);
    let _ticket_guard = TicketGuard {
        tickets,
        ticket: ticket.clone(),
    };
    queue(&tx, Frame::Control(Control::Open { ticket })).await?;
    let mut tunnel = timeout(wait, receiver)
        .await
        .context("data tunnel timed out")??;
    let (upload, download) = copy_bidirectional(&mut public, &mut tunnel).await?;
    debug!(upload, download, "TCP transfer complete");
    Ok(())
}

async fn serve_udp(mut tunnel: Tunnel, mapping: ServerProxy) -> Result<()> {
    let socket = match UdpSocket::bind(mapping.bind).await {
        Ok(socket) => socket,
        Err(_) => return reject(&mut tunnel, "cannot bind configured UDP port").await,
    };
    serve_udp_socket(tunnel, mapping, socket).await
}

trait DatagramSocket: Send {
    fn recv_from(
        &self,
        data: &mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send;
    fn send_to(
        &self,
        data: &[u8],
        address: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
}
impl DatagramSocket for UdpSocket {
    async fn recv_from(&self, data: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.recv_from(data).await
    }
    async fn send_to(&self, data: &[u8], address: SocketAddr) -> std::io::Result<usize> {
        self.send_to(data, address).await
    }
}
async fn serve_udp_socket<S: DatagramSocket>(
    mut tunnel: Tunnel,
    mapping: ServerProxy,
    socket: S,
) -> Result<()> {
    timeout(CONNECT_TIMEOUT, send_control(&mut tunnel, Control::Ready)).await??;
    info!(proxy = %mapping.name, bind = %mapping.bind, "UDP mapping ready");
    let (reader, writer) = tokio::io::split(tunnel);
    let (mut rx, _reader_task) = spawn_reader(reader);
    let (tx, _writer_task) = spawn_writer(writer);
    let heartbeat = sleep(heartbeat_delay());
    tokio::pin!(heartbeat);
    let mut cleanup = interval(Duration::from_secs(1));
    let mut by_addr = HashMap::<SocketAddr, u64>::new();
    let mut peers = HashMap::<u64, (SocketAddr, Instant)>::new();
    let mut next_peer = 0u64;
    let expiry = Duration::from_secs(mapping.udp_timeout_secs);
    let mut buffer = vec![0; MAX_DATAGRAM + 1];
    loop {
        tokio::select! {
            packet = socket.recv_from(&mut buffer) => {
                let (len, address) = packet?;
                if len > MAX_DATAGRAM { continue; }
                let peer = if let Some(&peer) = by_addr.get(&address) { peer } else {
                    if peers.len() >= mapping.max_connections { continue; }
                    next_peer = next_peer.checked_add(1).context("UDP peer IDs exhausted")?;
                    by_addr.insert(address, next_peer);
                    peers.insert(next_peer, (address, Instant::now()));
                    next_peer
                };
                peers.get_mut(&peer).unwrap().1 = Instant::now();
                match tx.try_send(Frame::Datagram { peer, data: buffer[..len].to_vec() }) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => bail!("tunnel writer closed"),
                }
            }
            frame = rx.recv() => {
                match frame.context("tunnel reader closed")?? {
                    Frame::Datagram { peer, data } => {
                        if let Some((address, last_active)) = peers.get_mut(&peer) {
                            *last_active = Instant::now();
                            if let Err(error) = socket.send_to(&data, *address).await {
                                debug!(%error, "UDP response dropped");
                            }
                        }
                    }
                    Frame::Control(Control::Ping) => queue(&tx, Frame::Control(Control::Pong)).await?,
                    Frame::Control(Control::Pong) => {}
                    _ => bail!("unexpected UDP control frame"),
                }
            }
            _ = cleanup.tick() => {
                peers.retain(|_, (address, last_active)| {
                    if last_active.elapsed() >= expiry { by_addr.remove(address); false } else { true }
                });
            }
            _ = &mut heartbeat => {
                queue(&tx, Frame::Control(Control::Ping)).await?;
                heartbeat.as_mut().reset(Instant::now() + heartbeat_delay());
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;
