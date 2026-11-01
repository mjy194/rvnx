use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use rvnx_common::{
    config::{self, Protocol, ServerConfig, ServerProxy},
    https::{self, Tunnel},
    protocol::{Control, Frame, MAX_DATAGRAM, POLICY_VERSION, VERSION, read_control, send_control},
    transport::{CONNECT_TIMEOUT, heartbeat_delay, queue, server_tls, spawn_reader, spawn_writer},
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, interval, sleep, timeout, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

type Tickets = Arc<Mutex<HashMap<String, Ticket>>>;

struct Ticket {
    deadline: Instant,
    scope: MappingScope,
    sender: oneshot::Sender<Tunnel>,
}
#[derive(Clone)]
struct MappingScope {
    owner: usize,
    id: u64,
    active: Arc<AtomicBool>,
}
struct Allocation {
    scope: MappingScope,
    protocol: Protocol,
    bind: SocketAddr,
}
#[derive(Default)]
struct Registry {
    next_id: u64,
    entries: HashMap<(usize, String), Allocation>,
}
impl Registry {
    fn reserve(
        &mut self,
        owner: usize,
        mapping: &ServerProxy,
        policy: bool,
        quota: usize,
    ) -> std::result::Result<MappingScope, &'static str> {
        let key = (
            if policy { owner } else { usize::MAX },
            mapping.name.clone(),
        );
        if self.entries.contains_key(&key) {
            return Err("name_in_use");
        }
        if self
            .entries
            .values()
            .any(|a| a.protocol == mapping.protocol && a.bind == mapping.bind)
        {
            return Err("port_in_use");
        }
        if policy
            && self
                .entries
                .values()
                .filter(|a| a.scope.owner == owner)
                .count()
                >= quota
        {
            return Err("quota_exceeded");
        }
        self.next_id = self.next_id.checked_add(1).ok_or("capacity_exhausted")?;
        let scope = MappingScope {
            owner,
            id: self.next_id,
            active: Arc::new(AtomicBool::new(true)),
        };
        self.entries.insert(
            key,
            Allocation {
                scope: scope.clone(),
                protocol: mapping.protocol,
                bind: mapping.bind,
            },
        );
        Ok(scope)
    }
}

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
    active: Mutex<Registry>,
    tickets: Tickets,
}

struct Registration {
    state: Arc<State>,
    name: String,
    scope: MappingScope,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.scope.active.store(false, Ordering::SeqCst);
        self.state
            .tickets
            .lock()
            .unwrap()
            .retain(|_, ticket| ticket.scope.id != self.scope.id);
        self.state
            .active
            .lock()
            .unwrap()
            .entries
            .retain(|_, allocation| allocation.scope.id != self.scope.id);
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
        active: Mutex::new(Registry::default()),
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
    let tokens = state.config.auth_tokens();
    https::dispatch(stream, tls, &tokens, state.probes.clone(), move |tunnel| {
        let state = handler_state.clone();
        async move {
            if let Err(error) = handle_tunnel(tunnel.tunnel, state, tunnel.identity).await {
                debug!(%error, "authenticated tunnel ended");
            }
        }
    })
    .await
}

async fn mapping_error(
    tunnel: &mut Tunnel,
    mapping: &ServerProxy,
    code: &str,
    reason: &str,
) -> Result<()> {
    let _ = timeout(
        CONNECT_TIMEOUT,
        send_control(
            tunnel,
            Control::MappingError {
                proxy: mapping.name.clone(),
                protocol: mapping.protocol,
                remote_port: mapping.bind.port(),
                code: code.into(),
                reason: reason.into(),
            },
        ),
    )
    .await;
    bail!("{code}: {reason}")
}

async fn handle_tunnel(mut tunnel: Tunnel, state: Arc<State>, owner: usize) -> Result<()> {
    let mut hello = timeout(CONNECT_TIMEOUT, read_control(&mut tunnel)).await??;
    let policy_mode = state.config.is_policy_mode();
    let mut fetched = false;
    if let Control::GetPolicy { version } = hello {
        if !policy_mode || version != POLICY_VERSION {
            return reject(&mut tunnel, "unsupported policy mode or protocol version").await;
        }
        let policy = &state.config.policies.as_ref().unwrap()[owner].policy;
        timeout(
            CONNECT_TIMEOUT,
            send_control(
                &mut tunnel,
                Control::Policy {
                    version: POLICY_VERSION,
                    policy: policy.clone(),
                },
            ),
        )
        .await??;
        fetched = true;
        hello = timeout(CONNECT_TIMEOUT, read_control(&mut tunnel)).await??;
    }
    match hello {
        Control::Attach { ticket } => {
            // Check ownership BEFORE consuming; a foreign request must not burn a ticket.
            let entry = {
                let mut tickets = state.tickets.lock().unwrap();
                if tickets.get(&ticket).is_some_and(|t| {
                    t.scope.owner == owner
                        && t.scope.active.load(Ordering::SeqCst)
                        && Instant::now() < t.deadline
                }) {
                    tickets.remove(&ticket)
                } else {
                    None
                }
            };
            let Some(entry) = entry else {
                return reject(&mut tunnel, "invalid or expired ticket").await;
            };
            timeout_at(entry.deadline, send_control(&mut tunnel, Control::Ready)).await??;
            ensure!(
                Instant::now() < entry.deadline && entry.scope.active.load(Ordering::SeqCst),
                "data tunnel establishment expired"
            );
            ensure!(
                entry.sender.send(tunnel).is_ok(),
                "public connection already closed"
            );
            Ok(())
        }
        Control::Register {
            version,
            proxy,
            protocol,
        } if !policy_mode => {
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
            let reservation =
                state
                    .active
                    .lock()
                    .unwrap()
                    .reserve(owner, &mapping, false, usize::MAX);
            let Ok(scope) = reservation else {
                return reject(&mut tunnel, "proxy is already connected").await;
            };
            let _registration = Registration {
                state: state.clone(),
                name: proxy,
                scope: scope.clone(),
            };
            match mapping.protocol {
                Protocol::Tcp => {
                    serve_tcp(tunnel, mapping, state.tickets.clone(), scope, false).await
                }
                Protocol::Udp => serve_udp(tunnel, mapping, false).await,
            }
        }
        Control::RegisterPolicy {
            version,
            proxy,
            protocol,
            remote_port,
        } => {
            let policy = state
                .config
                .policies
                .as_ref()
                .and_then(|p| p.get(owner))
                .map(|p| &p.policy);
            let mapping = ServerProxy {
                name: proxy,
                protocol,
                bind: SocketAddr::new(
                    policy.map_or(state.config.bind.ip(), |p| p.bind_ip),
                    remote_port,
                ),
                connection_wait_secs: state.config.connection_wait_secs,
                max_connections: 128,
                udp_timeout_secs: 60,
            };
            if !policy_mode || version != POLICY_VERSION || !fetched {
                return mapping_error(
                    &mut tunnel,
                    &mapping,
                    "mode_mismatch",
                    "fetch policy v3 before registering",
                )
                .await;
            }
            let policy = policy.unwrap();
            if let Err(error) = policy.validate_mapping(&mapping.name, &protocol, remote_port) {
                return mapping_error(&mut tunnel, &mapping, "policy_denied", &error.to_string())
                    .await;
            }
            if protocol == Protocol::Tcp && mapping.bind == state.config.bind {
                return mapping_error(
                    &mut tunnel,
                    &mapping,
                    "port_in_use",
                    "port conflicts with control listener",
                )
                .await;
            }
            let reservation =
                state
                    .active
                    .lock()
                    .unwrap()
                    .reserve(owner, &mapping, true, policy.max_mappings);
            let scope = match reservation {
                Ok(scope) => scope,
                Err(code) => {
                    return mapping_error(
                        &mut tunnel,
                        &mapping,
                        code,
                        "mapping name, port or quota is unavailable",
                    )
                    .await;
                }
            };
            let _registration = Registration {
                state: state.clone(),
                name: mapping.name.clone(),
                scope: scope.clone(),
            };
            match protocol {
                Protocol::Tcp => {
                    serve_tcp(tunnel, mapping, state.tickets.clone(), scope, true).await
                }
                Protocol::Udp => serve_udp(tunnel, mapping, true).await,
            }
        }
        _ => {
            reject(
                &mut tunnel,
                "expected register or attach; protocol mode mismatch",
            )
            .await
        }
    }
}

fn ready(mapping: &ServerProxy, policy: bool) -> Control {
    if policy {
        Control::Registered {
            proxy: mapping.name.clone(),
            protocol: mapping.protocol,
            remote_port: mapping.bind.port(),
        }
    } else {
        Control::Ready
    }
}

async fn serve_tcp(
    mut tunnel: Tunnel,
    mapping: ServerProxy,
    tickets: Tickets,
    scope: MappingScope,
    policy: bool,
) -> Result<()> {
    let listener = match TcpListener::bind(mapping.bind).await {
        Ok(listener) => listener,
        Err(_) => {
            return if policy {
                mapping_error(
                    &mut tunnel,
                    &mapping,
                    "bind_failed",
                    "cannot bind requested TCP port",
                )
                .await
            } else {
                reject(&mut tunnel, "cannot bind configured TCP port").await
            };
        }
    };
    timeout(
        CONNECT_TIMEOUT,
        send_control(&mut tunnel, ready(&mapping, policy)),
    )
    .await??;
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
                let deadline = Instant::now() + Duration::from_secs(mapping.connection_wait_secs);
                if transfers.len() >= mapping.max_connections {
                    debug!(%peer, "TCP mapping connection limit reached");
                    continue;
                }
                let tickets = tickets.clone();
                let scope = scope.clone();
                let tx = tx.clone();
                transfers.spawn(async move {
                    if let Err(error) = forward_tcp(stream, tickets, tx, deadline, scope, policy).await {
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
                    Frame::Control(Control::Cancel { ticket }) => {
                        let mut entries = tickets.lock().unwrap();
                        if entries.get(&ticket).is_some_and(|t| t.scope.id == scope.id && t.scope.owner == scope.owner) { entries.remove(&ticket); }
                    }
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
    deadline: Instant,
    scope: MappingScope,
    policy: bool,
) -> Result<()> {
    public.set_nodelay(true)?;
    let ticket: String = rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let (sender, receiver) = oneshot::channel();
    {
        let mut entries = tickets.lock().unwrap();
        ensure!(scope.active.load(Ordering::SeqCst), "mapping closed");
        ensure!(
            Instant::now() < deadline,
            "data tunnel establishment timed out"
        );
        entries.insert(
            ticket.clone(),
            Ticket {
                scope,
                sender,
                deadline,
            },
        );
    }
    let _ticket_guard = TicketGuard {
        tickets,
        ticket: ticket.clone(),
    };
    let setup = timeout_at(deadline, async {
        // Reserve queue capacity before measuring remaining time: queue delay is
        // part of the server's budget, never a fresh per-stage timeout.
        let permit = tx.reserve().await.context("control writer closed")?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            remaining.as_millis() > 0,
            "data tunnel establishment timed out"
        );
        permit.send(Frame::Control(Control::Open {
            ticket: ticket.clone(),
            timeout_ms: policy.then_some(remaining.as_millis().min(u64::MAX as u128) as u64),
        }));
        receiver.await.context("data tunnel cancelled")
    })
    .await;
    let mut tunnel = match setup {
        Ok(Ok(tunnel)) if Instant::now() < deadline => tunnel,
        result => {
            // Never await cancellation delivery past the authoritative deadline.
            // The client's local budget remains the backstop if this queue is full.
            if policy {
                let _ = tx.try_send(Frame::Control(Control::Cancel { ticket }));
            }
            return match result {
                Ok(Err(error)) => Err(error),
                _ => Err(anyhow::anyhow!("data tunnel establishment timed out")),
            };
        }
    };
    let (upload, download) = copy_bidirectional(&mut public, &mut tunnel).await?;
    debug!(upload, download, "TCP transfer complete");
    Ok(())
}

async fn serve_udp(mut tunnel: Tunnel, mapping: ServerProxy, policy: bool) -> Result<()> {
    let socket = match UdpSocket::bind(mapping.bind).await {
        Ok(socket) => socket,
        Err(_) => {
            return if policy {
                mapping_error(
                    &mut tunnel,
                    &mapping,
                    "bind_failed",
                    "cannot bind requested UDP port",
                )
                .await
            } else {
                reject(&mut tunnel, "cannot bind configured UDP port").await
            };
        }
    };
    serve_udp_socket(tunnel, mapping, socket, policy).await
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
    policy: bool,
) -> Result<()> {
    timeout(
        CONNECT_TIMEOUT,
        send_control(&mut tunnel, ready(&mapping, policy)),
    )
    .await??;
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

#[cfg(test)]
#[path = "tests/policy.rs"]
mod policy_tests;

#[cfg(test)]
#[path = "tests/budget.rs"]
mod budget_tests;
