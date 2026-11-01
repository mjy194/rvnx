use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rvnx_common::{
    cloudflare::{CfTransport, ClientTransport},
    config::{self, ClientConfig, ClientProxy, Protocol},
    https::{AuthenticationRejected, HttpsTransport, Tunnel},
    protocol::{Control, Frame, MAX_DATAGRAM, POLICY_VERSION, VERSION, read_control, send_control},
    transport::{CONNECT_TIMEOUT, client_tls, heartbeat_delay, queue, spawn_reader, spawn_writer},
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpStream, UdpSocket, lookup_host},
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::{Instant, sleep, timeout, timeout_at},
};
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(version, about = "RVNX — Veils Network eXposure client")]
struct Args {
    #[arg(short, long, default_value = "clnt.toml")]
    config: PathBuf,
    /// Validate configuration and TLS files, then exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rvnx_common::init_logging();
    let args = Args::parse();
    let config: ClientConfig = config::load(&args.config)?;
    config.validate()?;
    let tls = client_tls(&config.tls_ca).context("TLS configuration failed")?;
    // Validate the name even with --check, before starting reconnect loops.
    tokio_rustls::rustls::pki_types::ServerName::try_from(config.server_name.clone())?;
    if args.check {
        info!("configuration is valid");
        return Ok(());
    }
    let make_transport = |size| -> Result<Arc<ClientTransport>> {
        Ok(Arc::new(ClientTransport::Direct(HttpsTransport::new(
            tls.clone(),
            config.server.clone(),
            config.server_name.clone(),
            &config.token,
            size,
        )?)))
    };
    let cf = config
        .cloudflare
        .clone()
        .map(|cf| -> Result<_> {
            let endpoint = HttpsTransport::new(
                tls.clone(),
                config.server.clone(),
                config.server_name.clone(),
                &config.token,
                None,
            )?;
            let transport = if config.policy_mode {
                CfTransport::new_policy(endpoint, cf)?
            } else {
                CfTransport::new(endpoint, cf)?
            };
            Ok(Arc::new(ClientTransport::Cloudflare(transport)))
        })
        .transpose()?;
    let mut pools = Vec::new();
    let shared = if config
        .proxies
        .iter()
        .any(|p| config.multiplex_for(p) && p.dedicated_pool_size.is_none())
    {
        let pool = make_transport(Some(config.pool_size))?;
        pools.push(pool.clone());
        Some(pool)
    } else {
        None
    };
    let mut assignments = Vec::new();
    for proxy in config.proxies.clone() {
        let pool = if let Some(cf) = &cf {
            cf.clone()
        } else if !config.multiplex_for(&proxy) {
            make_transport(None)?
        } else if let Some(size) = proxy.dedicated_pool_size {
            let pool = make_transport(Some(size))?;
            pools.push(pool.clone());
            pool
        } else {
            shared.as_ref().unwrap().clone()
        };
        assignments.push((proxy, pool));
    }
    // Warm independent pools concurrently so one mapping does not serialize
    // another mapping's startup. JoinSet also owns cancellation on shutdown.
    let mut warmups = JoinSet::new();
    for pool in pools {
        warmups.spawn(async move {
            if let Err(error) = pool.warm().await {
                warn!(%error, "pool warm-up failed; mappings will retry");
            }
        });
    }
    while let Some(result) = warmups.join_next().await {
        result?;
    }
    let config = Arc::new(config);
    let mut mappings = JoinSet::new();
    for (proxy, pool) in assignments {
        let config = config.clone();
        mappings.spawn(async move {
            loop {
                if let Err(error) = run_mapping(&proxy, &pool, config.policy_mode).await {
                    if config.policy_mode && terminal_mapping_error(&error) {
                        let (code, reason) = if let Some(error) = error.downcast_ref::<TerminalMappingError>() {
                            (error.code.as_str(), error.reason.as_str())
                        } else {
                            ("authentication_rejected", "server rejected authentication")
                        };
                        warn!(proxy = %proxy.name, protocol = ?proxy.protocol, remote_port = proxy.remote_port, code, reason, "mapping stopped; configuration must be corrected");
                        return;
                    }
                    warn!(proxy = %proxy.name, error = %format!("{error:#}"), "mapping disconnected; reconnecting");
                }
                sleep(Duration::from_secs(config.reconnect_secs)).await;
            }
        });
    }
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            result = mappings.join_next(), if !mappings.is_empty() => {
                if let Some(Err(error)) = result {
                    warn!(%error, "mapping worker stopped unexpectedly; other mappings remain active");
                }
                if mappings.is_empty() {
                    bail!("all mapping workers stopped; correct configuration and restart");
                }
            }
        }
    }
    mappings.shutdown().await;
    info!("RVNX client stopped");
    Ok(())
}

async fn expect_ready<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    match read_control(reader).await? {
        Control::Ready => Ok(()),
        Control::Error { message } => bail!("server rejected request: {message}"),
        _ => bail!("unexpected server handshake response"),
    }
}

#[derive(Debug)]
struct TerminalMappingError {
    code: String,
    reason: String,
}
impl std::fmt::Display for TerminalMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}
impl std::error::Error for TerminalMappingError {}
fn terminal(code: &str, reason: impl Into<String>) -> anyhow::Error {
    TerminalMappingError {
        code: code.into(),
        reason: reason.into(),
    }
    .into()
}
fn terminal_mapping_error(error: &anyhow::Error) -> bool {
    error.is::<TerminalMappingError>() || error.is::<AuthenticationRejected>()
}

async fn read_policy_control<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Control> {
    read_control(reader).await.map_err(|error| {
        if error.is::<std::io::Error>() {
            error
        } else {
            terminal("protocol_mismatch", error.to_string())
        }
    })
}

// The policy lives only within this handshake and is fetched anew after every reconnect.
async fn policy_handshake<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    tunnel: &mut S,
    proxy: &ClientProxy,
) -> Result<()> {
    let remote_port = proxy
        .remote_port
        .ok_or_else(|| terminal("invalid_config", "remote_port is required"))?;
    let policy = match read_policy_control(tunnel).await? {
        Control::Policy {
            version: POLICY_VERSION,
            policy,
        } => policy,
        Control::Error { message } => return Err(terminal("policy_rejected", message)),
        _ => {
            return Err(terminal(
                "protocol_mismatch",
                "expected policy protocol version 3",
            ));
        }
    };
    policy
        .validate()
        .map_err(|error| terminal("invalid_policy", error.to_string()))?;
    policy
        .validate_mapping(&proxy.name, &proxy.protocol, remote_port)
        .map_err(|error| terminal("policy_denied", error.to_string()))?;
    send_control(
        tunnel,
        Control::RegisterPolicy {
            version: POLICY_VERSION,
            proxy: proxy.name.clone(),
            protocol: proxy.protocol,
            remote_port,
        },
    )
    .await?;
    match read_policy_control(tunnel).await? {
        Control::Registered {
            proxy: name,
            protocol,
            remote_port: port,
        } if name == proxy.name && protocol == proxy.protocol && port == remote_port => Ok(()),
        Control::MappingError {
            proxy: name,
            protocol,
            remote_port: port,
            code,
            reason,
        } if name == proxy.name && protocol == proxy.protocol && port == remote_port => {
            Err(terminal(&code, reason))
        }
        Control::Error { message } => Err(terminal("registration_rejected", message)),
        _ => Err(terminal(
            "protocol_mismatch",
            "registration response does not match requested mapping",
        )),
    }
}

async fn run_mapping(
    proxy: &ClientProxy,
    pool: &Arc<ClientTransport>,
    policy_mode: bool,
) -> Result<()> {
    let udp_target = if proxy.protocol == Protocol::Udp {
        Some(
            timeout(CONNECT_TIMEOUT, lookup_host(&proxy.local))
                .await??
                .next()
                .context("local UDP address resolved to no addresses")?,
        )
    } else {
        None
    };
    let hello = if policy_mode {
        Control::GetPolicy {
            version: POLICY_VERSION,
        }
    } else {
        Control::Register {
            version: VERSION,
            proxy: proxy.name.clone(),
            protocol: match proxy.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            }
            .into(),
        }
    };
    let mut tunnel = pool.open(hello).await?;
    if policy_mode {
        timeout(CONNECT_TIMEOUT, policy_handshake(&mut tunnel, proxy)).await??;
    } else {
        timeout(CONNECT_TIMEOUT, expect_ready(&mut tunnel)).await??;
    }
    info!(proxy = %proxy.name, local = %proxy.local, "mapping connected");
    run_session(proxy, pool.clone(), tunnel, udp_target, policy_mode).await
}

// Static dispatch lets tests inject transfer failures and panics while running
// the same session loop; the production path retains its concrete transport.
trait MappingBackend: Send + Sync + 'static {
    fn tcp(
        &self,
        local: &str,
        ticket: String,
        deadline: Option<Instant>,
        cancelled: Option<oneshot::Receiver<()>>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn udp(
        &self,
        peer: u64,
        target: SocketAddr,
        expiry: Duration,
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Frame>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}
impl MappingBackend for ClientTransport {
    async fn tcp(
        &self,
        local: &str,
        ticket: String,
        deadline: Option<Instant>,
        cancelled: Option<oneshot::Receiver<()>>,
    ) -> Result<()> {
        forward_tcp(self, local, ticket, deadline, cancelled).await
    }
    async fn udp(
        &self,
        peer: u64,
        target: SocketAddr,
        expiry: Duration,
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Frame>,
    ) -> Result<()> {
        forward_udp(peer, target, expiry, rx, tx).await
    }
}
enum TransferDone {
    Tcp(String),
    Udp(u64),
}

// A failed policy setup must release its slot immediately, not start another
// queue timeout. Server expiry and the peer's local budget are the backstops.
async fn cancel_transfer(
    tx: &mpsc::Sender<Frame>,
    ticket: String,
    policy_mode: bool,
) -> Result<()> {
    let frame = Frame::Control(Control::Cancel { ticket });
    if policy_mode {
        match tx.try_send(frame) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => bail!("control writer closed"),
        }
    } else {
        queue(tx, frame).await
    }
}

async fn run_session<B: MappingBackend>(
    proxy: &ClientProxy,
    pool: Arc<B>,
    tunnel: Tunnel,
    udp_target: Option<SocketAddr>,
    policy_mode: bool,
) -> Result<()> {
    let (reader, writer) = tokio::io::split(tunnel);
    let (mut rx, _reader_task) = spawn_reader(reader);
    let (tx, _writer_task) = spawn_writer(writer);
    let heartbeat = sleep(heartbeat_delay());
    tokio::pin!(heartbeat);
    let mut transfers = JoinSet::new();
    let mut udp_peers = HashMap::<u64, mpsc::Sender<Vec<u8>>>::new();
    let mut pending = HashMap::<String, oneshot::Sender<()>>::new();
    loop {
        tokio::select! {
            frame = rx.recv() => {
                match frame.context("tunnel reader closed")?? {
                    Frame::Control(Control::Ping) => queue(&tx, Frame::Control(Control::Pong)).await?,
                    Frame::Control(Control::Pong) => {}
                    Frame::Control(Control::Open { ticket, timeout_ms }) if proxy.protocol == Protocol::Tcp => {
                        let deadline = if policy_mode {
                            let budget = timeout_ms.ok_or_else(|| terminal("protocol_mismatch", "policy Open is missing timeout_ms"))?;
                            if budget > 600_000 { return Err(terminal("protocol_mismatch", "establishment budget exceeds server limit")); }
                            Some(Instant::now().checked_add(Duration::from_millis(budget))
                                .ok_or_else(|| terminal("protocol_mismatch", "invalid establishment budget"))?)
                        } else { None };
                        if transfers.len() >= proxy.max_connections {
                            debug!(proxy = %proxy.name, "local TCP connection limit reached");
                            cancel_transfer(&tx, ticket, policy_mode).await?;
                            continue;
                        }
                        let cancelled = if policy_mode {
                            let (sender, receiver) = oneshot::channel();
                            if pending.insert(ticket.clone(), sender).is_some() {
                                return Err(terminal("protocol_mismatch", "duplicate TCP ticket"));
                            }
                            Some(receiver)
                        } else { None };
                        let pool = pool.clone();
                        let local = proxy.local.clone();
                        let failures = tx.clone();
                        transfers.spawn(async move {
                            if let Err(error) = pool.tcp(&local, ticket.clone(), deadline, cancelled).await {
                                debug!(error = %format!("{error:#}"), "TCP transfer ended");
                                let _ = cancel_transfer(&failures, ticket.clone(), policy_mode).await;
                            }
                            TransferDone::Tcp(ticket)
                        });
                    }
                    Frame::Control(Control::Cancel { ticket }) if policy_mode && proxy.protocol == Protocol::Tcp => {
                        if let Some(cancelled) = pending.remove(&ticket) {
                            let _ = cancelled.send(());
                        }
                    }
                    Frame::Datagram { peer, data } if proxy.protocol == Protocol::Udp => {
                        if let Some(sender) = udp_peers.get(&peer) {
                            // UDP remains lossy under pressure; never stall all peers.
                            let _ = sender.try_send(data);
                        } else {
                            if transfers.len() >= proxy.max_connections { continue; }
                            let (sender, receiver) = mpsc::channel(64);
                            sender.try_send(data)?;
                            udp_peers.insert(peer, sender);
                            let tx = tx.clone();
                            let target = udp_target.unwrap();
                            let expiry = Duration::from_secs(proxy.udp_timeout_secs);
                            let pool = pool.clone();
                            transfers.spawn(async move {
                                if let Err(error) = pool.udp(peer, target, expiry, receiver, tx).await {
                                    debug!(%peer, %error, "UDP peer ended");
                                }
                                TransferDone::Udp(peer)
                            });
                        }
                    }
                    _ => bail!("unexpected tunnel frame"),
                }
            }
            Some(result) = transfers.join_next(), if !transfers.is_empty() => {
                match result {
                    Ok(TransferDone::Udp(peer)) => { udp_peers.remove(&peer); }
                    Ok(TransferDone::Tcp(ticket)) => { pending.remove(&ticket); }
                    Err(error) => bail!("transfer worker failed: {error}"),
                }
            }
            _ = &mut heartbeat => {
                queue(&tx, Frame::Control(Control::Ping)).await?;
                heartbeat.as_mut().reset(Instant::now() + heartbeat_delay());
            },
        }
    }
}

// Only establishment shares the deadline: established business transfers may
// run arbitrarily long. Injected futures let tests model slow local connects,
// CF capacity queues, Attach and Ready without external networks.
async fn establish_tcp<C, O, L, T>(
    connect: C,
    open: O,
    deadline: Option<Instant>,
    cancelled: Option<oneshot::Receiver<()>>,
) -> Result<(L, T)>
where
    C: std::future::Future<Output = Result<L>>,
    O: std::future::Future<Output = Result<T>>,
    T: tokio::io::AsyncRead + Unpin,
{
    let establish = async {
        let local = connect.await?;
        let mut tunnel = open.await?;
        timeout(CONNECT_TIMEOUT, expect_ready(&mut tunnel)).await??;
        Ok((local, tunnel))
    };
    let bounded = async {
        if let Some(deadline) = deadline {
            if deadline <= Instant::now() {
                bail!("TCP establishment budget exhausted");
            }
            timeout_at(deadline, establish)
                .await
                .context("TCP establishment budget exhausted")?
        } else {
            establish.await
        }
    };
    if let Some(mut cancelled) = cancelled {
        tokio::select! {
            biased;
            _ = &mut cancelled => bail!("TCP establishment cancelled by server"),
            result = bounded => result,
        }
    } else {
        bounded.await
    }
}

async fn forward_tcp(
    pool: &ClientTransport,
    local: &str,
    ticket: String,
    deadline: Option<Instant>,
    cancelled: Option<oneshot::Receiver<()>>,
) -> Result<()> {
    let connect = async {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(local)).await??;
        stream.set_nodelay(true)?;
        Ok(stream)
    };
    let (mut local, mut tunnel) = establish_tcp(
        connect,
        pool.open(Control::Attach { ticket }),
        deadline,
        cancelled,
    )
    .await?;
    let (upload, download) = copy_bidirectional(&mut tunnel, &mut local).await?;
    debug!(upload, download, "TCP transfer complete");
    Ok(())
}

async fn forward_udp(
    peer: u64,
    target: SocketAddr,
    expiry: Duration,
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Frame>,
) -> Result<()> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(target).await?;
    let mut buffer = vec![0; MAX_DATAGRAM + 1];
    let mut last_active = Instant::now();
    loop {
        tokio::select! {
            data = rx.recv() => {
                let Some(data) = data else { return Ok(()); };
                socket.send(&data).await?;
                last_active = Instant::now();
            }
            result = socket.recv(&mut buffer) => {
                let len = result?;
                if len > MAX_DATAGRAM { continue; }
                last_active = Instant::now();
                match tx.try_send(Frame::Datagram { peer, data: buffer[..len].to_vec() }) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                }
            }
            _ = tokio::time::sleep_until(last_active + expiry) => return Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "tests/client.rs"]
mod tests;
