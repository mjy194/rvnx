use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rvnx_common::{
    cloudflare::{CfTransport, ClientTransport},
    config::{self, ClientConfig, ClientProxy, Protocol},
    https::{HttpsTransport, Tunnel},
    protocol::{Control, Frame, MAX_DATAGRAM, VERSION, read_control},
    transport::{CONNECT_TIMEOUT, client_tls, heartbeat_delay, queue, spawn_reader, spawn_writer},
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpStream, UdpSocket, lookup_host},
    sync::mpsc,
    task::JoinSet,
    time::{Instant, sleep, timeout},
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
            Ok(Arc::new(ClientTransport::Cloudflare(CfTransport::new(
                endpoint, cf,
            )?)))
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
                if let Err(error) = run_mapping(&proxy, &pool).await {
                    warn!(proxy = %proxy.name, error = %format!("{error:#}"), "mapping disconnected; reconnecting");
                }
                sleep(Duration::from_secs(config.reconnect_secs)).await;
            }
        });
    }
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        result = mappings.join_next() => bail!("mapping worker stopped unexpectedly: {result:?}"),
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

async fn run_mapping(proxy: &ClientProxy, pool: &Arc<ClientTransport>) -> Result<()> {
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
    let mut tunnel = pool
        .open(Control::Register {
            version: VERSION,
            proxy: proxy.name.clone(),
            protocol: match proxy.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            }
            .into(),
        })
        .await?;
    timeout(CONNECT_TIMEOUT, expect_ready(&mut tunnel)).await??;
    info!(proxy = %proxy.name, local = %proxy.local, "mapping connected");
    run_session(proxy, pool.clone(), tunnel, udp_target).await
}

// Static dispatch lets tests inject transfer failures and panics while running
// the same session loop; the production path retains its concrete transport.
trait MappingBackend: Send + Sync + 'static {
    fn tcp(
        &self,
        local: &str,
        ticket: String,
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
    async fn tcp(&self, local: &str, ticket: String) -> Result<()> {
        forward_tcp(self, local, ticket).await
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
async fn run_session<B: MappingBackend>(
    proxy: &ClientProxy,
    pool: Arc<B>,
    tunnel: Tunnel,
    udp_target: Option<SocketAddr>,
) -> Result<()> {
    let (reader, writer) = tokio::io::split(tunnel);
    let (mut rx, _reader_task) = spawn_reader(reader);
    let (tx, _writer_task) = spawn_writer(writer);
    let heartbeat = sleep(heartbeat_delay());
    tokio::pin!(heartbeat);
    let mut transfers = JoinSet::new();
    let mut udp_peers = HashMap::<u64, mpsc::Sender<Vec<u8>>>::new();
    loop {
        tokio::select! {
            frame = rx.recv() => {
                match frame.context("tunnel reader closed")?? {
                    Frame::Control(Control::Ping) => queue(&tx, Frame::Control(Control::Pong)).await?,
                    Frame::Control(Control::Pong) => {}
                    Frame::Control(Control::Open { ticket }) if proxy.protocol == Protocol::Tcp => {
                        if transfers.len() >= proxy.max_connections {
                            debug!(proxy = %proxy.name, "local TCP connection limit reached");
                            queue(&tx, Frame::Control(Control::Cancel { ticket })).await?;
                            continue;
                        }
                        let pool = pool.clone();
                        let local = proxy.local.clone();
                        let failures = tx.clone();
                        transfers.spawn(async move {
                            if let Err(error) = pool.tcp(&local, ticket.clone()).await {
                                debug!(error = %format!("{error:#}"), "TCP transfer ended");
                                let _ = queue(&failures, Frame::Control(Control::Cancel { ticket })).await;
                            }
                            None
                        });
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
                                Some(peer)
                            });
                        }
                    }
                    _ => bail!("unexpected tunnel frame"),
                }
            }
            Some(result) = transfers.join_next(), if !transfers.is_empty() => {
                match result {
                    Ok(Some(peer)) => { udp_peers.remove(&peer); }
                    Ok(None) => {}
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

async fn forward_tcp(pool: &ClientTransport, local: &str, ticket: String) -> Result<()> {
    let mut local = timeout(CONNECT_TIMEOUT, TcpStream::connect(local)).await??;
    local.set_nodelay(true)?;
    let mut tunnel = pool.open(Control::Attach { ticket }).await?;
    timeout(CONNECT_TIMEOUT, expect_ready(&mut tunnel)).await??;
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
