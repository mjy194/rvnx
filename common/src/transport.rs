use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};

use crate::protocol::{Frame, read_frame, write_frame};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub fn heartbeat_delay() -> Duration {
    Duration::from_millis(rand::random_range(15_000..=25_000))
}

fn certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(Path::new(path))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "no certificates in {path}");
    Ok(certs)
}

pub fn server_tls(cert: &str, key: &str) -> Result<TlsAcceptor> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates(cert)?, PrivateKeyDer::from_pem_file(key)?)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn client_tls(ca: &str) -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    if ca.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        for cert in certificates(ca)? {
            roots.add(cert)?;
        }
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

pub async fn connect(
    connector: &TlsConnector,
    server: &str,
    name: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    timeout(CONNECT_TIMEOUT, async {
        let stream = TcpStream::connect(server).await?;
        stream.set_nodelay(true)?;
        let name = ServerName::try_from(name.to_owned()).context("invalid TLS server_name")?;
        Ok(connector.connect(name, stream).await?)
    })
    .await
    .context("connection timed out")?
}

// Dropping a session also stops its writer, even when the session exits through '?'.
pub struct WriterTask(JoinHandle<()>);

impl Drop for WriterTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct ReaderTask(JoinHandle<()>);

impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// A dedicated reader preserves partially read frames across select! iterations.
pub fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
) -> (mpsc::Receiver<Result<Frame>>, ReaderTask) {
    let (tx, rx) = mpsc::channel(128);
    let task = tokio::spawn(async move {
        loop {
            let frame = match timeout(IDLE_TIMEOUT, read_frame(&mut reader)).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("tunnel heartbeat timed out")),
            };
            let failed = frame.is_err();
            if tx.send(frame).await.is_err() || failed {
                break;
            }
        }
    });
    (rx, ReaderTask(task))
}

pub fn spawn_writer<W: AsyncWrite + Unpin + Send + 'static>(
    mut writer: W,
) -> (mpsc::Sender<Frame>, WriterTask) {
    let (tx, mut rx) = mpsc::channel(128);
    let task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match timeout(CONNECT_TIMEOUT, write_frame(&mut writer, &frame)).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        let _ = timeout(Duration::from_secs(1), writer.shutdown()).await;
    });
    (tx, WriterTask(task))
}

pub async fn queue(tx: &mpsc::Sender<Frame>, frame: Frame) -> Result<()> {
    timeout(CONNECT_TIMEOUT, tx.send(frame))
        .await
        .context("tunnel writer stalled")?
        .context("tunnel writer closed")
}

#[cfg(test)]
#[path = "tests/transport.rs"]
mod tests;
