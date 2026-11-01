use super::*;
use rvnx_common::protocol::send_control;

#[tokio::test]
async fn handshake_accepts_only_ready_and_preserves_rejection_reason() {
    for (control, expected) in [
        (Control::Ready, None),
        (
            Control::Error {
                message: "denied".into(),
            },
            Some("denied"),
        ),
        (Control::Pong, Some("unexpected server handshake")),
    ] {
        let mut bytes = Vec::new();
        send_control(&mut bytes, control).await.unwrap();
        let result = expect_ready(&mut bytes.as_slice()).await;
        match expected {
            Some(text) => assert!(result.unwrap_err().to_string().contains(text)),
            None => result.unwrap(),
        }
    }
}

#[tokio::test]
async fn udp_ipv6_roundtrip_and_closed_response_queue_release_worker() {
    let echo = UdpSocket::bind("[::1]:0").await.unwrap();
    let (input, rx) = mpsc::channel(2);
    let (tx, mut output) = mpsc::channel(2);
    let task = tokio::spawn(forward_udp(
        7,
        echo.local_addr().unwrap(),
        Duration::from_secs(5),
        rx,
        tx,
    ));
    input.send(b"request".to_vec()).await.unwrap();
    let mut data = [0; 64];
    let (size, address) = timeout(Duration::from_secs(2), echo.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data[..size], b"request");
    echo.send_to(b"reply", address).await.unwrap();
    assert!(
        matches!(timeout(Duration::from_secs(2), output.recv()).await.unwrap(), Some(Frame::Datagram {peer:7,data}) if data==b"reply")
    );
    drop(output);
    echo.send_to(b"closed", address).await.unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(input.is_closed());
}

#[tokio::test]
async fn udp_response_backpressure_drops_packet_without_stalling_other_work() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (input, rx) = mpsc::channel(2);
    let (tx, mut output) = mpsc::channel(1);
    tx.send(Frame::Control(Control::Ping)).await.unwrap();
    let task = tokio::spawn(forward_udp(
        1,
        echo.local_addr().unwrap(),
        Duration::from_secs(5),
        rx,
        tx,
    ));
    input.send(vec![1]).await.unwrap();
    let mut data = [0; 8];
    let (_, address) = timeout(Duration::from_secs(2), echo.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    echo.send_to(b"dropped", address).await.unwrap();
    // The receiver remains deliberately full while another outbound packet must progress.
    input.send(vec![2]).await.unwrap();
    timeout(Duration::from_secs(2), echo.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        output.recv().await,
        Some(Frame::Control(Control::Ping))
    ));
    drop(input);
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn udp_socket_send_error_ends_worker_and_releases_input_queue() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (input, rx) = mpsc::channel(1);
    let (tx, _output) = mpsc::channel(1);
    let task = tokio::spawn(forward_udp(
        1,
        echo.local_addr().unwrap(),
        Duration::from_secs(5),
        rx,
        tx,
    ));
    // Force a deterministic kernel send error instead of depending on ICMP timing.
    input.send(vec![0; MAX_DATAGRAM + 1]).await.unwrap();
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(input.is_closed());
}

struct SessionBackend {
    events: mpsc::UnboundedSender<String>,
    live: Arc<std::sync::atomic::AtomicUsize>,
    udp_failed: std::sync::atomic::AtomicBool,
}
struct TransferGuard(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for TransferGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl MappingBackend for SessionBackend {
    async fn tcp(&self, _: &str, ticket: String) -> Result<()> {
        self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _guard = TransferGuard(self.live.clone());
        self.events.send(ticket.clone()).unwrap();
        match ticket.as_str() {
            "panic" => panic!("injected transfer panic"),
            "hold" => std::future::pending().await,
            _ => bail!("injected TCP failure"),
        }
    }
    async fn udp(
        &self,
        peer: u64,
        _: SocketAddr,
        _: Duration,
        mut rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Frame>,
    ) -> Result<()> {
        let data = rx.recv().await.context("missing first packet")?;
        self.events.send(format!("udp-{peer}")).unwrap();
        if !self
            .udp_failed
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            bail!("injected UDP failure");
        }
        tx.send(Frame::Datagram { peer, data }).await?;
        while let Some(data) = rx.recv().await {
            tx.send(Frame::Datagram { peer, data }).await?;
        }
        Ok(())
    }
}
fn session_fixture(
    protocol: Protocol,
) -> (
    ClientProxy,
    Arc<SessionBackend>,
    mpsc::UnboundedReceiver<String>,
) {
    let (events, rx) = mpsc::unbounded_channel();
    (
        ClientProxy {
            name: "test".into(),
            protocol,
            local: "127.0.0.1:1".into(),
            multiplex: None,
            dedicated_pool_size: None,
            max_connections: 4,
            udp_timeout_secs: 60,
        },
        Arc::new(SessionBackend {
            events,
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            udp_failed: std::sync::atomic::AtomicBool::new(false),
        }),
        rx,
    )
}
fn session(
    proxy: ClientProxy,
    backend: Arc<SessionBackend>,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>) {
    let (client, peer) = tokio::io::duplex(4096);
    let worker = tokio::spawn(async move {
        run_session(
            &proxy,
            backend,
            Box::new(client),
            Some("127.0.0.1:1".parse().unwrap()),
        )
        .await
    });
    (peer, worker)
}

#[tokio::test]
async fn invalid_session_frames_stop_mapping_and_cancel_active_transfers() {
    use rvnx_common::protocol::write_frame;
    for (protocol, frame) in [
        (Protocol::Tcp, Frame::Control(Control::Ready)),
        (
            Protocol::Tcp,
            Frame::Datagram {
                peer: 1,
                data: vec![],
            },
        ),
        (
            Protocol::Udp,
            Frame::Control(Control::Open {
                ticket: "unexpected".into(),
            }),
        ),
    ] {
        let (proxy, backend, mut events) = session_fixture(protocol);
        let (mut peer, worker) = session(proxy, backend.clone());
        if protocol == Protocol::Tcp {
            send_control(
                &mut peer,
                Control::Open {
                    ticket: "hold".into(),
                },
            )
            .await
            .unwrap();
            assert_eq!(events.recv().await.unwrap(), "hold");
        }
        write_frame(&mut peer, &frame).await.unwrap();
        assert!(
            timeout(Duration::from_secs(2), worker)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("unexpected tunnel frame")
        );
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(backend.live.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn transfer_panic_ends_session_and_cancels_other_children() {
    let (proxy, backend, mut events) = session_fixture(Protocol::Tcp);
    let (mut peer, worker) = session(proxy, backend.clone());
    send_control(
        &mut peer,
        Control::Open {
            ticket: "hold".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(events.recv().await.unwrap(), "hold");
    send_control(
        &mut peer,
        Control::Open {
            ticket: "panic".into(),
        },
    )
    .await
    .unwrap();
    let error = timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("transfer worker failed"));
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.live.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_failure_cancels_only_its_ticket_and_keeps_control_alive() {
    let (proxy, backend, _events) = session_fixture(Protocol::Tcp);
    let (mut peer, worker) = session(proxy, backend);
    send_control(
        &mut peer,
        Control::Open {
            ticket: "failed".into(),
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(read_control(&mut peer).await.unwrap(),Control::Cancel{ticket} if ticket=="failed")
    );
    send_control(&mut peer, Control::Ping).await.unwrap();
    assert!(matches!(
        read_control(&mut peer).await.unwrap(),
        Control::Pong
    ));
    assert!(!worker.is_finished());
    drop(peer);
    assert!(worker.await.unwrap().is_err());
}

#[tokio::test]
async fn udp_worker_error_removes_peer_and_allows_same_peer_to_reconnect() {
    let logs = logging::Capture::new();
    use rvnx_common::protocol::{read_frame, write_frame};
    let (proxy, backend, mut events) = session_fixture(Protocol::Udp);
    let (mut peer, worker) = session(proxy, backend);
    let frame = Frame::Datagram {
        peer: 7,
        data: b"retry".to_vec(),
    };
    write_frame(&mut peer, &frame).await.unwrap();
    assert_eq!(events.recv().await.unwrap(), "udp-7");
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    write_frame(&mut peer, &frame).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap(),
        "udp-7"
    );
    assert!(
        matches!(read_frame(&mut peer).await.unwrap(),Frame::Datagram{peer:7,data} if data==b"retry")
    );
    write_frame(&mut peer, &frame).await.unwrap();
    assert!(matches!(
        read_frame(&mut peer).await.unwrap(),
        Frame::Datagram { peer: 7, .. }
    ));
    assert!(
        events.try_recv().is_err(),
        "existing peer must reuse its worker"
    );
    assert!(logs.text().contains("UDP peer ended"));
    drop(peer);
    assert!(worker.await.unwrap().is_err());
}

#[path = "../../../common/src/tests/logging.rs"]
mod logging;

#[tokio::test]
async fn oversized_ipv6_udp_response_is_dropped_without_ending_the_peer() {
    let echo = UdpSocket::bind("[::1]:0").await.unwrap();
    let (input, rx) = mpsc::channel(1);
    let (tx, mut output) = mpsc::channel(2);
    let task = tokio::spawn(forward_udp(
        1,
        echo.local_addr().unwrap(),
        Duration::from_secs(5),
        rx,
        tx,
    ));
    input.send(vec![1]).await.unwrap();
    let (_, address) = echo.recv_from(&mut [0; 1]).await.unwrap();
    echo.send_to(&vec![0; MAX_DATAGRAM + 1], address)
        .await
        .unwrap();
    echo.send_to(b"valid", address).await.unwrap();
    assert!(
        matches!(timeout(Duration::from_secs(2),output.recv()).await.unwrap(),Some(Frame::Datagram{data,..}) if data==b"valid")
    );
    drop(input);
    task.await.unwrap().unwrap();
}
