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
    async fn tcp(
        &self,
        _: &str,
        ticket: String,
        _: Option<Instant>,
        cancelled: Option<oneshot::Receiver<()>>,
    ) -> Result<()> {
        self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _guard = TransferGuard(self.live.clone());
        self.events.send(ticket.clone()).unwrap();
        match ticket.as_str() {
            "panic" => panic!("injected transfer panic"),
            "hold" => std::future::pending().await,
            "cancel-one" | "cancel-two" => {
                cancelled.unwrap().await.unwrap();
                self.events.send(format!("cancelled-{ticket}")).unwrap();
                bail!("cancelled setup");
            }
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
            remote_port: None,
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
            false,
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
                timeout_ms: None,
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
                    timeout_ms: None,
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
            timeout_ms: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(events.recv().await.unwrap(), "hold");
    send_control(
        &mut peer,
        Control::Open {
            ticket: "panic".into(),
            timeout_ms: None,
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
            timeout_ms: None,
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

fn port_policy(port: u16) -> rvnx_common::config::Policy {
    rvnx_common::config::Policy {
        bind_ip: "127.0.0.1".parse().unwrap(),
        allowed_ports: vec![rvnx_common::config::PortRange {
            start: port,
            end: port,
        }],
        protocols: vec![Protocol::Tcp],
        max_mappings: 1,
    }
}

#[tokio::test]
async fn policy_handshake_validates_then_registers_original_port_and_refetches() {
    let (mut proxy, _, _) = session_fixture(Protocol::Tcp);
    proxy.remote_port = Some(9000);
    // Each new control tunnel must present a fresh policy; a previously allowed
    // port is not reused after a reconnect to a server with a changed policy.
    for allowed in [true, false] {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let proxy = proxy.clone();
        let worker = tokio::spawn(async move { policy_handshake(&mut client, &proxy).await });
        send_control(
            &mut server,
            Control::Policy {
                version: POLICY_VERSION,
                policy: port_policy(if allowed { 9000 } else { 9001 }),
            },
        )
        .await
        .unwrap();
        if allowed {
            assert!(matches!(read_control(&mut server).await.unwrap(),
                Control::RegisterPolicy { version: POLICY_VERSION, proxy, protocol: Protocol::Tcp, remote_port: 9000 } if proxy == "test"));
            send_control(
                &mut server,
                Control::Registered {
                    proxy: "test".into(),
                    protocol: Protocol::Tcp,
                    remote_port: 9000,
                },
            )
            .await
            .unwrap();
            worker.await.unwrap().unwrap();
        } else {
            let error = worker.await.unwrap().unwrap_err();
            assert!(terminal_mapping_error(&error));
            assert_eq!(
                error.downcast_ref::<TerminalMappingError>().unwrap().code,
                "policy_denied"
            );
            // No registration bytes were sent before checking policy.
            assert!(read_control(&mut server).await.is_err());
        }
    }
}

#[tokio::test]
async fn policy_registration_denials_and_mismatched_acknowledgments_are_terminal() {
    let (mut proxy, _, _) = session_fixture(Protocol::Tcp);
    proxy.remote_port = Some(9000);
    for reply in [
        Control::MappingError {
            proxy: "test".into(),
            protocol: Protocol::Tcp,
            remote_port: 9000,
            code: "port_in_use".into(),
            reason: "port already occupied".into(),
        },
        Control::Registered {
            proxy: "test".into(),
            protocol: Protocol::Tcp,
            remote_port: 9001,
        },
        Control::Registered {
            proxy: "other".into(),
            protocol: Protocol::Tcp,
            remote_port: 9000,
        },
        Control::Registered {
            proxy: "test".into(),
            protocol: Protocol::Udp,
            remote_port: 9000,
        },
        Control::Ready,
    ] {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let proxy = proxy.clone();
        let worker = tokio::spawn(async move { policy_handshake(&mut client, &proxy).await });
        send_control(
            &mut server,
            Control::Policy {
                version: POLICY_VERSION,
                policy: port_policy(9000),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_control(&mut server).await.unwrap(),
            Control::RegisterPolicy { .. }
        ));
        send_control(&mut server, reply).await.unwrap();
        let error = worker.await.unwrap().unwrap_err();
        assert!(terminal_mapping_error(&error));
    }
}

#[tokio::test]
async fn policy_protocol_errors_are_terminal_but_disconnects_are_retryable() {
    let (mut proxy, _, _) = session_fixture(Protocol::Tcp);
    proxy.remote_port = Some(9000);
    for reply in [
        Control::Policy {
            version: VERSION,
            policy: port_policy(9000),
        },
        Control::Ready,
        Control::Error {
            message: "policy mode is disabled".into(),
        },
    ] {
        let (mut client, mut server) = tokio::io::duplex(4096);
        send_control(&mut server, reply).await.unwrap();
        assert!(terminal_mapping_error(
            &policy_handshake(&mut client, &proxy).await.unwrap_err()
        ));
    }
    let (mut client, server) = tokio::io::duplex(4096);
    drop(server);
    assert!(!terminal_mapping_error(
        &policy_handshake(&mut client, &proxy).await.unwrap_err()
    ));
    let malformed = [0, 0, 0, 1, 99];
    assert!(terminal_mapping_error(
        &read_policy_control(&mut malformed.as_slice())
            .await
            .unwrap_err()
    ));
}

#[tokio::test]
async fn establishment_budget_is_shared_by_local_connect_queue_attach_and_ready() {
    // Model each individual stage as pending while all other stages are ready.
    for stalled in 0..3 {
        let (client, mut server) = tokio::io::duplex(4096);
        if stalled != 2 {
            send_control(&mut server, Control::Ready).await.unwrap();
        }
        let connect = async {
            if stalled == 0 {
                std::future::pending::<()>().await;
            }
            Ok(())
        };
        let open = async {
            if stalled == 1 {
                std::future::pending::<()>().await;
            }
            Ok(client)
        };
        let result = establish_tcp(
            connect,
            open,
            Some(Instant::now() + Duration::from_millis(20)),
            None,
        )
        .await;
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("budget exhausted")
        );
    }
    // Local setup consumes most of the same allowance; queue waiting must not
    // receive a fresh allowance after local setup finishes.
    let (client, mut server) = tokio::io::duplex(4096);
    send_control(&mut server, Control::Ready).await.unwrap();
    let result = establish_tcp(
        async {
            sleep(Duration::from_millis(30)).await;
            Ok(())
        },
        async {
            sleep(Duration::from_millis(30)).await;
            Ok(client)
        },
        Some(Instant::now() + Duration::from_millis(45)),
        None,
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("budget exhausted")
    );
}

#[tokio::test]
async fn establishment_deadline_does_not_limit_established_transfer_or_legacy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client, mut server) = tokio::io::duplex(4096);
    send_control(&mut server, Control::Ready).await.unwrap();
    let (_, mut tunnel) = establish_tcp(
        async { Ok(()) },
        async { Ok(client) },
        Some(Instant::now() + Duration::from_millis(50)),
        None,
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(70)).await;
    server.write_all(b"still alive").await.unwrap();
    let mut reply = [0; 11];
    tunnel.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"still alive");
    let (client, mut server) = tokio::io::duplex(4096);
    send_control(&mut server, Control::Ready).await.unwrap();
    establish_tcp(
        async {
            sleep(Duration::from_millis(25)).await;
            Ok(())
        },
        async { Ok(client) },
        None,
        None,
    )
    .await
    .unwrap();
    let (client, _) = tokio::io::duplex(4096);
    assert!(
        establish_tcp(
            async { Ok(()) },
            async { Ok(client) },
            Some(Instant::now()),
            None
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn server_cancel_only_interrupts_pending_establishment() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client, _server) = tokio::io::duplex(4096);
    let (cancel, cancelled) = oneshot::channel();
    cancel.send(()).unwrap();
    let result = establish_tcp(
        async { std::future::pending::<Result<()>>().await },
        async { Ok(client) },
        None,
        Some(cancelled),
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("cancelled by server")
    );
    let (client, mut server) = tokio::io::duplex(4096);
    send_control(&mut server, Control::Ready).await.unwrap();
    let (cancel, cancelled) = oneshot::channel();
    let (_, mut established) = establish_tcp(
        async { Ok(()) },
        async { Ok(client) },
        None,
        Some(cancelled),
    )
    .await
    .unwrap();
    assert!(
        cancel.send(()).is_err(),
        "Ready must detach cancellation before raw copy"
    );
    server.write_all(b"data").await.unwrap();
    let mut data = [0; 4];
    established.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"data");
}

#[tokio::test]
async fn server_cancel_is_ticket_scoped_and_keeps_mapping_usable() {
    let (proxy, backend, mut events) = session_fixture(Protocol::Tcp);
    let (client, mut server) = tokio::io::duplex(4096);
    let worker =
        tokio::spawn(
            async move { run_session(&proxy, backend, Box::new(client), None, true).await },
        );
    for ticket in ["cancel-one", "cancel-two"] {
        send_control(
            &mut server,
            Control::Open {
                ticket: ticket.into(),
                timeout_ms: Some(1000),
            },
        )
        .await
        .unwrap();
        assert_eq!(events.recv().await.unwrap(), ticket);
    }
    send_control(
        &mut server,
        Control::Cancel {
            ticket: "cancel-one".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(events.recv().await.unwrap(), "cancelled-cancel-one");
    assert!(
        matches!(read_control(&mut server).await.unwrap(), Control::Cancel { ticket } if ticket == "cancel-one")
    );
    send_control(&mut server, Control::Ping).await.unwrap();
    assert!(matches!(
        read_control(&mut server).await.unwrap(),
        Control::Pong
    ));
    assert!(
        events.try_recv().is_err(),
        "other ticket must remain pending"
    );
    assert!(!worker.is_finished());
    send_control(
        &mut server,
        Control::Cancel {
            ticket: "cancel-two".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(events.recv().await.unwrap(), "cancelled-cancel-two");
    drop(server);
    assert!(worker.await.unwrap().is_err());
}

#[tokio::test]
async fn expired_policy_transfer_does_not_wait_for_full_cancel_queue() {
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(Frame::Control(Control::Ping)).await.unwrap();
    timeout(
        Duration::from_millis(10),
        cancel_transfer(&tx, "expired".into(), true),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        rx.recv().await,
        Some(Frame::Control(Control::Ping))
    ));
    assert!(rx.try_recv().is_err());
}
