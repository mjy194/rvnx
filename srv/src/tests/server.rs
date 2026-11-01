use super::*;
fn test_scope() -> MappingScope {
    MappingScope {
        owner: 0,
        id: 1,
        active: Arc::new(AtomicBool::new(true)),
    }
}

fn state(protocol: Protocol, bind: SocketAddr) -> Arc<State> {
    Arc::new(State {
        config: ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            token: Some("test".repeat(8)),
            tokens: None,
            policies: None,
            tls_cert: String::new(),
            tls_key: String::new(),
            cf_probe_enabled: false,
            proxies: vec![ServerProxy {
                connection_wait_secs: 1,
                name: "test".into(),
                protocol,
                bind,
                max_connections: 1,
                udp_timeout_secs: 1,
            }],
        },
        probes: None,
        active: Mutex::new(Registry::default()),
        tickets: Arc::new(Mutex::new(HashMap::new())),
    })
}
async fn register(peer: &mut tokio::io::DuplexStream, protocol: Protocol) {
    send_control(
        peer,
        Control::Register {
            version: VERSION,
            proxy: "test".into(),
            protocol: if protocol == Protocol::Tcp {
                "tcp"
            } else {
                "udp"
            }
            .into(),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_initial_message_and_cancelled_ticket_are_rejected_and_removed() {
    for cancelled in [false, true] {
        let state = state(Protocol::Tcp, "127.0.0.1:0".parse().unwrap());
        let hello = if cancelled {
            let (sender, receiver) = oneshot::channel();
            drop(receiver);
            state.tickets.lock().unwrap().insert(
                "cancelled".into(),
                Ticket {
                    scope: test_scope(),
                    sender,
                },
            );
            Control::Attach {
                ticket: "cancelled".into(),
            }
        } else {
            Control::Ping
        };
        let (server, mut peer) = tokio::io::duplex(1024);
        let worker = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 0));
        send_control(&mut peer, hello).await.unwrap();
        let reply = read_control(&mut peer).await.unwrap();
        assert!(if cancelled {
            matches!(reply, Control::Ready)
        } else {
            matches!(reply, Control::Error { .. })
        });
        let error = worker.await.unwrap().unwrap_err().to_string();
        assert!(error.contains(if cancelled {
            "public connection already closed"
        } else {
            "expected register or attach"
        }));
        assert!(state.tickets.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn bind_failures_release_registration_for_tcp_and_udp() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (protocol, address) in [
        (Protocol::Tcp, tcp.local_addr().unwrap()),
        (Protocol::Udp, udp.local_addr().unwrap()),
    ] {
        let state = state(protocol, address);
        let (server, mut peer) = tokio::io::duplex(1024);
        let worker = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 0));
        register(&mut peer, protocol).await;
        assert!(
            matches!(read_control(&mut peer).await.unwrap(),Control::Error{message} if message.contains("cannot bind"))
        );
        assert!(worker.await.unwrap().is_err());
        assert!(state.active.lock().unwrap().entries.is_empty());
    }
}

#[tokio::test]
async fn malformed_mapping_control_releases_registration_and_listener() {
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let state = state(protocol, "127.0.0.1:0".parse().unwrap());
        let (server, mut peer) = tokio::io::duplex(1024);
        let worker = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 0));
        register(&mut peer, protocol).await;
        assert!(matches!(
            read_control(&mut peer).await.unwrap(),
            Control::Ready
        ));
        send_control(&mut peer, Control::Ready).await.unwrap();
        assert!(
            worker
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("unexpected")
        );
        assert!(state.active.lock().unwrap().entries.is_empty());
    }
}

#[tokio::test]
async fn pending_public_connection_timeout_and_cancellation_remove_ticket() {
    for cancel in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (public, _) = listener.accept().await.unwrap();
        let tickets: Tickets = Arc::new(Mutex::new(HashMap::new()));
        let (tx, mut rx) = mpsc::channel(1);
        let worker = tokio::spawn(forward_tcp(
            public,
            tickets.clone(),
            tx,
            Duration::from_millis(50),
            test_scope(),
        ));
        assert!(matches!(
            rx.recv().await,
            Some(Frame::Control(Control::Open { .. }))
        ));
        assert_eq!(tickets.lock().unwrap().len(), 1);
        if cancel {
            worker.abort();
            assert!(worker.await.unwrap_err().is_cancelled());
        } else {
            assert!(
                worker
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("timed out")
            );
        }
        assert!(tickets.lock().unwrap().is_empty());
    }
}

struct FailingWriterTunnel {
    io: tokio::io::DuplexStream,
    fail: Arc<std::sync::atomic::AtomicBool>,
    failed: Arc<tokio::sync::Notify>,
}
impl tokio::io::AsyncRead for FailingWriterTunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for FailingWriterTunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            self.failed.notify_one();
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        std::pin::Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn udp_writer_failure_stops_mapping_and_releases_registration() {
    let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let state = state(Protocol::Udp, address);
    let (io, mut peer) = tokio::io::duplex(1024);
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failed = Arc::new(tokio::sync::Notify::new());
    let worker = tokio::spawn(handle_tunnel(
        Box::new(FailingWriterTunnel {
            io,
            fail: fail.clone(),
            failed: failed.clone(),
        }),
        state.clone(),
        0,
    ));
    register(&mut peer, Protocol::Udp).await;
    assert!(matches!(
        read_control(&mut peer).await.unwrap(),
        Control::Ready
    ));
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    send_control(&mut peer, Control::Ping).await.unwrap();
    timeout(Duration::from_secs(2), failed.notified())
        .await
        .unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(b"cannot forward", address).await.unwrap();
    let error = timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("tunnel writer closed"));
    assert!(state.active.lock().unwrap().entries.is_empty());
    UdpSocket::bind(address).await.unwrap();
}

struct FailFirstDatagram {
    socket: UdpSocket,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl DatagramSocket for FailFirstDatagram {
    async fn recv_from(&self, data: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(data).await
    }
    async fn send_to(&self, data: &[u8], address: SocketAddr) -> std::io::Result<usize> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return Err(std::io::ErrorKind::NetworkUnreachable.into());
        }
        self.socket.send_to(data, address).await
    }
}

#[tokio::test]
async fn udp_response_send_failure_drops_only_one_packet_and_preserves_mapping() {
    let logs = logging::Capture::new();
    use rvnx_common::protocol::{read_frame, write_frame};
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mapping = state(Protocol::Udp, address).config.proxies[0].clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (server, mut tunnel) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_udp_socket(
        Box::new(server),
        mapping,
        FailFirstDatagram {
            socket,
            calls: calls.clone(),
        },
        false,
    ));
    assert!(matches!(
        read_control(&mut tunnel).await.unwrap(),
        Control::Ready
    ));
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor.send_to(b"hello", address).await.unwrap();
    let Frame::Datagram { peer, .. } = read_frame(&mut tunnel).await.unwrap() else {
        panic!("missing visitor packet")
    };
    // Unknown peer responses are ignored without calling the socket.
    write_frame(
        &mut tunnel,
        &Frame::Datagram {
            peer: peer + 1,
            data: vec![0],
        },
    )
    .await
    .unwrap();
    write_frame(
        &mut tunnel,
        &Frame::Datagram {
            peer,
            data: b"dropped".to_vec(),
        },
    )
    .await
    .unwrap();
    send_control(&mut tunnel, Control::Ping).await.unwrap();
    assert!(matches!(
        read_control(&mut tunnel).await.unwrap(),
        Control::Pong
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    write_frame(
        &mut tunnel,
        &Frame::Datagram {
            peer,
            data: b"recovered".to_vec(),
        },
    )
    .await
    .unwrap();
    let mut data = [0; 64];
    let n = timeout(Duration::from_secs(2), visitor.recv(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data[..n], b"recovered");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(logs.text().contains("UDP response dropped"));
    assert!(!task.is_finished());
    drop(tunnel);
    assert!(task.await.unwrap().is_err());
}

#[path = "../../../common/src/tests/logging.rs"]
mod logging;

#[tokio::test]
async fn oversized_ipv6_udp_request_and_new_peer_at_capacity_are_dropped() {
    use rvnx_common::protocol::read_frame;
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mapping = state(Protocol::Udp, address).config.proxies[0].clone();
    let (server, mut tunnel) = tokio::io::duplex(4096);
    let task = tokio::spawn(serve_udp_socket(Box::new(server), mapping, socket, false));
    assert!(matches!(
        read_control(&mut tunnel).await.unwrap(),
        Control::Ready
    ));
    let first = UdpSocket::bind("[::1]:0").await.unwrap();
    let second = UdpSocket::bind("[::1]:0").await.unwrap();
    first
        .send_to(&vec![0; MAX_DATAGRAM + 1], address)
        .await
        .unwrap();
    first.send_to(b"first", address).await.unwrap();
    assert!(
        matches!(read_frame(&mut tunnel).await.unwrap(),Frame::Datagram{peer:1,data} if data==b"first")
    );
    second.send_to(b"at-capacity", address).await.unwrap();
    first.send_to(b"still-live", address).await.unwrap();
    assert!(
        matches!(read_frame(&mut tunnel).await.unwrap(),Frame::Datagram{peer:1,data} if data==b"still-live")
    );
    drop(tunnel);
    assert!(task.await.unwrap().is_err());
}
