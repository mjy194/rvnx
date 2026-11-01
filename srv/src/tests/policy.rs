use super::*;
use rvnx_common::config::{Policy, PortRange, TokenPolicy};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

fn policy_state() -> Arc<State> {
    Arc::new(State {
        config: ServerConfig {
            bind: "127.0.0.1:7000".parse().unwrap(),
            token: None,
            tokens: None,
            policies: Some(
                (0usize..2)
                    .map(|i| TokenPolicy {
                        token: i.to_string().repeat(32),
                        policy: Policy {
                            bind_ip: "127.0.0.1".parse().unwrap(),
                            allowed_ports: vec![PortRange {
                                start: 1,
                                end: 65535,
                            }],
                            protocols: vec![Protocol::Tcp, Protocol::Udp],
                            max_mappings: 4,
                        },
                    })
                    .collect(),
            ),
            tls_cert: String::new(),
            tls_key: String::new(),
            cf_probe_enabled: false,
            proxies: vec![],
        },
        probes: None,
        active: Mutex::new(Registry::default()),
        tickets: Arc::new(Mutex::new(HashMap::new())),
    })
}

fn mapping(name: &str, protocol: Protocol, port: u16) -> ServerProxy {
    ServerProxy {
        name: name.into(),
        protocol,
        bind: SocketAddr::from(([127, 0, 0, 1], port)),
        connection_wait_secs: 10,
        max_connections: 128,
        udp_timeout_secs: 60,
    }
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn register(mapping: &ServerProxy) -> Control {
    Control::RegisterPolicy {
        version: POLICY_VERSION,
        proxy: mapping.name.clone(),
        protocol: mapping.protocol,
        remote_port: mapping.bind.port(),
    }
}

async fn connect_policy(
    state: Arc<State>,
    owner: usize,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>) {
    let (mut client, server) = tokio::io::duplex(16384);
    let task = tokio::spawn(handle_tunnel(Box::new(server), state, owner));
    send_control(
        &mut client,
        Control::GetPolicy {
            version: POLICY_VERSION,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_control(&mut client).await.unwrap(),
        Control::Policy {
            version: POLICY_VERSION,
            ..
        }
    ));
    (client, task)
}

async fn start_mapping(
    state: Arc<State>,
    owner: usize,
    mapping: &ServerProxy,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>) {
    let (mut client, task) = connect_policy(state, owner).await;
    send_control(&mut client, register(mapping)).await.unwrap();
    match read_control(&mut client).await.unwrap() {
        Control::Registered {
            proxy,
            protocol,
            remote_port,
        } => {
            assert_eq!(proxy, mapping.name);
            assert_eq!(protocol, mapping.protocol);
            assert_eq!(remote_port, mapping.bind.port());
        }
        other => panic!("unexpected registration response: {other:?}"),
    }
    (client, task)
}

#[test]
fn concurrent_reservations_enforce_quota_atomically() {
    let registry = Arc::new(Mutex::new(Registry::default()));
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let workers: Vec<_> = (0..16)
        .map(|i| {
            let registry = registry.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mapping = mapping(&format!("mapping-{i}"), Protocol::Tcp, 10000 + i);
                barrier.wait();
                registry
                    .lock()
                    .unwrap()
                    .reserve(0, &mapping, true, 4)
                    .map(|scope| scope.id)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 4);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| *error == "quota_exceeded")
    );
    assert_eq!(registry.lock().unwrap().entries.len(), 4);
}

#[test]
fn reservation_names_are_per_owner_ports_are_global_and_protocols_are_separate() {
    let mut registry = Registry::default();
    registry
        .reserve(0, &mapping("web", Protocol::Tcp, 8000), true, 4)
        .unwrap();
    assert_eq!(
        registry
            .reserve(0, &mapping("web", Protocol::Tcp, 8001), true, 4)
            .err(),
        Some("name_in_use")
    );
    registry
        .reserve(1, &mapping("web", Protocol::Tcp, 8001), true, 4)
        .unwrap();
    assert_eq!(
        registry
            .reserve(1, &mapping("other", Protocol::Tcp, 8000), true, 4)
            .err(),
        Some("port_in_use")
    );
    registry
        .reserve(0, &mapping("dns", Protocol::Udp, 8000), true, 4)
        .unwrap();
    let mut legacy = Registry::default();
    legacy
        .reserve(0, &mapping("web", Protocol::Tcp, 8000), false, 0)
        .unwrap();
    assert_eq!(
        legacy
            .reserve(1, &mapping("web", Protocol::Tcp, 8001), false, 0)
            .err(),
        Some("name_in_use")
    );
}

#[tokio::test]
async fn bind_failure_rolls_back_name_port_and_quota() {
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let state = policy_state();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
        let mapping = mapping("occupied", protocol, port);
        let (mut client, task) = connect_policy(state.clone(), 0).await;
        send_control(&mut client, register(&mapping)).await.unwrap();
        assert!(
            matches!(read_control(&mut client).await.unwrap(), Control::MappingError { code, .. } if code == "bind_failed")
        );
        assert!(task.await.unwrap().is_err());
        assert!(state.active.lock().unwrap().entries.is_empty());
        drop((tcp, udp));
        let (client, task) = start_mapping(state.clone(), 0, &mapping).await;
        drop(client);
        assert!(
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(state.active.lock().unwrap().entries.is_empty());
    }
}

// Preloaded reads deliver GetPolicy then RegisterPolicy. The policy reply succeeds;
// the registration reply either fails or stalls, allowing deterministic rollback tests.
struct ReplyFault {
    input: std::io::Cursor<Vec<u8>>,
    writes: usize,
    block: bool,
    reached: Arc<tokio::sync::Notify>,
}
impl AsyncRead for ReplyFault {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let n = std::io::Read::read(&mut self.input, output.initialize_unfilled())?;
        output.advance(n);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ReplyFault {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.writes == 0 {
            self.writes += 1;
            Poll::Ready(Ok(bytes.len()))
        } else {
            self.reached.notify_one();
            if self.block {
                Poll::Pending
            } else {
                Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn failed_or_cancelled_registration_reply_releases_bound_socket_and_reservation() {
    for block in [false, true] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let state = policy_state();
            let mapping = mapping("reply", protocol, free_port().await);
            let mut input = Vec::new();
            send_control(
                &mut input,
                Control::GetPolicy {
                    version: POLICY_VERSION,
                },
            )
            .await
            .unwrap();
            send_control(&mut input, register(&mapping)).await.unwrap();
            let reached = Arc::new(tokio::sync::Notify::new());
            let stream = ReplyFault {
                input: std::io::Cursor::new(input),
                writes: 0,
                block,
                reached: reached.clone(),
            };
            let task = tokio::spawn(handle_tunnel(Box::new(stream), state.clone(), 0));
            timeout(Duration::from_secs(2), reached.notified())
                .await
                .unwrap();
            if block {
                assert_eq!(state.active.lock().unwrap().entries.len(), 1);
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert!(task.await.unwrap().is_err());
            }
            assert!(state.active.lock().unwrap().entries.is_empty());
            match protocol {
                Protocol::Tcp => {
                    TcpListener::bind(mapping.bind).await.unwrap();
                }
                Protocol::Udp => {
                    UdpSocket::bind(mapping.bind).await.unwrap();
                }
            }
        }
    }
}

#[tokio::test]
async fn foreign_attach_does_not_burn_ticket_and_owner_can_still_attach() {
    let state = policy_state();
    let scope = MappingScope {
        owner: 0,
        id: 1,
        active: Arc::new(AtomicBool::new(true)),
    };
    let (sender, mut receiver) = oneshot::channel();
    state
        .tickets
        .lock()
        .unwrap()
        .insert("ticket".into(), Ticket { scope, sender });
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 1));
    send_control(
        &mut client,
        Control::Attach {
            ticket: "ticket".into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_control(&mut client).await.unwrap(),
        Control::Error { .. }
    ));
    assert!(task.await.unwrap().is_err());
    assert!(state.tickets.lock().unwrap().contains_key("ticket"));
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 0));
    send_control(
        &mut client,
        Control::Attach {
            ticket: "ticket".into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_control(&mut client).await.unwrap(),
        Control::Ready
    ));
    assert!(task.await.unwrap().is_ok());
    assert!(receiver.await.is_ok());
    assert!(state.tickets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancel_and_teardown_revoke_only_the_originating_mapping_tickets() {
    let state = policy_state();
    let mapping = mapping("first", Protocol::Tcp, free_port().await);
    let (mut client, task) = start_mapping(state.clone(), 0, &mapping).await;
    let first = state.active.lock().unwrap().entries[&(0, "first".into())]
        .scope
        .clone();
    let mut second_mapping = mapping.clone();
    second_mapping.name = "second".into();
    second_mapping.bind.set_port(free_port().await);
    let second = state
        .active
        .lock()
        .unwrap()
        .reserve(0, &second_mapping, true, 4)
        .unwrap();
    let (own_sender, own_receiver) = oneshot::channel();
    let (other_sender, mut other_receiver) = oneshot::channel();
    state.tickets.lock().unwrap().insert(
        "own".into(),
        Ticket {
            scope: first.clone(),
            sender: own_sender,
        },
    );
    state.tickets.lock().unwrap().insert(
        "other".into(),
        Ticket {
            scope: second.clone(),
            sender: other_sender,
        },
    );
    send_control(
        &mut client,
        Control::Cancel {
            ticket: "other".into(),
        },
    )
    .await
    .unwrap();
    send_control(
        &mut client,
        Control::Cancel {
            ticket: "own".into(),
        },
    )
    .await
    .unwrap();
    send_control(&mut client, Control::Ping).await.unwrap();
    assert!(matches!(
        read_control(&mut client).await.unwrap(),
        Control::Pong
    ));
    assert!(own_receiver.await.is_err());
    assert!(matches!(
        other_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let (sender, pending) = oneshot::channel();
    state.tickets.lock().unwrap().insert(
        "pending".into(),
        Ticket {
            scope: first.clone(),
            sender,
        },
    );
    drop(client);
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!first.active.load(Ordering::SeqCst));
    assert!(pending.await.is_err());
    assert!(state.tickets.lock().unwrap().contains_key("other"));
    assert_eq!(state.active.lock().unwrap().entries.len(), 1);
    assert!(second.active.load(Ordering::SeqCst));
    TcpListener::bind(mapping.bind).await.unwrap();
}

#[tokio::test]
async fn established_data_connections_close_when_control_mapping_disconnects() {
    let state = policy_state();
    let mapping = mapping("active", Protocol::Tcp, free_port().await);
    let (mut control, task) = start_mapping(state.clone(), 0, &mapping).await;
    let mut public = TcpStream::connect(mapping.bind).await.unwrap();
    let Control::Open { ticket } = read_control(&mut control).await.unwrap() else {
        panic!("expected ticket")
    };
    let (mut data, server) = tokio::io::duplex(4096);
    let attach = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 0));
    send_control(&mut data, Control::Attach { ticket })
        .await
        .unwrap();
    assert!(matches!(
        read_control(&mut data).await.unwrap(),
        Control::Ready
    ));
    attach.await.unwrap().unwrap();
    drop(control);
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(2), public.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(2), data.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(state.active.lock().unwrap().entries.is_empty());
    assert!(state.tickets.lock().unwrap().is_empty());
}

#[test]
fn concurrent_name_and_port_contention_has_only_one_winner() {
    for collide_on_name in [true, false] {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let workers: Vec<_> = (0..16)
            .map(|i| {
                let registry = registry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let name = if collide_on_name {
                        "shared".into()
                    } else {
                        format!("mapping-{i}")
                    };
                    let port = if collide_on_name { 10000 + i } else { 10000 };
                    let mapping = mapping(&name, Protocol::Tcp, port);
                    barrier.wait();
                    registry
                        .lock()
                        .unwrap()
                        .reserve(0, &mapping, true, 16)
                        .map(|scope| scope.id)
                })
            })
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let expected = if collide_on_name {
            "name_in_use"
        } else {
            "port_in_use"
        };
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| *error == expected)
        );
    }
}

#[tokio::test]
async fn policy_registration_requires_fetch_and_revalidates_requested_port() {
    let state = policy_state();
    let mapping = mapping("denied", Protocol::Tcp, 0);
    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(handle_tunnel(Box::new(server), state.clone(), 0));
    send_control(&mut client, register(&mapping)).await.unwrap();
    assert!(
        matches!(read_control(&mut client).await.unwrap(), Control::MappingError { code, .. } if code == "mode_mismatch")
    );
    assert!(task.await.unwrap().is_err());
    let (mut client, task) = connect_policy(state.clone(), 0).await;
    send_control(&mut client, register(&mapping)).await.unwrap();
    match read_control(&mut client).await.unwrap() {
        Control::MappingError {
            proxy,
            protocol,
            remote_port,
            code,
            reason,
        } => {
            assert_eq!(proxy, mapping.name);
            assert_eq!(protocol, Protocol::Tcp);
            assert_eq!(remote_port, 0);
            assert_eq!(code, "policy_denied");
            assert!(!reason.is_empty());
        }
        other => panic!("unexpected response {other:?}"),
    }
    assert!(task.await.unwrap().is_err());
    assert!(state.active.lock().unwrap().entries.is_empty());
}
