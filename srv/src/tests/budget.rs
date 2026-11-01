use super::*;
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

fn scope() -> MappingScope {
    MappingScope {
        owner: 0,
        id: 1,
        active: Arc::new(AtomicBool::new(true)),
    }
}

fn state() -> Arc<State> {
    Arc::new(State {
        config: ServerConfig {
            connection_wait_secs: 10,
            bind: "127.0.0.1:7000".parse().unwrap(),
            token: Some("a".repeat(32)),
            tokens: None,
            policies: None,
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

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), server.unwrap().0)
}

#[tokio::test]
async fn full_control_queue_consumes_original_accept_deadline_without_sending_open() {
    let (mut peer, public) = tcp_pair().await;
    tokio::time::pause();
    let state = state();
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(Frame::Control(Control::Ping)).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    // Scheduling delay after accept is part of the same budget too.
    tokio::time::advance(Duration::from_millis(400)).await;
    let worker = tokio::spawn(forward_tcp(
        public,
        state.tickets.clone(),
        tx,
        deadline,
        scope(),
        true,
    ));
    tokio::task::yield_now().await;
    assert_eq!(state.tickets.lock().unwrap().len(), 1);
    tokio::time::advance(Duration::from_millis(600)).await;
    let error = worker.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("timed out"));
    // Tokio rounds timer-wheel wakeups to milliseconds; no fresh stage budget.
    assert!(Instant::now() >= deadline);
    assert!(Instant::now() <= deadline + Duration::from_millis(2));
    assert!(state.tickets.lock().unwrap().is_empty());
    assert!(matches!(
        rx.recv().await,
        Some(Frame::Control(Control::Ping))
    ));
    assert!(rx.recv().await.is_none()); // Neither Open nor Cancel could bypass the full queue.
    tokio::time::resume();
    assert_eq!(
        timeout(Duration::from_secs(2), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn open_carries_only_remaining_queue_adjusted_policy_budget_and_legacy_omits_it() {
    for policy in [true, false] {
        let (_peer, public) = tcp_pair().await;
        tokio::time::pause();
        let state = state();
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(Frame::Control(Control::Ping)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let worker = tokio::spawn(forward_tcp(
            public,
            state.tickets.clone(),
            tx,
            deadline,
            scope(),
            policy,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(250)).await;
        assert!(matches!(
            rx.recv().await,
            Some(Frame::Control(Control::Ping))
        ));
        let Some(Frame::Control(Control::Open { ticket, timeout_ms })) = rx.recv().await else {
            panic!("expected Open")
        };
        if policy {
            assert!(timeout_ms.is_some_and(|value| value > 0 && value <= 750));
        } else {
            assert_eq!(timeout_ms, None);
        }
        assert_eq!(state.tickets.lock().unwrap()[&ticket].deadline, deadline);
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        assert!(state.tickets.lock().unwrap().is_empty());
        tokio::time::resume();
    }
}

#[tokio::test(start_paused = true)]
async fn expired_attach_is_rejected_even_before_ticket_guard_cleanup() {
    let state = state();
    let (sender, mut receiver) = oneshot::channel();
    state.tickets.lock().unwrap().insert(
        "expired".into(),
        Ticket {
            scope: scope(),
            sender,
            deadline: Instant::now(),
        },
    );
    let (mut peer, stream) = tokio::io::duplex(4096);
    let worker = tokio::spawn(handle_tunnel(Box::new(stream), state.clone(), 0));
    send_control(
        &mut peer,
        Control::Attach {
            ticket: "expired".into(),
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(read_control(&mut peer).await.unwrap(), Control::Error { message } if message.contains("expired"))
    );
    assert!(worker.await.unwrap().is_err());
    assert!(state.tickets.lock().unwrap().contains_key("expired"));
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    state.tickets.lock().unwrap().clear();
    assert!(receiver.await.is_err());
}

struct StalledReply {
    input: std::io::Cursor<Vec<u8>>,
    reached: Arc<tokio::sync::Notify>,
}
impl AsyncRead for StalledReply {
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
impl AsyncWrite for StalledReply {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.reached.notify_one();
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_attach_ready_expires_at_ticket_deadline_and_closes_sender() {
    let state = state();
    let deadline = Instant::now() + Duration::from_millis(50);
    let (sender, receiver) = oneshot::channel();
    state.tickets.lock().unwrap().insert(
        "stalled".into(),
        Ticket {
            scope: scope(),
            sender,
            deadline,
        },
    );
    let mut input = Vec::new();
    send_control(
        &mut input,
        Control::Attach {
            ticket: "stalled".into(),
        },
    )
    .await
    .unwrap();
    let reached = Arc::new(tokio::sync::Notify::new());
    let stream = StalledReply {
        input: std::io::Cursor::new(input),
        reached: reached.clone(),
    };
    let worker = tokio::spawn(handle_tunnel(Box::new(stream), state.clone(), 0));
    reached.notified().await;
    assert!(state.tickets.lock().unwrap().is_empty());
    tokio::time::advance(Duration::from_millis(50)).await;
    assert!(worker.await.unwrap().is_err());
    // Tokio rounds timer-wheel wakeups to milliseconds; no fresh stage budget.
    assert!(Instant::now() >= deadline);
    assert!(Instant::now() <= deadline + Duration::from_millis(2));
    assert!(receiver.await.is_err());
}

#[tokio::test]
async fn established_transfer_remains_usable_past_setup_deadline() {
    let (mut peer, public) = tcp_pair().await;
    tokio::time::pause();
    let state = state();
    let (tx, mut rx) = mpsc::channel(1);
    let deadline = Instant::now() + Duration::from_secs(1);
    let worker = tokio::spawn(forward_tcp(
        public,
        state.tickets.clone(),
        tx,
        deadline,
        scope(),
        true,
    ));
    let Some(Frame::Control(Control::Open { ticket, .. })) = rx.recv().await else {
        panic!("expected Open")
    };
    let (mut data, stream) = tokio::io::duplex(4096);
    let attach = tokio::spawn(handle_tunnel(Box::new(stream), state.clone(), 0));
    send_control(&mut data, Control::Attach { ticket })
        .await
        .unwrap();
    assert!(matches!(
        read_control(&mut data).await.unwrap(),
        Control::Ready
    ));
    attach.await.unwrap().unwrap();
    // Let the receiving transfer cross from setup into its unbounded copy phase.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!worker.is_finished());
    tokio::time::resume();
    peer.write_all(b"after deadline").await.unwrap();
    let mut bytes = [0; 14];
    timeout(Duration::from_secs(2), data.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"after deadline");
    data.write_all(b"still connected").await.unwrap();
    let mut bytes = [0; 15];
    timeout(Duration::from_secs(2), peer.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"still connected");
    peer.shutdown().await.unwrap();
    data.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(state.tickets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn submillisecond_remaining_budget_never_emits_zero_timeout_open() {
    let (_peer, public) = tcp_pair().await;
    tokio::time::pause();
    let state = state();
    let (tx, mut rx) = mpsc::channel(2);
    let deadline = Instant::now() + Duration::from_micros(500);
    assert!(
        forward_tcp(public, state.tickets.clone(), tx, deadline, scope(), true)
            .await
            .is_err()
    );
    while let Some(frame) = rx.recv().await {
        assert!(matches!(frame, Frame::Control(Control::Cancel { .. })));
    }
    assert!(state.tickets.lock().unwrap().is_empty());
}
