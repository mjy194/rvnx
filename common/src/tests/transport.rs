use super::*;
use crate::protocol::Control;
use tokio::io::AsyncReadExt;

#[tokio::test(start_paused = true)]
async fn reader_times_out_partial_frames_and_stops_after_error() {
    let (reader, mut peer) = tokio::io::duplex(32);
    let (mut rx, task) = spawn_reader(reader);
    peer.write_all(&[0, 0]).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(IDLE_TIMEOUT).await;
    assert!(
        rx.recv()
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("heartbeat timed out")
    );
    assert!(rx.recv().await.is_none());
    drop(task);
}

#[tokio::test]
async fn reader_receiver_and_task_cancellation_release_the_stream() {
    let (reader, mut peer) = tokio::io::duplex(64);
    let (rx, mut task) = spawn_reader(reader);
    drop(rx);
    write_frame(&mut peer, &Frame::Control(Control::Ping))
        .await
        .unwrap();
    (&mut task.0).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn writer_times_out_on_backpressure_and_closes_its_queue() {
    let (writer, mut peer) = tokio::io::duplex(1);
    let (tx, task) = spawn_writer(writer);
    queue(&tx, Frame::Control(Control::Ping)).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(CONNECT_TIMEOUT).await;
    tx.closed().await;
    assert!(
        queue(&tx, Frame::Control(Control::Ping))
            .await
            .unwrap_err()
            .to_string()
            .contains("closed")
    );
    let mut remaining = Vec::new();
    peer.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(remaining.len(), 1);
    drop(task);
}

#[tokio::test]
async fn writer_io_failure_and_normal_queue_close_finish_cleanly() {
    for fail in [false, true] {
        let (writer, peer) = tokio::io::duplex(128);
        let (tx, mut task) = spawn_writer(writer);
        if fail {
            drop(peer);
        }
        queue(&tx, Frame::Control(Control::Ping)).await.unwrap();
        drop(tx);
        // Do not move the JoinHandle out of its abort-on-drop wrapper.
        timeout(Duration::from_secs(2), &mut task.0)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn queue_timeout_preserves_the_already_queued_frame() {
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(Frame::Control(Control::Ping)).await.unwrap();
    assert!(
        queue(&tx, Frame::Control(Control::Pong))
            .await
            .unwrap_err()
            .to_string()
            .contains("stalled")
    );
    assert!(matches!(
        rx.recv().await,
        Some(Frame::Control(Control::Ping))
    ));
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn dropping_io_tasks_releases_both_stream_halves() {
    let (stream, mut peer) = tokio::io::duplex(128);
    let (reader, writer) = tokio::io::split(stream);
    let (_rx, reader) = spawn_reader(reader);
    let (tx, writer) = spawn_writer(writer);
    drop(reader);
    drop(writer);
    tx.closed().await;
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[test]
fn public_trust_roots_and_heartbeat_interval() {
    client_tls("").unwrap();
    for _ in 0..100 {
        assert!((Duration::from_secs(15)..=Duration::from_secs(25)).contains(&heartbeat_delay()));
    }
}

#[test]
fn empty_and_malformed_certificate_files_are_rejected() {
    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let file = Temp(std::env::temp_dir().join(format!(
        "rvnx-invalid-ca-{}-{}.pem",
        std::process::id(),
        rand::random::<u64>()
    )));
    for contents in [
        "",
        "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    ] {
        std::fs::write(&file.0, contents).unwrap();
        let path = file.0.to_str().unwrap();
        assert!(client_tls(path).is_err());
        assert!(server_tls(path, path).is_err());
    }
    std::fs::remove_file(&file.0).unwrap();
    assert!(client_tls(file.0.to_str().unwrap()).is_err());
}

#[tokio::test]
async fn connection_refusal_and_invalid_server_name_return_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let connector = client_tls("").unwrap();
    assert!(
        connect(&connector, &address, "invalid name")
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("invalid TLS server_name")
    );
    drop(listener);
    assert!(connect(&connector, &address, "localhost").await.is_err());
}

#[tokio::test(start_paused = true)]
async fn stalled_tls_handshake_hits_the_connection_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    // Keep virtual time from auto-advancing while the real loopback socket starts.
    let clock_guard = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let connecting =
        tokio::spawn(async move { connect(&client_tls("").unwrap(), &address, "localhost").await });
    let (mut socket, _) = listener.accept().await.unwrap();
    socket.read_exact(&mut [0; 1]).await.unwrap();
    clock_guard.abort();
    tokio::time::advance(CONNECT_TIMEOUT).await;
    assert!(
        connecting
            .await
            .unwrap()
            .err()
            .unwrap()
            .to_string()
            .contains("connection timed out")
    );
}
