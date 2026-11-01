use super::*;
use std::time::Duration;

fn endpoint(pool: Option<usize>) -> HttpsTransport {
    HttpsTransport::new(
        crate::transport::client_tls("").unwrap(),
        "localhost:443".into(),
        "localhost".into(),
        "test-token",
        pool,
    )
    .unwrap()
}
fn driver(task: JoinHandle<()>) -> Arc<Driver> {
    Arc::new(Driver {
        task: Some(task),
        drain_on_drop: false,
    })
}
async fn client(io: tokio::io::DuplexStream) -> Connection {
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    Connection {
        sender,
        driver: driver(tokio::spawn(async move {
            let _ = connection.await;
        })),
        capacity: Arc::new(AtomicUsize::new(128)),
    }
}
async fn scripted(
    response: Response<()>,
    body: Bytes,
    trailers: Option<http::HeaderMap>,
    reset: bool,
) -> (Connection, Arc<Driver>) {
    let (a, b) = tokio::io::duplex(65536);
    let server = driver(tokio::spawn(async move {
        let mut connection = h2::server::handshake(b).await.unwrap();
        let mut held = Vec::new();
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            let mut send = respond.send_response(response.clone(), false).unwrap();
            if reset {
                send.send_reset(h2::Reason::CANCEL);
            } else {
                send.send_data(body.clone(), trailers.is_none()).unwrap();
                if let Some(trailers) = &trailers {
                    send.send_trailers(trailers.clone()).unwrap();
                }
            }
            held.push((request, send));
        }
    }));
    (client(a).await, server)
}
fn status(value: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("grpc-status", HeaderValue::from_str(value).unwrap());
    headers
}
fn grpc_headers() -> http::response::Builder {
    Response::builder().header("content-type", "application/grpc+proto")
}

#[tokio::test]
async fn grpc_rejects_http_status_content_type_encoding_and_header_status() {
    for (response, expected) in [
        (
            Response::builder().status(503).body(()).unwrap(),
            "gRPC request rejected",
        ),
        (Response::builder().body(()).unwrap(), "content type"),
        (
            grpc_headers()
                .header("grpc-encoding", "gzip")
                .body(())
                .unwrap(),
            "encoding",
        ),
        (
            grpc_headers().header("grpc-status", "8").body(()).unwrap(),
            "gRPC request failed",
        ),
    ] {
        let (connection, _server) = scripted(response, Bytes::new(), None, false).await;
        let error = endpoint(None)
            .download(&connection, 0, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[tokio::test]
async fn grpc_requires_success_trailers_and_exact_probe_length() {
    for (body, trailers, requested, expected) in [
        (grpc::encode(b""), None, 0, "gRPC status"),
        (grpc::encode(b""), Some(status("8")), 0, "gRPC status"),
        (grpc::encode(b"x"), Some(status("0")), 0, "excess payload"),
        (grpc::encode(b"x"), Some(status("0")), 2, "incomplete probe"),
    ] {
        let (connection, _server) =
            scripted(grpc_headers().body(()).unwrap(), body, trailers, false).await;
        let error = endpoint(None)
            .download(&connection, requested, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[tokio::test]
async fn h2_empty_io_eof_half_close_and_reset_are_observable() {
    let (connection, _server) =
        scripted(Response::new(()), Bytes::from_static(b"abc"), None, false).await;
    let transport = endpoint(Some(1));
    *transport.slots[0].lock().await = Some(connection);
    let mut stream = transport.open(Control::Ping).await.unwrap();
    assert_eq!(stream.read(&mut []).await.unwrap(), 0);
    assert_eq!(stream.write(&[]).await.unwrap(), 0);
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"abc");
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    stream.shutdown().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        stream.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let (connection, _server) =
        scripted(grpc_headers().body(()).unwrap(), Bytes::new(), None, true).await;
    assert!(
        endpoint(None)
            .download(&connection, 0, Duration::from_secs(2))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn direct_http_rejection_and_stale_pool_connection_are_not_reused() {
    let transport = endpoint(Some(1));
    let (connection, _server) = scripted(
        Response::builder().status(503).body(()).unwrap(),
        Bytes::new(),
        None,
        false,
    )
    .await;
    *transport.slots[0].lock().await = Some(connection);
    assert!(
        transport
            .open(Control::Ping)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("HTTPS request rejected")
    );
    // Keep the liveness handle pending while the actual H2 sender has died:
    // this reproduces the poll_ready / driver-completion race without a socket.
    let mut stale = Connection::for_test(128).await;
    let old_driver = stale.driver.clone();
    old_driver.task.as_ref().unwrap().abort();
    while !old_driver.is_finished() {
        tokio::task::yield_now().await;
    }
    stale.driver = driver(tokio::spawn(std::future::pending()));
    *transport.slots[0].lock().await = Some(stale);
    assert!(transport.open(Control::Ping).await.is_err());
    assert!(transport.slots[0].lock().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn dropping_single_use_driver_bounds_its_drain_time() {
    let task = tokio::spawn(std::future::pending::<()>());
    let abort = task.abort_handle();
    drop(Driver {
        task: Some(task),
        drain_on_drop: true,
    });
    tokio::task::yield_now().await;
    assert!(!abort.is_finished());
    tokio::time::advance(CONNECT_TIMEOUT).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(abort.is_finished());
}

#[tokio::test]
async fn server_backpressure_rejects_new_streams_but_keeps_connection_usable() {
    let (a, b) = tokio::io::duplex(65536);
    let (tx, mut rx) = mpsc::channel(1);
    let server = driver(tokio::spawn(async move {
        serve_h2(b, "test-token", tx, Some(Arc::new(Semaphore::new(0))))
            .await
            .unwrap();
    }));
    let connection = client(a).await;
    let transport = endpoint(Some(1));
    *transport.slots[0].lock().await = Some(connection.clone());
    let first = transport.open(Control::Ping).await.unwrap();
    assert!(
        transport
            .open(Control::Ping)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("503")
    );
    let held = rx.recv().await.unwrap();
    let second = transport.open(Control::Ping).await.unwrap();
    let second_server = rx.recv().await.unwrap();
    let error = transport
        .download(&connection, 0, Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("gRPC status")); // RESOURCE_EXHAUSTED trailers
    drop((first, held, second, second_server, server));
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_connection_has_an_absolute_deadline() {
    let (a, b) = tokio::io::duplex(65536);
    let (tx, _rx) = mpsc::channel(1);
    let server = tokio::spawn(async move { serve_h2(b, "test-token", tx, None).await });
    let connection = client(a).await;
    let mut sender = connection.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/api/stream")
        .body(())
        .unwrap();
    let (response, _send) = sender.send_request(request.clone(), true).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::NOT_FOUND);
    tokio::time::advance(Duration::from_secs(40)).await;
    let (response, _send) = sender.send_request(request, true).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::NOT_FOUND);
    tokio::time::advance(Duration::from_secs(20)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        server.is_finished(),
        "invalid traffic must not restart the deadline"
    );
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn reset_wakes_a_writer_blocked_by_http2_flow_control() {
    let (a, b) = tokio::io::duplex(65536);
    let (tx, mut rx) = mpsc::channel(1);
    let _server = driver(tokio::spawn(async move {
        let mut server = h2::server::Builder::new()
            .initial_window_size(0)
            .handshake::<_, Bytes>(b)
            .await
            .unwrap();
        let mut requests = Vec::new();
        while let Some(Ok((request, mut respond))) = server.accept().await {
            let send = respond.send_response(Response::new(()), false).unwrap();
            tx.send(send).await.unwrap();
            requests.push(request);
        }
    }));
    let connection = client(a).await;
    let transport = endpoint(Some(1));
    *transport.slots[0].lock().await = Some(connection);
    let mut stream = transport.open(Control::Ping).await.unwrap();
    let mut reset = rx.recv().await.unwrap();
    let mut writing = Box::pin(stream.write_all(b"waiting for credit"));
    assert!(matches!(
        futures_poll_once(&mut writing).await,
        Poll::Pending
    ));
    reset.send_reset(h2::Reason::CANCEL);
    assert!(
        timeout(Duration::from_secs(2), writing)
            .await
            .unwrap()
            .is_err()
    );
}

async fn futures_poll_once<F: std::future::Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(Pin::new(&mut *future).poll(cx))).await
}

#[tokio::test(start_paused = true)]
async fn unresponsive_peer_times_out_open_and_download() {
    let (a, b) = tokio::io::duplex(65536);
    let _server = driver(tokio::spawn(async move {
        let mut server = h2::server::handshake(b).await.unwrap();
        let mut held = Vec::new();
        while let Some(Ok(incoming)) = server.accept().await {
            held.push(incoming);
        }
    }));
    let connection = client(a).await;
    let transport = endpoint(Some(1));
    *transport.slots[0].lock().await = Some(connection.clone());
    assert!(
        transport
            .open(Control::Ping)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("open timed out")
    );
    assert!(
        transport
            .open_grpc(&connection, Control::Ping)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("open timed out")
    );
    assert!(
        transport
            .download(&connection, 1, Duration::from_secs(2))
            .await
            .unwrap_err()
            .to_string()
            .contains("download timed out")
    );
}

#[tokio::test]
async fn delayed_failed_opener_cannot_remove_a_replacement_pool_connection() {
    let transport = Arc::new(endpoint(Some(1)));
    let old = Connection::for_test(128).await;
    let replacement = Connection::for_test(128).await;
    let replacement_driver = replacement.driver.clone();
    let mut slot = transport.slots[0].lock().await;
    *slot = Some(old.clone());
    let clearing = tokio::spawn({
        let transport = transport.clone();
        async move {
            transport.discard_connection(0, &old.driver).await;
        }
    });
    tokio::task::yield_now().await;
    assert!(!clearing.is_finished());
    *slot = Some(replacement);
    drop(slot);
    clearing.await.unwrap();
    assert!(Arc::ptr_eq(
        &transport.slots[0].lock().await.as_ref().unwrap().driver,
        &replacement_driver
    ));
    transport.discard_connection(0, &replacement_driver).await;
    assert!(transport.slots[0].lock().await.is_none());
}

#[tokio::test]
async fn grpc_success_header_does_not_replace_required_success_trailers() {
    for trailers in [None, Some(status("0"))] {
        let success = trailers.is_some();
        let (connection, _server) = scripted(
            grpc_headers()
                .header("grpc-status", "0")
                .header("grpc-encoding", "identity")
                .body(())
                .unwrap(),
            grpc::encode(b"ok"),
            trailers,
            false,
        )
        .await;
        let result = endpoint(None)
            .download(&connection, 2, Duration::from_secs(2))
            .await;
        assert_eq!(result.is_ok(), success);
        if !success {
            assert!(result.unwrap_err().to_string().contains("gRPC status"));
        }
    }
}

#[test]
fn transport_constructor_rejects_invalid_pool_sizes_and_header_tokens() {
    for size in [0, 33] {
        assert!(
            HttpsTransport::new(
                crate::transport::client_tls("").unwrap(),
                "localhost:443".into(),
                "localhost".into(),
                "token",
                Some(size)
            )
            .is_err()
        );
    }
    assert!(
        HttpsTransport::new(
            crate::transport::client_tls("").unwrap(),
            "localhost:443".into(),
            "localhost".into(),
            "token\r\ninjected: value",
            None
        )
        .is_err()
    );
    assert!(endpoint(Some(32)).authorization.is_sensitive());
}

#[tokio::test]
async fn malformed_probe_requests_release_the_probe_permit() {
    let (a, b) = tokio::io::duplex(65536);
    let (tx, _rx) = mpsc::channel(1);
    let permits = Arc::new(Semaphore::new(1));
    let server_permits = permits.clone();
    let _server = driver(tokio::spawn(async move {
        let _ = serve_h2(b, "test-token", tx, Some(server_permits)).await;
    }));
    let connection = client(a).await;
    let transport = endpoint(None);
    for data in [
        vec![0, 0],
        (16 * 1024 * 1024 + 1u32).to_be_bytes().to_vec(),
        vec![0, 0, 0, 0, 1],
    ] {
        let mut stream = transport
            .grpc_request(&connection, grpc::DOWNLOAD_PATH, &data, true)
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_secs(2), stream.read_to_end(&mut Vec::new()))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(permits.available_permits(), 1);
        transport
            .download(&connection, 0, Duration::from_secs(2))
            .await
            .unwrap();
    }
}
