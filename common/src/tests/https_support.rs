use super::*;

impl Connection {
    // Transport policy tests do not touch sockets. The real h2 handles remain
    // alive, with a controllable driver lifetime and advertised capacity.
    pub(crate) async fn for_test(capacity: usize) -> Self {
        let (client, peer) = tokio::io::duplex(65536);
        let (sender, connection) = h2::client::handshake(client).await.unwrap();
        let driver = Arc::new(Driver {
            task: Some(tokio::spawn(async move {
                let _keep = (connection, peer);
                std::future::pending::<()>().await;
            })),
            drain_on_drop: false,
        });
        Self {
            sender,
            driver,
            capacity: Arc::new(AtomicUsize::new(capacity)),
        }
    }
    pub(crate) fn finish_for_test(&self) {
        self.driver.task.as_ref().unwrap().abort();
    }
}
