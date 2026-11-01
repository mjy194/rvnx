//! Thread-local capture for current-thread Tokio tests; never changes RUST_LOG.
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct Buffer(Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}
impl Capture {
    pub(super) fn new() -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Buffer(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish();
        Self {
            bytes,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }
    pub(super) fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
    }
}
