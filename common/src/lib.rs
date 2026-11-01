pub mod cloudflare;
pub mod config;
pub mod grpc;
pub mod https;
pub mod protocol;
pub mod transport;

pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
}
