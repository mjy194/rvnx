use std::{collections::HashSet, net::SocketAddr, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    /// Legacy single-token form; mutually exclusive with `tokens`.
    pub token: Option<String>,
    pub tokens: Option<Vec<String>>,
    pub tls_cert: String,
    pub tls_key: String,
    #[serde(default)]
    pub cf_probe_enabled: bool,
    pub proxies: Vec<ServerProxy>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerProxy {
    #[serde(default = "default_connection_wait")]
    pub connection_wait_secs: u64,
    pub name: String,
    pub protocol: Protocol,
    pub bind: SocketAddr,
    #[serde(default = "default_limit")]
    pub max_connections: usize,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_secs: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub server: String,
    pub server_name: String,
    pub token: String,
    #[serde(default)]
    pub tls_ca: String,
    #[serde(default)]
    pub cloudflare: Option<crate::cloudflare::CfConfig>,
    #[serde(default = "default_reconnect")]
    pub reconnect_secs: u64,
    /// Opt in to sharing HTTPS connections across business connections.
    #[serde(default)]
    pub multiplex: bool,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    pub proxies: Vec<ClientProxy>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProxy {
    pub name: String,
    pub protocol: Protocol,
    pub local: String,
    /// Override the client's multiplex setting for this mapping.
    #[serde(default)]
    pub multiplex: Option<bool>,
    /// Use an exclusive HTTPS pool for this mapping instead of the shared pool.
    #[serde(default)]
    pub dedicated_pool_size: Option<usize>,
    #[serde(default = "default_limit")]
    pub max_connections: usize,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_secs: u64,
}

fn default_connection_wait() -> u64 {
    10
}

fn default_limit() -> usize {
    128
}
fn default_pool_size() -> usize {
    4
}
fn default_udp_timeout() -> u64 {
    60
}
fn default_reconnect() -> u64 {
    3
}

pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
}

fn validate_token(token: &str) -> Result<()> {
    ensure!(
        token.bytes().all(|b| b.is_ascii_graphic()),
        "token must contain only visible ASCII characters"
    );
    ensure!(
        token != "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
        "replace the example token with a random secret"
    );
    ensure!(token.len() >= 32, "token must contain at least 32 bytes");
    ensure!(token.len() <= 4096, "token must contain at most 4096 bytes");
    Ok(())
}

fn validate_name(name: &str, names: &mut HashSet<String>) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 64,
        "proxy name must contain 1..64 bytes"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "proxy name may contain only ASCII letters, numbers, '-' and '_'"
    );
    ensure!(
        names.insert(name.to_owned()),
        "duplicate proxy name: {name}"
    );
    Ok(())
}

fn validate_limits(limit: usize, timeout: u64) -> Result<()> {
    ensure!(
        (1..=4096).contains(&limit),
        "max_connections must be in 1..=4096"
    );
    ensure!(
        (1..=86400).contains(&timeout),
        "udp_timeout_secs must be in 1..=86400"
    );
    Ok(())
}

impl ServerConfig {
    /// Accepted server credentials. Call `validate` before serving requests.
    pub fn auth_tokens(&self) -> &[String] {
        match (&self.token, &self.tokens) {
            (Some(token), None) => std::slice::from_ref(token),
            (None, Some(tokens)) => tokens,
            _ => &[],
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.token.is_some() != self.tokens.is_some(),
            "configure exactly one of token or tokens"
        );
        let tokens = self.auth_tokens();
        ensure!(!tokens.is_empty(), "tokens must not be empty");
        let mut unique = HashSet::new();
        for token in tokens {
            validate_token(token)?;
            ensure!(unique.insert(token), "duplicate token in tokens");
        }
        ensure!(!self.proxies.is_empty(), "at least one proxy is required");
        ensure!(self.bind.port() != 0, "server port cannot be zero");
        let mut names = HashSet::new();
        let mut binds = HashSet::new();
        for proxy in &self.proxies {
            validate_name(&proxy.name, &mut names)?;
            validate_limits(proxy.max_connections, proxy.udp_timeout_secs)?;
            ensure!(
                (1..=600).contains(&proxy.connection_wait_secs),
                "connection_wait_secs must be in 1..=600"
            );
            ensure!(proxy.bind.port() != 0, "proxy port cannot be zero");
            ensure!(
                binds.insert((proxy.protocol as u8, proxy.bind)),
                "duplicate proxy bind: {}",
                proxy.bind
            );
            ensure!(
                proxy.protocol != Protocol::Tcp || proxy.bind != self.bind,
                "proxy bind conflicts with server bind"
            );
        }
        Ok(())
    }
}

impl ClientConfig {
    pub fn multiplex_for(&self, proxy: &ClientProxy) -> bool {
        proxy.multiplex.unwrap_or(self.multiplex)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=32).contains(&self.pool_size),
            "pool_size must be in 1..=32"
        );
        validate_token(&self.token)?;
        ensure!(
            !self.server.is_empty() && !self.server_name.is_empty(),
            "server and server_name are required"
        );
        ensure!(
            (1..=300).contains(&self.reconnect_secs),
            "reconnect_secs must be in 1..=300"
        );
        ensure!(!self.proxies.is_empty(), "at least one proxy is required");
        if let Some(cf) = &self.cloudflare {
            cf.validate()?;
            let authority: http::uri::Authority = self.server.parse()?;
            ensure!(
                authority.host() == self.server_name,
                "Cloudflare server authority must match server_name"
            );
            ensure!(
                !self.multiplex
                    && self
                        .proxies
                        .iter()
                        .all(|p| p.multiplex.is_none() && p.dedicated_pool_size.is_none()),
                "cloudflare is a separate shared transport mode; remove multiplex and dedicated_pool_size overrides"
            );
        }
        let mut names = HashSet::new();
        let mut connections = if self
            .proxies
            .iter()
            .any(|p| self.multiplex_for(p) && p.dedicated_pool_size.is_none())
        {
            self.pool_size
        } else {
            0
        };
        for proxy in &self.proxies {
            validate_name(&proxy.name, &mut names)?;
            validate_limits(proxy.max_connections, proxy.udp_timeout_secs)?;
            ensure!(!proxy.local.is_empty(), "local address is required");
            if let Some(size) = proxy.dedicated_pool_size {
                ensure!(
                    (1..=32).contains(&size),
                    "dedicated_pool_size must be in 1..=32"
                );
                if self.multiplex_for(proxy) {
                    connections += size;
                }
                ensure!(
                    connections <= 256,
                    "total transport pool size must not exceed 256"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
