use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Total TCP setup budget for policy-created mappings; legacy mappings keep their own value.
    #[serde(default = "default_connection_wait")]
    pub connection_wait_secs: u64,
    pub bind: SocketAddr,
    /// Legacy single-token form; mutually exclusive with `tokens`.
    pub token: Option<String>,
    pub tokens: Option<Vec<String>>,
    /// Presence selects policy mode, mutually exclusive with legacy credentials/proxies.
    pub policies: Option<Vec<TokenPolicy>>,
    pub tls_cert: String,
    pub tls_key: String,
    #[serde(default)]
    pub cf_probe_enabled: bool,
    #[serde(default)]
    pub proxies: Vec<ServerProxy>,
}

/// Server-only identity binding. Never send this wrapper to clients or log it.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPolicy {
    pub token: String,
    pub policy: Policy,
}

/// Complete policy sent to its authenticated owner, without any credentials.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub bind_ip: IpAddr,
    pub allowed_ports: Vec<PortRange>,
    pub protocols: Vec<Protocol>,
    pub max_mappings: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=4096).contains(&self.max_mappings),
            "max_mappings must be in 1..=4096"
        );
        ensure!(
            (1..=128).contains(&self.allowed_ports.len()),
            "allowed_ports must contain 1..=128 ranges"
        );
        let mut ranges: Vec<_> = self.allowed_ports.iter().collect();
        ranges.sort_by_key(|range| range.start);
        let mut previous_end = 0;
        for range in ranges {
            ensure!(
                range.start > 0 && range.start <= range.end,
                "invalid allowed port range"
            );
            ensure!(
                range.start > previous_end,
                "allowed port ranges must not overlap"
            );
            previous_end = range.end;
        }
        ensure!(
            !self.protocols.is_empty(),
            "at least one protocol is required"
        );
        let mut protocols = HashSet::new();
        for protocol in &self.protocols {
            ensure!(protocols.insert(protocol), "duplicate policy protocol");
        }
        // Leave ample room for the versioned control-message envelope (8192-byte limit).
        ensure!(
            serde_json::to_vec(self)?.len() <= 4096,
            "policy is too large"
        );
        Ok(())
    }

    /// Shared client/server check. The server separately enforces live quota and ownership.
    pub fn validate_mapping(&self, name: &str, protocol: &Protocol, port: u16) -> Result<()> {
        validate_name(name, &mut HashSet::new())?;
        ensure!(
            self.protocols.contains(protocol),
            "protocol is not allowed by policy"
        );
        ensure!(
            port != 0
                && self
                    .allowed_ports
                    .iter()
                    .any(|range| (range.start..=range.end).contains(&port)),
            "remote port is not allowed by policy"
        );
        Ok(())
    }
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
    /// Explicitly opt in to policy protocol v3; never fall back to legacy registration.
    #[serde(default)]
    pub policy_mode: bool,
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
    pub remote_port: Option<u16>,
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
    pub fn is_policy_mode(&self) -> bool {
        self.policies.is_some()
    }

    /// Accepted server credentials, in the same order as `policies` in policy mode.
    /// Call `validate` before serving requests.
    pub fn auth_tokens(&self) -> Vec<String> {
        if let Some(policies) = &self.policies {
            return policies.iter().map(|entry| entry.token.clone()).collect();
        }
        match (&self.token, &self.tokens) {
            (Some(token), None) => vec![token.clone()],
            (None, Some(tokens)) => tokens.clone(),
            _ => vec![],
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.bind.port() != 0, "server port cannot be zero");
        ensure!(
            (1..=600).contains(&self.connection_wait_secs),
            "connection_wait_secs must be in 1..=600"
        );
        if let Some(policies) = &self.policies {
            ensure!(
                self.token.is_none() && self.tokens.is_none() && self.proxies.is_empty(),
                "policies cannot be combined with legacy token, tokens or proxies"
            );
            ensure!(
                !policies.is_empty(),
                "at least one token policy is required"
            );
            let mut unique = HashSet::new();
            for entry in policies {
                validate_token(&entry.token)?;
                ensure!(unique.insert(&entry.token), "duplicate policy token");
                entry.policy.validate()?;
            }
            return Ok(());
        }
        ensure!(
            self.token.is_some() != self.tokens.is_some(),
            "configure exactly one of token or tokens"
        );
        let tokens = self.auth_tokens();
        ensure!(!tokens.is_empty(), "tokens must not be empty");
        let mut unique = HashSet::new();
        for token in &tokens {
            validate_token(token)?;
            ensure!(unique.insert(token), "duplicate token in tokens");
        }
        ensure!(!self.proxies.is_empty(), "at least one proxy is required");
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
            ensure!(
                self.policy_mode == proxy.remote_port.is_some(),
                "remote_port is required in policy mode and forbidden in legacy mode"
            );
            ensure!(proxy.remote_port != Some(0), "remote_port cannot be zero");
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
