//! Sticky, measured primary/standby connections. Scores belong to TLS connections,
//! never to an IP cache: redialing requires a fresh measurement.
use crate::{
    https::{Connection, HttpsTransport, Tunnel},
    protocol::Control,
};
use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{Instant, MissedTickBehavior, interval, timeout},
};
use tracing::{info, warn};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CfConfig {
    pub candidates: Vec<SocketAddr>,
    pub candidate_count: usize,
    pub quick_download_mib: usize,
    pub final_download_mib: usize,
    pub final_samples: usize,
    pub target_mbps: f64,
    pub keepalive_secs: u64,
    pub health_interval_secs: u64,
    pub health_download_mib: usize,
    pub slow_mbps: f64,
    pub slow_failures: usize,
    pub rotate_after: usize,
    pub hard_budget: usize,
    pub queue_timeout_secs: u64,
    pub probe_timeout_secs: u64,
    /// Backoff after an unsuccessful selection/refill, never after success.
    pub retry_secs: u64,
    pub refill_download_mib: usize,
    pub refill_attempts: usize,
    pub probe_budget_mib_per_minute: usize,
    pub probe_burst_mib: usize,
}
impl Default for CfConfig {
    fn default() -> Self {
        Self {
            candidates: vec![],
            candidate_count: 6,
            quick_download_mib: 4,
            final_download_mib: 16,
            final_samples: 2,
            target_mbps: 100.0,
            keepalive_secs: 12,
            health_interval_secs: 300,
            health_download_mib: 16,
            slow_mbps: 50.0,
            slow_failures: 2,
            rotate_after: 80,
            hard_budget: 112,
            queue_timeout_secs: 60,
            probe_timeout_secs: 30,
            retry_secs: 60,
            refill_download_mib: 8,
            refill_attempts: 2,
            probe_budget_mib_per_minute: 64,
            probe_burst_mib: 96,
        }
    }
}
impl CfConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.candidates.is_empty() && self.candidates.len() <= 4096,
            "cloudflare.candidates requires 1..=4096 IP:port entries"
        );
        ensure!(
            self.candidates
                .iter()
                .all(|a| a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast()),
            "invalid Cloudflare candidate address"
        );
        ensure!(
            (2..=16).contains(&self.candidate_count),
            "candidate_count must be in 2..=16"
        );
        ensure!(
            [
                self.quick_download_mib,
                self.final_download_mib,
                self.health_download_mib,
                self.refill_download_mib
            ]
            .into_iter()
            .all(|n| (1..=16).contains(&n)),
            "probe sizes must be in 1..=16 MiB"
        );
        ensure!(
            (1..=4).contains(&self.final_samples),
            "final_samples must be in 1..=4"
        );
        ensure!(
            self.target_mbps.is_finite()
                && self.slow_mbps.is_finite()
                && self.slow_mbps > 0.0
                && self.target_mbps >= self.slow_mbps,
            "require finite 0 < slow_mbps <= target_mbps"
        );
        ensure!(
            self.rotate_after > 0
                && self.rotate_after < self.hard_budget
                && self.hard_budget <= 1_000_000,
            "require 0 < rotate_after < hard_budget <= 1000000"
        );
        ensure!(
            (1..=10).contains(&self.slow_failures),
            "slow_failures must be in 1..=10"
        );
        ensure!(
            (1..=30).contains(&self.keepalive_secs),
            "keepalive_secs must be in 1..=30"
        );
        ensure!(
            (1..=86400).contains(&self.health_interval_secs),
            "health_interval_secs must be in 1..=86400"
        );
        ensure!(
            (1..=300).contains(&self.probe_timeout_secs)
                && (1..=300).contains(&self.queue_timeout_secs),
            "probe and queue timeouts must be in 1..=300"
        );
        ensure!(
            (1..=3600).contains(&self.retry_secs),
            "retry_secs must be in 1..=3600"
        );
        ensure!(
            (1..=6).contains(&self.refill_attempts),
            "refill_attempts must be in 1..=6"
        );
        ensure!(
            (1..=4096).contains(&self.probe_budget_mib_per_minute),
            "probe_budget_mib_per_minute must be in 1..=4096"
        );
        let largest = [
            self.quick_download_mib,
            self.final_download_mib,
            self.health_download_mib,
            self.refill_download_mib,
        ]
        .into_iter()
        .max()
        .unwrap();
        ensure!(
            (largest..=1024).contains(&self.probe_burst_mib),
            "probe_burst_mib must cover the largest probe and be <=1024"
        );
        Ok(())
    }
}

const MIB: usize = 1024 * 1024;

/// A byte token bucket: measurements may run at line speed, while total requested
/// payload (including failed/cancelled probes) is bounded by burst + rate * time.
struct ProbeBudget {
    tokens: f64,
    capacity: f64,
    bytes_per_second: f64,
    updated: Instant,
}
impl ProbeBudget {
    fn new(config: &CfConfig, now: Instant) -> Self {
        let capacity = config.probe_burst_mib as f64 * MIB as f64;
        Self {
            tokens: capacity,
            capacity,
            bytes_per_second: config.probe_budget_mib_per_minute as f64 * MIB as f64 / 60.0,
            updated: now,
        }
    }
    fn reserve(&mut self, bytes: usize, now: Instant) -> Option<Duration> {
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * self.bytes_per_second)
            .min(self.capacity);
        self.updated = now;
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            None
        } else {
            Some(Duration::from_secs_f64(
                (bytes as f64 - self.tokens) / self.bytes_per_second,
            ))
        }
    }
}

fn retry_deadline(success: bool, now: Instant, config: &CfConfig) -> Instant {
    if success {
        now
    } else {
        now + Duration::from_secs(config.retry_secs)
    }
}

pub enum ClientTransport {
    Direct(HttpsTransport),
    Cloudflare(CfTransport),
}
impl ClientTransport {
    pub async fn warm(&self) -> Result<()> {
        match self {
            Self::Direct(t) => t.warm().await,
            Self::Cloudflare(_) => Ok(()),
        }
    }
    pub async fn open(&self, hello: Control) -> Result<Tunnel> {
        match self {
            Self::Direct(t) => t.open(hello).await,
            Self::Cloudflare(t) => t.open(hello).await,
        }
    }
}

struct Candidate {
    id: usize,
    address: SocketAddr,
    connection: Connection,
    score: f64,
    opened: AtomicUsize,
    active: AtomicUsize,
    failed: AtomicBool,
    rotate: AtomicBool,
    changed: Arc<Notify>,
}
impl Candidate {
    fn healthy(&self) -> bool {
        !self.failed.load(Ordering::Relaxed) && !self.connection.finished()
    }
    fn capacity(&self) -> bool {
        // Leave two HTTP/2 slots available for keepalive and measurement.
        self.active.load(Ordering::Relaxed)
            < self
                .connection
                .capacity
                .load(Ordering::Relaxed)
                .min(128)
                .saturating_sub(2)
    }
}
struct Lease(Arc<Candidate>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
        self.0.changed.notify_waiters();
    }
}
struct LeasedStream {
    stream: Tunnel,
    _lease: Lease,
}
impl AsyncRead for LeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for LeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
#[derive(Default)]
struct State {
    primary: Option<Arc<Candidate>>,
    standby: Option<Arc<Candidate>>,
    low: usize,
}
// Static dispatch keeps the production transport allocation/dispatch unchanged.
// Tests replace network outcomes while exercising this same scheduling loop.
trait Backend: Send + Sync {
    fn establish(&self, address: SocketAddr) -> impl Future<Output = Result<Connection>> + Send;
    fn download(
        &self,
        connection: &Connection,
        bytes: usize,
        deadline: Duration,
    ) -> impl Future<Output = Result<f64>> + Send;
    fn open(
        &self,
        connection: &Connection,
        hello: Control,
    ) -> impl Future<Output = Result<Tunnel>> + Send;
}
impl Backend for HttpsTransport {
    async fn establish(&self, address: SocketAddr) -> Result<Connection> {
        self.establish_at(&address.to_string()).await
    }
    async fn download(
        &self,
        connection: &Connection,
        bytes: usize,
        deadline: Duration,
    ) -> Result<f64> {
        HttpsTransport::download(self, connection, bytes, deadline).await
    }
    async fn open(&self, connection: &Connection, hello: Control) -> Result<Tunnel> {
        self.open_grpc(connection, hello).await
    }
}
struct WorkerTask(JoinHandle<()>);
impl Drop for WorkerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Manager<B = HttpsTransport> {
    config: CfConfig,
    endpoint: Arc<B>,
    state: Mutex<State>,
    changed: Arc<Notify>,
    next: AtomicUsize,
    next_address: AtomicUsize,
    probe_budget: Mutex<ProbeBudget>,
    probe_bytes: AtomicU64,
}
pub struct CfTransport {
    manager: Arc<Manager>,
    _worker: WorkerTask,
}
impl CfTransport {
    pub fn new(endpoint: HttpsTransport, config: CfConfig) -> Result<Self> {
        config.validate()?;
        let manager = Manager::new(endpoint, config);
        let worker = WorkerTask(tokio::spawn(manager.clone().run()));
        Ok(Self {
            manager,
            _worker: worker,
        })
    }
    async fn open(&self, hello: Control) -> Result<Tunnel> {
        self.manager.open(hello).await
    }
}
#[derive(Debug, PartialEq)]
enum Decision {
    Use,
    Rotate,
    Wait,
}
fn decision(
    healthy: bool,
    capacity: bool,
    opened: usize,
    requested: bool,
    standby: bool,
    business: bool,
    config: &CfConfig,
) -> Decision {
    let wants = !healthy || !capacity || requested || opened >= config.rotate_after;
    if wants && standby {
        Decision::Rotate
    } else if healthy && capacity && (!business || opened < config.hard_budget) {
        Decision::Use
    } else {
        Decision::Wait
    }
}
fn low_count(previous: usize, score: f64, config: &CfConfig) -> usize {
    if score < config.slow_mbps {
        previous + 1
    } else {
        0
    }
}
fn score(samples: &[f64]) -> f64 {
    samples.iter().copied().fold(f64::INFINITY, f64::min)
}
impl<B: Backend + 'static> Manager<B> {
    fn new(endpoint: B, config: CfConfig) -> Arc<Self> {
        Arc::new(Self {
            probe_budget: Mutex::new(ProbeBudget::new(&config, Instant::now())),
            probe_bytes: AtomicU64::new(0),
            config,
            endpoint: Arc::new(endpoint),
            state: Mutex::new(State::default()),
            changed: Arc::new(Notify::new()),
            next: AtomicUsize::new(0),
            next_address: AtomicUsize::new(0),
        })
    }
    async fn open(&self, hello: Control) -> Result<Tunnel> {
        let business = matches!(hello, Control::Attach { .. });
        let lease = timeout(
            Duration::from_secs(self.config.queue_timeout_secs),
            self.acquire(business),
        )
        .await
        .context("Cloudflare connection capacity/budget wait timed out")?;
        let result = self.endpoint.open(&lease.0.connection, hello).await;
        match result {
            Ok(stream) => Ok(Box::new(LeasedStream {
                stream,
                _lease: lease,
            })),
            Err(error) => {
                lease.0.failed.store(true, Ordering::Relaxed);
                self.changed.notify_waiters();
                Err(error)
            }
        }
    }

    fn promote(&self, state: &mut State) {
        if let Some(next) = state.standby.take() {
            info!(connection = next.id, ip = %next.address, mbps = next.score, previous = state.primary.as_ref().map(|p|p.id), "CF primary selected; existing streams keep their connection");
            state.primary = Some(next);
            state.low = 0;
            self.changed.notify_waiters();
        }
    }
    fn maintain(&self, state: &mut State) {
        if state.standby.as_ref().is_some_and(|p| !p.healthy()) {
            state.standby = None;
        }
        let rotate = state.primary.as_ref().is_none_or(|p| {
            !p.healthy()
                || p.rotate.load(Ordering::Relaxed)
                || p.opened.load(Ordering::Relaxed) >= self.config.rotate_after
        });
        if rotate && state.standby.is_some() {
            self.promote(state);
        }
    }
    async fn acquire(&self, business: bool) -> Lease {
        loop {
            // Register before examining state so releases/promotions cannot be lost.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                self.maintain(&mut state);
                if let Some(primary) = state.primary.clone() {
                    let d = decision(
                        primary.healthy(),
                        primary.capacity(),
                        primary.opened.load(Ordering::Relaxed),
                        primary.rotate.load(Ordering::Relaxed),
                        state.standby.is_some(),
                        business,
                        &self.config,
                    );
                    if d == Decision::Rotate {
                        self.promote(&mut state);
                        continue;
                    }
                    if !primary.capacity() {
                        primary.rotate.store(true, Ordering::Relaxed);
                    }
                    if d == Decision::Use {
                        primary.active.fetch_add(1, Ordering::Relaxed);
                        if business {
                            let count = primary.opened.fetch_add(1, Ordering::Relaxed) + 1;
                            info!(
                                connection = primary.id,
                                opened = count,
                                "CF TCP connection allocated"
                            );
                            if count >= self.config.rotate_after {
                                self.changed.notify_waiters();
                            }
                        }
                        return Lease(primary);
                    }
                }
            }
            changed.await;
        }
    }
    async fn measure(
        &self,
        candidate: &Candidate,
        mib: usize,
        purpose: &'static str,
    ) -> Result<f64> {
        let bytes = mib * MIB;
        loop {
            let delay = self
                .probe_budget
                .lock()
                .unwrap()
                .reserve(bytes, Instant::now());
            match delay {
                Some(delay) => tokio::time::sleep(delay).await,
                None => break,
            }
        }
        let total = self.probe_bytes.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
        info!(
            connection = candidate.id,
            purpose,
            bytes,
            total_bytes = total,
            "CF probe budget charged"
        );
        self.endpoint
            .download(
                &candidate.connection,
                bytes,
                Duration::from_secs(self.config.probe_timeout_secs),
            )
            .await
    }

    async fn dial(
        &self,
        id: usize,
        address: SocketAddr,
        auth_slots: Option<&Semaphore>,
    ) -> Result<Candidate> {
        let connection = self.endpoint.establish(address).await?;
        let _permit = match auth_slots {
            Some(slots) => Some(slots.acquire().await?),
            None => None,
        };
        self.endpoint
            .download(&connection, 0, Duration::from_secs(10))
            .await?;
        Ok(Candidate {
            id,
            address,
            connection,
            score: 0.0,
            opened: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            rotate: AtomicBool::new(false),
            changed: self.changed.clone(),
        })
    }

    /// One measured standby is sufficient. Reuse the IP as a hint, never a score
    /// or a TLS connection; alternate candidates are tried only on failure.
    async fn refill(self: Arc<Self>, preferred: Option<SocketAddr>) -> Vec<Arc<Candidate>> {
        let started = Instant::now();
        let before = self.probe_bytes.load(Ordering::Relaxed);
        for attempt in 0..self.config.refill_attempts {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            let address = if let Some(address) = preferred.filter(|_| attempt == 0) {
                address
            } else {
                // Keep address traversal separate from connection IDs. Overriding
                // every first attempt with the preferred IP must not starve entries.
                let mut address = self.config.candidates[0];
                for _ in 0..self.config.candidates.len() {
                    let index = self.next_address.fetch_add(1, Ordering::Relaxed);
                    address = self.config.candidates[index % self.config.candidates.len()];
                    if Some(address) != preferred {
                        break;
                    }
                }
                address
            };
            let mut candidate = match self.dial(id, address, None).await {
                Ok(candidate) => candidate,
                Err(error) => {
                    warn!(%address, %error, "CF standby dial failed");
                    continue;
                }
            };
            let mut samples = Vec::new();
            for _ in 0..self.config.final_samples {
                match self
                    .measure(&candidate, self.config.refill_download_mib, "refill")
                    .await
                {
                    Ok(speed) if speed >= self.config.target_mbps => samples.push(speed),
                    Ok(speed) => {
                        info!(
                            connection = id,
                            mbps = speed,
                            "CF standby below target; stop measuring this candidate"
                        );
                        break;
                    }
                    Err(error) => {
                        warn!(connection = id, %error, "CF standby measurement failed");
                        break;
                    }
                }
            }
            if samples.len() == self.config.final_samples && candidate.healthy() {
                candidate.score = score(&samples);
                info!(connection = id, ip = %address, mbps = candidate.score, "CF candidate measured");
                info!(
                    connection = id,
                    probe_bytes = self.probe_bytes.load(Ordering::Relaxed) - before,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "CF standby refill complete"
                );
                return vec![Arc::new(candidate)];
            }
        }
        warn!(
            probe_bytes = self.probe_bytes.load(Ordering::Relaxed) - before,
            "CF standby refill failed; backing off"
        );
        Vec::new()
    }
    async fn select(self: Arc<Self>) -> Vec<Arc<Candidate>> {
        let mut dialing = JoinSet::new();
        let auth_slots = Arc::new(Semaphore::new(2));
        // Round-robin advances between rounds; repeated IPs still create distinct TLS connections.
        let start = self
            .next
            .fetch_add(self.config.candidate_count, Ordering::Relaxed);
        for offset in 0..self.config.candidate_count {
            let manager = self.clone();
            let auth_slots = auth_slots.clone();
            let id = start + offset;
            let address = self.config.candidates[id % self.config.candidates.len()];
            dialing.spawn(async move { manager.dial(id, address, Some(&auth_slots)).await });
        }
        let mut candidates = Vec::new();
        while let Some(result) = dialing.join_next().await {
            match result {
                Ok(Ok(candidate)) => candidates.push(candidate),
                Ok(Err(error)) => warn!(%error, "CF candidate dial failed"),
                Err(error) => warn!(%error, "CF candidate task failed"),
            }
        }
        // Sequential downloads avoid candidates competing with one another for local bandwidth.
        let mut quick = Vec::new();
        for mut candidate in candidates {
            match self
                .measure(
                    &candidate,
                    self.config.quick_download_mib,
                    "selection_quick",
                )
                .await
            {
                Ok(speed) => {
                    candidate.score = speed;
                    quick.push(candidate);
                }
                Err(error) => warn!(ip = %candidate.address, %error, "CF quick measurement failed"),
            }
        }
        quick.sort_by(|a, b| b.score.total_cmp(&a.score));
        quick.truncate(2);
        let mut qualified = Vec::new();
        for mut candidate in quick {
            let mut samples = Vec::new();
            for _ in 0..self.config.final_samples {
                match self
                    .measure(
                        &candidate,
                        self.config.final_download_mib,
                        "selection_final",
                    )
                    .await
                {
                    Ok(speed) => samples.push(speed),
                    Err(error) => {
                        warn!(ip = %candidate.address, %error, "CF final measurement failed");
                        break;
                    }
                }
            }
            if samples.len() != self.config.final_samples {
                continue;
            }
            candidate.score = score(&samples);
            info!(connection = candidate.id, ip = %candidate.address, mbps = candidate.score, "CF candidate measured");
            if candidate.score >= self.config.target_mbps && candidate.healthy() {
                qualified.push(Arc::new(candidate));
            }
        }
        qualified.sort_by(|a, b| b.score.total_cmp(&a.score));
        qualified
    }
    async fn run(self: Arc<Self>) {
        enum Event {
            Selected(Vec<Arc<Candidate>>),
            Keepalive(Vec<(Arc<Candidate>, bool)>),
            Health(Arc<Candidate>, Result<f64>),
        }
        let mut jobs = JoinSet::new();
        let mut selecting = false;
        let mut keeping = false;
        let mut checking = false;
        let mut retry_at = Instant::now();
        let mut keep_at = Instant::now() + Duration::from_secs(self.config.keepalive_secs);
        let mut health_at = Instant::now() + Duration::from_secs(self.config.health_interval_secs);
        let mut tick = interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {},
                _ = self.changed.notified() => {},
                Some(result) = jobs.join_next(), if !jobs.is_empty() => {
                    match result {
                        Ok(Event::Selected(candidates)) => {
                            selecting = false;
                            // Success permits immediate replenishment after promotion. Only a
                            // failed round backs off; a separate byte budget bounds probe traffic.
                            retry_at = retry_deadline(!candidates.is_empty(), Instant::now(), &self.config);
                            let mut state = self.state.lock().unwrap();
                            for candidate in candidates {
                                if state.primary.is_none() { state.standby = Some(candidate); self.promote(&mut state); }
                                else if state.standby.is_none() { state.standby = Some(candidate); }
                                self.maintain(&mut state);
                            }
                            self.maintain(&mut state); self.changed.notify_waiters();
                        }
                        Ok(Event::Keepalive(results)) => {
                            keeping = false;
                            for (candidate, ok) in results { if !ok { candidate.failed.store(true, Ordering::Relaxed); } }
                            self.changed.notify_waiters();
                        }
                        Ok(Event::Health(candidate, result)) => {
                            checking = false;
                            let mut state = self.state.lock().unwrap();
                            if state.primary.as_ref().is_some_and(|p| Arc::ptr_eq(p, &candidate)) {
                                match result {
                                    Ok(speed) => {
                                        state.low = low_count(state.low, speed, &self.config);
                                        info!(connection = candidate.id, mbps = speed, consecutive_low = state.low, "CF health measurement");
                                        if state.low >= self.config.slow_failures { candidate.failed.store(true, Ordering::Relaxed); }
                                    }
                                    Err(error) => { warn!(%error, "CF health measurement failed"); candidate.failed.store(true, Ordering::Relaxed); }
                                }
                            }
                            self.changed.notify_waiters();
                        }
                        Err(error) => { warn!(%error, "CF worker task failed"); return; }
                    }
                }
            }
            let (primary, standby) = {
                let mut state = self.state.lock().unwrap();
                self.maintain(&mut state);
                (state.primary.clone(), state.standby.clone())
            };
            let now = Instant::now();
            if standby.is_none() && !selecting && !checking && now >= retry_at {
                selecting = true;
                let manager = self.clone();
                let cold_start = primary.is_none();
                let preferred = primary.as_ref().filter(|p| p.healthy()).map(|p| p.address);
                jobs.spawn(async move {
                    Event::Selected(if cold_start {
                        manager.select().await
                    } else {
                        manager.refill(preferred).await
                    })
                });
            }
            if !keeping && now >= keep_at {
                keep_at = now + Duration::from_secs(self.config.keepalive_secs);
                let candidates: Vec<_> = primary
                    .iter()
                    .chain(standby.iter())
                    .filter(|p| p.healthy())
                    .cloned()
                    .collect();
                if !candidates.is_empty() {
                    keeping = true;
                    let endpoint = self.endpoint.clone();
                    jobs.spawn(async move {
                        let mut checks = JoinSet::new();
                        for candidate in candidates {
                            let endpoint = endpoint.clone();
                            checks.spawn(async move {
                                let ok = endpoint
                                    .download(&candidate.connection, 0, Duration::from_secs(10))
                                    .await
                                    .is_ok();
                                (candidate, ok)
                            });
                        }
                        let mut results = Vec::new();
                        while let Some(Ok(result)) = checks.join_next().await {
                            results.push(result);
                        }
                        Event::Keepalive(results)
                    });
                }
            }
            // No simultaneous bandwidth tests within this client. Health checks
            // still run every configured interval when a refill is not in flight.
            let health_ready = {
                let budget = self.probe_budget.lock().unwrap();
                (budget.tokens
                    + now.saturating_duration_since(budget.updated).as_secs_f64()
                        * budget.bytes_per_second)
                    .min(budget.capacity)
                    >= (self.config.health_download_mib * MIB) as f64
            };
            if !checking
                && !selecting
                && (standby.is_some() || now < retry_at)
                && health_ready
                && now >= health_at
            {
                health_at = now + Duration::from_secs(self.config.health_interval_secs);
                if let Some(candidate) = primary.filter(|p| p.healthy()) {
                    checking = true;
                    let manager = self.clone();
                    jobs.spawn(async move {
                        let result = manager
                            .measure(&candidate, manager.config.health_download_mib, "health")
                            .await;
                        Event::Health(candidate, result)
                    });
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/cloudflare.rs"]
mod tests;
