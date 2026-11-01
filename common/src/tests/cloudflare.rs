use super::*;
#[test]
fn successful_refill_is_immediate_but_failures_back_off() {
    let config = CfConfig::default();
    let now = Instant::now();
    assert_eq!(retry_deadline(true, now, &config), now);
    assert_eq!(
        retry_deadline(false, now, &config),
        now + Duration::from_secs(60)
    );
}

#[test]
fn probe_budget_bounds_bursts_and_accounts_for_waiting() {
    let config = CfConfig {
        probe_burst_mib: 16,
        probe_budget_mib_per_minute: 60,
        ..CfConfig::default()
    };
    let start = Instant::now();
    let mut budget = ProbeBudget::new(&config, start);
    assert_eq!(budget.reserve(16 * MIB, start), None);
    assert_eq!(budget.reserve(8 * MIB, start), Some(Duration::from_secs(8)));
    // Cancelling a waiter has not consumed any additional bytes.
    assert_eq!(
        budget.reserve(8 * MIB, start + Duration::from_secs(4)),
        Some(Duration::from_secs(4))
    );
    assert_eq!(
        budget.reserve(8 * MIB, start + Duration::from_secs(8)),
        None
    );
    assert_eq!(
        budget.reserve(MIB, start + Duration::from_secs(8)),
        Some(Duration::from_secs(1))
    );
    // Long idle periods refill only to the configured burst ceiling.
    assert_eq!(
        budget.reserve(16 * MIB, start + Duration::from_secs(3600)),
        None
    );
    assert_eq!(
        budget.reserve(MIB, start + Duration::from_secs(3600)),
        Some(Duration::from_secs(1))
    );
}

#[test]
fn default_budget_supports_four_new_connections_per_second() {
    let config = CfConfig::default();
    let start = Instant::now();
    let mut budget = ProbeBudget::new(&config, start);
    // Initial six-candidate scan still costs 88 MiB.
    assert_eq!(budget.reserve(88 * MIB, start), None);
    for round in 1..=30 {
        let now = start + Duration::from_secs(round * 20);
        // Every promotion immediately prepares one measured standby: 16 MiB.
        assert_eq!(
            budget.reserve(config.refill_download_mib * config.final_samples * MIB, now),
            None
        );
        if round % 15 == 0 {
            assert_eq!(budget.reserve(config.health_download_mib * MIB, now), None);
        }
    }
}

#[test]
fn stable_primary_soft_rotation_and_hard_budget() {
    let c = CfConfig::default();
    assert_eq!(
        decision(true, true, 0, false, true, true, &c),
        Decision::Use
    ); // No score-based preemption.
    assert_eq!(
        decision(true, true, 80, false, true, true, &c),
        Decision::Rotate
    );
    assert_eq!(
        decision(true, true, 80, false, false, true, &c),
        Decision::Use
    );
    assert_eq!(
        decision(true, true, 112, false, false, true, &c),
        Decision::Wait
    );
    assert_eq!(
        decision(true, true, 112, false, false, false, &c),
        Decision::Use
    ); // Control isn't TCP budget.
    assert_eq!(
        decision(false, true, 0, false, true, true, &c),
        Decision::Rotate
    );
    assert_eq!(
        decision(true, false, 0, false, true, true, &c),
        Decision::Rotate
    );
    assert_eq!(
        decision(true, false, 0, false, false, true, &c),
        Decision::Wait
    );
}
#[test]
fn conservative_scores_and_consecutive_low_health() {
    let c = CfConfig::default();
    assert_eq!(score(&[280.0, 150.0]), 150.0);
    assert_eq!(low_count(0, 49.0, &c), 1);
    assert_eq!(low_count(1, 50.0, &c), 0);
    assert_eq!(low_count(1, 49.0, &c), c.slow_failures);
    let mut invalid = c;
    invalid.candidates = vec!["127.0.0.1:443".parse().unwrap()];
    assert!(invalid.validate().is_ok());
    invalid.target_mbps = f64::NAN;
    assert!(invalid.validate().is_err());
}

use std::collections::{HashMap, VecDeque};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[derive(Clone)]
enum Step {
    Panic,
    Speed(f64),
    Fail,
    Block(Arc<Notify>, f64),
    BlockFail(Arc<Notify>),
}
#[derive(Default)]
struct Script {
    dial_failures: VecDeque<bool>,
    dial_panics: VecDeque<bool>,
    addresses: Vec<SocketAddr>,
    connections: Vec<Connection>,
    downloads: Vec<(usize, usize)>,
    speeds: VecDeque<Step>,
    per_connection: HashMap<usize, VecDeque<Step>>,
    pings: HashMap<usize, VecDeque<Step>>,
    authentication: VecDeque<Step>,
    opens: VecDeque<Step>,
    peers: Vec<DuplexStream>,
}
#[derive(Clone, Default)]
struct FakeBackend {
    script: Arc<Mutex<Script>>,
    active: Arc<AtomicUsize>,
}
struct ActiveCall(Arc<AtomicUsize>);
impl ActiveCall {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count.clone())
    }
}
impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
fn connection_id(connection: &Connection) -> usize {
    Arc::as_ptr(&connection.capacity) as usize
}
async fn run_step(step: Step) -> Result<f64> {
    match step {
        Step::Panic => panic!("injected backend panic"),
        Step::Speed(speed) => Ok(speed),
        Step::Fail => anyhow::bail!("injected transport failure"),
        Step::BlockFail(gate) => {
            gate.notified().await;
            anyhow::bail!("late injected failure")
        }
        Step::Block(gate, speed) => {
            gate.notified().await;
            Ok(speed)
        }
    }
}
impl Backend for FakeBackend {
    async fn establish(&self, address: SocketAddr) -> Result<Connection> {
        {
            let mut script = self.script.lock().unwrap();
            script.addresses.push(address);
            let panic_dial = script.dial_panics.pop_front().unwrap_or(false);
            if panic_dial {
                drop(script);
                panic!("injected dial panic");
            }
            if script.dial_failures.pop_front().unwrap_or(false) {
                anyhow::bail!("injected dial failure");
            }
        }
        let connection = Connection::for_test(128).await;
        self.script
            .lock()
            .unwrap()
            .connections
            .push(connection.clone());
        Ok(connection)
    }
    async fn download(
        &self,
        connection: &Connection,
        bytes: usize,
        deadline: Duration,
    ) -> Result<f64> {
        let _active = ActiveCall::new(&self.active);
        let step = {
            let mut script = self.script.lock().unwrap();
            let id = connection_id(connection);
            script.downloads.push((id, bytes));
            if bytes == 0 {
                script
                    .pings
                    .get_mut(&id)
                    .and_then(VecDeque::pop_front)
                    .or_else(|| script.authentication.pop_front())
                    .unwrap_or(Step::Speed(0.0))
            } else {
                script
                    .per_connection
                    .get_mut(&id)
                    .and_then(VecDeque::pop_front)
                    .or_else(|| script.speeds.pop_front())
                    .unwrap_or(Step::Speed(200.0))
            }
        };
        timeout(deadline, run_step(step)).await?
    }
    async fn open(&self, _: &Connection, _: Control) -> Result<Tunnel> {
        let _active = ActiveCall::new(&self.active);
        let step = self
            .script
            .lock()
            .unwrap()
            .opens
            .pop_front()
            .unwrap_or(Step::Speed(0.0));
        run_step(step).await?;
        let (stream, peer) = tokio::io::duplex(1024);
        self.script.lock().unwrap().peers.push(peer);
        Ok(Box::new(stream))
    }
}
fn test_config() -> CfConfig {
    CfConfig {
        candidates: vec![
            "127.0.0.1:443".parse().unwrap(),
            "127.0.0.2:443".parse().unwrap(),
        ],
        candidate_count: 2,
        quick_download_mib: 1,
        final_download_mib: 1,
        refill_download_mib: 1,
        health_download_mib: 1,
        keepalive_secs: 30,
        health_interval_secs: 2,
        ..CfConfig::default()
    }
}
async fn candidate(manager: &Manager<FakeBackend>, id: usize, capacity: usize) -> Arc<Candidate> {
    Arc::new(Candidate {
        id,
        address: manager.config.candidates[0],
        connection: Connection::for_test(capacity).await,
        score: 200.0,
        opened: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        rotate: AtomicBool::new(false),
        changed: manager.changed.clone(),
    })
}
async fn seeded(config: CfConfig) -> (Arc<Manager<FakeBackend>>, Arc<Candidate>, Arc<Candidate>) {
    let manager = Manager::new(FakeBackend::default(), config);
    let primary = candidate(&manager, 100, 128).await;
    let standby = candidate(&manager, 101, 128).await;
    {
        let mut state = manager.state.lock().unwrap();
        state.primary = Some(primary.clone());
        state.standby = Some(standby.clone());
    }
    (manager, primary, standby)
}
async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}
async fn advance(seconds: u64) {
    tokio::time::advance(Duration::from_secs(seconds)).await;
    settle().await;
}
fn primary_id(manager: &Manager<FakeBackend>) -> usize {
    manager.state.lock().unwrap().primary.as_ref().unwrap().id
}
fn attach() -> Control {
    Control::Attach {
        ticket: "test-ticket".into(),
    }
}
fn run(manager: &Arc<Manager<FakeBackend>>) -> WorkerTask {
    WorkerTask(tokio::spawn(manager.clone().run()))
}

#[tokio::test(start_paused = true)]
async fn worker_starts_with_measured_primary_and_standby_then_stays_sticky() {
    let manager = Manager::new(FakeBackend::default(), test_config());
    let _worker = run(&manager);
    settle().await;
    let id = primary_id(&manager);
    assert!(manager.state.lock().unwrap().standby.is_some());
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (6 * MIB) as u64
    );
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 2);
    advance(1).await;
    assert_eq!(primary_id(&manager), id);
    // A better standby is not a reason to abandon a healthy active connection.
    let mut state = manager.state.lock().unwrap();
    Arc::get_mut(state.standby.as_mut().unwrap()).unwrap().score = 9999.0;
    manager.maintain(&mut state);
    assert_eq!(state.primary.as_ref().unwrap().id, id);
}

#[tokio::test(start_paused = true)]
async fn two_low_health_checks_rotate_but_a_recovery_resets_the_streak() {
    let (manager, primary, standby) = seeded(test_config()).await;
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .per_connection
        .insert(
            connection_id(&primary.connection),
            [49.0, 50.0, 49.0, 49.0].map(Step::Speed).into(),
        );
    let _worker = run(&manager);
    settle().await;
    for expected_low in [1, 0, 1] {
        advance(2).await;
        assert_eq!(primary_id(&manager), primary.id);
        assert_eq!(manager.state.lock().unwrap().low, expected_low);
    }
    advance(2).await;
    assert_eq!(primary_id(&manager), standby.id);
    assert_eq!(manager.state.lock().unwrap().low, 0);
    assert!(manager.state.lock().unwrap().standby.is_some()); // Immediate measured refill.
}

#[tokio::test(start_paused = true)]
async fn late_health_error_after_keepalive_rotation_cannot_poison_new_primary() {
    let config = CfConfig {
        keepalive_secs: 2,
        ..test_config()
    };
    let (manager, primary, standby) = seeded(config).await;
    let gate = Arc::new(Notify::new());
    {
        let mut script = manager.endpoint.script.lock().unwrap();
        script.per_connection.insert(
            connection_id(&primary.connection),
            [Step::BlockFail(gate.clone())].into(),
        );
        script
            .pings
            .insert(connection_id(&primary.connection), [Step::Fail].into());
    }
    let _worker = run(&manager);
    settle().await;
    advance(2).await;
    assert_eq!(primary_id(&manager), standby.id);
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 1);
    gate.notify_waiters();
    settle().await;
    assert_eq!(primary_id(&manager), standby.id);
    assert_eq!(manager.state.lock().unwrap().low, 0);
    assert!(standby.healthy());
    assert!(manager.state.lock().unwrap().standby.is_some());
}

#[tokio::test(start_paused = true)]
async fn standby_failure_replenishes_without_preempting_primary() {
    let config = CfConfig {
        keepalive_secs: 1,
        health_interval_secs: 100,
        ..test_config()
    };
    let (manager, primary, standby) = seeded(config).await;
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .pings
        .insert(connection_id(&standby.connection), [Step::Fail].into());
    let _worker = run(&manager);
    settle().await;
    advance(1).await;
    assert_eq!(primary_id(&manager), primary.id);
    let state = manager.state.lock().unwrap();
    assert_ne!(state.standby.as_ref().unwrap().id, standby.id);
    assert!(state.standby.as_ref().unwrap().healthy());
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (2 * MIB) as u64
    );
}

#[tokio::test(start_paused = true)]
async fn failed_refill_backs_off_and_keeps_health_checks_alive() {
    let config = CfConfig {
        retry_secs: 10,
        ..test_config()
    };
    let (manager, primary, _) = seeded(config).await;
    manager.state.lock().unwrap().standby = None;
    manager.endpoint.script.lock().unwrap().dial_failures = [true, true].into();
    let _worker = run(&manager);
    settle().await;
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 2);
    advance(2).await;
    assert!(
        manager
            .endpoint
            .script
            .lock()
            .unwrap()
            .downloads
            .contains(&(connection_id(&primary.connection), MIB))
    );
    advance(7).await;
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 2);
    advance(1).await;
    assert_eq!(primary_id(&manager), primary.id);
    assert!(manager.state.lock().unwrap().standby.is_some());
}

#[tokio::test(start_paused = true)]
async fn retired_stream_survives_rotation_and_releases_only_its_own_lease() {
    let config = CfConfig {
        rotate_after: 1,
        hard_budget: 2,
        ..test_config()
    };
    let (manager, primary, standby) = seeded(config).await;
    let mut old = manager.open(attach()).await.unwrap();
    let mut peer = manager.endpoint.script.lock().unwrap().peers.pop().unwrap();
    let new = manager.acquire(true).await;
    assert_eq!(primary_id(&manager), standby.id);
    old.write_all(b"after rotation").await.unwrap();
    old.flush().await.unwrap();
    old.shutdown().await.unwrap();
    let mut data = Vec::new();
    peer.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"after rotation");
    peer.write_all(b"reply").await.unwrap();
    peer.shutdown().await.unwrap();
    data.clear();
    old.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"reply");
    assert_eq!(primary.active.load(Ordering::Relaxed), 1);
    drop(old);
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
    assert_eq!(standby.active.load(Ordering::Relaxed), 1);
    drop(new);
    assert_eq!(standby.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn outer_connection_exit_and_capacity_exhaustion_promote_a_ready_standby() {
    let (manager, primary, standby) = seeded(test_config()).await;
    primary.connection.finish_for_test();
    settle().await;
    let lease = manager.acquire(true).await;
    assert_eq!(lease.0.id, standby.id);
    drop(lease);
    let replacement = candidate(&manager, 102, 128).await;
    manager.state.lock().unwrap().standby = Some(replacement.clone());
    // Advertised capacity reserves two streams for measurements and keepalive.
    standby.connection.capacity.store(2, Ordering::Relaxed);
    let lease = manager.acquire(true).await;
    assert_eq!(lease.0.id, replacement.id);
    assert_eq!(standby.opened.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_acquisition_never_overshoots_hard_budget_and_cancelled_waiters_leak_nothing() {
    let config = CfConfig {
        rotate_after: 4,
        hard_budget: 8,
        ..test_config()
    };
    let (manager, primary, _) = seeded(config).await;
    manager.state.lock().unwrap().standby = None;
    let barrier = Arc::new(tokio::sync::Barrier::new(65));
    let mut tasks = JoinSet::new();
    for _ in 0..64 {
        let manager = manager.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            manager.acquire(true).await
        });
    }
    barrier.wait().await;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(
            timeout(Duration::from_secs(2), tasks.join_next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        );
    }
    assert!(
        timeout(Duration::from_millis(20), tasks.join_next())
            .await
            .is_err()
    );
    assert_eq!(primary.opened.load(Ordering::Relaxed), 8);
    assert_eq!(primary.active.load(Ordering::Relaxed), 8);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(held);
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
    assert_eq!(primary.opened.load(Ordering::Relaxed), 8); // Cumulative budget is never refunded.
    let control = manager.acquire(false).await;
    assert_eq!(primary.opened.load(Ordering::Relaxed), 8);
    drop(control);
}

#[tokio::test(start_paused = true)]
async fn capacity_waiter_wakes_when_a_lease_drops_without_losing_a_notification() {
    let (manager, primary, _) = seeded(test_config()).await;
    manager.state.lock().unwrap().standby = None;
    primary.connection.capacity.store(3, Ordering::Relaxed);
    let held = manager.acquire(true).await;
    let waiting = tokio::spawn({
        let manager = manager.clone();
        async move { manager.acquire(true).await }
    });
    settle().await;
    assert!(!waiting.is_finished());
    drop(held);
    settle().await;
    assert!(waiting.is_finished());
    let lease = waiting.await.unwrap();
    assert_eq!(primary.active.load(Ordering::Relaxed), 1);
    drop(lease);
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn cancelling_an_inflight_open_releases_capacity_without_refunding_a_tcp_open() {
    let (manager, primary, _) = seeded(test_config()).await;
    let gate = Arc::new(Notify::new());
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .opens
        .push_back(Step::Block(gate, 0.0));
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.open(attach()).await }
    });
    settle().await;
    assert_eq!(primary.active.load(Ordering::Relaxed), 1);
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 1);
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    settle().await;
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
    assert_eq!(primary.opened.load(Ordering::Relaxed), 1);
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
    assert!(primary.healthy());
}

#[tokio::test(start_paused = true)]
async fn failed_open_releases_lease_and_next_request_uses_standby() {
    let (manager, primary, standby) = seeded(test_config()).await;
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .opens
        .push_back(Step::Fail);
    assert!(manager.open(attach()).await.is_err());
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
    assert_eq!(primary.opened.load(Ordering::Relaxed), 1);
    assert!(!primary.healthy());
    let stream = manager.open(attach()).await.unwrap();
    assert_eq!(primary_id(&manager), standby.id);
    drop(stream);
    assert_eq!(standby.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn queue_timeout_leaves_counters_and_transport_untouched() {
    let config = CfConfig {
        rotate_after: 1,
        hard_budget: 2,
        queue_timeout_secs: 3,
        ..test_config()
    };
    let (manager, primary, _) = seeded(config).await;
    manager.state.lock().unwrap().standby = None;
    primary.opened.store(2, Ordering::Relaxed);
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.open(attach()).await }
    });
    settle().await;
    advance(3).await;
    assert!(
        task.await
            .unwrap()
            .err()
            .expect("queue must time out")
            .to_string()
            .contains("wait timed out")
    );
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
    assert_eq!(primary.opened.load(Ordering::Relaxed), 2);
    assert!(manager.endpoint.script.lock().unwrap().peers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancelling_probe_waiter_spends_nothing_but_cancelled_download_is_not_refunded() {
    let config = CfConfig {
        probe_budget_mib_per_minute: 60,
        probe_burst_mib: 1,
        ..test_config()
    };
    let (manager, primary, _) = seeded(config).await;
    assert_eq!(
        manager
            .probe_budget
            .lock()
            .unwrap()
            .reserve(MIB, Instant::now()),
        None
    );
    let waiting = tokio::spawn({
        let m = manager.clone();
        let p = primary.clone();
        async move { m.measure(&p, 1, "test").await }
    });
    settle().await;
    assert_eq!(manager.probe_bytes.load(Ordering::Relaxed), 0);
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    assert!(manager.endpoint.script.lock().unwrap().downloads.is_empty());
    advance(1).await;
    let gate = Arc::new(Notify::new());
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .speeds
        .push_back(Step::Block(gate, 200.0));
    let started = tokio::spawn({
        let m = manager.clone();
        async move { m.measure(&primary, 1, "test").await }
    });
    settle().await;
    assert_eq!(manager.probe_bytes.load(Ordering::Relaxed), MIB as u64);
    started.abort();
    assert!(started.await.unwrap_err().is_cancelled());
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        manager
            .probe_budget
            .lock()
            .unwrap()
            .reserve(MIB, Instant::now()),
        Some(Duration::from_secs(1))
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_worker_aborts_inflight_measurements_and_stops_future_probes() {
    let manager = Manager::new(FakeBackend::default(), test_config());
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .speeds
        .push_back(Step::Block(Arc::new(Notify::new()), 200.0));
    let worker = run(&manager);
    settle().await;
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 1);
    let charged = manager.probe_bytes.load(Ordering::Relaxed);
    drop(worker);
    settle().await;
    advance(300).await;
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
    assert_eq!(manager.probe_bytes.load(Ordering::Relaxed), charged);
    assert!(manager.state.lock().unwrap().primary.is_none());
}

#[tokio::test(start_paused = true)]
async fn refill_rejects_a_slow_sample_early_falls_back_and_stops_at_first_qualified_connection() {
    let logs = logging::Capture::new();
    let manager = Manager::new(FakeBackend::default(), test_config());
    let preferred = manager.config.candidates[1];
    manager.endpoint.script.lock().unwrap().speeds =
        [Step::Speed(99.0), Step::Speed(150.0), Step::Speed(120.0)].into();
    let result = manager.clone().refill(Some(preferred)).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].score, 120.0);
    assert!(
        logs.text()
            .contains("CF standby below target; stop measuring this candidate")
    );
    let script = manager.endpoint.script.lock().unwrap();
    assert_eq!(
        script.addresses,
        vec![preferred, manager.config.candidates[0]]
    );
    assert_eq!(
        script
            .downloads
            .iter()
            .filter(|(_, bytes)| *bytes > 0)
            .count(),
        3
    );
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (3 * MIB) as u64
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_cursor_visits_every_nonpreferred_address_across_failed_rounds() {
    let config = CfConfig {
        candidates: (1..=4)
            .map(|n| format!("127.0.0.{n}:443").parse().unwrap())
            .collect(),
        ..test_config()
    };
    let manager = Manager::new(FakeBackend::default(), config);
    let preferred = manager.config.candidates[2];
    manager.endpoint.script.lock().unwrap().dial_failures = vec![true; 8].into();
    for _ in 0..4 {
        assert!(manager.clone().refill(Some(preferred)).await.is_empty());
    }
    let script = manager.endpoint.script.lock().unwrap();
    assert_eq!(
        script
            .addresses
            .iter()
            .step_by(2)
            .copied()
            .collect::<Vec<_>>(),
        vec![preferred; 4]
    );
    assert_eq!(
        script
            .addresses
            .iter()
            .skip(1)
            .step_by(2)
            .copied()
            .collect::<Vec<_>>(),
        vec![
            manager.config.candidates[0],
            manager.config.candidates[1],
            manager.config.candidates[3],
            manager.config.candidates[0]
        ]
    );
    assert_eq!(manager.probe_bytes.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn duplicate_addresses_and_failed_measurements_remain_bounded() {
    let config = CfConfig {
        candidates: vec!["127.0.0.1:443".parse().unwrap(); 3],
        ..test_config()
    };
    let manager = Manager::new(FakeBackend::default(), config);
    manager.endpoint.script.lock().unwrap().speeds = vec![Step::Fail; 2].into();
    assert!(
        manager
            .clone()
            .refill(Some(manager.config.candidates[0]))
            .await
            .is_empty()
    );
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 2);
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (2 * MIB) as u64
    );
    // A new TLS connection must be measured again; failed scores are never reused.
    let next = manager.clone().refill(None).await;
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].id, 2);
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (4 * MIB) as u64
    );
}

#[test]
fn configuration_numeric_boundaries_and_invalid_addresses() {
    let valid = CfConfig {
        candidates: vec!["127.0.0.1:443".parse().unwrap()],
        ..CfConfig::default()
    };
    macro_rules! bounds {
        ($field:ident, $min:expr, $max:expr) => {
            for (value, accepted) in [
                ($min, true),
                ($max, true),
                ($min - 1, false),
                ($max + 1, false),
            ] {
                let mut c = valid.clone();
                c.$field = value;
                assert_eq!(
                    c.validate().is_ok(),
                    accepted,
                    "{}={value}",
                    stringify!($field)
                );
            }
        };
    }
    bounds!(candidate_count, 2, 16);
    bounds!(quick_download_mib, 1, 16);
    bounds!(final_download_mib, 1, 16);
    bounds!(health_download_mib, 1, 16);
    bounds!(refill_download_mib, 1, 16);
    bounds!(final_samples, 1, 4);
    bounds!(slow_failures, 1, 10);
    bounds!(keepalive_secs, 1, 30);
    bounds!(health_interval_secs, 1, 86400);
    bounds!(queue_timeout_secs, 1, 300);
    bounds!(probe_timeout_secs, 1, 300);
    bounds!(retry_secs, 1, 3600);
    bounds!(refill_attempts, 1, 6);
    bounds!(probe_budget_mib_per_minute, 1, 4096);
    bounds!(probe_burst_mib, 16, 1024);
    for (rotate, hard, accepted) in [
        (1, 2, true),
        (999_999, 1_000_000, true),
        (0, 2, false),
        (2, 2, false),
        (3, 2, false),
        (1, 1_000_001, false),
    ] {
        let mut c = valid.clone();
        c.rotate_after = rotate;
        c.hard_budget = hard;
        assert_eq!(c.validate().is_ok(), accepted, "budgets {rotate}/{hard}");
    }
    for (target, slow, accepted) in [
        (50.0, 50.0, true),
        (49.0, 50.0, false),
        (100.0, 0.0, false),
        (100.0, -1.0, false),
        (f64::NAN, 50.0, false),
        (f64::INFINITY, 50.0, false),
        (100.0, f64::NAN, false),
        (100.0, f64::INFINITY, false),
    ] {
        let mut c = valid.clone();
        c.target_mbps = target;
        c.slow_mbps = slow;
        assert_eq!(c.validate().is_ok(), accepted, "thresholds {target}/{slow}");
    }
    for address in [
        "0.0.0.0:443",
        "[::]:443",
        "224.0.0.1:443",
        "[ff02::1]:443",
        "127.0.0.1:0",
    ] {
        let mut c = valid.clone();
        c.candidates = vec![address.parse().unwrap()];
        assert!(c.validate().is_err(), "{address}");
    }
    for (len, accepted) in [(0, false), (1, true), (4096, true), (4097, false)] {
        let mut c = valid.clone();
        c.candidates = vec!["[::1]:443".parse().unwrap(); len];
        assert_eq!(c.validate().is_ok(), accepted, "candidate list {len}");
    }
    assert!(toml::from_str::<CfConfig>("unknown_option = 3").is_err());
    assert!(toml::from_str::<CfConfig>("candidate_count = -1").is_err());
    let mut c = valid;
    c.probe_burst_mib = 8;
    c.final_download_mib = 8;
    c.health_download_mib = 8;
    assert!(c.validate().is_ok());
    c.refill_download_mib = 9;
    assert!(c.validate().is_err());
}

#[tokio::test(start_paused = true)]
async fn startup_dial_failure_backs_off_then_recovers_without_a_ready_primary() {
    let manager = Manager::new(
        FakeBackend::default(),
        CfConfig {
            retry_secs: 5,
            ..test_config()
        },
    );
    manager.endpoint.script.lock().unwrap().dial_failures = [true, true].into();
    let _worker = run(&manager);
    settle().await;
    assert!(manager.state.lock().unwrap().primary.is_none());
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 2);
    advance(4).await;
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 2);
    advance(1).await;
    assert!(manager.state.lock().unwrap().primary.is_some());
    assert!(manager.state.lock().unwrap().standby.is_some());
    assert_eq!(manager.endpoint.script.lock().unwrap().addresses.len(), 4);
}

#[tokio::test(start_paused = true)]
async fn startup_measurement_timeout_discards_only_that_connection() {
    let manager = Manager::new(
        FakeBackend::default(),
        CfConfig {
            probe_timeout_secs: 2,
            ..test_config()
        },
    );
    manager.endpoint.script.lock().unwrap().speeds = [
        Step::Block(Arc::new(Notify::new()), 200.0),
        Step::Speed(180.0),
        Step::Speed(170.0),
        Step::Speed(150.0),
    ]
    .into();
    let select = tokio::spawn(manager.clone().select());
    settle().await;
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 1);
    advance(2).await;
    let chosen = select.await.unwrap();
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].score, 150.0);
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (4 * MIB) as u64
    );
}

#[tokio::test(start_paused = true)]
async fn final_selection_rejects_failed_and_below_target_candidates() {
    let manager = Manager::new(FakeBackend::default(), test_config());
    manager.endpoint.script.lock().unwrap().speeds = [
        Step::Speed(300.0),
        Step::Speed(200.0),
        Step::Fail,
        Step::Speed(99.0),
        Step::Speed(150.0),
    ]
    .into();
    assert!(manager.clone().select().await.is_empty());
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (5 * MIB) as u64
    );
}

#[tokio::test(start_paused = true)]
async fn primary_health_io_failure_promotes_standby_immediately() {
    let (manager, primary, standby) = seeded(test_config()).await;
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .per_connection
        .insert(connection_id(&primary.connection), [Step::Fail].into());
    let _worker = run(&manager);
    settle().await;
    advance(2).await;
    assert!(!primary.healthy());
    assert_eq!(primary_id(&manager), standby.id);
    assert_eq!(manager.state.lock().unwrap().low, 0);
}

#[tokio::test(start_paused = true)]
async fn panicking_candidate_is_discarded_without_poisoning_selection() {
    let manager = Manager::new(FakeBackend::default(), test_config());
    manager.endpoint.script.lock().unwrap().dial_panics = [true, false].into();
    let selected = manager.clone().select().await;
    assert_eq!(selected.len(), 1);
    assert!(selected[0].healthy());
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn panicking_refill_stops_worker_and_releases_inflight_resources() {
    let (manager, primary, _) = seeded(test_config()).await;
    manager.state.lock().unwrap().standby = None;
    manager
        .endpoint
        .script
        .lock()
        .unwrap()
        .speeds
        .push_back(Step::Panic);
    let worker = run(&manager);
    settle().await;
    assert!(worker.0.is_finished());
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
    let probes = manager.probe_bytes.load(Ordering::Relaxed);
    advance(300).await;
    assert_eq!(manager.probe_bytes.load(Ordering::Relaxed), probes);
    assert!(primary.healthy());
    let stream = manager.open(attach()).await.unwrap();
    drop(stream);
    assert_eq!(primary.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn cloudflare_warm_is_nonblocking_and_does_not_create_a_direct_pool() {
    let endpoint = HttpsTransport::new(
        crate::transport::client_tls("").unwrap(),
        "localhost:443".into(),
        "localhost".into(),
        "test-token",
        None,
    )
    .unwrap();
    let cf = CfTransport::new(endpoint, test_config()).unwrap();
    let transport = ClientTransport::Cloudflare(cf);
    timeout(Duration::from_millis(1), transport.warm())
        .await
        .unwrap()
        .unwrap();
    let ClientTransport::Cloudflare(cf) = &transport else {
        unreachable!()
    };
    assert!(cf.manager.state.lock().unwrap().primary.is_none());
    assert_eq!(cf.manager.probe_bytes.load(Ordering::Relaxed), 0);
    drop(transport);
    settle().await;
}

#[path = "logging.rs"]
mod logging;

#[tokio::test(start_paused = true)]
async fn authentication_failure_discards_candidate_before_spending_probe_budget() {
    let manager = Manager::new(FakeBackend::default(), test_config());
    manager.endpoint.script.lock().unwrap().authentication = [Step::Fail, Step::Speed(0.0)].into();
    let selected = manager.clone().select().await;
    assert_eq!(selected.len(), 1);
    let script = manager.endpoint.script.lock().unwrap();
    let failed_id = script.downloads[0].0;
    assert!(
        script
            .downloads
            .iter()
            .all(|(id, bytes)| *id != failed_id || *bytes == 0)
    );
    assert_eq!(
        manager.probe_bytes.load(Ordering::Relaxed),
        (3 * MIB) as u64
    );
    assert_eq!(manager.endpoint.active.load(Ordering::SeqCst), 0);
}
