// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    auth::{TurnCredentials, VkAuth},
    dispatcher::Dispatcher,
    events::Events,
    obfs::ObfsMode,
    packet::PacketPool,
    session::{ConfigDeliveryState, SessionConfig, SessionRuntime, TurnAllocateError, run_session},
    stats::Stats,
};
use std::{
    collections::HashSet,
    net::SocketAddr,
    ops::Range,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub const WORKERS_PER_GROUP: usize = 9;
const _: () = assert!(WORKERS_PER_GROUP == 9);
pub const GROUPS_PER_CREDENTIAL: usize = 2;
pub const WORKERS_PER_CREDENTIAL: usize = WORKERS_PER_GROUP * GROUPS_PER_CREDENTIAL;
const _: () = assert!(WORKERS_PER_CREDENTIAL == 18);
pub const WORKER_START_INTERVAL: Duration = Duration::from_millis(100);
const CREDENTIAL_POST_DELAY: Duration = Duration::from_millis(100);
const RECOVERY_LOG_INTERVAL_MS: u64 = 10_000;
static RECOVERY_CLOCK: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
static NETWORK_RECOVERY_LOG: RecoveryLogGate = RecoveryLogGate::new();
static TURN_TIMEOUT_RECOVERY_LOG: RecoveryLogGate = RecoveryLogGate::new();
static WRAP_TIMEOUT_RECOVERY_LOG: RecoveryLogGate = RecoveryLogGate::new();
static GETCONF_TIMEOUT_RECOVERY_LOG: RecoveryLogGate = RecoveryLogGate::new();
static PEER_LIVENESS_RECOVERY_LOG: RecoveryLogGate = RecoveryLogGate::new();

struct RecoveryLogGate {
    pending: AtomicU64,
    next_report_ms: AtomicU64,
}

impl RecoveryLogGate {
    const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            next_report_ms: AtomicU64::new(0),
        }
    }

    fn observe(&self, now_ms: u64) -> Option<u64> {
        self.pending.fetch_add(1, Ordering::Relaxed);
        loop {
            let deadline = self.next_report_ms.load(Ordering::Acquire);
            if deadline != 0 && now_ms < deadline {
                return None;
            }
            let next = now_ms.saturating_add(RECOVERY_LOG_INTERVAL_MS).max(1);
            if self
                .next_report_ms
                .compare_exchange(deadline, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(self.pending.swap(0, Ordering::AcqRel));
            }
        }
    }
}

fn recovery_now_ms() -> u64 {
    RECOVERY_CLOCK
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub struct RuntimeParams {
    pub peer: SocketAddr,
    pub turn_host: Option<Arc<str>>,
    pub turn_port: Option<Arc<str>>,
    pub hashes: Arc<[String]>,
    pub wrap_key: [u8; 32],
    pub mode: ObfsMode,
    pub generation: u64,
    pub salt: Arc<str>,
    pub local_port: Arc<str>,
    pub device_id: Arc<str>,
    pub password: Arc<str>,
}

pub struct GroupContext {
    pub params: Arc<RuntimeParams>,
    pub auth: Arc<VkAuth>,
    pub dispatcher: Arc<Dispatcher>,
    pub pool: Arc<PacketPool>,
    pub stats: Arc<Stats>,
    pub events: Events,
    pub paused: Arc<AtomicBool>,
    pub config_tx: mpsc::Sender<String>,
    pub start_pacer: Arc<WorkerStartPacer>,
    pub credential_pacer: Arc<tokio::sync::Mutex<()>>,
    pub ready_credential_tx: Option<mpsc::UnboundedSender<usize>>,
    pub config_sent: Arc<AtomicBool>,
    pub config_in_flight: Arc<AtomicBool>,
    pub cancel: CancellationToken,
}

pub struct WorkerStartPacer {
    next: Mutex<Instant>,
    interval: Duration,
}

impl WorkerStartPacer {
    pub fn new(interval: Duration) -> Self {
        Self {
            next: Mutex::new(Instant::now()),
            interval,
        }
    }

    async fn wait(&self, cancel: &CancellationToken) -> bool {
        let mut next = tokio::select! {
            biased;
            _ = cancel.cancelled() => return false,
            next = self.next.lock() => next,
        };
        let scheduled = (*next).max(Instant::now());
        tokio::select! {
            biased;
            _ = cancel.cancelled() => false,
            _ = tokio::time::sleep_until(scheduled) => {
                *next = scheduled + self.interval;
                true
            },
        }
    }
}

struct ConfigFlightGuard {
    in_flight: Arc<AtomicBool>,
    acquired: bool,
}

impl ConfigFlightGuard {
    fn acquire(sent: &AtomicBool, in_flight: Arc<AtomicBool>) -> Self {
        let acquired = !sent.load(Ordering::Acquire)
            && in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        Self {
            in_flight,
            acquired,
        }
    }
}

impl Drop for ConfigFlightGuard {
    fn drop(&mut self) {
        if self.acquired {
            self.in_flight.store(false, Ordering::Release);
        }
    }
}

pub async fn run_groups(groups: usize, context: Arc<GroupContext>) {
    let credential_count = groups.div_ceil(GROUPS_PER_CREDENTIAL);
    let credentials: Vec<_> = (0..credential_count)
        .map(|credential_index| {
            let hash_index = credential_hash_index(credential_index, context.params.hashes.len());
            Arc::new(GroupCredentials {
                credential_id: credential_index + 1,
                hash: context.params.hashes[hash_index].clone(),
                context: context.clone(),
                state: tokio::sync::Mutex::new(None),
            })
        })
        .collect();
    let mut tasks = tokio::task::JoinSet::new();
    for group_index in 0..groups {
        let group_context = context.clone();
        let group_credentials = credentials[credential_index_for_group(group_index)].clone();
        tasks.spawn(async move {
            run_group(group_index + 1, group_context, group_credentials).await;
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            crate::log_error!("[СУПЕРВИЗОР] Задача группы завершилась аварийно: {error}");
        }
    }
}

async fn run_group(
    group_id: usize,
    context: Arc<GroupContext>,
    group_creds: Arc<GroupCredentials>,
) {
    while context.paused.load(Ordering::Acquire) {
        tokio::select! {
            _ = context.cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
    let mut workers = tokio::task::JoinSet::new();
    for id in group_worker_ids(group_id) {
        let worker_context = context.clone();
        let worker_creds = group_creds.clone();
        workers.spawn(async move {
            supervise_worker(id, worker_context, worker_creds).await;
        });
    }
    while let Some(result) = workers.join_next().await {
        if let Err(error) = result {
            crate::log_error!("[ГРУППА #{group_id}] Задача воркера завершилась аварийно: {error}");
        }
    }
    crate::log_error!("[ГРУППА #{group_id}] Все воркеры группы завершились.");
}

pub struct GroupCredentials {
    pub credential_id: usize,
    pub hash: String,
    pub context: Arc<GroupContext>,
    pub state: tokio::sync::Mutex<Option<TurnCredentials>>,
}

impl GroupCredentials {
    pub async fn get(&self) -> Option<TurnCredentials> {
        let mut state = self.state.lock().await;
        if let Some(creds) = &*state {
            return Some(creds.clone());
        }
        let credential_stream_id = credential_stream_id(self.credential_id);
        let _guard = tokio::select! {
            _ = self.context.cancel.cancelled() => return None,
            guard = self.context.credential_pacer.lock() => guard,
        };
        let short_hash: String = self.hash.chars().take(8).collect();
        crate::log_error!(
            "[КРЕД #{}] Запрос (хеш: {short_hash}...)",
            self.credential_id
        );
        let fetched = tokio::select! {
            _ = self.context.cancel.cancelled() => return None,
            result = self.context.auth.get_credentials(&self.hash, credential_stream_id) => result,
        };
        match fetched {
            Ok(creds) => {
                tokio::select! {
                    _ = self.context.cancel.cancelled() => return None,
                    _ = tokio::time::sleep(CREDENTIAL_POST_DELAY) => {}
                }
                crate::log_error!(
                    "[КРЕД #{}] OK, TURN: {:?}, до {} воркеров",
                    self.credential_id,
                    creds.server_addresses,
                    WORKERS_PER_CREDENTIAL
                );
                self.context.events.progress("credentials");
                *state = Some(creds.clone());
                Some(creds)
            }
            Err(error) => {
                crate::log_error!(
                    "[КРЕД #{}] Ошибка: {error:#}. Повторяем через 100мс...",
                    self.credential_id
                );
                tokio::select! {
                    _ = self.context.cancel.cancelled() => return None,
                    _ = tokio::time::sleep(CREDENTIAL_POST_DELAY) => {}
                }
                None
            }
        }
    }

    pub async fn invalidate(&self, bad_creds: &TurnCredentials) {
        let mut state = self.state.lock().await;
        if let Some(current) = &*state
            && same_turn_credentials(current, bad_creds)
        {
            *state = None;
            crate::log_error!(
                "[КРЕД #{}] Невалиден, запрашиваем новый",
                self.credential_id
            );
        }
    }
}

async fn supervise_worker(
    id: usize,
    context: Arc<GroupContext>,
    group_creds: Arc<GroupCredentials>,
) {
    let endpoint_cursor = Arc::new(AtomicUsize::new(0));
    loop {
        let task = tokio::spawn(worker_loop(
            id,
            context.clone(),
            group_creds.clone(),
            endpoint_cursor.clone(),
        ));
        match task.await {
            Ok(()) => return,
            Err(error) if error.is_panic() && !context.cancel.is_cancelled() => {
                crate::log_error!(
                    "[ВОРКЕР #{id}] Паника изолирована, перезапуск через 1 секунду: {error}"
                );
                tokio::select! {
                    _ = context.cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
            Err(error) => {
                crate::log_error!("[ВОРКЕР #{id}] Задача отменена: {error}");
                return;
            }
        }
    }
}

async fn worker_loop(
    id: usize,
    context: Arc<GroupContext>,
    group_creds: Arc<GroupCredentials>,
    endpoint_cursor: Arc<AtomicUsize>,
) {
    let mut attempt = 0usize;
    loop {
        if context.cancel.is_cancelled() {
            return;
        }
        let credentials = loop {
            if let Some(creds) = group_creds.get().await {
                break creds;
            }
            if context.cancel.is_cancelled() {
                return;
            }
        };
        if !context.start_pacer.wait(&context.cancel).await {
            return;
        }
        let config_guard =
            ConfigFlightGuard::acquire(&context.config_sent, context.config_in_flight.clone());
        let get_config = config_guard.acquired;
        let turn_endpoint_cursor = endpoint_cursor.fetch_add(1, Ordering::Relaxed);
        let session_config = SessionConfig {
            id,
            peer: context.params.peer,
            turn_host: context.params.turn_host.clone(),
            turn_port: context.params.turn_port.clone(),
            local_port: context.params.local_port.clone(),
            device_id: context.params.device_id.clone(),
            password: context.params.password.clone(),
            generation: context.params.generation,
            salt: context.params.salt.clone(),
            mode: context.params.mode,
            wrap_key: context.params.wrap_key,
            get_config,
            turn_endpoint_cursor,
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        let ready_credential_tx = context.ready_credential_tx.clone();
        let ready_credential = group_creds.credential_id;
        let ready_task = tokio::spawn(async move {
            let ready = ready_rx.await.is_ok();
            if ready && let Some(sender) = ready_credential_tx {
                let _ = sender.send(ready_credential);
            }
            ready
        });
        let result = run_session(
            session_config,
            credentials.clone(),
            SessionRuntime {
                dispatcher: context.dispatcher.clone(),
                pool: context.pool.clone(),
                stats: context.stats.clone(),
                events: context.events.clone(),
                config_tx: get_config.then(|| context.config_tx.clone()),
                config_delivery: get_config.then(|| ConfigDeliveryState {
                    sent: context.config_sent.clone(),
                    in_flight: context.config_in_flight.clone(),
                }),
                cancel: context.cancel.clone(),
                ready_tx: Some(ready_tx),
            },
        )
        .await;
        let was_ready = ready_task.await.unwrap_or(false);
        if was_ready {
            attempt = 0;
        }
        drop(config_guard);
        if context.cancel.is_cancelled() {
            return;
        }
        let mut delay = worker_retry_delay(attempt.max(1));
        if let Err(error) = &result {
            attempt = attempt.saturating_add(1);
            delay = worker_retry_delay(attempt);
            let message = error.to_string();
            let lower = message.to_ascii_lowercase();
            if should_invalidate_turn_credentials(error, &lower) {
                group_creds.invalidate(&credentials).await;
            }
            if is_local_network_down(error) {
                delay = Duration::from_millis(250 + rand::random::<u64>() % 751);
                if let Some(count) = NETWORK_RECOVERY_LOG.observe(recovery_now_ms()) {
                    crate::log_error!(
                        "[СЕТЬ][RETRY] Локальный маршрут недоступен, {count} попыток восстановления"
                    );
                }
            } else {
                if message.contains("FATAL_AUTH") || message.contains("хеш мёртв") {
                    delay = Duration::from_secs(5 + rand::random::<u64>() % 6);
                    crate::log_error!(
                        "[ВОРКЕР #{id}] Ошибка авторизации, изолированный повтор через {:?}: {message}",
                        delay
                    );
                } else if lower.contains("wrap_auth_timeout") {
                    if let Some(count) = WRAP_TIMEOUT_RECOVERY_LOG.observe(recovery_now_ms()) {
                        crate::log_error!(
                            "[HANDSHAKE][RETRY] WRAP_AUTH_TIMEOUT, {count} попыток восстановления"
                        );
                    }
                } else if lower.contains("getconf") && lower.contains("timeout") {
                    if let Some(count) = GETCONF_TIMEOUT_RECOVERY_LOG.observe(recovery_now_ms()) {
                        crate::log_error!(
                            "[GETCONF][RETRY] Нет подтверждения, {count} попыток восстановления"
                        );
                    }
                } else if lower.contains("path_unresponsive") {
                    if let Some(count) = PEER_LIVENESS_RECOVERY_LOG.observe(recovery_now_ms()) {
                        crate::log_error!(
                            "[СЕССИЯ][RETRY] Сервер перестал подтверждать канал, {count} попыток восстановления"
                        );
                    }
                } else if lower.contains("turn ") && lower.contains("transaction timeout") {
                    if let Some(count) = TURN_TIMEOUT_RECOVERY_LOG.observe(recovery_now_ms()) {
                        crate::log_error!(
                            "[TURN][RETRY] Нет ответа на служебную транзакцию, {count} попыток восстановления"
                        );
                    }
                } else if lower.contains("turn ") {
                    crate::log_error!("[ВОРКЕР #{id}] [TURN][RETRY] Попытка {attempt}: {message}");
                } else {
                    crate::log_error!("[ВОРКЕР #{id}] Ошибка (попытка {attempt}): {message}");
                }
                if lower.contains("getconf") {
                    delay = Duration::from_millis(100 + rand::random::<u64>() % 151);
                }
                if lower.contains("error 29") || lower.contains("cannot create socket") {
                    delay = Duration::from_secs(2 + rand::random::<u64>() % 3);
                    crate::log_error!(
                        "[ВОРКЕР #{id}] [СЕТЬ][RETRY] Временная ошибка сокета, пересоздаём транспорт через {:?}: {message}",
                        delay
                    );
                }
            }
        }
        tokio::select! {
            _ = context.cancel.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

fn worker_retry_delay(attempt: usize) -> Duration {
    worker_retry_delay_with_jitter(attempt, rand::random::<u64>() % 251)
}

fn worker_retry_delay_with_jitter(attempt: usize, jitter_ms: u64) -> Duration {
    let shift = attempt.saturating_sub(1).min(4) as u32;
    let base_ms = 250u64.saturating_mul(1u64 << shift).min(4_000);
    Duration::from_millis(base_ms.saturating_add(jitter_ms.min(250)))
}

fn should_invalidate_turn_credentials(error: &anyhow::Error, message: &str) -> bool {
    if let Some(stun_code) = error.chain().find_map(|cause| {
        cause
            .downcast_ref::<TurnAllocateError>()
            .and_then(TurnAllocateError::stun_code)
    }) {
        return matches!(stun_code, 401 | 441 | 486);
    }
    message.contains("turn allocate")
        && [
            "stun error 401",
            "stun error 441",
            "stun error 486",
            "unauthorized",
            "wrong credential",
            "authentication failed",
            "allocation quota reached",
            "quota reached",
        ]
        .iter()
        .any(|marker| message.contains(marker))
}

fn same_turn_credentials(left: &TurnCredentials, right: &TurnCredentials) -> bool {
    left.username == right.username
        && left.password == right.password
        && left.server_addresses == right.server_addresses
}

fn is_local_network_down(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                io_error.raw_os_error(),
                Some(100 | 101 | 113 | 10_050 | 10_051 | 10_065)
            )
        {
            return true;
        }
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    [
        "network is unreachable",
        "network is down",
        "no route to host",
        "no route to network",
        "enetunreach",
        "enetdown",
        "ehostunreach",
    ]
    .iter()
    .any(|marker| message.contains(marker))
        || [100, 101, 113, 10_050, 10_051, 10_065]
            .into_iter()
            .any(|code| contains_os_error_code(&message, code))
}

fn contains_os_error_code(message: &str, code: i32) -> bool {
    let needle = format!("os error {code}");
    message.match_indices(&needle).any(|(index, _)| {
        message[index + needle.len()..]
            .chars()
            .next()
            .is_none_or(|character| !character.is_ascii_digit())
    })
}

pub fn parse_hashes(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.split([',', ';', '\n', '\r', '\t', ' '])
        .filter_map(normalize_hash)
        .filter(|hash| seen.insert(hash.clone()))
        .collect()
}

fn normalize_hash(input: &str) -> Option<String> {
    let mut value = input.trim().trim_matches(['<', '>', '"', '\'']).to_owned();
    if value.is_empty() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if let Some(index) = lower.find("/call/join/") {
        value = value[index + "/call/join/".len()..].to_owned();
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        return None;
    }
    if let Some(index) = value.find(['?', '#', '/']) {
        value.truncate(index);
    }
    let value = value.trim().trim_matches('/');
    (!value.is_empty()).then(|| value.to_owned())
}

fn group_worker_ids(group_id: usize) -> Range<usize> {
    let first = (group_id - 1) * WORKERS_PER_GROUP + 1;
    first..first + WORKERS_PER_GROUP
}

fn credential_stream_id(credential_id: usize) -> usize {
    credential_id * 100
}

fn credential_index_for_group(group_index: usize) -> usize {
    group_index / GROUPS_PER_CREDENTIAL
}

fn credential_hash_index(credential_index: usize, hash_count: usize) -> usize {
    credential_index % hash_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_deduplicates_vk_hashes() {
        assert_eq!(
            parse_hashes("abc, https://vk.com/call/join/def?x=1;abc"),
            vec!["abc", "def"]
        );
    }

    #[test]
    fn rejects_unrelated_http_urls() {
        assert!(parse_hashes("https://example.com/not-a-call").is_empty());
    }

    #[test]
    fn every_credential_is_shared_by_at_most_two_complete_groups() {
        for group_id in 1..=18 {
            let workers: Vec<_> = group_worker_ids(group_id).collect();
            assert_eq!(workers.len(), WORKERS_PER_GROUP);
            assert_eq!(credential_index_for_group(group_id - 1), (group_id - 1) / 2);
        }
        for groups in 1usize..=18 {
            let credentials = groups.div_ceil(GROUPS_PER_CREDENTIAL);
            assert_eq!(credentials, groups.div_ceil(2));
            for credential_index in 0..credentials {
                let assigned = (0..groups)
                    .filter(|group_index| {
                        credential_index_for_group(*group_index) == credential_index
                    })
                    .count();
                assert!((1..=GROUPS_PER_CREDENTIAL).contains(&assigned));
                assert!(assigned * WORKERS_PER_GROUP <= WORKERS_PER_CREDENTIAL);
                assert_eq!(
                    credential_stream_id(credential_index + 1),
                    (credential_index + 1) * 100
                );
            }
        }
        assert_eq!(18usize.div_ceil(GROUPS_PER_CREDENTIAL), 9);
        for (workers, expected_credentials) in
            [(9, 1), (18, 1), (27, 2), (54, 3), (108, 6), (162, 9)]
        {
            let groups = workers / WORKERS_PER_GROUP;
            assert_eq!(groups.div_ceil(GROUPS_PER_CREDENTIAL), expected_credentials);
        }
    }

    #[test]
    fn credential_cohorts_are_even_for_every_supported_hash_count() {
        for hash_count in 1..=6 {
            for groups in 1usize..=18 {
                let mut counts = vec![0usize; hash_count];
                let credentials = groups.div_ceil(GROUPS_PER_CREDENTIAL);
                for credential_index in 0..credentials {
                    counts[credential_hash_index(credential_index, hash_count)] += 1;
                }
                assert_eq!(counts.iter().sum::<usize>(), credentials);
                let minimum = counts.iter().copied().min().unwrap();
                let maximum = counts.iter().copied().max().unwrap();
                assert!(maximum - minimum <= 1);
            }
        }
        assert_eq!([2, 2, 2, 2, 1], {
            let mut counts = [0usize; 5];
            for credential_index in 0..9 {
                counts[credential_hash_index(credential_index, 5)] += 1;
            }
            counts
        });
    }

    #[test]
    fn config_flight_is_globally_exclusive_and_released_by_drop() {
        let sent = AtomicBool::new(false);
        let in_flight = Arc::new(AtomicBool::new(false));
        let first = ConfigFlightGuard::acquire(&sent, in_flight.clone());
        assert!(first.acquired);
        let second = ConfigFlightGuard::acquire(&sent, in_flight.clone());
        assert!(!second.acquired);
        drop(first);
        let third = ConfigFlightGuard::acquire(&sent, in_flight);
        assert!(third.acquired);
    }

    #[test]
    fn delivered_config_prevents_new_flight() {
        let sent = AtomicBool::new(true);
        let in_flight = Arc::new(AtomicBool::new(false));
        let guard = ConfigFlightGuard::acquire(&sent, in_flight.clone());
        assert!(!guard.acquired);
        assert!(!in_flight.load(Ordering::Acquire));
    }

    #[tokio::test(start_paused = true)]
    async fn global_worker_start_pacer_spaces_all_162_starts_by_100_milliseconds() {
        let pacer = Arc::new(WorkerStartPacer::new(WORKER_START_INTERVAL));
        let cancel = CancellationToken::new();
        let started = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..162 {
            let pacer = pacer.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                assert!(pacer.wait(&cancel).await);
                Instant::now()
            });
        }
        let mut starts = Vec::with_capacity(162);
        while let Some(result) = tasks.join_next().await {
            starts.push(result.unwrap());
        }
        starts.sort_unstable();
        assert_eq!(starts.len(), 162);
        assert_eq!(starts[0], started);
        assert_eq!(
            starts[161].duration_since(started),
            Duration::from_millis(16_100)
        );
        assert!(
            starts
                .windows(2)
                .all(|pair| pair[1].duration_since(pair[0]) == WORKER_START_INTERVAL)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_worker_start_does_not_wait_for_a_reserved_slot() {
        let pacer = WorkerStartPacer::new(WORKER_START_INTERVAL);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(!pacer.wait(&cancel).await);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_queued_reconnect_does_not_consume_the_next_slot() {
        let pacer = Arc::new(WorkerStartPacer::new(WORKER_START_INTERVAL));
        let live = CancellationToken::new();
        assert!(pacer.wait(&live).await);
        let cancelled = CancellationToken::new();
        let queued = {
            let pacer = pacer.clone();
            let cancelled = cancelled.clone();
            tokio::spawn(async move { pacer.wait(&cancelled).await })
        };
        tokio::task::yield_now().await;
        cancelled.cancel();
        assert!(!queued.await.unwrap());
        let before = Instant::now();
        assert!(pacer.wait(&live).await);
        assert_eq!(Instant::now() - before, WORKER_START_INTERVAL);
    }

    #[tokio::test(start_paused = true)]
    async fn isolated_reconnect_after_idle_starts_immediately() {
        let pacer = WorkerStartPacer::new(WORKER_START_INTERVAL);
        let cancel = CancellationToken::new();
        assert!(pacer.wait(&cancel).await);
        tokio::time::advance(Duration::from_secs(60)).await;
        let before = Instant::now();
        assert!(pacer.wait(&cancel).await);
        assert_eq!(Instant::now(), before);
    }

    #[test]
    fn worker_retry_delay_is_bounded_and_caps_at_4250_milliseconds() {
        for (attempt, minimum_ms) in [
            (0, 250),
            (1, 250),
            (2, 500),
            (3, 1_000),
            (4, 2_000),
            (5, 4_000),
            (16, 4_000),
            (usize::MAX, 4_000),
        ] {
            assert_eq!(
                worker_retry_delay_with_jitter(attempt, 0),
                Duration::from_millis(minimum_ms)
            );
            assert_eq!(
                worker_retry_delay_with_jitter(attempt, u64::MAX),
                Duration::from_millis(minimum_ms + 250)
            );
        }
    }

    #[test]
    fn worker_retry_delay_is_monotonic_for_every_jitter_value() {
        for jitter_ms in 0..=250 {
            let delays: Vec<_> = (1..=32)
                .map(|attempt| worker_retry_delay_with_jitter(attempt, jitter_ms))
                .collect();
            assert!(delays.windows(2).all(|window| window[0] <= window[1]));
            assert_eq!(delays[0], Duration::from_millis(250 + jitter_ms));
            assert_eq!(delays[4], Duration::from_millis(4_000 + jitter_ms));
            assert_eq!(delays[31], Duration::from_millis(4_000 + jitter_ms));
        }
    }

    #[test]
    fn recovery_log_gate_coalesces_storms_without_losing_counts() {
        let gate = RecoveryLogGate::new();
        assert_eq!(gate.observe(0), Some(1));
        for now in 1..10_000 {
            assert_eq!(gate.observe(now), None);
        }
        assert_eq!(gate.observe(10_000), Some(10_000));
        for _ in 0..100_000 {
            assert_eq!(gate.observe(10_001), None);
        }
        assert_eq!(gate.observe(20_000), Some(100_001));
    }

    #[test]
    fn turn_credentials_are_invalidated_for_allocate_auth_and_quota_rejection() {
        let error = anyhow::anyhow!("TURN Allocate failed: unauthorized; STUN error 401");
        assert!(should_invalidate_turn_credentials(
            &error,
            "turn allocate failed: unauthorized; stun error 401"
        ));
        let error = anyhow::anyhow!("TURN Allocate failed: wrong credentials; STUN error 441");
        assert!(should_invalidate_turn_credentials(
            &error,
            "turn allocate failed: wrong credentials; stun error 441"
        ));
        let error =
            anyhow::anyhow!("TURN Allocate failed: Allocation Quota Reached; STUN error 486");
        assert!(should_invalidate_turn_credentials(
            &error,
            "turn allocate failed: allocation quota reached; stun error 486"
        ));
        let error = anyhow::anyhow!("PATH_UNRESPONSIVE: worker 4");
        assert!(!should_invalidate_turn_credentials(
            &error,
            "path_unresponsive: worker 4"
        ));
        let error = anyhow::anyhow!("TURN ChannelBind hard timeout");
        assert!(!should_invalidate_turn_credentials(
            &error,
            "turn channelbind hard timeout"
        ));
        let error = anyhow::anyhow!("TURN Allocate hard timeout");
        assert!(!should_invalidate_turn_credentials(
            &error,
            "turn allocate hard timeout"
        ));
        let error = anyhow::anyhow!("TURN Allocate failed: Unknown Attribute; STUN error 420");
        assert!(!should_invalidate_turn_credentials(
            &error,
            "turn allocate failed: unknown attribute; stun error 420"
        ));
        let error = anyhow::anyhow!("TURN Allocate failed: Insufficient Capacity; STUN error 508");
        assert!(!should_invalidate_turn_credentials(
            &error,
            "turn allocate failed: insufficient capacity; stun error 508"
        ));
    }

    #[test]
    fn credential_identity_includes_secret_and_not_only_turn_addresses() {
        let addresses: Arc<[Arc<str>]> = Arc::from([Arc::from("turn.example:3478")]);
        let first = TurnCredentials {
            username: Arc::from("first"),
            password: Arc::from("secret-a"),
            server_addresses: addresses.clone(),
        };
        let same = first.clone();
        let replacement = TurnCredentials {
            username: Arc::from("second"),
            password: Arc::from("secret-b"),
            server_addresses: addresses,
        };
        assert!(same_turn_credentials(&first, &same));
        assert!(!same_turn_credentials(&first, &replacement));
    }

    #[test]
    fn local_network_classifier_uses_io_codes_and_not_generic_timeouts() {
        assert!(is_local_network_down(&anyhow::Error::new(
            std::io::Error::from_raw_os_error(101)
        )));
        assert!(is_local_network_down(&anyhow::anyhow!(
            "writer: Network is unreachable (os error 101)"
        )));
        assert!(!is_local_network_down(&anyhow::anyhow!(
            "reader: read udp 127.0.0.1:3478: i/o timeout"
        )));
        assert!(!is_local_network_down(&anyhow::anyhow!(
            "PEER_LIVENESS_TIMEOUT"
        )));
        assert!(!is_local_network_down(&anyhow::anyhow!(
            "connect failed (os error 10061)"
        )));
        assert!(!is_local_network_down(&anyhow::anyhow!(
            "connect timed out (os error 10060)"
        )));
    }
}
