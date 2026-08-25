// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    auth::TurnCredentials,
    dispatcher::{Dispatcher, PacketReceiver, WorkerChannels, packet_channel},
    events::Events,
    obfs::{ObfsCipher, ObfsConfig, ObfsMode, ObfsState, is_rtp_packet},
    packet::{PacketBuf, PacketPool},
    protocol::{
        ConfigResponse, config_request, disconnect_request, is_config_response,
        is_control_response, is_panel_restart_notice, parse_config_response,
    },
    selective_fec,
    stats::Stats,
    turn::{TurnAllocation, TurnReceiver, TurnRequestError},
};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const KEEPALIVE_BYTE: u8 = 0xff;
const PATH_RECEIPT_ACK: &[u8] = b"\xffCSQTT_RX_ACK";
const PATH_PROBE_V2_MAGIC: &[u8; 4] = b"CSQ2";
const CONFIG_RESPONSE_TIMEOUT_MS: [u64; 3] = [750, 1_500, 3_000];
const DEALLOCATE_TIMEOUT: Duration = Duration::from_secs(1);
const CONNECT_CANCEL_GRACE: Duration = Duration::from_secs(1);
const SESSION_SHUTDOWN_GRACE: Duration = Duration::from_millis(1_500);
const DISCONNECT_SEND_TIMEOUT: Duration = Duration::from_millis(750);
const PATH_PROBE_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const PATH_PROBE_MISS_LIMIT: u8 = 3;
const PATH_PROBE_BYTES: usize = 45;
const PATH_PROBE_SCHEDULER_STALL: Duration = Duration::from_secs(5);
const WORKER_QUEUE_MAX_AGE: Duration = Duration::from_millis(2000);
const WORKER_NORMAL_CAPACITY: usize = 128;
const WORKER_SMALL_CAPACITY: usize = 128;
const WORKER_BULK_CAPACITY: usize = 256;
const WORKER_DOOMSDAY_CAPACITY: usize = 128;
const WRITER_SCHEDULE: [u8; 8] = [1, 2, 0, 2, 1, 2, 0, 2];
const WRITER_COMMAND_CAPACITY: usize = 4;
const WRITER_COMMAND_CHECK_PACKETS: usize = 32;
static NEXT_INCARNATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct TurnAllocateError(anyhow::Error);

impl TurnAllocateError {
    pub fn stun_code(&self) -> Option<i32> {
        self.0.chain().find_map(|cause| {
            cause
                .downcast_ref::<TurnRequestError>()
                .map(TurnRequestError::stun_code)
        })
    }
}

impl std::fmt::Display for TurnAllocateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "TURN Allocate: {:#}", self.0)
    }
}

impl std::error::Error for TurnAllocateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub struct SessionConfig {
    pub id: usize,
    pub peer: SocketAddr,
    pub turn_host: Option<Arc<str>>,
    pub turn_port: Option<Arc<str>>,
    pub local_port: Arc<str>,
    pub device_id: Arc<str>,
    pub password: Arc<str>,
    pub generation: u64,
    pub turn_endpoint_cursor: usize,
    pub salt: Arc<str>,
    pub mode: ObfsMode,
    pub wrap_key: [u8; 32],
    pub get_config: bool,
}

pub struct SessionRuntime {
    pub dispatcher: Arc<Dispatcher>,
    pub pool: Arc<PacketPool>,
    pub stats: Arc<Stats>,
    pub events: Events,
    pub config_tx: Option<mpsc::Sender<String>>,
    pub config_delivery: Option<ConfigDeliveryState>,
    pub cancel: CancellationToken,
    pub ready_tx: Option<oneshot::Sender<()>>,
}

pub struct ConfigDeliveryState {
    pub sent: Arc<AtomicBool>,
    pub in_flight: Arc<AtomicBool>,
}

impl ConfigDeliveryState {
    fn complete(&self, delivered: bool) {
        if delivered {
            self.sent.store(true, Ordering::Release);
        }
        self.in_flight.store(false, Ordering::Release);
    }
}

struct TransportShared {
    allocation: Arc<TurnAllocation>,
    cipher: ObfsCipher,
    config: ObfsConfig,
    pool: Arc<PacketPool>,
}

struct TransportWriter {
    shared: Arc<TransportShared>,
    write_state: ObfsState,
    fec_budget: selective_fec::Budget,
}

struct TransportReader {
    shared: Arc<TransportShared>,
    receiver: TurnReceiver,
    replay: ReplayProtection,
}

enum WriterCommand {
    SendBytes {
        data: Box<[u8]>,
        completion: oneshot::Sender<Result<()>>,
    },
}

struct WriterRuntime {
    normal: PacketReceiver,
    small: PacketReceiver,
    bulk: PacketReceiver,
    doomsday: PacketReceiver,
    commands: mpsc::Receiver<WriterCommand>,
    path_probe: Option<Box<[u8]>>,
    unanswered_probes: Arc<AtomicU8>,
    outstanding_probe: Arc<AtomicU64>,
    stats: Arc<Stats>,
    initial_path_validation: bool,
}

struct ReaderRuntime {
    dispatcher: Arc<Dispatcher>,
    unanswered_probes: Arc<AtomicU8>,
    outstanding_probe: Arc<AtomicU64>,
    stats: Arc<Stats>,
    events: Events,
    worker_id: usize,
}

struct ReplayWindow {
    highest: Option<u64>,
    seen: Box<[u64; 256]>,
}

#[derive(Default)]
struct ReplayProtection {
    rtp: ReplayWindow,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: Box::new([0; 256]),
        }
    }
}

impl ReplayWindow {
    fn accept(&mut self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.set_bit(counter);
            return true;
        };
        if counter > highest {
            let shift = counter - highest;
            if shift >= 16384 {
                self.seen.fill(0);
            } else {
                for i in 1..=shift {
                    self.clear_bit(highest + i);
                }
            }
            self.highest = Some(counter);
            self.set_bit(counter);
            return true;
        }
        let age = highest - counter;
        if age >= 16384 {
            return false;
        }
        if self.test_bit(counter) {
            return false;
        }
        self.set_bit(counter);
        true
    }

    fn set_bit(&mut self, counter: u64) {
        let idx = (counter % 16384) as usize;
        self.seen[idx / 64] |= 1 << (idx % 64);
    }

    fn clear_bit(&mut self, counter: u64) {
        let idx = (counter % 16384) as usize;
        self.seen[idx / 64] &= !(1 << (idx % 64));
    }

    fn test_bit(&self, counter: u64) -> bool {
        let idx = (counter % 16384) as usize;
        (self.seen[idx / 64] & (1 << (idx % 64))) != 0
    }

    fn accept_rtp(&mut self, sequence: u16) -> bool {
        let Some(highest) = self.highest else {
            return self.accept(sequence as u64);
        };
        let base = highest & !(u16::MAX as u64);
        let mut extended = base | sequence as u64;
        if extended.saturating_add(1 << 15) < highest {
            extended = extended.saturating_add(1 << 16);
        } else if extended > highest.saturating_add(1 << 15) && extended >= 1 << 16 {
            extended -= 1 << 16;
        }
        self.accept(extended)
    }
}

struct ActiveConnection {
    stats: Arc<Stats>,
    events: Events,
}

struct WorkerRegistration {
    dispatcher: Arc<Dispatcher>,
    id: usize,
    incarnation_id: u64,
}

impl WorkerRegistration {
    fn new(dispatcher: Arc<Dispatcher>, id: usize, incarnation_id: u64) -> Self {
        Self {
            dispatcher,
            id,
            incarnation_id,
        }
    }
}

impl Drop for WorkerRegistration {
    fn drop(&mut self) {
        self.dispatcher.unregister(self.id, self.incarnation_id);
    }
}

fn authenticate_inbound(
    cipher: &ObfsCipher,
    config: &ObfsConfig,
    replay: &mut ReplayProtection,
    packet: &mut PacketBuf,
) -> bool {
    is_rtp_packet(packet.as_slice())
        && cipher
            .unwrap(packet, config.mode)
            .is_ok_and(|sequence| replay.rtp.accept_rtp(sequence))
}

impl ActiveConnection {
    fn new(stats: Arc<Stats>, events: Events) -> Self {
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { stats, events }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        if self.stats.active_connections.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.events.active_zero();
        }
    }
}

impl TransportWriter {
    fn new(shared: Arc<TransportShared>) -> Self {
        Self {
            shared,
            write_state: ObfsState::new(),
            fec_budget: selective_fec::Budget::new(),
        }
    }

    async fn send_data(&mut self, packet: PacketBuf) -> Result<()> {
        self.send_packet(packet).await
    }

    async fn send_packet(&mut self, mut packet: PacketBuf) -> Result<()> {
        let duplicate =
            selective_fec::should_duplicate(packet.as_slice()) && self.fec_budget.allow();
        self.shared
            .cipher
            .wrap(&mut packet, &self.shared.config, &mut self.write_state)?;
        self.shared
            .allocation
            .send_with_duplicate(&mut packet, duplicate)
            .await?;
        Ok(())
    }

    async fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        let pool = self.shared.pool.clone();
        self.send_bytes_with_pool(data, &pool).await
    }

    async fn send_bytes_with_pool(&mut self, data: &[u8], pool: &Arc<PacketPool>) -> Result<()> {
        let mut packet = pool.try_acquire().context("packet budget exhausted")?;
        if data.len() > packet.read_area().len() {
            bail!("transport payload too large: {}", data.len());
        }
        packet.read_area()[..data.len()].copy_from_slice(data);
        packet.set_read_len(data.len())?;
        self.send_packet(packet).await
    }
}

impl TransportReader {
    fn new(shared: Arc<TransportShared>, receiver: TurnReceiver) -> Self {
        Self {
            shared,
            receiver,
            replay: ReplayProtection::default(),
        }
    }

    async fn recv(&mut self) -> Result<PacketBuf> {
        loop {
            let mut packet = self
                .receiver
                .recv()
                .await
                .context("TURN allocation receive")?;
            if authenticate_inbound(
                &self.shared.cipher,
                &self.shared.config,
                &mut self.replay,
                &mut packet,
            ) {
                return Ok(packet);
            }
        }
    }
}

pub async fn run_session(
    config: SessionConfig,
    credentials: TurnCredentials,
    runtime: SessionRuntime,
) -> Result<bool> {
    if credentials.server_addresses.is_empty() {
        bail!("РЅРµС‚ TURN URL РІ СѓС‡РµС‚РЅС‹С… РґР°РЅРЅС‹С…");
    }
    let selected = credentials.server_addresses[turn_endpoint_index(
        config.id,
        config.turn_endpoint_cursor,
        credentials.server_addresses.len(),
    )]
    .as_ref();
    let turn_address = override_turn_address(
        selected,
        config.turn_host.as_deref(),
        config.turn_port.as_deref(),
    )?;
    crate::log_error!("[TURN] Подключение к {turn_address}");
    let cancel = runtime.cancel.clone();
    let mut connect = Box::pin(TurnAllocation::connect(
        &turn_address,
        credentials.username,
        credentials.password,
        config.peer,
        runtime.pool.clone(),
    ));
    let allocation = tokio::select! {
        biased;
        result = &mut connect => result.map_err(TurnAllocateError)?,
        _ = cancel.cancelled() => {
            if let Ok(Ok(allocation)) = tokio::time::timeout(CONNECT_CANCEL_GRACE, &mut connect).await {
                let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
            }
            return Ok(false);
        },
    };
    crate::log_error!(
        "[РЎР•РЎРЎР˜РЇ #{}] Relay: {}",
        config.id,
        allocation.local_addr()
    );
    let channel = tokio::select! {
        biased;
        result = allocation.prepare_channel() => result,
        _ = cancel.cancelled() => {
            let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
            return Ok(false);
        },
    };
    if let Err(error) = channel {
        let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
        return Err(error.context("TURN ChannelBind РѕР±СЏР·Р°С‚РµР»РµРЅ"));
    }
    let session = tokio::spawn(run_allocated_session(
        config,
        runtime,
        allocation.clone(),
    ));
    let result = await_session_task(&cancel, session).await;
    let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
    result
}

async fn await_session_task(
    cancel: &CancellationToken,
    mut session: JoinHandle<Result<bool>>,
) -> Result<bool> {
    tokio::select! {
        biased;
        result = &mut session => match result {
            Ok(result) => result,
            Err(error) if error.is_panic() => Err(anyhow!("РїР°РЅРёРєР° СЃРµСЃСЃРёРё РёР·РѕР»РёСЂРѕРІР°РЅР°: {error}")),
            Err(error) => Err(anyhow!("Р·Р°РґР°С‡Р° СЃРµСЃСЃРёРё Р·Р°РІРµСЂС€РµРЅР° Р°РІР°СЂРёР№РЅРѕ: {error}")),
        },
        _ = cancel.cancelled() => {
            match tokio::time::timeout(SESSION_SHUTDOWN_GRACE, &mut session).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) if error.is_panic() => {
                    Err(anyhow!("session panicked during graceful shutdown: {error}"))
                }
                Ok(Err(error)) => {
                    Err(anyhow!("session stopped during graceful shutdown: {error}"))
                }
                Err(_) => {
                    session.abort();
                    let _ = session.await;
                    Ok(false)
                }
            }
        }
    }
}

async fn run_allocated_session(
    config: SessionConfig,
    mut runtime: SessionRuntime,
    allocation: Arc<TurnAllocation>,
) -> Result<bool> {
    let session_cancel = CancellationToken::new();
    let turn_receiver = allocation.take_receiver()?;
    crate::log_error!(
        "[РЎР•РЎРЎРРЇ #{}] [DIRECT] РџСЂСЏРјРѕР№ СЂРµР¶РёРј РѕР±С„СѓСЃРєР°С†РёРё ({:?})",
        config.id,
        config.mode
    );
    let shared = Arc::new(TransportShared {
        allocation,
        cipher: ObfsCipher::new(config.wrap_key)?,
        config: ObfsConfig::new(config.mode),
        pool: runtime.pool.clone(),
    });
    let mut writer_transport = TransportWriter::new(shared.clone());
    let mut reader_transport = TransportReader::new(shared, turn_receiver);
    let incarnation_id = NEXT_INCARNATION_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let config_tx = config.get_config.then_some(runtime.config_tx).flatten();
    let config_delivered = match request_configuration(
        &mut writer_transport,
        &mut reader_transport,
        &config,
        &runtime.events,
        config_tx,
    )
    .await
    {
        Ok(delivered) => {
            let delivered = config.get_config && delivered;
            if let Some(state) = &runtime.config_delivery {
                state.complete(delivered);
            }
            delivered
        }
        Err(error) => {
            if let Some(state) = &runtime.config_delivery {
                state.complete(false);
            }
            return Err(error);
        }
    };
    let (normal_tx, normal_rx) = packet_channel(WORKER_NORMAL_CAPACITY, WORKER_QUEUE_MAX_AGE, true);
    let (small_tx, small_rx) = packet_channel(WORKER_SMALL_CAPACITY, WORKER_QUEUE_MAX_AGE, true);
    let (bulk_tx, bulk_rx) = packet_channel(WORKER_BULK_CAPACITY, WORKER_QUEUE_MAX_AGE, true);
    let (doomsday_tx, doomsday_rx) =
        packet_channel(WORKER_DOOMSDAY_CAPACITY, WORKER_QUEUE_MAX_AGE, true);
    let worker_channels = WorkerChannels {
        id: config.id,
        incarnation_id,
        normal: normal_tx,
        small: small_tx,
        bulk: bulk_tx,
        doomsday: doomsday_tx,
    };
    runtime.dispatcher.register(worker_channels.clone());
    let _registration =
        WorkerRegistration::new(runtime.dispatcher.clone(), config.id, incarnation_id);
    if let Some(ready_tx) = runtime.ready_tx.take() {
        let _ = ready_tx.send(());
    }
    crate::log_error!(
        "[Р’РћР РљР•Р  #{}] [READY] РџРѕС‚РѕРє РіРѕС‚РѕРІ вњ“",
        config.id
    );
    runtime.events.ready(config.id);
    let _active = ActiveConnection::new(runtime.stats.clone(), runtime.events.clone());
    let (writer_command_tx, writer_command_rx) = mpsc::channel(WRITER_COMMAND_CAPACITY);
    let path_probe = smart_ping_payload(&config.device_id, config.generation, config.id);
    let initial_path_validation = false;
    let unanswered_probes = Arc::new(AtomicU8::new(0));
    let outstanding_probe = Arc::new(AtomicU64::new(0));
    let mut writer = tokio::spawn(writer_loop(
        writer_transport,
        WriterRuntime {
            normal: normal_rx,
            small: small_rx,
            bulk: bulk_rx,
            doomsday: doomsday_rx,
            commands: writer_command_rx,
            path_probe,
            unanswered_probes: unanswered_probes.clone(),
            outstanding_probe: outstanding_probe.clone(),
            stats: runtime.stats.clone(),
            initial_path_validation,
        },
        session_cancel.clone(),
    ));
    let mut reader = tokio::spawn(reader_loop(
        reader_transport,
        ReaderRuntime {
            dispatcher: runtime.dispatcher.clone(),
            unanswered_probes,
            outstanding_probe,
            stats: runtime.stats.clone(),
            events: runtime.events.clone(),
            worker_id: config.id,
        },
        session_cancel.clone(),
    ));
    let (session_result, completed): (Result<()>, u8) = tokio::select! {
        _ = runtime.cancel.cancelled() => {
            let request = disconnect_request(&config.device_id, &config.salt);
            let _ = tokio::time::timeout(
                DISCONNECT_SEND_TIMEOUT,
                send_writer_bytes(&writer_command_tx, request.as_bytes()),
            ).await;
            (Ok(()), 0)
        }
        result = &mut writer => {
            (result.map_err(anyhow::Error::from).and_then(|value| value), 1)
        }
        result = &mut reader => {
            (result.map_err(anyhow::Error::from).and_then(|value| value), 2)
        }
    };
    session_cancel.cancel();
    stop_session_tasks(completed, writer, reader).await;
    crate::log_error!("[РЎР•РЎРЎРРЇ #{}] Р—Р°РІРµСЂС€РµРЅР°", config.id);
    session_result?;
    Ok(config_delivered)
}

async fn stop_session_tasks(
    completed: u8,
    writer: JoinHandle<Result<()>>,
    reader: JoinHandle<Result<()>>,
) {
    match completed {
        0 => {
            writer.abort();
            reader.abort();
            let _ = writer.await;
            let _ = reader.await;
        }
        1 => {
            reader.abort();
            let _ = reader.await;
        }
        _ => {
            writer.abort();
            let _ = writer.await;
        }
    }
}

async fn request_configuration(
    writer: &mut TransportWriter,
    reader: &mut TransportReader,
    config: &SessionConfig,
    events: &Events,
    config_tx: Option<mpsc::Sender<String>>,
) -> Result<bool> {
    let request = config_request(
        &config.local_port,
        &config.device_id,
        &config.password,
        config.generation,
        &config.salt,
        config.id,
    );
    'attempts: for (attempt, timeout_ms) in CONFIG_RESPONSE_TIMEOUT_MS.into_iter().enumerate() {
        writer
            .send_bytes(request.as_bytes())
            .await
            .context("РѕС‚РїСЂР°РІРєР° GETCONF")?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let packet = loop {
            match tokio::time::timeout_at(deadline, reader.recv()).await {
                Ok(result) => {
                    let packet =
                        result.context("GETCONF С‡С‚РµРЅРёРµ РѕС‚РІРµС‚Р° РєРѕРЅС„РёРіР°")?;
                    if is_panel_restart_notice(packet.as_slice()) {
                        events.panel_restart();
                        continue;
                    }
                    if !is_config_response(packet.as_slice()) {
                        continue;
                    }
                    break packet;
                }
                Err(_) if attempt + 1 < CONFIG_RESPONSE_TIMEOUT_MS.len() => continue 'attempts,
                Err(_) => {
                    bail!(
                        "GETCONF С‡С‚РµРЅРёРµ РѕС‚РІРµС‚Р° РєРѕРЅС„РёРіР°: timeout РїРѕСЃР»Рµ {} РїРѕРїС‹С‚РѕРє",
                        CONFIG_RESPONSE_TIMEOUT_MS.len()
                    )
                }
            }
        };
        match parse_config_response(packet.as_slice())? {
            ConfigResponse::NoConfig => return Ok(false),
            ConfigResponse::Config(value) => {
                if let Some(sender) = &config_tx {
                    let _ = sender.try_send(value);
                }
                crate::log_error!("[Р’РћР РљР•Р  #{}] РљРѕРЅС„РёРі РїРѕР»СѓС‡РµРЅ", config.id);
                return Ok(true);
            }
        }
    }
    bail!("GETCONF РѕС‚РІРµС‚ РЅРµ РїРѕР»СѓС‡РµРЅ")
}

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_PACKET: [u8; 16] = [KEEPALIVE_BYTE; 16];

async fn writer_loop(
    mut transport: TransportWriter,
    runtime: WriterRuntime,
    cancel: CancellationToken,
) -> Result<()> {
    let WriterRuntime {
        normal,
        small,
        bulk,
        doomsday,
        mut commands,
        mut path_probe,
        unanswered_probes,
        outstanding_probe,
        stats,
        initial_path_validation,
    } = runtime;
    let mut schedule = 0;
    let mut packets_since_command = WRITER_COMMAND_CHECK_PACKETS;
    let mut validation_generation = crate::path_validation::generation();
    let mut next_probe = Instant::now();
    let mut validation_active = initial_path_validation && path_probe.is_some();
    let mut validation_sent = false;
    let jitter_ms = (rand::random::<u64>() % 4000) as u64;
    let mut next_keepalive = Instant::now() + KEEPALIVE_INTERVAL + Duration::from_millis(jitter_ms);
    loop {
        let now = Instant::now();
        let current_generation = crate::path_validation::generation();
        if current_generation != validation_generation {
            validation_generation = current_generation;
            unanswered_probes.store(0, Ordering::Release);
            validation_active = path_probe.is_some();
            validation_sent = false;
            next_probe = now;
        }
        if validation_active && validation_sent && unanswered_probes.load(Ordering::Acquire) == 0 {
            validation_active = false;
        }
        if validation_active && now >= next_probe {
            reset_probe_misses_after_scheduler_stall(now, next_probe, &unanswered_probes, &stats);
            send_path_probe(
                &mut transport,
                path_probe.as_deref_mut().unwrap_or_default(),
                &unanswered_probes,
                &outstanding_probe,
                &stats,
            )
            .await?;
            validation_sent = true;
            next_probe = Instant::now() + PATH_PROBE_RECOVERY_INTERVAL;
        }
        if now >= next_keepalive {
            let _ = transport.send_bytes(&KEEPALIVE_PACKET).await;
            let jitter_ms = (rand::random::<u64>() % 4000) as u64;
            next_keepalive = Instant::now() + KEEPALIVE_INTERVAL + Duration::from_millis(jitter_ms);
        }
        if packets_since_command >= WRITER_COMMAND_CHECK_PACKETS {
            if let Ok(command) = commands.try_recv() {
                handle_writer_command(&mut transport, command).await?;
                packets_since_command = 0;
                continue;
            }
            packets_since_command = 0;
        }
        if let Some(packet) = doomsday.try_recv() {
            transport.send_data(packet).await?;
            packets_since_command += 1;
            continue;
        }

        let packet = if let Some(packet) =
            next_scheduled_packet(&normal, &small, &bulk, &mut schedule)
        {
            Some(packet)
        } else if normal.is_closed()
            && small.is_closed()
            && bulk.is_closed()
            && doomsday.is_closed()
        {
            None
        } else {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                command = commands.recv() => {
                    if let Some(command) = command {
                        handle_writer_command(&mut transport, command).await?;
                    }
                    continue;
                }
                generation = crate::path_validation::changed(validation_generation) => {
                    validation_generation = generation;
                    unanswered_probes.store(0, Ordering::Release);
                    validation_active = path_probe.is_some();
                    validation_sent = false;
                    next_probe = Instant::now();
                    continue;
                }
                _ = tokio::time::sleep_until(next_probe.into()), if validation_active => continue,
                _ = tokio::time::sleep_until(next_keepalive.into()) => continue,
                packet = doomsday.recv(&cancel) => packet,
                packet = small.recv(&cancel) => packet,
                packet = normal.recv(&cancel) => packet,
                packet = bulk.recv(&cancel) => packet,
            }
        };
        let Some(packet) = packet else {
            if cancel.is_cancelled()
                || (normal.is_closed()
                    && small.is_closed()
                    && bulk.is_closed()
                    && doomsday.is_closed())
            {
                return Ok(());
            }
            continue;
        };
        transport.send_data(packet).await?;
        packets_since_command += 1;
    }
}

async fn send_path_probe(
    transport: &mut TransportWriter,
    payload: &mut [u8],
    unanswered_probes: &AtomicU8,
    outstanding_probe: &AtomicU64,
    stats: &Stats,
) -> Result<()> {
    let incremented =
        unanswered_probes.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < PATH_PROBE_MISS_LIMIT).then_some(count + 1)
        });
    let Ok(previous) = incremented else {
        stats.path_unresponsive.fetch_add(1, Ordering::Relaxed);
        bail!("PATH_UNRESPONSIVE: server did not acknowledge path probes");
    };
    if previous > 0 {
        stats.path_probe_misses.fetch_add(1, Ordering::Relaxed);
    }
    let previous_sequence = outstanding_probe
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(current.wrapping_add(1).max(1))
        })
        .unwrap_or_default();
    let sequence = previous_sequence.wrapping_add(1).max(1);
    payload[31..39].copy_from_slice(&sequence.to_be_bytes());
    match transport.send_bytes(payload).await {
        Ok(()) => {
            stats.path_probes_sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(error) => {
            stats.path_probe_send_errors.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    }
}

fn reset_probe_misses_after_scheduler_stall(
    now: Instant,
    deadline: Instant,
    unanswered_probes: &AtomicU8,
    stats: &Stats,
) -> bool {
    if now.saturating_duration_since(deadline) < PATH_PROBE_SCHEDULER_STALL {
        return false;
    }
    if unanswered_probes.swap(0, Ordering::AcqRel) > 0 {
        stats.path_scheduler_resets.fetch_add(1, Ordering::Relaxed);
    }
    true
}

async fn handle_writer_command(
    transport: &mut TransportWriter,
    command: WriterCommand,
) -> Result<()> {
    match command {
        WriterCommand::SendBytes { data, completion } => {
            let result = transport.send_bytes(&data).await;
            let _ = completion.send(result);
            Ok(())
        }
    }
}

async fn send_writer_bytes(sender: &mpsc::Sender<WriterCommand>, data: &[u8]) -> Result<()> {
    let (completion, result) = oneshot::channel();
    sender
        .send(WriterCommand::SendBytes {
            data: Box::from(data),
            completion,
        })
        .await
        .context("writer command queue closed")?;
    result.await.context("writer command response closed")?
}

fn next_scheduled_packet(
    normal: &PacketReceiver,
    small: &PacketReceiver,
    bulk: &PacketReceiver,
    schedule: &mut usize,
) -> Option<PacketBuf> {
    for _ in 0..WRITER_SCHEDULE.len() {
        let class = WRITER_SCHEDULE[*schedule % WRITER_SCHEDULE.len()];
        *schedule = (*schedule).wrapping_add(1);
        let packet = match class {
            0 => normal.try_recv(),
            1 => small.try_recv(),
            _ => bulk.try_recv(),
        };
        if packet.is_some() {
            return packet;
        }
    }
    None
}

async fn reader_loop(
    mut transport: TransportReader,
    runtime: ReaderRuntime,
    cancel: CancellationToken,
) -> Result<()> {
    let ReaderRuntime {
        dispatcher,
        unanswered_probes,
        outstanding_probe,
        stats,
        events,
        worker_id,
    } = runtime;
    loop {
        let packet = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            result = transport.recv() => result?,
        };
        let is_legacy_ack = is_keepalive(packet.as_slice());
        let is_current_ack = parse_path_ack(packet.as_slice()).is_some_and(|(worker, sequence)| {
            usize::from(worker) == worker_id
                && sequence != 0
                && sequence == outstanding_probe.load(Ordering::Acquire)
        });
        let is_path_ack = is_legacy_ack || is_current_ack;
        if is_path_ack || (!packet.as_slice().starts_with(PATH_RECEIPT_ACK)) {
            unanswered_probes.store(0, Ordering::Release);
        }
        if is_path_ack {
            stats.path_probe_acks.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if packet.as_slice().starts_with(PATH_RECEIPT_ACK) {
            continue;
        }
        if is_panel_restart_notice(packet.as_slice()) {
            events.panel_restart();
            continue;
        }
        if is_control_response(packet.as_slice()) {
            continue;
        }
        deliver_inbound_packet(&dispatcher, packet);
    }
}

fn deliver_inbound_packet(dispatcher: &Dispatcher, packet: PacketBuf) {
    dispatcher.return_packet(packet);
}

fn is_keepalive(packet: &[u8]) -> bool {
    !packet.is_empty() && packet.iter().all(|byte| *byte == KEEPALIVE_BYTE)
}

fn smart_ping_payload(device_id: &str, generation: u64, worker_id: usize) -> Option<Box<[u8]>> {
    let device = device_id.as_bytes();
    let worker_id = u16::try_from(worker_id).ok()?;
    if device.is_empty() || device.len() > 16 || worker_id == 0 || worker_id > 162 {
        return None;
    }
    let mut payload = vec![KEEPALIVE_BYTE; PATH_PROBE_BYTES];
    payload[1..17].fill(0);
    payload[1..1 + device.len()].copy_from_slice(device);
    payload[17..25].copy_from_slice(&generation.to_be_bytes());
    payload[25..29].copy_from_slice(PATH_PROBE_V2_MAGIC);
    payload[29..31].copy_from_slice(&worker_id.to_be_bytes());
    payload[31..39].fill(0);
    Some(payload.into_boxed_slice())
}

fn parse_path_ack(payload: &[u8]) -> Option<(u16, u64)> {
    if payload.len() != PATH_RECEIPT_ACK.len() + 10 || !payload.starts_with(PATH_RECEIPT_ACK) {
        return None;
    }
    let offset = PATH_RECEIPT_ACK.len();
    let worker = u16::from_be_bytes(payload[offset..offset + 2].try_into().ok()?);
    let sequence = u64::from_be_bytes(payload[offset + 2..offset + 10].try_into().ok()?);
    Some((worker, sequence))
}

fn turn_endpoint_index(id: usize, cursor: usize, endpoint_count: usize) -> usize {
    debug_assert!(endpoint_count > 0);
    (id % endpoint_count + cursor % endpoint_count) % endpoint_count
}

fn override_turn_address(address: &str, host: Option<&str>, port: Option<&str>) -> Result<String> {
    let address = address.trim();
    let lower = address.to_ascii_lowercase();
    if lower.starts_with("turns:") {
        bail!("TURN TLS endpoint cannot be used by UDP transport");
    }
    let address = if lower.starts_with("turn:") {
        &address["turn:".len()..]
    } else {
        address
    };
    let (clean, query) = address.split_once('?').unwrap_or((address, ""));
    for parameter in query.split('&').filter(|parameter| !parameter.is_empty()) {
        let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if key.eq_ignore_ascii_case("transport") && !value.eq_ignore_ascii_case("udp") {
            bail!("non-UDP TURN endpoint rejected");
        }
    }
    let (original_host, original_port) =
        split_host_port(clean).with_context(|| format!("СЂР°Р·Р±РѕСЂ TURN URL {address:?}"))?;
    let selected_host = host
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| original_host.to_owned());
    let selected_port = port
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| original_port.to_owned());
    if selected_host.contains(':') && !selected_host.starts_with('[') {
        Ok(format!("[{selected_host}]:{selected_port}"))
    } else {
        Ok(format!("{selected_host}:{selected_port}"))
    }
}

fn split_host_port(address: &str) -> Result<(&str, &str)> {
    if let Some(rest) = address.strip_prefix('[') {
        return rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("IPv6 TURN address has no port"));
    }
    address
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("TURN address has no port"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::future::pending;

    #[test]
    fn udp_session_rejects_tls_and_tcp_turn_endpoints_defensively() {
        assert!(override_turn_address("turns:relay.example:5349", None, None).is_err());
        assert!(
            override_turn_address(
                "turn:relay.example:3478?transport=tcp",
                Some("override.example"),
                Some("3478"),
            )
            .is_err()
        );
        assert_eq!(
            override_turn_address(
                "turn:relay.example:3478?transport=udp",
                Some("override.example"),
                Some("19302"),
            )
            .unwrap(),
            "override.example:19302"
        );
    }

    #[derive(Clone, Copy, Default)]
    struct ReplayCoverage {
        duplicate: usize,
        age_16383: usize,
        age_16384: usize,
        age_16385: usize,
        forward_small: usize,
        forward_large: usize,
    }

    impl ReplayCoverage {
        fn complete(self) -> bool {
            self.duplicate > 0
                && self.age_16383 > 0
                && self.age_16384 > 0
                && self.age_16385 > 0
                && self.forward_small > 0
                && self.forward_large > 0
        }
    }

    struct DropFlag(Arc<AtomicBool>);

    fn model_accept(
        highest: &mut Option<u64>,
        seen: &mut HashSet<u64>,
        counter: u64,
        model_window: u64,
    ) -> bool {
        match *highest {
            None => {
                *highest = Some(counter);
                seen.insert(counter);
                true
            }
            Some(current) if counter > current => {
                *highest = Some(counter);
                seen.retain(|value| counter - *value < model_window);
                seen.insert(counter);
                true
            }
            Some(current) if current - counter >= model_window => false,
            Some(_) => seen.insert(counter),
        }
    }

    fn replay_trace_matches(counters: &[u64], model_window: u64) -> bool {
        let mut window = ReplayWindow::default();
        let mut highest = None;
        let mut seen = HashSet::new();
        for &counter in counters {
            let expected = model_accept(&mut highest, &mut seen, counter, model_window);
            if window.accept(counter) != expected {
                return false;
            }
        }
        true
    }

    fn replay_trace_coverage(counters: &[u64]) -> ReplayCoverage {
        let mut highest = None;
        let mut seen = HashSet::new();
        let mut coverage = ReplayCoverage::default();
        for &counter in counters {
            if seen.contains(&counter) {
                coverage.duplicate += 1;
            }
            if let Some(current) = highest {
                if counter > current {
                    let delta = counter - current;
                    if delta < 16384 {
                        coverage.forward_small += 1;
                    } else {
                        coverage.forward_large += 1;
                    }
                } else {
                    match current - counter {
                        16383 => coverage.age_16383 += 1,
                        16384 => coverage.age_16384 += 1,
                        16385 => coverage.age_16385 += 1,
                        _ => {}
                    }
                }
            }
            model_accept(&mut highest, &mut seen, counter, 16384);
        }
        coverage
    }

    fn extend_rtp_reference(highest: u64, sequence: u16) -> u64 {
        let base = highest & !(u16::MAX as u64);
        let current = base | u64::from(sequence);
        let previous = current.checked_sub(1 << 16);
        let next = current.saturating_add(1 << 16);
        let mut selected = current;
        let mut distance = current.abs_diff(highest);
        if let Some(previous) = previous {
            let candidate_distance = previous.abs_diff(highest);
            if candidate_distance < distance {
                selected = previous;
                distance = candidate_distance;
            }
        }
        if next.abs_diff(highest) < distance {
            selected = next;
        }
        selected
    }

    fn rtp_trace_matches(sequences: &[u16]) -> bool {
        let mut window = ReplayWindow::default();
        let mut highest = None;
        let mut seen = HashSet::new();
        for &sequence in sequences {
            let extended = highest
                .map(|value| extend_rtp_reference(value, sequence))
                .unwrap_or(u64::from(sequence));
            let expected = model_accept(&mut highest, &mut seen, extended, 16384);
            if window.accept_rtp(sequence) != expected {
                return false;
            }
        }
        true
    }

    fn mix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn deterministic_replay_trace(seed: u64, length: usize) -> Vec<u64> {
        let mut state = seed;
        let mut counters = Vec::with_capacity(length);
        let prefix = [1_000, 1_000, 1_001, 17_385, 1_002, 1_001, 1_000, 25_000];
        counters.extend(prefix.into_iter().take(length));
        let mut highest = (seed & 0xffff).max(counters.iter().copied().max().unwrap_or(0));
        for _ in counters.len()..length {
            state = mix64(state);
            let counter = match state % 8 {
                0 => highest,
                1 => highest.saturating_sub(16383),
                2 => highest.saturating_sub(16384),
                3 => highest.saturating_sub(16385),
                4 => highest.saturating_sub(state % 512),
                5 => {
                    highest = highest.saturating_add(1 + (state >> 8) % 4);
                    highest
                }
                6 => {
                    highest = highest.saturating_add(16384 + (state >> 8) % 4_096);
                    highest
                }
                _ => state & 0x0000_ffff_ffff_ffff,
            };
            highest = highest.max(counter);
            counters.push(counter);
        }
        counters
    }

    #[test]
    fn weighted_writer_schedule_prevents_class_starvation() {
        let pool = PacketPool::new(512);
        let (normal_tx, normal) = packet_channel(256, Duration::from_secs(1), true);
        let (small_tx, small) = packet_channel(256, Duration::from_secs(1), true);
        let (bulk_tx, bulk) = packet_channel(256, Duration::from_secs(1), true);
        for (sender, class) in [(&normal_tx, 0), (&small_tx, 1), (&bulk_tx, 2)] {
            for _ in 0..160 {
                let mut packet = pool.acquire();
                packet.set_read_len(1).unwrap();
                packet.as_mut_slice()[0] = class;
                assert!(sender.try_send(packet).is_ok());
            }
        }
        let mut schedule = 0;
        let mut counts = [0usize; 3];
        let mut last_seen = [None; 3];
        for position in 0usize..160 {
            let packet = next_scheduled_packet(&normal, &small, &bulk, &mut schedule).unwrap();
            let class = packet.as_slice()[0] as usize;
            counts[class] += 1;
            if let Some(previous) = last_seen[class] {
                let bound = if class == 2 { 2 } else { 4 };
                assert!(position - previous <= bound);
            }
            last_seen[class] = Some(position);
        }
        assert_eq!(counts, [40, 40, 80]);
    }

    #[test]
    fn bulk_queue_saturates_before_packets_can_age_out_on_a_ten_megabit_path() {
        const TUN_MTU: u128 = 1_300;
        const BITS_PER_SECOND: u128 = 10_000_000;
        let allowed_buffered_bits =
            WORKER_BULK_CAPACITY as u128 * TUN_MTU * 8 * 1_000_000 / BITS_PER_SECOND;
        assert!(allowed_buffered_bits < WORKER_QUEUE_MAX_AGE.as_micros());
        assert_eq!(WORKER_BULK_CAPACITY, 256);
    }

    #[test]
    fn sustained_simultaneous_queues_keep_half_of_send_slots_for_bulk() {
        let pool = PacketPool::new(2_400);
        let (normal_tx, normal) = packet_channel(800, Duration::from_secs(60), true);
        let (small_tx, small) = packet_channel(800, Duration::from_secs(60), true);
        let (bulk_tx, bulk) = packet_channel(800, Duration::from_secs(60), true);
        for (sender, class) in [(&normal_tx, 0), (&small_tx, 1), (&bulk_tx, 2)] {
            for _ in 0..800 {
                let mut packet = pool.acquire();
                packet.set_read_len(1).unwrap();
                packet.as_mut_slice()[0] = class;
                assert!(sender.try_send(packet).is_ok());
            }
        }
        let mut schedule = 0;
        let mut counts = [0usize; 3];
        for _ in 0..800 {
            let packet = next_scheduled_packet(&normal, &small, &bulk, &mut schedule).unwrap();
            counts[packet.as_slice()[0] as usize] += 1;
        }
        assert_eq!(counts, [200, 200, 400]);
    }

    #[test]
    fn replay_window_accepts_reordering_once_and_rejects_duplicates() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(100));
        assert!(window.accept(102));
        assert!(window.accept(101));
        assert!(!window.accept(101));
        assert!(!window.accept(100));
        assert!(window.accept(230));
        assert!(!window.accept(102));
    }

    #[test]
    fn replay_window_handles_rtp_wrap_and_late_packets() {
        let mut window = ReplayWindow::default();
        for sequence in [65_534, 65_535, 0, 2, 1, 3] {
            assert!(window.accept_rtp(sequence));
        }
        assert!(!window.accept_rtp(0));
        assert!(!window.accept_rtp(65_535));
        assert_eq!(window.highest, Some(65_539));
    }

    #[test]
    fn replay_window_is_bounded_under_million_packet_attack() {
        let mut window = ReplayWindow::default();
        for counter in 0..1_000_000 {
            assert!(window.accept(counter));
            assert!(!window.accept(counter));
        }
        assert_eq!(std::mem::size_of_val(&window), 24);
    }

    proptest! {
        #[test]
        fn replay_window_matches_independent_set_model(
            counters in proptest::collection::vec(any::<u32>(), 1..=5_000)
        ) {
            let counters = counters.into_iter().map(u64::from).collect::<Vec<_>>();
            prop_assert!(replay_trace_matches(&counters, 16384));
        }

        #[test]
        fn rtp_replay_window_matches_independent_extended_sequence_model(
            sequences in proptest::collection::vec(any::<u16>(), 1..=2_000)
        ) {
            prop_assert!(rtp_trace_matches(&sequences));
        }
    }

    #[test]
    fn replay_oracle_detects_window_off_by_one_mutation() {
        let counters = [100, 16484, 101];
        assert!(replay_trace_matches(&counters, 16384));
        assert!(!replay_trace_matches(&counters, 16383));
    }

    #[test]
    fn deterministic_replay_fault_generator_is_reproducible_and_hits_boundaries() {
        let first = deterministic_replay_trace(0x1234_5678_9abc_def0, 4_096);
        let second = deterministic_replay_trace(0x1234_5678_9abc_def0, 4_096);
        let different = deterministic_replay_trace(0x1234_5678_9abc_def1, 4_096);
        assert_eq!(first, second);
        assert_ne!(first, different);
        assert!(first.windows(2).any(|pair| pair[0] == pair[1]));
        assert!(replay_trace_coverage(&first).complete());
    }

    #[test]
    fn replay_coverage_oracle_rejects_each_missing_boundary() {
        let complete = ReplayCoverage {
            duplicate: 1,
            age_16383: 1,
            age_16384: 1,
            age_16385: 1,
            forward_small: 1,
            forward_large: 1,
        };
        assert!(complete.complete());
        for index in 0..6 {
            let mut mutated = complete;
            match index {
                0 => mutated.duplicate = 0,
                1 => mutated.age_16383 = 0,
                2 => mutated.age_16384 = 0,
                3 => mutated.age_16385 = 0,
                4 => mutated.forward_small = 0,
                _ => mutated.forward_large = 0,
            }
            assert!(!mutated.complete());
        }
    }

    #[test]
    fn rtp_replay_reference_survives_multiple_wraps_duplicates_and_late_packets() {
        let mut sequence = 65_000u16;
        let mut trace = Vec::with_capacity(20_000);
        for index in 0..10_000 {
            sequence = sequence.wrapping_add(97);
            trace.push(sequence);
            if index % 7 == 0 {
                trace.push(sequence);
            }
            if index % 11 == 0 {
                trace.push(sequence.wrapping_sub(16383));
                trace.push(sequence.wrapping_sub(16384));
                trace.push(sequence.wrapping_sub(16385));
            }
        }
        assert!(rtp_trace_matches(&trace));
    }

    #[test]
    #[ignore = "explicit deterministic stability soak"]
    fn deterministic_replay_chaos_soak() {
        let seconds = std::env::var("CSQTT_SOAK_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120)
            .max(1);
        let first_seed = std::env::var("CSQTT_SOAK_SEED")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let counters_per_seed = std::env::var("CSQTT_REPLAY_SOAK_COUNTERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4_096)
            .max(8);
        let started = Instant::now();
        let mut offset = 0u64;
        loop {
            let seed = first_seed.wrapping_add(offset);
            let counters = deterministic_replay_trace(seed, counters_per_seed);
            assert!(
                replay_trace_matches(&counters, 16384)
                    && replay_trace_coverage(&counters).complete(),
                "replay window diverged at reproducible seed {seed}"
            );
            offset = offset.wrapping_add(1);
            if started.elapsed() >= Duration::from_secs(seconds) {
                break;
            }
        }
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn completed_writer_is_not_polled_twice() {
        let mut writer = tokio::spawn(async { Ok(()) });
        let reader = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });

        let result: Result<()> = (&mut writer).await.unwrap();
        result.unwrap();
        stop_session_tasks(1, writer, reader).await;
    }

    #[tokio::test]
    async fn completed_reader_is_not_polled_twice() {
        let writer = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });
        let mut reader = tokio::spawn(async { Ok(()) });

        let result: Result<()> = (&mut reader).await.unwrap();
        result.unwrap();
        stop_session_tasks(2, writer, reader).await;
    }

    #[tokio::test]
    async fn cancelled_session_aborts_every_child_task() {
        let writer = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });
        let reader = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });

        tokio::time::timeout(
            Duration::from_secs(1),
            stop_session_tasks(0, writer, reader),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn panicked_writer_handle_is_consumed_only_once() {
        let mut writer = tokio::spawn(async { panic!("injected writer failure") });
        let reader = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });

        assert!((&mut writer).await.unwrap_err().is_panic());
        stop_session_tasks(1, writer, reader).await;
    }

    #[tokio::test]
    async fn cancellation_aborts_and_awaits_pending_session_startup() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let session = tokio::spawn(async move {
            let _flag = DropFlag(task_dropped);
            pending::<()>().await;
            Ok(false)
        });
        tokio::task::yield_now().await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(!await_session_task(&cancel, session).await.unwrap());
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn plaintext_corruption_and_replay_never_authenticate() {
        let pool = PacketPool::new(5);
        let cipher = ObfsCipher::new([0x52; 32]).unwrap();
        let config = ObfsConfig::new(ObfsMode::Video);
        let mut replay = ReplayProtection::default();
        let mut encoded = pool.acquire();
        encoded.read_area()[..7].copy_from_slice(b"payload");
        encoded.set_read_len(7).unwrap();
        cipher
            .wrap(&mut encoded, &config, &mut ObfsState::new())
            .unwrap();
        let wire = encoded.as_slice().to_vec();
        drop(encoded);

        let mut plaintext = pool.acquire();
        plaintext.read_area()[..6].copy_from_slice(b"DENIED");
        plaintext.set_read_len(6).unwrap();
        assert!(!authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut plaintext
        ));

        let mut corrupt_wire = wire.clone();
        let last = corrupt_wire.len() - 1;
        corrupt_wire[last] ^= 0x80;
        let mut corrupt = pool.acquire();
        corrupt.read_area()[..corrupt_wire.len()].copy_from_slice(&corrupt_wire);
        corrupt.set_read_len(corrupt_wire.len()).unwrap();
        assert!(!authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut corrupt
        ));

        let mut valid = pool.acquire();
        valid.read_area()[..wire.len()].copy_from_slice(&wire);
        valid.set_read_len(wire.len()).unwrap();
        assert!(authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut valid
        ));
        assert_eq!(valid.as_slice(), b"payload");

        let mut replayed = pool.acquire();
        replayed.read_area()[..wire.len()].copy_from_slice(&wire);
        replayed.set_read_len(wire.len()).unwrap();
        assert!(!authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut replayed
        ));
    }

    #[test]
    fn keepalive_requires_a_nonempty_all_ff_payload() {
        assert!(is_keepalive(&[0xff; 32]));
        assert!(!is_keepalive(&[]));
        assert!(!is_keepalive(&[0xff, 0x00, 0xff]));
    }

    #[test]
    fn smart_ping_matches_server_wire_contract() {
        let payload = smart_ping_payload("0123456789abcdef", 42, 162).unwrap();
        assert_eq!(payload.len(), 45);
        assert_eq!(&payload[1..17], b"0123456789abcdef");
        assert_eq!(&payload[17..25], &42u64.to_be_bytes());
        assert_eq!(&payload[25..29], PATH_PROBE_V2_MAGIC);
        assert_eq!(&payload[29..31], &162u16.to_be_bytes());
        assert_eq!(&payload[31..39], &[0; 8]);
        assert!(payload[39..].iter().all(|byte| *byte == 0xff));
        assert!(smart_ping_payload("", 42, 1).is_none());
        assert!(smart_ping_payload("0123456789abcdef0", 42, 1).is_none());
        assert!(smart_ping_payload("0123456789abcdef", 42, 0).is_none());
        assert!(smart_ping_payload("0123456789abcdef", 42, 163).is_none());
    }

    #[tokio::test]
    async fn cancellation_waits_for_graceful_session_exit() {
        let cancel = CancellationToken::new();
        let exited = Arc::new(AtomicBool::new(false));
        let task_cancel = cancel.clone();
        let task_exited = exited.clone();
        let session = tokio::spawn(async move {
            task_cancel.cancelled().await;
            tokio::time::sleep(Duration::from_millis(25)).await;
            task_exited.store(true, Ordering::Release);
            Ok(false)
        });
        cancel.cancel();
        assert!(!await_session_task(&cancel, session).await.unwrap());
        assert!(exited.load(Ordering::Acquire));
    }

    #[test]
    fn transport_shutdown_token_is_independent() {
        let global = CancellationToken::new();
        let transport = CancellationToken::new();
        global.cancel();
        assert!(!transport.is_cancelled());
        transport.cancel();
        assert!(transport.is_cancelled());
    }

    #[test]
    fn path_ack_requires_exact_wire_shape() {
        let mut ack = PATH_RECEIPT_ACK.to_vec();
        ack.extend_from_slice(&17u16.to_be_bytes());
        ack.extend_from_slice(&91u64.to_be_bytes());
        assert_eq!(parse_path_ack(&ack), Some((17, 91)));
        ack.push(0);
        assert_eq!(parse_path_ack(&ack), None);
    }

    #[tokio::test]
    async fn path_probe_requires_three_full_unanswered_intervals_before_failure() {
        let misses = AtomicU8::new(0);
        for expected in 1..=PATH_PROBE_MISS_LIMIT {
            let updated = misses.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < PATH_PROBE_MISS_LIMIT).then_some(count + 1)
            });
            assert!(updated.is_ok());
            assert_eq!(misses.load(Ordering::Acquire), expected);
        }
        assert!(
            misses
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < PATH_PROBE_MISS_LIMIT).then_some(count + 1)
                })
                .is_err()
        );
        misses.store(0, Ordering::Release);
        assert_eq!(misses.load(Ordering::Acquire), 0);
    }

    #[test]
    fn scheduler_stall_discards_old_probe_misses() {
        let misses = AtomicU8::new(PATH_PROBE_MISS_LIMIT);
        let stats = Stats::default();
        let deadline = Instant::now();

        assert!(!reset_probe_misses_after_scheduler_stall(
            deadline + PATH_PROBE_SCHEDULER_STALL - Duration::from_millis(1),
            deadline,
            &misses,
            &stats,
        ));
        assert_eq!(misses.load(Ordering::Acquire), PATH_PROBE_MISS_LIMIT);
        assert_eq!(stats.path_scheduler_resets.load(Ordering::Acquire), 0);

        assert!(reset_probe_misses_after_scheduler_stall(
            deadline + PATH_PROBE_SCHEDULER_STALL,
            deadline,
            &misses,
            &stats,
        ));
        assert_eq!(misses.load(Ordering::Acquire), 0);
        assert_eq!(stats.path_scheduler_resets.load(Ordering::Acquire), 1);
        assert_eq!(PATH_PROBE_RECOVERY_INTERVAL, Duration::from_secs(1));
    }

    #[test]
    fn endpoint_rotation_is_local_cyclic_and_overflow_safe() {
        for endpoint_count in 1..=8 {
            for id in 1..=162 {
                let selected = (0..endpoint_count)
                    .map(|cursor| turn_endpoint_index(id, cursor, endpoint_count))
                    .collect::<std::collections::HashSet<_>>();
                assert_eq!(selected.len(), endpoint_count);
                assert!(selected.iter().all(|endpoint| *endpoint < endpoint_count));
                assert_eq!(
                    turn_endpoint_index(id, usize::MAX, endpoint_count),
                    (id % endpoint_count + usize::MAX % endpoint_count) % endpoint_count
                );
            }
        }
    }

    #[test]
    fn turn_allocate_error_exposes_nested_io_source() {
        let error = anyhow::Error::new(TurnAllocateError(anyhow::Error::new(
            std::io::Error::from_raw_os_error(101),
        )));
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(101))
        }));
    }

    #[test]
    fn turn_allocate_error_exposes_structured_stun_code() {
        let error = TurnAllocateError(anyhow::Error::new(TurnRequestError::new(3, 0, 486)));
        assert_eq!(error.stun_code(), Some(486));
    }

    #[test]
    fn successful_config_delivery_is_sticky() {
        let sent = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicBool::new(true));
        ConfigDeliveryState {
            sent: sent.clone(),
            in_flight: in_flight.clone(),
        }
        .complete(true);
        assert!(sent.load(Ordering::Acquire));
        assert!(!in_flight.load(Ordering::Acquire));
    }

    #[test]
    fn failed_config_delivery_can_be_retried() {
        let sent = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicBool::new(true));
        ConfigDeliveryState {
            sent: sent.clone(),
            in_flight: in_flight.clone(),
        }
        .complete(false);
        assert!(!sent.load(Ordering::Acquire));
        assert!(!in_flight.load(Ordering::Acquire));
    }
}
