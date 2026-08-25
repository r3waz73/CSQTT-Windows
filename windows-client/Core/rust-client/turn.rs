// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#[cfg(test)]
use crate::turn_core::{AF_IPV4, NativeAddress};
use crate::{
    dns,
    packet::{PACKET_CAPACITY, PACKET_HEADROOM, PacketBuf, PacketPool},
    turn_core::{
        EVENT_CHANNEL_BOUND, EVENT_CONTROL_OVERFLOW, EVENT_DATA_REJECTED, EVENT_EVENT_OVERFLOW,
        EVENT_FORCED_DESTROY, EVENT_RELAY_ADDRESS, EVENT_REQUEST_COMPLETE, EVENT_STATE,
        METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_REFRESH, NativeCore,
        RESULT_INVALID_ARGUMENT, RESULT_NOT_CONTROL, STATE_DEALLOCATED, STATE_DESTROYING,
        STATE_READY, native_status_text,
    },
};
use anyhow::{Context, Result, bail};
use socket2::SockRef;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinHandle,
};

const CONTROL_MAX: usize = 1024;
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const UDP_RECEIVE_BUFFER_BYTES: usize = 1024 * 1024;
const UDP_SEND_BUFFER_BYTES: usize = 512 * 1024;
const _: () = assert!(UDP_RECEIVE_BUFFER_BYTES + UDP_SEND_BUFFER_BYTES <= 2 * 1024 * 1024);
const INCOMING_QUEUE_CAPACITY: usize = 64;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(12);
const ALLOCATION_TIMEOUT: Duration = Duration::from_secs(25);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(35);
const READY_CLEANUP_TIMEOUT: Duration = Duration::from_secs(12);
const CLEANUP_ERROR_RETRY: Duration = Duration::from_millis(100);
const MAX_BACKGROUND_CLEANUPS: usize = 128;
const TURN_RESUME_VALIDATION_STALL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct TurnRequestError {
    method: u32,
    status: i32,
    stun_code: i32,
}

impl TurnRequestError {
    pub(crate) fn new(method: u32, status: i32, stun_code: i32) -> Self {
        Self {
            method,
            status,
            stun_code,
        }
    }

    pub fn stun_code(&self) -> i32 {
        self.stun_code
    }
}

impl std::fmt::Display for TurnRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "TURN {} failed: {}{}",
            method_name(self.method),
            native_status_text(self.status),
            stun_suffix(self.stun_code)
        )
    }
}

impl std::error::Error for TurnRequestError {}

#[derive(Clone, Default)]
struct Completion {
    sequence: u64,
    status: i32,
    stun_code: i32,
}

#[derive(Clone, Default)]
struct CoreSnapshot {
    state: u32,
    relay: Option<SocketAddr>,
    channel: Option<u16>,
    allocate: Completion,
    refresh: Completion,
    permission: Completion,
    channel_bind: Completion,
    terminal: Option<Arc<str>>,
}

impl CoreSnapshot {
    fn completion(&self, method: u32) -> &Completion {
        match method {
            METHOD_ALLOCATE => &self.allocate,
            METHOD_REFRESH => &self.refresh,
            METHOD_CREATE_PERMISSION => &self.permission,
            METHOD_CHANNEL_BIND => &self.channel_bind,
            _ => &self.allocate,
        }
    }

    fn completion_mut(&mut self, method: u32) -> Option<&mut Completion> {
        match method {
            METHOD_ALLOCATE => Some(&mut self.allocate),
            METHOD_REFRESH => Some(&mut self.refresh),
            METHOD_CREATE_PERMISSION => Some(&mut self.permission),
            METHOD_CHANNEL_BIND => Some(&mut self.channel_bind),
            _ => None,
        }
    }
}

struct DriverShared {
    snapshot: watch::Sender<CoreSnapshot>,
    wake: Notify,
    closing: AtomicBool,
    terminal_present: AtomicBool,
    control_sent: AtomicBool,
    channel: AtomicU16,
    queue_full_drops: AtomicU64,
    pool_deficit_drops: AtomicU64,
    #[cfg(test)]
    native_pumps: AtomicU64,
}

impl DriverShared {
    fn fail(&self, reason: impl Into<Arc<str>>) {
        if self.closing.load(Ordering::Acquire) {
            return;
        }
        let reason = reason.into();
        let mut inserted = false;
        self.snapshot.send_modify(|snapshot| {
            if snapshot.terminal.is_none() {
                snapshot.terminal = Some(reason.clone());
                inserted = true;
            }
        });
        if inserted {
            self.terminal_present.store(true, Ordering::Release);
            self.wake.notify_waiters();
        }
    }

    fn terminal(&self) -> Option<Arc<str>> {
        self.terminal_present
            .load(Ordering::Acquire)
            .then(|| self.snapshot.borrow().terminal.clone())
            .flatten()
    }

    fn request_cleanup(&self) {
        self.closing.store(true, Ordering::Release);
        self.channel.store(0, Ordering::Release);
        self.wake.notify_one();
    }
}

pub struct TurnAllocation {
    socket: Arc<UdpSocket>,
    core: Arc<NativeCore>,
    incoming: Mutex<Option<mpsc::Receiver<PacketBuf>>>,
    shared: Arc<DriverShared>,
    relay_address: Mutex<SocketAddr>,
    prepare_lock: tokio::sync::Mutex<()>,
    driver: Mutex<Option<JoinHandle<()>>>,
    deallocated: AtomicBool,
}

pub struct TurnReceiver {
    incoming: mpsc::Receiver<PacketBuf>,
    state: watch::Receiver<CoreSnapshot>,
    shared: Arc<DriverShared>,
}

impl TurnReceiver {
    pub async fn recv(&mut self) -> Result<PacketBuf> {
        loop {
            if let Some(reason) = self.shared.terminal() {
                bail!("{reason}");
            }
            tokio::select! {
                biased;
                changed = self.state.changed() => {
                    if changed.is_err() {
                        bail!("TURN allocation state closed");
                    }
                }
                packet = self.incoming.recv() => {
                    if let Some(packet) = packet {
                        return Ok(packet);
                    }
                    let reason = self
                        .shared
                        .terminal()
                        .unwrap_or_else(|| Arc::from("TURN allocation closed"));
                    bail!("{reason}");
                }
            }
        }
    }
}

impl TurnAllocation {
    pub async fn connect(
        turn_address: &str,
        username: Arc<str>,
        password: Arc<str>,
        peer: SocketAddr,
        pool: Arc<PacketPool>,
    ) -> Result<Arc<Self>> {
        if username.len() > 512 {
            bail!("TURN username превышает 512 байт");
        }
        if password.len() > 512 {
            bail!("TURN password превышает 512 байт");
        }
        let server = dns::resolve_socket(turn_address).await?;
        let bind = if server.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = Arc::new(UdpSocket::bind(bind).await.context("TURN UDP bind")?);
        configure_udp_socket_buffers(&socket);
        socket
            .connect(server)
            .await
            .with_context(|| format!("TURN UDP connect {server}"))?;
        let core = NativeCore::create(server, &username, &password, peer)?;
        let (snapshot, _) = watch::channel(CoreSnapshot::default());
        let shared = Arc::new(DriverShared {
            snapshot,
            wake: Notify::new(),
            closing: AtomicBool::new(false),
            terminal_present: AtomicBool::new(false),
            control_sent: AtomicBool::new(false),
            channel: AtomicU16::new(0),
            queue_full_drops: AtomicU64::new(0),
            pool_deficit_drops: AtomicU64::new(0),
            #[cfg(test)]
            native_pumps: AtomicU64::new(0),
        });
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_QUEUE_CAPACITY);
        let driver = tokio::spawn(driver_loop(DriverRuntime {
            socket: socket.clone(),
            core: core.clone(),
            pool: pool.clone(),
            incoming: incoming_tx,
            shared: shared.clone(),
            server,
            peer,
        }));
        let allocation = Arc::new(Self {
            socket,
            core,
            incoming: Mutex::new(Some(incoming_rx)),
            shared,
            relay_address: Mutex::new(SocketAddr::new(server.ip(), 0)),
            prepare_lock: tokio::sync::Mutex::new(()),
            driver: Mutex::new(Some(driver)),
            deallocated: AtomicBool::new(false),
        });
        let baseline = allocation.completion_sequence(METHOD_ALLOCATE);
        if let Err(error) = allocation.core.start_allocation() {
            allocation.shared.fail(Arc::from(format!("{error:#}")));
            return Err(error);
        }
        allocation.shared.wake.notify_one();
        let relay_address = match tokio::time::timeout(
            ALLOCATION_TIMEOUT,
            allocation.wait_for_allocation(baseline),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                allocation
                    .shared
                    .fail("TURN Allocate exceeded the hard safety deadline");
                bail!("TURN Allocate exceeded the hard safety deadline");
            }
        };
        *allocation
            .relay_address
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = relay_address;
        crate::log_error!("[TURN] Аллокация активна: relay {relay_address}");
        Ok(allocation)
    }

    pub fn local_addr(&self) -> SocketAddr {
        *self
            .relay_address
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn take_receiver(&self) -> Result<TurnReceiver> {
        let incoming = self
            .incoming
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .context("TURN receiver already acquired")?;
        Ok(TurnReceiver {
            incoming,
            state: self.shared.snapshot.subscribe(),
            shared: self.shared.clone(),
        })
    }

    pub async fn prepare_channel(&self) -> Result<()> {
        let _guard = self.prepare_lock.lock().await;
        self.ensure_open()?;
        if self.shared.channel.load(Ordering::Acquire) != 0 {
            return Ok(());
        }
        let permission_baseline = self.completion_sequence(METHOD_CREATE_PERMISSION);
        if let Err(error) = self.core.start_permission() {
            self.shared.fail(Arc::from(format!("{error:#}")));
            return Err(error);
        }
        self.shared.wake.notify_one();
        self.wait_for_completion(
            METHOD_CREATE_PERMISSION,
            permission_baseline,
            CONTROL_TIMEOUT,
        )
        .await?;
        crate::log_error!("[TURN] CreatePermission подтверждён ✓");
        let channel_baseline = self.completion_sequence(METHOD_CHANNEL_BIND);
        if let Err(error) = self.core.start_channel() {
            self.shared.fail(Arc::from(format!("{error:#}")));
            return Err(error);
        }
        self.shared.wake.notify_one();
        self.wait_for_completion(METHOD_CHANNEL_BIND, channel_baseline, CONTROL_TIMEOUT)
            .await?;
        let mut receiver = self.shared.snapshot.subscribe();
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            loop {
                let snapshot = receiver.borrow().clone();
                if let Some(reason) = snapshot.terminal {
                    bail!("{reason}");
                }
                if snapshot.channel.is_some() {
                    return Ok(());
                }
                receiver
                    .changed()
                    .await
                    .context("TURN ChannelBind state channel closed")?;
            }
        })
        .await
        .context("TURN ChannelBind confirmation timeout")??;
        let channel = self.shared.channel.load(Ordering::Acquire);
        crate::log_error!("[TURN] ChannelBind активен: канал 0x{channel:04X}");
        crate::log_error!("[TURN] Сессия готова к передаче данных ✓");
        Ok(())
    }

    pub async fn send_with_duplicate(&self, packet: &mut PacketBuf, duplicate: bool) -> Result<()> {
        self.ensure_open()?;
        let channel = self.shared.channel.load(Ordering::Acquire);
        if channel == 0 {
            bail!("TURN ChannelBind обязателен");
        }
        encode_channel_data(packet, channel)?;
        self.socket
            .send(packet.as_slice())
            .await
            .context("TURN UDP send")?;
        if duplicate {
            let _ = self.socket.try_send(packet.as_slice());
        }
        Ok(())
    }

    pub async fn deallocate(&self) {
        if self.deallocated.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared.request_cleanup();
        let _ = self.core.graceful_shutdown();
        let driver = self
            .driver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut driver) = driver
            && tokio::time::timeout(CLEANUP_TIMEOUT + Duration::from_secs(1), &mut driver)
                .await
                .is_err()
        {
            self.core.force_destroy(0);
            driver.abort();
            let _ = driver.await;
        }
    }

    fn ensure_open(&self) -> Result<()> {
        if self.shared.closing.load(Ordering::Acquire) {
            bail!("TURN allocation closing");
        }
        if let Some(reason) = self.shared.terminal() {
            bail!("{reason}");
        }
        Ok(())
    }

    fn completion_sequence(&self, method: u32) -> u64 {
        self.shared.snapshot.borrow().completion(method).sequence
    }

    async fn wait_for_allocation(&self, baseline: u64) -> Result<SocketAddr> {
        self.wait_for_completion(METHOD_ALLOCATE, baseline, ALLOCATION_TIMEOUT)
            .await?;
        let mut receiver = self.shared.snapshot.subscribe();
        loop {
            let snapshot = receiver.borrow().clone();
            if let Some(reason) = snapshot.terminal {
                bail!("{reason}");
            }
            if snapshot.state == STATE_READY
                && let Some(relay) = snapshot.relay
            {
                return Ok(relay);
            }
            receiver
                .changed()
                .await
                .context("TURN Allocate state channel closed")?;
        }
    }

    async fn wait_for_completion(
        &self,
        method: u32,
        baseline: u64,
        timeout: Duration,
    ) -> Result<()> {
        let mut receiver = self.shared.snapshot.subscribe();
        tokio::time::timeout(timeout, async {
            loop {
                let snapshot = receiver.borrow().clone();
                let completion = snapshot.completion(method);
                if completion.sequence > baseline {
                    if completion.status == 0 && completion.stun_code == 0 {
                        return Ok(());
                    }
                    return Err(anyhow::Error::new(TurnRequestError::new(
                        method,
                        completion.status,
                        completion.stun_code,
                    )));
                }
                if let Some(reason) = snapshot.terminal {
                    bail!("{reason}");
                }
                receiver.changed().await.with_context(|| {
                    format!("TURN {} state channel closed", method_name(method))
                })?;
            }
        })
        .await
        .with_context(|| format!("TURN {} hard timeout", method_name(method)))?
    }

    #[cfg(test)]
    fn ingress_queue_full_drops(&self) -> u64 {
        self.shared.queue_full_drops.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn ingress_pool_deficit_drops(&self) -> u64 {
        self.shared.pool_deficit_drops.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn native_pump_count(&self) -> u64 {
        self.shared.native_pumps.load(Ordering::Relaxed)
    }
}

impl Drop for TurnAllocation {
    fn drop(&mut self) {
        self.shared.request_cleanup();
        let _ = self.core.graceful_shutdown();
        let _ = self
            .driver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

struct DriverRuntime {
    socket: Arc<UdpSocket>,
    core: Arc<NativeCore>,
    pool: Arc<PacketPool>,
    incoming: mpsc::Sender<PacketBuf>,
    shared: Arc<DriverShared>,
    server: SocketAddr,
    peer: SocketAddr,
}

async fn driver_loop(runtime: DriverRuntime) {
    let DriverRuntime {
        socket,
        core,
        pool,
        incoming,
        shared,
        server,
        peer,
    } = runtime;
    let mut deficit_buffer = [0u8; PACKET_CAPACITY - PACKET_HEADROOM];
    let mut cleanup_deadline = None;
    let mut cleanup_permit: Option<OwnedSemaphorePermit> = None;
    let mut shutdown_requested = false;
    let mut native_deadline = Instant::now();
    let mut pump_needed = true;
    loop {
        if shared.closing.load(Ordering::Acquire) {
            if !shared.control_sent.load(Ordering::Acquire) {
                break;
            }
            if cleanup_permit.is_none() {
                cleanup_permit = match cleanup_limiter().clone().try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => break,
                };
            }
            let state = shared.snapshot.borrow().state;
            let (deadline, started) =
                start_driver_cleanup(&core, &mut cleanup_deadline, &mut shutdown_requested, state);
            pump_needed |= started;
            if state >= STATE_DEALLOCATED || Instant::now() >= deadline {
                break;
            }
        }
        let now = Instant::now();
        if resume_validation_due(
            now,
            native_deadline,
            shared.snapshot.borrow().state,
            shared.closing.load(Ordering::Acquire),
        ) {
            let _ = core.start_channel();
            pump_needed = true;
        }
        if pump_needed || now >= native_deadline {
            match pump_native(&socket, &core, &shared, server, peer).await {
                Ok(delay) => {
                    native_deadline =
                        Instant::now() + delay.unwrap_or(Duration::from_secs(24 * 60 * 60));
                    pump_needed = false;
                    continue;
                }
                Err(error) => {
                    shared.fail(Arc::from(format!("{error:#}")));
                    shared.request_cleanup();
                    if !shared.control_sent.load(Ordering::Acquire) {
                        break;
                    }
                    if let Some(deadline) = cleanup_deadline {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        tokio::time::sleep(CLEANUP_ERROR_RETRY.min(remaining)).await;
                    }
                    pump_needed = true;
                    continue;
                }
            }
        }
        let wait_deadline =
            cleanup_deadline.map_or(native_deadline, |deadline| deadline.min(native_deadline));
        let mut wait = wait_deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            wait = Duration::from_millis(1);
        }
        if shared.closing.load(Ordering::Acquire) {
            while let Ok(length) = socket.try_recv(&mut deficit_buffer) {
                if matches!(
                    process_deficit_packet(&core, &shared, &deficit_buffer[..length]),
                    PacketAction::Pump
                ) {
                    pump_needed = true;
                }
            }
            let event = tokio::select! {
                biased;
                _ = shared.wake.notified() => DriverEvent::Wake,
                _ = tokio::time::sleep(wait) => DriverEvent::Timer,
                result = socket.recv(&mut deficit_buffer) => DriverEvent::Packet(result),
            };
            match event {
                DriverEvent::Wake | DriverEvent::Timer => {
                    pump_needed = true;
                }
                DriverEvent::Packet(Ok(length)) => {
                    pump_needed = matches!(
                        process_deficit_packet(&core, &shared, &deficit_buffer[..length]),
                        PacketAction::Pump
                    );
                }
                DriverEvent::Packet(Err(error)) => {
                    shared.fail(Arc::from(format!("TURN UDP receive failed: {error}")));
                    pump_needed = true;
                    tokio::time::sleep(CLEANUP_ERROR_RETRY).await;
                }
                DriverEvent::OwnerClosed => {}
            }
        } else {
            // High-throughput batch draining: drain up to 64 packets in tight synchronous loop
            const MAX_BURST_BATCH: usize = 64;
            let mut burst_count = 0usize;
            let mut socket_empty = false;
            while burst_count < MAX_BURST_BATCH {
                if let Some(mut packet) = pool.try_acquire() {
                    match socket.try_recv(packet.read_area()) {
                        Ok(length) => {
                            burst_count += 1;
                            if packet.set_read_len(length).is_err() {
                                continue;
                            }
                            let action = process_packet(&core, &shared, &incoming, packet);
                            match action {
                                PacketAction::Wait => {}
                                PacketAction::Pump => pump_needed = true,
                                PacketAction::OwnerClosed => {
                                    shared.request_cleanup();
                                    break;
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            socket_empty = true;
                            break;
                        }
                        Err(error) => {
                            shared.fail(Arc::from(format!("TURN UDP receive failed: {error}")));
                            shared.request_cleanup();
                            pump_needed = true;
                            break;
                        }
                    }
                } else {
                    // Pool deficit: process with stack deficit_buffer
                    match socket.try_recv(&mut deficit_buffer) {
                        Ok(length) => {
                            burst_count += 1;
                            if matches!(
                                process_deficit_packet(&core, &shared, &deficit_buffer[..length]),
                                PacketAction::Pump
                            ) {
                                pump_needed = true;
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            socket_empty = true;
                            break;
                        }
                        Err(error) => {
                            shared.fail(Arc::from(format!("TURN UDP receive failed: {error}")));
                            shared.request_cleanup();
                            pump_needed = true;
                            break;
                        }
                    }
                }
            }

            if burst_count > 0 && !socket_empty {
                // Yield gracefully after full burst to prevent task starvation
                tokio::task::yield_now().await;
                continue;
            }

            if let Some(mut packet) = pool.try_acquire() {
                let event = tokio::select! {
                    biased;
                    _ = shared.wake.notified() => DriverEvent::Wake,
                    _ = tokio::time::sleep(wait) => DriverEvent::Timer,
                    _ = incoming.closed() => DriverEvent::OwnerClosed,
                    result = socket.recv(packet.read_area()) => DriverEvent::Packet(result),
                };
                match event {
                    DriverEvent::Wake | DriverEvent::Timer => {
                        pump_needed = true;
                    }
                    DriverEvent::OwnerClosed => {
                        shared.request_cleanup();
                    }
                    DriverEvent::Packet(Ok(length)) => {
                        if packet.set_read_len(length).is_err() {
                            continue;
                        }
                        let action = process_packet(&core, &shared, &incoming, packet);
                        match action {
                            PacketAction::Wait => {}
                            PacketAction::Pump => pump_needed = true,
                            PacketAction::OwnerClosed => shared.request_cleanup(),
                        }
                    }
                    DriverEvent::Packet(Err(error)) => {
                        shared.fail(Arc::from(format!("TURN UDP receive failed: {error}")));
                        shared.request_cleanup();
                        pump_needed = true;
                    }
                }
            } else {
                let event = tokio::select! {
                    biased;
                    _ = shared.wake.notified() => DriverEvent::Wake,
                    _ = tokio::time::sleep(wait) => DriverEvent::Timer,
                    _ = incoming.closed() => DriverEvent::OwnerClosed,
                    result = socket.recv(&mut deficit_buffer) => DriverEvent::Packet(result),
                };
                match event {
                    DriverEvent::Wake | DriverEvent::Timer => {
                        pump_needed = true;
                    }
                    DriverEvent::OwnerClosed => {
                        shared.request_cleanup();
                    }
                    DriverEvent::Packet(Ok(length)) => {
                        pump_needed = matches!(
                            process_deficit_packet(&core, &shared, &deficit_buffer[..length]),
                            PacketAction::Pump
                        );
                    }
                    DriverEvent::Packet(Err(error)) => {
                        shared.fail(Arc::from(format!("TURN UDP receive failed: {error}")));
                        shared.request_cleanup();
                        pump_needed = true;
                    }
                }
            }
        }
    }
    core.force_destroy(0);
}

fn resume_validation_due(
    now: Instant,
    native_deadline: Instant,
    state: u32,
    closing: bool,
) -> bool {
    !closing
        && state == STATE_READY
        && now.saturating_duration_since(native_deadline) >= TURN_RESUME_VALIDATION_STALL
}

enum DriverEvent {
    Wake,
    Timer,
    OwnerClosed,
    Packet(std::io::Result<usize>),
}

fn start_driver_cleanup(
    core: &NativeCore,
    cleanup_deadline: &mut Option<Instant>,
    shutdown_requested: &mut bool,
    state: u32,
) -> (Instant, bool) {
    let now = Instant::now();
    let timeout = if state >= STATE_READY {
        READY_CLEANUP_TIMEOUT
    } else {
        CLEANUP_TIMEOUT
    };
    let proposed_deadline = now + timeout;
    let deadline = cleanup_deadline.get_or_insert(proposed_deadline);
    if proposed_deadline < *deadline {
        *deadline = proposed_deadline;
    }
    let mut started = false;
    if !*shutdown_requested {
        *shutdown_requested = true;
        started = true;
        let _ = core.graceful_shutdown();
    }
    (*deadline, started)
}

fn cleanup_limiter() -> &'static Arc<Semaphore> {
    static LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(Semaphore::new(MAX_BACKGROUND_CLEANUPS)))
}

async fn pump_native(
    socket: &UdpSocket,
    core: &NativeCore,
    shared: &DriverShared,
    server: SocketAddr,
    peer: SocketAddr,
) -> Result<Option<Duration>> {
    #[cfg(test)]
    shared.native_pumps.fetch_add(1, Ordering::Relaxed);
    let next_timer = core.poll()?;
    let mut control = [0u8; CONTROL_MAX];
    while let Some((length, destination)) = core.pull_control(&mut control)? {
        if destination != server {
            bail!("TURN core attempted control send to unexpected destination {destination}");
        }
        socket
            .send(&control[..length])
            .await
            .context("TURN control UDP send")?;
        shared.control_sent.store(true, Ordering::Release);
    }
    let mut unexpected_destroy = false;
    while let Some(event) = core.pull_event()? {
        match event.kind {
            EVENT_STATE => {
                if event.state != STATE_READY {
                    shared.channel.store(0, Ordering::Release);
                }
                shared.snapshot.send_modify(|snapshot| {
                    snapshot.state = event.state;
                    if event.state != STATE_READY {
                        snapshot.channel = None;
                    }
                    if event.state >= STATE_DEALLOCATED {
                        snapshot.relay = None;
                    }
                });
                if event.state == STATE_DESTROYING && !shared.closing.load(Ordering::Acquire) {
                    unexpected_destroy = true;
                }
            }
            EVENT_REQUEST_COMPLETE => {
                shared.snapshot.send_modify(|snapshot| {
                    if let Some(completion) = snapshot.completion_mut(event.method) {
                        completion.sequence = completion.sequence.wrapping_add(1);
                        completion.status = event.status;
                        completion.stun_code = event.stun_code;
                    }
                });
                if event.method == METHOD_REFRESH && event.status == 0 && event.stun_code == 0 {
                    crate::log_error!("[TURN] Refresh аллокации подтверждён ✓");
                }
                if (event.status != 0 || event.stun_code != 0)
                    && !shared.closing.load(Ordering::Acquire)
                {
                    shared.fail(Arc::from(format!(
                        "TURN {} failed: {}{}",
                        method_name(event.method),
                        native_status_text(event.status),
                        stun_suffix(event.stun_code)
                    )));
                }
            }
            EVENT_CHANNEL_BOUND => {
                let event_peer = event.address.to_socket_addr()?;
                if event_peer != peer {
                    shared.fail(Arc::from(format!(
                        "TURN ChannelBind confirmed unexpected peer {event_peer}"
                    )));
                } else if !(0x4000..=0x7fff).contains(&event.channel) {
                    shared.fail(Arc::from(format!(
                        "TURN core returned invalid channel {}",
                        event.channel
                    )));
                } else {
                    shared.channel.store(event.channel, Ordering::Release);
                    shared.snapshot.send_modify(|snapshot| {
                        snapshot.channel = Some(event.channel);
                    });
                }
            }
            EVENT_RELAY_ADDRESS => {
                let relay = event.address.to_socket_addr()?;
                let queried = core.relay_address()?;
                if queried != relay {
                    bail!("TURN core relay address event/getter mismatch");
                }
                shared.snapshot.send_modify(|snapshot| {
                    snapshot.relay = Some(relay);
                });
            }
            EVENT_CONTROL_OVERFLOW => {
                shared.fail(Arc::from(format!(
                    "TURN control output ring overflow dropped {} datagrams",
                    event.dropped
                )));
            }
            EVENT_DATA_REJECTED => {}
            EVENT_FORCED_DESTROY => {
                if !shared.closing.load(Ordering::Acquire) {
                    shared.fail("TURN core was force-destroyed");
                }
            }
            EVENT_EVENT_OVERFLOW => {
                shared.fail(Arc::from(format!(
                    "TURN event ring overflow dropped {} events",
                    event.dropped
                )));
            }
            kind => {
                shared.fail(Arc::from(format!(
                    "TURN core returned unknown event {kind}"
                )));
            }
        }
    }
    if unexpected_destroy && shared.terminal().is_none() {
        shared.fail("TURN allocation entered DESTROYING unexpectedly");
    }
    Ok(next_timer)
}

fn process_packet(
    core: &NativeCore,
    shared: &DriverShared,
    incoming: &mpsc::Sender<PacketBuf>,
    mut packet: PacketBuf,
) -> PacketAction {
    let wire = packet.as_slice();
    if let Some((channel, payload_length)) = channel_data_header(wire) {
        if channel != shared.channel.load(Ordering::Acquire) {
            return PacketAction::Wait;
        }
        if packet.trim_front(4).is_err() || packet.truncate(payload_length).is_err() {
            return PacketAction::Wait;
        }
        match incoming.try_send(packet) {
            Ok(()) => PacketAction::Wait,
            Err(mpsc::error::TrySendError::Full(_)) => {
                shared.queue_full_drops.fetch_add(1, Ordering::Relaxed);
                PacketAction::Wait
            }
            Err(mpsc::error::TrySendError::Closed(_)) => PacketAction::OwnerClosed,
        }
    } else {
        if is_stun(wire) {
            let status = core.input_stun(wire);
            if !matches!(status, 0 | RESULT_NOT_CONTROL | RESULT_INVALID_ARGUMENT) {
                let _ = status;
            }
            return PacketAction::Pump;
        }
        PacketAction::Wait
    }
}

fn process_deficit_packet(core: &NativeCore, shared: &DriverShared, wire: &[u8]) -> PacketAction {
    if let Some((channel, _)) = channel_data_header(wire) {
        if channel == shared.channel.load(Ordering::Acquire) {
            shared.pool_deficit_drops.fetch_add(1, Ordering::Relaxed);
        }
        PacketAction::Wait
    } else if is_stun(wire) {
        let _ = core.input_stun(wire);
        PacketAction::Pump
    } else {
        PacketAction::Wait
    }
}

enum PacketAction {
    Wait,
    Pump,
    OwnerClosed,
}

fn channel_data_header(wire: &[u8]) -> Option<(u16, usize)> {
    if wire.len() < 4 || wire[0] & 0xc0 != 0x40 {
        return None;
    }
    let channel = u16::from_be_bytes([wire[0], wire[1]]);
    if !(0x4000..=0x7fff).contains(&channel) {
        return None;
    }
    let payload_length = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    if payload_length > wire.len() - 4 {
        return None;
    }
    if wire.len() - 4 - payload_length > 3 {
        return None;
    }
    Some((channel, payload_length))
}

fn is_stun(wire: &[u8]) -> bool {
    wire.len() >= 20 && wire[0] & 0xc0 == 0 && wire[4..8] == MAGIC_COOKIE
}

fn encode_channel_data(packet: &mut PacketBuf, channel: u16) -> Result<()> {
    if !(0x4000..=0x7fff).contains(&channel) {
        bail!("TURN channel is invalid");
    }
    let payload_length = packet.len();
    if payload_length > u16::MAX as usize {
        bail!("TURN payload too large");
    }
    let padding = (4 - payload_length % 4) % 4;
    let range = packet.range();
    if range.start < 4
        || range
            .end
            .checked_add(padding)
            .is_none_or(|end| end > PACKET_CAPACITY)
    {
        bail!("TURN ChannelData exceeds packet buffer");
    }
    packet.extend_tail(padding)?.fill(0);
    let header = packet.prepend(4)?;
    header[..2].copy_from_slice(&channel.to_be_bytes());
    header[2..4].copy_from_slice(&(payload_length as u16).to_be_bytes());
    Ok(())
}

fn configure_udp_socket_buffers(socket: &UdpSocket) {
    let socket = SockRef::from(socket);
    let _ = socket.set_recv_buffer_size(UDP_RECEIVE_BUFFER_BYTES);
    let _ = socket.set_send_buffer_size(UDP_SEND_BUFFER_BYTES);
}

fn method_name(method: u32) -> &'static str {
    match method {
        METHOD_ALLOCATE => "Allocate",
        METHOD_REFRESH => "Refresh",
        METHOD_CREATE_PERMISSION => "CreatePermission",
        METHOD_CHANNEL_BIND => "ChannelBind",
        _ => "request",
    }
}

fn stun_suffix(stun_code: i32) -> String {
    if stun_code == 0 {
        String::new()
    } else {
        format!("; STUN error {stun_code}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_socket_buffer_budget_is_bounded_per_worker() {
        assert_eq!(UDP_RECEIVE_BUFFER_BYTES, 1024 * 1024);
        assert_eq!(UDP_SEND_BUFFER_BYTES, 512 * 1024);
    }

    #[test]
    fn channel_header_accepts_padding_and_rejects_truncation() {
        assert_eq!(
            channel_data_header(&[0x40, 0x21, 0, 3, 1, 2, 3, 0]),
            Some((0x4021, 3))
        );
        assert_eq!(channel_data_header(&[0x40, 0x21, 0, 4, 1, 2, 3]), None);
        assert_eq!(
            channel_data_header(&[0x40, 0x21, 0, 1, 1, 0, 0, 0, 0]),
            None
        );
        assert_eq!(channel_data_header(&[0x3f, 0xff, 0, 0]), None);
        assert_eq!(channel_data_header(&[0x80, 0, 0, 0]), None);
    }

    #[test]
    fn channel_encoding_reuses_storage_and_zeroes_padding() {
        let pool = PacketPool::new(1);
        let mut packet = pool.acquire();
        let storage = packet.storage_mut().as_ptr();
        packet.read_area()[..3].copy_from_slice(&[1, 2, 3]);
        packet.set_read_len(3).unwrap();
        encode_channel_data(&mut packet, 0x4567).unwrap();
        assert_eq!(packet.storage_mut().as_ptr(), storage);
        assert_eq!(packet.as_slice(), &[0x45, 0x67, 0, 3, 1, 2, 3, 0]);
    }

    #[test]
    fn stun_classifier_is_strict() {
        let mut packet = [0u8; 20];
        packet[4..8].copy_from_slice(&MAGIC_COOKIE);
        assert!(is_stun(&packet));
        packet[0] = 0x40;
        assert!(!is_stun(&packet));
        packet[0] = 0;
        packet[4] ^= 1;
        assert!(!is_stun(&packet));
    }

    #[test]
    fn native_addresses_are_host_endian_and_family_exact() {
        let mut address = NativeAddress {
            family: AF_IPV4,
            port: 3478,
            ..NativeAddress::default()
        };
        address.ip[..4].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(
            address.to_socket_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 3478))
        );
        address.family = 99;
        assert!(address.to_socket_addr().is_err());
    }

    #[test]
    fn invalid_channel_cannot_touch_packet() {
        let pool = PacketPool::new(1);
        let mut packet = pool.acquire();
        packet.read_area()[0] = 7;
        packet.set_read_len(1).unwrap();
        let before = packet.range();
        assert!(encode_channel_data(&mut packet, 0x3fff).is_err());
        assert_eq!(packet.range(), before);
        assert_eq!(packet.as_slice(), &[7]);
    }

    #[test]
    fn completion_sequences_are_independent() {
        let mut snapshot = CoreSnapshot::default();
        snapshot.completion_mut(METHOD_ALLOCATE).unwrap().sequence = 1;
        snapshot
            .completion_mut(METHOD_CREATE_PERMISSION)
            .unwrap()
            .sequence = 2;
        snapshot
            .completion_mut(METHOD_CHANNEL_BIND)
            .unwrap()
            .sequence = 3;
        snapshot.completion_mut(METHOD_REFRESH).unwrap().sequence = 4;
        assert_eq!(snapshot.completion(METHOD_ALLOCATE).sequence, 1);
        assert_eq!(snapshot.completion(METHOD_CREATE_PERMISSION).sequence, 2);
        assert_eq!(snapshot.completion(METHOD_CHANNEL_BIND).sequence, 3);
        assert_eq!(snapshot.completion(METHOD_REFRESH).sequence, 4);
    }

    #[test]
    fn resume_validation_requires_a_late_ready_session() {
        let deadline = Instant::now();
        assert!(!resume_validation_due(
            deadline + TURN_RESUME_VALIDATION_STALL - Duration::from_millis(1),
            deadline,
            STATE_READY,
            false,
        ));
        assert!(resume_validation_due(
            deadline + TURN_RESUME_VALIDATION_STALL,
            deadline,
            STATE_READY,
            false,
        ));
        assert!(!resume_validation_due(
            deadline + TURN_RESUME_VALIDATION_STALL,
            deadline,
            STATE_READY - 1,
            false,
        ));
        assert!(!resume_validation_due(
            deadline + TURN_RESUME_VALIDATION_STALL,
            deadline,
            STATE_READY,
            true,
        ));
    }

    #[test]
    fn native_core_is_thread_safe_by_contract() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NativeCore>();
    }
}

#[cfg(test)]
#[path = "turn_integration_tests.rs"]
mod integration_tests;
