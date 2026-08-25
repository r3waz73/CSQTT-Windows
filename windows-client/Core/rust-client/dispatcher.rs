// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    packet::{PacketBuf, PacketPool},
    stats::Stats,
    striped_scheduler::{DispatchTicket, PacketClass, StripedScheduler},
    tun,
};
use anyhow::Result;
use arc_swap::ArcSwap;
use crossbeam_queue::ArrayQueue;
use socket2::SockRef;
use std::{
    fs::File,
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Notify, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;

const RETURN_CAPACITY: usize = 1024;
const RETURN_MAX_AGE: Duration = Duration::from_millis(250);

const QUEUE_ACTIVE: u64 = 1;

struct QueuedPacket {
    packet: PacketBuf,
    queued_at: Instant,
    epoch: u64,
}

struct PacketQueue {
    queue: ArrayQueue<QueuedPacket>,
    notify: Notify,
    state: AtomicU64,
    senders: AtomicUsize,
    receiver_open: AtomicBool,
    max_age: Duration,
}

pub struct PacketSender {
    shared: Arc<PacketQueue>,
}

pub struct PacketReceiver {
    shared: Arc<PacketQueue>,
}

impl Clone for PacketSender {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for PacketSender {
    fn drop(&mut self) {
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.notify.notify_waiters();
        }
    }
}

impl PacketSender {
    pub fn try_send(&self, packet: PacketBuf) -> std::result::Result<(), PacketBuf> {
        self.send(packet, false)
    }

    pub fn force_send(&self, packet: PacketBuf) -> std::result::Result<(), PacketBuf> {
        self.send(packet, true)
    }

    fn send(&self, packet: PacketBuf, force: bool) -> std::result::Result<(), PacketBuf> {
        if !self.shared.receiver_open.load(Ordering::Acquire) {
            return Err(packet);
        }
        let state = self.shared.state.load(Ordering::Acquire);
        if state & QUEUE_ACTIVE == 0 {
            return Err(packet);
        }
        let queued = QueuedPacket {
            packet,
            queued_at: Instant::now(),
            epoch: state >> 1,
        };
        if force {
            drop(self.shared.queue.force_push(queued));
        } else if let Err(queued) = self.shared.queue.push(queued) {
            return Err(queued.packet);
        }
        self.shared.notify.notify_one();
        Ok(())
    }
}

impl PacketReceiver {
    pub fn try_recv(&self) -> Option<PacketBuf> {
        loop {
            let queued = self.shared.queue.pop()?;
            let state = self.shared.state.load(Ordering::Acquire);
            if state & QUEUE_ACTIVE != 0
                && queued.epoch == state >> 1
                && Instant::now().saturating_duration_since(queued.queued_at) <= self.shared.max_age
            {
                return Some(queued.packet);
            }
        }
    }

    pub async fn recv(&self, cancel: &CancellationToken) -> Option<PacketBuf> {
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            if let Some(packet) = self.try_recv() {
                return Some(packet);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return None;
            }
            let notified = self.shared.notify.notified();
            if let Some(packet) = self.try_recv() {
                return Some(packet);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return None;
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return None,
                _ = notified => {}
            }
        }
    }

    fn resume(&self) {
        let previous = self.shared.state.load(Ordering::Acquire) >> 1;
        let epoch = previous.saturating_add(1);
        self.shared.state.store(epoch << 1, Ordering::Release);
        self.purge();
        self.shared
            .state
            .store((epoch << 1) | QUEUE_ACTIVE, Ordering::Release);
        self.shared.notify.notify_waiters();
    }

    fn suspend(&self) {
        let state = self.shared.state.load(Ordering::Acquire);
        self.shared
            .state
            .store(state & !QUEUE_ACTIVE, Ordering::Release);
        self.purge();
        self.shared.notify.notify_waiters();
    }

    fn purge(&self) {
        while self.shared.queue.pop().is_some() {}
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.shared.senders.load(Ordering::Acquire) == 0 && self.shared.queue.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shared.queue.len()
    }
}

impl Drop for PacketReceiver {
    fn drop(&mut self) {
        self.shared.receiver_open.store(false, Ordering::Release);
        self.purge();
        self.shared.notify.notify_waiters();
    }
}

pub fn packet_channel(
    capacity: usize,
    max_age: Duration,
    active: bool,
) -> (PacketSender, PacketReceiver) {
    let state = u64::from(active) * QUEUE_ACTIVE;
    let shared = Arc::new(PacketQueue {
        queue: ArrayQueue::new(capacity.max(1)),
        notify: Notify::new(),
        state: AtomicU64::new(state),
        senders: AtomicUsize::new(1),
        receiver_open: AtomicBool::new(true),
        max_age,
    });
    (
        PacketSender {
            shared: shared.clone(),
        },
        PacketReceiver { shared },
    )
}

#[derive(Clone)]
pub struct WorkerChannels {
    pub id: usize,
    pub incarnation_id: u64,
    pub normal: PacketSender,
    pub small: PacketSender,
    pub bulk: PacketSender,
    pub doomsday: PacketSender,
}

pub struct Dispatcher {
    workers: ArcSwap<Vec<WorkerChannels>>,
    return_tx: PacketSender,
    scheduler: StripedScheduler,
    cancel: CancellationToken,
    tasks: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
}

impl Dispatcher {
    pub async fn start(
        listen: &str,
        tun_uds: Option<String>,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
        cancel: CancellationToken,
    ) -> Result<(Arc<Self>, String)> {
        let tun_mode = tun_uds.is_some();
        let (return_tx, return_rx) = packet_channel(RETURN_CAPACITY, RETURN_MAX_AGE, !tun_mode);
        let dispatcher = Arc::new(Self {
            workers: ArcSwap::from_pointee(Vec::new()),
            return_tx,
            scheduler: StripedScheduler::new(),
            cancel: cancel.clone(),
            tasks: tokio::sync::Mutex::new(Vec::new()),
        });
        if let Some(name) = tun_uds {
            crate::log_error!("[КЛИЕНТ] Запуск UDS-слушателя: {name} для получения TUN FD...");
            let io_dispatcher = dispatcher.clone();
            let task_cancel = dispatcher.cancel.clone();
            let io_task = spawn_critical("TUN dispatcher", task_cancel, async move {
                let mut return_rx = return_rx;
                loop {
                    let result = tun::receive_fd(name.clone(), io_dispatcher.cancel.clone()).await;
                    let file = match result {
                        Ok(file) => file,
                        Err(_) if io_dispatcher.cancel.is_cancelled() => return,
                        Err(error) => {
                            crate::log_error!(
                                "[ОШИБКА] Не удалось получить TUN FD из UDS: {error}"
                            );
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    crate::log_error!("[КЛИЕНТ] TUN FD успешно получен!");
                    return_rx.resume();
                    io_dispatcher
                        .run_tun(file, &mut return_rx, pool.clone(), stats.clone())
                        .await;
                    return_rx.suspend();
                }
            });
            dispatcher.tasks.lock().await.push(io_task);
            Ok((dispatcher, "0".to_owned()))
        } else {
            let socket = bind_udp(listen).await?;
            let local_port = socket.local_addr()?.port().to_string();
            let socket = Arc::new(socket);
            let client = Arc::new(tokio::sync::RwLock::new(None));
            let read_dispatcher = dispatcher.clone();
            let read_socket = socket.clone();
            let read_client = client.clone();
            let read_pool = pool.clone();
            let read_stats = stats.clone();
            let read_cancel = dispatcher.cancel.clone();
            let read_task = spawn_critical("UDP reader", read_cancel, async move {
                read_dispatcher
                    .read_udp(read_socket, read_client, read_pool, read_stats)
                    .await;
            });
            let write_dispatcher = dispatcher.clone();
            let write_cancel = dispatcher.cancel.clone();
            let write_task = spawn_critical("UDP writer", write_cancel, async move {
                write_dispatcher
                    .write_udp(socket, client, return_rx, stats)
                    .await;
            });
            dispatcher
                .tasks
                .lock()
                .await
                .extend([read_task, write_task]);
            Ok((dispatcher, local_port))
        }
    }

    pub fn register(&self, channels: WorkerChannels) {
        let id = channels.id;
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id);
            updated.push(channels.clone());
            updated.sort_unstable_by_key(|worker| worker.id);
            Arc::new(updated)
        });
    }

    pub fn unregister(&self, id: usize, incarnation_id: u64) {
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id || worker.incarnation_id != incarnation_id);
            Arc::new(updated)
        });
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.workers.load().len()
    }

    #[cfg(test)]
    pub fn worker(&self, id: usize) -> Option<WorkerChannels> {
        self.workers
            .load()
            .iter()
            .find(|worker| worker.id == id)
            .cloned()
    }

    pub fn return_packet(&self, packet: PacketBuf) {
        let _ = self.return_tx.force_send(packet);
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        for task in self.tasks.lock().await.drain(..) {
            let _ = task.await;
        }
    }

    #[cfg(unix)]
    async fn run_tun(
        self: &Arc<Self>,
        file: File,
        receiver: &mut PacketReceiver,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
    ) {
        use tokio::io::unix::AsyncFd;

        let device = match AsyncFd::new(file) {
            Ok(device) => Arc::new(device),
            Err(error) => {
                crate::log_error!("[ОШИБКА] Не удалось зарегистрировать TUN FD: {error}");
                return;
            }
        };
        tokio::select! {
            _ = self.cancel.cancelled() => {}
            _ = self.clone().read_tun(device.clone(), pool, stats.clone()) => {}
            _ = self.write_tun(device, receiver, stats) => {}
        }
    }

    #[cfg(not(unix))]
    async fn run_tun(
        self: &Arc<Self>,
        _file: File,
        _receiver: &mut PacketReceiver,
        _pool: Arc<PacketPool>,
        _stats: Arc<Stats>,
    ) {
        crate::log_error!("[ОШИБКА] TUN FD поддерживается только на Android и Unix");
    }

    #[cfg(unix)]
    async fn read_tun(
        self: Arc<Self>,
        device: Arc<tokio::io::unix::AsyncFd<File>>,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
    ) {
        use std::os::fd::AsRawFd;

        loop {
            let readiness = tokio::select! {
                _ = self.cancel.cancelled() => return,
                result = device.readable() => result,
            };
            let mut guard = match readiness {
                Ok(guard) => guard,
                Err(error) => {
                    crate::log_error!("[ОШИБКА] Ожидание чтения TUN завершено: {error}");
                    return;
                }
            };
            
            // Burst read: read up to 32 packets in a row while TUN FD has pending datagrams
            let mut burst = 0usize;
            while burst < 32 {
                let Some(mut packet) = pool.try_acquire() else {
                    break;
                };
                let result = guard.try_io(|inner| {
                    let area = packet.read_area();
                    let length = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            area.as_mut_ptr().cast(),
                            area.len(),
                        )
                    };
                    if length < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(length as usize)
                    }
                });
                match result {
                    Ok(Ok(0)) => return,
                    Ok(Ok(length)) => {
                        burst += 1;
                        if packet.set_read_len(length).is_err() {
                            return;
                        }
                        stats
                            .total_bytes_up
                            .fetch_add(length as i64, Ordering::Relaxed);
                        self.dispatch(packet);
                    }
                    Ok(Err(error)) if is_retryable_tun_error(&error) => {
                        break;
                    }
                    Ok(Err(error)) if is_closed_tun_error(&error) => {
                        crate::log_error!("[TUN] Интерфейс закрыт, ожидаем новый FD");
                        return;
                    }
                    Ok(Err(error)) => {
                        crate::log_error!("[ОШИБКА] Чтение TUN завершено: {error}");
                        return;
                    }
                    Err(_) => break, // WouldBlock
                }
            }
        }
    }

    async fn read_udp(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        client: Arc<tokio::sync::RwLock<Option<SocketAddr>>>,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
    ) {
        loop {
            let Some(mut packet) = pool.try_acquire() else {
                tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
                continue;
            };
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                result = socket.recv_from(packet.read_area()) => match result {
                    Ok((length, address)) => {
                        *client.write().await = Some(address);
                        if packet.set_read_len(length).is_err() {
                            continue;
                        }
                        stats.total_bytes_up.fetch_add(length as i64, Ordering::Relaxed);
                        self.dispatch(packet);
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
    }

    fn dispatch(&self, packet: PacketBuf) {
        self.dispatch_now(packet);
    }

    fn dispatch_now(&self, mut packet: PacketBuf) {
        let workers = self.workers.load();
        let Some(ticket) = self.scheduler.begin(workers.len(), packet.as_slice()) else {
            return;
        };
        if let Err(returned) = try_workers(&workers, ticket, packet) {
            packet = returned;
            let _ = try_normal_workers(&workers, ticket, packet);
        }
    }

    #[cfg(unix)]
    async fn write_tun(
        &self,
        device: Arc<tokio::io::unix::AsyncFd<File>>,
        receiver: &mut PacketReceiver,
        stats: Arc<Stats>,
    ) {
        loop {
            let packet = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return,
                packet = receiver.recv(&self.cancel) => match packet {
                    Some(packet) => packet,
                    None => return,
                },
            };
            if !self.write_tun_packet(&device, &stats, packet).await {
                return;
            }

            // Burst write: immediately drain and write remaining queued packets up to 64
            let mut burst = 0usize;
            while burst < 64 {
                if let Some(next) = receiver.try_recv() {
                    burst += 1;
                    if !self.write_tun_packet(&device, &stats, next).await {
                        return;
                    }
                } else {
                    break;
                }
            }
        }
    }

    #[cfg(unix)]
    async fn write_tun_packet(
        &self,
        device: &Arc<tokio::io::unix::AsyncFd<File>>,
        stats: &Stats,
        packet: PacketBuf,
    ) -> bool {
        use std::os::fd::AsRawFd;

        let mut written = 0;
        while written < packet.len() {
            let readiness = tokio::select! {
                _ = self.cancel.cancelled() => return false,
                result = device.writable() => result,
            };
            let mut guard = match readiness {
                Ok(guard) => guard,
                Err(error) => {
                    crate::log_error!("[ОШИБКА] Ожидание записи TUN завершено: {error}");
                    return false;
                }
            };
            let result = guard.try_io(|inner| {
                let remaining = &packet.as_slice()[written..];
                let length = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        remaining.as_ptr().cast(),
                        remaining.len(),
                    )
                };
                if length < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(length as usize)
                }
            });
            match result {
                Ok(Ok(0)) => {
                    crate::log_error!("[ОШИБКА] Запись TUN вернула 0 байт");
                    return false;
                }
                Ok(Ok(length)) => written += length,
                Ok(Err(error)) if is_retryable_tun_error(&error) => {
                    tokio::task::yield_now().await;
                }
                Ok(Err(error)) if is_closed_tun_error(&error) => {
                    crate::log_error!("[TUN] Интерфейс закрыт, ожидаем новый FD");
                    return false;
                }
                Ok(Err(error)) => {
                    crate::log_error!("[ОШИБКА] Запись TUN завершена: {error}");
                    return false;
                }
                Err(_) => {}
            }
        }
        stats
            .total_bytes_down
            .fetch_add(packet.len() as i64, Ordering::Relaxed);
        true
    }

    async fn write_udp(
        &self,
        socket: Arc<UdpSocket>,
        client: Arc<tokio::sync::RwLock<Option<SocketAddr>>>,
        receiver: PacketReceiver,
        stats: Arc<Stats>,
    ) {
        loop {
            let packet = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return,
                packet = receiver.recv(&self.cancel) => match packet {
                    Some(packet) => packet,
                    None => return,
                },
            };
            let address = *client.read().await;
            self.write_udp_packet(&socket, address, &stats, packet)
                .await;
        }
    }

    async fn write_udp_packet(
        &self,
        socket: &UdpSocket,
        address: Option<SocketAddr>,
        stats: &Stats,
        packet: PacketBuf,
    ) {
        if let Some(address) = address
            && socket.send_to(packet.as_slice(), address).await.is_ok()
        {
            stats
                .total_bytes_down
                .fetch_add(packet.len() as i64, Ordering::Relaxed);
        }
    }
}

fn spawn_critical<F>(name: &'static str, cancel: CancellationToken, future: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = tokio::spawn(future).await {
            crate::log_error!("[СУПЕРВИЗОР] {name} завершился аварийно: {error}");
            cancel.cancel();
        }
    })
}

#[cfg(unix)]
fn is_closed_tun_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EIO || code == libc::EBADF || code == libc::ENODEV
    )
}

#[cfg(unix)]
fn is_retryable_tun_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Interrupted
        || error.kind() == std::io::ErrorKind::WouldBlock
        || matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ENOBUFS || code == libc::ENOMEM
        )
}

fn try_workers(
    workers: &[WorkerChannels],
    ticket: DispatchTicket,
    mut packet: PacketBuf,
) -> Result<(), PacketBuf> {
    for offset in 0..ticket.cohort_len {
        let index = ticket.worker_index(offset);
        let worker = &workers[index];
        let channel = match ticket.class {
            PacketClass::Doomsday => &worker.doomsday,
            PacketClass::Small => &worker.small,
            PacketClass::Bulk => &worker.bulk,
        };
        match channel.try_send(packet) {
            Ok(()) => return Ok(()),
            Err(returned) => packet = returned,
        }
    }
    Err(packet)
}

fn try_normal_workers(
    workers: &[WorkerChannels],
    ticket: DispatchTicket,
    mut packet: PacketBuf,
) -> Result<(), PacketBuf> {
    for offset in 0..ticket.cohort_len {
        let index = ticket.worker_index(offset);
        match workers[index].normal.try_send(packet) {
            Ok(()) => return Ok(()),
            Err(returned) => packet = returned,
        }
    }
    if workers.is_empty() || ticket.cohort_len == 0 {
        return Err(packet);
    }
    workers[ticket.worker_index(0)].normal.force_send(packet)
}

async fn bind_udp(address: &str) -> Result<UdpSocket> {
    for attempt in 1..=5 {
        match UdpSocket::bind(address).await {
            Ok(socket) => {
                SockRef::from(&socket).set_recv_buffer_size(625 * 1024)?;
                SockRef::from(&socket).set_send_buffer_size(625 * 1024)?;
                return Ok(socket);
            }
            Err(error) if attempt < 5 => {
                crate::log_error!("[ОЖИДАНИЕ] Порт {address} занят. Жду... ({attempt}/5): {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => crate::log_error!("[АВТО-ПОРТ] Порт {address} всё ещё занят: {error}"),
        }
    }
    UdpSocket::bind("127.0.0.1:0").await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;

    #[derive(Clone, Copy, Default)]
    struct QueueCoverage {
        full_rejection: usize,
        forced_replacement: usize,
        inactive_rejection: usize,
        suspended: usize,
        resumed: usize,
        purged: usize,
    }

    impl QueueCoverage {
        fn complete(self) -> bool {
            self.full_rejection > 0
                && self.forced_replacement > 0
                && self.inactive_rejection > 0
                && self.suspended > 0
                && self.resumed > 0
                && self.purged > 0
        }
    }

    fn test_dispatcher() -> (Arc<Dispatcher>, PacketReceiver) {
        let (return_tx, return_rx) = packet_channel(64, RETURN_MAX_AGE, true);
        (
            Arc::new(Dispatcher {
                workers: ArcSwap::from_pointee(Vec::new()),
                return_tx,
                scheduler: StripedScheduler::new(),
                cancel: CancellationToken::new(),
                tasks: tokio::sync::Mutex::new(Vec::new()),
            }),
            return_rx,
        )
    }

    fn channels(
        id: usize,
        capacity: usize,
    ) -> (
        WorkerChannels,
        PacketReceiver,
        PacketReceiver,
        PacketReceiver,
        PacketReceiver,
    ) {
        let (normal, normal_rx) = packet_channel(capacity, RETURN_MAX_AGE, true);
        let (small, small_rx) = packet_channel(capacity, RETURN_MAX_AGE, true);
        let (bulk, bulk_rx) = packet_channel(capacity, RETURN_MAX_AGE, true);
        let (doomsday, doomsday_rx) = packet_channel(capacity, RETURN_MAX_AGE, true);
        (
            WorkerChannels {
                id,
                incarnation_id: id as u64 + 1,
                normal,
                small,
                bulk,
                doomsday,
            },
            normal_rx,
            small_rx,
            bulk_rx,
            doomsday_rx,
        )
    }

    fn queue_trace_outcome(actions: &[(u8, u8)], replace_oldest: bool) -> (bool, QueueCoverage) {
        let capacity = 7;
        let pool = PacketPool::new(32);
        let (sender, receiver) = packet_channel(capacity, Duration::from_secs(3_600), true);
        let mut model = VecDeque::new();
        let mut active = true;
        let mut coverage = QueueCoverage::default();
        for &(operation, value) in actions {
            match operation % 6 {
                0 => {
                    let mut packet = pool.acquire();
                    packet.set_read_len(1).unwrap();
                    packet.as_mut_slice()[0] = value;
                    let accepted = sender.try_send(packet).is_ok();
                    let expected = active && model.len() < capacity;
                    if accepted != expected {
                        return (false, coverage);
                    }
                    if expected {
                        model.push_back(value);
                    } else if active {
                        coverage.full_rejection += 1;
                    } else {
                        coverage.inactive_rejection += 1;
                    }
                }
                1 => {
                    let mut packet = pool.acquire();
                    packet.set_read_len(1).unwrap();
                    packet.as_mut_slice()[0] = value;
                    let accepted = sender.force_send(packet).is_ok();
                    if accepted != active {
                        return (false, coverage);
                    }
                    if active {
                        if model.len() == capacity {
                            coverage.forced_replacement += 1;
                            if replace_oldest {
                                model.pop_front();
                            } else {
                                model.pop_back();
                            }
                        }
                        model.push_back(value);
                    } else {
                        coverage.inactive_rejection += 1;
                    }
                }
                2 => {
                    let actual = receiver.try_recv().map(|packet| packet.as_slice()[0]);
                    if actual != model.pop_front() {
                        return (false, coverage);
                    }
                }
                3 => {
                    receiver.suspend();
                    active = false;
                    model.clear();
                    coverage.suspended += 1;
                }
                4 => {
                    receiver.resume();
                    active = true;
                    model.clear();
                    coverage.resumed += 1;
                }
                _ => {
                    receiver.purge();
                    model.clear();
                    coverage.purged += 1;
                }
            }
        }
        while let Some(expected) = model.pop_front() {
            if receiver.try_recv().map(|packet| packet.as_slice()[0]) != Some(expected) {
                return (false, coverage);
            }
        }
        (
            receiver.try_recv().is_none() && pool.available() == pool.capacity(),
            coverage,
        )
    }

    fn queue_trace_matches(actions: &[(u8, u8)], replace_oldest: bool) -> bool {
        queue_trace_outcome(actions, replace_oldest).0
    }

    fn mix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn deterministic_queue_actions(seed: u64, length: usize) -> Vec<(u8, u8)> {
        let mut state = seed;
        let mut actions = Vec::with_capacity(length);
        let prefix = [
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (0, 5),
            (0, 6),
            (0, 7),
            (0, 8),
            (1, 9),
            (3, 0),
            (0, 10),
            (4, 0),
            (1, 11),
            (5, 0),
        ];
        actions.extend(prefix.into_iter().take(length));
        for _ in actions.len()..length {
            state = mix64(state);
            actions.push(((state % 6) as u8, (state >> 24) as u8));
        }
        actions
    }

    fn tcp_packet(pool: &Arc<PacketPool>, source_port: u16, sequence: u32) -> PacketBuf {
        tcp_packet_len(pool, source_port, sequence, 1_200)
    }

    fn tcp_packet_len(
        pool: &Arc<PacketPool>,
        source_port: u16,
        sequence: u32,
        len: usize,
    ) -> PacketBuf {
        assert!(len >= 40);
        let mut packet = pool.acquire();
        packet.set_read_len(len).unwrap();
        let bytes = packet.as_mut_slice();
        bytes.fill(0);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[10, 66, 67, 2]);
        bytes[16..20].copy_from_slice(&[1, 1, 1, 1]);
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
        bytes[32] = 5 << 4;
        bytes[33] = 0x18;
        packet
    }

    fn packet_sequence(packet: &PacketBuf) -> u32 {
        u32::from_be_bytes(packet.as_slice()[24..28].try_into().unwrap_or_default())
    }

    #[tokio::test(start_paused = true)]
    async fn direct_downlink_preserves_late_tcp_retransmit() {
        let (dispatcher, return_rx) = test_dispatcher();
        let pool = PacketPool::new(4);
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 0));
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 2_320));
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 0);
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 2_320);
        tokio::time::advance(Duration::from_millis(81)).await;
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 1_160));
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 1_160);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    #[ignore]
    fn tcp_bulk_fallback_can_use_every_active_worker() {
        let (dispatcher, _return_rx) = test_dispatcher();
        let pool = PacketPool::new(384);
        let mut workers = Vec::new();
        let mut receivers = Vec::new();
        for id in 0..162 {
            let (worker, normal, _small, bulk, _doomsday) = channels(id, 1);
            workers.push(worker);
            receivers.push((normal, bulk));
        }
        dispatcher.workers.store(Arc::new(workers));
        let probe = tcp_packet(&pool, 51_000, 7);
        let ticket = dispatcher.scheduler.begin(162, probe.as_slice()).unwrap();
        drop(probe);
        assert_eq!(ticket.cohort_len, 162, "cohort must cover all workers");
        for _ in 0..324 {
            dispatcher.dispatch(tcp_packet(&pool, 51_000, 7));
        }
        let total_queued: usize = receivers
            .iter()
            .map(|(normal, bulk)| bulk.len() + normal.len())
            .sum();
        assert!(total_queued > 0, "nothing queued");
    }

    #[test]
    fn unregister_and_recover_one_worker_never_changes_its_siblings() {
        let (dispatcher, _return_rx) = test_dispatcher();
        for id in 0..9 {
            dispatcher.register(channels(id, 1).0);
        }
        for cycle in 0..10_000 {
            let id = cycle % 9;
            dispatcher.unregister(id, id as u64 + 1);
            assert_eq!(dispatcher.active_count(), 8);
            for sibling in 0..9 {
                assert_eq!(dispatcher.worker(sibling).is_some(), sibling != id);
            }
            dispatcher.register(channels(id, 1).0);
            assert_eq!(dispatcher.active_count(), 9);
        }
    }

    #[test]
    fn stale_registration_drop_cannot_unregister_replacement() {
        let (dispatcher, _return_rx) = test_dispatcher();
        let mut old = channels(4, 1).0;
        old.incarnation_id = 40;
        dispatcher.register(old);
        let mut replacement = channels(4, 1).0;
        replacement.incarnation_id = 41;
        dispatcher.register(replacement);

        dispatcher.unregister(4, 40);

        assert_eq!(dispatcher.active_count(), 1);
        assert_eq!(dispatcher.worker(4).unwrap().incarnation_id, 41);
    }

    #[test]
    fn overload_keeps_queues_and_packet_memory_strictly_bounded() {
        let (dispatcher, _return_rx) = test_dispatcher();
        let pool = PacketPool::new(64);
        let mut workers = Vec::new();
        let mut receivers = Vec::new();
        for id in 0..9 {
            let (worker, normal, small, bulk, _doomsday) = channels(id, 1);
            workers.push(worker);
            receivers.push((normal, small, bulk));
        }
        dispatcher.workers.store(Arc::new(workers));
        for sequence in 0..100_000 {
            let mut packet = pool.try_acquire().unwrap();
            packet
                .set_read_len(if sequence % 2 == 0 { 100 } else { 1_000 })
                .unwrap();
            dispatcher.dispatch(packet);
        }
        let mut queued = 0;
        for (normal, small, bulk) in &receivers {
            queued += normal.len() + small.len() + bulk.len();
        }
        assert!(queued <= 27);
        assert!(queued > 0);
        assert_eq!(pool.available() + queued, pool.capacity());
        for (normal, small, bulk) in &receivers {
            while normal.try_recv().is_some() {}
            while small.try_recv().is_some() {}
            while bulk.try_recv().is_some() {}
        }
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn saturated_queue_replaces_oldest_with_newest() {
        let pool = PacketPool::new(4);
        let (sender, receiver) = packet_channel(2, Duration::from_secs(1), true);
        for value in 1..=3 {
            let mut packet = pool.acquire();
            packet.set_read_len(1).unwrap();
            packet.as_mut_slice()[0] = value;
            assert!(sender.force_send(packet).is_ok());
        }
        assert_eq!(receiver.try_recv().unwrap().as_slice(), [2]);
        assert_eq!(receiver.try_recv().unwrap().as_slice(), [3]);
        assert!(receiver.try_recv().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_packets_are_released_instead_of_replayed() {
        let pool = PacketPool::new(2);
        let (sender, receiver) = packet_channel(2, Duration::from_millis(100), true);
        assert!(sender.force_send(pool.acquire()).is_ok());
        tokio::time::advance(Duration::from_millis(101)).await;
        assert!(receiver.try_recv().is_none());
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn suspend_and_resume_purge_previous_network_epoch() {
        let pool = PacketPool::new(3);
        let (sender, receiver) = packet_channel(3, Duration::from_secs(1), true);
        assert!(sender.force_send(pool.acquire()).is_ok());
        receiver.suspend();
        assert_eq!(pool.available(), pool.capacity());
        assert!(sender.force_send(pool.acquire()).is_err());
        receiver.resume();
        assert!(sender.force_send(pool.acquire()).is_ok());
        assert!(receiver.try_recv().is_some());
        assert!(receiver.try_recv().is_none());
    }

    proptest! {
        #[test]
        fn packet_queue_matches_bounded_reference_model(
            actions in proptest::collection::vec((any::<u8>(), any::<u8>()), 1..=2_000)
        ) {
            prop_assert!(queue_trace_matches(&actions, true));
        }
    }

    #[test]
    fn queue_oracle_detects_keep_oldest_mutation() {
        let actions = [
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 4),
            (1, 5),
            (1, 6),
            (1, 7),
            (1, 8),
            (2, 0),
        ];
        assert!(queue_trace_matches(&actions, true));
        assert!(!queue_trace_matches(&actions, false));
    }

    #[test]
    fn deterministic_queue_fault_generator_is_reproducible_and_complete() {
        let first = deterministic_queue_actions(0x1234_5678_9abc_def0, 4_096);
        let second = deterministic_queue_actions(0x1234_5678_9abc_def0, 4_096);
        let different = deterministic_queue_actions(0x1234_5678_9abc_def1, 4_096);
        assert_eq!(first, second);
        assert_ne!(first, different);
        let mut covered = [false; 6];
        for &(operation, _) in &first {
            covered[usize::from(operation % 6)] = true;
        }
        assert!(covered.into_iter().all(|value| value));
        let (matches, coverage) = queue_trace_outcome(&first, true);
        assert!(matches);
        assert!(coverage.complete());
    }

    #[test]
    fn queue_coverage_oracle_rejects_each_missing_state_transition() {
        let complete = QueueCoverage {
            full_rejection: 1,
            forced_replacement: 1,
            inactive_rejection: 1,
            suspended: 1,
            resumed: 1,
            purged: 1,
        };
        assert!(complete.complete());
        for index in 0..6 {
            let mut mutated = complete;
            match index {
                0 => mutated.full_rejection = 0,
                1 => mutated.forced_replacement = 0,
                2 => mutated.inactive_rejection = 0,
                3 => mutated.suspended = 0,
                4 => mutated.resumed = 0,
                _ => mutated.purged = 0,
            }
            assert!(!mutated.complete());
        }
    }

    #[test]
    #[ignore = "explicit deterministic stability soak"]
    fn deterministic_queue_chaos_soak() {
        let seconds = std::env::var("CSQTT_SOAK_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120)
            .max(1);
        let first_seed = std::env::var("CSQTT_SOAK_SEED")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let actions_per_seed = std::env::var("CSQTT_QUEUE_SOAK_ACTIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4_096)
            .max(14);
        let started = Instant::now();
        let mut offset = 0u64;
        loop {
            let seed = first_seed.wrapping_add(offset);
            let actions = deterministic_queue_actions(seed, actions_per_seed);
            let (matches, coverage) = queue_trace_outcome(&actions, true);
            assert!(
                matches && coverage.complete(),
                "packet queue diverged at reproducible seed {seed}"
            );
            offset = offset.wrapping_add(1);
            if started.elapsed() >= Duration::from_secs(seconds) {
                break;
            }
        }
    }

    #[test]
    fn concurrent_send_suspend_resume_storm_never_replays_previous_epoch() {
        let pool = PacketPool::new(4_096);
        let (sender, receiver) = packet_channel(64, Duration::from_secs(3_600), true);
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut threads = Vec::new();
        for thread in 0..8u8 {
            let sender = sender.clone();
            let pool = pool.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for sequence in 0..25_000u32 {
                    let mut packet = pool.acquire();
                    packet.set_read_len(2).unwrap();
                    packet.as_mut_slice()[0] = thread;
                    packet.as_mut_slice()[1] = sequence as u8;
                    drop(sender.force_send(packet));
                }
            }));
        }
        barrier.wait();
        for cycle in 0..10_000 {
            if cycle % 3 == 0 {
                receiver.suspend();
            } else if cycle % 3 == 1 {
                receiver.resume();
            } else {
                while receiver.try_recv().is_some() {}
            }
        }
        for thread in threads {
            thread.join().unwrap();
        }
        receiver.suspend();
        receiver.resume();
        let mut marker = pool.acquire();
        marker.set_read_len(1).unwrap();
        marker.as_mut_slice()[0] = 0xa5;
        assert!(sender.force_send(marker).is_ok());
        assert_eq!(receiver.try_recv().unwrap().as_slice(), [0xa5]);
        assert!(receiver.try_recv().is_none());
        drop(sender);
        drop(receiver);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn receiver_notification_race_has_no_lost_wakeup() {
        let pool = PacketPool::new(1);
        for sequence in 0..2_000 {
            let (sender, receiver) = packet_channel(1, Duration::from_secs(1), true);
            let cancel = CancellationToken::new();
            let waiter_cancel = cancel.clone();
            let waiter = tokio::spawn(async move { receiver.recv(&waiter_cancel).await });
            if sequence % 2 == 0 {
                tokio::task::yield_now().await;
            }
            assert!(sender.force_send(pool.acquire()).is_ok());
            let packet = tokio::time::timeout(Duration::from_millis(1000), waiter)
                .await
                .unwrap()
                .unwrap();
            assert!(packet.is_some());
            drop(packet);
            drop(sender);
            assert_eq!(pool.available(), pool.capacity());
        }
    }

    #[test]
    fn receiver_drop_race_releases_every_buffer() {
        for _ in 0..100 {
            let pool = PacketPool::new(32);
            let (sender, receiver) = packet_channel(8, Duration::from_secs(1), true);
            let barrier = Arc::new(std::sync::Barrier::new(9));
            let mut threads = Vec::new();
            for _ in 0..8 {
                let sender = sender.clone();
                let pool = pool.clone();
                let barrier = barrier.clone();
                threads.push(std::thread::spawn(move || {
                    barrier.wait();
                    drop(sender.force_send(pool.acquire()));
                }));
            }
            barrier.wait();
            drop(receiver);
            for thread in threads {
                thread.join().unwrap();
            }
            drop(sender);
            assert_eq!(pool.available(), pool.capacity());
        }
    }

    #[tokio::test]
    async fn critical_task_panic_is_contained_and_cancels_runtime() {
        let cancel = CancellationToken::new();
        let task = spawn_critical("injected", cancel.clone(), async {
            panic!("injected dispatcher panic");
        });
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn successful_critical_task_does_not_cancel_runtime() {
        let cancel = CancellationToken::new();
        spawn_critical("completed", cancel.clone(), async {})
            .await
            .unwrap();
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn dispatcher_shutdown_completes_during_total_packet_deficit() {
        let pool = PacketPool::new(1);
        let held = pool.acquire();
        let cancel = CancellationToken::new();
        let (dispatcher, _) = Dispatcher::start(
            "127.0.0.1:0",
            None,
            pool.clone(),
            Arc::new(Stats::default()),
            cancel,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_millis(100), dispatcher.shutdown())
            .await
            .unwrap();
        drop(held);
        assert_eq!(pool.available(), pool.capacity());
    }
}

#[cfg(test)]
mod transport_chaos_tests;

#[cfg(test)]
mod throughput_soak_tests;
