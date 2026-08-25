// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::events::{Events, PathHealthEvent};
use std::sync::{
    Arc,
    atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Stats {
    pub total_bytes_up: AtomicI64,
    pub total_bytes_down: AtomicI64,
    pub active_connections: AtomicI32,
    pub path_probes_sent: AtomicU64,
    pub path_probe_acks: AtomicU64,
    pub path_probe_misses: AtomicU64,
    pub path_probe_send_errors: AtomicU64,
    pub path_unresponsive: AtomicU64,
    pub path_scheduler_resets: AtomicU64,
}

impl Stats {
    pub async fn run(self: Arc<Self>, events: Events, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        let mut path_interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.tick().await;
        path_interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = interval.tick() => {
                    let active = self.active_connections.load(Ordering::Relaxed);
                    let up = self.total_bytes_up.load(Ordering::Relaxed);
                    let down = self.total_bytes_down.load(Ordering::Relaxed);
                    let total_mb = (up + down) as f64 / (1024.0 * 1024.0);
                    crate::log_error!("[СТАТИСТИКА] Активных: {active} | Трафик: {total_mb:.2} МБ");
                    events.stats(active, up, down);
                }
                _ = path_interval.tick() => {
                    events.path_health(PathHealthEvent {
                        active: self.active_connections.load(Ordering::Relaxed),
                        sent: self.path_probes_sent.swap(0, Ordering::AcqRel),
                        acked: self.path_probe_acks.swap(0, Ordering::AcqRel),
                        missed: self.path_probe_misses.swap(0, Ordering::AcqRel),
                        send_errors: self.path_probe_send_errors.swap(0, Ordering::AcqRel),
                        unresponsive: self.path_unresponsive.swap(0, Ordering::AcqRel),
                        scheduler_resets: self.path_scheduler_resets.swap(0, Ordering::AcqRel),
                    });
                }
            }
        }
    }
}
