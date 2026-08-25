// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::atomic::{AtomicUsize, Ordering};

pub const SMALL_PACKET_LIMIT: usize = 384;
pub const DOOMSDAY_PACKET_LIMIT: usize = 133;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketClass {
    Doomsday,
    Small,
    Bulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchTicket {
    pub start_slot: usize,
    pub worker_count: usize,
    pub cohort_len: usize,
    pub class: PacketClass,
}

impl DispatchTicket {
    #[inline(always)]
    pub fn worker_index(self, offset: usize) -> usize {
        (self.start_slot + offset) % self.worker_count
    }
}

pub struct StripedScheduler {
    doomsday_packet: AtomicUsize,
    small_packet: AtomicUsize,
    bulk_packet: AtomicUsize,
}

impl StripedScheduler {
    pub const fn new() -> Self {
        Self {
            doomsday_packet: AtomicUsize::new(0),
            small_packet: AtomicUsize::new(0),
            bulk_packet: AtomicUsize::new(0),
        }
    }

    #[inline(always)]
    pub fn begin(&self, count: usize, packet: &[u8]) -> Option<DispatchTicket> {
        if count == 0 {
            return None;
        }
        let length = packet.len();
        let class = packet_class(length);

        let worker_idx = match class {
            PacketClass::Doomsday => self.doomsday_packet.fetch_add(1, Ordering::Relaxed) % count,
            PacketClass::Small => (self.small_packet.fetch_add(1, Ordering::Relaxed) / 2) % count,
            PacketClass::Bulk => (self.bulk_packet.fetch_add(1, Ordering::Relaxed) / 32) % count,
        };

        let safe_idx = worker_idx.min(count.saturating_sub(1));

        Some(DispatchTicket {
            start_slot: safe_idx,
            worker_count: count,
            cohort_len: count,
            class,
        })
    }
}

impl Default for StripedScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn packet_class(length: usize) -> PacketClass {
    if length <= DOOMSDAY_PACKET_LIMIT {
        PacketClass::Doomsday
    } else if length <= SMALL_PACKET_LIMIT {
        PacketClass::Small
    } else {
        PacketClass::Bulk
    }
}
