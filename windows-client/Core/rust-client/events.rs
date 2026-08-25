// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";

#[derive(Clone)]
pub struct Events {
    enabled: bool,
    panel_restart_emitted: Arc<AtomicBool>,
}

#[derive(Serialize)]
pub struct PathHealthEvent {
    pub active: i32,
    pub sent: u64,
    pub acked: u64,
    pub missed: u64,
    pub send_errors: u64,
    pub unresponsive: u64,
    pub scheduler_resets: u64,
}

impl Events {
    pub fn from_env() -> Self {
        Self::new(std::env::var("CSQTT_EVENTS").as_deref() == Ok("1"))
    }

    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            panel_restart_emitted: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn emit<T: Serialize>(&self, kind: &str, payload: &T) {
        if !self.enabled {
            return;
        }
        if let Some(line) = encode_event(kind, payload) {
            crate::log_output!("{line}");
        }
    }

    pub fn ready(&self, worker: usize) {
        self.emit("READY", &serde_json::json!({"worker": worker}));
    }

    pub fn stopped(&self) {
        self.emit("STOPPED", &serde_json::json!({}));
    }

    pub fn config(&self, config: &str) {
        self.emit("CONFIG", &serde_json::json!({"config": config}));
    }

    pub fn stats(&self, active: i32, bytes_up: i64, bytes_down: i64) {
        self.emit(
            "STATS",
            &serde_json::json!({
                "active": active,
                "bytes_up": bytes_up,
                "bytes_down": bytes_down
            }),
        );
    }

    pub fn active_zero(&self) {
        self.emit("ACTIVE_ZERO", &serde_json::json!({}));
    }

    pub fn panel_restart(&self) {
        if !self.panel_restart_emitted.swap(true, Ordering::AcqRel) {
            self.emit("SERVER_RESTART", &serde_json::json!({"source": "panel"}));
        }
    }

    pub fn path_health(&self, event: PathHealthEvent) {
        self.emit("PATH_HEALTH", &event);
    }

    pub fn progress(&self, kind: &str) {
        self.emit("PROGRESS", &serde_json::json!({"kind": kind}));
    }
}

fn encode_event<T: Serialize>(kind: &str, payload: &T) -> Option<String> {
    let json = serde_json::to_string(payload).ok()?;
    Some(format!("{EVENT_PREFIX}{kind}|{json}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_payload_lifecycle_events_are_json_objects() {
        assert_eq!(
            encode_event("READY", &serde_json::json!({})).as_deref(),
            Some("__CSQTT_EVENT__|READY|{}")
        );
        assert_eq!(
            encode_event("STOPPED", &serde_json::json!({})).as_deref(),
            Some("__CSQTT_EVENT__|STOPPED|{}")
        );
        assert_eq!(
            encode_event("ACTIVE_ZERO", &serde_json::json!({})).as_deref(),
            Some("__CSQTT_EVENT__|ACTIVE_ZERO|{}")
        );
    }

    #[test]
    fn panel_restart_is_deduplicated_across_workers() {
        let first = Events::new(false);
        let second = first.clone();
        assert!(!first.panel_restart_emitted.load(Ordering::Acquire));
        first.panel_restart();
        assert!(second.panel_restart_emitted.load(Ordering::Acquire));
        second.panel_restart();
        assert!(first.panel_restart_emitted.load(Ordering::Acquire));
    }
}
