// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::stun_codec::{Class, Message};
use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

pub(crate) const RESULT_EMPTY: i32 = -1;
pub(crate) const RESULT_BUFFER_TOO_SMALL: i32 = -2;
pub(crate) const RESULT_INVALID_ARGUMENT: i32 = -3;
pub(crate) const RESULT_CLOSED: i32 = -4;
pub(crate) const RESULT_NOT_CONTROL: i32 = -5;
const RESULT_TIMEOUT: i32 = -6;
const RESULT_AUTHENTICATION: i32 = -7;
const RESULT_PROTOCOL: i32 = -8;

pub(crate) const EVENT_STATE: u32 = 1;
pub(crate) const EVENT_REQUEST_COMPLETE: u32 = 2;
pub(crate) const EVENT_CHANNEL_BOUND: u32 = 3;
pub(crate) const EVENT_RELAY_ADDRESS: u32 = 4;
pub(crate) const EVENT_CONTROL_OVERFLOW: u32 = 5;
pub(crate) const EVENT_DATA_REJECTED: u32 = 6;
pub(crate) const EVENT_FORCED_DESTROY: u32 = 7;
pub(crate) const EVENT_EVENT_OVERFLOW: u32 = 8;

pub(crate) const METHOD_ALLOCATE: u32 = 3;
pub(crate) const METHOD_REFRESH: u32 = 4;
pub(crate) const METHOD_CREATE_PERMISSION: u32 = 8;
pub(crate) const METHOD_CHANNEL_BIND: u32 = 9;

const STATE_NULL: u32 = 0;
const STATE_ALLOCATING: u32 = 3;
pub(crate) const STATE_READY: u32 = 4;
const STATE_DEALLOCATING: u32 = 5;
pub(crate) const STATE_DEALLOCATED: u32 = 6;
pub(crate) const STATE_DESTROYING: u32 = 7;

pub(crate) const AF_IPV4: u8 = 4;
pub(crate) const AF_IPV6: u8 = 6;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_CHANNEL_NUMBER: u16 = 0x000c;
const ATTR_LIFETIME: u16 = 0x000d;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_FINGERPRINT: u16 = 0x8028;
const MAGIC_COOKIE: u32 = 0x2112_a442;
const FINGERPRINT_XOR: u32 = 0x5354_554e;
const CONTROL_CAPACITY: usize = 16;
const EVENT_CAPACITY: usize = 64;
const INITIAL_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_millis(1600);
const MAX_TRANSMISSIONS: u8 = 7;
const PERMISSION_REFRESH: Duration = Duration::from_secs(240);
const CHANNEL_REFRESH: Duration = Duration::from_secs(240);
const ALLOCATION_REFRESH_MARGIN: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_NONCE_RETRIES: u8 = 8;
const CHANNEL_NUMBER: u16 = 0x4000;

const SEND_INDICATION_KIND: u16 = 0x0016;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CsqttTurnProfile {
    pub(crate) allocation_refresh_margin: Duration,
    pub(crate) permission_refresh: Duration,
    pub(crate) channel_refresh: Duration,
    pub(crate) keepalive_interval: Duration,
    pub(crate) max_nonce_retries: u8,
}

impl CsqttTurnProfile {
    pub(crate) const PJNATH_COMPAT: Self = Self {
        allocation_refresh_margin: ALLOCATION_REFRESH_MARGIN,
        permission_refresh: PERMISSION_REFRESH,
        channel_refresh: CHANNEL_REFRESH,
        keepalive_interval: KEEPALIVE_INTERVAL,
        max_nonce_retries: MAX_NONCE_RETRIES,
    };
}

#[used]
static CORE_IMPLEMENTATION: [u8; 26] = *b"CSQTT_RUST_TURN_SANS_IO_V1";

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct NativeAddress {
    pub(crate) family: u8,
    pub(crate) reserved: u8,
    pub(crate) port: u16,
    pub(crate) ip: [u8; 16],
}

impl NativeAddress {
    fn from_socket_addr(address: SocketAddr) -> Self {
        let mut result = Self {
            family: if address.is_ipv4() { AF_IPV4 } else { AF_IPV6 },
            port: address.port(),
            ..Self::default()
        };
        match address.ip() {
            IpAddr::V4(ip) => result.ip[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => result.ip.copy_from_slice(&ip.octets()),
        }
        result
    }

    pub(crate) fn to_socket_addr(self) -> Result<SocketAddr> {
        let ip = match self.family {
            AF_IPV4 => IpAddr::V4(Ipv4Addr::new(
                self.ip[0], self.ip[1], self.ip[2], self.ip[3],
            )),
            AF_IPV6 => IpAddr::V6(Ipv6Addr::from(self.ip)),
            value => bail!("TURN core returned address family {value}"),
        };
        Ok(SocketAddr::new(ip, self.port))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct NativeEvent {
    pub(crate) kind: u32,
    pub(crate) method: u32,
    pub(crate) status: i32,
    pub(crate) stun_code: i32,
    pub(crate) state: u32,
    pub(crate) previous_state: u32,
    pub(crate) dropped: u32,
    pub(crate) channel: u16,
    pub(crate) reserved: u16,
    pub(crate) address: NativeAddress,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Operation {
    Allocate,
    Refresh,
    Deallocate,
    Permission,
    Channel,
}

impl Operation {
    fn method(self) -> u32 {
        match self {
            Self::Allocate => METHOD_ALLOCATE,
            Self::Refresh | Self::Deallocate => METHOD_REFRESH,
            Self::Permission => METHOD_CREATE_PERMISSION,
            Self::Channel => METHOD_CHANNEL_BIND,
        }
    }
}

struct Pending {
    operation: Operation,
    transaction: [u8; 12],
    packet: Vec<u8>,
    next_attempt: Instant,
    rto: Duration,
    transmissions: u8,
    nonce_retries: u8,
    authenticated: bool,
}

struct Control {
    packet: Vec<u8>,
    destination: SocketAddr,
}

struct Inner {
    server: SocketAddr,
    peer: SocketAddr,
    username: Arc<str>,
    password: Arc<str>,
    realm: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    key: Option<[u8; 16]>,
    state: u32,
    relay: Option<SocketAddr>,
    channel: Option<u16>,
    controls: VecDeque<Control>,
    events: VecDeque<NativeEvent>,
    pending: Vec<Pending>,
    allocation_refresh: Option<Instant>,
    permission_refresh: Option<Instant>,
    channel_refresh: Option<Instant>,
    keepalive: Option<Instant>,
    shutting_down: bool,
    destroyed: bool,
    profile: CsqttTurnProfile,
}

pub(crate) struct NativeCore {
    inner: Mutex<Inner>,
}

impl NativeCore {
    pub(crate) fn create(
        server: SocketAddr,
        username: &str,
        password: &str,
        peer: SocketAddr,
    ) -> Result<Arc<Self>> {
        Self::create_with_profile(
            server,
            username,
            password,
            peer,
            CsqttTurnProfile::PJNATH_COMPAT,
        )
    }

    pub(crate) fn create_with_profile(
        server: SocketAddr,
        username: &str,
        password: &str,
        peer: SocketAddr,
        profile: CsqttTurnProfile,
    ) -> Result<Arc<Self>> {
        if server.port() == 0 || peer.port() == 0 {
            bail!(
                "TURN core create: {}",
                native_status_text(RESULT_INVALID_ARGUMENT)
            );
        }
        if username.is_empty()
            || username.len() > 512
            || password.is_empty()
            || password.len() > 512
        {
            bail!(
                "TURN core create: {}",
                native_status_text(RESULT_INVALID_ARGUMENT)
            );
        }
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                server,
                peer,
                username: Arc::from(username),
                password: Arc::from(password),
                realm: None,
                nonce: None,
                key: None,
                state: STATE_NULL,
                relay: None,
                channel: None,
                controls: VecDeque::with_capacity(CONTROL_CAPACITY),
                events: VecDeque::with_capacity(EVENT_CAPACITY),
                pending: Vec::with_capacity(4),
                allocation_refresh: None,
                permission_refresh: None,
                channel_refresh: None,
                keepalive: None,
                shutting_down: false,
                destroyed: false,
                profile,
            }),
        }))
    }

    pub(crate) fn start_allocation(&self) -> Result<()> {
        let mut inner = self.lock();
        inner.require_open("TURN Allocate start")?;
        if inner.state != STATE_NULL {
            bail!(
                "TURN Allocate start: {}",
                native_status_text(RESULT_INVALID_ARGUMENT)
            );
        }
        inner.set_state(STATE_ALLOCATING);
        inner.start_operation(Operation::Allocate, false, 0)?;
        Ok(())
    }

    pub(crate) fn start_permission(&self) -> Result<()> {
        let mut inner = self.lock();
        inner.require_ready("TURN CreatePermission start")?;
        inner.start_operation(Operation::Permission, true, 0)?;
        Ok(())
    }

    pub(crate) fn start_channel(&self) -> Result<()> {
        let mut inner = self.lock();
        inner.require_ready("TURN ChannelBind start")?;
        inner.start_operation(Operation::Channel, true, 0)?;
        Ok(())
    }

    pub(crate) fn input_stun(&self, packet: &[u8]) -> i32 {
        let message = match Message::decode(packet) {
            Ok(message) => message,
            Err(_) => return RESULT_INVALID_ARGUMENT,
        };
        if !matches!(message.class(), Class::Success | Class::Error) {
            return RESULT_NOT_CONTROL;
        }
        if message.fingerprint_valid() == Some(false) {
            return RESULT_INVALID_ARGUMENT;
        }
        let transaction = message.transaction();
        let method = u32::from(message.method());
        let mut inner = self.lock();
        let Some(index) = inner.pending.iter().position(|pending| {
            pending.transaction == transaction && pending.operation.method() == method
        }) else {
            return RESULT_NOT_CONTROL;
        };
        let pending = inner.pending.remove(index);
        inner.remove_queued_transaction(transaction);
        if pending.authenticated && !verify_integrity(packet, &message, inner.key.as_ref()) {
            inner.complete_failure(pending.operation, RESULT_AUTHENTICATION, 0);
            return RESULT_AUTHENTICATION;
        }
        if message.class() == Class::Success && !pending.authenticated {
            inner.complete_failure(pending.operation, RESULT_AUTHENTICATION, 0);
            return RESULT_AUTHENTICATION;
        }
        let now = Instant::now();
        if message.class() == Class::Error {
            let code = error_code(&message).unwrap_or(0);
            if code == 0 {
                inner.complete_failure(pending.operation, RESULT_PROTOCOL, 0);
                return 0;
            }
            let realm = message
                .attribute(ATTR_REALM)
                .map(|attribute| attribute.value.to_vec())
                .or_else(|| (code == 438).then(|| inner.realm.clone()).flatten());
            let nonce = message
                .attribute(ATTR_NONCE)
                .map(|attribute| attribute.value.to_vec());
            if matches!(code, 401 | 438)
                && pending.nonce_retries < inner.profile.max_nonce_retries
                && let (Some(realm), Some(nonce)) = (realm, nonce)
            {
                inner.set_auth(realm, nonce);
                if inner
                    .start_operation(pending.operation, true, pending.nonce_retries + 1)
                    .is_ok()
                {
                    return 0;
                }
            }
            match pending.operation {
                Operation::Channel => {
                    inner.channel = None;
                    inner.channel_refresh = None;
                    inner.complete(pending.operation, RESULT_PROTOCOL, i32::from(code));
                }
                Operation::Permission => {
                    inner.permission_refresh = None;
                    inner.complete(pending.operation, RESULT_PROTOCOL, i32::from(code));
                }
                Operation::Allocate | Operation::Refresh | Operation::Deallocate => {
                    inner.complete_failure(pending.operation, RESULT_PROTOCOL, i32::from(code));
                }
            }
            return 0;
        }
        let result = inner.complete_success(pending.operation, &message, now);
        if result.is_err() {
            inner.complete_failure(pending.operation, RESULT_PROTOCOL, 0);
            return RESULT_PROTOCOL;
        }
        0
    }

    pub(crate) fn poll(&self) -> Result<Option<Duration>> {
        let now = Instant::now();
        let mut inner = self.lock();
        if inner.destroyed {
            return Ok(None);
        }
        inner.expire_transactions(now);
        if !inner.shutting_down && inner.state == STATE_READY {
            let mut control_started = false;
            if inner
                .allocation_refresh
                .is_some_and(|deadline| now >= deadline)
                && !inner.has_operation(Operation::Refresh)
            {
                inner.allocation_refresh = None;
                inner.start_operation(Operation::Refresh, true, 0)?;
                control_started = true;
            }
            if inner
                .permission_refresh
                .is_some_and(|deadline| now >= deadline)
                && !inner.has_operation(Operation::Permission)
            {
                inner.permission_refresh = None;
                inner.start_operation(Operation::Permission, true, 0)?;
                control_started = true;
            }
            if inner
                .channel_refresh
                .is_some_and(|deadline| now >= deadline)
                && !inner.has_operation(Operation::Channel)
            {
                inner.channel_refresh = None;
                inner.start_operation(Operation::Channel, true, 0)?;
                control_started = true;
            }

            if inner.keepalive.is_some_and(|deadline| now >= deadline) {
                inner.keepalive = Some(now + inner.profile.keepalive_interval);
                if !control_started {
                    let packet = MessageBuilder::new(SEND_INDICATION_KIND)
                        .attribute(ATTR_DATA, &[])
                        .finish();
                    inner.push_control(packet);
                }
            }
        }
        Ok(inner.next_deadline().map(|deadline| {
            deadline
                .saturating_duration_since(now)
                .max(Duration::from_millis(1))
        }))
    }

    pub(crate) fn pull_control(
        &self,
        buffer: &mut [u8; 1024],
    ) -> Result<Option<(usize, SocketAddr)>> {
        let mut inner = self.lock();
        let Some(control) = inner.controls.pop_front() else {
            return Ok(None);
        };
        if control.packet.len() > buffer.len() {
            bail!(
                "TURN control dequeue: {}",
                native_status_text(RESULT_BUFFER_TOO_SMALL)
            );
        }
        buffer[..control.packet.len()].copy_from_slice(&control.packet);
        Ok(Some((control.packet.len(), control.destination)))
    }

    pub(crate) fn pull_event(&self) -> Result<Option<NativeEvent>> {
        Ok(self.lock().events.pop_front())
    }

    pub(crate) fn relay_address(&self) -> Result<SocketAddr> {
        self.lock().relay.context("TURN relay address: unavailable")
    }

    pub(crate) fn graceful_shutdown(&self) -> Result<()> {
        let mut inner = self.lock();
        if inner.destroyed || inner.shutting_down {
            return Ok(());
        }
        inner.shutting_down = true;
        inner.channel = None;
        inner.permission_refresh = None;
        inner.channel_refresh = None;
        inner.keepalive = None;
        inner.controls.clear();
        if inner.state == STATE_READY {
            inner.pending.clear();
            inner.set_state(STATE_DEALLOCATING);
            inner.start_operation(Operation::Deallocate, true, 0)?;
        } else if inner.state != STATE_ALLOCATING {
            inner.pending.clear();
        }
        Ok(())
    }

    pub(crate) fn force_destroy(&self, status: i32) {
        let mut inner = self.lock();
        if inner.destroyed {
            return;
        }
        inner.destroyed = true;
        inner.controls.clear();
        inner.pending.clear();
        inner.set_state(STATE_DESTROYING);
        inner.push_event(NativeEvent {
            kind: EVENT_FORCED_DESTROY,
            status,
            state: STATE_DESTROYING,
            ..NativeEvent::default()
        });
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for NativeCore {
    fn drop(&mut self) {
        let inner = self
            .inner
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.controls.clear();
        inner.pending.clear();
    }
}

impl Inner {
    fn require_open(&self, operation: &str) -> Result<()> {
        if self.destroyed || self.shutting_down {
            bail!("{operation}: {}", native_status_text(RESULT_CLOSED));
        }
        Ok(())
    }

    fn require_ready(&self, operation: &str) -> Result<()> {
        self.require_open(operation)?;
        if self.state != STATE_READY {
            bail!(
                "{operation}: {}",
                native_status_text(RESULT_INVALID_ARGUMENT)
            );
        }
        Ok(())
    }

    fn set_state(&mut self, state: u32) {
        if self.state == state {
            return;
        }
        let previous_state = self.state;
        self.state = state;
        self.push_event(NativeEvent {
            kind: EVENT_STATE,
            state,
            previous_state,
            ..NativeEvent::default()
        });
    }

    fn set_auth(&mut self, realm: Vec<u8>, nonce: Vec<u8>) {
        let mut digest = Md5::new();
        digest.update(self.username.as_bytes());
        digest.update(b":");
        digest.update(&realm);
        digest.update(b":");
        digest.update(self.password.as_bytes());
        self.key = Some(digest.finalize().into());
        self.realm = Some(realm);
        self.nonce = Some(nonce);
    }

    fn start_operation(
        &mut self,
        operation: Operation,
        authenticated: bool,
        nonce_retries: u8,
    ) -> Result<()> {
        if self.has_operation(operation) {
            if operation == Operation::Channel
                && let Some(pending) = self
                    .pending
                    .iter()
                    .find(|pending| pending.operation == operation)
            {
                self.queue_packet(pending.packet.clone());
            }
            return Ok(());
        }
        if authenticated && (self.realm.is_none() || self.nonce.is_none() || self.key.is_none()) {
            bail!("TURN authentication state is incomplete");
        }
        let transaction = rand::random::<[u8; 12]>();
        let packet = self.build_request(operation, transaction, authenticated)?;
        self.push_control(packet.clone());
        self.pending.push(Pending {
            operation,
            transaction,
            packet,
            next_attempt: Instant::now() + INITIAL_RTO,
            rto: INITIAL_RTO,
            transmissions: 1,
            nonce_retries,
            authenticated,
        });
        Ok(())
    }

    fn build_request(
        &self,
        operation: Operation,
        transaction: [u8; 12],
        authenticated: bool,
    ) -> Result<Vec<u8>> {
        let mut builder = MessageBuilder::with_transaction(operation.method() as u16, transaction);
        match operation {
            Operation::Allocate => {
                builder = builder.attribute(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
                let family = if self.peer.is_ipv4() { 1 } else { 2 };
                builder = builder.attribute(ATTR_REQUESTED_ADDRESS_FAMILY, &[family, 0, 0, 0]);
            }
            Operation::Refresh => {}
            Operation::Deallocate => {
                builder = builder.attribute(ATTR_LIFETIME, &0u32.to_be_bytes());
            }
            Operation::Permission => {
                builder = builder.xor_address(ATTR_XOR_PEER_ADDRESS, self.peer);
            }
            Operation::Channel => {
                builder = builder
                    .attribute(ATTR_CHANNEL_NUMBER, &[0x40, 0, 0, 0])
                    .xor_address(ATTR_XOR_PEER_ADDRESS, self.peer);
            }
        }
        if authenticated {
            builder = builder
                .attribute(ATTR_USERNAME, self.username.as_bytes())
                .attribute(ATTR_REALM, self.realm.as_deref().unwrap_or_default())
                .attribute(ATTR_NONCE, self.nonce.as_deref().unwrap_or_default());
            builder.finish_authenticated(
                self.key
                    .as_ref()
                    .context("TURN authentication key missing")?,
            )
        } else {
            Ok(builder.finish())
        }
    }

    fn has_operation(&self, operation: Operation) -> bool {
        self.pending
            .iter()
            .any(|pending| pending.operation == operation)
    }

    fn push_control(&mut self, packet: Vec<u8>) {
        self.queue_packet(packet);
    }

    fn queue_packet(&mut self, packet: Vec<u8>) {
        if self.controls.len() == CONTROL_CAPACITY {
            self.controls.pop_front();
            self.push_event(NativeEvent {
                kind: EVENT_CONTROL_OVERFLOW,
                status: RESULT_BUFFER_TOO_SMALL,
                dropped: 1,
                ..NativeEvent::default()
            });
        }
        self.controls.push_back(Control {
            packet,
            destination: self.server,
        });
    }

    fn push_event(&mut self, event: NativeEvent) {
        if self.events.len() == EVENT_CAPACITY {
            self.events.pop_front();
            self.events.push_back(NativeEvent {
                kind: EVENT_EVENT_OVERFLOW,
                status: RESULT_BUFFER_TOO_SMALL,
                dropped: 1,
                ..NativeEvent::default()
            });
            return;
        }
        self.events.push_back(event);
    }

    fn remove_queued_transaction(&mut self, transaction: [u8; 12]) {
        self.controls
            .retain(|control| control.packet.get(8..20) != Some(transaction.as_slice()));
    }

    fn expire_transactions(&mut self, now: Instant) {
        let mut index = 0;
        while index < self.pending.len() {
            if now < self.pending[index].next_attempt {
                index += 1;
                continue;
            }
            if self.pending[index].transmissions >= MAX_TRANSMISSIONS {
                let pending = self.pending.remove(index);
                self.remove_queued_transaction(pending.transaction);
                self.complete_failure(pending.operation, RESULT_TIMEOUT, 0);
                continue;
            }
            let packet = self.pending[index].packet.clone();
            self.queue_packet(packet);
            let pending = &mut self.pending[index];
            pending.transmissions += 1;
            pending.rto = pending.rto.saturating_mul(2).min(MAX_RTO);
            pending.next_attempt = now + pending.rto;
            index += 1;
        }
    }

    fn complete_success(
        &mut self,
        operation: Operation,
        message: &Message<'_>,
        now: Instant,
    ) -> Result<()> {
        match operation {
            Operation::Allocate => {
                let relay = decode_xor_address(
                    message
                        .attribute(ATTR_XOR_RELAYED_ADDRESS)
                        .context("TURN Allocate response has no relayed address")?
                        .value,
                    &message.transaction(),
                )?;
                if relay.is_ipv4() != self.peer.is_ipv4() || relay.port() == 0 {
                    bail!("TURN Allocate response has invalid relayed address");
                }
                let lifetime = attribute_u32(message, ATTR_LIFETIME).unwrap_or(600);
                if lifetime == 0 {
                    bail!("TURN Allocate response lifetime is zero");
                }
                self.relay = Some(relay);
                self.allocation_refresh = Some(refresh_deadline(
                    now,
                    lifetime,
                    self.profile.allocation_refresh_margin,
                ));
                self.keepalive = Some(now + self.profile.keepalive_interval);
                self.push_event(NativeEvent {
                    kind: EVENT_RELAY_ADDRESS,
                    address: NativeAddress::from_socket_addr(relay),
                    ..NativeEvent::default()
                });
                if self.shutting_down {
                    self.set_state(STATE_DEALLOCATING);
                    self.start_operation(Operation::Deallocate, true, 0)?;
                    return Ok(());
                }
                self.set_state(STATE_READY);
                self.complete(operation, 0, 0);
            }
            Operation::Refresh => {
                let lifetime = attribute_u32(message, ATTR_LIFETIME).unwrap_or(600);
                if lifetime == 0 {
                    bail!("TURN Refresh response lifetime is zero");
                }
                self.allocation_refresh = Some(refresh_deadline(
                    now,
                    lifetime,
                    self.profile.allocation_refresh_margin,
                ));
                self.complete(operation, 0, 0);
            }
            Operation::Deallocate => {
                if attribute_u32(message, ATTR_LIFETIME).unwrap_or(0) != 0 {
                    bail!("TURN deallocation response lifetime is not zero");
                }
                self.relay = None;
                self.allocation_refresh = None;
                self.complete(operation, 0, 0);
                self.set_state(STATE_DEALLOCATED);
            }
            Operation::Permission => {
                self.permission_refresh = Some(now + self.profile.permission_refresh);
                self.complete(operation, 0, 0);
            }
            Operation::Channel => {
                self.channel = Some(CHANNEL_NUMBER);
                self.permission_refresh = Some(now + self.profile.permission_refresh);
                self.channel_refresh = Some(now + self.profile.channel_refresh);
                self.push_event(NativeEvent {
                    kind: EVENT_CHANNEL_BOUND,
                    channel: CHANNEL_NUMBER,
                    address: NativeAddress::from_socket_addr(self.peer),
                    ..NativeEvent::default()
                });
                self.complete(operation, 0, 0);
            }
        }
        Ok(())
    }

    fn complete_failure(&mut self, operation: Operation, status: i32, stun_code: i32) {
        self.complete(operation, status, stun_code);
        self.controls.clear();
        self.pending.clear();
        self.channel = None;
        self.allocation_refresh = None;
        self.permission_refresh = None;
        self.channel_refresh = None;
        self.keepalive = None;
        self.relay = None;
        if operation == Operation::Deallocate {
            self.set_state(STATE_DEALLOCATED);
        } else {
            self.set_state(STATE_DESTROYING);
        }
    }

    fn complete(&mut self, operation: Operation, status: i32, stun_code: i32) {
        self.push_event(NativeEvent {
            kind: EVENT_REQUEST_COMPLETE,
            method: operation.method(),
            status,
            stun_code,
            state: self.state,
            channel: self.channel.unwrap_or(0),
            address: self
                .relay
                .map(NativeAddress::from_socket_addr)
                .unwrap_or_default(),
            ..NativeEvent::default()
        });
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|pending| pending.next_attempt)
            .chain(self.allocation_refresh)
            .chain(self.permission_refresh)
            .chain(self.channel_refresh)
            .chain(self.keepalive)
            .min()
    }
}

struct MessageBuilder {
    bytes: Vec<u8>,
    transaction: [u8; 12],
}

impl MessageBuilder {
    fn new(kind: u16) -> Self {
        Self::with_transaction(kind, rand::random())
    }

    fn with_transaction(kind: u16, transaction: [u8; 12]) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction);
        Self { bytes, transaction }
    }

    fn attribute(mut self, kind: u16, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(&kind.to_be_bytes());
        self.bytes
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(value);
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
        self
    }

    fn xor_address(self, kind: u16, address: SocketAddr) -> Self {
        let value = encode_xor_address(address, &self.transaction);
        self.attribute(kind, &value)
    }

    fn finish_authenticated(mut self, key: &[u8; 16]) -> Result<Vec<u8>> {
        let signed_length = (self.bytes.len() - 20 + 24) as u16;
        self.bytes[2..4].copy_from_slice(&signed_length.to_be_bytes());
        let mut mac = <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(key)
            .context("HMAC-SHA1 accepts a 16-byte key")?;
        mac.update(&self.bytes);
        let integrity = mac.finalize().into_bytes();
        self = self.attribute(ATTR_MESSAGE_INTEGRITY, &integrity);
        Ok(self.finish())
    }

    fn finish(mut self) -> Vec<u8> {
        let final_length = (self.bytes.len() - 20 + 8) as u16;
        self.bytes[2..4].copy_from_slice(&final_length.to_be_bytes());
        let fingerprint = crc32fast::hash(&self.bytes) ^ FINGERPRINT_XOR;
        self = self.attribute(ATTR_FINGERPRINT, &fingerprint.to_be_bytes());
        self.bytes
    }
}

fn verify_integrity(packet: &[u8], message: &Message<'_>, key: Option<&[u8; 16]>) -> bool {
    let (Some(key), Some(integrity)) = (key, message.attribute(ATTR_MESSAGE_INTEGRITY)) else {
        return false;
    };
    if integrity.value.len() != 20 || integrity.header_start < 20 {
        return false;
    }
    let mut signed = packet[..integrity.header_start].to_vec();
    let Ok(signed_length) = u16::try_from(integrity.header_start + 24 - 20) else {
        return false;
    };
    signed[2..4].copy_from_slice(&signed_length.to_be_bytes());
    let Ok(mut mac) = <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(key) else {
        return false;
    };
    mac.update(&signed);
    mac.verify_slice(integrity.value).is_ok()
}

fn error_code(message: &Message<'_>) -> Option<u16> {
    let value = message.attribute(ATTR_ERROR_CODE)?.value;
    if value.len() < 4 || value[2] > 6 || value[3] > 99 {
        return None;
    }
    Some(u16::from(value[2]) * 100 + u16::from(value[3]))
}

fn attribute_u32(message: &Message<'_>, kind: u16) -> Option<u32> {
    let value: [u8; 4] = message.attribute(kind)?.value.try_into().ok()?;
    Some(u32::from_be_bytes(value))
}

fn refresh_deadline(now: Instant, lifetime: u32, margin: Duration) -> Instant {
    let lifetime = Duration::from_secs(u64::from(lifetime));
    let advance = if lifetime > margin.saturating_mul(2) {
        margin
    } else {
        lifetime / 2
    };
    now + lifetime.saturating_sub(advance)
}

fn encode_xor_address(address: SocketAddr, transaction: &[u8; 12]) -> Vec<u8> {
    let mut value = Vec::with_capacity(if address.is_ipv4() { 8 } else { 20 });
    value.push(0);
    value.push(if address.is_ipv4() { 1 } else { 2 });
    value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    match address.ip() {
        IpAddr::V4(ip) => {
            value
                .extend_from_slice(&(u32::from_be_bytes(ip.octets()) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction);
            for (octet, mask) in ip.octets().into_iter().zip(mask) {
                value.push(octet ^ mask);
            }
        }
    }
    value
}

fn decode_xor_address(value: &[u8], transaction: &[u8; 12]) -> Result<SocketAddr> {
    if value.len() < 4 || value[0] != 0 {
        bail!("TURN XOR address is malformed");
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    let ip = match (value[1], value.len()) {
        (1, 8) => {
            let encoded = u32::from_be_bytes(value[4..8].try_into()?);
            IpAddr::V4(Ipv4Addr::from(encoded ^ MAGIC_COOKIE))
        }
        (2, 20) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction);
            let mut octets = [0u8; 16];
            for index in 0..16 {
                octets[index] = value[index + 4] ^ mask[index];
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => bail!("TURN XOR address family is invalid"),
    };
    Ok(SocketAddr::new(ip, port))
}

pub(crate) fn native_status_text(status: i32) -> String {
    let text = match status {
        0 => "success",
        RESULT_EMPTY => "empty",
        RESULT_BUFFER_TOO_SMALL => "buffer too small",
        RESULT_INVALID_ARGUMENT => "invalid argument",
        RESULT_CLOSED => "closed",
        RESULT_NOT_CONTROL => "not a TURN control response",
        RESULT_TIMEOUT => "request timeout",
        RESULT_AUTHENTICATION => "response authentication failed",
        RESULT_PROTOCOL => "TURN protocol error",
        _ => return format!("TURN status {status}"),
    };
    format!("{text} ({status})")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_core() -> (Arc<NativeCore>, [u8; 16]) {
        let core = NativeCore::create_with_profile(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "127.0.0.1:9000".parse().unwrap(),
            CsqttTurnProfile::PJNATH_COMPAT,
        )
        .unwrap();
        core.start_allocation().unwrap();
        let mut wire = [0u8; 1024];
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let initial = Message::decode(&wire[..length]).unwrap();
        let challenge = MessageBuilder::with_transaction(0x0113, initial.transaction())
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 1])
            .attribute(ATTR_REALM, b"realm")
            .attribute(ATTR_NONCE, b"nonce")
            .finish();
        assert_eq!(core.input_stun(&challenge), 0);
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let authenticated = Message::decode(&wire[..length]).unwrap();
        let key = core.lock().key.unwrap();
        let success = MessageBuilder::with_transaction(0x0103, authenticated.transaction())
            .xor_address(ATTR_XOR_RELAYED_ADDRESS, "127.0.0.1:50000".parse().unwrap())
            .attribute(ATTR_LIFETIME, &86_400u32.to_be_bytes())
            .finish_authenticated(&key)
            .unwrap();
        assert_eq!(core.input_stun(&success), 0);
        assert_eq!(core.lock().state, STATE_READY);
        (core, key)
    }

    fn complete_empty_success(core: &NativeCore, method: u16, key: &[u8; 16]) {
        let mut wire = [0u8; 1024];
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let request = Message::decode(&wire[..length]).unwrap();
        assert_eq!(request.method(), method);
        let success = MessageBuilder::with_transaction(0x0100 | method, request.transaction())
            .finish_authenticated(key)
            .unwrap();
        assert_eq!(core.input_stun(&success), 0);
    }

    fn bind_ready_channel(core: &NativeCore, key: &[u8; 16]) {
        core.start_permission().unwrap();
        complete_empty_success(core, METHOD_CREATE_PERMISSION as u16, key);
        core.start_channel().unwrap();
        complete_empty_success(core, METHOD_CHANNEL_BIND as u16, key);
        assert_eq!(core.lock().channel, Some(CHANNEL_NUMBER));
    }

    #[test]
    fn request_has_fingerprint_and_expected_allocate_attributes() {
        let core = NativeCore::create(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "127.0.0.1:9000".parse().unwrap(),
        )
        .unwrap();
        core.start_allocation().unwrap();
        let mut wire = [0u8; 1024];
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let message = Message::decode(&wire[..length]).unwrap();
        assert_eq!(message.method(), METHOD_ALLOCATE as u16);
        assert_eq!(message.fingerprint_valid(), Some(true));
        assert_eq!(
            message.attribute(ATTR_REQUESTED_TRANSPORT).unwrap().value,
            [17, 0, 0, 0]
        );
        assert_eq!(
            message
                .attribute(ATTR_REQUESTED_ADDRESS_FAMILY)
                .unwrap()
                .value,
            [1, 0, 0, 0]
        );
    }

    #[test]
    fn native_layout_remains_stable() {
        assert_eq!(std::mem::size_of::<NativeAddress>(), 20);
        assert_eq!(std::mem::align_of::<NativeAddress>(), 2);
        assert_eq!(std::mem::size_of::<NativeEvent>(), 52);
        assert_eq!(std::mem::align_of::<NativeEvent>(), 4);
    }

    #[test]
    fn stale_nonce_retries_with_the_same_realm_and_new_transaction() {
        let core = NativeCore::create(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "127.0.0.1:9000".parse().unwrap(),
        )
        .unwrap();
        core.start_allocation().unwrap();
        let mut wire = [0u8; 1024];
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let initial = Message::decode(&wire[..length]).unwrap();
        let challenge = MessageBuilder::with_transaction(0x0113, initial.transaction())
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 1])
            .attribute(ATTR_REALM, b"realm")
            .attribute(ATTR_NONCE, b"nonce-1")
            .finish();
        assert_eq!(core.input_stun(&challenge), 0);
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let authenticated = Message::decode(&wire[..length]).unwrap();
        assert_eq!(
            authenticated.attribute(ATTR_NONCE).unwrap().value,
            b"nonce-1"
        );
        let first_authenticated_transaction = authenticated.transaction();
        let key = {
            let inner = core.lock();
            inner.key.unwrap()
        };
        let stale = MessageBuilder::with_transaction(0x0113, first_authenticated_transaction)
            .attribute(ATTR_ERROR_CODE, &[0, 0, 4, 38])
            .attribute(ATTR_NONCE, b"nonce-2")
            .finish_authenticated(&key)
            .unwrap();
        assert_eq!(core.input_stun(&stale), 0);
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let retried = Message::decode(&wire[..length]).unwrap();
        assert_ne!(retried.transaction(), first_authenticated_transaction);
        assert_eq!(retried.attribute(ATTR_REALM).unwrap().value, b"realm");
        assert_eq!(retried.attribute(ATTR_NONCE).unwrap().value, b"nonce-2");
        assert!(verify_integrity(&wire[..length], &retried, Some(&key)));
    }

    #[test]
    fn retransmission_schedule_matches_the_previous_pjnath_configuration() {
        let core = NativeCore::create(
            "127.0.0.1:3478".parse().unwrap(),
            "user",
            "pass",
            "127.0.0.1:9000".parse().unwrap(),
        )
        .unwrap();
        core.start_allocation().unwrap();
        let mut wire = [0u8; 1024];
        core.pull_control(&mut wire).unwrap().unwrap();
        let mut inner = core.lock();
        for expected in [400, 800, 1600, 1600, 1600, 1600] {
            let deadline = inner.pending[0].next_attempt;
            inner.expire_transactions(deadline);
            assert_eq!(
                inner.pending[0].next_attempt - deadline,
                Duration::from_millis(expected)
            );
            assert_eq!(inner.controls.len(), 1);
            inner.controls.clear();
        }
        let timeout = inner.pending[0].next_attempt;
        inner.expire_transactions(timeout);
        assert!(inner.pending.is_empty());
        assert!(inner.events.iter().any(|event| {
            event.kind == EVENT_REQUEST_COMPLETE
                && event.method == METHOD_ALLOCATE
                && event.status == RESULT_TIMEOUT
        }));
    }

    #[test]
    fn lifecycle_timers_emit_refresh_channel_and_permission_requests() {
        let (core, key) = ready_core();
        bind_ready_channel(&core, &key);
        while core.pull_event().unwrap().is_some() {}
        {
            let now = Instant::now();
            let mut inner = core.lock();
            inner.allocation_refresh = Some(now);
            inner.channel_refresh = Some(now);
            inner.keepalive = Some(now + Duration::from_secs(1));
        }
        core.poll().unwrap();
        let mut wire = [0u8; 1024];
        let mut requests = Vec::new();
        while let Some((length, _)) = core.pull_control(&mut wire).unwrap() {
            let request = Message::decode(&wire[..length]).unwrap();
            requests.push((
                request.method(),
                request.transaction(),
                wire[..length].to_vec(),
            ));
        }
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].0, METHOD_REFRESH as u16);
        assert_eq!(requests[1].0, METHOD_CHANNEL_BIND as u16);
        let refresh = Message::decode(&requests[0].2).unwrap();
        assert!(refresh.attribute(ATTR_LIFETIME).is_none());
        assert!(refresh.attribute(ATTR_MESSAGE_INTEGRITY).is_some());
        let refresh_success = MessageBuilder::with_transaction(0x0104, requests[0].1)
            .attribute(ATTR_LIFETIME, &7_200u32.to_be_bytes())
            .finish_authenticated(&key)
            .unwrap();
        let channel_success = MessageBuilder::with_transaction(0x0109, requests[1].1)
            .finish_authenticated(&key)
            .unwrap();
        assert_eq!(core.input_stun(&refresh_success), 0);
        assert_eq!(core.input_stun(&channel_success), 0);
        {
            let inner = core.lock();
            let now = Instant::now();
            let allocation_delay = inner.allocation_refresh.unwrap() - now;
            let channel_delay = inner.channel_refresh.unwrap() - now;
            let permission_delay = inner.permission_refresh.unwrap() - now;
            assert!(allocation_delay >= Duration::from_secs(7_139));
            assert!(allocation_delay <= Duration::from_secs(7_140));
            assert!(channel_delay >= Duration::from_secs(239));
            assert!(channel_delay <= Duration::from_secs(240));
            assert!(permission_delay >= Duration::from_secs(239));
            assert!(permission_delay <= Duration::from_secs(240));
        }
        {
            let now = Instant::now();
            let mut inner = core.lock();
            inner.permission_refresh = Some(now);
            inner.channel_refresh = Some(now + Duration::from_secs(240));
            inner.allocation_refresh = Some(now + Duration::from_secs(7_140));
            inner.keepalive = Some(now + Duration::from_secs(1));
        }
        core.poll().unwrap();
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        assert_eq!(
            Message::decode(&wire[..length]).unwrap().method(),
            METHOD_CREATE_PERMISSION as u16
        );
        assert!(core.pull_control(&mut wire).unwrap().is_none());
    }

    #[test]
    fn long_scheduler_pause_retransmits_once_and_rebases_the_deadline() {
        let (core, key) = ready_core();
        core.start_permission().unwrap();
        let mut wire = [0u8; 1024];
        core.pull_control(&mut wire).unwrap().unwrap();
        let mut inner = core.lock();
        let wake = Instant::now() + Duration::from_secs(11 * 60 * 60);
        inner.expire_transactions(wake);
        assert_eq!(inner.pending[0].transmissions, 2);
        assert_eq!(
            inner.pending[0].next_attempt - wake,
            Duration::from_millis(400)
        );
        assert_eq!(inner.controls.len(), 1);
        drop(inner);
        let (length, _) = core.pull_control(&mut wire).unwrap().unwrap();
        let request = Message::decode(&wire[..length]).unwrap();
        let response = MessageBuilder::with_transaction(0x0108, request.transaction())
            .finish_authenticated(&key)
            .unwrap();
        assert_eq!(core.input_stun(&response), 0);
    }

    #[test]
    fn maintenance_timeout_invalidates_the_entire_allocation() {
        let (core, key) = ready_core();
        bind_ready_channel(&core, &key);
        core.start_channel().unwrap();
        let mut wire = [0u8; 1024];
        core.pull_control(&mut wire).unwrap().unwrap();
        let mut inner = core.lock();
        for _ in 0..MAX_TRANSMISSIONS {
            let Some(deadline) = inner.pending.first().map(|pending| pending.next_attempt) else {
                break;
            };
            inner.expire_transactions(deadline);
            inner.controls.clear();
        }
        assert_eq!(inner.state, STATE_DESTROYING);
        assert!(inner.pending.is_empty());
        assert!(inner.controls.is_empty());
        assert!(inner.relay.is_none());
        assert!(inner.channel.is_none());
        assert!(inner.allocation_refresh.is_none());
        assert!(inner.permission_refresh.is_none());
        assert!(inner.channel_refresh.is_none());
        assert!(inner.keepalive.is_none());
        assert!(inner.events.iter().any(|event| {
            event.kind == EVENT_REQUEST_COMPLETE
                && event.method == METHOD_CHANNEL_BIND
                && event.status == RESULT_TIMEOUT
        }));
    }

    #[test]
    fn refresh_deadline_uses_margin_and_avoids_short_lifetime_spin() {
        let now = Instant::now();
        assert_eq!(
            refresh_deadline(now, 86_400, ALLOCATION_REFRESH_MARGIN) - now,
            Duration::from_secs(86_340)
        );
        assert_eq!(
            refresh_deadline(now, 600, ALLOCATION_REFRESH_MARGIN) - now,
            Duration::from_secs(540)
        );
        assert_eq!(
            refresh_deadline(now, 60, ALLOCATION_REFRESH_MARGIN) - now,
            Duration::from_secs(30)
        );
        assert_eq!(
            refresh_deadline(now, 1, ALLOCATION_REFRESH_MARGIN) - now,
            Duration::from_millis(500)
        );
    }
}
