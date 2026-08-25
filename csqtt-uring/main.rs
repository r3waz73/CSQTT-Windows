// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![allow(linker_messages)]
#![recursion_limit = "256"]

mod dataplane;
mod model;
mod net_setup;
mod packet;
mod perf;
mod protocol;
mod proxy_route;
#[path = "../shared/selective_fec.rs"]
mod selective_fec;
mod striped_scheduler;
mod tproxy;
mod tun_device;
#[cfg(test)]
mod udp_supervisor;
mod uring_io;
mod web_panel;

use anyhow::{Context, Result, bail};
use clap::Parser;
use dashmap::DashMap;
use model::{Database, DatabasePersistence, load_database, now, random_password, save_database};
use protocol::{DeviceEpochState, Session};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;

#[derive(Parser, Debug)]
#[command(name = "csqtt", version, about = "Сервер и консоль управления CSQTT")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:46000", help = "UDP-адрес сервера")]
    listen: SocketAddr,

    #[arg(long, default_value_t = 46002, help = "HTTPS-порт веб-панели")]
    web_port: u16,

    #[arg(long, default_value = "/etc/csqtt", help = "Каталог конфигурации")]
    config_dir: std::path::PathBuf,

    #[arg(
        long,
        env = "CSQTT_MAIN_PASSWORD",
        default_value = "",
        help = "Основной пароль CSQTT"
    )]
    password: String,

    #[arg(
        long,
        env = "CSQTT_DEVICE_ID",
        default_value = "",
        help = "Идентификатор устройства"
    )]
    device_id: String,

    #[arg(
        long,
        env = "CSQTT_WEB_USER",
        default_value = "admin",
        help = "Логин веб-панели"
    )]
    web_user: String,

    #[arg(
        long,
        env = "CSQTT_WEB_PASS",
        default_value = "",
        help = "Пароль веб-панели"
    )]
    web_pass: String,

    #[arg(
        long,
        env = "CSQTT_DNS",
        help = "Один или два DNS IPv4-адреса через запятую"
    )]
    dns: Option<String>,

    #[arg(
        long,
        env = "CSQTT_SECURE_COOKIE",
        default_value_t = false,
        help = "Выдавать cookie только по HTTPS"
    )]
    secure_cookie: bool,

    #[arg(long, help = "Запустить службу CSQTT")]
    start: bool,

    #[arg(long, help = "Остановить службу CSQTT")]
    stop: bool,

    #[arg(long, help = "Перезапустить службу CSQTT")]
    restart: bool,

    #[arg(long, short = 'd', help = "Открыть DPI-монитор")]
    dpi: bool,

    #[arg(
        long,
        short = 's',
        default_value_t = 0,
        help = "Число последних DPI-записей"
    )]
    samples: usize,
}

#[derive(Debug, Default, serde::Deserialize)]
struct DeployOverrides {
    #[serde(default)]
    main_password: String,
    // None означает, что deploy не управляет привязкой. Some("") — явная
    // команда очистить прежнюю привязку главного пароля.
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    dns: String,
}

fn normalize_dns(value: &str) -> Result<String> {
    let addresses: Vec<_> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if addresses.is_empty() || addresses.len() > 2 {
        bail!("DNS must contain one or two IPv4 addresses");
    }
    for address in &addresses {
        address
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("invalid DNS IPv4 address: {address}"))?;
    }
    Ok(addresses.join(","))
}

pub struct App {
    pub db: RwLock<Database>,
    pub db_persistence: DatabasePersistence,
    pub dns: RwLock<String>,
    pub startup_main_password: String,
    pub startup_dns: String,
    pub config_dir: std::path::PathBuf,
    pub listen: SocketAddr,
    pub web_port: u16,
    pub web_user: String,
    pub web_pass: String,
    pub secure_cookie: bool,
    pub sessions: DashMap<SocketAddr, Arc<Session>>,
    pub device_epochs: DashMap<String, Arc<tokio::sync::Mutex<DeviceEpochState>>>,
    pub web_sessions: DashMap<String, i64>,
    pub login_limits: DashMap<String, (u32, i64)>,
    pub bytes_from_client: Arc<AtomicU64>,
    pub bytes_to_client: Arc<AtomicU64>,
    pub total_connections: AtomicU64,
    pub cpu_percent: AtomicU64,
    pub cpu_cores: AtomicU64,
    pub started: i64,
    pub derived_keys: DashMap<String, [u8; 32]>,
    pub logs: std::sync::Mutex<std::collections::VecDeque<String>>,
    pub logging_active: std::sync::atomic::AtomicBool,
    pub stream_debug_active: Arc<AtomicBool>,
    pub log_file_path: std::path::PathBuf,
    pub proxy_route: RwLock<Option<Arc<proxy_route::ProxyRoute>>>,
    pub proxy_operation: tokio::sync::Mutex<()>,
    pub proxy_trigger: tokio::sync::Notify,
    pub proxy_port_listening: std::sync::atomic::AtomicBool,
    pub proxy_health_error: std::sync::RwLock<Option<String>>,
    pub dataplane: std::sync::OnceLock<dataplane::DataplaneHandle<protocol::ProtocolCommand>>,
}

#[inline]
pub fn lock_unpoison<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn enqueue_log_write(path: std::path::PathBuf, line: String) {
    static SENDER: std::sync::OnceLock<std::sync::mpsc::SyncSender<(std::path::PathBuf, String)>> =
        std::sync::OnceLock::new();
    let sender = SENDER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(512);
        let _ = std::thread::Builder::new()
            .name("csqtt-log-writer".to_owned())
            .spawn(move || {
                while let Ok((path, line)) = receiver.recv() {
                    use std::io::Write;
                    if let Ok(metadata) = std::fs::metadata(&path)
                        && metadata.len() > 8 * 1024 * 1024
                    {
                        let _ = std::fs::remove_file(&path);
                    }
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        let _ = writeln!(file, "{line}");
                    }
                }
            });
        sender
    });
    let _ = sender.try_send((path, line));
}

pub fn log_event(app: &Arc<App>, level: &str, _module: &str, msg: &str) {
    if !app.logging_active.load(Ordering::Relaxed) {
        return;
    }
    let time_str = chrono::Local::now().format("%d %b %y %H:%M").to_string();
    let mut formatted = String::with_capacity(time_str.len() + level.len() + msg.len() + 8);
    use std::fmt::Write;
    let _ = write!(formatted, "[{}] [{}] {}", time_str, level, msg);

    eprintln!("{}", formatted);

    let mut logs = lock_unpoison(&app.logs);
    logs.push_back(formatted.clone());
    if logs.len() > 600 {
        logs.pop_front();
    }
    drop(logs);

    let path = app.log_file_path.clone();
    enqueue_log_write(path, formatted);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuSnapshot {
    total: u64,
    process: u64,
    cores: u64,
}

fn parse_cpu_total(line: &str) -> Option<u64> {
    let parts: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if parts.len() < 4 {
        return None;
    }
    Some(parts.iter().copied().sum())
}

fn parse_host_cpu(stat: &str) -> Option<(u64, u64)> {
    let aggregate = stat.lines().next()?;
    if !aggregate.starts_with("cpu ") {
        return None;
    }
    let total = parse_cpu_total(aggregate)?;
    let cores = stat
        .lines()
        .skip(1)
        .filter(|line| {
            line.strip_prefix("cpu")
                .and_then(|suffix| suffix.split_whitespace().next())
                .is_some_and(|cpu| !cpu.is_empty() && cpu.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .count()
        .max(1) as u64;
    Some((total, cores))
}

fn parse_process_cpu(stat: &str) -> Option<u64> {
    let fields: Vec<&str> = stat
        .get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some(user.saturating_add(system))
}

fn cpu_percentage(previous: CpuSnapshot, current: CpuSnapshot) -> Option<u64> {
    let total_delta = current.total.checked_sub(previous.total)?;
    if total_delta == 0 {
        return None;
    }
    let process_delta = current.process.saturating_sub(previous.process);
    let process =
        (process_delta as f64 * current.cores as f64 * 100.0 / total_delta as f64).round() as u64;
    Some(process.min(current.cores.saturating_mul(100)))
}

async fn cpu_loop(app: Arc<App>) {
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    let mut previous = None;
    loop {
        timer.tick().await;
        model::refresh_cached_now();
        protocol::refresh_monotonic_millis();
        let (host_stat, process_stat) = tokio::join!(
            tokio::fs::read_to_string("/proc/stat"),
            tokio::fs::read_to_string("/proc/self/stat")
        );
        if let (Ok(host_stat), Ok(process_stat)) = (host_stat, process_stat)
            && let Some((total, cores)) = parse_host_cpu(&host_stat)
            && let Some(process) = parse_process_cpu(&process_stat)
        {
            let current = CpuSnapshot {
                total,
                process,
                cores,
            };
            if let Some(previous) = previous
                && let Some(process_percent) = cpu_percentage(previous, current)
            {
                app.cpu_percent.store(process_percent, Ordering::Relaxed);
            }
            app.cpu_cores.store(cores, Ordering::Relaxed);
            previous = Some(current);
        }
    }
}

async fn stats_loop(app: Arc<App>) {
    let path = app.config_dir.join("server.log");
    let mut timer = tokio::time::interval(Duration::from_secs(60));
    loop {
        timer.tick().await;
        let line = {
            let db = app.db.read().await;
            let line = serde_json::json!({
                "timestamp": now(),
                "uptime": now().saturating_sub(app.started),
                "active": app.sessions.len(),
                "total": app.total_connections.load(Ordering::Relaxed),
                "up_bytes": app.bytes_from_client.load(Ordering::Relaxed),
                "down_bytes": app.bytes_to_client.load(Ordering::Relaxed),
                "passwords": db.passwords.len(),
                "devices": db.devices.len(),
                "tunnel": "userspace-tun",
                "transport": "rtp-aead"
            })
            .to_string();
            app.db_persistence.submit(db.clone());
            line
        };

        let config_dir = app.config_dir.clone();
        let stats_path = path.clone();
        tokio::task::spawn_blocking(move || {
            let temp = config_dir.join(".server.log.tmp");
            if std::fs::write(&temp, format!("{line}\n")).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o640));
                }
                let _ = std::fs::rename(&temp, &stats_path);
            }
        });
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                eprintln!("[SIGNAL] SIGTERM handler unavailable: {error}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn run_systemctl(action: &str) -> Result<()> {
    if std::env::var("CSQTT_SERVICE_MANAGER").is_ok_and(|value| value == "docker") {
        if action != "restart" {
            bail!("для управления контейнером используйте docker start/stop csqtt");
        }
        #[cfg(unix)]
        {
            if unsafe { libc::kill(1, libc::SIGTERM) } == 0 {
                println!("[CLI] Docker-контейнер перезапускается");
                return Ok(());
            }
            return Err(std::io::Error::last_os_error().into());
        }
        #[cfg(not(unix))]
        bail!("Docker service manager поддерживается только на Unix");
    }
    #[cfg(unix)]
    {
        if unsafe { libc_geteuid() } != 0 {
            bail!("для управления службой csqtt нужны права root");
        }
    }
    println!("[CLI] Выполняется systemctl {action} csqtt...");
    let status = std::process::Command::new("systemctl")
        .args([action, "csqtt"])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("[CLI] Готово");
            Ok(())
        }
        Ok(s) => {
            bail!("[CLI] systemctl завершился с ошибкой: {}", s);
        }
        Err(e) => {
            bail!("[CLI] не удалось запустить systemctl: {}", e);
        }
    }
}

pub(crate) fn request_service_restart() -> Result<()> {
    #[cfg(unix)]
    {
        let pid = unsafe { libc::getpid() };
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error().into())
    }
    #[cfg(not(unix))]
    bail!("managed restart is supported only on Unix");
}

fn acquire_instance_lock(config_dir: &std::path::Path) -> Result<std::fs::File> {
    let path = config_dir.join(".server.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open instance lock {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another CSQTT server instance owns {}", path.display());
        }
    }
    Ok(file)
}

async fn run_dpi_client(samples: usize) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    println!(
        "\x1b[1;33m               CSQTT DEEP PACKET INSPECTION (DPI) LIVE TRAFFIC SNIFFER               \x1b[0m"
    );
    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );

    let mut stream = match tokio::net::TcpStream::connect("127.0.0.1:46003").await {
        Ok(s) => s,
        Err(e) => {
            bail!(
                "Could not connect to running CSQTT server DPI socket (127.0.0.1:46003): {e}. Ensure csqtt is active!"
            );
        }
    };

    let req = format!("GET_DPI:{samples}\n");
    stream.write_all(req.as_bytes()).await?;

    let (reader, _) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(frame) = serde_json::from_str::<protocol::DpiFrame>(&line) {
                    let dt =
                        chrono::DateTime::from_timestamp((frame.timestamp_ms / 1000) as i64, 0)
                            .map(|t| t.format("%H:%M:%S").to_string())
                            .unwrap_or_else(|| "00:00:00".to_string());

                    let dir_str = if frame.direction == "INBOUND" {
                        "\x1b[1;32m▲ INBOUND \x1b[0m"
                    } else {
                        "\x1b[1;34m▼ OUTBOUND\x1b[0m"
                    };

                    let pt_str = if frame.pt == 111 {
                        "\x1b[1;33mRTP-Audio (PT=111)\x1b[0m".to_string()
                    } else if frame.pt == 96 {
                        "\x1b[1;35mRTP-Video (PT=96)\x1b[0m".to_string()
                    } else {
                        format!("\x1b[1;36m{}\x1b[0m", frame.proto)
                    };

                    println!(
                        "[\x1b[2m{}\x1b[0m] {} | \x1b[1;33m{}\x1b[0m -> \x1b[1;36m{}\x1b[0m | Size: {} B (Wire: {} B)",
                        dt, dir_str, frame.src, frame.dst, frame.len, frame.wire_len
                    );
                    println!(
                        "  Proto: {} | Seq: #\x1b[1m{}\x1b[0m | Device: \x1b[1;32m{}\x1b[0m | Gen: \x1b[1;33m{}\x1b[0m | Salt: \x1b[1;35m{}\x1b[0m",
                        pt_str, frame.seq, frame.device_id, frame.gen_id, frame.salt
                    );
                    println!("  Detail: \x1b[1;37m{}\x1b[0m", frame.detail);
                    if !frame.hex_preview.is_empty() {
                        println!(
                            "  Hex & ASCII Preview:\n\x1b[2m{}\x1b[0m",
                            frame.hex_preview
                        );
                    }
                    println!(
                        "\x1b[2m────────────────────────────────────────────────────────────────────────────────────\x1b[0m"
                    );
                }
            }
        }
    }

    Ok(())
}

async fn syscalls_broadcast_loop() {
    let mut last_counters = *crate::protocol::GLOBAL_IO_COUNTERS.read().unwrap();
    let mut last_crypto = crate::protocol::CRYPTO_OPS_COUNTER.load(Ordering::Relaxed);
    let mut last_crypto_perf = *crate::protocol::GLOBAL_CRYPTO_PERF.read().unwrap();
    let mut last_all_perf = crate::perf::GLOBAL_DATAPLANE
        .read()
        .unwrap()
        .merge(*crate::perf::GLOBAL_PROTOCOL.read().unwrap());
    let mut last_process_cpu = perf::process_cpu_time_ns();
    let (mut last_process_user_cpu, mut last_process_system_cpu) = perf::process_cpu_split_ns();
    let mut last_dataplane_cpu = perf::DATAPLANE_CPU_NS.load(Ordering::Acquire);
    let mut last_dataplane_sequence = perf::DATAPLANE_CPU_SEQUENCE.load(Ordering::Acquire);
    let mut last_threads: HashMap<u32, perf::ThreadCpuSnapshot> = HashMap::new();
    let mut last_sample = std::time::Instant::now();
    let mut monitoring = false;
    let mut thread_sampling = false;
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        if protocol::SYSCALLS_BROADCAST.receiver_count() == 0 {
            monitoring = false;
            thread_sampling = false;
            last_threads.clear();
            continue;
        }

        let all_active = perf::ALL_CLIENTS.load(Ordering::Acquire) != 0;
        if !monitoring {
            last_counters = *crate::protocol::GLOBAL_IO_COUNTERS.read().unwrap();
            last_crypto = crate::protocol::CRYPTO_OPS_COUNTER.load(Ordering::Relaxed);
            last_crypto_perf = *crate::protocol::GLOBAL_CRYPTO_PERF.read().unwrap();
            last_all_perf = crate::perf::GLOBAL_DATAPLANE
                .read()
                .unwrap()
                .merge(*crate::perf::GLOBAL_PROTOCOL.read().unwrap());
            last_process_cpu = perf::process_cpu_time_ns();
            (last_process_user_cpu, last_process_system_cpu) = perf::process_cpu_split_ns();
            last_dataplane_cpu = perf::DATAPLANE_CPU_NS.load(Ordering::Acquire);
            last_dataplane_sequence = perf::DATAPLANE_CPU_SEQUENCE.load(Ordering::Acquire);
            last_threads = if all_active {
                perf::process_thread_cpu_snapshot()
                    .into_iter()
                    .map(|thread| (thread.tid, thread))
                    .collect()
            } else {
                HashMap::new()
            };
            last_sample = std::time::Instant::now();
            monitoring = true;
            thread_sampling = all_active;
            continue;
        }

        let sample_now = std::time::Instant::now();
        let sample_window_ns = sample_now
            .saturating_duration_since(last_sample)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let current_process_cpu = perf::process_cpu_time_ns();
        let process_cpu_ns = current_process_cpu.saturating_sub(last_process_cpu);
        let (current_process_user_cpu, current_process_system_cpu) = perf::process_cpu_split_ns();
        let process_user_cpu_ns = current_process_user_cpu.saturating_sub(last_process_user_cpu);
        let process_system_cpu_ns =
            current_process_system_cpu.saturating_sub(last_process_system_cpu);
        let current_dataplane_cpu = perf::DATAPLANE_CPU_NS.load(Ordering::Acquire);
        let current_dataplane_sequence = perf::DATAPLANE_CPU_SEQUENCE.load(Ordering::Acquire);
        let current_threads = if all_active {
            perf::process_thread_cpu_snapshot()
                .into_iter()
                .map(|thread| (thread.tid, thread))
                .collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };
        let mut threads = current_threads
            .values()
            .map(|thread| {
                let previous = last_threads.get(&thread.tid);
                protocol::ThreadCpuFrame {
                    tid: thread.tid,
                    name: thread.name.clone(),
                    user_cpu_ns: previous
                        .map_or(0, |value| thread.user_ns.saturating_sub(value.user_ns)),
                    system_cpu_ns: previous
                        .map_or(0, |value| thread.system_ns.saturating_sub(value.system_ns)),
                }
            })
            .collect::<Vec<_>>();
        threads.sort_unstable_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.tid.cmp(&right.tid))
        });
        let dataplane_cpu_ns = if thread_sampling
            && all_active
            && current_dataplane_sequence != last_dataplane_sequence
        {
            current_dataplane_cpu.saturating_sub(last_dataplane_cpu)
        } else {
            0
        };

        let current_counters = *crate::protocol::GLOBAL_IO_COUNTERS.read().unwrap();
        let current_crypto = crate::protocol::CRYPTO_OPS_COUNTER.load(Ordering::Relaxed);
        let current_crypto_perf = *crate::protocol::GLOBAL_CRYPTO_PERF.read().unwrap();
        let crypto_perf = current_crypto_perf.delta(last_crypto_perf);
        let current_all_perf = crate::perf::GLOBAL_DATAPLANE
            .read()
            .unwrap()
            .merge(*crate::perf::GLOBAL_PROTOCOL.read().unwrap());
        let all_perf = current_all_perf.delta(last_all_perf);
        let active_sessions = crate::protocol::ACTIVE_SESSIONS_GAUGE.load(Ordering::Relaxed);

        let frame = protocol::SyscallsFrame {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_millis() as u64,
            sample_window_ns,
            process_cpu_ns,
            process_user_cpu_ns,
            process_system_cpu_ns,
            dataplane_cpu_ns,
            dataplane_tid: perf::DATAPLANE_TID.load(Ordering::Acquire) as u32,
            threads,
            udp_rx_pps: current_counters
                .udp_rx_packets
                .saturating_sub(last_counters.udp_rx_packets),
            udp_rx_bps: current_counters
                .udp_rx_bytes
                .saturating_sub(last_counters.udp_rx_bytes),
            udp_rx_errors_s: current_counters
                .udp_rx_errors
                .saturating_sub(last_counters.udp_rx_errors),
            udp_tx_pps: current_counters
                .udp_tx_packets
                .saturating_sub(last_counters.udp_tx_packets),
            udp_tx_bps: current_counters
                .udp_tx_bytes
                .saturating_sub(last_counters.udp_tx_bytes),
            udp_tx_errors_s: current_counters
                .udp_tx_errors
                .saturating_sub(last_counters.udp_tx_errors),
            udp_tx_drops_s: current_counters
                .udp_tx_drops
                .saturating_sub(last_counters.udp_tx_drops),
            tun_rx_pps: current_counters
                .tun_rx_packets
                .saturating_sub(last_counters.tun_rx_packets),
            tun_rx_bps: current_counters
                .tun_rx_bytes
                .saturating_sub(last_counters.tun_rx_bytes),
            tun_rx_errors_s: current_counters
                .tun_rx_errors
                .saturating_sub(last_counters.tun_rx_errors),
            tun_tx_pps: current_counters
                .tun_tx_packets
                .saturating_sub(last_counters.tun_tx_packets),
            tun_tx_bps: current_counters
                .tun_tx_bytes
                .saturating_sub(last_counters.tun_tx_bytes),
            tun_tx_errors_s: current_counters
                .tun_tx_errors
                .saturating_sub(last_counters.tun_tx_errors),
            tun_tx_drops_s: current_counters
                .tun_tx_drops
                .saturating_sub(last_counters.tun_tx_drops),
            sqe_per_sec: current_counters
                .sqe_submissions
                .saturating_sub(last_counters.sqe_submissions),
            cqe_per_sec: current_counters
                .cqe_completions
                .saturating_sub(last_counters.cqe_completions),
            udp_rx_rearms_s: current_counters
                .udp_rx_rearms
                .saturating_sub(last_counters.udp_rx_rearms),
            tun_rx_rearms_s: current_counters
                .tun_rx_rearms
                .saturating_sub(last_counters.tun_rx_rearms),
            crypto_ops_s: current_crypto.saturating_sub(last_crypto),
            active_sessions,
            free_udp_tx_slots: current_counters.free_udp_tx_slots,
            free_tun_tx_slots: current_counters.free_tun_tx_slots,
            cq_min_wait_usec: current_counters.cq_min_wait_usec,
            cq_wait_batch: current_counters.cq_wait_batch,
            cq_capacity: current_counters.cq_capacity,
            cq_overflow_s: current_counters
                .cq_overflow
                .saturating_sub(last_counters.cq_overflow),
            udp_rx_enobufs_s: current_counters
                .udp_rx_enobufs
                .saturating_sub(last_counters.udp_rx_enobufs),
            udp_rx_multishot: current_counters.udp_rx_multishot,
            udp_rx_buffer_count: current_counters.udp_rx_buffer_count,
            tun_fixed_buffers: current_counters.tun_fixed_buffers,
            iowq_bounded_limit: current_counters.iowq_bounded_limit,
            iowq_unbounded_limit: current_counters.iowq_unbounded_limit,
            uring_mode: current_counters.uring_mode,
            total_udp_rx_packets: current_counters.udp_rx_packets,
            total_udp_tx_packets: current_counters.udp_tx_packets,
            total_tun_rx_packets: current_counters.tun_rx_packets,
            total_tun_tx_packets: current_counters.tun_tx_packets,
            crypto_sample_interval: protocol::CRYPTO_PERF_SAMPLE_INTERVAL,
            chacha: crypto_perf.chacha,
            srtp: crypto_perf.srtp,
            unwrap_crypto: crypto_perf.unwrap_crypto,
            wrap_crypto: crypto_perf.wrap_crypto,
            all_sample_interval: perf::SAMPLE_INTERVAL,
            all: all_perf,
        };

        let _ = protocol::SYSCALLS_BROADCAST.send(frame);

        last_counters = current_counters;
        last_crypto = current_crypto;
        last_crypto_perf = current_crypto_perf;
        last_all_perf = current_all_perf;
        last_process_cpu = current_process_cpu;
        last_process_user_cpu = current_process_user_cpu;
        last_process_system_cpu = current_process_system_cpu;
        last_dataplane_cpu = current_dataplane_cpu;
        last_dataplane_sequence = current_dataplane_sequence;
        last_threads = current_threads;
        thread_sampling = all_active;
        last_sample = sample_now;
    }
}

async fn run_syscalls_client() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    println!(
        "\x1b[1;33m                   CSQTT I/O & SYSCALL MONITOR (1 update/sec)                      \x1b[0m"
    );
    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );

    let mut stream = match tokio::net::TcpStream::connect("127.0.0.1:46004").await {
        Ok(s) => s,
        Err(e) => {
            bail!(
                "Could not connect to CSQTT syscalls socket (127.0.0.1:46004): {e}. Ensure csqtt is active!"
            );
        }
    };

    stream.write_all(b"SUBSCRIBE\n").await?;

    let (reader, _) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(f) = serde_json::from_str::<protocol::SyscallsFrame>(&line) {
                    print!("\x1b[2J\x1b[H");
                    println!(
                        "\x1b[1;36m═══════════════ CSQTT SYSCALL MONITOR ═══════════════\x1b[0m"
                    );
                    println!(
                        "\x1b[1;33m Sessions: \x1b[1;37m{}\x1b[0m",
                        f.active_sessions
                    );
                    println!();
                    println!(
                        "\x1b[1;32m  ▲ UDP RX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}",
                        f.udp_rx_pps, f.udp_rx_bps, f.udp_rx_errors_s
                    );
                    println!(
                        "\x1b[1;34m  ▼ UDP TX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}  drops: {}",
                        f.udp_tx_pps, f.udp_tx_bps, f.udp_tx_errors_s, f.udp_tx_drops_s
                    );
                    println!(
                        "\x1b[1;32m  ▲ TUN RX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}",
                        f.tun_rx_pps, f.tun_rx_bps, f.tun_rx_errors_s
                    );
                    println!(
                        "\x1b[1;34m  ▼ TUN TX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}  drops: {}",
                        f.tun_tx_pps, f.tun_tx_bps, f.tun_tx_errors_s, f.tun_tx_drops_s
                    );
                    println!();
                    println!(
                        "\x1b[1;35m  io_uring  \x1b[0m SQE/s: {:>8}  CQE/s: {:>8}",
                        f.sqe_per_sec, f.cqe_per_sec
                    );
                    println!(
                        "\x1b[1;35m  rearms/s  \x1b[0m UDP RX: {:>8}  TUN RX: {:>8}",
                        f.udp_rx_rearms_s, f.tun_rx_rearms_s
                    );
                    println!("\x1b[1;35m  crypto/s  \x1b[0m {:>8}", f.crypto_ops_s);
                    println!();
                    println!(
                        "\x1b[2m  free slots │ UDP TX: {}  TUN TX: {}\x1b[0m",
                        f.free_udp_tx_slots, f.free_tun_tx_slots
                    );
                    println!(
                        "\x1b[2m  totals    │ UDP RX: {}  UDP TX: {}  TUN RX: {}  TUN TX: {}\x1b[0m",
                        f.total_udp_rx_packets,
                        f.total_udp_tx_packets,
                        f.total_tun_rx_packets,
                        f.total_tun_tx_packets
                    );
                    println!(
                        "\x1b[1;36m═════════════════════════════════════════════════════\x1b[0m"
                    );
                }
            }
        }
    }
    Ok(())
}

fn perf_estimated_ns(counters: perf::Counters) -> f64 {
    if counters.samples == 0 {
        return 0.0;
    }
    counters.sampled_ns as f64 / counters.samples as f64 * counters.operations as f64
}

fn print_all_perf_row(name: &str, counters: perf::Counters, sample_window_ns: u64) {
    let estimated_ns = perf_estimated_ns(counters);
    let average_ns = if counters.operations == 0 {
        0.0
    } else {
        estimated_ns / counters.operations as f64
    };
    let operations_per_sec =
        counters.operations as f64 * 1_000_000_000.0 / sample_window_ns.max(1) as f64;
    println!(
        "{name:<24} {:>9.0} оп/с  {:>9.0} нс/оп  {:>7.2}% ядра  выборок: {}",
        operations_per_sec,
        average_ns,
        estimated_ns * 100.0 / sample_window_ns.max(1) as f64,
        counters.samples
    );
}

fn print_io_timing_row(name: &str, counters: perf::Counters, sample_window_ns: u64) {
    let estimated_cpu_ns = perf_estimated_ns(counters);
    let average_cpu_ns = if counters.samples == 0 {
        0.0
    } else {
        counters.sampled_ns as f64 / counters.samples as f64
    };
    let average_wall_ns = if counters.samples == 0 {
        0.0
    } else {
        counters.sampled_wall_ns as f64 / counters.samples as f64
    };
    let operations_per_sec =
        counters.operations as f64 * 1_000_000_000.0 / sample_window_ns.max(1) as f64;
    println!(
        "{name:<24} {:>9.0} оп/с  CPU {:>8.0} нс/оп  WALL {:>8.1} мкс/оп  {:>7.2}% ядра",
        operations_per_sec,
        average_cpu_ns,
        average_wall_ns / 1_000.0,
        estimated_cpu_ns * 100.0 / sample_window_ns.max(1) as f64
    );
}

fn print_derived_perf_row(name: &str, operations: u64, estimated_ns: f64, sample_window_ns: u64) {
    let average_ns = if operations == 0 {
        0.0
    } else {
        estimated_ns / operations as f64
    };
    let operations_per_sec = operations as f64 * 1_000_000_000.0 / sample_window_ns.max(1) as f64;
    println!(
        "{name:<24} {:>9.0} оп/с  {:>9.0} нс/оп  {:>7.2}% ядра  расчёт",
        operations_per_sec,
        average_ns,
        estimated_ns * 100.0 / sample_window_ns.max(1) as f64
    );
}

fn print_perf_all(frame: &protocol::SyscallsFrame) {
    let all = frame.all;
    let io_wait_ns = perf_estimated_ns(all.io_wait);
    let cqe_ns = perf_estimated_ns(all.cqe_processing);
    let flush_ns = perf_estimated_ns(all.flush);
    let bookkeeping_ns = perf_estimated_ns(all.bookkeeping);
    let wrap_ns = if frame.wrap_crypto.samples == 0 {
        0.0
    } else {
        frame.wrap_crypto.sampled_ns as f64 / frame.wrap_crypto.samples as f64
            * frame.wrap_crypto.operations as f64
    };
    let unwrap_ns = if frame.unwrap_crypto.samples == 0 {
        0.0
    } else {
        frame.unwrap_crypto.sampled_ns as f64 / frame.unwrap_crypto.samples as f64
            * frame.unwrap_crypto.operations as f64
    };
    let udp_queue_ns = perf_estimated_ns(all.udp_queue);
    let total_ns = io_wait_ns + cqe_ns + flush_ns + bookkeeping_ns;
    let sample_window_ns = frame.sample_window_ns.max(1);
    let process_percent = frame.process_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let sampled_top_percent = total_ns * 100.0 / sample_window_ns as f64;
    let dataplane_percent = frame.dataplane_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let user_percent = frame.process_user_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let system_percent = frame.process_system_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let threads_cpu_ns = frame.threads.iter().fold(0u64, |total, thread| {
        total.saturating_add(thread.user_cpu_ns.saturating_add(thread.system_cpu_ns))
    });
    let dataplane_proc_ns = frame
        .threads
        .iter()
        .find(|thread| thread.tid == frame.dataplane_tid)
        .map_or(0, |thread| {
            thread.user_cpu_ns.saturating_add(thread.system_cpu_ns)
        });
    let other_threads_ns = threads_cpu_ns.saturating_sub(dataplane_proc_ns);
    let unattributed_ns = frame.process_cpu_ns.saturating_sub(threads_cpu_ns);
    let other_threads_percent = other_threads_ns as f64 * 100.0 / sample_window_ns as f64;
    let unattributed_percent = unattributed_ns as f64 * 100.0 / sample_window_ns as f64;

    println!("CSQTT PERF ALL — профиль dataplane за последнюю секунду");
    println!(
        "Сессий: {} · UDP RX/TX: {}/{} pps · TUN RX/TX: {}/{} pps · выборка 1/{}\n",
        frame.active_sessions,
        frame.udp_rx_pps,
        frame.udp_tx_pps,
        frame.tun_rx_pps,
        frame.tun_tx_pps,
        frame.all_sample_interval
    );
    let cqe_per_cycle = if all.cqe_processing.operations == 0 {
        0.0
    } else {
        frame.cqe_per_sec as f64 / all.cqe_processing.operations as f64
    };
    println!(
        "CQE за проход: {:.2} · адаптивное окно: {} мкс · цель: до {} CQE\n",
        cqe_per_cycle, frame.cq_min_wait_usec, frame.cq_wait_batch
    );
    println!(
        "UDP multishot: {} · provided buffers: {} · CQ: {} · overflow: +{}/с · ENOBUFS: +{}/с\n",
        if frame.udp_rx_multishot != 0 {
            "активен"
        } else {
            "fallback"
        },
        frame.udp_rx_buffer_count,
        frame.cq_capacity,
        frame.cq_overflow_s,
        frame.udp_rx_enobufs_s
    );
    let uring_mode = match frame.uring_mode {
        5 => "single+coop+defer",
        4 => "single+coop+taskrun",
        3 => "coop",
        2 => "single",
        1 => "basic",
        _ => "неизвестен",
    };
    println!(
        "io_uring mode: {uring_mode} · TUN I/O: nonblock+poll · io-wq B/U: {}\n",
        if frame.iowq_bounded_limit != 0 || frame.iowq_unbounded_limit != 0 {
            format!(
                "{}/{}",
                frame.iowq_bounded_limit, frame.iowq_unbounded_limit
            )
        } else {
            "не поддерживается ядром".to_owned()
        }
    );
    println!(
        "I/O ошибки: UDP RX/TX {}/{} · TUN RX/TX {}/{} · drops UDP/TUN {}/{}\n",
        frame.udp_rx_errors_s,
        frame.udp_tx_errors_s,
        frame.tun_rx_errors_s,
        frame.tun_tx_errors_s,
        frame.udp_tx_drops_s,
        frame.tun_tx_drops_s
    );
    println!("Верхний уровень, независимая sampled-оценка:");
    print_all_perf_row("I/O cycle inclusive", all.io_wait, sample_window_ns);
    print_all_perf_row("CQE dispatch (всего)", all.cqe_processing, sample_window_ns);
    print_all_perf_row("sendmmsg/flush", all.flush, sample_window_ns);
    print_all_perf_row("loop bookkeeping", all.bookkeeping, sample_window_ns);
    println!(
        "{:<24} {:>31.2}% ядра",
        "СУММА SAMPLED СТАДИЙ", sampled_top_percent
    );
    println!(
        "{:<24} {:>31.2}% ядра",
        "DATAPLANE THREAD ТОЧНО", dataplane_percent
    );
    println!(
        "{:<24} {:>31.2}% ядра",
        "ПРОЦЕСС CSQTT ТОЧНО", process_percent
    );
    println!(
        "{:<24} {:>20.2}% user · {:>6.2}% system",
        "ПРОЦЕСС CPU SPLIT", user_percent, system_percent
    );
    println!(
        "{:<24} {:>31.2}% ядра",
        "ПРОЧИЕ ПОТОКИ CSQTT", other_threads_percent
    );
    println!(
        "{:<24} {:>31.2}% ядра\n",
        "НЕ АТРИБУТИРОВАНО /PROC", unattributed_percent
    );

    if !frame.threads.is_empty() {
        println!("Стабильная разбивка живых потоков по /proc:");
        for thread in frame.threads.iter().take(16) {
            let thread_user = thread.user_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
            let thread_system = thread.system_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
            println!(
                "{:<18} tid {:>7} {:>7.2}% · {:>6.2}% user · {:>6.2}% system",
                thread.name,
                thread.tid,
                thread_user + thread_system,
                thread_user,
                thread_system
            );
        }
        if frame.threads.len() > 16 {
            println!("ещё потоков: {}", frame.threads.len() - 16);
        }
        println!();
    }

    if dataplane_percent > 0.0 && sampled_top_percent > dataplane_percent * 1.25 {
        println!(
            "Sampled-оценка смещена периодической выборкой; для итога используй точные строки процесса и потоков.\n"
        );
    }

    println!("Разложение I/O cycle, CPU и wall измеряются отдельно:");
    print_io_timing_row("io_uring enter/wait", all.io_enter, sample_window_ns);
    print_io_timing_row("SQ submit", all.sq_submit, sample_window_ns);
    print_io_timing_row("CQ shared-memory drain", all.cq_drain, sample_window_ns);

    println!("\nПриблизительная sampled-атрибуция внутри CQE dispatch:");
    print_all_perf_row("UDP RX overhead", all.udp_rx, sample_window_ns);
    print_derived_perf_row(
        "parse+unwrap+crypto",
        frame.unwrap_crypto.operations,
        unwrap_ns,
        sample_window_ns,
    );
    print_all_perf_row("route/replay", all.route_replay, sample_window_ns);
    print_all_perf_row("TUN write", all.tun_write, sample_window_ns);
    print_all_perf_row("TUN RX overhead", all.tun_rx, sample_window_ns);
    print_derived_perf_row(
        "prepare+wrap+crypto",
        frame.wrap_crypto.operations,
        wrap_ns,
        sample_window_ns,
    );
    print_derived_perf_row(
        "UDP queue inclusive",
        all.udp_queue.operations,
        udp_queue_ns,
        sample_window_ns,
    );
    println!(
        "\nВнутренние строки sampled независимо и не складываются в точный итог. Истинный общий расход показывает «DATAPLANE THREAD ТОЧНО»; CPU ожидания не включает wall-сон."
    );
}

async fn run_perf_client() -> Result<()> {
    use std::io::Write;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:46004")
        .await
        .with_context(
            || "не удалось подключиться к CSQTT на 127.0.0.1:46004; убедитесь, что служба запущена",
        )?;
    stream.write_all(b"PERF ALL\n").await?;

    let (reader, _) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let Ok(frame) = serde_json::from_str::<protocol::SyscallsFrame>(&line) else {
            continue;
        };
        print!("\x1b[2J\x1b[H");
        print_perf_all(&frame);
        println!("Ctrl+C — выход.");
        std::io::stdout().flush()?;
    }
    Ok(())
}

fn print_cli_help() {
    println!(
        "CSQTT — сервер и консоль управления\n\n\
Использование:\n  \
  csqtt start                 Запустить службу\n  \
  csqtt stop                  Остановить службу\n  \
  csqtt restart               Перезапустить службу\n  \
  csqtt dpi                   Открыть DPI-монитор\n  \
  csqtt dpi s 50              Показать последние 50 DPI-записей и выйти\n  \
  csqtt syscalls              Открыть монитор I/O и системных вызовов\n  \
  csqtt perf all              Разложить весь dataplane по этапам\n  \
  csqtt help                  Показать эту справку\n\n\
Ручной запуск сервера:\n  \
  --listen АДРЕС              UDP-адрес, по умолчанию 0.0.0.0:46000\n  \
  --web-port ПОРТ             HTTPS-порт панели, по умолчанию 46002\n  \
  --config-dir ПУТЬ           Каталог конфигурации, по умолчанию /etc/csqtt\n  \
  --password ПАРОЛЬ           Основной пароль CSQTT\n  \
  --device-id ID              Идентификатор устройства\n  \
  --web-user ЛОГИН            Логин веб-панели\n  \
  --web-pass ПАРОЛЬ           Пароль веб-панели\n  \
  --dns IP[,IP]               Один или два DNS IPv4-адреса\n  \
  --secure-cookie             Выдавать cookie только по HTTPS\n\n\
Диагностика io_uring:\n  \
  --io-uring-probe             Проверить setup/enter/CQE и вывести выбранный режим\n  \
  CSQTT_URING_MODE=defer      SINGLE_ISSUER + COOP_TASKRUN + DEFER_TASKRUN\n  \
  CSQTT_URING_MODE=coop       SINGLE_ISSUER + COOP_TASKRUN + TASKRUN_FLAG\n  \
  CSQTT_URING_MODE=single     Только SINGLE_ISSUER\n  \
  CSQTT_URING_MODE=basic      Совместимый режим без дополнительных флагов\n"
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let args_vec: Vec<String> = std::env::args().collect();
    if args_vec.len() == 2 && args_vec[1] == "--io-uring-probe" {
        println!("{}", uring_io::probe_compatibility()?);
        return Ok(());
    }
    if args_vec.len() == 1
        || (args_vec.len() == 2 && matches!(args_vec[1].as_str(), "help" | "--help" | "-h"))
    {
        print_cli_help();
        return Ok(());
    }

    if args_vec.len() >= 2 {
        let cmd = args_vec[1].as_str();
        match cmd {
            "start" | "stop" | "restart" => {
                return run_systemctl(cmd);
            }
            "dpi" => {
                let mut samples = 0;
                if args_vec.len() >= 4 && args_vec[2] == "s" {
                    samples = args_vec[3].parse::<usize>().unwrap_or(0);
                }
                return run_dpi_client(samples).await;
            }
            "syscalls" => {
                return run_syscalls_client().await;
            }
            "perf" => {
                if args_vec.get(2).map(String::as_str) != Some("all") {
                    println!("Использование:\n  csqtt perf all");
                    return Ok(());
                }
                return run_perf_client().await;
            }
            _ => {}
        }
    }

    let mut args = Args::parse();

    if args.start {
        return run_systemctl("start");
    }
    if args.stop {
        return run_systemctl("stop");
    }
    if args.restart {
        return run_systemctl("restart");
    }

    if args.dpi || args.samples > 0 {
        return run_dpi_client(args.samples).await;
    }

    if unsafe { libc_geteuid() } != 0 {
        bail!("csqtt-server must run as root");
    }

    if args.config_dir == std::path::Path::new("/etc/csqtt")
        && !args.config_dir.exists()
        && std::path::Path::new("/etc/wdttq").exists()
    {
        args.config_dir = std::path::PathBuf::from("/etc/wdttq");
        println!("[INIT] legacy config dir /etc/wdttq в использовании");
    }

    tokio::fs::create_dir_all(&args.config_dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&args.config_dir, std::fs::Permissions::from_mode(0o700))
            .await?;
    }

    let _instance_lock = acquire_instance_lock(&args.config_dir)?;
    proxy_route::ProxyRoute::cleanup_orphaned_policy()
        .await
        .context("cleanup orphaned CSQTT proxy policy")?;

    let mut db = load_database(&args.config_dir)?;
    db.admin_id.clear();
    db.bot_token.clear();
    db.web_sessions.clear();

    let deploy_overrides_path = args.config_dir.join("deploy-overrides.json");
    let deploy_overrides = if deploy_overrides_path.exists() {
        let text = std::fs::read_to_string(&deploy_overrides_path)
            .with_context(|| format!("read {}", deploy_overrides_path.display()))?;
        serde_json::from_str::<DeployOverrides>(&text)
            .with_context(|| format!("parse {}", deploy_overrides_path.display()))?
    } else {
        DeployOverrides::default()
    };

    if !args.password.is_empty() {
        db.main_password = args.password.clone();
    } else if !deploy_overrides.main_password.is_empty() {
        db.main_password = deploy_overrides.main_password.clone();
    }
    if !args.device_id.is_empty() {
        db.main_device_id = args.device_id.clone();
    } else if let Some(device_id) = deploy_overrides.device_id.as_ref() {
        db.main_device_id = device_id.clone();
    }
    if db.main_password.is_empty() {
        db.main_password = random_password() + &random_password();
        println!("[INIT] generated main password: {}", db.main_password);
    }

    let configured_dns = args
        .dns
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            let value = deploy_overrides.dns.trim();
            (!value.is_empty()).then(|| value.to_owned())
        });
    let runtime_dns = match configured_dns {
        Some(configured) => normalize_dns(&configured)?,
        None if !db.dns.trim().is_empty() => normalize_dns(db.dns.trim())?,
        None => "1.1.1.1".to_owned(),
    };
    db.dns = runtime_dns.clone();

    let web_pass = if args.web_pass.is_empty() {
        let value = random_password() + &random_password();
        println!("[INIT] generated web password: {value}");
        value
    } else {
        args.web_pass
    };

    save_database(&args.config_dir, &db)?;
    if deploy_overrides_path.exists() {
        std::fs::remove_file(&deploy_overrides_path).with_context(|| {
            format!(
                "remove consumed deploy overrides {}",
                deploy_overrides_path.display()
            )
        })?;
    }

    let web_sessions = DashMap::new();

    let logging_active_val = db.logging_active.unwrap_or(true);
    let device_epochs = DashMap::new();
    for (device_id, device) in &db.devices {
        device_epochs.insert(
            device_id.clone(),
            Arc::new(tokio::sync::Mutex::new(DeviceEpochState::new(
                device.last_generation_id,
                device.last_session_salt.clone(),
            ))),
        );
    }
    let startup_main_password = db.main_password.clone();
    let startup_dns = runtime_dns.clone();
    let app = Arc::new(App {
        db_persistence: DatabasePersistence::new(args.config_dir.clone()),
        db: RwLock::new(db),
        dns: RwLock::new(runtime_dns),
        startup_main_password,
        startup_dns,
        config_dir: args.config_dir.clone(),
        listen: args.listen,
        web_port: args.web_port,
        web_user: args.web_user,
        web_pass,
        secure_cookie: args.secure_cookie,
        sessions: DashMap::new(),
        device_epochs,
        web_sessions,
        login_limits: DashMap::new(),
        bytes_from_client: Arc::new(AtomicU64::new(0)),
        bytes_to_client: Arc::new(AtomicU64::new(0)),
        total_connections: AtomicU64::new(0),
        cpu_percent: AtomicU64::new(0),
        cpu_cores: AtomicU64::new(1),
        started: now(),
        derived_keys: DashMap::new(),
        logs: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(600)),
        logging_active: std::sync::atomic::AtomicBool::new(logging_active_val),
        stream_debug_active: Arc::new(AtomicBool::new(false)),
        log_file_path: args.config_dir.join("csqtt.log"),
        proxy_route: RwLock::new(None),
        proxy_operation: tokio::sync::Mutex::new(()),
        proxy_trigger: tokio::sync::Notify::new(),
        proxy_port_listening: std::sync::atomic::AtomicBool::new(true),
        proxy_health_error: std::sync::RwLock::new(None),
        dataplane: std::sync::OnceLock::new(),
    });

    log_event(&app, "INFO", "SYSTEM", " CSQTT Server 2.0.0");
    log_event(
        &app,
        "INFO",
        "SYSTEM",
        &format!(" RTP AEAD: {}", app.listen),
    );
    log_event(&app, "INFO", "SYSTEM", " Tunnel: Userspace TUN (CSQTT)");
    log_event(
        &app,
        "INFO",
        "SYSTEM",
        &format!(" Web: 0.0.0.0:{}", app.web_port),
    );

    let web_app = app.clone();
    let stats_app = app.clone();

    tokio::spawn(async move {
        if let Err(e) = protocol::run_dpi_server().await {
            eprintln!("[DPI] Server listener error: {e}");
        }
    });

    tokio::spawn(async move {
        if let Err(e) = protocol::run_syscalls_server().await {
            eprintln!("[SYSCALLS] Server listener error: {e}");
        }
    });

    tokio::spawn(syscalls_broadcast_loop());

    let cert_path = app.config_dir.join("web_cert.pem");
    let key_path = app.config_dir.join("web_key.pem");
    if !cert_path.exists() || !key_path.exists() {
        let mut subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
            let hostname = hostname.trim().to_string();
            if !hostname.is_empty() {
                subject_alt_names.push(hostname);
            }
        }
        if let Ok(probe) = std::net::UdpSocket::bind("0.0.0.0:0") {
            let _ = probe.set_nonblocking(true);
            if probe.connect("8.8.8.8:53").is_ok()
                && let Ok(addr) = probe.local_addr()
                && !addr.ip().is_loopback()
            {
                subject_alt_names.push(addr.ip().to_string());
            }
        }
        if let Ok(cert) = rcgen::generate_simple_self_signed(subject_alt_names) {
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();
            let _ = tokio::fs::write(&cert_path, cert_pem).await;
            let _ = tokio::fs::write(&key_path, key_pem).await;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                        .await;
            }
        }
    }

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .context("load web cert")?;

    let protocol_runtime = protocol::start(app.clone()).await?;
    let mut protocol_status = protocol_runtime.status_receiver();
    let mut web_task = tokio::spawn(async move { web_panel::run(web_app, tls_config).await });
    tokio::spawn(protocol::session_janitor(app.clone()));
    tokio::spawn(protocol::password_janitor(app.clone()));

    let cpu_app = stats_app.clone();
    tokio::spawn(cpu_loop(cpu_app));
    tokio::spawn(stats_loop(stats_app));

    let monitor_app = app.clone();
    tokio::spawn(local_proxy_monitor_loop(monitor_app));

    let mut web_completed = false;
    let mut terminal_error = None;
    tokio::select! {
        _ = shutdown_signal() => {}
        result = &mut web_task => {
            web_completed = true;
            terminal_error = Some(match result {
                Ok(Ok(())) => anyhow::anyhow!("web server stopped unexpectedly"),
                Ok(Err(error)) => anyhow::anyhow!("web server failed: {error:#}"),
                Err(error) => anyhow::anyhow!("web server task failed: {error}"),
            });
        }
        changed = protocol_status.changed() => {
            terminal_error = Some(match changed {
                Ok(()) => protocol_status
                    .borrow()
                    .clone()
                    .map(anyhow::Error::msg)
                    .unwrap_or_else(|| anyhow::anyhow!("io_uring dataplane stopped unexpectedly")),
                Err(_) => anyhow::anyhow!("io_uring dataplane status channel closed"),
            });
        }
    }

    if !web_completed {
        web_task.abort();
        let _ = web_task.await;
    }
    if let Err(error) = protocol_runtime.shutdown().await
        && terminal_error.is_none()
    {
        terminal_error = Some(error);
    }

    log_event(&app, "INFO", "SHUTDOWN", "Stopping server...");

    let _proxy_operation = app.proxy_operation.lock().await;
    let proxy_route = app.proxy_route.write().await.take();
    if let Some(route) = proxy_route {
        route.deactivate().await;
    }
    if let Err(error) = proxy_route::ProxyRoute::cleanup_orphaned_policy().await
        && terminal_error.is_none()
    {
        terminal_error = Some(error.context("cleanup CSQTT proxy policy during shutdown"));
    }

    let final_revision = {
        let db = app.db.read().await;
        app.db_persistence.submit(db.clone())
    };
    if let Err(error) = app.db_persistence.wait(final_revision).await {
        eprintln!("[DB] final save: {error:#}");
    }

    protocol::drop_all_sessions(&app);
    match terminal_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(target_os = "linux")]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(target_os = "linux"))]
unsafe fn libc_geteuid() -> u32 {
    0
}

async fn local_proxy_monitor_loop(app: Arc<App>) {
    const PORT_CHECK: Duration = Duration::from_secs(3);
    const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
    const IDLE_INTERVAL: Duration = Duration::from_secs(5);
    const STRIKES_BEFORE_PAUSE: u32 = 5;
    const PAUSE_SCHEDULE: [u64; 4] = [30, 90, 120, 120];

    let mut port_failures: u32 = 0;
    let mut pause_round: u32 = 0;
    let mut health_failures: u8 = 0;
    let mut wait = Duration::from_secs(2);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = app.proxy_trigger.notified() => {
                port_failures = 0;
                pause_round = 0;
                health_failures = 0;
            }
        }

        let _operation = app.proxy_operation.lock().await;
        let profile = {
            let db = app.db.read().await;
            db.local_proxy.active_profile().cloned()
        };

        let Some(profile) = profile else {
            *app.proxy_health_error.write().unwrap() = None;
            let old = app.proxy_route.write().await.take();
            if let Some(route) = old {
                route.deactivate().await;
                log_event(
                    &app,
                    "INFO",
                    "PROXY",
                    "Local SOCKS5 routing disabled; direct VPS route restored",
                );
            } else {
                proxy_route::ProxyRoute::cleanup_stale_policy().await;
            }
            port_failures = 0;
            pause_round = 0;
            health_failures = 0;
            wait = IDLE_INTERVAL;
            continue;
        };

        let current = {
            let guard = app.proxy_route.read().await;
            guard.clone()
        };
        if let Some(route) = current {
            if route.is_alive() && route.matches(&profile) {
                if !proxy_route::port_is_listening(profile.port).await {
                    *app.proxy_health_error.write().unwrap() = Some(format!("Порт {} не отвечает", profile.port));
                    app.proxy_port_listening
                        .store(false, std::sync::atomic::Ordering::Release);
                    let failed = app.proxy_route.write().await.take();
                    if let Some(failed) = failed {
                        failed.deactivate().await;
                    }
                    log_event(
                        &app,
                        "WARNING",
                        "PROXY",
                        &format!(
                            "SOCKS5 port {} is no longer listening; clients switched to the direct route",
                            profile.port
                        ),
                    );
                    port_failures = 1;
                    pause_round = 0;
                    health_failures = 0;
                    wait = PORT_CHECK;
                } else {
                    app.proxy_port_listening
                        .store(true, std::sync::atomic::Ordering::Release);
                    match proxy_route::probe_proxy(&profile).await {
                        Ok(()) => {
                            *app.proxy_health_error.write().unwrap() = None;
                            health_failures = 0;
                            port_failures = 0;
                            pause_round = 0;
                            wait = HEALTH_INTERVAL;
                        }
                        Err(error) => {
                            *app.proxy_health_error.write().unwrap() = Some(format!("{error:#}"));
                            health_failures = health_failures.saturating_add(1);
                            log_event(
                                &app,
                                "WARNING",
                                "PROXY",
                                &format!(
                                    "Local SOCKS5 health check failed ({health_failures}/2): {error:#}"
                                ),
                            );
                            if health_failures >= 2 {
                                let failed = app.proxy_route.write().await.take();
                                if let Some(failed) = failed {
                                    failed.deactivate().await;
                                }
                                log_event(
                                    &app,
                                    "WARNING",
                                    "PROXY",
                                    "SOCKS5 route removed; clients continue through the main VPS",
                                );
                                health_failures = 0;
                            }
                            wait = PORT_CHECK;
                        }
                    }
                }
                continue;
            }

            let stale = app.proxy_route.write().await.take();
            if let Some(stale) = stale {
                stale.deactivate().await;
            }
            wait = Duration::from_millis(100);
            continue;
        }

        let listening = proxy_route::port_is_listening(profile.port).await;
        app.proxy_port_listening
            .store(listening, std::sync::atomic::Ordering::Release);
        if !listening {
            *app.proxy_health_error.write().unwrap() = Some(format!("Порт {} не отвечает", profile.port));
            if port_failures == 0 {
                log_event(
                    &app,
                    "WARNING",
                    "PROXY",
                    &format!(
                        "SOCKS5 port {} is not listening; traffic goes direct, port re-check every 3s",
                        profile.port
                    ),
                );
            }
            port_failures = port_failures.saturating_add(1);
            if port_failures >= STRIKES_BEFORE_PAUSE {
                port_failures = 0;
                let pause = PAUSE_SCHEDULE[(pause_round as usize).min(PAUSE_SCHEDULE.len() - 1)];
                pause_round = pause_round.saturating_add(1);
                wait = Duration::from_secs(pause);
            } else {
                wait = PORT_CHECK;
            }
            continue;
        }

        port_failures = 0;
        pause_round = 0;
        health_failures = 0;
        log_event(
            &app,
            "INFO",
            "PROXY",
            &format!(
                "Connecting SOCKS5 forwarder to local SOCKS5 127.0.0.1:{}...",
                profile.port
            ),
        );
        let proxy_log_app = app.clone();
        let proxy_log: proxy_route::LogFn = Arc::new(move |level: &str, msg: &str| {
            log_event(&proxy_log_app, level, "PROXY", msg);
        });
        match proxy_route::ProxyRoute::connect(&profile, proxy_log).await {
            Ok(route) => {
                *app.proxy_health_error.write().unwrap() = None;
                app.proxy_route.write().await.replace(route);
                log_event(
                    &app,
                    "INFO",
                    "PROXY",
                    &format!(
                        "Local SOCKS5 route 127.0.0.1:{} is active (TCP and UDP)",
                        profile.port
                    ),
                );
                wait = HEALTH_INTERVAL;
            }
            Err(error) => {
                *app.proxy_health_error.write().unwrap() = Some(format!("{error:#}"));
                proxy_route::ProxyRoute::cleanup_stale_policy().await;
                log_event(
                    &app,
                    "ERROR",
                    "PROXY",
                    &format!(
                        "Local SOCKS5 is not ready: {error:#}. Direct VPS route is active; retry in 3s"
                    ),
                );
                wait = PORT_CHECK;
            }
        }
    }
}

#[cfg(test)]
mod lock_tests {
    use super::{CpuSnapshot, cpu_percentage, normalize_dns, parse_host_cpu, parse_process_cpu};

    #[test]
    fn dns_override_accepts_one_or_two_ipv4_addresses() {
        assert_eq!(normalize_dns("8.8.8.8").unwrap(), "8.8.8.8");
        assert_eq!(
            normalize_dns(" 8.8.8.8, 8.8.4.4 ").unwrap(),
            "8.8.8.8,8.8.4.4"
        );
    }

    #[test]
    fn dns_override_rejects_invalid_or_excess_addresses() {
        assert!(normalize_dns("").is_err());
        assert!(normalize_dns("example.org").is_err());
        assert!(normalize_dns("1.1.1.1,1.0.0.1,8.8.8.8").is_err());
    }

    #[test]
    fn poisoned_mutex_recovers_without_process_failure() {
        let mutex = std::sync::Arc::new(std::sync::Mutex::new(1u64));
        let poisoned = mutex.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("poison");
        })
        .join();
        *super::lock_unpoison(&mutex) = 2;
        assert_eq!(*super::lock_unpoison(&mutex), 2);
    }

    #[test]
    fn parses_linux_cpu_counters_and_process_name_with_spaces() {
        let host = "cpu  100 2 30 400 10 0 0 0 0 0\ncpu0 50 1 15 200\ncpu1 50 1 15 200\n";
        assert_eq!(parse_host_cpu(host), Some((542, 2)));
        let process = "77 (csqtt worker) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14";
        assert_eq!(parse_process_cpu(process), Some(23));
    }

    #[test]
    fn calculates_process_cpu_in_one_core_percent() {
        let previous = CpuSnapshot {
            total: 2_000,
            process: 100,
            cores: 4,
        };
        let current = CpuSnapshot {
            total: 2_100,
            process: 120,
            cores: 4,
        };
        assert_eq!(cpu_percentage(previous, current), Some(80));
    }
}
