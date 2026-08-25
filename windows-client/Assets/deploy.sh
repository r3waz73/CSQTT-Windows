#!/bin/bash
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export TERM="${TERM:-xterm}"

readonly SCRIPT_VERSION="2.0.0-fast"
readonly LOG_FILE="/var/log/csqtt-install.log"
readonly PEER_PORT="${CSQTT_PEER_PORT:-46000}"
readonly SSH_PORT="${CSQTT_SSH_PORT:-22}"
readonly WEB_PORT="${CSQTT_WEB_PORT:-46002}"
readonly DEPLOY_MODE="${CSQTT_DEPLOY_MODE:-systemd}"
readonly CSQTT_IFACE="csqtt1"
readonly CSQTT_CONFIG_DIR="/etc/csqtt"
readonly CSQTT_ACCESS_DB="passwords.json"
readonly CSQTT_ENV_FILE="${CSQTT_CONFIG_DIR}/csqtt.env"
readonly CSQTT_DEPLOY_OVERRIDES_FILE="${CSQTT_CONFIG_DIR}/deploy-overrides.json"
readonly CSQTT_SYSCTL_FILE="/etc/sysctl.d/99-csqtt.conf"
readonly CSQTT_UDP_SYSCTL_FILE="/etc/sysctl.d/99-csqtt-udp-buffers.conf"
readonly IPT_COMMENT="CSQTT_MANAGED"
readonly IPT_MIRROR_COMMENT="CSQTT_MIRRORED"
readonly CSQTT_PROXY_RULE_PATTERN="CSQTT_TPROXY|CSQTT_LOCAL_SOCKS|CSQTT_LOCAL_SOCKS_MARK|CSQTT_SOCKS|CSQTT_CASCADE_NO_QUIC"
readonly CSQTT_DOCKER_DIR="${CSQTT_CONFIG_DIR}/docker"
readonly CSQTT_DOCKER_IMAGE="csqtt:2.0.0"
readonly CSQTT_DOCKER_CONTAINER="csqtt"
readonly XT_WAIT="${CSQTT_XT_WAIT:-2}"
readonly NETFILTER_TIMEOUT="${CSQTT_NETFILTER_TIMEOUT:-8}"
readonly DEEP_CLEANUP="${CSQTT_DEEP_CLEANUP:-0}"
readonly START_STABILITY_SECONDS="${CSQTT_START_STABILITY_SECONDS:-1}"
readonly NETWORK_READY_STAMP="/run/csqtt-network-ready"

CSQTT_URING_SELECTED_MODE=""
SYSTEMD_NEEDS_RELOAD=0
NETFILTER_CLEANUP_OK=1

validate_port() {
    local name="$1" value="$2"
    case "$value" in
        ''|*[!0-9]*) die "$name должен быть числом от 1 до 65535, получено: $value" ;;
    esac
    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        die "$name должен быть в диапазоне 1..65535, получено: $value"
    fi
}

C_GREEN=''; C_YELLOW=''; C_RED=''
C_CYAN='';  C_BOLD='';      C_NC=''

log_info()  { echo -e "${C_GREEN}[✓]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${C_YELLOW}[!]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${C_RED}[✗]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_step()  { echo -e "${C_CYAN}[►]${C_NC} ${C_BOLD}$*${C_NC}" | tee -a "$LOG_FILE"; }

die() { log_error "$*"; exit 1; }

prog() { echo "CSQTT_PROGRESS|$1|$2"; }

run_timed() {
    local label="$1" started=$SECONDS
    shift
    "$@"
    log_info "Время этапа «$label»: $((SECONDS - started))с"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Скрипт должен быть запущен от root. Если sudo отсутствует, зайдите под root и запустите: bash $0 $*"
    fi
}

OS_ID="" ; PKG_MGR=""

detect_os() {
    log_step "Определение операционной системы..."
    if [ ! -f /etc/os-release ]; then
        die "Файл /etc/os-release не найден."
    fi
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)     PKG_MGR="apt" ;;
        centos|rhel|rocky|almalinux|oracle|ol) PKG_MGR="yum"
            command -v dnf &>/dev/null && PKG_MGR="dnf" ;;
        fedora)                          PKG_MGR="dnf" ;;
        arch|manjaro|endeavouros)        PKG_MGR="pacman" ;;
        *)
            case " ${ID_LIKE:-} " in
                *" debian "*) PKG_MGR="apt" ;;
                *" rhel "*|*" fedora "*)
                    PKG_MGR="yum"
                    command -v dnf &>/dev/null && PKG_MGR="dnf"
                    ;;
                *" arch "*) PKG_MGR="pacman" ;;
                *) die "Неподдерживаемый дистрибутив: $OS_ID" ;;
            esac
            ;;
    esac
    log_info "ОС: ${PRETTY_NAME:-$OS_ID} | PM: $PKG_MGR"
}

pkg_update_done=0

pkg_update() {
    [ "$pkg_update_done" = "1" ] && return 0
    log_step "Обновление индексов пакетов..."
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >>"$LOG_FILE" 2>&1 || log_warn "apt update завершился с ошибкой, пробую продолжить"
            ;;
        dnf)    dnf makecache -y >>"$LOG_FILE" 2>&1 || true ;;
        yum)    yum makecache -y >>"$LOG_FILE" 2>&1 || true ;;
        pacman) : ;;
    esac
    pkg_update_done=1
}

pkg_install() {
    [ "$#" -eq 0 ] && return 0
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y -qq --no-install-recommends "$@" >>"$LOG_FILE" 2>&1
            ;;
        dnf)    dnf install -y "$@" >>"$LOG_FILE" 2>&1 ;;
        yum)    yum install -y "$@" >>"$LOG_FILE" 2>&1 ;;
        pacman) pacman -Syu --noconfirm --needed "$@" >>"$LOG_FILE" 2>&1 ;;
    esac
}

install_prerequisites() {
    prog 0.10 "Пакеты..."
    log_step "Проверка базовых зависимостей..."

    local ip_package procps_package
    case "$PKG_MGR" in
        apt)     ip_package="iproute2"; procps_package="procps" ;;
        dnf|yum) ip_package="iproute";  procps_package="procps-ng" ;;
        pacman)  ip_package="iproute2"; procps_package="procps-ng" ;;
    esac

    local -a packages=()
    local need_iptables=0
    command -v ip >/dev/null 2>&1 || packages+=("$ip_package")
    command -v modprobe >/dev/null 2>&1 || packages+=("kmod")
    if ! command -v sysctl >/dev/null 2>&1 || ! command -v pkill >/dev/null 2>&1; then
        packages+=("$procps_package")
    fi
    command -v iptables >/dev/null 2>&1 || need_iptables=1

    if [ "$PKG_MGR" = "pacman" ] && [ "$need_iptables" -eq 1 ]; then
        packages+=("iptables")
        need_iptables=0
    fi

    if [ "${#packages[@]}" -eq 0 ] && [ "$need_iptables" -eq 0 ]; then
        log_info "Все системные зависимости уже установлены — обновление пакетов не требуется"
        return 0
    fi

    pkg_update
    if [ "${#packages[@]}" -gt 0 ]; then
        pkg_install "${packages[@]}" || die "Не удалось установить обязательные пакеты: ${packages[*]}"
    fi

    if [ "$need_iptables" -eq 1 ]; then
        case "$PKG_MGR:$OS_ID" in
            dnf:fedora)
                pkg_install iptables-nft || pkg_install iptables || \
                    die "Не удалось установить iptables/iptables-nft"
                ;;
            dnf:*|yum:*)
                pkg_install iptables || pkg_install iptables-nft || \
                    die "Не удалось установить iptables/iptables-nft"
                ;;
            *)
                pkg_install iptables || die "Не удалось установить обязательный пакет iptables"
                ;;
        esac
    fi
}

require_runtime_tools() {
    command -v iptables-save >/dev/null 2>&1 || die "iptables-save not found"
    command -v iptables-restore >/dev/null 2>&1 || die "iptables-restore not found"
    command -v ip >/dev/null 2>&1 || die "Команда ip не найдена. Установите iproute2/iproute."
    command -v iptables >/dev/null 2>&1 || die "Команда iptables не найдена. Она обязательна для TUN и NAT."
    command -v sysctl >/dev/null 2>&1 || die "Команда sysctl не найдена. Установите procps/procps-ng."
    command -v pkill >/dev/null 2>&1 || die "Команда pkill не найдена. Установите procps/procps-ng."
    if [ "$DEPLOY_MODE" = "systemd" ]; then
        command -v systemctl >/dev/null 2>&1 || die "systemctl не найден. Для native-установки нужен VPS с systemd."
    fi
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) die "Серверный бинарник CSQTT собран для x86_64; архитектура $(uname -m) пока не поддерживается." ;;
    esac
}

detect_wan_interface() {
    local iface=""
    iface=$(ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    [ -z "$iface" ] && iface=$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR == 1 { print $2 }')
    [ -z "$iface" ] && iface=$(ls /sys/class/net/ | grep -v lo | head -1)
    echo "$iface"
}

FW_BACKEND=""

iptables_add_input() {
    local proto="$1" port="$2" comment="$3"
    [ "$FW_BACKEND" = "iptables" ] || return 0
    case "$proto:$port" in
        tcp:[0-9]*|udp:[0-9]*) ;;
        *) return 0 ;;
    esac
    [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || return 0
    iptables -C INPUT -p "$proto" --dport "$port" -m comment --comment "$comment" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p "$proto" --dport "$port" -m comment --comment "$comment" -j ACCEPT 2>/dev/null || true
}

mirror_port_to_iptables() {
    local proto="$1" port="$2" source="$3"
    iptables_add_input "$proto" "$port" "$IPT_MIRROR_COMMENT"
    log_info "iptables: сохранён доступ $port/$proto из $source"
}

mirror_existing_firewall_ports_to_iptables() {
    # Не перечисляем весь nft ruleset. На некоторых VPS `nft list ruleset`
    # занимает 15+ секунд. Добавление наших iptables-правил не удаляет
    # существующие UFW/nftables правила, поэтому дорогое зеркалирование не нужно.
    return 0
}

detect_firewall() {
    command -v iptables >/dev/null 2>&1 || \
        die "iptables не найден: без него сервер не сможет создать рабочий TUN/NAT."
    FW_BACKEND="iptables"
    local ver
    ver="$(iptables --version 2>/dev/null || echo unknown)"
    log_info "Firewall backend: iptables (${ver})"
}

ipt_add_or_ensure() {
    # Быстрый путь после успешной cleanup: сразу добавляем правило (1 вызов вместо -C + add).
    # Если cleanup не смог прочитать/восстановить ruleset, используем idempotent -C fallback.
    local table="$1" chain="$2"
    shift 2
    local -a targs=()
    [ "$table" = "filter" ] || targs=(-t "$table")
    if [ "$NETFILTER_CLEANUP_OK" -eq 1 ]; then
        iptables -w "$XT_WAIT" "${targs[@]}" -I "$chain" "$@" >>"$LOG_FILE" 2>&1
    else
        iptables -w "$XT_WAIT" "${targs[@]}" -C "$chain" "$@" >/dev/null 2>&1 || \
            iptables -w "$XT_WAIT" "${targs[@]}" -I "$chain" "$@" >>"$LOG_FILE" 2>&1
    fi
}

fw_add_input_udp() {
    local port="$1"
    ipt_add_or_ensure filter INPUT -p udp --dport "$port" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось открыть ${port}/udp в iptables"
}

fw_add_input_tcp() {
    local port="$1"
    ipt_add_or_ensure filter INPUT -p tcp --dport "$port" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось открыть ${port}/tcp в iptables"
}

fw_add_forward() {
    ipt_add_or_ensure filter FORWARD -i "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось установить FORWARD -i $CSQTT_IFACE"
    ipt_add_or_ensure filter FORWARD -o "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось установить FORWARD -o $CSQTT_IFACE"
}

fw_add_masquerade() {
    local iface="$1" subnet="$2"
    # POSTROUTING логичнее append, чтобы не ломать порядок существующего NAT.
    if [ "$NETFILTER_CLEANUP_OK" -eq 1 ]; then
        iptables -w "$XT_WAIT" -t nat -A POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$IPT_COMMENT" -j MASQUERADE >>"$LOG_FILE" 2>&1 || \
            die "Не удалось установить NAT MASQUERADE через $iface"
    else
        iptables -w "$XT_WAIT" -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$IPT_COMMENT" -j MASQUERADE >/dev/null 2>&1 || \
            iptables -w "$XT_WAIT" -t nat -A POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$IPT_COMMENT" -j MASQUERADE >>"$LOG_FILE" 2>&1 || \
            die "Не удалось установить NAT MASQUERADE через $iface"
    fi
}

fw_add_mss_clamping() {
    local subnet="$1"
    ipt_add_or_ensure mangle FORWARD -s "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu || \
        die "Не удалось установить исходящий TCP MSS clamping"
    ipt_add_or_ensure mangle FORWARD -d "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu || \
        die "Не удалось установить входящий TCP MSS clamping"
}

filter_netfilter_backend() {
    local save_cmd="$1" restore_cmd="$2" pattern="$3"
    command -v "$save_cmd" >/dev/null 2>&1 || return 0
    command -v "$restore_cmd" >/dev/null 2>&1 || return 0

    local dump filtered
    dump="$(mktemp 2>/dev/null || echo "/tmp/csqtt-save-$$.tmp")"
    filtered="$(mktemp 2>/dev/null || echo "/tmp/csqtt-filtered-$$.tmp")"

    # Один save вместо прежних 2-3 проходов по каждому backend.
    if ! timeout "$NETFILTER_TIMEOUT" "$save_cmd" >"$dump" 2>>"$LOG_FILE"; then
        log_warn "$save_cmd не завершился за ${NETFILTER_TIMEOUT}с; перехожу на idempotent добавление правил"
        NETFILTER_CLEANUP_OK=0
        rm -f "$dump" "$filtered"
        return 0
    fi

    if ! grep -Eq "$pattern" "$dump"; then
        rm -f "$dump" "$filtered"
        return 0
    fi

    grep -Ev "$pattern" "$dump" >"$filtered" || true
    if [ -s "$filtered" ]; then
        if ! timeout "$NETFILTER_TIMEOUT" "$restore_cmd" -w "$XT_WAIT" <"$filtered" >>"$LOG_FILE" 2>&1; then
            NETFILTER_CLEANUP_OK=0
            log_warn "$restore_cmd не успел применить очищенный ruleset; перехожу на idempotent добавление"
        fi
    fi
    rm -f "$dump" "$filtered"
}

filter_all_netfilter_backends() {
    local pattern="$1"

    # Для обычного деплоя очищаем только АКТИВНЫЙ backend, которым пользуется
    # команда `iptables`. На Ubuntu 24 iptables-save и iptables-nft-save часто
    # являются одним и тем же xtables-nft backend, а двойной обход стоит секунды.
    filter_netfilter_backend iptables-save iptables-restore "$pattern"

    # Опциональный медленный migration/deep-clean для редких случаев смены backend.
    [ "$DEEP_CLEANUP" = "1" ] || return 0
    local active_save candidate_save candidate_restore active_real candidate_real
    active_save="$(command -v iptables-save 2>/dev/null || true)"
    active_real="$(readlink -f "$active_save" 2>/dev/null || echo "$active_save")"
    for pair in "iptables-nft-save:iptables-nft-restore" "iptables-legacy-save:iptables-legacy-restore"; do
        candidate_save="${pair%%:*}"
        candidate_restore="${pair#*:}"
        command -v "$candidate_save" >/dev/null 2>&1 || continue
        candidate_real="$(readlink -f "$(command -v "$candidate_save")" 2>/dev/null || command -v "$candidate_save")"
        [ "$candidate_real" = "$active_real" ] && continue
        filter_netfilter_backend "$candidate_save" "$candidate_restore" "$pattern"
    done
}

verify_all_netfilter_backends() {
    # Отдельный повторный *-save намеренно убран: он дублировал дорогую работу.
    # filter_netfilter_backend уже фильтрует снимок и проверяет restore status.
    return 0
}

cleanup_csqtt_netfilter_rules() {
    local pattern="$IPT_COMMENT|$IPT_MIRROR_COMMENT|$CSQTT_PROXY_RULE_PATTERN"
    filter_all_netfilter_backends "$pattern"

    # Старые native nft-таблицы удаляем параллельно и с коротким лимитом.
    # Это не вызывает дорогой `nft list ruleset`.
    if command -v nft >/dev/null 2>&1; then
        timeout 1 nft delete table ip csqtt >/dev/null 2>&1 &
        local p1=$!
        timeout 1 nft delete table inet csqtt >/dev/null 2>&1 &
        local p2=$!
        timeout 1 nft delete table inet csqtt_mangle >/dev/null 2>&1 &
        local p3=$!
        wait "$p1" 2>/dev/null || true
        wait "$p2" 2>/dev/null || true
        wait "$p3" 2>/dev/null || true
    fi
}

fw_cleanup_csqtt_rules() {
    # Сохранено как совместимый alias для старых путей uninstall/status.
    cleanup_csqtt_netfilter_rules
}

cleanup_csqtt_proxy_policy() {
    local i
    for i in 1 2 3 4; do ip -4 rule del fwmark 0x1/0x1 priority 100 table 100 >/dev/null 2>&1 || break; done
    for i in 1 2 3 4; do ip -4 rule del fwmark 0x422 priority 1066 table 1066 >/dev/null 2>&1 || break; done
    for i in 1 2 3 4; do ip -4 rule del from 10.66.67.0/24 priority 1066 table 1066 >/dev/null 2>&1 || break; done
    ip -4 route flush table 100 >/dev/null 2>&1 || true
    ip -4 route flush table 1066 >/dev/null 2>&1 || true
    ip -4 route flush cache >/dev/null 2>&1 || true
}

cleanup_config_dir_keep_access_db() {
    [ -d "$CSQTT_CONFIG_DIR" ] || return 0
    find "$CSQTT_CONFIG_DIR" -mindepth 1 -maxdepth 1 \
        ! -name "$CSQTT_ACCESS_DB" \
        ! -name "web_cert.pem" \
        ! -name "web_key.pem" \
        ! -name "csqtt.log" \
        ! -name "csqtt.env" \
        -exec rm -rf {} + 2>/dev/null || true
    [ -f "$CSQTT_CONFIG_DIR/$CSQTT_ACCESS_DB" ] && chmod 600 "$CSQTT_CONFIG_DIR/$CSQTT_ACCESS_DB" 2>/dev/null || true
    [ -f "$CSQTT_ENV_FILE" ] && chmod 600 "$CSQTT_ENV_FILE" 2>/dev/null || true
    [ -f "$CSQTT_CONFIG_DIR/web_key.pem" ] && chmod 600 "$CSQTT_CONFIG_DIR/web_key.pem" 2>/dev/null || true
}

# Удаляет TUN-интерфейсы csqtp*, оставшиеся от старой tun2proxy-архитектуры
# локального SOCKS5-форвардера (новые версии используют TPROXY без второго TUN).
cleanup_legacy_proxy_interfaces() {
    local iface
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep '^csqtp'); do
        timeout 2 ip link del "$iface" 2>/dev/null || true
    done
}

csqtt_cleanup() {
    prog 0.15 "Очистка..."
    echo "🧹 Очистка старой установки CSQTT..."

    local had_old_install=0
    if [ -e /etc/systemd/system/csqtt.service ] || [ -x /usr/local/bin/csqtt ] || \
       [ -d "$CSQTT_CONFIG_DIR" ] || ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        had_old_install=1
    fi

    if command -v docker >/dev/null 2>&1; then
        timeout 3 docker rm -f "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1 || true
    fi

    # Redeploy не должен ждать TimeoutStopSec. Сразу отменяем старый runtime.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop csqtt --no-block >/dev/null 2>&1 || true
        timeout 2 systemctl kill --kill-who=all --signal=SIGKILL csqtt >/dev/null 2>&1 || true
    fi
    pkill -9 -x csqtt >/dev/null 2>&1 || true

    if [ -L /etc/systemd/system/csqtt.service ]; then
        # systemd mask (/dev/null) или чужой symlink: заменим нашим обычным unit.
        rm -f /etc/systemd/system/csqtt.service 2>/dev/null || true
        SYSTEMD_NEEDS_RELOAD=1
    fi

    if [ -d /etc/systemd/system/csqtt.service.d ]; then
        rm -rf /etc/systemd/system/csqtt.service.d 2>/dev/null || true
        SYSTEMD_NEEDS_RELOAD=1
    fi
    if [ "$DEPLOY_MODE" != "systemd" ]; then
        [ -e /etc/systemd/system/csqtt.service ] || [ -L /etc/systemd/system/csqtt.service ] && SYSTEMD_NEEDS_RELOAD=1
        rm -f /etc/systemd/system/csqtt.service 2>/dev/null || true
        rm -f /etc/systemd/system/multi-user.target.wants/csqtt.service 2>/dev/null || true
    fi
    # Для systemd redeploy unit оставляем на месте до atomic compare/install.
    # Так неизменный unit не требует daemon-reload (~2 сек на тестовом VPS).

    rm -f "$NETWORK_READY_STAMP" 2>/dev/null || true
    if ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        timeout 2 ip link del "$CSQTT_IFACE" 2>/dev/null || true
    fi
    cleanup_legacy_proxy_interfaces

    cleanup_csqtt_proxy_policy
    [ "$had_old_install" -eq 1 ] && cleanup_csqtt_netfilter_rules

    rm -f /usr/local/bin/csqtt 2>/dev/null || true
    cleanup_config_dir_keep_access_db

    echo "✓ Очистка завершена (база доступа сохранена)"
}

setup_sysctl() {
    prog 0.25 "Sysctl..."
    echo "⚙️  Настройка сетевых параметров..."

    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    mkdir -p /etc/sysctl.d
    cat > "$CSQTT_SYSCTL_FILE" << 'SYSEOF'
net.ipv4.ip_forward = 1
# TCP BBR (Bottleneck Bandwidth and Round-trip propagation time)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Max connection tracking (for TPROXY & heavy load)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# Socket limits
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
SYSEOF

    if [ -r /proc/sys/kernel/io_uring_disabled ]; then
        local io_uring_disabled
        io_uring_disabled="$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo unknown)"
        case "$io_uring_disabled" in
            0) log_info "io_uring разрешён ядром" ;;
            1|2)
                log_warn "kernel.io_uring_disabled=$io_uring_disabled; пробую включить io_uring"
                sysctl -w kernel.io_uring_disabled=0 >>"$LOG_FILE" 2>&1 || \
                    log_warn "Провайдер не разрешает менять io_uring sysctl; решающей будет рабочая probe"
                ;;
            *) log_warn "Неизвестное kernel.io_uring_disabled=$io_uring_disabled; решающей будет рабочая probe" ;;
        esac
    fi

    cat > "$CSQTT_UDP_SYSCTL_FILE" << 'SYSEOF'
# Extreme buffer sizes for 100-200+ Mbps proxying
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Auto-tuning TCP buffers
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432

# Enable Window Scaling
net.ipv4.tcp_window_scaling = 1
SYSEOF

    sysctl -p "$CSQTT_SYSCTL_FILE" >>"$LOG_FILE" 2>&1 || log_warn "Не удалось применить некоторые параметры BBR/sysctl (возможно ядро не поддерживает BBR)"
    sysctl -p "$CSQTT_UDP_SYSCTL_FILE" >>"$LOG_FILE" 2>&1 || log_warn "Ядро ограничило UDP/TCP буферы; сервер продолжит работу с доступными значениями"

    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || \
        die "IPv4 forwarding невозможно включить на этом VPS"

    echo "✓ Sysctl настроен"
}

setup_nat_and_firewall() {
    prog 0.40 "NAT + Firewall..."
    echo "🛡  Настройка NAT и фаервола..."

    local iface
    iface=$(detect_wan_interface)

    if [ -z "$iface" ]; then
        die "Не удалось определить WAN-интерфейс для NAT подсети 10.66.67.0/24"
    fi
    ip link show "$iface" >/dev/null 2>&1 || die "Определённый WAN-интерфейс $iface не существует"

    log_info "WAN-интерфейс: $iface"

    fw_add_input_udp "$PEER_PORT"
    fw_add_input_tcp "$SSH_PORT"
    fw_add_input_tcp "$WEB_PORT"

    fw_add_forward

    fw_add_masquerade "$iface" "10.66.67.0/24"
    
    fw_add_mss_clamping "10.66.67.0/24"

    mkdir -p /run
    touch "$NETWORK_READY_STAMP"

    echo "✓ NAT: MASQUERADE на $iface для 10.66.67.0/24"
    echo "✓ Порты: ${PEER_PORT}/udp(PEER), ${SSH_PORT}/tcp(SSH), ${WEB_PORT}/tcp(WEB)"
    echo "✓ TCP MSS Clamping включен"
}

install_network_helper() {
    mkdir -p /usr/local/lib/csqtt
    cat > /usr/local/lib/csqtt/network-up.sh << NETEOF
#!/bin/sh
set -eu
STAMP="$NETWORK_READY_STAMP"
PEER_PORT="$PEER_PORT"
SSH_PORT="$SSH_PORT"
WEB_PORT="$WEB_PORT"
CSQTT_IFACE="$CSQTT_IFACE"
IPT_COMMENT="$IPT_COMMENT"
SUBNET="10.66.67.0/24"
XT_WAIT="$XT_WAIT"

# Во время текущего deploy сеть уже настроена. /run очищается после reboot,
# поэтому на следующей загрузке правила будут восстановлены автоматически.
if [ -e "\$STAMP" ] && [ "\$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
    exit 0
fi

command -v ip >/dev/null 2>&1 || exit 20
command -v iptables >/dev/null 2>&1 || exit 21
[ -w /proc/sys/net/ipv4/ip_forward ] && echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
WAN_IFACE=\$(ip route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if(\$i=="dev") {print \$(i+1); exit}}')
[ -n "\$WAN_IFACE" ] || WAN_IFACE=\$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1 {print \$2}')
[ -n "\$WAN_IFACE" ] || exit 22

ipt() { iptables -w "\$XT_WAIT" "\$@"; }
ipt -C INPUT -p udp --dport "\$PEER_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p udp --dport "\$PEER_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$SSH_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$SSH_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$WEB_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$WEB_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -i "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I FORWARD -i "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -o "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I FORWARD -o "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -t nat -C POSTROUTING -s "\$SUBNET" -o "\$WAN_IFACE" -m comment --comment "\$IPT_COMMENT" -j MASQUERADE 2>/dev/null || ipt -t nat -A POSTROUTING -s "\$SUBNET" -o "\$WAN_IFACE" -m comment --comment "\$IPT_COMMENT" -j MASQUERADE
ipt -t mangle -C FORWARD -s "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ipt -t mangle -I FORWARD -s "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
ipt -t mangle -C FORWARD -d "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ipt -t mangle -I FORWARD -d "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
mkdir -p /run
touch "\$STAMP"
NETEOF
    chmod 0755 /usr/local/lib/csqtt/network-up.sh
}

verify_configured_network() {
    # Быстрая финальная проверка без повторных семи iptables -C вызовов.
    local iface="${1:-$(detect_wan_interface)}"
    [ -n "$iface" ] || die "WAN-интерфейс не определён при проверке сети"
    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || die "IPv4 forwarding не включён"
    ip link show "$iface" >/dev/null 2>&1 || die "WAN-интерфейс $iface исчез"
}

setup_csqtt_binary() {
    prog 0.60 "Бинарник..."
    echo "Установка csqtt..."

    if [ -f /tmp/csqtt ]; then
        chmod +x /tmp/csqtt
        install -m 0755 /tmp/csqtt /usr/local/bin/csqtt 2>/dev/null || mv /tmp/csqtt /usr/local/bin/csqtt
        echo "✓ csqtt установлен"
    elif [ -f /usr/local/bin/csqtt ]; then
        echo "✓ csqtt уже установлен"
    else
        die "csqtt не найден ни в /tmp/csqtt, ни в /usr/local/bin/csqtt"
    fi

    # Локальный SOCKS5-форвардер встроен в csqtt (TPROXY + kernel TCP, in-process)
    # и поднимается автоматически при активации SOCKS5-профиля.
    # Удаляем старые внешние копии HEV, если они остались от прошлых версий.
    rm -f /usr/local/bin/hev-socks5-tunnel
    echo "✓ SOCKS5-форвардер встроен в csqtt (TPROXY, поднимается при первом использовании)"

    # Миграция: удаляем старый межсерверный каскад. HEV tunnel остаётся и
    # теперь подключается только к обычному локальному SOCKS5 в 3x-ui.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop csqtt-cascade.service --no-block >/dev/null 2>&1 || true
        timeout 1 systemctl kill --kill-who=all --signal=SIGKILL csqtt-cascade.service >/dev/null 2>&1 || true
    fi
    if [ -e /etc/systemd/system/csqtt-cascade.service ] || [ -L /etc/systemd/system/csqtt-cascade.service ]; then
        SYSTEMD_NEEDS_RELOAD=1
    fi
    rm -f /etc/systemd/system/csqtt-cascade.service
    rm -f /etc/systemd/system/multi-user.target.wants/csqtt-cascade.service
    rm -f /usr/local/bin/csqtt-cascade /usr/local/bin/hev-socks5-server
    rm -f /usr/local/share/csqtt/cascade.sh
    rm -rf /etc/csqtt-cascade

    mkdir -p "$CSQTT_CONFIG_DIR"
}

setup_csqtt_environment() {
    if [ -f /tmp/csqtt.env ]; then
        install -m 0600 /tmp/csqtt.env "$CSQTT_ENV_FILE"
    elif [ ! -f "$CSQTT_ENV_FILE" ]; then
        install -m 0600 /dev/null "$CSQTT_ENV_FILE"
    fi

    [ -s /tmp/csqtt-deploy.json ] || die "Одноразовая deploy-конфигурация не загружена"
    install -m 0600 /tmp/csqtt-deploy.json "$CSQTT_DEPLOY_OVERRIDES_FILE"
    rm -f /tmp/csqtt.env /tmp/csqtt-deploy.json
    echo "✓ Конфигурация запуска установлена безопасным EnvironmentFile"
}

persist_runtime_compatibility_env() {
    [ -n "$CSQTT_URING_SELECTED_MODE" ] || die "Совместимый CSQTT_URING_MODE не выбран"
    local tmp
    tmp="$(mktemp)"
    if [ -f "$CSQTT_ENV_FILE" ]; then
        grep -Ev '^[[:space:]]*(export[[:space:]]+)?CSQTT_URING_MODE=' "$CSQTT_ENV_FILE" >"$tmp" || true
    fi
    printf 'CSQTT_URING_MODE=%s\n' "$CSQTT_URING_SELECTED_MODE" >>"$tmp"
    install -m 0600 "$tmp" "$CSQTT_ENV_FILE"
    rm -f "$tmp"
    log_info "Runtime compatibility: CSQTT_URING_MODE=$CSQTT_URING_SELECTED_MODE"
}

ensure_docker() {
    log_step "Проверка Docker Engine..."

    if ! command -v docker >/dev/null 2>&1; then
        pkg_update
        if [ "$PKG_MGR" = "pacman" ]; then
            pkg_install docker || die "Не удалось установить Docker Engine"
        else
            pkg_install ca-certificates curl || die "Не удалось установить curl и ca-certificates для Docker"
            local installer
            installer="$(mktemp)"
            curl -fsSL https://get.docker.com -o "$installer" || die "Не удалось загрузить официальный установщик Docker"
            sh "$installer" >>"$LOG_FILE" 2>&1 || {
                rm -f "$installer"
                die "Не удалось установить Docker Engine"
            }
            rm -f "$installer"
        fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker >>"$LOG_FILE" 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
        service docker start >>"$LOG_FILE" 2>&1 || true
    fi

    docker --version | tee -a "$LOG_FILE"
    docker info >>"$LOG_FILE" 2>&1 || die "Docker установлен, но демон недоступен; проверьте docker info"
    log_info "Docker Engine готов"
}

ensure_tun_device() {
    if [ -c /dev/net/tun ]; then
        chmod 666 /dev/net/tun 2>/dev/null || true
        return 0
    fi
    if command -v modprobe >/dev/null 2>&1; then
        modprobe tun >>"$LOG_FILE" 2>&1 || true
    fi
    mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 >>"$LOG_FILE" 2>&1 || true
    [ -c /dev/net/tun ] || die "Устройство /dev/net/tun недоступно на этом VPS"
    chmod 666 /dev/net/tun 2>/dev/null || true
}

check_kernel_compatibility() {
    [ "$(uname -s)" = "Linux" ] || die "CSQTT Server поддерживает только Linux"
    local release base major minor
    release="$(uname -r)"
    base="${release%%-*}"
    major="${base%%.*}"
    base="${base#*.}"
    minor="${base%%.*}"
    case "$major:$minor" in
        *[!0-9:]*|:*) log_warn "Не удалось разобрать версию ядра $release; решающей будет рабочая io_uring-проба" ;;
        *)
            if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 5 ]; }; then
                log_warn "Ядро $release старше проверенного диапазона 5.5–7.x; установка продолжится только при успешных рабочих пробах"
            else
                log_info "Ядро Linux $release входит в поддерживаемый диапазон"
            fi
            ;;
    esac
}

load_kernel_network_modules() {
    command -v modprobe >/dev/null 2>&1 || return 0
    local module
    for module in tun nf_tables ip_tables iptable_filter iptable_nat iptable_mangle iptable_raw nf_nat nf_conntrack xt_comment xt_MASQUERADE xt_TCPMSS; do
        modprobe "$module" >>"$LOG_FILE" 2>&1 || true
    done
}

probe_tun_support() {
    ensure_tun_device
    local probe_iface="cqtprobe$(( $$ % 100000 ))"
    ip link del "$probe_iface" >>"$LOG_FILE" 2>&1 || true
    if ! ip tuntap add dev "$probe_iface" mode tun >>"$LOG_FILE" 2>&1; then
        load_kernel_network_modules
        ip link del "$probe_iface" >>"$LOG_FILE" 2>&1 || true
        if ! ip tuntap add dev "$probe_iface" mode tun >>"$LOG_FILE" 2>&1; then
            die "TUN существует, но ядро или политика VPS запрещает TUNSETIFF/CAP_NET_ADMIN"
        fi
    fi
    if ! ip link del "$probe_iface" >>"$LOG_FILE" 2>&1; then
        die "Рабочий TUN создан, но тестовый интерфейс $probe_iface не удалось удалить"
    fi
    log_info "TUN проверен реальным созданием и удалением интерфейса"
}

cleanup_netfilter_probe() {
    local chain="$1" table
    for table in filter nat mangle; do
        iptables -w "$XT_WAIT" -t "$table" -X "$chain" >/dev/null 2>&1 || true
    done
}

probe_netfilter_support() {
    local table chain="CSQTT_P$(( $$ % 1000000 ))"
    # Проверяем только реально используемые таблицы и без дорогих -S/verify проходов.
    for table in filter nat mangle; do
        if ! iptables -w "$XT_WAIT" -t "$table" -N "$chain" >>"$LOG_FILE" 2>&1; then
            load_kernel_network_modules
            iptables -w "$XT_WAIT" -t "$table" -N "$chain" >>"$LOG_FILE" 2>&1 || {
                cleanup_netfilter_probe "$chain"
                die "Нет доступа к netfilter-таблице $table"
            }
        fi
        iptables -w "$XT_WAIT" -t "$table" -X "$chain" >>"$LOG_FILE" 2>&1 || {
            cleanup_netfilter_probe "$chain"
            die "Не удалось удалить тестовую netfilter-цепочку $chain из $table"
        }
    done
    log_info "Netfilter filter/nat/mangle проверен быстрой записью и удалением правил"
}

probe_io_uring_support() {
    [ -x /usr/local/bin/csqtt ] || die "io_uring-проба невозможна: бинарник csqtt не установлен"
    local requested output mode last_output=""
    CSQTT_URING_SELECTED_MODE=""

    # На большинстве VPS первый defer проходит сразу. Остальные режимы — fallback.
    for requested in defer basic single coop; do
        if output="$(CSQTT_URING_MODE="$requested" /usr/local/bin/csqtt --io-uring-probe 2>&1)"; then
            mode="$(printf '%s\n' "$output" | tail -n 1 | tr -d '\r')"
            case "$mode" in
                defer|coop|single|basic)
                    CSQTT_URING_SELECTED_MODE="$mode"
                    break
                    ;;
            esac
        fi
        last_output="$output"
    done

    if [ -z "$CSQTT_URING_SELECTED_MODE" ]; then
        printf '%s\n' "$last_output" >>"$LOG_FILE"
        die "io_uring setup/enter/CQE не работает. Возможны seccomp, LSM или запрет провайдера"
    fi
    log_info "io_uring setup/enter/CQE работает; выбран совместимый режим: $CSQTT_URING_SELECTED_MODE"
}

run_platform_preflight() {
    prog 0.35 "Совместимость ядра..."
    log_step "Проверка совместимости ядра и VPS..."
    check_kernel_compatibility
    probe_tun_support
    # Netfilter проверяется ниже реальными INPUT/FORWARD/NAT/mangle правилами.
    # Отдельный create/delete probe дублировал работу и замедлял nft backend.
    probe_io_uring_support
}

setup_csqtt_docker() {
    prog 0.75 "Docker-образ..."
    ensure_tun_device
    mkdir -p "$CSQTT_DOCKER_DIR"
    chmod 700 "$CSQTT_DOCKER_DIR"
    install -m 0755 /usr/local/bin/csqtt "$CSQTT_DOCKER_DIR/csqtt"

    cat > "$CSQTT_DOCKER_DIR/Dockerfile" << 'DOCKERFILE'
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables procps && rm -rf /var/lib/apt/lists/*
COPY csqtt /usr/local/bin/csqtt
RUN chmod 0755 /usr/local/bin/csqtt
ENTRYPOINT ["/usr/local/bin/csqtt"]
DOCKERFILE

    docker build -t "$CSQTT_DOCKER_IMAGE" "$CSQTT_DOCKER_DIR" >>"$LOG_FILE" 2>&1 || \
        die "Сборка Docker-образа CSQTT завершилась ошибкой"
    probe_docker_runtime
    log_info "Docker-образ $CSQTT_DOCKER_IMAGE собран"
}

probe_docker_runtime() {
    local probe_iface="cqtd$(( $$ % 100000 ))" probe_chain="CSQTT_D$(( $$ % 1000000 ))" output
    if ! output="$(docker run --rm \
        --network host \
        --privileged \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --device /dev/net/tun:/dev/net/tun \
        --security-opt seccomp=unconfined \
        --env "PROBE_IFACE=$probe_iface" \
        --env "PROBE_CHAIN=$probe_chain" \
        --env "CSQTT_URING_MODE=$CSQTT_URING_SELECTED_MODE" \
        --entrypoint /bin/sh \
        "$CSQTT_DOCKER_IMAGE" -ec '
mode=$(/usr/local/bin/csqtt --io-uring-probe)
case "$mode" in defer|coop|single|basic) ;; *) exit 41 ;; esac
ip tuntap add dev "$PROBE_IFACE" mode tun
ip link del "$PROBE_IFACE"
for table in filter nat mangle; do
    iptables -w 2 -t "$table" -N "$PROBE_CHAIN"
    iptables -w 2 -t "$table" -X "$PROBE_CHAIN"
done
printf "%s\n" "$mode"
' 2>&1)"; then
        printf '%s\n' "$output" >>"$LOG_FILE"
        die "Docker не прошёл рабочую проверку io_uring, TUN или netfilter"
    fi
    printf '%s\n' "$output" >>"$LOG_FILE"
    log_info "Docker runtime проверен: TUN/netfilter/io_uring=$CSQTT_URING_SELECTED_MODE"
}

start_csqtt_docker() {
    prog 0.90 "Запуск Docker..."
    ensure_tun_device
    touch /run/xtables.lock
    timeout 3 docker rm -f "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1 || true
    log_warn "Docker-контейнер CSQTT запускается с privileged-доступом к ядру и устройствам VPS"

    docker run -d \
        --name "$CSQTT_DOCKER_CONTAINER" \
        --restart unless-stopped \
        --network host \
        --privileged \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --device /dev/net/tun:/dev/net/tun \
        --security-opt seccomp=unconfined \
        --stop-timeout 5 \
        --ulimit nofile=65535:65535 \
        --env-file "$CSQTT_ENV_FILE" \
        --env "CSQTT_URING_MODE=$CSQTT_URING_SELECTED_MODE" \
        --env CSQTT_SERVICE_MANAGER=docker \
        --volume "$CSQTT_CONFIG_DIR:$CSQTT_CONFIG_DIR" \
        --volume /run/xtables.lock:/run/xtables.lock \
        "$CSQTT_DOCKER_IMAGE" \
        --listen "0.0.0.0:${PEER_PORT}" \
        --web-port "$WEB_PORT" \
        --config-dir "$CSQTT_CONFIG_DIR" >>"$LOG_FILE" 2>&1 || \
        die "Не удалось создать Docker-контейнер CSQTT"

    local state running main_pid restarts candidate_pid=0 candidate_restarts=0 found=0
    local attempts=0
    while [ "$attempts" -lt 48 ]; do
        attempts=$((attempts + 1))
        state="$(docker inspect --format '{{.State.Running}}|{{.State.Pid}}|{{.RestartCount}}' "$CSQTT_DOCKER_CONTAINER" 2>/dev/null || echo 'false|0|-1')"
        IFS='|' read -r running main_pid restarts <<< "$state"
        case "$main_pid" in ''|*[!0-9]*) main_pid=0 ;; esac
        case "$restarts" in ''|*[!0-9]*) restarts=-1 ;; esac
        if [ "$running" = "true" ] && [ "$main_pid" -gt 1 ] && ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
            candidate_pid="$main_pid"
            candidate_restarts="$restarts"
            found=1
            break
        fi
        sleep 0.25
    done

    if [ "$found" -ne 1 ]; then
        docker logs --tail 50 "$CSQTT_DOCKER_CONTAINER" 2>&1 | sed 's/^/   >> /' || true
        die "Docker CSQTT не запустился или TUN $CSQTT_IFACE не создан"
    fi

    sleep "$START_STABILITY_SECONDS"
    state="$(docker inspect --format '{{.State.Running}}|{{.State.Pid}}|{{.RestartCount}}' "$CSQTT_DOCKER_CONTAINER" 2>/dev/null || echo 'false|0|-1')"
    IFS='|' read -r running main_pid restarts <<< "$state"
    if [ "$running" != "true" ] || [ "$main_pid" != "$candidate_pid" ] || [ "$restarts" != "$candidate_restarts" ] || \
       ! ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        docker logs --tail 50 "$CSQTT_DOCKER_CONTAINER" 2>&1 | sed 's/^/   >> /' || true
        die "Docker CSQTT вошёл в crash-loop во время стабильной проверки"
    fi

    verify_configured_network
    prog 1.0 "Готово!"
    echo ""
    echo "✓ Деплой успешно завершён"
    echo "CSQTT_DEPLOY_OK"
    echo "   Режим:      Docker"
    echo "   Бинарник:   /usr/local/bin/csqtt"
    echo "   Dockerfile: ${CSQTT_DOCKER_DIR}/Dockerfile"
    echo "   Конфиг:     ${CSQTT_CONFIG_DIR}"
    echo "   Контейнер:  ${CSQTT_DOCKER_CONTAINER}"
    echo "   Образ:      ${CSQTT_DOCKER_IMAGE}"
    echo "   PEER:       порт ${PEER_PORT}"
    echo "   SSH:        порт ${SSH_PORT}"
    echo "   WEB:        порт ${WEB_PORT}"
    echo "   io_uring:   ${CSQTT_URING_SELECTED_MODE} (PID ${candidate_pid})"
    echo "   Логи:       docker logs -f ${CSQTT_DOCKER_CONTAINER}"
    echo "   Статус:     docker ps --filter name=${CSQTT_DOCKER_CONTAINER}"
    echo ""
}

setup_csqtt_service() {
    prog 0.75 "Сервис..."
    echo "🔧 Создание systemd-сервиса CSQTT..."

    local unit_tmp
    unit_tmp="$(mktemp)"
    cat > "$unit_tmp" << CSQTTSVC
[Unit]
Description=CSQTT VPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=20
StartLimitBurst=5

[Service]
Type=simple
EnvironmentFile=-${CSQTT_ENV_FILE}
Environment=CSQTT_SERVICE_MANAGER=systemd
ExecStartPre=-/usr/bin/env bash -c "ip link show ${CSQTT_IFACE} >/dev/null 2>&1 && ip link del ${CSQTT_IFACE} 2>/dev/null || true"
ExecStartPre=/usr/local/lib/csqtt/network-up.sh
ExecStart=/usr/local/bin/csqtt --listen 0.0.0.0:${PEER_PORT} --web-port ${WEB_PORT} --config-dir ${CSQTT_CONFIG_DIR}
Restart=on-failure
RestartSec=1
KillMode=control-group
TimeoutStartSec=30
TimeoutStopSec=5
LimitNOFILE=65535
TasksMax=infinity

[Install]
WantedBy=multi-user.target
CSQTTSVC

    if [ ! -f /etc/systemd/system/csqtt.service ] || ! cmp -s "$unit_tmp" /etc/systemd/system/csqtt.service; then
        install -m 0644 "$unit_tmp" /etc/systemd/system/csqtt.service
        SYSTEMD_NEEDS_RELOAD=1
    fi
    rm -f "$unit_tmp"

    if [ "$SYSTEMD_NEEDS_RELOAD" -eq 1 ]; then
        systemctl daemon-reload || die "systemctl daemon-reload завершился ошибкой"
        SYSTEMD_NEEDS_RELOAD=0
    fi

    mkdir -p /etc/systemd/system/multi-user.target.wants
    ln -sfn /etc/systemd/system/csqtt.service /etc/systemd/system/multi-user.target.wants/csqtt.service
    echo "✓ Сервис csqtt.service создан и включён"
}

diagnose_systemd_failure() {
    local props result="unknown" exec_code="unknown" exec_status="unknown" restarts="unknown" active="unknown" sub="unknown" pid="0"
    props="$(systemctl show csqtt -p Result -p ExecMainCode -p ExecMainStatus -p NRestarts -p ActiveState -p SubState -p MainPID 2>/dev/null || true)"
    while IFS='=' read -r key value; do
        case "$key" in
            Result) result="$value" ;; ExecMainCode) exec_code="$value" ;; ExecMainStatus) exec_status="$value" ;;
            NRestarts) restarts="$value" ;; ActiveState) active="$value" ;; SubState) sub="$value" ;; MainPID) pid="$value" ;;
        esac
    done <<< "$props"
    log_error "systemd: active=$active/$sub result=$result code=$exec_code status=$exec_status restarts=$restarts pid=$pid"
    journalctl -u csqtt -b -n 50 --no-pager 2>/dev/null | sed 's/^/   >> /' | tee -a "$LOG_FILE" || true
}

start_csqtt() {
    if [ "$DEPLOY_MODE" = "docker" ]; then
        start_csqtt_docker
        return
    fi
    prog 0.90 "Запуск..."
    echo "🚀 Запуск CSQTT VPN Server..."

    [ -x /usr/local/bin/csqtt ] || die "Исполняемый файл /usr/local/bin/csqtt не установлен"

    # cleanup уже остановил старый runtime. Блокирующего systemctl stop здесь нет.
    if ! systemctl start csqtt; then
        # start-limit-hit после старого crash-loop: reset только по необходимости.
        systemctl reset-failed csqtt >/dev/null 2>&1 || true
        if ! systemctl start csqtt; then
            diagnose_systemd_failure
            die "systemctl start csqtt завершился ошибкой"
        fi
    fi

    local props key value active sub main_pid restarts
    local candidate_pid=0 candidate_restarts=0 attempts=0 found=0
    # Обычный успешный путь занимает несколько сотен мс; 12с — только аварийный потолок.
    while [ "$attempts" -lt 48 ]; do
        attempts=$((attempts + 1))
        active=""; sub=""; main_pid=0; restarts=0
        props="$(systemctl show csqtt -p ActiveState -p SubState -p MainPID -p NRestarts 2>/dev/null || true)"
        while IFS='=' read -r key value; do
            case "$key" in
                ActiveState) active="$value" ;; SubState) sub="$value" ;; MainPID) main_pid="$value" ;; NRestarts) restarts="$value" ;;
            esac
        done <<< "$props"
        case "$main_pid" in ''|*[!0-9]*) main_pid=0 ;; esac
        case "$restarts" in ''|*[!0-9]*) restarts=0 ;; esac

        if [ "$active" = "active" ] && [ "$sub" = "running" ] && [ "$main_pid" -gt 1 ] && \
           kill -0 "$main_pid" 2>/dev/null && ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
            candidate_pid="$main_pid"
            candidate_restarts="$restarts"
            found=1
            break
        fi
        sleep 0.25
    done

    if [ "$found" -ne 1 ]; then
        diagnose_systemd_failure
        die "CSQTT не запустился: сервис не running или TUN $CSQTT_IFACE не создан"
    fi

    # Короткое окно ловит прежний immediate signal/crash-loop без фиксированных 5 секунд.
    sleep "$START_STABILITY_SECONDS"
    active=""; sub=""; main_pid=0; restarts=0
    props="$(systemctl show csqtt -p ActiveState -p SubState -p MainPID -p NRestarts 2>/dev/null || true)"
    while IFS='=' read -r key value; do
        case "$key" in
            ActiveState) active="$value" ;; SubState) sub="$value" ;; MainPID) main_pid="$value" ;; NRestarts) restarts="$value" ;;
        esac
    done <<< "$props"
    case "$main_pid" in ''|*[!0-9]*) main_pid=0 ;; esac
    case "$restarts" in ''|*[!0-9]*) restarts=0 ;; esac

    if [ "$active" != "active" ] || [ "$sub" != "running" ] || [ "$main_pid" != "$candidate_pid" ] || \
       [ "$restarts" != "$candidate_restarts" ] || ! kill -0 "$candidate_pid" 2>/dev/null || \
       ! ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        diagnose_systemd_failure
        die "CSQTT вошёл в crash-loop или потерял TUN во время стабильной проверки"
    fi

    verify_configured_network
    [ "$restarts" -eq 0 ] || log_warn "Во время старта csqtt перезапустился $restarts раз(а), затем стабилизировался"
    log_info "CSQTT сервер подтверждён: PID $candidate_pid, интерфейс $CSQTT_IFACE активен"

    prog 1.0 "Готово!"
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "✓ Деплой успешно завершён"
    echo "CSQTT_DEPLOY_OK"
    echo "   Режим: systemd"
    echo "   Бинарник: /usr/local/bin/csqtt"
    echo "   Unit: /etc/systemd/system/csqtt.service"
    echo "   Конфиг: ${CSQTT_CONFIG_DIR}"
    echo "   NAT:  MASQUERADE (восстанавливается после reboot)"
    echo "   PEER: порт ${PEER_PORT}"
    echo "   SSH:  порт ${SSH_PORT}"
    echo "   WEB:  порт ${WEB_PORT}"
    echo "   io_uring: ${CSQTT_URING_SELECTED_MODE} (PID ${candidate_pid})"
    echo "   Логи:   journalctl -u csqtt -f"
    echo "   Статус: systemctl status csqtt"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
}

do_uninstall() {
    log_step "Удаление CSQTT..."

    if command -v docker >/dev/null 2>&1; then
        timeout 3 docker rm -f "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1 || true
        timeout 5 docker image rm "$CSQTT_DOCKER_IMAGE" >/dev/null 2>&1 || true
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop csqtt --no-block >/dev/null 2>&1 || true
        timeout 2 systemctl kill --kill-who=all --signal=SIGKILL csqtt >/dev/null 2>&1 || true
        systemctl disable csqtt >/dev/null 2>&1 || true
    fi
    pkill -9 -x csqtt >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/csqtt.service
    rm -rf /etc/systemd/system/csqtt.service.d
    rm -f /etc/systemd/system/multi-user.target.wants/csqtt.service
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true

    rm -f "$NETWORK_READY_STAMP" 2>/dev/null || true
    if ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        timeout 2 ip link del "$CSQTT_IFACE" 2>/dev/null || true
    fi
    cleanup_legacy_proxy_interfaces
    cleanup_csqtt_proxy_policy
    cleanup_csqtt_netfilter_rules

    rm -f /usr/local/bin/csqtt /usr/local/bin/csqtt-cascade
    rm -f /usr/local/bin/hev-socks5-tunnel /usr/local/bin/hev-socks5-server
    rm -rf /run/csqtt /usr/local/lib/csqtt /var/lib/csqtt
    cleanup_config_dir_keep_access_db
    find "$CSQTT_CONFIG_DIR" -mindepth 1 -maxdepth 1 ! -name "$CSQTT_ACCESS_DB" -exec rm -rf {} + 2>/dev/null || true
    rm -f "$CSQTT_SYSCTL_FILE" "$CSQTT_UDP_SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    log_info "CSQTT удалён. База доступа сохранена: ${CSQTT_CONFIG_DIR}/${CSQTT_ACCESS_DB}"
}

do_status() {
    echo "Статус CSQTT:"
    echo ""
    if command -v docker >/dev/null 2>&1 && docker inspect "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1; then
        if [ "$(docker inspect --format '{{.State.Running}}' "$CSQTT_DOCKER_CONTAINER" 2>/dev/null)" = "true" ]; then
            log_info "Docker-контейнер: АКТИВЕН"
        else
            log_warn "Docker-контейнер: НЕ АКТИВЕН"
        fi
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active csqtt &>/dev/null; then
        log_info "Сервис: АКТИВЕН"
    else
        log_warn "Сервис: НЕ АКТИВЕН"
    fi
    if [ -f /usr/local/bin/csqtt ]; then
        log_info "Бинарник: установлен"
    else
        log_warn "Бинарник: НЕ найден"
    fi
    if ip link show "$CSQTT_IFACE" &>/dev/null; then
        log_info "CSQTT интерфейс ($CSQTT_IFACE): активен"
    else
        log_warn "CSQTT интерфейс ($CSQTT_IFACE): не активен"
    fi
}

main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       CSQTT VPN Server — Installer v${SCRIPT_VERSION}                    ║"
    echo "║       PEER: ${PEER_PORT}  |  SSH: ${SSH_PORT}  | WEB: ${WEB_PORT}       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"

    local action="${1:-install}"
    check_root
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== CSQTT Installer v${SCRIPT_VERSION} — $(date) ===" >> "$LOG_FILE"

    case "$action" in
        status|--status|-s)       do_status ;;
        uninstall|--uninstall|-u)
            validate_port "CSQTT_PEER_PORT" "$PEER_PORT"
            do_uninstall
            ;;
        install|--install|-i|*)
            case "$DEPLOY_MODE" in
                systemd|docker) ;;
                *) die "CSQTT_DEPLOY_MODE должен быть systemd или docker" ;;
            esac
            validate_port "CSQTT_PEER_PORT" "$PEER_PORT"
            validate_port "CSQTT_SSH_PORT" "$SSH_PORT"
            validate_port "CSQTT_WEB_PORT" "$WEB_PORT"

            local total_started=$SECONDS
            detect_os
            run_timed "зависимости" install_prerequisites
            require_runtime_tools
            if [ "$DEPLOY_MODE" = "docker" ]; then
                prog 0.12 "Docker..."
                run_timed "Docker" ensure_docker
            fi
            run_timed "очистка" csqtt_cleanup
            run_timed "sysctl" setup_sysctl
            run_timed "бинарник" setup_csqtt_binary
            run_timed "preflight" run_platform_preflight
            detect_firewall
            run_timed "NAT/firewall" setup_nat_and_firewall
            install_network_helper
            setup_csqtt_environment
            persist_runtime_compatibility_env
            if [ "$DEPLOY_MODE" = "docker" ]; then
                run_timed "Docker image" setup_csqtt_docker
            else
                run_timed "systemd unit" setup_csqtt_service
            fi
            run_timed "запуск" start_csqtt
            log_info "Общее время deploy.sh: $((SECONDS - total_started))с"
            ;;
    esac
}

main "$@"
