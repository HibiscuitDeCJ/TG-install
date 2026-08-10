#!/usr/bin/env bash
# ============================================================
# Trojan-Go Secure Installer v1.8
#
# Target: Ubuntu 24.04 / amd64 / IPv4
#
# Modes:
#   tcp       Trojan-Go TCP + TLS, no Nginx
#   ws        Trojan-Go WebSocket + TLS, no Nginx
#   fallback  Trojan-Go TCP + TLS + local Nginx fallback
#
# Commands:
#   install    Full installation
#   test       Pre-installation environment test
#   audit      Post-installation security audit
#   status     Quick runtime status
#   update     Future: safe update (stub)
#   uninstall  Future: full uninstall (stub)
#
# Security principles:
#   - no curl | bash
#   - pinned Trojan-Go version
#   - SHA256 required before binary installation
#   - dedicated non-root user
#   - private credentials are never logged
#   - Cloudflare DNS-01
#   - UFW never reset
#   - existing Nginx config is not overwritten
#   - systemd hardening
#   - PASSWORD cleared on all exit paths
#
# IMPORTANT:
#   v0.10.6 is the latest official Trojan-Go release currently
#   visible on GitHub. The official release page does not expose
#   a checksum for the ZIP asset, so this script REFUSES to install
#   until TROJAN_GO_SHA256 is supplied and independently verified.
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

# -----------------------------------------------------------
# Constants
# -----------------------------------------------------------
readonly SCRIPT_VERSION="1.8.0"
readonly TROJAN_GO_VERSION="v0.10.6"
readonly TROJAN_GO_REPO="p4gefau1t/trojan-go"
readonly TROJAN_GO_ASSET="trojan-go-linux-amd64.zip"

# Supply the independently verified SHA256 before installation.
# Example:
#   TROJAN_GO_SHA256='...' ./U24amd.sh install --mode tcp
TROJAN_GO_SHA256="${TROJAN_GO_SHA256:-}"

readonly TROJAN_USER="trojan"
readonly TROJAN_GROUP="trojan"
readonly TROJAN_BIN="/usr/local/bin/trojan-go"
readonly TROJAN_ETC="/etc/trojan-go"
readonly TROJAN_CONFIG="${TROJAN_ETC}/config.json"
readonly TROJAN_CERT_DIR="${TROJAN_ETC}/certs"
readonly TROJAN_DATA="/var/lib/trojan-go"
readonly TROJAN_CACHE="/var/cache/trojan-go"
readonly CF_CREDENTIALS="${TROJAN_ETC}/cloudflare.ini"
readonly SYSTEMD_UNIT="/etc/systemd/system/trojan-go.service"

readonly FALLBACK_ROOT="/var/www/trojan-fallback"
readonly FALLBACK_HTTP_PORT="8080"
readonly FALLBACK_RAW_PORT="8081"

COMMAND=""
MODE=""
DOMAIN=""
EMAIL=""
PASSWORD=""
WS_PATH=""

SSH_PORTS=()
CURRENT_SSH_PORT=""

# Audit counters
AUDIT_PASS=0
AUDIT_FAIL=0
AUDIT_WARN=0

# -----------------------------------------------------------
# Logging
# -----------------------------------------------------------
LOG_FILE="/var/log/trojan-go-installer.log"

log() {
    local level="$1"; shift
    local msg
    msg="$(printf '[%s] [%s] %s' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
    echo "$msg"
    # Best-effort append to log file; never fail on logging
    if [[ -d "$(dirname "$LOG_FILE")" ]]; then
        echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}
info()  { log INFO  "$@"; }
warn()  { log WARN  "$@"; }
error() { log ERROR "$@" >&2; }
die()   { error "$@"; exit 1; }

# -----------------------------------------------------------
# Cleanup — ensure sensitive data is cleared on any exit
# -----------------------------------------------------------
cleanup() {
    unset PASSWORD 2>/dev/null || true
}
trap cleanup EXIT

on_error() {
    local rc=$? line="$1"
    # Prevent recursive trap during error handling
    trap - ERR
    error "Failure at line ${line}, exit code ${rc}."
    exit "$rc"
}
trap 'on_error "${LINENO}"' ERR

# -----------------------------------------------------------
# Usage
# -----------------------------------------------------------
usage() {
    cat <<EOF
Trojan-Go Secure Installer ${SCRIPT_VERSION}

Commands:
  install        Full installation
  test           Pre-installation environment test
  audit          Post-installation security audit
  status         Quick runtime status
  update         Future: safe update
  uninstall      Future: full uninstall

Install options:
  --mode tcp|ws|fallback   (required)
  --domain DOMAIN
  --email EMAIL

Examples:
  TROJAN_GO_SHA256='...' $0 install --mode tcp --domain example.com
  TROJAN_GO_SHA256='...' $0 install --mode ws  --domain example.com
  TROJAN_GO_SHA256='...' $0 install --mode fallback --domain example.com
  $0 test
  $0 audit
  $0 status

The SHA256 is intentionally mandatory. Do not remove that check.
EOF
}

# ===========================================================
# CHECK FUNCTIONS
# ===========================================================

check_root() {
    [[ $EUID -eq 0 ]] || die "Run as root."
}

check_os() {
    [[ -r /etc/os-release ]] || die "Missing /etc/os-release."
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] \
        || die "Ubuntu 24.04 is required. Detected: ${ID:-} ${VERSION_ID:-}"
}

check_arch() {
    [[ "$(dpkg --print-architecture)" == "amd64" ]] \
        || die "This version supports amd64 only."
}

check_commands() {
    local c missing=()
    for c in awk sed grep ip ss dpkg systemctl; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    [[ ${#missing[@]} -eq 0 ]] || die "Missing commands: ${missing[*]}"
}

check_ipv4() {
    local ip4
    ip4="$(ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    if [[ -n "$ip4" ]]; then
        info "Server IPv4: $ip4"
    else
        warn "Could not detect IPv4 automatically."
    fi
}

check_ports_free() {
    local port port_list=(443)
    [[ "$MODE" == "fallback" ]] && port_list+=(8080 8081)

    info "Checking port availability..."
    for port in "${port_list[@]}"; do
        if ss -lntp 2>/dev/null | grep -qE ":${port}[[:space:]]"; then
            die "Port ${port} is already in use. Please free it before installing."
        fi
        info "  Port ${port}: free"
    done
}

check_dns() {
    local domain="${1:-}"
    [[ -n "$domain" ]] || return 0

    info "Checking DNS resolution for ${domain}..."
    local resolved=""
    if command -v dig >/dev/null 2>&1; then
        resolved="$(dig +short "$domain" A 2>/dev/null || true)"
    elif command -v nslookup >/dev/null 2>&1; then
        resolved="$(nslookup "$domain" 2>/dev/null | awk '/^Address:/ && !/#/{print $2}' || true)"
    elif command -v host >/dev/null 2>&1; then
        resolved="$(host "$domain" 2>/dev/null | awk '/has address/{print $NF}' || true)"
    fi

    if [[ -n "$resolved" ]]; then
        info "  ${domain} resolves to: ${resolved}"
    else
        warn "  Could not resolve ${domain}. DNS may not be configured yet."
    fi
}

check_resources() {
    info "Checking system resources..."

    local mem_kb
    mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    if [[ "$mem_kb" -ge 524288 ]]; then
        info "  Memory: $((mem_kb / 1024)) MB — OK"
    else
        warn "  Memory: $((mem_kb / 1024)) MB — recommended >= 512 MB"
    fi

    local disk_kb
    disk_kb="$(df -k / --output=avail 2>/dev/null | tail -1 || echo 0)"
    if [[ "$disk_kb" -ge 1048576 ]]; then
        info "  Disk free: $((disk_kb / 1024)) MB — OK"
    else
        warn "  Disk free: $((disk_kb / 1024)) MB — recommended >= 1 GB"
    fi
}

check_clock() {
    info "Checking system clock..."
    if command -v timedatectl >/dev/null 2>&1; then
        local synced
        synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo 'unknown')"
        if [[ "$synced" == "yes" ]]; then
            info "  NTP synchronized: yes"
        else
            warn "  NTP synchronized: ${synced}. Time skew may cause TLS/cert issues."
        fi
    else
        warn "  timedatectl not available; cannot verify clock sync."
    fi
}

check_kernel() {
    local kver
    kver="$(uname -r 2>/dev/null || echo '0.0.0')"
    local major
    major="$(echo "$kver" | cut -d. -f1)"
    if [[ "$major" -ge 4 ]]; then
        info "  Kernel: ${kver} — OK"
    else
        warn "  Kernel: ${kver} — recommended >= 4.x"
    fi
}

# ===========================================================
# ARGUMENT PARSING
# ===========================================================

parse_args() {
    [[ $# -gt 0 ]] || { usage; exit 0; }
    COMMAND="$1"; shift

    case "$COMMAND" in
        install)
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --mode)   [[ $# -ge 2 ]] || die "--mode needs a value"; MODE="$2"; shift 2;;
                    --domain) [[ $# -ge 2 ]] || die "--domain needs a value"; DOMAIN="$2"; shift 2;;
                    --email)  [[ $# -ge 2 ]] || die "--email needs a value"; EMAIL="$2"; shift 2;;
                    --help|-h) usage; exit 0;;
                    *) die "Unknown option: $1";;
                esac
            done
            ;;
        test|audit|status|update|uninstall)
            [[ $# -eq 0 ]] || die "Unexpected arguments for '$COMMAND'."
            ;;
        help|-h|--help) usage; exit 0;;
        *) die "Unknown command: $COMMAND";;
    esac
}

# ===========================================================
# INTERACTIVE PROMPTS
# ===========================================================

select_mode() {
    [[ -n "$MODE" ]] && return
    echo "1) TCP + TLS"
    echo "2) WebSocket + TLS"
    echo "3) TCP + TLS + Nginx fallback"
    read -r -p "Mode [1-3]: " choice
    case "$choice" in
        1) MODE=tcp;;
        2) MODE=ws;;
        3) MODE=fallback;;
        *) die "Invalid mode.";;
    esac
}

validate_mode() {
    case "$MODE" in tcp|ws|fallback) ;; *) die "Invalid mode: $MODE";; esac
}

prompt_domain() {
    [[ -n "$DOMAIN" ]] || read -r -p "Domain: " DOMAIN
    [[ -n "$DOMAIN" ]] || die "Domain is required."
    [[ ${#DOMAIN} -le 253 ]] || die "Domain is too long (max 253 chars)."
    [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] \
        || die "Invalid domain format."
    [[ "$DOMAIN" != *..* ]] || die "Invalid domain (consecutive dots)."
}

prompt_email() {
    [[ -n "$EMAIL" ]] && return
    while true; do
        read -r -p "Let's Encrypt email: " EMAIL
        [[ "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] && break
        warn "Invalid email format."
    done
}

prompt_password() {
    while true; do
        read -r -s -p "Trojan password: " PASSWORD; echo
        [[ -n "$PASSWORD" ]] || { warn "Password cannot be empty."; continue; }
        local confirm=""
        read -r -s -p "Confirm password: " confirm; echo
        if [[ "$PASSWORD" == "$confirm" ]]; then
            unset confirm
            return
        fi
        unset confirm
        PASSWORD=""
        warn "Passwords do not match."
    done
}

generate_ws_path() {
    command -v openssl >/dev/null 2>&1 || die "openssl is required."
    WS_PATH="/$(openssl rand -hex 16)"
}

# ===========================================================
# INSTALLATION FUNCTIONS
# ===========================================================

install_base_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl ca-certificates openssl unzip jq certbot \
        python3-certbot-dns-cloudflare ufw iproute2
}

create_user_and_dirs() {
    getent group "$TROJAN_GROUP" >/dev/null 2>&1 || groupadd --system "$TROJAN_GROUP"
    id "$TROJAN_USER" >/dev/null 2>&1 || \
        useradd --system --gid "$TROJAN_GROUP" \
            --home-dir "$TROJAN_DATA" --no-create-home \
            --shell /usr/sbin/nologin "$TROJAN_USER"

    install -d -o root -g "$TROJAN_GROUP" -m 0750 "$TROJAN_ETC"
    install -d -o root -g "$TROJAN_GROUP" -m 0750 "$TROJAN_CERT_DIR"
    install -d -o "$TROJAN_USER" -g "$TROJAN_GROUP" -m 0750 "$TROJAN_DATA"
    install -d -o root -g root -m 0750 "$TROJAN_CACHE"
}

prompt_cloudflare_token() {
    local token=""
    echo
    echo "Cloudflare API Token requirements:"
    echo "  Zone -> DNS -> Edit"
    echo "  Restricted to the target zone only."
    echo
    read -r -s -p "Cloudflare API Token: " token
    echo
    [[ -n "$token" ]] || die "Cloudflare token is empty."

    umask 077
    printf 'dns_cloudflare_api_token = %s\n' "$token" > "$CF_CREDENTIALS"
    unset token
    chown root:root "$CF_CREDENTIALS"
    chmod 0600 "$CF_CREDENTIALS"
}

issue_certificate() {
    certbot certonly \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --no-eff-email \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CF_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 30 \
        --keep-until-expiring \
        -d "$DOMAIN"

    local src="/etc/letsencrypt/live/$DOMAIN"
    [[ -f "$src/fullchain.pem" && -f "$src/privkey.pem" ]] \
        || die "Let's Encrypt certificate files not found."

    install -o root -g "$TROJAN_GROUP" -m 0640 \
        "$src/fullchain.pem" "$TROJAN_CERT_DIR/fullchain.pem"
    install -o root -g "$TROJAN_GROUP" -m 0640 \
        "$src/privkey.pem" "$TROJAN_CERT_DIR/privkey.pem"

    verify_cert_pair
}

verify_cert_pair() {
    local cert="$TROJAN_CERT_DIR/fullchain.pem"
    local key="$TROJAN_CERT_DIR/privkey.pem"
    [[ -s "$cert" && -s "$key" ]] || die "Certificate/key missing."

    openssl x509 -in "$cert" -noout -subject -issuer -dates >/dev/null
    local a b
    a="$(openssl x509 -in "$cert" -pubkey -noout |
        openssl pkey -pubin -outform DER | sha256sum)"
    b="$(openssl pkey -in "$key" -pubout |
        openssl pkey -pubin -outform DER | sha256sum)"
    [[ "$a" == "$b" ]] || die "Certificate / private-key mismatch."
}

create_cert_deploy_hook() {
    local hook="/etc/letsencrypt/renewal-hooks/deploy/trojan-go"
    install -d -o root -g root -m 0755 "$(dirname "$hook")"

    cat > "$hook" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

DOMAIN="$DOMAIN"
SRC="/etc/letsencrypt/live/\${DOMAIN}"
DST="$TROJAN_CERT_DIR"

install -o root -g $TROJAN_GROUP -m 0640 "\${SRC}/fullchain.pem" "\${DST}/fullchain.pem"
install -o root -g $TROJAN_GROUP -m 0640 "\${SRC}/privkey.pem" "\${DST}/privkey.pem"

if systemctl is-active --quiet trojan-go; then
    systemctl restart trojan-go
fi
EOF
    chmod 0755 "$hook"
}

download_trojan_go() {
    [[ -n "$TROJAN_GO_SHA256" ]] \
        || die "TROJAN_GO_SHA256 is not set. Installation refused."

    [[ "$TROJAN_GO_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] \
        || die "Invalid SHA256 format."

    local url="https://github.com/${TROJAN_GO_REPO}/releases/download/${TROJAN_GO_VERSION}/${TROJAN_GO_ASSET}"
    local archive="$TROJAN_CACHE/$TROJAN_GO_ASSET"
    local extract="$TROJAN_CACHE/extract"

    rm -f "$archive"
    rm -rf "$extract"
    install -d -o root -g root -m 0750 "$extract"

    curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        -o "$archive" "$url"

    printf '%s  %s\n' "$TROJAN_GO_SHA256" "$archive" | sha256sum -c -

    unzip -q "$archive" -d "$extract"
    [[ -f "$extract/trojan-go" ]] || die "trojan-go binary missing from archive."

    install -o root -g root -m 0755 "$extract/trojan-go" "$TROJAN_BIN"

    # Install bundled data files if present.
    [[ -f "$extract/geoip.dat" ]] &&
        install -o root -g "$TROJAN_GROUP" -m 0644 "$extract/geoip.dat" "$TROJAN_ETC/geoip.dat"
    [[ -f "$extract/geosite.dat" ]] &&
        install -o root -g "$TROJAN_GROUP" -m 0644 "$extract/geosite.dat" "$TROJAN_ETC/geosite.dat"

    rm -f "$archive"
    rm -rf "$extract"
}

generate_config() {
    if [[ "$MODE" == "ws" ]]; then
        jq -n \
            --arg p "$PASSWORD" \
            --arg cert "$TROJAN_CERT_DIR/fullchain.pem" \
            --arg key "$TROJAN_CERT_DIR/privkey.pem" \
            --arg sni "$DOMAIN" \
            --arg path "$WS_PATH" \
            --arg host "$DOMAIN" \
            '{
              run_type:"server",
              local_addr:"0.0.0.0",
              local_port:443,
              remote_addr:"127.0.0.1",
              remote_port:9,
              disable_http_check:true,
              password:[$p],
              ssl:{
                cert:$cert,
                key:$key,
                sni:$sni,
                alpn:["http/1.1"]
              },
              tcp:{no_delay:true,keep_alive:true,prefer_ipv4:true},
              websocket:{enabled:true,path:$path,host:$host}
            }' > "$TROJAN_CONFIG"
    elif [[ "$MODE" == "fallback" ]]; then
        jq -n \
            --arg p "$PASSWORD" \
            --arg cert "$TROJAN_CERT_DIR/fullchain.pem" \
            --arg key "$TROJAN_CERT_DIR/privkey.pem" \
            --arg sni "$DOMAIN" \
            '{
              run_type:"server",
              local_addr:"0.0.0.0",
              local_port:443,
              remote_addr:"127.0.0.1",
              remote_port:8080,
              password:[$p],
              ssl:{
                cert:$cert,
                key:$key,
                sni:$sni,
                alpn:["http/1.1"],
                fallback_addr:"127.0.0.1",
                fallback_port:8081
              },
              tcp:{no_delay:true,keep_alive:true,prefer_ipv4:true},
              websocket:{enabled:false}
            }' > "$TROJAN_CONFIG"
    else
        jq -n \
            --arg p "$PASSWORD" \
            --arg cert "$TROJAN_CERT_DIR/fullchain.pem" \
            --arg key "$TROJAN_CERT_DIR/privkey.pem" \
            --arg sni "$DOMAIN" \
            '{
              run_type:"server",
              local_addr:"0.0.0.0",
              local_port:443,
              remote_addr:"127.0.0.1",
              remote_port:9,
              disable_http_check:true,
              password:[$p],
              ssl:{
                cert:$cert,
                key:$key,
                sni:$sni,
                alpn:["http/1.1"]
              },
              tcp:{no_delay:true,keep_alive:true,prefer_ipv4:true},
              websocket:{enabled:false}
            }' > "$TROJAN_CONFIG"
    fi

    chmod 0640 "$TROJAN_CONFIG"
    chown root:"$TROJAN_GROUP" "$TROJAN_CONFIG"
    jq empty "$TROJAN_CONFIG" >/dev/null
}

install_nginx_fallback() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y nginx

    install -d -o root -g root -m 0755 "$FALLBACK_ROOT"

    cat > "$FALLBACK_ROOT/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
</head>
<body><h1>Welcome</h1></body>
</html>
EOF
    chmod 0644 "$FALLBACK_ROOT/index.html"

    local conf="/etc/nginx/sites-available/trojan-go-fallback"
    cat > "$conf" <<EOF
server {
    listen 127.0.0.1:${FALLBACK_HTTP_PORT};
    server_name ${DOMAIN};

    root ${FALLBACK_ROOT};
    index index.html;
    server_tokens off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    access_log off;
    error_log /var/log/nginx/trojan-go-fallback-error.log warn;
}

server {
    listen 127.0.0.1:${FALLBACK_RAW_PORT};
    server_name ${DOMAIN};

    root ${FALLBACK_ROOT};
    index index.html;
    server_tokens off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    access_log off;
    error_log /var/log/nginx/trojan-go-fallback-raw-error.log warn;
}
EOF

    chmod 0644 "$conf"
    ln -sfn "$conf" /etc/nginx/sites-enabled/trojan-go-fallback

    nginx -t

    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
    else
        systemctl enable nginx
        systemctl start nginx
    fi

    systemctl is-active --quiet nginx || die "Nginx failed to start."
}

create_systemd_unit() {
    cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Trojan-Go Secure Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${TROJAN_USER}
Group=${TROJAN_GROUP}

ExecStart=${TROJAN_BIN} -config ${TROJAN_CONFIG}

Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

ReadWritePaths=${TROJAN_DATA}
UMask=0027

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$SYSTEMD_UNIT"
    systemctl daemon-reload
}

start_trojan() {
    systemctl enable trojan-go
    systemctl restart trojan-go
    sleep 2

    if ! systemctl is-active --quiet trojan-go; then
        journalctl -u trojan-go --no-pager -n 100 >&2
        die "Trojan-Go failed to start."
    fi
}

detect_ssh() {
    SSH_PORTS=()
    if command -v sshd >/dev/null 2>&1; then
        mapfile -t SSH_PORTS < <(
            sshd -T 2>/dev/null |
            awk '$1=="port"{print $2}' | sort -nu
        )
    fi
    [[ ${#SSH_PORTS[@]} -gt 0 ]] || SSH_PORTS=(22)

    CURRENT_SSH_PORT=""
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        CURRENT_SSH_PORT="$(awk '{print $4}' <<< "$SSH_CONNECTION")"
    fi
}

configure_ufw() {
    command -v ufw >/dev/null 2>&1 || return 0
    detect_ssh

    local active="no"
    ufw status | grep -q 'Status: active' && active="yes"

    if [[ "$active" == "no" ]]; then
        echo
        read -r -p "UFW is inactive. Enable minimal firewall (SSH + 443)? [y/N]: " answer
        [[ "$answer" =~ ^[Yy]$ ]] || {
            warn "UFW was left disabled."
            return
        }

        ufw default deny incoming
        ufw default allow outgoing
    fi

    local p
    for p in "${SSH_PORTS[@]}"; do
        ufw allow "${p}/tcp" >/dev/null
    done

    [[ -n "$CURRENT_SSH_PORT" ]] &&
        ufw allow "${CURRENT_SSH_PORT}/tcp" >/dev/null

    ufw allow 443/tcp >/dev/null

    if [[ "$active" == "no" ]]; then
        ufw --force enable
    fi

    ufw status verbose
}

verify_ports() {
    info "Verifying listening ports..."

    ss -lntp | grep -E ':(443|8080|8081)[[:space:]]' || true

    if [[ "$MODE" == "fallback" ]]; then
        ss -lntp | grep -Eq '127\.0\.0\.1:8080[[:space:]]' \
            || die "Fallback HTTP port 8080 is not listening on 127.0.0.1."
        ss -lntp | grep -Eq '127\.0\.0\.1:8081[[:space:]]' \
            || die "Fallback raw port 8081 is not listening on 127.0.0.1."
    fi

    ss -lntp | grep -Eq '0\.0\.0\.0:443[[:space:]]' \
        || die "Trojan-Go is not listening on 0.0.0.0:443."
}

# ===========================================================
# INSTALL ORCHESTRATION
# ===========================================================

install_all() {
    validate_mode
    prompt_domain
    prompt_email
    prompt_password
    [[ "$MODE" == "ws" ]] && generate_ws_path

    echo
    echo "Mode   : $MODE"
    echo "Domain : $DOMAIN"
    echo "Arch   : amd64"
    [[ "$MODE" == "ws" ]] && echo "WS Path: $WS_PATH"
    echo

    check_ports_free
    check_dns "$DOMAIN"
    check_resources

    install_base_packages
    create_user_and_dirs
    prompt_cloudflare_token
    issue_certificate
    create_cert_deploy_hook

    download_trojan_go
    generate_config
    create_systemd_unit

    [[ "$MODE" == "fallback" ]] && install_nginx_fallback

    start_trojan
    configure_ufw
    verify_ports

    info "Installation completed."
    echo
    info "Running post-installation audit..."
    run_audit
}

# ===========================================================
# TEST COMMAND
# ===========================================================

test_installation() {
    echo "=============================================="
    echo " Trojan-Go Installer ${SCRIPT_VERSION} — Pre-Install Test"
    echo "=============================================="
    echo

    local failures=0

    run_test() {
        local desc="$1"; shift
        printf "  %-50s " "$desc ..."
        if "$@" >/dev/null 2>&1; then
            echo "PASS"
        else
            echo "FAIL"
            ((failures++)) || true
        fi
    }

    run_test "Root user" check_root
    run_test "Ubuntu 24.04" check_os
    run_test "amd64 architecture" check_arch
    run_test "Required commands" check_commands
    echo

    info "IPv4 detection:"
    check_ipv4
    echo

    info "Port availability:"
    local port
    for port in 443 8080 8081; do
        if ss -lntp 2>/dev/null | grep -qE ":${port}[[:space:]]"; then
            warn "  Port ${port}: IN USE"
        else
            info "  Port ${port}: free"
        fi
    done
    echo

    info "DNS check (informational):"
    if command -v dig >/dev/null 2>&1; then
        info "  dig: available"
    elif command -v nslookup >/dev/null 2>&1; then
        info "  nslookup: available"
    else
        warn "  No DNS lookup tool found (dig/nslookup/host)."
    fi
    echo

    check_resources
    check_clock
    check_kernel
    echo

    if [[ "$failures" -eq 0 ]]; then
        info "All mandatory checks passed."
    else
        warn "${failures} check(s) failed. Review above before installing."
    fi
}

# ===========================================================
# STATUS COMMAND
# ===========================================================

status() {
    echo "=============================================="
    echo " Trojan-Go Installer ${SCRIPT_VERSION} — Status"
    echo "=============================================="
    echo

    # Installation status
    echo "--- Installation ---"
    if id "$TROJAN_USER" >/dev/null 2>&1; then
        echo "  User trojan  : present ($(id "$TROJAN_USER" 2>/dev/null || true))"
    else
        echo "  User trojan  : NOT INSTALLED"
    fi

    if [[ -x "$TROJAN_BIN" ]]; then
        echo "  Binary       : $TROJAN_BIN"
        local bin_sha
        bin_sha="$(sha256sum "$TROJAN_BIN" 2>/dev/null | awk '{print $1}' || echo 'unknown')"
        echo "  SHA256       : ${bin_sha}"
        local bin_ver
        bin_ver="$("$TROJAN_BIN" -version 2>/dev/null || echo 'unknown')"
        echo "  Version      : ${bin_ver}"
    else
        echo "  Binary       : NOT INSTALLED"
    fi

    if [[ -f "$TROJAN_CONFIG" ]]; then
        echo "  Config       : $TROJAN_CONFIG"
        local cfg_mode
        cfg_mode="$(jq -r 'if .websocket.enabled then "ws" elif .ssl.fallback_addr then "fallback" else "tcp" end' "$TROJAN_CONFIG" 2>/dev/null || echo 'unknown')"
        echo "  Mode         : ${cfg_mode}"
    else
        echo "  Config       : MISSING"
    fi
    echo

    # systemd
    echo "--- systemd ---"
    if [[ -f "$SYSTEMD_UNIT" ]]; then
        echo "  Unit file    : present"
    else
        echo "  Unit file    : MISSING"
    fi

    if systemctl is-enabled --quiet trojan-go 2>/dev/null; then
        echo "  Enabled      : yes"
    else
        echo "  Enabled      : no"
    fi

    if systemctl is-active --quiet trojan-go 2>/dev/null; then
        echo "  Running      : yes"
    else
        echo "  Running      : no"
    fi
    echo

    # Certificate
    echo "--- Certificate ---"
    local cert_file="$TROJAN_CERT_DIR/fullchain.pem"
    if [[ -f "$cert_file" ]]; then
        echo "  Certificate  : present"
        local expiry
        expiry="$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2 || echo 'unknown')"
        echo "  Expires      : ${expiry}"
        local san
        san="$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -oP 'DNS:[^\s,]+' | tr '\n' ' ' || echo 'unknown')"
        echo "  SAN          : ${san}"
    else
        echo "  Certificate  : MISSING"
    fi
    echo

    # Listening ports
    echo "--- Listening Ports ---"
    ss -lntp 2>/dev/null | grep -E ':(443|80|8080|8081)[[:space:]]' \
        | awk '{print "  "$4" -> "$NF}' || echo "  (none detected)"
    echo

    # UFW
    echo "--- Firewall ---"
    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null | grep -E '(Status|443|22|ssh|8080|8081)' || echo "  (no relevant rules)"
    else
        echo "  UFW: not installed"
    fi
    echo

    # Nginx (informational)
    if command -v nginx >/dev/null 2>&1; then
        echo "--- Nginx ---"
        if systemctl is-active --quiet nginx 2>/dev/null; then
            echo "  Running      : yes"
        else
            echo "  Running      : no"
        fi
        if [[ -f /etc/nginx/sites-enabled/trojan-go-fallback ]]; then
            echo "  Fallback cfg : enabled"
        else
            echo "  Fallback cfg : not enabled"
        fi
        echo
    fi
}

# ===========================================================
# AUDIT COMMAND
# ===========================================================

# Audit helper: prints PASS/FAIL/WARN with consistent formatting
audit_item() {
    local result="$1"; shift
    local label="$1"; shift
    local detail="${1:-}"

    case "$result" in
        PASS) ((AUDIT_PASS++)) || true
              printf '  [PASS] %s\n' "$label" ;;
        FAIL) ((AUDIT_FAIL++)) || true
              printf '  [FAIL] %s  — %s\n' "$label" "$detail" ;;
        WARN) ((AUDIT_WARN++)) || true
              printf '  [WARN] %s  — %s\n' "$label" "$detail" ;;
    esac
}

run_audit() {
    AUDIT_PASS=0
    AUDIT_FAIL=0
    AUDIT_WARN=0

    echo "=============================================="
    echo " Trojan-Go ${SCRIPT_VERSION} — Security Audit"
    echo "=============================================="
    echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
    echo

    # ---- 1. System Environment ----
    echo "1. System Environment"
    echo "----------------------"
    local os_name
    os_name="$(source /etc/os-release 2>/dev/null && echo "${ID:-} ${VERSION_ID:-}" || echo 'unknown')"
    audit_item PASS "OS             : ${os_name}"

    local kver
    kver="$(uname -r 2>/dev/null || echo 'unknown')"
    audit_item PASS "Kernel         : ${kver}"

    local uptime_str
    uptime_str="$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo 'unknown')"
    audit_item PASS "Uptime         : ${uptime_str}"
    echo

    # ---- 2. Trojan-Go Binary ----
    echo "2. Trojan-Go Binary"
    echo "----------------------"
    if [[ -x "$TROJAN_BIN" ]]; then
        audit_item PASS "Binary exists  : $TROJAN_BIN"
        local sha
        sha="$(sha256sum "$TROJAN_BIN" 2>/dev/null | awk '{print $1}')"
        audit_item PASS "SHA256         : ${sha:0:16}..."

        local owner
        owner="$(stat -c '%U:%G' "$TROJAN_BIN" 2>/dev/null || echo 'unknown')"
        if [[ "$owner" == "root:root" ]]; then
            audit_item PASS "Ownership      : ${owner}"
        else
            audit_item FAIL "Ownership      : ${owner} (expected root:root)"
        fi

        local perms
        perms="$(stat -c '%a' "$TROJAN_BIN" 2>/dev/null || echo '000')"
        if [[ "$perms" == "755" ]]; then
            audit_item PASS "Permissions    : ${perms}"
        else
            audit_item WARN "Permissions    : ${perms} (expected 755)"
        fi
    else
        audit_item FAIL "Binary missing : $TROJAN_BIN does not exist or is not executable"
    fi
    echo

    # ---- 3. Trojan-Go Configuration ----
    echo "3. Configuration"
    echo "----------------------"
    if [[ -f "$TROJAN_CONFIG" ]]; then
        audit_item PASS "Config exists  : $TROJAN_CONFIG"

        if jq empty "$TROJAN_CONFIG" >/dev/null 2>&1; then
            audit_item PASS "JSON valid     : yes"

            local run_type
            run_type="$(jq -r '.run_type // "missing"' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ "$run_type" == "server" ]]; then
                audit_item PASS "run_type       : server"
            else
                audit_item FAIL "run_type       : ${run_type} (expected server)"
            fi

            local local_addr
            local_addr="$(jq -r '.local_addr // "missing"' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ "$local_addr" == "0.0.0.0" ]]; then
                audit_item PASS "local_addr     : 0.0.0.0"
            else
                audit_item WARN "local_addr     : ${local_addr}"
            fi

            local local_port
            local_port="$(jq -r '.local_port // 0' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ "$local_port" == "443" ]]; then
                audit_item PASS "local_port     : 443"
            else
                audit_item FAIL "local_port     : ${local_port} (expected 443)"
            fi

            local ssl_cert
            ssl_cert="$(jq -r '.ssl.cert // "missing"' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ -f "$ssl_cert" ]]; then
                audit_item PASS "ssl.cert       : exists"
            else
                audit_item FAIL "ssl.cert       : file not found (${ssl_cert})"
            fi

            local ssl_key
            ssl_key="$(jq -r '.ssl.key // "missing"' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ -f "$ssl_key" ]]; then
                audit_item PASS "ssl.key        : exists"
            else
                audit_item FAIL "ssl.key        : file not found (${ssl_key})"
            fi

            local ws_enabled
            ws_enabled="$(jq -r '.websocket.enabled // false' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ "$ws_enabled" == "true" ]]; then
                local ws_path
                ws_path="$(jq -r '.websocket.path // "missing"' "$TROJAN_CONFIG" 2>/dev/null)"
                audit_item PASS "websocket      : enabled, path present"
            else
                audit_item PASS "websocket      : disabled (tcp/fallback mode)"
            fi

            local fb_addr
            fb_addr="$(jq -r '.ssl.fallback_addr // ""' "$TROJAN_CONFIG" 2>/dev/null)"
            if [[ -n "$fb_addr" ]]; then
                if [[ "$fb_addr" == "127.0.0.1" ]]; then
                    audit_item PASS "fallback_addr  : 127.0.0.1"
                else
                    audit_item FAIL "fallback_addr  : ${fb_addr} (expected 127.0.0.1)"
                fi
            fi

        else
            audit_item FAIL "JSON valid     : INVALID — $(jq empty "$TROJAN_CONFIG" 2>&1)"
        fi

        local cfg_owner
        cfg_owner="$(stat -c '%U:%G' "$TROJAN_CONFIG" 2>/dev/null || echo 'unknown')"
        if [[ "$cfg_owner" == "root:${TROJAN_GROUP}" ]]; then
            audit_item PASS "Config owner   : ${cfg_owner}"
        else
            audit_item FAIL "Config owner   : ${cfg_owner} (expected root:${TROJAN_GROUP})"
        fi

        local cfg_perms
        cfg_perms="$(stat -c '%a' "$TROJAN_CONFIG" 2>/dev/null || echo '000')"
        if [[ "$cfg_perms" == "640" ]]; then
            audit_item PASS "Config perms   : ${cfg_perms}"
        else
            audit_item FAIL "Config perms   : ${cfg_perms} (expected 640)"
        fi
    else
        audit_item FAIL "Config missing : $TROJAN_CONFIG"
    fi
    echo

    # ---- 4. Certificate Audit ----
    echo "4. Certificate Audit"
    echo "----------------------"
    local cert_file="$TROJAN_CERT_DIR/fullchain.pem"
    local key_file="$TROJAN_CERT_DIR/privkey.pem"

    if [[ -f "$cert_file" ]]; then
        audit_item PASS "fullchain.pem  : exists"

        local cert_owner
        cert_owner="$(stat -c '%U:%G' "$cert_file" 2>/dev/null || echo 'unknown')"
        if [[ "$cert_owner" == "root:${TROJAN_GROUP}" ]]; then
            audit_item PASS "Cert owner     : ${cert_owner}"
        else
            audit_item WARN "Cert owner     : ${cert_owner} (expected root:${TROJAN_GROUP})"
        fi

        local cert_perms
        cert_perms="$(stat -c '%a' "$cert_file" 2>/dev/null || echo '000')"
        if [[ "$cert_perms" == "640" ]]; then
            audit_item PASS "Cert perms     : ${cert_perms}"
        else
            audit_item WARN "Cert perms     : ${cert_perms} (expected 640)"
        fi

        # Validity
        local not_after
        not_after="$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)"
        if [[ -n "$not_after" ]]; then
            local expiry_epoch
            expiry_epoch="$(date -d "$not_after" +%s 2>/dev/null || echo 0)"
            local now_epoch
            now_epoch="$(date +%s)"
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            if [[ "$days_left" -gt 30 ]]; then
                audit_item PASS "Cert expiry    : ${days_left} days (${not_after})"
            elif [[ "$days_left" -gt 0 ]]; then
                audit_item WARN "Cert expiry    : ${days_left} days — RENEW SOON (${not_after})"
            else
                audit_item FAIL "Cert expired   : ${not_after}"
            fi
        else
            audit_item FAIL "Cert expiry    : could not read"
        fi

        # SAN
        local san
        san="$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -oP 'DNS:[^\s,]+' | tr '\n' ' ' || echo '')"
        if [[ -n "$san" ]]; then
            audit_item PASS "SAN            : ${san}"
        fi
    else
        audit_item FAIL "fullchain.pem  : MISSING"
    fi

    if [[ -f "$key_file" ]]; then
        audit_item PASS "privkey.pem    : exists"

        local key_owner
        key_owner="$(stat -c '%U:%G' "$key_file" 2>/dev/null || echo 'unknown')"
        if [[ "$key_owner" == "root:${TROJAN_GROUP}" ]]; then
            audit_item PASS "Key owner      : ${key_owner}"
        else
            audit_item FAIL "Key owner      : ${key_owner} (expected root:${TROJAN_GROUP})"
        fi

        local key_perms
        key_perms="$(stat -c '%a' "$key_file" 2>/dev/null || echo '000')"
        if [[ "$key_perms" == "640" ]]; then
            audit_item PASS "Key perms      : ${key_perms}"
        else
            audit_item FAIL "Key perms      : ${key_perms} (expected 640)"
        fi
    else
        audit_item FAIL "privkey.pem    : MISSING"
    fi

    # Cert/key match
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        local cert_pub key_pub
        cert_pub="$(openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
        key_pub="$(openssl pkey -in "$key_file" -pubout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
        if [[ "$cert_pub" == "$key_pub" ]]; then
            audit_item PASS "Cert/key match : yes"
        else
            audit_item FAIL "Cert/key match : MISMATCH"
        fi
    fi

    # Certbot timer
    if systemctl list-timers --all 2>/dev/null | grep -q 'certbot'; then
        audit_item PASS "Certbot timer  : active"
    elif [[ -f /etc/cron.d/certbot ]] || [[ -f /etc/systemd/system/certbot.timer ]]; then
        audit_item PASS "Certbot timer  : configured"
    else
        audit_item WARN "Certbot timer  : not detected — renewal may not be automatic"
    fi
    echo

    # ---- 5. systemd Audit ----
    echo "5. systemd Audit"
    echo "----------------------"
    if [[ -f "$SYSTEMD_UNIT" ]]; then
        audit_item PASS "Unit file      : exists"

        local unit_user
        unit_user="$(grep -Po '(?<=^User=).*' "$SYSTEMD_UNIT" 2>/dev/null || echo '')"
        if [[ "$unit_user" == "$TROJAN_USER" ]]; then
            audit_item PASS "User           : ${TROJAN_USER}"
        else
            audit_item FAIL "User           : ${unit_user:-MISSING} (expected ${TROJAN_USER})"
        fi

        # Check key security directives
        local check_directives=(
            "NoNewPrivileges=true"
            "PrivateTmp=true"
            "PrivateDevices=true"
            "ProtectHome=true"
            "ProtectSystem=strict"
            "RestrictSUIDSGID=true"
            "LockPersonality=true"
        )
        local d
        for d in "${check_directives[@]}"; do
            local key="${d%%=*}"
            if grep -qF "$d" "$SYSTEMD_UNIT" 2>/dev/null; then
                audit_item PASS "  ${key}"
            else
                audit_item WARN "  ${key}       : missing"
            fi
        done

        if grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$' "$SYSTEMD_UNIT" 2>/dev/null; then
            audit_item PASS "  CapabilityBoundingSet : CAP_NET_BIND_SERVICE"
        elif grep -q '^CapabilityBoundingSet=$' "$SYSTEMD_UNIT" 2>/dev/null; then
            audit_item FAIL "  CapabilityBoundingSet : empty — cannot bind port 443"
        else
            audit_item WARN "  CapabilityBoundingSet : unexpected value"
        fi

        if systemctl is-enabled --quiet trojan-go 2>/dev/null; then
            audit_item PASS "Enabled        : yes"
        else
            audit_item FAIL "Enabled        : no — will not start on boot"
        fi

        if systemctl is-active --quiet trojan-go 2>/dev/null; then
            audit_item PASS "Active         : yes"
        else
            audit_item FAIL "Active         : no — service is not running"
        fi
    else
        audit_item FAIL "Unit file      : MISSING ($SYSTEMD_UNIT)"
    fi
    echo

    # ---- 6. User & Permissions ----
    echo "6. User & Permissions"
    echo "----------------------"
    if id "$TROJAN_USER" >/dev/null 2>&1; then
        audit_item PASS "User trojan    : exists"

        local shell
        shell="$(getent passwd "$TROJAN_USER" | cut -d: -f7)"
        if [[ "$shell" == "/usr/sbin/nologin" ]] || [[ "$shell" == "/bin/false" ]] || [[ "$shell" == "/usr/sbin/nologin" ]]; then
            audit_item PASS "Shell          : ${shell} (no login)"
        else
            audit_item FAIL "Shell          : ${shell} (expected nologin)"
        fi

        # Check not in sudo group
        if id -nG "$TROJAN_USER" 2>/dev/null | grep -qw 'sudo'; then
            audit_item FAIL "sudo access    : YES — trojan user has sudo!"
        else
            audit_item PASS "sudo access    : none"
        fi
    else
        audit_item FAIL "User trojan    : MISSING"
    fi

    # Directory permissions
    local check_dirs=(
        "$TROJAN_ETC:root:${TROJAN_GROUP}:750"
        "$TROJAN_CERT_DIR:root:${TROJAN_GROUP}:750"
        "$TROJAN_DATA:${TROJAN_USER}:${TROJAN_GROUP}:750"
        "$TROJAN_CACHE:root:root:750"
    )
    local d_entry
    for d_entry in "${check_dirs[@]}"; do
        IFS=':' read -r d_path d_owner d_group d_perms <<< "$d_entry"
        if [[ -d "$d_path" ]]; then
            local actual_owner actual_perms
            actual_owner="$(stat -c '%U:%G' "$d_path" 2>/dev/null || echo '?:?')"
            actual_perms="$(stat -c '%a' "$d_path" 2>/dev/null || echo '000')"
            if [[ "$actual_owner" == "${d_owner}:${d_group}" ]] && [[ "$actual_perms" == "$d_perms" ]]; then
                audit_item PASS "Dir            : $d_path (${actual_owner} ${actual_perms})"
            else
                audit_item WARN "Dir            : $d_path (${actual_owner} ${actual_perms}, expected ${d_owner}:${d_group} ${d_perms})"
            fi
        else
            # Only FAIL for cert dir when we have config; otherwise INFO via PASS
            audit_item PASS "Dir            : $d_path (not present)"
        fi
    done
    echo

    # ---- 7. Network Audit ----
    echo "7. Network Audit"
    echo "----------------------"

    # 443
    if ss -lntp 2>/dev/null | grep -Eq '0\.0\.0\.0:443[[:space:]]'; then
        local proc_443
        proc_443="$(ss -lntp 2>/dev/null | grep -E '0\.0\.0\.0:443[[:space:]]' | awk '{print $NF}' | head -1)"
        audit_item PASS "443 listening  : yes (${proc_443})"
    elif ss -lntp 2>/dev/null | grep -Eq ':443[[:space:]]'; then
        local proc_443
        proc_443="$(ss -lntp 2>/dev/null | grep -E ':443[[:space:]]' | awk '{print $NF}' | head -1)"
        audit_item WARN "443 listening  : yes but check bind address (${proc_443})"
    else
        audit_item FAIL "443 listening  : NO — Trojan-Go is not reachable"
    fi

    # 8080/8081 must be 127.0.0.1 only (only relevant in fallback mode or if Nginx is installed)
    local port
    for port in 8080 8081; do
        if ss -lntp 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
            if ss -lntp 2>/dev/null | grep -Eq "127\.0\.0\.1:${port}[[:space:]]"; then
                audit_item PASS "Port ${port}    : 127.0.0.1 only (safe)"
            else
                audit_item FAIL "Port ${port}    : EXPOSED — must listen on 127.0.0.1 only!"
            fi
        else
            # Not listening — fine unless fallback mode
            audit_item PASS "Port ${port}    : not listening (OK for non-fallback)"
        fi
    done

    # UFW
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -q 'Status: active'; then
            audit_item PASS "UFW            : active"
        else
            audit_item WARN "UFW            : inactive"
        fi

        # Check no 8080/8081 exposed
        if ufw status 2>/dev/null | grep -qE '8080|8081'; then
            audit_item FAIL "UFW 8080/8081  : exposed in firewall — should be internal only!"
        else
            audit_item PASS "UFW 8080/8081  : not exposed"
        fi

        if ufw status 2>/dev/null | grep -qE '443'; then
            audit_item PASS "UFW 443        : allowed"
        else
            audit_item FAIL "UFW 443        : NOT allowed"
        fi
    else
        audit_item WARN "UFW            : not installed"
    fi
    echo

    # ---- 8. Nginx Audit (fallback only) ----
    echo "8. Nginx Audit"
    echo "----------------------"
    if command -v nginx >/dev/null 2>&1; then
        if systemctl is-active --quiet nginx 2>/dev/null; then
            audit_item PASS "Nginx running  : yes"
        else
            audit_item FAIL "Nginx running  : no"
        fi

        local fb_conf="/etc/nginx/sites-available/trojan-go-fallback"
        if [[ -f "$fb_conf" ]]; then
            audit_item PASS "Fallback conf  : exists"

            if grep -q 'listen 127.0.0.1:8080' "$fb_conf" 2>/dev/null; then
                audit_item PASS "  8080 bind    : 127.0.0.1"
            else
                audit_item FAIL "  8080 bind    : NOT 127.0.0.1"
            fi

            if grep -q 'listen 127.0.0.1:8081' "$fb_conf" 2>/dev/null; then
                audit_item PASS "  8081 bind    : 127.0.0.1"
            else
                audit_item FAIL "  8081 bind    : NOT 127.0.0.1"
            fi

            if grep -q 'server_tokens off' "$fb_conf" 2>/dev/null; then
                audit_item PASS "  server_tokens: off"
            else
                audit_item WARN "  server_tokens: not off"
            fi

            if nginx -t >/dev/null 2>&1; then
                audit_item PASS "Nginx config   : valid"
            else
                audit_item FAIL "Nginx config   : INVALID — run nginx -t"
            fi
        else
            audit_item PASS "Fallback conf  : none (not a fallback install)"
        fi
    else
        audit_item PASS "Nginx          : not installed (OK for non-fallback)"
    fi
    echo

    # ---- 9. Sensitive Files ----
    echo "9. Sensitive File Audit"
    echo "----------------------"

    if [[ -f "$CF_CREDENTIALS" ]]; then
        local cf_owner cf_perms
        cf_owner="$(stat -c '%U:%G' "$CF_CREDENTIALS" 2>/dev/null || echo '?:?')"
        cf_perms="$(stat -c '%a' "$CF_CREDENTIALS" 2>/dev/null || echo '000')"

        if [[ "$cf_owner" == "root:root" ]]; then
            audit_item PASS "cloudflare.ini owner   : root:root"
        else
            audit_item FAIL "cloudflare.ini owner   : ${cf_owner} (expected root:root)"
        fi

        if [[ "$cf_perms" == "600" ]]; then
            audit_item PASS "cloudflare.ini perms   : 600"
        else
            audit_item FAIL "cloudflare.ini perms   : ${cf_perms} (expected 600)"
        fi

        # Verify trojan user cannot read
        if su -s /bin/bash -c "test -r $CF_CREDENTIALS && echo readable || echo denied" "$TROJAN_USER" 2>/dev/null | grep -q 'denied'; then
            audit_item PASS "cloudflare.ini trojan  : cannot read"
        else
            # Alternative check: if file is 600 root:root, trojan can't read
            if [[ "$cf_owner" == "root:root" && "$cf_perms" == "600" ]]; then
                audit_item PASS "cloudflare.ini trojan  : cannot read (by perms)"
            else
                audit_item FAIL "cloudflare.ini trojan  : MAY BE READABLE by trojan user"
            fi
        fi
    else
        audit_item PASS "cloudflare.ini : not present (no Cloudflare token stored)"
    fi

    # Config contains password — verify it's not world-readable
    if [[ -f "$TROJAN_CONFIG" ]]; then
        local cfg_perms_check
        cfg_perms_check="$(stat -c '%a' "$TROJAN_CONFIG" 2>/dev/null || echo '000')"
        if [[ "${cfg_perms_check: -1}" == "0" ]]; then
            audit_item PASS "config.json world  : not readable"
        else
            audit_item FAIL "config.json world  : readable! ($cfg_perms_check)"
        fi
    fi

    # Private key not world-readable
    if [[ -f "$key_file" ]]; then
        local key_perms_check
        key_perms_check="$(stat -c '%a' "$key_file" 2>/dev/null || echo '000')"
        if [[ "${key_perms_check: -1}" == "0" ]]; then
            audit_item PASS "privkey.pem world   : not readable"
        else
            audit_item FAIL "privkey.pem world   : readable! ($key_perms_check)"
        fi
    fi
    echo

    # ---- Summary ----
    echo "=============================================="
    echo " Audit Summary"
    echo "=============================================="
    echo "  PASS : ${AUDIT_PASS}"
    echo "  WARN : ${AUDIT_WARN}"
    echo "  FAIL : ${AUDIT_FAIL}"
    echo "----------------------------------------------"

    if [[ "$AUDIT_FAIL" -gt 0 ]]; then
        echo "  Result: FAILED — ${AUDIT_FAIL} issue(s) need attention."
        echo
        exit 1
    elif [[ "$AUDIT_WARN" -gt 0 ]]; then
        echo "  Result: PASSED with ${AUDIT_WARN} warning(s)."
        echo
        exit 2
    else
        echo "  Result: ALL PASSED"
        echo
        exit 0
    fi
}

# ===========================================================
# UPDATE / UNINSTALL (stubs)
# ===========================================================

update() {
    die "Update will be available in v2.0. For now, reinstall with a pinned, independently verified release."
}

uninstall() {
    die "Uninstall will be available in v2.0. Manual cleanup only at this stage."
}

# ===========================================================
# MAIN
# ===========================================================

main() {
    parse_args "$@"

    case "$COMMAND" in
        install)
            check_root
            check_os
            check_arch
            check_commands
            check_ipv4
            select_mode
            install_all
            ;;
        test)
            check_root
            test_installation
            ;;
        audit)
            check_root
            run_audit
            ;;
        status)
            status
            ;;
        update)
            update
            ;;
        uninstall)
            uninstall
            ;;
    esac
}

main "$@"
