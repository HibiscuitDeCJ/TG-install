#!/usr/bin/env bash
# ============================================================
# Trojan-Go Secure Installer v1.6
#
# Target: Ubuntu 24.04 / amd64 / IPv4
#
# Modes:
#   tcp       Trojan-Go TCP + TLS, no Nginx
#   ws        Trojan-Go WebSocket + TLS, no Nginx
#   fallback  Trojan-Go TCP + TLS + local Nginx fallback
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

readonly SCRIPT_VERSION="1.6.0"
readonly TROJAN_GO_VERSION="v0.10.6"
readonly TROJAN_GO_REPO="p4gefau1t/trojan-go"
readonly TROJAN_GO_ASSET="trojan-go-linux-amd64.zip"

# Supply the independently verified SHA256 before installation.
# Example:
#   TROJAN_GO_SHA256='...' ./install.sh install --mode tcp
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

log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" \
        | tee -a /var/log/trojan-go-installer.log
}
info(){ log INFO "$@"; }
warn(){ log WARN "$@"; }
error(){ log ERROR "$@" >&2; }
die(){ error "$@"; exit 1; }

on_error() {
    local rc=$? line="$1"
    error "Failure at line ${line}, exit code ${rc}."
    exit "$rc"
}
trap 'on_error "${LINENO}"' ERR

usage() {
    cat <<EOF
Trojan-Go Secure Installer ${SCRIPT_VERSION}

Usage:
  $0 install --mode tcp|ws|fallback [--domain DOMAIN] [--email EMAIL]
  $0 status
  $0 test
  $0 update
  $0 uninstall

Examples:
  TROJAN_GO_SHA256='...' $0 install --mode tcp --domain example.com
  TROJAN_GO_SHA256='...' $0 install --mode ws --domain example.com
  TROJAN_GO_SHA256='...' $0 install --mode fallback --domain example.com

The SHA256 is intentionally mandatory. Do not remove that check.
EOF
}

check_root() {
    [[ $EUID -eq 0 ]] || die "Run as root."
}

check_os() {
    [[ -r /etc/os-release ]] || die "Missing /etc/os-release."
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] \
        || die "Ubuntu 24.04 is required."
}

check_arch() {
    [[ "$(dpkg --print-architecture)" == "amd64" ]] \
        || die "This version supports amd64 only."
}

check_commands() {
    local c
    for c in awk sed grep ip ss dpkg systemctl; do
        command -v "$c" >/dev/null 2>&1 || die "Missing command: $c"
    done
}

check_ipv4() {
    local ip4
    ip4="$(ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    [[ -n "$ip4" ]] && info "Server IPv4: $ip4" || warn "Could not detect IPv4 automatically."
}

parse_args() {
    [[ $# -gt 0 ]] || { usage; exit 0; }
    COMMAND="$1"; shift

    case "$COMMAND" in
        install)
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --mode) [[ $# -ge 2 ]] || die "--mode needs a value"; MODE="$2"; shift 2;;
                    --domain) [[ $# -ge 2 ]] || die "--domain needs a value"; DOMAIN="$2"; shift 2;;
                    --email) [[ $# -ge 2 ]] || die "--email needs a value"; EMAIL="$2"; shift 2;;
                    --help|-h) usage; exit 0;;
                    *) die "Unknown option: $1";;
                esac
            done
            ;;
        status|test|update|uninstall)
            [[ $# -eq 0 ]] || die "Unexpected arguments."
            ;;
        help|-h|--help) usage; exit 0;;
        *) die "Unknown command: $COMMAND";;
    esac
}

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
    [[ ${#DOMAIN} -le 253 ]] || die "Domain is too long."
    [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] \
        || die "Invalid domain."
    [[ "$DOMAIN" != *..* ]] || die "Invalid domain."
}

prompt_email() {
    [[ -n "$EMAIL" ]] && return
    while true; do
        read -r -p "Let's Encrypt email: " EMAIL
        [[ "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] && break
        warn "Invalid email."
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

install_base_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl ca-certificates openssl unzip jq certbot python3-certbot-dns-cloudflare ufw
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
    echo "Cloudflare token must have only:"
    echo "  Zone -> DNS -> Edit"
    echo "restricted to the required zone."
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
    [[ "$a" == "$b" ]] || die "Certificate/private-key mismatch."
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
        || die "Invalid SHA256."

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

    # Install the bundled data files if present.
    [[ -f "$extract/geoip.dat" ]] &&
        install -o root -g "$TROJAN_GROUP" -m 0644 "$extract/geoip.dat" "$TROJAN_ETC/geoip.dat"
    [[ -f "$extract/geosite.dat" ]] &&
        install -o root -g "$TROJAN_GROUP" -m 0644 "$extract/geosite.dat" "$TROJAN_ETC/geosite.dat"

    rm -f "$archive"
    rm -rf "$extract"
}

generate_config() {
    local remote_port=9
    local fallback_json=''

    if [[ "$MODE" == "fallback" ]]; then
        fallback_json='"fallback_addr":"127.0.0.1","fallback_port":8081,'
    fi

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
CapabilityBoundingSet=
AmbientCapabilities=
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
    ss -lntp | grep -E ':(443|8080|8081)\b' || true

    if [[ "$MODE" == "fallback" ]]; then
        ss -lntp | grep -Eq '127\.0\.0\.1:8080\b' \
            || die "Fallback HTTP port 8080 is not listening."
        ss -lntp | grep -Eq '127\.0\.0\.1:8081\b' \
            || die "Fallback raw port 8081 is not listening."
    fi

    ss -lntp | grep -Eq '0\.0\.0\.0:443\b' \
        || die "Trojan-Go is not listening on IPv4 port 443."
}

status() {
    echo "Trojan-Go Secure Installer ${SCRIPT_VERSION}"
    echo "---------------------------------------"
    echo "User: $(id "$TROJAN_USER" 2>/dev/null || echo not-installed)"
    [[ -x "$TROJAN_BIN" ]] && echo "Binary: installed" || echo "Binary: not-installed"
    systemctl is-enabled --quiet trojan-go 2>/dev/null && echo "Enabled: yes" || echo "Enabled: no"
    systemctl is-active --quiet trojan-go 2>/dev/null && echo "Running: yes" || echo "Running: no"
    [[ -f "$TROJAN_CONFIG" ]] && echo "Config: $TROJAN_CONFIG"
    [[ -f "$TROJAN_CERT_DIR/fullchain.pem" ]] && echo "Certificate: present" || echo "Certificate: missing"
    echo
}

test_installation() {
    check_root
    check_os
    check_arch
    check_commands
    check_ipv4
    info "Environment test passed."
}

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
    echo

    install_base_packages
    create_user_and_dirs
    prompt_cloudflare_token
    install_certbot
    issue_certificate
    create_cert_deploy_hook

    download_trojan_go
    generate_config
    create_systemd_unit

    [[ "$MODE" == "fallback" ]] && install_nginx_fallback

    start_trojan
    configure_ufw
    verify_ports

    unset PASSWORD
    info "Installation completed."
    info "Use: $0 status"
}

update() {
    die "Update is intentionally disabled in v1.6. Reinstall a pinned, independently verified release."
}

uninstall() {
    die "Uninstall is intentionally disabled in v1.6 until the final file/ownership inventory is frozen."
}

main() {
    parse_args "$@"
    check_root
    check_os
    check_arch
    check_commands
    check_ipv4

    case "$COMMAND" in
        install) select_mode; install_all;;
        status) status;;
        test) test_installation;;
        update) update;;
        uninstall) uninstall;;
    esac
}

main "$@"
