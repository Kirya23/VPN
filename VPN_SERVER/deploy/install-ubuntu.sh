#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERR] install-ubuntu.sh must be run as root" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PREFIX="/opt/qvpn-server"
BUILD_DIR="/tmp/qvpn-server-build"
EXTERNAL_IFACE="eth0"
PORT="8080"
TUN_NAME="qvpn0"
TUN_ADDRESS="10.10.0.1/24"
SUBNET="10.10.0.0/24"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --external-iface)
            EXTERNAL_IFACE="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --tun-name)
            TUN_NAME="$2"
            shift 2
            ;;
        --tun-address)
            TUN_ADDRESS="$2"
            shift 2
            ;;
        --subnet)
            SUBNET="$2"
            shift 2
            ;;
        --help|-h)
            cat <<EOF
Usage: bash install-ubuntu.sh [options]

Options:
  --prefix PATH            Installation prefix. Default: /opt/qvpn-server
  --build-dir PATH         Temporary build directory. Default: /tmp/qvpn-server-build
  --external-iface NAME    Public network interface. Default: eth0
  --port PORT              UDP listen port. Default: 8080
  --tun-name NAME          TUN interface name. Default: qvpn0
  --tun-address CIDR       TUN interface address. Default: 10.10.0.1/24
  --subnet CIDR            VPN subnet for forwarding/NAT. Default: 10.10.0.0/24
EOF
            exit 0
            ;;
        *)
            echo "[ERR] Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

echo "[INFO] Installing Ubuntu build and runtime dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    qt6-base-dev \
    libssl-dev \
    iproute2 \
    iptables

echo "[INFO] Building VPN_server"
rm -rf "${BUILD_DIR}"
cmake -S "${SERVER_DIR}" -B "${BUILD_DIR}" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}"
cmake --build "${BUILD_DIR}"
cmake --install "${BUILD_DIR}"

install -d "${PREFIX}/bin"
install -m 0755 "${SCRIPT_DIR}/configure-network.sh" "${PREFIX}/bin/configure-network.sh"

echo "[INFO] Writing /etc/default/qvpn-server"
cat >/etc/default/qvpn-server <<EOF
QVPN_PORT=${PORT}
QVPN_TUN_NAME=${TUN_NAME}
QVPN_TUN_ADDRESS=${TUN_ADDRESS}
QVPN_EXTERNAL_IFACE=${EXTERNAL_IFACE}
QVPN_SUBNET=${SUBNET}
EOF

echo "[INFO] Persisting IPv4 forwarding"
cat >/etc/sysctl.d/99-qvpn-server.conf <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null

echo "[INFO] Writing systemd unit"
cat >/etc/systemd/system/qvpn-server.service <<EOF
[Unit]
Description=QVPN UDP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/qvpn-server
ExecStartPre=${PREFIX}/bin/configure-network.sh
ExecStart=${PREFIX}/bin/VPN_server
WorkingDirectory=${PREFIX}/bin
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo "[INFO] Enabling qvpn-server.service"
systemctl daemon-reload
systemctl enable --now qvpn-server.service

echo "[OK] QVPN server is installed"
echo "[INFO] Check status with: systemctl status qvpn-server"
echo "[INFO] Follow logs with: journalctl -u qvpn-server -f"
