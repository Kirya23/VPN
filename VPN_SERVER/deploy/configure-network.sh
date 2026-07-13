#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERR] configure-network.sh must be run as root" >&2
    exit 1
fi

QVPN_PORT="${QVPN_PORT:-8080}"
QVPN_EXTERNAL_IFACE="${QVPN_EXTERNAL_IFACE:-eth0}"
QVPN_SUBNET="${QVPN_SUBNET:-10.10.0.0/24}"

add_rule() {
    local table="$1"
    shift

    if [[ -n "${table}" ]]; then
        if ! iptables -t "${table}" -C "$@" 2>/dev/null; then
            iptables -t "${table}" -A "$@"
        fi
    else
        if ! iptables -C "$@" 2>/dev/null; then
            iptables -A "$@"
        fi
    fi
}

echo "[INFO] Enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[INFO] Allowing UDP ${QVPN_PORT}"
add_rule "" INPUT -p udp --dport "${QVPN_PORT}" -j ACCEPT

echo "[INFO] Allowing forwarding for ${QVPN_SUBNET}"
add_rule "" FORWARD -s "${QVPN_SUBNET}" -j ACCEPT
add_rule "" FORWARD -d "${QVPN_SUBNET}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[INFO] Enabling NAT via ${QVPN_EXTERNAL_IFACE}"
add_rule "nat" POSTROUTING -s "${QVPN_SUBNET}" -o "${QVPN_EXTERNAL_IFACE}" -j MASQUERADE

echo "[OK] Network rules are in place"
