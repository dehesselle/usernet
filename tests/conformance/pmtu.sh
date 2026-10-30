#!/bin/sh

# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

# A path that narrows one hop out, so the kernel itself answers our segments
# with ICMP "fragmentation needed". Nothing else exercises path-MTU handling
# against real traffic.
#
#   sudo sh tests/conformance/pmtu.sh
#   sudo sh tests/conformance/pmtu.sh --off
#
#   us 10.99.0.2 --tun--> kernel --veth, MTU 1000--> far 10.98.0.2 (MTU 1500)
#
# Only the hop is narrow. The far end's own interface stays at 1500, so its
# SYN-ACK offers an MSS of 1460 and the handshake gives nothing away. The
# kernel forwards our full-sized segments, finds them too big for the hop with
# DF set, and says so -- before its FORWARD chain, which is why the rules below
# are needed only for what fits. A server in the far namespace takes an upload
# and answers with its length and digest.
#
# Needs tests/conformance/setup.sh first, for the tun device.

set -eu

NS=usernet-far
NEAR=veth-unear
FAR=veth-ufar
NEAR_IP=10.98.0.1
FAR_IP=10.98.0.2
PORT=9000
HOP_MTU=${USERNET_PMTU_HOP:-1000}
DEV=${USERNET_TUN_DEV:-usernet0}
TUN_NET=10.99.0.0/24
PIDFILE=/run/usernet-far.pid
HERE=$(dirname "$0")

forward_rules() {
    # Docker, among others, sets the FORWARD policy to DROP.
    command -v iptables >/dev/null || return 0
    iptables "$1" FORWARD -i "$DEV" -o "$NEAR" -j ACCEPT 2>/dev/null || true
    iptables "$1" FORWARD -i "$NEAR" -o "$DEV" -j ACCEPT 2>/dev/null || true
}

if [ "$(id -u)" -ne 0 ]; then
    echo "this needs root: sudo sh $0 $*" >&2
    exit 1
fi

if [ "${1:-}" = "--off" ]; then
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    forward_rules -D
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$NEAR" 2>/dev/null || true
    echo "removed the far namespace"
    exit 0
fi

ip netns del "$NS" 2>/dev/null || true
ip link del "$NEAR" 2>/dev/null || true
ip netns add "$NS"
ip link add "$NEAR" type veth peer name "$FAR"
ip link set "$FAR" netns "$NS"

ip addr add "$NEAR_IP/24" dev "$NEAR"
ip link set "$NEAR" mtu "$HOP_MTU" up
ip -n "$NS" addr add "$FAR_IP/24" dev "$FAR"
ip -n "$NS" link set "$FAR" mtu 1500 up
ip -n "$NS" link set lo up
ip -n "$NS" route add "$TUN_NET" via "$NEAR_IP"

sysctl -qw net.ipv4.ip_forward=1
forward_rules -I

ip netns exec "$NS" python3 "$HERE/far_server.py" "$FAR_IP" "$PORT" >/dev/null 2>&1 &
echo $! > "$PIDFILE"

echo "far end at $FAR_IP:$PORT behind a $HOP_MTU-byte hop"
echo
echo "next:  uv run pytest tests/conformance/test_kernel_pmtu.py -v"
