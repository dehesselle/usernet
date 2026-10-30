#!/bin/sh

# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

# Degrade both directions of the tun link, for the conformance runs that
# actually exercise recovery.
#
#   sudo sh tests/conformance/impair.sh [profile]
#   sudo sh tests/conformance/impair.sh <delay> [loss]
#   sudo sh tests/conformance/impair.sh --off
#
# Profiles, each applied to both directions; CI runs every one:
#
#   loss        20ms, 2% loss (the default). Fast retransmit and NewReno.
#   reorder     20ms, a quarter of packets sent early. Reassembly, and that
#               reordering costs a duplicate ACK rather than a retransmission.
#   duplicate   20ms, 5% sent twice. Duplicates must be trimmed, never delivered.
#   corrupt     20ms, 1% with a flipped bit. The receive checksum, both ways.
#   bottleneck  20ms at 10 Mbit/s behind a 64-packet queue. Loss from overflow,
#               driven by our own sending rate, which is what cwnd is for.
#   long-fat    100ms, 0.5% loss. A large window in flight: window scaling and
#               cwnd growth, and recovery with a long RTT.
#
# A plain `tc qdisc add dev usernet0 root netem ...` is not enough, and the way it
# falls short is invisible: a root qdisc is EGRESS only, so it degrades
# kernel->us and leaves our own packets untouched. Our retransmission -- the
# code most likely to be wrong, and the reason for impairing anything -- is
# then never exercised. Ingress has to be redirected through an ifb device to
# get a qdisc on it at all.

set -eu

DEV=${USERNET_TUN_DEV:-usernet0}
IFB=ifb-usernet

# netem's default queue is 1000 packets, which is itself a bandwidth limit:
# a link holds delay x rate packets in flight, so at 150ms RTT anything past
# a ~1 MiB window overflows the qdisc and the losses look like a bug in the
# thing under test. Raised well clear of any window we would configure.
LIMIT=${USERNET_NETEM_LIMIT:-50000}

case "${1:-loss}" in
    --off)      ;;
    loss)       NETEM="delay 20ms loss 2%" ;;
    reorder)    NETEM="delay 20ms reorder 25% 50%" ;;
    duplicate)  NETEM="delay 20ms duplicate 5%" ;;
    corrupt)    NETEM="delay 20ms corrupt 1%" ;;
    # The queue is the point here, so it is short on purpose.
    bottleneck) NETEM="delay 20ms rate 10mbit"; LIMIT=${USERNET_NETEM_LIMIT:-64} ;;
    long-fat)   NETEM="delay 100ms loss 0.5%" ;;
    # The original form, still used by bench/run.py: a delay and a loss rate.
    [0-9]*)     NETEM="delay $1 loss ${2:-2%}" ;;
    *)          echo "unknown profile: $1" >&2; exit 2 ;;
esac

if [ "${1:-}" = "--off" ]; then
    tc qdisc del dev "$DEV" root 2>/dev/null || true
    tc qdisc del dev "$DEV" ingress 2>/dev/null || true
    ip link del "$IFB" 2>/dev/null || true
    echo "impairment removed from $DEV"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "this needs root: sudo sh $0 $*" >&2
    exit 1
fi

modprobe ifb numifbs=0 2>/dev/null || modprobe ifb 2>/dev/null || true
ip link del "$IFB" 2>/dev/null || true
ip link add "$IFB" type ifb
ip link set "$IFB" up

# Egress: what the kernel sends us.
tc qdisc del dev "$DEV" root 2>/dev/null || true
# shellcheck disable=SC2086 # NETEM is a list of netem arguments
tc qdisc add dev "$DEV" root netem $NETEM limit "$LIMIT"

# Ingress: what we send the kernel, redirected so it can have a qdisc.
tc qdisc del dev "$DEV" ingress 2>/dev/null || true
tc qdisc add dev "$DEV" handle ffff: ingress
tc filter add dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev "$IFB"
# shellcheck disable=SC2086
tc qdisc add dev "$IFB" root netem $NETEM limit "$LIMIT"

echo "$DEV impaired both ways: $NETEM, limit $LIMIT"
echo
echo "next:  USERNET_TUN_NETEM=1 uv run pytest tests/conformance -v"
