#!/bin/sh
# Degrade both directions of the tun link, for the conformance run that
# actually exercises loss recovery.
#
#   sudo sh tests/conformance/impair.sh [delay] [loss]
#   sudo sh tests/conformance/impair.sh --off
#
# A plain `tc qdisc add dev pyac0 root netem ...` is not enough, and the way it
# falls short is invisible: a root qdisc is EGRESS only, so it degrades
# kernel->us and leaves our own packets untouched. Our retransmission -- the
# code most likely to be wrong, and the reason for impairing anything -- is
# then never exercised. Ingress has to be redirected through an ifb device to
# get a qdisc on it at all.

set -eu

DEV=${PYAC_TUN_DEV:-pyac0}
IFB=ifb-pyac
DELAY=${1:-20ms}
LOSS=${2:-2%}

# netem's default queue is 1000 packets, which is itself a bandwidth limit:
# a link holds delay x rate packets in flight, so at 150ms RTT anything past
# a ~1 MiB window overflows the qdisc and the losses look like a bug in the
# thing under test. Raised well clear of any window we would configure.
LIMIT=${PYAC_NETEM_LIMIT:-50000}

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
tc qdisc add dev "$DEV" root netem delay "$DELAY" loss "$LOSS" limit "$LIMIT"

# Ingress: what we send the kernel, redirected so it can have a qdisc.
tc qdisc del dev "$DEV" ingress 2>/dev/null || true
tc qdisc add dev "$DEV" handle ffff: ingress
tc filter add dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev "$IFB"
tc qdisc add dev "$IFB" root netem delay "$DELAY" loss "$LOSS" limit "$LIMIT"

echo "$DEV impaired both ways: delay $DELAY, loss $LOSS"
echo
echo "next:  PYAC_TUN_NETEM=1 uv run pytest tests/conformance -v"
