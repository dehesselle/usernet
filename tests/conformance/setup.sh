#!/bin/sh
# Create the tun device the L3 conformance suite drives.
#
# Root is needed to create the interface and give it an address; it is not
# needed to run the tests, because the device is created owned by the invoking
# user. Run this once per boot (the device does not survive a reboot).
#
#   sudo tests/conformance/setup.sh
#   tests/conformance/setup.sh --down     # remove it again
#
# The addresses match tests/conformance/conftest.py: the kernel answers on
# 10.99.0.1 and our stack lives at 10.99.0.2.

set -eu

DEV=${USERNET_TUN_DEV:-usernet0}
HOST_IP=${USERNET_TUN_HOST:-10.99.0.1}
PREFIX=24
MTU=1500

if [ "${1:-}" = "--down" ]; then
    ip link del "$DEV" 2>/dev/null || true
    echo "removed $DEV"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "this needs root: sudo $0" >&2
    exit 1
fi

# The user who will run pytest. Under sudo, SUDO_USER is that person, not root.
OWNER=${SUDO_USER:-$(id -un)}

ip link del "$DEV" 2>/dev/null || true
ip tuntap add dev "$DEV" mode tun user "$OWNER"
ip addr add "$HOST_IP/$PREFIX" dev "$DEV"
ip link set dev "$DEV" mtu "$MTU"
ip link set dev "$DEV" up

echo "created $DEV ($HOST_IP/$PREFIX, mtu $MTU) owned by $OWNER"
echo
echo "next:  uv run python -m tests.conformance.preflight"
