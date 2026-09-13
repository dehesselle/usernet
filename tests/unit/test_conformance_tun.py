"""The Linux-only bits of the tun helper, checked from anywhere.

``TUNSETIFF`` is a magic number and ``struct ifreq`` is a magic layout. Both
are wrong in exactly the same way when mistyped: the ioctl fails with EINVAL on
a machine the author cannot reach, and the whole conformance suite skips with a
message about the device not existing. Deriving them from first principles here
turns that into a failure anyone can see.
"""

from __future__ import annotations

import struct
import sys
import types

import pytest


@pytest.fixture
def tun(monkeypatch: pytest.MonkeyPatch) -> object:
    """Import the helper, standing in for ``fcntl`` where there is none.

    The point is to execute the module body -- constants, struct definitions,
    class bodies -- on every platform, not just the one that can run it.
    """
    if sys.platform != "linux":
        monkeypatch.setitem(sys.modules, "fcntl", types.SimpleNamespace(ioctl=lambda *a: None))
    import tests.conformance.tun as module

    return module


def ioctl_request(direction: int, kind: str, number: int, size: int) -> int:
    """``_IOC`` from <asm-generic/ioctl.h>, for the asm-generic architectures."""
    return (direction << 30) | (size << 16) | (ord(kind) << 8) | number


def test_the_tunsetiff_number_matches_the_kernel_macro(tun: object) -> None:
    """<linux/if_tun.h>: #define TUNSETIFF _IOW('T', 202, int)"""
    write = 1
    macro = ioctl_request(write, "T", 202, struct.calcsize("i"))
    assert macro == tun.TUNSETIFF


def test_the_ifreq_layout_is_the_size_the_kernel_expects(tun: object) -> None:
    """sizeof(struct ifreq) is 40 on 64-bit Linux: 16 bytes of name and a
    union the kernel reads past regardless of what we put in it."""
    assert tun.IFREQ.size == 40


def test_the_interface_name_is_packed_where_the_kernel_reads_it(tun: object) -> None:
    packed = tun.IFREQ.pack(b"usernet0", tun.IFF_TUN | tun.IFF_NO_PI, b"")
    assert packed[:9] == b"usernet0\x00"
    assert packed[16:18] == struct.pack("H", 0x1001)


def test_the_tun_link_satisfies_the_iplink_protocol(tun: object) -> None:
    """The claim the whole suite rests on: the driver and the stack are the
    shipping code, and only the link underneath is swapped. If TunLink drifts
    from IpLink the conformance run fails on Linux with an AttributeError deep
    in the driver; here it fails as one readable assertion.
    """
    from usernet.link import IpLink, SimpleLinkConfig

    device = types.SimpleNamespace(fd=-1, name="usernet0")
    config = SimpleLinkConfig(address="10.99.0.2", netmask="255.255.255.0", mtu=1500)
    link = tun.TunLink(device, config)

    assert isinstance(link, IpLink)
    assert link.config.address == "10.99.0.2"
    assert link.take_inbound() == []
    assert not link.closed.is_set()


def test_an_oversized_packet_is_counted_rather_than_sent_silently(tun: object) -> None:
    """MTU violations are the silent-hang failure from the risk list: the
    handshake works, small requests work, and anything larger disappears."""
    from usernet.link import SimpleLinkConfig

    device = types.SimpleNamespace(fd=-1, name="usernet0")
    config = SimpleLinkConfig(address="10.99.0.2", netmask="255.255.255.0", mtu=100)
    link = tun.TunLink(device, config)
    link.send(b"\x45" + b"\x00" * 200)  # os.write to fd -1 fails; the count is the point
    assert link.oversized == 1


def test_the_flags_request_a_tun_without_packet_information(tun: object) -> None:
    """IFF_TAP would deliver Ethernet frames and IFF_NO_PI's absence would
    prepend four bytes to every packet -- either turns our parser's first read
    into nonsense."""
    assert tun.IFF_TUN == 0x0001
    assert tun.IFF_NO_PI == 0x1000
