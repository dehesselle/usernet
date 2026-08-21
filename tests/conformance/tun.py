"""A Linux tun device presented as an :class:`~usernet.link.IpLink`.

The payoff of the layering: the driver, the stack and every socket operation
are the shipping code, unmodified. Only the bottom 40 lines change -- instead
of CSTP frames over TLS, raw IP packets go to a kernel interface, where a real
Linux TCP implementation answers them.

Linux only. Importing this module on any other platform fails at ``fcntl``,
which is why ``conftest.py`` refuses to collect this package elsewhere.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import struct
from types import TracebackType

from usernet.link import SimpleLinkConfig
from tests.conformance.trace import PacketTrace

# <linux/if_tun.h>. TUNSETIFF is _IOW('T', 202, int).
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# struct ifreq: 16 bytes of name, the flags, then padding out to 40.
IFREQ = struct.Struct("16sH22s")

TUN_PATH = "/dev/net/tun"

# Read at most this many packets per readable callback before yielding back to
# the event loop, so a fast sender cannot starve the driver that consumes them.
READ_BATCH = 64


class TunSetupError(RuntimeError):
    """The device could not be opened, with an explanation of what to do."""


class TunDevice:
    """An open file descriptor on a persistent tun interface.

    The interface itself is created out of band -- see ``setup.sh`` -- because
    that needs root and a test suite should not.
    """

    def __init__(self, name: str = "pyac0") -> None:
        self.name = name
        self.fd = self._open(name)

    @staticmethod
    def _open(name: str) -> int:
        try:
            fd = os.open(TUN_PATH, os.O_RDWR)
        except FileNotFoundError as exc:
            raise TunSetupError(
                f"{TUN_PATH} does not exist -- the tun module is not loaded. Run: sudo modprobe tun"
            ) from exc
        except PermissionError as exc:
            raise TunSetupError(
                f"no permission to open {TUN_PATH}. Run: sudo sh tests/conformance/setup.sh, "
                f"which creates the interface owned by your user."
            ) from exc

        request = IFREQ.pack(name.encode(), IFF_TUN | IFF_NO_PI, b"")
        try:
            fcntl.ioctl(fd, TUNSETIFF, request)
        except OSError as exc:
            os.close(fd)
            raise TunSetupError(
                f"could not attach to tun device {name!r} ({exc}). "
                f"Run: sudo sh tests/conformance/setup.sh to create it, or "
                f"'uv run python -m tests.conformance.preflight' to see what is missing."
            ) from exc

        os.set_blocking(fd, False)
        return fd

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class TunLink:
    """:class:`~usernet.link.IpLink` over a tun file descriptor."""

    def __init__(
        self,
        device: TunDevice,
        config: SimpleLinkConfig,
        trace: PacketTrace | None = None,
    ) -> None:
        self._device = device
        self._config = config
        self._trace = trace
        self._inbound: list[bytes] = []
        self._wake = asyncio.Event()
        self._closed = asyncio.Event()
        self._close_reason = ""
        self._reading = False

        self.dropped = 0
        """Writes the kernel refused because the interface queue was full.
        A real link drops too, so this is counted rather than raised -- but a
        non-zero value explains an otherwise mysterious retransmission."""

        self.oversized = 0
        """Packets we emitted larger than the MTU. Must stay zero: this is the
        silent-hang bug from the risk list, caught directly."""

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        asyncio.get_running_loop().add_reader(self._device.fd, self._readable)
        self._reading = True

    async def aclose(self) -> None:
        if self._reading:
            asyncio.get_running_loop().remove_reader(self._device.fd)
            self._reading = False
        self._closed.set()

    async def __aenter__(self) -> TunLink:
        self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- IpLink ------------------------------------------------------------

    @property
    def config(self) -> SimpleLinkConfig:
        return self._config

    @property
    def wake(self) -> asyncio.Event:
        return self._wake

    @property
    def closed(self) -> asyncio.Event:
        return self._closed

    @property
    def close_reason(self) -> str:
        return self._close_reason

    def send(self, packet: bytes) -> None:
        if len(packet) > self._config.mtu:
            self.oversized += 1
        if self._trace is not None:
            self._trace.record(True, packet)
        try:
            os.write(self._device.fd, packet)
        except BlockingIOError:
            self.dropped += 1
        except OSError as exc:  # the interface went away mid-test
            self._close_reason = f"tun write failed: {exc}"
            self._closed.set()

    def take_inbound(self) -> list[bytes]:
        # Cleared before the swap, and there is no await between the two, so a
        # packet arriving in between cannot be left unannounced.
        self._wake.clear()
        packets, self._inbound = self._inbound, []
        return packets

    # --- the reader --------------------------------------------------------

    def _readable(self) -> None:
        for _ in range(READ_BATCH):
            try:
                packet = os.read(self._device.fd, 65535)
            except BlockingIOError:
                break
            except OSError as exc:
                self._close_reason = f"tun read failed: {exc}"
                self._closed.set()
                return
            if not packet:
                break
            if self._trace is not None:
                self._trace.record(False, packet)
            self._inbound.append(packet)
        self._wake.set()
