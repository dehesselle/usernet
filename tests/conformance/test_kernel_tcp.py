"""Our TCP against Linux TCP.

This is the layer the vnet suite cannot reach. There, two instances of our own
stack talk to each other, so a shared misreading of RFC 9293 passes every
assertion on both sides. Here the peer is a kernel that has been interoperating
since 1991 and has no interest in agreeing with us.

Each test states what a *disagreement* would look like, because that is the
failure this suite exists to catch.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Iterator

import pytest

from tests.conformance.conftest import HOST_IP, IMPAIRED, within
from tests.conformance.trace import PacketTrace
from usernet.errors import ConnectionRefused, NetworkError
from usernet.net.ipv4 import PROTO_TCP, parse_ipv4
from usernet.net.tcp import Flag, TcpSegment, parse_tcp
from usernet.runtime.driver import Driver

pytestmark = pytest.mark.linux_only

needs_clean_link = pytest.mark.skipif(
    IMPAIRED, reason="USERNET_TUN_NETEM is set: loss makes packet counts meaningless"
)

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
Serve = Callable[[Handler], Awaitable[int]]


def payload(size: int) -> bytes:
    """A deterministic body big enough to need many segments."""
    unit = b"usernet-conformance-payload-"
    return (unit * (size // len(unit) + 1))[:size]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def tcp_segments(trace: PacketTrace, *, outbound: bool | None = None) -> Iterator[TcpSegment]:
    """Every TCP segment in the trace, parsed off the wire."""
    for was_outbound, packet in trace.packets:
        if outbound is not None and was_outbound != outbound:
            continue
        header, body = parse_ipv4(packet)
        if header.protocol == PROTO_TCP:
            yield parse_tcp(body)


# --- handshake and teardown --------------------------------------------------


async def test_the_kernel_completes_our_handshake(driver: Driver, serve: Serve) -> None:
    """The whole suite rests on this: if the kernel will not answer our SYN,
    our SYN is malformed in some way no self-test could reveal."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    port = await within(5, "the kernel-side listener to start", serve(handler))
    stream = await within(10, f"the handshake with {HOST_IP}:{port}", driver.connect(HOST_IP, port))
    assert stream.connected.is_set()
    stream.close()


async def test_window_scaling_is_negotiated(
    driver: Driver, serve: Serve, trace: PacketTrace
) -> None:
    """Linux offers window scaling on every connection. If we failed to parse
    or echo the option the transfer would still work, just capped at 64 KiB --
    a performance bug that no correctness assertion would ever notice."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    stream.close()

    ours = [s for s in tcp_segments(trace, outbound=True) if s.flags & Flag.SYN]
    theirs = [
        s for s in tcp_segments(trace, outbound=False) if s.flags & Flag.SYN and s.flags & Flag.ACK
    ]
    assert ours and ours[0].window_scale is not None, "our SYN offered no window scale"
    assert theirs, "the kernel never sent a SYN-ACK"
    assert theirs[0].window_scale is not None, (
        "the kernel declined window scaling, which it does only when the "
        "option in our SYN was malformed"
    )


async def test_a_closed_port_is_refused_rather_than_timing_out(
    driver: Driver, closed_port: int
) -> None:
    """The kernel answers a SYN to a dead port with a RST. Reading that as
    anything but a refusal costs 15 seconds and reports the wrong cause."""
    with pytest.raises(ConnectionRefused):
        await within(10, "the RST", driver.connect(HOST_IP, closed_port, timeout=8))


async def test_the_peer_closing_first_is_seen_as_eof(driver: Driver, serve: Serve) -> None:
    """CLOSE_WAIT driven by a real FIN rather than by our own test peer."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"done")
        await writer.drain()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    body = await within(10, "the body and the peer's FIN", stream.read_all())
    assert body == b"done"
    stream.close()


async def test_our_close_is_completed_by_the_kernel(driver: Driver, serve: Serve) -> None:
    """We close first, so the kernel must see a well-formed FIN and finish the
    exchange. A FIN with a wrong sequence number produces a RST instead, which
    is what this would catch."""
    finished = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read()  # returns b"" once our FIN arrives
        finished.set()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    stream.close()
    await within(10, "the kernel to see our FIN", finished.wait())


async def test_half_close_lets_the_peer_keep_sending(driver: Driver, serve: Serve) -> None:
    """The shape every request/response protocol uses, and the one that broke
    `usernet nc`: shutting down our write direction must not stop the peer's."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.read()  # read to our EOF, then answer
        writer.write(b"received " + str(len(request)).encode())
        await writer.drain()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    await within(10, "the request", stream.write(b"x" * 100))
    stream.close()  # FIN only; the peer replies afterwards
    body = await within(10, "the reply after our FIN", stream.read_all())
    assert body == b"received 100"


# --- data transfer -----------------------------------------------------------


async def test_a_request_and_response_round_trip(driver: Driver, serve: Serve) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = await reader.readline()
        writer.write(b"echo:" + line)
        await writer.drain()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    await within(10, "the request", stream.write(b"hello\n"))
    body = await within(10, "the response", stream.read_all())
    assert body == b"echo:hello\n"


@pytest.mark.slow
@pytest.mark.timeout(180)
async def test_bulk_send_arrives_byte_exact(driver: Driver, serve: Serve, link: object) -> None:
    """One megabyte into a real receiver. Exercises cwnd growth, the peer's
    advertised window, and our retransmission, judged by a stack that will not
    accept a byte out of order."""
    size = 1024 * 1024
    body = payload(size)
    received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(-1)
        if not received.done():
            received.set_result(data)
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    await within(120, f"{size} bytes to be accepted", stream.write(body))
    stream.close()

    arrived = await within(60, "the kernel to report what it received", received)
    assert len(arrived) == size, f"kernel received {len(arrived)} of {size} bytes"
    assert digest(arrived) == digest(body), "the bytes arrived corrupted or reordered"
    assert getattr(link, "oversized", 0) == 0, "we emitted a packet larger than the MTU"


@pytest.mark.slow
@pytest.mark.timeout(180)
async def test_bulk_receive_arrives_byte_exact(driver: Driver, serve: Serve) -> None:
    """Two megabytes from a real sender -- the direction that tests *us*.

    Linux will fill our advertised window and keep it full, so this is where a
    mistake in reassembly, window accounting or delayed ACK shows up as a stall
    rather than as a wrong byte.
    """
    size = 2 * 1024 * 1024
    body = payload(size)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(body)
        await writer.drain()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    arrived = await within(120, f"{size} bytes from the kernel", stream.read_all(limit=size + 1))
    assert len(arrived) == size, f"received {len(arrived)} of {size} bytes"
    assert digest(arrived) == digest(body)


@pytest.mark.slow
@pytest.mark.timeout(180)
@needs_clean_link
async def test_a_bulk_send_does_not_storm(
    driver: Driver, serve: Serve, trace: PacketTrace, tun_mtu: int
) -> None:
    """Correctness assertions pass happily while a stack retransmits everything
    twice. Counting packets is what catches that -- and an ACK loop, which
    otherwise looks like success with a bad throughput number."""
    size = 512 * 1024
    body = payload(size)
    done = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(-1)
        done.set()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    await within(120, "the transfer", stream.write(body))
    stream.close()
    await within(60, "the peer to finish reading", done.wait())

    ideal = size / (tun_mtu - 40)
    assert trace.sent < ideal * 1.5, (
        f"sent {trace.sent} packets for {size} bytes; about {ideal:.0f} would do. "
        f"That ratio means retransmission on a lossless link."
    )


# --- many connections --------------------------------------------------------


async def test_connections_can_be_opened_repeatedly(driver: Driver, serve: Serve) -> None:
    """Ephemeral port reuse against a kernel that keeps its own TIME_WAIT and
    will RST a reused four-tuple it still remembers."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"ok")
        await writer.drain()
        writer.close()

    port = await within(5, "the listener", serve(handler))
    for attempt in range(20):
        stream = await within(10, f"handshake {attempt + 1} of 20", driver.connect(HOST_IP, port))
        body = await within(10, f"the reply on connection {attempt + 1}", stream.read_all())
        assert body == b"ok", f"connection {attempt + 1} returned {body!r}"
        stream.close()


@pytest.mark.timeout(60)
async def test_connections_can_be_opened_concurrently(driver: Driver, serve: Serve) -> None:
    """Eight at once through one stack: demultiplexing by four-tuple, with a
    real peer choosing its own ports and sequence numbers."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.readline()
        writer.write(b"pong:" + request)
        await writer.drain()
        writer.close()

    port = await within(5, "the listener", serve(handler))

    async def exchange(index: int) -> bytes:
        stream = await driver.connect(HOST_IP, port, timeout=15)
        await stream.write(f"{index}\n".encode())
        body = await stream.read_all()
        stream.close()
        return body

    results = await within(
        45, "eight concurrent exchanges", asyncio.gather(*(exchange(i) for i in range(8)))
    )
    assert sorted(results) == sorted(f"pong:{i}\n".encode() for i in range(8))


# --- error paths -------------------------------------------------------------


async def test_a_reset_mid_connection_surfaces_as_an_error(driver: Driver, serve: Serve) -> None:
    """SO_LINGER 0 makes the kernel send a RST instead of a FIN. We must report
    it as an error rather than as a clean end of stream, or a truncated
    response silently looks complete."""
    import socket
    import struct

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(1)
        raw = writer.get_extra_info("socket")
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.transport.abort()

    port = await within(5, "the listener", serve(handler))
    stream = await within(10, "the handshake", driver.connect(HOST_IP, port))
    await within(10, "the write", stream.write(b"go"))

    with pytest.raises(NetworkError):
        await within(15, "the RST to be reported", stream.read_all())
