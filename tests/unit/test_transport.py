"""``StackTransport``: the bridge that makes the stack look like a socket.

Driven against a fake :class:`ByteStream` rather than a real tunnel, because
what needs proving here is the *transport contract* -- when the protocol's
callbacks fire, and what flow control does -- not that TCP works. The tunnel
end of it is covered by tests/integration/test_api.py.
"""

from __future__ import annotations

import asyncio

import pytest

from usernet.runtime.transport import StackTransport, wrap_stream


class FakeStream:
    """A byte stream under the test's control, in both directions."""

    def __init__(self, *, inbound: list[bytes] | None = None) -> None:
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        for chunk in inbound or []:
            self._inbound.put_nowait(chunk)
        self.written = bytearray()
        self.closed = False
        self.aborted = False
        self.write_gate = asyncio.Event()
        self.write_gate.set()

    async def read(self, size: int = 65536) -> bytes:
        return await self._inbound.get()

    async def write(self, data: bytes) -> None:
        await self.write_gate.wait()
        self.written += data

    def close(self) -> None:
        self.closed = True

    def abort(self) -> None:
        self.aborted = True
        self.closed = True

    # --- test control ------------------------------------------------------

    def deliver(self, data: bytes) -> None:
        self._inbound.put_nowait(data)

    def end(self) -> None:
        self._inbound.put_nowait(b"")


class RecordingProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.transport: asyncio.BaseTransport | None = None
        self.data = bytearray()
        self.eof = False
        self.lost = asyncio.Event()
        self.error: BaseException | None = None
        self.pauses = 0
        self.resumes = 0
        self.keep_open_on_eof = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        self.data += data

    def eof_received(self) -> bool:
        self.eof = True
        return self.keep_open_on_eof

    def connection_lost(self, exc: Exception | None) -> None:
        self.error = exc
        self.lost.set()

    def pause_writing(self) -> None:
        self.pauses += 1

    def resume_writing(self) -> None:
        self.resumes += 1


async def settle(times: int = 4) -> None:
    """Let the pump tasks run; they are ordinary tasks, not magic."""
    for _ in range(times):
        await asyncio.sleep(0)


# --- the protocol callbacks --------------------------------------------------


async def test_connection_made_fires_before_anything_else() -> None:
    """A StreamWriter is built on the line after the transport, so the reader
    must already be attached by the time the constructor returns."""
    stream = FakeStream()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)

    assert protocol.transport is transport
    transport.abort()


async def test_inbound_data_reaches_the_protocol() -> None:
    stream = FakeStream(inbound=[b"hello ", b"world"])
    protocol = RecordingProtocol()
    StackTransport(stream, protocol)

    await settle()
    assert bytes(protocol.data) == b"hello world"


async def test_end_of_stream_reports_eof_then_closes() -> None:
    stream = FakeStream(inbound=[b"tail"])
    protocol = RecordingProtocol()
    StackTransport(stream, protocol)
    stream.end()

    await asyncio.wait_for(protocol.lost.wait(), timeout=2)
    assert protocol.eof
    assert protocol.error is None


async def test_a_protocol_may_keep_the_transport_open_after_eof() -> None:
    """Returning True from eof_received is how half close is expressed, and it
    is what lets a request/response protocol answer after the peer is done."""
    stream = FakeStream()
    protocol = RecordingProtocol()
    protocol.keep_open_on_eof = True
    transport = StackTransport(stream, protocol)
    stream.end()

    await settle()
    assert protocol.eof
    assert not protocol.lost.is_set()
    assert not transport.is_closing()
    transport.abort()


async def test_a_stream_failure_becomes_connection_lost() -> None:
    class Broken(FakeStream):
        async def read(self, size: int = 65536) -> bytes:
            raise ConnectionResetError("peer went away")

    protocol = RecordingProtocol()
    StackTransport(Broken(), protocol)

    await asyncio.wait_for(protocol.lost.wait(), timeout=2)
    assert isinstance(protocol.error, ConnectionResetError)


async def test_connection_lost_is_reported_once() -> None:
    stream = FakeStream()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)
    calls = 0

    def count(exc: Exception | None) -> None:
        nonlocal calls
        calls += 1
        protocol.lost.set()

    protocol.connection_lost = count  # type: ignore[method-assign]
    transport.abort()
    transport.abort()
    transport.close()
    await settle()

    assert calls == 1


# --- writing -----------------------------------------------------------------


async def test_written_data_reaches_the_stream() -> None:
    stream = FakeStream()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)

    transport.write(b"one")
    transport.write(b"two")
    await settle()

    assert bytes(stream.written) == b"onetwo"
    transport.abort()


async def test_writing_past_the_high_water_mark_pauses_the_protocol() -> None:
    """This is what makes StreamWriter.drain wait, and therefore what stops an
    application outrunning the tunnel."""
    stream = FakeStream()
    stream.write_gate.clear()  # nothing drains until the test says so
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)
    transport.set_write_buffer_limits(high=1024, low=256)

    transport.write(b"x" * 4096)
    assert protocol.pauses == 1
    assert transport.get_write_buffer_size() == 4096

    stream.write_gate.set()
    await settle(8)
    assert protocol.resumes == 1
    assert transport.get_write_buffer_size() == 0
    transport.abort()


async def test_write_buffer_limits_are_validated() -> None:
    stream = FakeStream()
    transport = StackTransport(stream, RecordingProtocol())
    with pytest.raises(ValueError):
        transport.set_write_buffer_limits(high=10, low=100)
    transport.abort()


async def test_close_flushes_what_was_already_written() -> None:
    """A graceful close must not discard buffered data; that is what abort is
    for, and confusing the two truncates the last response of every session."""
    stream = FakeStream()
    stream.write_gate.clear()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)

    transport.write(b"important")
    transport.close()
    stream.write_gate.set()

    await asyncio.wait_for(protocol.lost.wait(), timeout=2)
    assert bytes(stream.written) == b"important"


async def test_abort_discards_and_resets() -> None:
    stream = FakeStream()
    stream.write_gate.clear()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)

    transport.write(b"never sent")
    transport.abort()

    await asyncio.wait_for(protocol.lost.wait(), timeout=2)
    assert stream.aborted
    assert bytes(stream.written) == b""


async def test_write_eof_half_closes_after_the_buffer_drains() -> None:
    """The FIN has to follow the data, not overtake it."""
    stream = FakeStream()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)

    transport.write(b"request")
    transport.write_eof()
    await settle(6)

    assert bytes(stream.written) == b"request"
    assert stream.closed
    assert not protocol.lost.is_set(), "half close must not end the connection"
    transport.abort()


async def test_writes_after_close_are_ignored_rather_than_raising() -> None:
    """asyncio transports drop late writes; raising here would turn a benign
    race in a protocol into a crash."""
    stream = FakeStream()
    transport = StackTransport(stream, RecordingProtocol())
    transport.close()
    transport.write(b"too late")
    await settle()

    assert bytes(stream.written) == b""


# --- reading and flow control ------------------------------------------------


async def test_pausing_reads_stops_draining_the_stream() -> None:
    """Which is the whole design: while paused nothing is buffered on our
    behalf, so the receive window shuts and the peer stops sending."""
    stream = FakeStream()
    protocol = RecordingProtocol()
    transport = StackTransport(stream, protocol)
    await settle()

    transport.pause_reading()
    assert not transport.is_reading()
    stream.deliver(b"while paused")
    await settle(6)
    assert bytes(protocol.data) == b""

    transport.resume_reading()
    await settle(6)
    assert bytes(protocol.data) == b"while paused"
    transport.abort()


# --- the stdlib pairing ------------------------------------------------------


async def test_wrap_stream_produces_a_working_reader_and_writer() -> None:
    """The payoff: anything written against asyncio.open_connection works."""
    stream = FakeStream(inbound=[b"HTTP/1.1 200 OK\r\n", b"\r\n"])
    reader, writer = await wrap_stream(stream, peername=("10.0.0.1", 80))

    writer.write(b"GET / HTTP/1.1\r\n\r\n")
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), timeout=2)

    assert line == b"HTTP/1.1 200 OK\r\n"
    assert bytes(stream.written) == b"GET / HTTP/1.1\r\n\r\n"
    assert writer.get_extra_info("peername") == ("10.0.0.1", 80)
    writer.transport.abort()


async def test_reader_sees_eof_as_an_empty_read() -> None:
    stream = FakeStream(inbound=[b"body"])
    reader, _writer = await wrap_stream(stream)
    stream.end()

    assert await asyncio.wait_for(reader.read(), timeout=2) == b"body"
    assert await asyncio.wait_for(reader.read(), timeout=2) == b""
