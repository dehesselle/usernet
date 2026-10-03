"""A SOCKS5 proxy in front of the tunnel.

This is how ordinary tools reach the VPN: ``curl --socks5``, a browser, or
``ssh`` through a proxy-aware ``ProxyCommand``. Nothing they do requires them
to know a tunnel exists.

**The listener is an unauthenticated hole into the corporate network for every
process on the machine.** That is the security story of this whole file, and
why it binds loopback, refuses anything else without an explicit flag, and
offers RFC 1929 credentials.

Backpressure works because neither direction buffers. Client to tunnel blocks
in ``TcpStream.write`` until the peer's window allows more; tunnel to client
calls ``drain()`` before reading again, so a slow client leaves bytes in the
stack's receive buffer, which shrinks the advertised window and makes the peer
stop sending. Copying either direction into a queue would silently undo it.

**Names are resolved by the tunnel or not at all.** A SOCKS5 request may carry
a hostname instead of an address, and the whole point of ``socks5h://`` is that
the *proxy* resolves it. Which resolver that should be is a property of the
tunnel -- MagicDNS for a tailnet, whatever the gateway advertises for a VPN,
a fixed table for one that offers none -- so it arrives as a ``resolver``
callable (the driver's, by default) rather than being decided here. With none,
names are refused. Falling back to the host's own DNS would be actively wrong:
it would send tunnel-destined traffic to whatever public record happened to
match the name.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import ipaddress
import logging
from types import TracebackType

from usernet.errors import NetworkError, ProtocolParseError, ResolveError
from usernet.resolve import Resolver
from usernet.routing import describe_routes, route_allows
from usernet.runtime.driver import Driver, TcpStream
from usernet.socks.protocol import (
    AUTH_UNACCEPTABLE,
    AUTH_USERPASS,
    CMD_CONNECT,
    REQUEST_PREFIX,
    VERSION,
    Reply,
    Request,
    SocksRejection,
    build_auth_reply,
    build_method_reply,
    build_reply,
    choose_method,
    parse_request,
    parse_userpass,
    reply_for,
    request_length,
)

log = logging.getLogger("usernet.socks")

RELAY_CHUNK = 65536


class Socks5Server:
    """CONNECT-only SOCKS5, serving one :class:`~usernet.runtime.driver.Driver`."""

    def __init__(
        self,
        driver: Driver,
        *,
        host: str = "127.0.0.1",
        port: int = 1080,
        username: str | None = None,
        password: str | None = None,
        allow_non_loopback: bool = False,
        connect_timeout: float = 30.0,
        route_policy: str = "auto",
        resolver: Resolver | None = None,
    ) -> None:
        self._driver = driver
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._connect_timeout = connect_timeout
        self._route_policy = route_policy
        # The driver's resolver unless this proxy was given its own.
        self._resolver = resolver if resolver is not None else driver.resolver
        self._server: asyncio.Server | None = None
        self._bound_port = port
        self._handlers: set[asyncio.Task[None]] = set()

        if not allow_non_loopback and not _is_loopback(host):
            raise NetworkError(
                f"refusing to bind {host}: a SOCKS listener on a non-loopback address "
                f"lets anything that can reach this machine into the VPN. Pass "
                f"allow_non_loopback (--socks-allow-remote) and set credentials if "
                f"that is genuinely what you want."
            )

        self.connections = 0
        self.rejected = 0
        self.active = 0
        # Live relays, by the destination the *client* asked for: the stream's
        # own peer is the resolved address, which is not what anyone typed.
        self.relays: dict[TcpStream, str] = {}

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        self._bound_port = int(self._server.sockets[0].getsockname()[1])

    @property
    def port(self) -> int:
        """The bound port, which matters when 0 was requested."""
        assert self._server is not None
        return self._bound_port

    @property
    def address(self) -> str:
        return f"{self._host}:{self.port}"

    async def aclose(self, grace: float = 2.0) -> None:
        """Stop listening, then tear down whatever is still connected.

        Bounded on purpose, in both directions. ``Server.wait_closed`` waits
        for in-flight handlers from Python 3.12 on, so waiting on it alone
        means an idle SSH session makes Ctrl-C on ``usernet up`` do nothing at
        all. Cancelling immediately is no better: a relay that is *already*
        finishing gets a RST instead of its FIN exchange. So give them ``grace``
        seconds to end by themselves, then cancel the stragglers.
        """
        if self._server is None:
            return
        self._server.close()

        if self._handlers:
            _done, pending = await asyncio.wait(set(self._handlers), timeout=grace)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        with contextlib.suppress(Exception):
            async with asyncio.timeout(grace):
                await self._server.wait_closed()
        self._server = None

    async def __aenter__(self) -> Socks5Server:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- one client --------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self.active += 1
        stream: TcpStream | None = None
        relayed = False
        # Tracked so shutdown can cancel a relay rather than wait on one.
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        try:
            await self._negotiate(reader, writer)
            request = await self._read_request(reader)
            stream = await self._open(request)

            # BND.ADDR is informational for CONNECT; reporting the tunnel
            # address makes a proxy log line correlate with a pcap.
            writer.write(build_reply(Reply.SUCCESS, self._driver.link.config.address, request.port))
            await writer.drain()
            log.info("socks: %s:%d connected", request.host, request.port)
            self.relays[stream] = f"{request.host}:{request.port}"

            await self._relay(stream, reader, writer)
            relayed = True
        except SocksRejection as exc:
            self.rejected += 1
            log.warning("socks: rejected (%s): %s", exc.reply.name, exc)
            await self._refuse(writer, exc.reply)
        except NetworkError as exc:
            self.rejected += 1
            log.warning("socks: connection failed: %s", exc)
            await self._refuse(writer, reply_for(exc))
        except (ProtocolParseError, asyncio.IncompleteReadError) as exc:
            self.rejected += 1
            log.warning("socks: malformed client request: %s", exc)
        except ConnectionError:
            pass  # a client hanging up mid-negotiation is routine
        finally:
            self.active -= 1
            if stream is not None:
                self.relays.pop(stream, None)
            if task is not None:
                self._handlers.discard(task)
            if stream is not None and not relayed:
                # Only an abandoned connection gets a RST. Resetting one that
                # just closed cleanly would undo the FIN exchange, skip
                # TIME_WAIT, and make every SSH session end in the server's log
                # as an abnormal disconnect.
                stream.abort()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _refuse(self, writer: asyncio.StreamWriter, reply: Reply) -> None:
        with contextlib.suppress(OSError, ConnectionError):
            writer.write(build_reply(reply))
            await writer.drain()

    # --- negotiation -------------------------------------------------------

    async def _negotiate(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, count = await reader.readexactly(2)
        if version != VERSION:
            raise ProtocolParseError(f"client offered SOCKS version {version}, not 5")

        methods = await reader.readexactly(count)
        method = choose_method(methods, require_auth=self._username is not None)
        writer.write(build_method_reply(method))
        await writer.drain()

        if method == AUTH_UNACCEPTABLE:
            raise ProtocolParseError(
                "no acceptable authentication method"
                + (" (this listener requires a username and password)" if self._username else "")
            )
        if method == AUTH_USERPASS:
            await self._authenticate(reader, writer)

    async def _authenticate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        prefix = await reader.readexactly(2)
        data = prefix + await reader.readexactly(prefix[1] + 1)
        data += await reader.readexactly(data[2 + prefix[1]])
        username, password = parse_userpass(data)

        # Constant time, and both halves compared before combining, so neither
        # the outcome nor the timing reveals which one was wrong.
        expected_user = self._username or ""
        expected_pass = self._password or ""
        user_ok = hmac.compare_digest(username.encode(), expected_user.encode())
        pass_ok = hmac.compare_digest(password.encode(), expected_pass.encode())
        accepted = user_ok and pass_ok

        writer.write(build_auth_reply(accepted))
        await writer.drain()
        if not accepted:
            raise ProtocolParseError(f"bad credentials for {username!r}")

    async def _read_request(self, reader: asyncio.StreamReader) -> Request:
        prefix = await reader.readexactly(REQUEST_PREFIX)
        rest = await reader.readexactly(request_length(prefix) - REQUEST_PREFIX)
        return parse_request(prefix + rest)

    async def _open(self, request: Request) -> TcpStream:
        if request.command != CMD_CONNECT:
            raise SocksRejection(
                Reply.COMMAND_NOT_SUPPORTED,
                f"command {request.command} needs the proxy to accept inbound "
                f"connections, which a client-only stack cannot do",
            )
        host = request.host
        if request.is_name:
            if self._resolver is None:
                raise SocksRejection(
                    Reply.HOST_UNREACHABLE,
                    f"cannot resolve {host!r}: this tunnel advertises no DNS servers, "
                    f"so there is nothing to resolve against. Use an address, or "
                    f"--socks5 rather than --socks5-hostname.",
                )
            try:
                host = await self._resolver(host)
            except ResolveError as exc:
                # The resolver's message, not ours: it knows which names it
                # serves and this class does not.
                raise SocksRejection(Reply.HOST_UNREACHABLE, str(exc)) from None
            log.debug("socks: resolved %s to %s", request.host, host)

        config = self._driver.link.config
        if self._route_policy == "auto" and not route_allows(config, host):
            where = request.host if host == request.host else f"{request.host} ({host})"
            raise SocksRejection(
                Reply.NOT_ALLOWED,
                f"{where} is outside the tunnel's routes "
                f"({describe_routes(config)}); packets would be discarded with no error",
            )

        return await self._driver.connect(host, request.port, timeout=self._connect_timeout)

    # --- relaying ----------------------------------------------------------

    async def _relay(
        self, stream: TcpStream, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Pump both directions until each reaches its end.

        A failure in either -- the tunnel dropping, the client vanishing --
        ends this connection and nothing else. The group is caught here rather
        than in the caller so one broken relay cannot take down the listener.
        """
        try:
            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(self._to_tunnel(stream, reader), name="socks-upstream")
                tasks.create_task(self._to_client(stream, writer), name="socks-downstream")
        except* ConnectionError:
            pass
        except* Exception as group:
            log.warning("socks: relay ended early: %s", group.exceptions)

    async def _to_tunnel(self, stream: TcpStream, reader: asyncio.StreamReader) -> None:
        while True:
            data = await reader.read(RELAY_CHUNK)
            if not data:
                break
            # Blocks until the peer's window has room, which back-pressures the
            # local client's socket rather than buffering here.
            await stream.write(data)
        stream.close()  # half close: the client is done talking, we may not be

    async def _to_client(self, stream: TcpStream, writer: asyncio.StreamWriter) -> None:
        while True:
            data = await stream.read(RELAY_CHUNK)
            if not data:
                break
            writer.write(data)
            # Before the next read, never after: this is what leaves unread
            # bytes in the stack's buffer and keeps the receive window honest.
            await writer.drain()
        with contextlib.suppress(OSError, ConnectionError):
            writer.write_eof()


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
