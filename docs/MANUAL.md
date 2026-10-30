# Manual

This manual covers using usernet as a library: supplying a tunnel, opening
connections, presenting them as asyncio streams, TLS, HTTP or SOCKS5, and the
helpers for logging, capture and tests.

For the reasoning behind the API, see [DESIGN.md](DESIGN.md). For defaults,
limits and failure behavior, see [OPERATIONS.md](OPERATIONS.md).

## Supplying a tunnel

Everything in usernet runs on an `IpLink` (in `usernet.link`). Any object with
these members satisfies it; no base class is needed.

| Member | Contract |
| --- | --- |
| `config` | a `LinkConfig`: the tunnel's current parameters |
| `wake` | an `asyncio.Event` that is set whenever inbound packets arrive |
| `send(packet)` | queues one IPv4 packet for the far side; must not block |
| `take_inbound()` | returns every packet received since the last call, and empties the queue |
| `closed` | an `asyncio.Event` that is set when the link is finished |
| `close_reason` | why the link closed, as a human-readable string |
| `aclose()` | shuts the link down cleanly |

`LinkConfig` is the part of the tunnel's configuration that the stack reads.
A tunnel's own configuration object can satisfy it directly.

| Property | Meaning |
| --- | --- |
| `address` | our address inside the tunnel, as a dotted quad |
| `netmask` | its netmask; `255.255.255.255` when there is no on-link subnet |
| `mtu` | the largest IP packet the tunnel carries |
| `split_include` | `IPv4Network`s the tunnel carries; empty means all of them |
| `split_exclude` | `IPv4Network`s it refuses; these override `split_include` |

`SimpleLinkConfig` is a frozen dataclass with these fields, for links that have
nothing else to say.

The driver reads `config.address` on every pass. If it changes (for example, a
reconnecting gateway assigned a new address), every open connection fails and
the stack is rebuilt for the new address. See
[OPERATIONS.md](OPERATIONS.md#failure-and-recovery).

## The driver

```python
from usernet import Driver

driver = Driver(link, buffer=4 * 1024 * 1024, resolver=my_resolver)
driver.start()
...
await driver.aclose()
```

`Driver(link, *, mss=None, buffer=None, stack_config=None, resolver=None)`:

- `mss`: the maximum segment size to offer. The default is the link MTU minus
  40. The stack also clamps it to the peer's MSS during the handshake, and
  never sends larger segments, even when this is below the RFC 1122 default
  of 536.
- `buffer`: the per-connection send and receive buffer, in bytes. The default
  is 1 MiB. A single connection cannot go faster than buffer ÷ RTT, so a
  distant gateway needs a larger one. The out-of-order reassembly cap scales
  with this value.
- `stack_config`: a complete `StackConfig` that replaces everything the driver
  would otherwise derive from the link. When you pass it, `mss` and `buffer`
  are ignored.
- `resolver`: how names become addresses for everything that dials through
  this driver (see [Names and routes](#names-and-routes)). With `None`, only
  IPv4 addresses are accepted.

`start()` creates the driver task, and must be called from inside a running
event loop. `aclose()` cancels the task. Neither one closes the link.

Operations:

- `await driver.connect(host, port, *, timeout=30.0)` returns a `TcpStream`.
  If the connect times out, the half-open socket is aborted and
  `ConnectionTimeout` is raised. Wrapping the call in your own timeout instead
  would leave the socket sending SYNs. `connect` does not check split routes.
  Use `route_allows` first if you want a clear error rather than a timeout.
- `await driver.ping(host, sequence, *, timeout=2.0)` sends one ICMP echo. It
  returns the round-trip time in milliseconds, or `None` if no reply arrived in
  time.
- `await driver.resolve(host)` returns `host` unchanged if it is an address.
  Otherwise it asks the resolver, or raises `ResolveError` if there is none.

`driver.address_changes` counts how many times the link's address changed and
the stack was rebuilt.

## TcpStream

`TcpStream` is the connection object that `Driver.connect` returns.

- `await read(max_bytes=65536)` reads once, waiting until data is available.
  It returns `b""` at end of stream.
- `await read_all(limit=8 MiB)` reads until the peer closes, but stops at
  `limit` bytes.
- `await write(data)` returns once all of `data` is in the send buffer,
  waiting for space as needed.
- `close()` starts an orderly shutdown (FIN). `abort()` sends RST.
  `await wait_closed()` waits until the connection is fully finished.
- Using the stream as an `async with` context manager calls `close()` on exit.
- `peer` holds the remote address. The `rx` and `tx` attributes count payload
  bytes as the application saw them, and `opened_at` holds the
  `time.monotonic()` value at open.

Once a connection fails, `read` and `write` raise its `NetworkError` (see
[Errors](#errors)).

## asyncio streams

Libraries such as `asyncssh` and `asyncpg` expect the standard library's
`(StreamReader, StreamWriter)` pair. To give them one:

```python
from usernet.runtime.transport import wrap_stream

stream = await driver.connect("10.0.0.5", 22)
reader, writer = await wrap_stream(stream, peername=stream.peer)
```

Flow control works in both directions. A full `StreamReader` stops draining the
stack, which shrinks the advertised window. `writer.drain()` waits while the
transport holds more than its high-water mark.

`wrap_stream` accepts any `ByteStream`, meaning any object with
`async read(size)`, `async write(data)` and `close()`. A `TlsStream` qualifies
too.

## TLS inside the tunnel

```python
import ssl
from usernet.runtime.tls import wrap

stream = await driver.connect("10.0.0.5", 443)
tls = await wrap(stream, ssl.create_default_context(), server_hostname="api.internal")
await tls.write(b"...")
data = await tls.read()
await tls.aclose()
```

`wrap` drives `ssl.SSLObject` over memory BIOs and finishes the handshake
before it returns. Handshake and record errors are raised as `TlsError`, a
`NetworkError`. `TlsStream` also exposes `peer_certificate()`,
`selected_alpn_protocol()`, `version()` and `cipher()`. `unwrap()` sends
`close_notify`. `aclose()` calls `unwrap()` and then closes the underlying
stream. A peer that disconnects without `close_notify` reads as end of stream,
not as an error.

## HTTP (httpx extra)

```python
from usernet.http import httpx_client

async with httpx_client(driver, base_url="https://api.internal") as client:
    response = await client.get("/status")
```

- `httpx_client(driver, **kwargs)` returns an `httpx.AsyncClient` whose
  connections all go through the tunnel. Extra keyword arguments go to
  `AsyncClient`. Pass `transport=` to supply your own.
- `httpx_transport(driver, **kwargs)` and `TunnelTransport(driver, *,
  verify=True, connect_timeout=30.0, http2=False, **pool_options)` build the
  transport itself. The `pool_options` go to `httpcore.AsyncConnectionPool`.
- Pass `verify` (`True`, `False`, a CA bundle path, or an `ssl.SSLContext`) to
  the **transport**. `httpx.AsyncClient` ignores its own `verify` when it is
  given a custom transport. `verify` concerns the target's certificate, never
  the gateway's.
- `TunnelTransport.last_connect_ms` is the duration of the most recent TCP
  handshake, which is one round trip through the tunnel.
- `PoolTransport(backend, *, ssl_context=None, http1=True, http2=False,
  **pool_options)` takes any httpcore `AsyncNetworkBackend`. Use it to run
  HTTP over a byte source that is not a driver.

httpcore exceptions are translated to their httpx equivalents. usernet's own
`NetworkError`s pass through unchanged, because their messages say more than
`ConnectError`.

## SOCKS5

```python
from usernet import Socks5Server

server = Socks5Server(driver, port=1080)
await server.start()
...
await server.aclose()
```

`Socks5Server(driver, *, host="127.0.0.1", port=1080, username=None,
password=None, allow_non_loopback=False, connect_timeout=30.0,
handshake_timeout=10.0, route_policy="auto", resolver=None)`:

- Only `CONNECT` is supported. `BIND` and `UDP ASSOCIATE` are refused.
- A non-loopback `host` raises `NetworkError` unless `allow_non_loopback=True`.
  If you do expose the listener, also set `username` and `password` (RFC 1929).
- A client that hasn't finished the SOCKS handshake and sent its request
  within `handshake_timeout` seconds is disconnected and counted as rejected.
- `port=0` picks a free port. After `start()`, read it back from `server.port`
  or `server.address`.
- With `route_policy="auto"`, destinations outside the link's split routes are
  rejected straight away with "not allowed" and the route table in the message.
  Any other value turns the check off.
- `resolver` defaults to the driver's. Requests that carry a hostname
  (`socks5h://`, `curl --socks5-hostname`) are resolved through it and refused
  if there is none.
- `aclose(grace=2.0)` stops listening, gives open relays `grace` seconds to
  finish, then cancels the rest.
- The counters `connections`, `rejected` and `active`, and `relays` (open
  relays, by the destination the client asked for), are there for status
  displays.

`usernet.socks.client.open_via_socks(proxy_host, proxy_port, host, port, *,
username=None, password=None)` is the client side. It does a SOCKS5 CONNECT
through an existing proxy and returns an asyncio stream pair. A second process
can use it to share a tunnel that is already up, instead of logging in again.

## Names and routes

A `Resolver` (in `usernet.resolve`) is any `async (host: str) -> str` callable.
It returns an IPv4 address, or raises `ResolveError` with a message the end
user will read.

`StaticResolver(hosts, *, source="the host table")` is a fixed table for
networks without DNS:

```python
from usernet.resolve import StaticResolver

resolver = StaticResolver({"build.internal": "10.1.2.3"}, source="[hosts] in vpn.toml")
driver = Driver(link, resolver=resolver)
```

Names match exactly, ignoring case and a trailing dot. There are no wildcards
and no search domains. Invalid entries raise `ValueError` that names `source`.
`lookup(host)` returns `None` for unknown names, and `resolve(host)` raises.

`usernet.routing` answers which destinations the tunnel carries:

- `route_allows(config, host)` checks an IPv4 address. Excludes win. An empty
  include list means a full tunnel. The link's own subnet is always allowed.
- `describe_routes(config)` returns the route table as one line, for error
  messages.

## Errors

Everything usernet raises derives from `usernet.errors.UsernetError`.

| Exception | Raised when |
| --- | --- |
| `ProtocolParseError` | malformed input from the network, the tunnel or a SOCKS client; it is the only exception parsers raise |
| `NetworkError` | base for connection failures; also used for a closed link, a changed address, or a failed driver |
| `ConnectionRefused` | RST in reply to SYN, or ICMP port unreachable while connecting |
| `ConnectionReset` | RST on an established connection |
| `ConnectionTimeout` | the connect timed out, or retransmissions ran out |
| `HostUnreachable` | any other ICMP destination-unreachable hard error while connecting |
| `RouteNotAllowed` | the destination is outside the split routes (SOCKS client side) |
| `ResolveError` | a name could not be resolved, or there is no resolver |
| `TlsError` | a TLS handshake or record failure (`usernet.runtime.tls`) |

A tunnel implementation should root its own exceptions at `UsernetError`, so
that callers catching the tunnel's base class also catch stack failures.

## Logging and capture

```python
from usernet import log

log.configure(1, loggers=("myclient", "usernet"), patterns=(*log.DEFAULT_PATTERNS, COOKIE))
```

- `configure(verbosity, *, loggers=("usernet",), patterns=DEFAULT_PATTERNS,
  stream=None)`: 0 logs warnings, 1 logs debug output, 2 logs debug output
  with timestamps and logger names. List your own logger and `"usernet"`, or
  the stack's diagnostics go nowhere.
- Output goes to stderr, never stdout, because a relay over stdout would be
  corrupted by a single log line.
- A `RedactingFilter` on the handler applies `patterns`. A pattern with two
  groups redacts the second group; one with three keeps the third (a closing
  delimiter). `password=...` is built in; add your own tunnel's secrets.
  `redact(text, patterns)` applies the same patterns to a string.

`usernet.pcap.PcapWriter(path)` writes raw IP packets (`LINKTYPE_RAW`) that
Wireshark opens directly. Call `write(packet, timestamp=None)` for each packet
in either direction, then `close()`, or use it as a context manager. It is not
thread-safe, so call it from the event loop.

## Using the stack directly

`PyStack(StackConfig(...))` is the sans-IO core. You can drive it without the
driver, for example from a different event loop or from a simulation.
`StackConfig` has `local_ip`, `netmask`, `mtu`, `max_sockets`,
`verify_checksums`, `tcb` (a `TcbConfig`) and `rng`. Pass a cryptographic `rng`
such as `lambda: secrets.randbits(32)`. The default returns 0, which makes the
ISNs and ephemeral ports predictable and is for tests only.

The rules (see [DESIGN.md](DESIGN.md#core-principles)):

- Pass `now` as integer milliseconds from a monotonic clock.
- After every call, drain `take_output()` (packets for the link) and
  `take_events()` (events from `usernet.net.events`).
- Call `poll(now)` no later than `poll_at()`.
- `tcp_connect()` allocates a socket, and `start_connect(sid, now)` sends the
  SYN. Register the socket before you call `start_connect`, so you are ready
  for the reply.

The methods follow `NetworkBackend` in
[net/backend.py](../src/usernet/net/backend.py): `tcp_send`, `tcp_recv`,
`tcp_tx_space`, `tcp_rx_available`, `tcp_state`, `tcp_shutdown_write`,
`tcp_close`, `tcp_abort`, `udp_open`, `udp_send_to`, `udp_recv_from`,
`udp_close` and `icmp_echo`.

## Test helpers

`usernet.testing` ships for the test suites of tunnels built on usernet.

- `VirtualLink(peer, *, address="172.29.29.5", mtu=1383, loss=0.0,
  duplicate=0.0, reorder=0.0, seed=0, on_send=None, split_include=(),
  split_exclude=())` is an in-memory `IpLink` to a `TcpPeer`. Loss,
  duplication and reordering use the given seed, so a failure reproduces
  exactly. The routes are CIDR strings. `sent_count`, `dropped_count` and
  `reordered_count` count what happened, and `close(reason)` simulates the
  tunnel going down.
- `TcpPeer(ip, port, handler)` is a minimal passive-open TCP server for
  tests. It handles in-order data only and acknowledges immediately.
  `usernet.testing.peer.http_handler(body, status="200 OK")` answers one HTTP
  request. Use `stream_factory` for endpoints that keep state per connection.
- `usernet.testing.pipes.pipes()` is a context manager that yields `Pipes`:
  OS pipes standing in for stdin and stdout, for testing commands built on
  `usernet.runtime.stdio.StdioBridge`.
- `usernet.testing.pcap.records(path)` reads a capture back, so tests can
  assert on it.
- `usernet.testing.tls_endpoint.TlsHttpEndpoint(chain, body)` is a
  TLS-terminating HTTP responder for a `TcpPeer`. It needs the `testing` extra
  (`trustme`), so `usernet.testing` does not re-export it.

`usernet.runtime.stdio.StdioBridge(in_fd=None, out_fd=None)` provides async
`read` and `write` over stdin and stdout on every platform, including the
Windows proactor loop. Use it for `ProxyCommand`-style relays.
