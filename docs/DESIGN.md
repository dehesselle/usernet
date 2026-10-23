# Design

This document covers usernet's architecture: the layers, the seams between
them, what the library deliberately leaves out, and the principles the code
must not break.

Reasoning that concerns only one module is in that module's docstring, next to
the code it explains. This document covers what spans modules and links to
those docstrings instead of repeating them.

## Architecture

The layers, from the wire up:

| Layer | Modules | Role |
| --- | --- | --- |
| Link | [link.py](../src/usernet/link.py) | `IpLink` and `LinkConfig`: the only interface to the tunnel |
| Stack | [net/](../src/usernet/net/) | `PyStack`, a sans-IO IPv4/TCP/UDP/ICMP implementation behind the `NetworkBackend` protocol |
| Driver | [runtime/driver.py](../src/usernet/runtime/driver.py) | the one asyncio task that joins the stack to the link, and `TcpStream` for applications |
| Adapters | [runtime/transport.py](../src/usernet/runtime/transport.py), [runtime/tls.py](../src/usernet/runtime/tls.py), [runtime/stdio.py](../src/usernet/runtime/stdio.py), [http.py](../src/usernet/http.py), [socks/](../src/usernet/socks/) | ways to present a `TcpStream`: an asyncio stream pair, TLS inside the tunnel, a stdio relay, httpx, and a SOCKS5 server and client |
| Policy | [resolve.py](../src/usernet/resolve.py), [routing.py](../src/usernet/routing.py) | which names become which addresses, and which destinations the tunnel carries |
| Support | [errors.py](../src/usernet/errors.py), [log.py](../src/usernet/log.py), [pcap.py](../src/usernet/pcap.py), [aio.py](../src/usernet/aio.py) | the exception hierarchy, redacting log setup, packet capture, and asyncio helpers |
| Test harness | [testing/](../src/usernet/testing/) | `VirtualLink`, `TcpPeer` and friends: a network for tests that has no network |

### How a packet moves

Inbound: the link sets its `wake` event. The driver wakes, calls
`take_inbound()`, and passes each packet to `PyStack.handle_input(packet, now)`.
The stack demultiplexes the packet by protocol and four-tuple to a TCB, which
updates its state and queues outbound segments (ACKs, window updates) and
events. The driver then drains both: packets go to `link.send()`, and events
set the `asyncio.Event`s that `TcpStream` readers and writers wait on.

Outbound: `TcpStream.write()` calls `tcp_send()`, which copies as much as fits
into the send buffer, and then wakes the driver. On its next pass, the driver
runs `poll(now)` for timers and flushes whatever the stack queued.

Received data stays in the TCB's receive buffer until the application reads it.
The window the stack advertises is computed from that backlog, which is how a
slow reader slows the peer down (principle 5).

## Seams

Each seam is a `Protocol`, not a base class, and each one has a reason.

- **`IpLink` and `LinkConfig`.** A tunnel's configuration object is mostly
  tunnel-specific (DPD timers, rekey settings, DERP regions). Structural typing
  lets that object satisfy `LinkConfig` whole, instead of being split in two or
  forced into a meaningless hierarchy. `SimpleLinkConfig` exists for links with
  nothing more to say. See [link.py](../src/usernet/link.py).
- **`NetworkBackend`.** It separates the deterministic, synchronous stack from
  the code that does I/O, so the risky code can be tested and the slow code
  replaced. A native backend (smoltcp via PyO3) could satisfy it, and a PyO3
  extension type cannot cheaply inherit a Python ABC. See
  [net/backend.py](../src/usernet/net/backend.py).
- **`ByteStream` and the TLS `Transport`.** The asyncio transport adapter and
  the TLS wrapper accept anything with `read`, `write` and `close`. A
  `TcpStream` and a `TlsStream` are interchangeable there, so TLS inside the
  tunnel reuses the same transport code.
- **`PoolTransport`.** It is the httpx transport with a pluggable httpcore
  network backend. `TunnelTransport` is the variant that dials through a
  driver. `pyts` uses `PoolTransport` to run HTTP/2 inside a Noise session,
  which has no driver. See [http.py](../src/usernet/http.py).
- **`Resolver`.** A resolver is any async `str -> str` callable. Which resolver
  a tunnel needs (MagicDNS, a fixed table, none) is a property of the tunnel,
  so the consumer chooses. See [resolve.py](../src/usernet/resolve.py).

## Scope

Left out on purpose, with the reasons in the linked docstrings:

- **Passive open.** There are no `LISTEN` or `SYN_RECEIVED` states, so the
  shipping code never carries the code or the attack surface for accepting
  connections. The server side used by tests lives in
  [testing/peer.py](../src/usernet/testing/peer.py). See
  [net/tcb.py](../src/usernet/net/tcb.py).
- **SACK and timestamps.** Both options are parsed for their length and
  skipped, and neither is advertised. The gateway's peers do not offer
  `SACK_PERM`, so it would never be negotiated. See
  [net/tcb.py](../src/usernet/net/tcb.py).
- **Nagle.** The consumers are interactive SSH and request/response HTTP, and
  the driver already batches application writes.
- **SOCKS `BIND` and `UDP ASSOCIATE`.** Both need inbound connections, which a
  client-only stack cannot accept. They are refused with the matching reply
  code. See [socks/protocol.py](../src/usernet/socks/protocol.py).
- **In-tunnel DNS.** UDP is a thin codec used for diagnostics. Name
  resolution is the consumer's job, through a `Resolver`. See
  [net/udp.py](../src/usernet/net/udp.py).
- **IP fragmentation.** Every packet is sent with DF set and sized to the MTU,
  and received fragments are dropped. ICMP "fragmentation needed" lowers the
  connection's MSS instead. See [net/stack.py](../src/usernet/net/stack.py).
- **IPv6.** The link carries IPv4 only.

## Dependencies

`dependencies` in `pyproject.toml` is empty on purpose. The stack, the driver,
the SOCKS server and the link seam need only the standard library, so a
consumer can treat usernet as an internal detail rather than a dependency tree.
Two optional extras exist: `httpx` for [http.py](../src/usernet/http.py), and
`testing` (`trustme`) for `usernet.testing.tls_endpoint`.

`usernet.testing` is part of the package rather than the test tree. Every
tunnel built on usernet needs the same virtual peer in its own tests, so it is
imported rather than copied.

## Core principles

1. **`usernet.net` is sans-IO.** It never imports `asyncio`, `socket`, `ssl`,
   `time` or `random`. That keeps the code with the most correctness risk
   deterministic and testable without a network. Ruff's banned-API rule
   (TID251) enforces this, and
   [test_sans_io_guard.py](../tests/unit/test_sans_io_guard.py) checks it
   again at runtime.
2. **Time is a parameter.** `now` is an `int` of milliseconds since an
   arbitrary monotonic epoch. The stack never reads a clock, so tests control
   time exactly and the arithmetic stays exact.
3. **Every mutating stack call may produce output.** After every call into the
   stack, the driver drains both `take_output()` and `take_events()`. This rules
   out the "forgot to poll" class of bug.
4. **Only the driver touches the stack, and nothing awaits between two stack
   calls that must be atomic.** Stack methods are synchronous and asyncio is
   single-threaded, so this is the whole locking scheme. See
   [runtime/driver.py](../src/usernet/runtime/driver.py).
5. **No queue between the network and the application.** Received bytes stay
   in the stack's receive buffer until the application reads them, and the
   advertised window is computed from that backlog. A queue in between would
   reopen the window without the data going anywhere, which turns flow control
   into unbounded memory growth. The driver, the asyncio transport, the SOCKS
   relay and the stdio bridge all follow this rule.
6. **Readable and Writable are edge events.** They fire on the transition, not
   while the condition holds. The driver must never drop one, and consumers
   must read until the buffer is empty. See
   [net/events.py](../src/usernet/net/events.py).
7. **Sequence numbers are compared only through the helpers in
   [net/tcp.py](../src/usernet/net/tcp.py).** They wrap at 2³², so a raw `<` is
   wrong once a connection crosses the wrap, and the resulting bug is close to
   undebuggable. Never inline these comparisons.
8. **Names are resolved by the tunnel or not at all.** There is never a
   fallback to the host's resolver, which would send tunnel-internal names to
   the machine's DNS and dial whatever public record matched.
9. **Nothing here knows about gateways, tailnets or logins.** Tunnel concepts
   stay in the consumers. Consumers root their own exceptions at
   `UsernetError`, so that catching their base class also catches stack
   failures.
10. **Parsers raise only `ProtocolParseError`.** If an `IndexError` or
    `struct.error` escaped, callers could not tell malformed input from a bug.
11. **Received checksums are verified at every layer** (IP header, TCP, UDP,
    ICMP), as RFC 1122 requires. The tunnel's crypto protects only the leg to
    the gateway. Spec compliance is not traded for speed.
12. **Importing `usernet` has no side effects.** The top-level names are bound
    lazily, so a program that only wants `__version__` does not import asyncio
    and the stack.
13. **An optimisation must pay for its complexity.** Measure it A/B against
    `master` with [bench/run.py](../bench/run.py), and keep it only if it
    measurably helps. See [bench/README.md](../bench/README.md).
