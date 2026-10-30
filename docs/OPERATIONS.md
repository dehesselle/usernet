# Runtime behavior

This document covers how usernet behaves while running: the defaults and
limits, what happens when the tunnel or a peer misbehaves, what it reports, and
how to diagnose a connection that hangs.

For the API that sets these values, see [MANUAL.md](MANUAL.md).

## Defaults and limits

These are per connection unless marked otherwise. The values come from
`TcbConfig` ([net/tcb.py](../src/usernet/net/tcb.py)) and `StackConfig`
([net/stack.py](../src/usernet/net/stack.py)), plus the driver's constants.

| Setting | Default | Notes |
| --- | --- | --- |
| Send and receive buffer | 1 MiB each | A cap, not an allocation: the buffers grow on demand, so idle connections cost almost nothing. Set with `Driver(buffer=...)`. |
| Throughput ceiling | buffer ÷ RTT | 1 MiB at 150 ms is about 3.6 MB/s on a real kernel. Only a larger buffer raises it. |
| MSS offered | link MTU − 40 | Also clamped to the peer's MSS, and lowered by ICMP "fragmentation needed". |
| Window scaling | on | Without it the advertised window could not exceed 64 KiB. |
| Initial congestion window | 10 segments | IW10, RFC 6928. |
| Out-of-order segments held | max(4096, buffer ÷ 536 + 64) | Bounds the list. The memory is already bounded by the window. |
| Sockets per stack | 512 | `tcp_connect` raises `NetworkError` beyond this. Worst case memory is 512 × 1 MiB receive buffer. |
| Ephemeral ports | 49152–65535 | Allocation starts at a random point (RFC 6056), so a short-lived process run twice does not reuse its previous four-tuple. |
| RTO | 1000 ms initial, 250 ms min, 60 s max | RFC 6298, with exponential backoff and Karn's rule. |
| Retransmissions | 8 (4 for SYN) | Then the connection fails with `ConnectionTimeout`. |
| Zero-window probes | 8 unanswered | Then `ConnectionTimeout`. A peer that answers probes with a closed window is waited for indefinitely. |
| Connect timeout | 15 s in the stack, 30 s in `Driver.connect` | The shorter one wins, unless you pass a smaller `timeout`. |
| Delayed ACK | 40 ms | Not 200 ms: asyncio timers on Windows have about 15.6 ms resolution, and anything longer is felt in SSH. |
| TIME_WAIT | 30 s | |
| Driver idle wake | 500 ms | The longest the driver sleeps. It doubles as a watchdog and lets Ctrl-C get through on Windows. |
| Transport write buffer | 64 KiB high, 16 KiB low | `StreamWriter.drain()` waits above the high mark. |
| SOCKS connect timeout | 30 s | `Socks5Server(connect_timeout=...)`. |
| SOCKS handshake timeout | 10 s | `Socks5Server(handshake_timeout=...)`. A client that hasn't sent its request by then is disconnected. |
| SOCKS shutdown grace | 2 s | Open relays get this long to finish before they are cancelled. |

Nagle is off. Received checksums are verified at every layer and failures are
dropped. IP fragments are never sent (DF is set and segments fit the MTU), and
received fragments are dropped.

## Failure and recovery

- **The link closes.** On its next pass, the driver fails every open stream
  with `NetworkError(link.close_reason)` and stops. A reconnecting tunnel needs
  a new driver.
- **The link's address changes.** The driver logs a warning, fails every open
  stream with a message naming the old and new addresses, and rebuilds the
  stack on the new address. New connections work at once. Old ones cannot
  continue, because their four-tuple names an address the gateway has taken
  back. `driver.address_changes` counts these events.
- **The driver task crashes.** The exception is logged at error level, and
  every open stream fails with `NetworkError("driver failed: ...")`.
- **A connect fails.** A RST that acknowledges our SYN gives
  `ConnectionRefused` immediately. One that doesn't is ignored, as RFC 9293
  requires: anyone who guesses the four-tuple could send it. An ICMP hard
  error while connecting gives `ConnectionRefused` (port unreachable) or
  `HostUnreachable` immediately, instead of waiting for the timeout. On a
  timeout, the half-open socket is aborted before `ConnectionTimeout` is
  raised.
- **A half-closed connection** (we have sent our FIN, the peer is still
  sending) has nothing of ours outstanding once the FIN is acknowledged, so no
  timer runs against it. It lasts as long as the peer keeps sending.
- **An abort after a clean close**, in TIME_WAIT, sends nothing, ends
  TIME_WAIT early and reports the socket closed.
- **A RST on a connection** ends it only if its sequence number is exactly
  the next one we expect. Elsewhere in the receive window it gets a challenge
  ACK, which a genuine peer answers with a RST that does match (RFC 5961). Out
  of the window it is ignored.
- **ICMP errors** count only if the segment they quote is still in flight
  (RFC 5927). Others are dropped as `icmp-stale`.
- **ICMP "fragmentation needed".** The connection's MSS is lowered and
  retransmission carries the data. It is never lowered below 536, nor raised
  above its current value. The connection is not aborted.
- **Segments for unknown sockets** are dropped silently, without an RST.
- **A name with no resolver** fails with `ResolveError`. It is never passed to
  the host's DNS.

## Diagnostics

Logger names are `usernet.runtime` (the driver and asyncio transport),
`usernet.net` (packets the stack discarded) and `usernet.socks` (the SOCKS
server). Use `usernet.log.configure` with `"usernet"` in `loggers` to see
them. Raise `usernet.net` to `INFO` to silence routine drops alone; dropped
fragments still show.

What is logged:

- **error**: the driver task failed.
- **warning**: the tunnel address changed; an IP fragment arrived and was
  dropped (we set DF and size from the MTU, so a fragment means the path does
  not match the tunnel's MTU); a SOCKS request was rejected, its connect
  failed, the client sent a malformed request or none within the handshake
  timeout, or a relay ended early.
- **info**: each SOCKS connection opened.
- **debug**: every other packet the stack discarded, as
  `dropped (<reason>): <summary>`. Reasons include `bad-ip-checksum`,
  `bad-tcp-checksum`, `not-for-us`, `no-socket`, `malformed-tcp`,
  `icmp-ignored` and `icmp-stale`; `pmtu-clamp` reports an MSS lowered by
  ICMP. Also SOCKS hostname resolution.
- **exception**: a protocol's flow-control callback raised inside the asyncio
  transport.

Retransmissions are not logged; they show up in a capture.

**Packet capture.** Write every packet in both directions with
`usernet.pcap.PcapWriter`, then open the file in Wireshark. This is the first
thing to do for any "it hangs" report.

**Drop tracing.** The drops above come from `PacketDropped(reason, summary)`
events, which the stack emits when `PyStack.trace_drops` is set. The `Driver`
always sets it and logs the events. When you drive `PyStack` yourself, set it
and read the events from `take_events()`.

**Counters.** `TcpStream` has `rx` and `tx`, `Socks5Server` has
`connections`, `rejected`, `active` and `relays`, and `TunnelTransport` has
`last_connect_ms`, which is one tunnel round trip.

## A connection hangs

A hang with no error almost always means packets are being discarded
somewhere silently. Check these in order:

1. **Split routes.** A split-tunnel gateway discards packets for destinations
   outside its include list, without an error. `route_allows(link.config,
   host)` and `describe_routes(link.config)` show what the tunnel carries.
   `Socks5Server` checks this itself (`route_policy="auto"`), but
   `Driver.connect` does not.
2. **MTU and MSS.** If the link's `mtu` is larger than what the tunnel really
   carries, large segments are lost while small ones get through. The handshake
   succeeds, and the transfer then stalls. A capture shows full-size segments
   being retransmitted.
3. **The address changed.** Check `driver.address_changes`, and look for the
   warning in the log.
4. **The link itself.** If the capture shows our packets leaving and nothing
   coming back, the problem is below usernet. For the conformance setup, see
   "When everything times out" in
   [tests/conformance/README.md](../tests/conformance/README.md).
