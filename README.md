# usernet

A userspace TCP/IPv4 stack for VPN clients whose tunnel carries raw IP packets.
A client built on it needs nothing from the operating system: no tun device, no
virtual adapter, no routing change, no administrator rights. It hands
decapsulated packets to usernet and gets back connections, an asyncio stream
pair, an httpx client, or a local SOCKS5 proxy that ordinary tools can use.

usernet does not provide the tunnel itself. A tunnel is anything that
implements `IpLink`: `pyac` supplies CSTP over TLS, and `pyts` supplies
WireGuard over DERP. The library needs only the standard library; the httpx
bridge is an optional extra.

## Installation and usage

```sh
uv add "usernet @ git+https://github.com/dehesselle/usernet@v0.6.0"
uv add "usernet[httpx] @ git+https://github.com/dehesselle/usernet@v0.6.0"  # with the httpx bridge
```

The example below opens a connection through the stack. `VirtualLink` is the
in-memory test link that ships with the package; a real client passes its own
tunnel there instead.

```python
import asyncio

from usernet import Driver
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler


async def main() -> None:
    # A real tunnel goes here. VirtualLink connects to an in-memory TCP peer.
    peer = TcpPeer(ip="10.0.0.5", port=80, handler=http_handler(b"hello"))
    driver = Driver(VirtualLink(peer, address="10.0.0.2"))
    driver.start()
    try:
        stream = await driver.connect("10.0.0.5", 80)
        await stream.write(b"GET / HTTP/1.1\r\nHost: internal\r\n\r\n")
        print((await stream.read_all()).decode())
    finally:
        await driver.aclose()


asyncio.run(main())
```

## Caveats

- A SOCKS5 listener lets every local process into the VPN without
  authentication. `Socks5Server` therefore binds to loopback only unless told
  otherwise.
- Hostnames are resolved only by the resolver you give the driver. They are
  never sent to the host's DNS. Without a resolver, only addresses work.
- TCP is client-only: the stack opens connections and never accepts them.

## Documentation

- [docs/MANUAL.md](docs/MANUAL.md): the library API, covering how to supply a
  tunnel, the driver, streams, HTTP, SOCKS5, resolvers, errors, logging and the
  test helpers
- [docs/DESIGN.md](docs/DESIGN.md): architecture, seams, scope and the core
  principles the code must keep
- [docs/OPERATIONS.md](docs/OPERATIONS.md): runtime behavior, covering defaults
  and limits, failure and recovery, diagnostics, and troubleshooting hangs
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): setup, checks, test strategy and
  CI
- [tests/conformance/README.md](tests/conformance/README.md): the test suite
  against a real Linux kernel
- [bench/README.md](bench/README.md): benchmark method and measured results

## AI disclosure

Substantial parts of this code were generated with Sonnet 5.x/Opus 5.x.
Generated code was tested, but not every line was reviewed in detail.

## License

[0BSD](LICENSES/0BSD.txt)
