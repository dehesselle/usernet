"""usernet -- a userspace TCP/IP stack for tunnels that carry raw IP.

A VPN client written against this package never asks the operating system for
anything: no tun device, no virtual adapter, no routing change, no
administrator privilege. It hands decapsulated IPv4 packets to
:class:`~usernet.net.stack.PyStack`, which terminates IP itself, and gets back
ordinary asyncio streams.

    driver = Driver(link)          # link is anything satisfying IpLink
    driver.start()
    stream = await driver.connect("10.0.0.5", 22)
    await Socks5Server(driver, port=1080).start()

The one thing you must supply is the tunnel: an :class:`~usernet.link.IpLink`
that moves packets between here and the far side. ``pyac`` supplies CSTP over
TLS, ``pyts`` WireGuard over DERP, and :mod:`usernet.testing` supplies one made
of nothing at all.

Importing this package stays free of side effects: the names below are bound
lazily, so ``import usernet`` does not drag in asyncio and the whole stack for
a program that only wanted the version.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "Driver",
    "IpLink",
    "LinkConfig",
    "PyStack",
    "SimpleLinkConfig",
    "Socks5Server",
    "StackConfig",
    "TcpStream",
    "__version__",
    "describe_routes",
    "route_allows",
]

if TYPE_CHECKING:
    from usernet.link import IpLink, LinkConfig, SimpleLinkConfig
    from usernet.net.stack import PyStack, StackConfig
    from usernet.routing import describe_routes, route_allows
    from usernet.runtime.driver import Driver, TcpStream
    from usernet.socks import Socks5Server


def __getattr__(name: str) -> Any:
    if name == "__version__":
        # From the installed metadata rather than a literal here. The project
        # takes its version from git tags (hatch-vcs), so a hardcoded string
        # would sooner or later disagree with the package actually installed --
        # and a version that lies is worse than one that is merely unknown.
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("usernet")
        except PackageNotFoundError:
            return "0.0.0+unknown"
    if name in ("IpLink", "LinkConfig", "SimpleLinkConfig"):
        from usernet import link

        return getattr(link, name)
    if name in ("PyStack", "StackConfig"):
        from usernet.net import stack

        return getattr(stack, name)
    if name in ("Driver", "TcpStream"):
        from usernet.runtime import driver

        return getattr(driver, name)
    if name == "Socks5Server":
        from usernet.socks import Socks5Server

        return Socks5Server
    if name in ("describe_routes", "route_allows"):
        from usernet import routing

        return getattr(routing, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
