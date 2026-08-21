"""Which destinations the tunnel will carry.

Cheap to test and expensive to get wrong: a false negative refuses a host the
user can actually reach, and a false positive restores the unexplained hang the
check exists to prevent.
"""

from __future__ import annotations

import ipaddress

from usernet.link import SimpleLinkConfig
from usernet.routing import describe_routes, route_allows


def tunnel(**kwargs: object) -> SimpleLinkConfig:
    defaults: dict[str, object] = {"address": "172.29.29.3", "netmask": "255.255.255.255"}
    return SimpleLinkConfig(**{**defaults, **kwargs})  # type: ignore[arg-type]


def networks(*specs: str) -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(ipaddress.IPv4Network(spec) for spec in specs)


def test_an_address_inside_the_include_list_is_allowed() -> None:
    config = tunnel(split_include=networks("10.221.188.0/23"))
    assert route_allows(config, "10.221.188.32")


def test_an_address_outside_the_include_list_is_refused() -> None:
    """The alternative is a connection that hangs with no explanation."""
    config = tunnel(split_include=networks("10.221.188.0/23"))
    assert not route_allows(config, "8.8.8.8")


def test_an_excluded_address_is_refused_even_if_included() -> None:
    config = tunnel(
        split_include=networks("10.0.0.0/8"),
        split_exclude=networks("10.221.188.0/24"),
    )
    assert route_allows(config, "10.5.0.1")
    assert not route_allows(config, "10.221.188.32")


def test_no_include_list_means_full_tunnel() -> None:
    assert route_allows(tunnel(), "8.8.8.8")


def test_our_own_subnet_is_always_reachable() -> None:
    config = tunnel(
        address="172.29.29.3",
        netmask="255.255.0.0",
        split_include=networks("10.221.188.0/23"),
    )
    assert route_allows(config, "172.29.1.1")


def test_the_boundaries_of_a_network_are_inside_it() -> None:
    config = tunnel(split_include=networks("10.221.188.0/23"))
    assert route_allows(config, "10.221.188.0")
    assert route_allows(config, "10.221.189.255")
    assert not route_allows(config, "10.221.190.0")


def test_routes_are_described_for_the_error_message() -> None:
    config = tunnel(
        split_include=networks("10.221.188.0/23", "192.168.0.0/16"),
        split_exclude=networks("10.221.189.0/24"),
    )
    assert describe_routes(config) == "10.221.188.0/23, 192.168.0.0/16 except 10.221.189.0/24"
    assert describe_routes(tunnel()) == "full tunnel"
