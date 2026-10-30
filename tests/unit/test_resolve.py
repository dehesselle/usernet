# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""StaticResolver: a fixed table, matched exactly, with no fallback."""

from __future__ import annotations

import pytest

from usernet.errors import ResolveError
from usernet.resolve import StaticResolver, is_address, normalize


def test_a_name_in_the_table_resolves() -> None:
    resolver = StaticResolver({"node-1.orka": "10.221.188.11"})
    assert resolver.lookup("node-1.orka") == "10.221.188.11"


@pytest.mark.parametrize("spelling", ["NODE-1.Orka", "node-1.orka.", " node-1.orka "])
def test_case_and_the_root_dot_do_not_matter(spelling: str) -> None:
    resolver = StaticResolver({"Node-1.ORKA.": "10.221.188.11"})
    assert resolver.lookup(spelling) == "10.221.188.11"


def test_an_address_passes_through_unchanged() -> None:
    assert StaticResolver({}).lookup("10.0.0.5") == "10.0.0.5"


def test_there_is_no_suffix_or_wildcard_matching() -> None:
    """Anything cleverer than an exact match starts reimplementing DNS."""
    resolver = StaticResolver({"orka": "10.0.0.1"})
    assert resolver.lookup("node.orka") is None
    assert resolver.lookup("orka.example") is None


async def test_a_miss_names_the_table_and_rules_out_the_host_resolver() -> None:
    resolver = StaticResolver({"a": "10.0.0.1"}, source="[profiles.orka.hosts]")
    with pytest.raises(ResolveError, match=r"not in \[profiles\.orka\.hosts\].*host's resolver"):
        await resolver("b")


async def test_a_hit_is_awaitable_like_any_resolver() -> None:
    assert await StaticResolver({"a": "10.0.0.1"})("A") == "10.0.0.1"


@pytest.mark.parametrize(
    ("hosts", "message"),
    [
        ({"a": "not-an-ip"}, "not an IPv4 address"),
        ({"a": "fe80::1"}, "not an IPv4 address"),
        ({"": "10.0.0.1"}, "empty host name"),
        ({".": "10.0.0.1"}, "empty host name"),
        ({"10.0.0.2": "10.0.0.1"}, "is an address, not a name"),
    ],
)
def test_a_bad_table_is_refused_up_front(hosts: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        StaticResolver(hosts, source="table")


def test_helpers() -> None:
    assert is_address("10.1.2.3")
    assert not is_address("example")
    assert not is_address("::1")
    assert normalize("Example.COM.") == "example.com"
