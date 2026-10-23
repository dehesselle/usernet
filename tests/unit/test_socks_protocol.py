"""The SOCKS5 codec.

Byte-level and pure. The reply codes matter more than they look: they are
almost the only thing a client can show its user, so a wrong one turns our
clear failure into somebody else's baffling message.
"""

from __future__ import annotations

import struct

import pytest

from usernet.errors import (
    ConnectionRefused,
    ConnectionTimeout,
    HostUnreachable,
    ProtocolParseError,
    ResolveError,
    RouteNotAllowed,
)
from usernet.socks.protocol import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    AUTH_NONE,
    AUTH_UNACCEPTABLE,
    AUTH_USERPASS,
    CMD_BIND,
    CMD_CONNECT,
    CMD_UDP_ASSOCIATE,
    REQUEST_PREFIX,
    VERSION,
    Reply,
    SocksRejection,
    build_auth_reply,
    build_method_reply,
    build_reply,
    choose_method,
    error_for,
    parse_request,
    parse_userpass,
    reply_for,
    request_length,
    userpass_length,
)


def ipv4_request(host: bytes = b"\x0a\xdd\xbc\x20", port: int = 80, command: int = CMD_CONNECT):
    return bytes((VERSION, command, 0x00, ATYP_IPV4)) + host + struct.pack("!H", port)


def domain_request(name: bytes, port: int = 443) -> bytes:
    return (
        bytes((VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, len(name))) + name + struct.pack("!H", port)
    )


# --- method negotiation -----------------------------------------------------


def test_no_auth_is_chosen_when_none_is_configured() -> None:
    assert choose_method(bytes((AUTH_NONE, AUTH_USERPASS)), require_auth=False) == AUTH_NONE


def test_credentials_are_required_when_configured() -> None:
    """Otherwise the password is decorative and any local process walks in."""
    assert choose_method(bytes((AUTH_NONE,)), require_auth=True) == AUTH_UNACCEPTABLE
    assert choose_method(bytes((AUTH_NONE, AUTH_USERPASS)), require_auth=True) == AUTH_USERPASS


def test_a_client_offering_nothing_we_speak_is_refused() -> None:
    assert choose_method(b"\x80\x81", require_auth=False) == AUTH_UNACCEPTABLE
    assert choose_method(b"", require_auth=False) == AUTH_UNACCEPTABLE


def test_the_method_reply_names_the_version() -> None:
    assert build_method_reply(AUTH_USERPASS) == bytes((VERSION, AUTH_USERPASS))


# --- RFC 1929 ---------------------------------------------------------------


def test_credentials_round_trip() -> None:
    message = b"\x01\x05alice\x07hunter2"
    assert parse_userpass(message) == ("alice", "hunter2")
    assert userpass_length(message) == len(message)


def test_empty_credentials_are_parsed_not_rejected() -> None:
    """An empty password is a bad password, not a malformed message."""
    assert parse_userpass(b"\x01\x00\x00") == ("", "")


def test_the_length_is_unknown_until_enough_bytes_arrive() -> None:
    assert userpass_length(b"\x01") is None
    assert userpass_length(b"\x01\x05ali") is None
    assert userpass_length(b"\x01\x05alice\x07") == 15


def test_a_truncated_credential_message_is_reported() -> None:
    with pytest.raises(ProtocolParseError, match="truncated username"):
        parse_userpass(b"\x01\x05ali")
    with pytest.raises(ProtocolParseError, match="truncated password"):
        parse_userpass(b"\x01\x05alice\x07short")


def test_a_wrong_auth_version_is_rejected() -> None:
    with pytest.raises(ProtocolParseError, match="not an RFC 1929 message"):
        parse_userpass(b"\x05\x05alice\x07hunter2")


def test_the_auth_reply_says_yes_or_no() -> None:
    assert build_auth_reply(True) == b"\x01\x00"
    assert build_auth_reply(False) == b"\x01\x01"


# --- request sizing ---------------------------------------------------------


def test_each_address_type_has_a_known_length() -> None:
    assert request_length(ipv4_request()[:REQUEST_PREFIX]) == 10
    assert request_length(bytes((VERSION, 1, 0, ATYP_IPV6, 0))) == 22
    assert request_length(domain_request(b"api.internal")[:REQUEST_PREFIX]) == 4 + 1 + 12 + 2


def test_sizing_needs_the_whole_prefix() -> None:
    with pytest.raises(ProtocolParseError, match="need 5 bytes"):
        request_length(b"\x05\x01\x00")


def test_an_unknown_address_type_is_rejected_while_sizing() -> None:
    """It has to be caught here: without a length we cannot even skip it."""
    with pytest.raises(SocksRejection) as caught:
        request_length(bytes((VERSION, 1, 0, 0x09, 0)))
    assert caught.value.reply is Reply.ADDRESS_TYPE_NOT_SUPPORTED


# --- requests ---------------------------------------------------------------


def test_an_ipv4_request_is_parsed() -> None:
    request = parse_request(ipv4_request(port=8080))
    assert (request.command, request.host, request.port) == (CMD_CONNECT, "10.221.188.32", 8080)
    assert not request.is_name


def test_bind_and_udp_associate_survive_parsing() -> None:
    """The command is reported, not rejected here; the server decides."""
    assert parse_request(ipv4_request(command=CMD_BIND)).command == CMD_BIND
    assert parse_request(ipv4_request(command=CMD_UDP_ASSOCIATE)).command == CMD_UDP_ASSOCIATE


def test_a_domain_name_is_reported_as_a_name() -> None:
    request = parse_request(domain_request(b"api.internal"))
    assert (request.host, request.port, request.is_name) == ("api.internal", 443, True)


def test_an_address_sent_as_a_name_is_still_an_address() -> None:
    """Some clients do this, and refusing it would be inexplicable."""
    request = parse_request(domain_request(b"10.221.188.32", port=80))
    assert (request.host, request.port, request.is_name) == ("10.221.188.32", 80, False)


def test_ipv6_is_rejected_because_the_tunnel_carries_none() -> None:
    body = bytes((VERSION, CMD_CONNECT, 0x00, ATYP_IPV6)) + bytes(16) + b"\x00\x50"
    with pytest.raises(SocksRejection) as caught:
        parse_request(body)
    assert caught.value.reply is Reply.ADDRESS_TYPE_NOT_SUPPORTED


def test_a_name_of_arbitrary_bytes_does_not_raise() -> None:
    """Untrusted input reaches this parser directly; only declared errors may
    escape it, and the idna codec raises UnicodeError on plenty of bytes."""
    request = parse_request(domain_request(bytes(range(0x80, 0x90))))
    assert request.is_name
    assert isinstance(request.host, str)


def test_a_non_socks5_request_is_rejected() -> None:
    with pytest.raises(ProtocolParseError, match="not a SOCKS5 request"):
        parse_request(b"\x04\x01\x00\x50")


def test_a_truncated_request_is_rejected() -> None:
    with pytest.raises(ProtocolParseError, match="truncated"):
        parse_request(ipv4_request()[:-1])
    with pytest.raises(ProtocolParseError, match="truncated"):
        parse_request(domain_request(b"api.internal")[:-1])


# --- replies ----------------------------------------------------------------


def test_a_reply_carries_the_bound_address() -> None:
    reply = build_reply(Reply.SUCCESS, "172.29.29.3", 1080)
    assert reply == bytes((VERSION, 0x00, 0x00, ATYP_IPV4)) + b"\xac\x1d\x1d\x03" + b"\x04\x38"


def test_a_reply_defaults_to_the_unspecified_address() -> None:
    assert build_reply(Reply.GENERAL_FAILURE) == b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"


def test_an_unusable_bound_address_does_not_break_the_reply() -> None:
    """A reply that cannot be built is a hang; a vague one is merely vague."""
    assert build_reply(Reply.SUCCESS, "not-an-address")[4:8] == b"\x00\x00\x00\x00"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ConnectionRefused("no"), Reply.CONNECTION_REFUSED),
        (RouteNotAllowed("outside"), Reply.NOT_ALLOWED),
        (HostUnreachable("gone"), Reply.HOST_UNREACHABLE),
        (ResolveError("unknown"), Reply.HOST_UNREACHABLE),
        (ConnectionTimeout("slow"), Reply.TTL_EXPIRED),
        (TimeoutError(), Reply.TTL_EXPIRED),
        (ValueError("something else"), Reply.GENERAL_FAILURE),
    ],
)
def test_failures_map_onto_the_closest_reply_code(error: Exception, expected: Reply) -> None:
    assert reply_for(error) is expected


def test_a_refused_route_names_the_destination() -> None:
    """The proxy's "not allowed" comes back as the error a local check raises."""
    error = error_for(Reply.NOT_ALLOWED, "10.9.8.7:443")
    assert isinstance(error, RouteNotAllowed)
    assert error.dst == "10.9.8.7:443"
    assert str(error) == "10.9.8.7:443 is outside the tunnel's split-include routes"
