"""SOCKS5 wire format (RFC 1928) and username/password auth (RFC 1929).

Sans-IO: everything here takes or returns bytes and never touches a socket.
Messages are short, and each one's total length can be worked out from a fixed
prefix -- which is what :func:`request_length` is for. The server reads the
prefix, learns how much more to read, and hands the whole message here.

Only ``CONNECT`` is implemented. ``BIND`` and ``UDP ASSOCIATE`` require the
proxy to accept inbound connections, which a client-only stack deliberately
cannot do, so they are refused with the code that says exactly that.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from enum import IntEnum

from usernet.errors import (
    ConnectionRefused,
    ConnectionTimeout,
    HostUnreachable,
    NetworkError,
    ProtocolParseError,
    ResolveError,
    RouteNotAllowed,
    UsernetError,
)

VERSION = 0x05
AUTH_VERSION = 0x01

AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_UNACCEPTABLE = 0xFF

CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

AUTH_SUCCESS = 0x00
AUTH_FAILURE = 0x01


class Reply(IntEnum):
    """RFC 1928 reply codes. Getting these right is most of what a client can
    show its user, so a wrong code becomes someone else's confusing message."""

    SUCCESS = 0x00
    GENERAL_FAILURE = 0x01
    NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class SocksRejection(UsernetError):
    """A request we will answer with a specific reply code and then close."""

    def __init__(self, reply: Reply, detail: str) -> None:
        super().__init__(detail)
        self.reply = reply


@dataclass(frozen=True, slots=True)
class Request:
    command: int
    host: str
    port: int
    is_name: bool = False
    """True when the client sent a domain name rather than a literal address."""


# --- greeting ---------------------------------------------------------------


def choose_method(methods: bytes, *, require_auth: bool) -> int:
    """Pick an authentication method from the client's offer.

    When credentials are configured, ``AUTH_NONE`` must not be selectable --
    otherwise the password is decorative and any local process walks straight
    in.
    """
    if require_auth:
        return AUTH_USERPASS if AUTH_USERPASS in methods else AUTH_UNACCEPTABLE
    if AUTH_NONE in methods:
        return AUTH_NONE
    return AUTH_UNACCEPTABLE


def build_method_reply(method: int) -> bytes:
    return bytes((VERSION, method))


def parse_userpass(data: bytes) -> tuple[str, str]:
    """Parse an RFC 1929 credentials message."""
    if len(data) < 2 or data[0] != AUTH_VERSION:
        raise ProtocolParseError(f"not an RFC 1929 message: {data[:2]!r}")
    ulen = data[1]
    if len(data) < 2 + ulen + 1:
        raise ProtocolParseError("truncated username")
    username = data[2 : 2 + ulen]
    plen = data[2 + ulen]
    start = 3 + ulen
    if len(data) < start + plen:
        raise ProtocolParseError("truncated password")
    password = data[start : start + plen]
    return username.decode("utf-8", "replace"), password.decode("utf-8", "replace")


def userpass_length(prefix: bytes) -> int | None:
    """Total length of an RFC 1929 message, or None if ``prefix`` is too short.

    Needs 2 bytes to learn the username length, then one more past it for the
    password length, so callers read in two steps.
    """
    if len(prefix) < 2:
        return None
    ulen = prefix[1]
    if len(prefix) < 3 + ulen:
        return None
    return 3 + ulen + prefix[2 + ulen]


def build_auth_reply(ok: bool) -> bytes:
    return bytes((AUTH_VERSION, AUTH_SUCCESS if ok else AUTH_FAILURE))


# --- request and reply -------------------------------------------------------

REQUEST_PREFIX = 5
"""Version, command, reserved, address type, and the first address byte -- the
last of which is the length for a domain name."""


def request_length(prefix: bytes) -> int:
    """Total request length, given at least :data:`REQUEST_PREFIX` bytes."""
    if len(prefix) < REQUEST_PREFIX:
        raise ProtocolParseError(f"need {REQUEST_PREFIX} bytes to size a request")
    atyp = prefix[3]
    if atyp == ATYP_IPV4:
        return 4 + 4 + 2
    if atyp == ATYP_IPV6:
        return 4 + 16 + 2
    if atyp == ATYP_DOMAIN:
        return 4 + 1 + prefix[4] + 2
    raise SocksRejection(Reply.ADDRESS_TYPE_NOT_SUPPORTED, f"address type {atyp}")


def parse_request(data: bytes) -> Request:
    """Parse a complete SOCKS5 request."""
    if len(data) < 4 or data[0] != VERSION:
        raise ProtocolParseError(f"not a SOCKS5 request: {data[:4]!r}")

    command, atyp = data[1], data[3]
    body = data[4:]

    if atyp == ATYP_IPV4:
        if len(body) < 6:
            raise ProtocolParseError("truncated IPv4 request")
        host = str(ipaddress.IPv4Address(body[:4]))
        port = struct.unpack("!H", body[4:6])[0]
        return Request(command=command, host=host, port=port)

    if atyp == ATYP_IPV6:
        # Nothing in the tunnel is IPv6: the gateway assigns an IPv4 address
        # and the stack speaks IPv4 only, so this can never succeed.
        raise SocksRejection(Reply.ADDRESS_TYPE_NOT_SUPPORTED, "IPv6 is not carried by the tunnel")

    if atyp == ATYP_DOMAIN:
        if not body:
            raise ProtocolParseError("truncated domain request")
        length = body[0]
        if len(body) < 1 + length + 2:
            raise ProtocolParseError("truncated domain request")
        # ASCII, not idna: these bytes are attacker-controlled and the idna
        # codec raises UnicodeError on plenty of them. Names arrive already
        # punycoded by convention, so this preserves them exactly, and a
        # resolver would want that form anyway.
        name = body[1 : 1 + length].decode("ascii", "replace")
        port = struct.unpack("!H", body[1 + length : 3 + length])[0]
        # Some clients send a literal address in the name field. Accepting it
        # costs one parse and saves an inexplicable failure.
        try:
            return Request(command=command, host=str(ipaddress.IPv4Address(name)), port=port)
        except ValueError:
            return Request(command=command, host=name, port=port, is_name=True)

    raise SocksRejection(Reply.ADDRESS_TYPE_NOT_SUPPORTED, f"address type {atyp}")


def build_reply(reply: Reply, host: str = "0.0.0.0", port: int = 0) -> bytes:
    """Build a reply. ``host`` is BND.ADDR, which for CONNECT is informational."""
    try:
        packed = ipaddress.IPv4Address(host).packed
    except ValueError:
        packed = b"\x00\x00\x00\x00"
    return bytes((VERSION, int(reply), 0x00, ATYP_IPV4)) + packed + struct.pack("!H", port)


# --- the client half ---------------------------------------------------------
#
# Needed by ``usernet nc --via``, which talks to a proxy rather than serving one.
# Keeping both halves here makes the pair testable against each other.


def build_greeting(methods: tuple[int, ...] = (AUTH_NONE,)) -> bytes:
    return bytes((VERSION, len(methods), *methods))


def parse_method_reply(data: bytes) -> int:
    if len(data) < 2 or data[0] != VERSION:
        raise ProtocolParseError(f"not a SOCKS5 method reply: {data[:2]!r}")
    return data[1]


def build_userpass(username: str, password: str) -> bytes:
    user, secret = username.encode(), password.encode()
    if len(user) > 255 or len(secret) > 255:
        raise ProtocolParseError("RFC 1929 limits both fields to 255 bytes")
    return bytes((AUTH_VERSION, len(user))) + user + bytes((len(secret),)) + secret


def parse_auth_reply(data: bytes) -> bool:
    if len(data) < 2 or data[0] != AUTH_VERSION:
        raise ProtocolParseError(f"not an RFC 1929 reply: {data[:2]!r}")
    return data[1] == AUTH_SUCCESS


def build_request(host: str, port: int, command: int = CMD_CONNECT) -> bytes:
    """Build a request, sending an address as an address wherever possible."""
    try:
        address = bytes((ATYP_IPV4,)) + ipaddress.IPv4Address(host).packed
    except ValueError:
        name = host.encode("ascii", "replace")
        if len(name) > 255:
            raise ProtocolParseError(f"host name is {len(name)} bytes, maximum is 255") from None
        address = bytes((ATYP_DOMAIN, len(name))) + name
    return bytes((VERSION, command, 0x00)) + address + struct.pack("!H", port)


REPLY_PREFIX = 5
"""Same shape as a request: the fifth byte sizes a domain name."""


def reply_length(prefix: bytes) -> int:
    if len(prefix) < REPLY_PREFIX:
        raise ProtocolParseError(f"need {REPLY_PREFIX} bytes to size a reply")
    return request_length(prefix)


def parse_reply(data: bytes) -> tuple[Reply, str, int]:
    """Parse a reply into ``(code, bound address, bound port)``."""
    if len(data) < 4 or data[0] != VERSION:
        raise ProtocolParseError(f"not a SOCKS5 reply: {data[:4]!r}")
    try:
        code = Reply(data[1])
    except ValueError:
        code = Reply.GENERAL_FAILURE  # an unknown code is still a failure

    atyp, body = data[3], data[4:]
    if atyp == ATYP_IPV4 and len(body) >= 6:
        return code, str(ipaddress.IPv4Address(body[:4])), struct.unpack("!H", body[4:6])[0]
    if atyp == ATYP_DOMAIN and body and len(body) >= 1 + body[0] + 2:
        length = body[0]
        name = body[1 : 1 + length].decode("ascii", "replace")
        return code, name, struct.unpack("!H", body[1 + length : 3 + length])[0]
    if atyp == ATYP_IPV6 and len(body) >= 18:
        return code, str(ipaddress.IPv6Address(body[:16])), struct.unpack("!H", body[16:18])[0]
    raise ProtocolParseError(f"truncated reply for address type {atyp}")


def error_for(reply: Reply, target: str) -> NetworkError:
    """Turn a proxy's refusal back into the error it stands for."""
    if reply is Reply.CONNECTION_REFUSED:
        return ConnectionRefused(f"{target} refused the connection")
    if reply is Reply.NOT_ALLOWED:
        return RouteNotAllowed(f"the proxy will not route to {target}")
    if reply is Reply.HOST_UNREACHABLE:
        return HostUnreachable(f"{target} is unreachable through the proxy")
    if reply is Reply.NETWORK_UNREACHABLE:
        return HostUnreachable(f"no route to {target} through the proxy")
    if reply is Reply.TTL_EXPIRED:
        return ConnectionTimeout(f"the proxy timed out connecting to {target}")
    return NetworkError(f"the proxy refused {target}: {reply.name.lower().replace('_', ' ')}")


def reply_for(error: Exception) -> Reply:
    """Map a connection failure onto the closest RFC 1928 code."""
    if isinstance(error, ConnectionRefused):
        return Reply.CONNECTION_REFUSED
    if isinstance(error, RouteNotAllowed):
        return Reply.NOT_ALLOWED
    if isinstance(error, HostUnreachable | ResolveError):
        return Reply.HOST_UNREACHABLE
    if isinstance(error, ConnectionTimeout | TimeoutError):
        return Reply.TTL_EXPIRED
    return Reply.GENERAL_FAILURE
