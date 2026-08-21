"""Guards on the httpcore/httpx interface we plug into.

``network_backend`` is a real constructor argument of
``httpx.AsyncHTTPTransport`` but is not part of httpx's public API, and
``AsyncNetworkBackend`` is httpcore's. Both could change under a version bump.
These tests make that fail here, with a message naming the cause, rather than
at runtime with a ``TypeError`` from deep inside a request.
"""

from __future__ import annotations

import inspect

import httpcore
import httpx

from usernet.http import (
    EXCEPTION_MAP,
    PyacNetworkBackend,
    TlsNetworkStream,
    TunnelStream,
    TunnelTransport,
)


def parameters(method: object) -> list[str]:
    return list(inspect.signature(method).parameters)  # type: ignore[arg-type]


def test_the_connection_pool_still_accepts_a_network_backend() -> None:
    """The single most fragile thing this project depends on.

    Note it is *httpcore's* pool, not ``httpx.AsyncHTTPTransport`` -- which the
    plan assumed and which turned out not to take one at all. This assertion is
    what caught that.
    """
    assert "network_backend" in parameters(httpcore.AsyncConnectionPool.__init__)


def test_the_httpx_extension_points_we_build_on_exist() -> None:
    assert issubclass(TunnelTransport, httpx.AsyncBaseTransport)
    assert hasattr(httpx, "AsyncByteStream")
    for name in ("handle_async_request", "aclose"):
        assert callable(getattr(TunnelTransport, name)), name


def test_httpcore_errors_are_translated_for_callers() -> None:
    """Someone catching httpx.ConnectError should still catch one."""
    assert EXCEPTION_MAP, "the exception map went empty; nothing would be translated"
    assert EXCEPTION_MAP[httpcore.ConnectError] is httpx.ConnectError
    assert EXCEPTION_MAP[httpcore.ReadTimeout] is httpx.ReadTimeout
    # Specific before general, or a ConnectTimeout would surface as a plain
    # TimeoutException and lose the reason.
    order = list(EXCEPTION_MAP)
    assert order.index(httpcore.ConnectTimeout) < order.index(httpcore.TimeoutException)


def test_the_backend_interface_is_the_one_we_implement() -> None:
    assert parameters(httpcore.AsyncNetworkBackend.connect_tcp) == parameters(
        PyacNetworkBackend.connect_tcp
    )
    assert parameters(httpcore.AsyncNetworkBackend.connect_unix_socket) == parameters(
        PyacNetworkBackend.connect_unix_socket
    )
    assert parameters(httpcore.AsyncNetworkBackend.sleep) == parameters(PyacNetworkBackend.sleep)


def test_the_stream_interface_is_the_one_we_implement() -> None:
    for name in ("read", "write", "aclose", "start_tls", "get_extra_info"):
        expected = parameters(getattr(httpcore.AsyncNetworkStream, name))
        assert parameters(getattr(TunnelStream, name)) == expected, name
        assert parameters(getattr(TlsNetworkStream, name)) == expected, name


def test_our_streams_are_recognised_as_httpcore_streams() -> None:
    assert issubclass(TunnelStream, httpcore.AsyncNetworkStream)
    assert issubclass(TlsNetworkStream, httpcore.AsyncNetworkStream)
    assert issubclass(PyacNetworkBackend, httpcore.AsyncNetworkBackend)


def test_httpx_is_pinned_below_a_version_we_have_not_tested() -> None:
    """The pin is what makes the guards above meaningful rather than advisory."""
    major, minor = (int(part) for part in httpx.__version__.split(".")[:2])
    assert (major, minor) < (0, 29), (
        f"httpx {httpx.__version__} is beyond the tested range; re-check "
        "network_backend and the AsyncNetworkStream signatures before raising the pin"
    )
