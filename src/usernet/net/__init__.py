"""The sans-IO TCP/IP stack.

Nothing in this package performs I/O, reads a clock, or uses global
randomness. Time arrives as an ``int`` parameter (milliseconds since an
arbitrary monotonic epoch) and randomness as an injected callable, which is
what makes the TCP state machine deterministically testable without a network.

The rule is enforced by a ruff banned-import rule scoped to this package and
re-checked at runtime by ``tests/unit/test_sans_io_guard.py``.
"""
