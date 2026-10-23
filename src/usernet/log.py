"""Logging setup, with redaction that does not rely on remembering.

Secrets are stripped by a filter on the handler rather than at each call site.
Redaction that depends on every future ``log.debug`` being careful is redaction
that will eventually fail.

What counts as a secret is the caller's business, not this package's: a session
cookie, an auth key, a node private key. The mechanism is here, the patterns
arrive as an argument. Only one pattern is built in, because
``password=<something>`` is universal and forgetting it once is expensive.

:func:`configure` attaches to several logger names at once, and a client is
expected to name both its own and ``usernet``. Miss the second and this
package's own diagnostics -- the dropped packets, a reassigned tunnel address,
every SOCKS rejection -- go nowhere, which is exactly when they are wanted.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Sequence
from typing import TextIO

Patterns = Sequence[re.Pattern[str]]

# A pattern with two groups redacts the second; one with three keeps the third,
# so a delimiter (``</password>``) survives the substitution.
DEFAULT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(password[\"']?\s*[:=]\s*)(\S+)", re.IGNORECASE),
)


def redact(text: str, patterns: Patterns = DEFAULT_PATTERNS) -> str:
    for pattern in patterns:
        if pattern.groups == 3:
            text = pattern.sub(r"\1<redacted>\3", text)
        else:
            text = pattern.sub(r"\1<redacted>", text)
    return text


class RedactingFilter(logging.Filter):
    """Removes secrets from formatted log records."""

    def __init__(self, patterns: Patterns = DEFAULT_PATTERNS) -> None:
        super().__init__()
        self._patterns = patterns

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact(message, self._patterns)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def configure(
    verbosity: int,
    *,
    loggers: Sequence[str] = ("usernet",),
    patterns: Patterns = DEFAULT_PATTERNS,
    stream: TextIO | None = None,
) -> None:
    """Set up logging. 0 = warnings, 1 = debug, 2 = debug with timestamps.

    ``stream`` defaults to stderr, which is also what it must be: a ``nc``-style
    command relays a connection over stdout, so a single log line landing there
    would corrupt the stream it is trying to describe. Callers that care pass it
    explicitly rather than trusting the default to stay put.
    """
    level = logging.WARNING if verbosity == 0 else logging.DEBUG
    fmt = "%(message)s" if verbosity < 2 else "%(asctime)s %(name)s %(message)s"

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    handler.addFilter(RedactingFilter(patterns))

    for name in loggers:
        root = logging.getLogger(name)
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(level)
        root.propagate = False
