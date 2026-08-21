"""Secrets must not reach a log line.

Redaction lives in a filter rather than at call sites: anything that relies on
every future ``log.debug`` remembering to be careful will eventually leak.

The patterns themselves belong to whoever knows what a secret looks like, so
what is proved here is the mechanism -- that a caller's patterns are applied,
that the surrounding text survives, and that an ordinary message is left alone.
"""

from __future__ import annotations

import io
import logging
import re

import pytest

from usernet.log import DEFAULT_PATTERNS, RedactingFilter, configure, redact

# A caller's patterns, in both shapes the substitution supports: two groups
# (redact the tail) and three (keep the closing delimiter).
CALLER_PATTERNS = (
    re.compile(r"(webvpn=)([^\s;,]+)", re.IGNORECASE),
    re.compile(r"(<session-token>)(.*?)(</session-token>)", re.IGNORECASE | re.DOTALL),
)

REAL_TOKEN = "35B466@-1035079680@A96E@AE5ED7B1C96F6A05AE4842B8424564A705C2326B"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("password=hunter2", "hunter2"),
        ('password: "hunter2"', "hunter2"),
    ],
)
def test_the_built_in_pattern_removes_passwords(text: str, secret: str) -> None:
    result = redact(text)
    assert secret not in result
    assert "<redacted>" in result


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"Cookie: webvpn={REAL_TOKEN}", REAL_TOKEN),
        (f"<session-token>{REAL_TOKEN}</session-token>", REAL_TOKEN),
    ],
)
def test_a_callers_patterns_are_applied(text: str, secret: str) -> None:
    assert secret not in redact(text, CALLER_PATTERNS)
    assert secret in redact(text)  # and only when asked for


def test_a_three_group_pattern_keeps_its_delimiter() -> None:
    result = redact(f"<session-token>{REAL_TOKEN}</session-token>", CALLER_PATTERNS)
    assert result == "<session-token><redacted></session-token>"


def test_surrounding_text_survives() -> None:
    result = redact(f"Cookie: webvpn={REAL_TOKEN}; path=/", CALLER_PATTERNS)
    assert result == "Cookie: webvpn=<redacted>; path=/"


def test_ordinary_messages_are_untouched() -> None:
    message = "<- DPD_OUT (0 bytes)"
    assert redact(message, CALLER_PATTERNS) == message


def test_filter_rewrites_the_record() -> None:
    record = logging.LogRecord(
        name="usernet.runtime",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=1,
        msg="sending Cookie: webvpn=%s",
        args=(REAL_TOKEN,),
        exc_info=None,
    )
    assert RedactingFilter(CALLER_PATTERNS).filter(record) is True
    assert REAL_TOKEN not in record.getMessage()


def test_configure_attaches_to_every_named_logger() -> None:
    # The reason this is worth a test: a client that names only its own logger
    # silently loses the stack's diagnostics, and notices at the worst moment.
    stream = io.StringIO()
    try:
        configure(1, loggers=("usernet", "pyac"), patterns=CALLER_PATTERNS, stream=stream)
        logging.getLogger("usernet.runtime").debug("stack says hello")
        logging.getLogger("pyac.cstp").debug("tunnel says webvpn=%s", REAL_TOKEN)
    finally:
        for name in ("usernet", "pyac"):
            logger = logging.getLogger(name)
            logger.handlers.clear()
            logger.propagate = True

    output = stream.getvalue()
    assert "stack says hello" in output
    assert "tunnel says webvpn=<redacted>" in output
    assert REAL_TOKEN not in output


def test_the_default_patterns_are_not_mutable_by_a_caller() -> None:
    assert isinstance(DEFAULT_PATTERNS, tuple)
