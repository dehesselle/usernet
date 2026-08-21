"""Credentials must not reach a log line.

Redaction lives in a filter rather than at call sites: anything that relies on
every future ``log.debug`` remembering to be careful will eventually leak.
"""

from __future__ import annotations

import logging

import pytest

from usernet._logging import RedactingFilter, redact

REAL_TOKEN = "35B466@-1035079680@A96E@AE5ED7B1C96F6A05AE4842B8424564A705C2326B"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"Cookie: webvpn={REAL_TOKEN}", REAL_TOKEN),
        (f"<session-token>{REAL_TOKEN}</session-token>", REAL_TOKEN),
        ("<password>hunter2</password>", "hunter2"),
        ("password=hunter2", "hunter2"),
        ('password: "hunter2"', "hunter2"),
    ],
)
def test_secrets_are_removed(text: str, secret: str) -> None:
    result = redact(text)
    assert secret not in result
    assert "redacted" in result


def test_surrounding_text_survives() -> None:
    assert redact(f"Cookie: webvpn={REAL_TOKEN}; path=/").startswith("Cookie: webvpn=<redacted>")


def test_ordinary_messages_are_untouched() -> None:
    message = "<- DPD_OUT (0 bytes)"
    assert redact(message) == message


def test_filter_rewrites_the_record(caplog: pytest.LogCaptureFixture) -> None:
    record = logging.LogRecord(
        name="usernet.cstp",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=1,
        msg="sending Cookie: webvpn=%s",
        args=(REAL_TOKEN,),
        exc_info=None,
    )
    assert RedactingFilter().filter(record) is True
    assert REAL_TOKEN not in record.getMessage()
