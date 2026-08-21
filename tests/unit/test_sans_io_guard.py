"""The sans-IO contract, checked at runtime.

Two mechanisms guard :mod:`usernet.net`, and they cover different things:

* The ruff ``banned-api`` rule in ``pyproject.toml`` is a *source* check. It is
  what catches ``import time`` or ``import random`` in our own modules, and it
  is the right tool for that -- stdlib modules we legitimately depend on may
  import ``time`` transitively, which says nothing about our code.
* This test is a *runtime* check for the I/O machinery specifically. Those
  modules have no innocent path into the stack, so if importing the stack pulls
  one in, the layering has genuinely been broken.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

# No legitimate transitive dependency of a pure protocol codec reaches these.
FORBIDDEN = ("asyncio", "socket", "ssl", "select", "selectors")

_PROBE = textwrap.dedent(
    """
    import importlib.abc, sys

    FORBIDDEN = {forbidden!r}

    # Drop anything already loaded so a cached module cannot satisfy an import
    # without going through the finder below.
    for name in list(sys.modules):
        if name.partition(".")[0] in FORBIDDEN:
            del sys.modules[name]

    class Blocker(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.partition(".")[0] in FORBIDDEN:
                raise AssertionError(
                    "usernet.net must be sans-IO, but importing the stack pulled in "
                    + fullname
                )
            return None

    sys.meta_path.insert(0, Blocker())

    import usernet.net.stack
    import usernet.net.backend
    import usernet.net.checksum
    import usernet.net.events

    print("clean")
    """
)


def test_stack_imports_no_io_machinery() -> None:
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE.format(forbidden=FORBIDDEN)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "clean"
