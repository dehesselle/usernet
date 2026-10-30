# CLAUDE.md

usernet is a userspace TCP/IPv4 stack, driver and SOCKS5 proxy for VPN clients
whose tunnel carries raw IP; `pyac` and `pyts` build on it.

- Read docs/DESIGN.md before architectural changes, and respect its core
  principles. Before changing a module, read its docstring: that is where the
  module's own reasoning lives.
- docs/MANUAL.md describes the public API, and docs/OPERATIONS.md the runtime
  behavior (defaults, limits, failures, diagnostics).
- bench/README.md covers benchmarking and results; tests/conformance/README.md
  covers the kernel conformance suite.

@docs/DEVELOPMENT.md

Documentation rules:

- Keep README.md short. A change that affects design, usage or behavior
  updates the matching document in the same change.
- Keep DESIGN.md current, with no project history. Reasoning that concerns
  only one module goes in that module's docstring, not in docs/.
- Nothing in this package may refer to a consumer's CLI or tunnel protocol,
  except as an example.

Run the five checks from DEVELOPMENT.md before committing.
