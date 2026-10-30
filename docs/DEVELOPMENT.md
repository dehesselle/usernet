# Development

This document covers setting up a checkout, running the checks CI runs, how
the test suite is organised, releasing, and where benchmarking is described.

## Setup

```sh
uv sync --dev
```

The version comes from git tags via hatch-vcs and is written to
`src/usernet/version.py`, a generated file. Clone with full history: hatch-vcs
needs the tags, which is why CI checks out with `fetch-depth: 0`.

## Checks

CI runs ruff and the REUSE check once on Ubuntu, and mypy and pytest on
Ubuntu, Windows and macOS with Python 3.12, plus Ubuntu with 3.14. Run all
five before committing.

```sh
uvx --from 'ruff~=0.16.0' ruff check .
uvx --from 'ruff~=0.16.0' ruff format --check .
uv run mypy src
uv run pytest -q -m "not linux_only"
uvx reuse lint
```

- Ruff isn't a project dependency. `required-version` in `pyproject.toml`
  and the pin in `.github/workflows/build.yml` are bumped together, once a
  new minor release's findings have been reviewed.
- Ruff's banned-API rule (TID251) keeps `usernet.net` sans-IO. The other
  directories opt out of it in `pyproject.toml`. Don't add `src/usernet/net`
  to that list.
- mypy runs in strict mode for `usernet.net.*`, `usernet.link` and
  `usernet.routing`, the code with the most correctness risk.
- pytest has a global 30 s timeout. A broken TCP stack hangs rather than
  failing, and would otherwise wedge CI.
- The project is REUSE-compliant. New files start with the SPDX header that
  `reuse annotate` writes; files that can't carry a comment get covered in
  `REUSE.toml`.

## Test strategy

Each layer proves something the one before it cannot.

| Suite | Location | What it proves |
| --- | --- | --- |
| Unit | [tests/unit/](../tests/unit/) | Codecs, checksums, sequence arithmetic, the TCB state machine, timers, SOCKS framing, redaction, pcap output, and the seams. Hypothesis generates inputs for the checksum and IPv4/ICMP codecs. `test_sans_io_guard.py` and `test_httpcore_seam.py` pin the import contract and the httpcore API that `http.py` relies on. |
| Integration | [tests/integration/](../tests/integration/) | The real stack and driver over `VirtualLink` and `TcpPeer` (the "vnet" suite): HTTP, TLS, SOCKS relays and resolvers, with seeded loss, duplication and reordering. These prove self-consistency only, because a misreading of RFC 9293 shared by both sides still passes. |
| Conformance | [tests/conformance/](../tests/conformance/) | Our TCP against a real Linux kernel over a tun device, on a clean link and on one with 2 % loss and 20 ms delay in both directions. This is the only suite that proves conformance. It is Linux-only and marked `linux_only`. |

The conformance suite has its own guide: setup, running it without root,
impairment, and reading the packet traces it prints on failure. See
[tests/conformance/README.md](../tests/conformance/README.md). It runs locally
under WSL2. In CI it has a job of its own that runs both the clean and the
impaired pass.

Code shared by test suites goes in `src/usernet/testing/` when other projects
need it too. Otherwise it stays in `tests/`.

## Releasing

Pushing a tag `vX.Y.Z` runs the full workflow and, if every job passes,
attaches the built sdist and wheel to a draft GitHub release and publishes
them to PyPI. The build job checks that the wheel's `__version__` matches the
tag. PyPI accepts the upload through trusted publishing, which requires a
publisher on pypi.org for this repository, the workflow `build.yml` and the
GitHub environment `pypi`. The draft release is published by hand.

## Benchmarks

Performance work is measured A/B against `master` with the scripts in
[bench/](../bench/). Micro-benchmarks run anywhere. The whole-stack benchmarks
run on a dedicated-vCPU Linux box against the kernel. Method, scenarios and the
results so far are in [bench/README.md](../bench/README.md).
