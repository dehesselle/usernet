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
  failing, and would otherwise wedge CI. The few tests that legitimately run
  longer, or shrink a failure for longer, raise it for themselves.
- CI also measures coverage in every test and conformance job, combines it in
  the Coverage job, and fails that job below `fail_under` in
  `pyproject.toml`. That number is a floor, not a target: raise it when
  coverage rises, and never lower it to let a change through.
- The project is REUSE-compliant. New files start with the SPDX header that
  `reuse annotate` writes; files that can't carry a comment get covered in
  `REUSE.toml`.

## Test strategy

Each layer proves something the one before it cannot.

| Suite | Location | What it proves |
| --- | --- | --- |
| Unit | [tests/unit/](../tests/unit/) | Codecs, checksums, sequence arithmetic, the TCB state machine, timers, ICMP errors, SOCKS framing, redaction, pcap output, and the seams. `test_sans_io_guard.py` and `test_httpcore_seam.py` pin the import contract and the httpcore API that `http.py` relies on. |
| Property and fuzz | [tests/unit/](../tests/unit/) | What no hand-written case reaches. `test_tcb_stateful.py` lets Hypothesis drive one TCB against a peer and a network that reorders, duplicates and drops, plus hostile segments, and checks invariants after every step: bytes delivered exactly, memory bounded, nothing outstanding without a timer. `test_stack_fuzz.py` feeds the stack packets that lie in any field but carry valid checksums. `test_transport_codecs.py` and the codec tests hold the parsers to raising only `ProtocolParseError`. |
| Integration | [tests/integration/](../tests/integration/) | The real stack and driver over `VirtualLink` and `TcpPeer` (the "vnet" suite): HTTP, TLS, the SOCKS server and client, and resolvers, with seeded loss, duplication and reordering. `test_churn.py` ends hundreds of connections every way there is and checks that nothing is left behind; `test_soak.py` runs seeded random transfers. These prove self-consistency only, because a misreading of RFC 9293 shared by both sides still passes. |
| Conformance | [tests/conformance/](../tests/conformance/) | Our TCP against a real Linux kernel over a tun device: on a clean link, under six impairment profiles in both directions, with the kernel offering no window scaling and a small MSS, and through a narrow hop that makes the kernel send ICMP "fragmentation needed". This is the only suite that proves conformance. It is Linux-only and marked `linux_only`. |

The conformance suite has its own guide: setup, running it without root,
impairment, and reading the packet traces it prints on failure. See
[tests/conformance/README.md](../tests/conformance/README.md). It runs locally
under WSL2. In CI it is a matrix with one job per link, so a failure names the
impairment that caused it.

### Searching deeper

Hypothesis reads its profile from `HYPOTHESIS_PROFILE`, defined in
[tests/conftest.py](../tests/conftest.py). `ci`, the default, is what every
push runs. `nightly` searches far longer and needs the timeout lifted. The
driver soak takes its seed count from `USERNET_SOAK_SEEDS` and its first seed
from `USERNET_SOAK_SEED_BASE`, and a failing seed is replayed alone with
`USERNET_SOAK_SEED`.

```sh
HYPOTHESIS_PROFILE=nightly uv run pytest tests/unit -o timeout=3600
USERNET_SOAK_SEEDS=500 uv run pytest tests/integration/test_soak.py
```

The [nightly workflow](../.github/workflows/nightly.yml) runs both, plus ten
minutes of mixed traffic against the kernel under three impairment profiles.
Every run uses new seeds, derived from the run number, so the nights add up to
more coverage instead of repeating one night's.
It never blocks a pull request; check its runs on the Actions page. It can
also be started by hand from there.

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
