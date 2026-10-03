# Benchmarks

A/B comparison of two checkouts: a baseline and a candidate. The question it
answers is "did this change make the stack cheaper per packet, and by how
much?" Each benchmarked change has to pay for any complexity it adds, so
measure after every change, not only at the end.

| file | what |
|---|---|
| `micro.py` | pyperf micro-benchmarks: checksum, build, parse, one segment through `PyStack` in each direction, timer scan with 1–500 sockets |
| `macro.py` | whole stack (`Driver` + `PyStack` over the conformance suite's `TunLink`) against real Linux TCP: throughput, request/response latency, idle sockets, loss |
| `kernel_server.py` | the kernel's end of `macro.py`, run as a separate process so it doesn't share our GIL |
| `run.py` | runs both checkouts on the same benchmark code, interleaved A B B A, pinned to separate cores, and writes a summary |
| `box-setup.sh` | prepares a fresh Ubuntu box |

All benchmarks use only the public API. The same scripts can then measure
any revision, including ones whose internals have been rearranged.

## Micro, anywhere (including Windows)

```sh
uv run --with pyperf python bench/micro.py -o before.json
# ... change something ...
uv run --with pyperf python bench/micro.py -o after.json
uv run --with pyperf python -m pyperf compare_to --table before.json after.json
```

## Macro, on a Linux box

Use a dedicated-vCPU machine (Hetzner CCX, not CX/CPX). Shared cores are
noisier than most of the effects being measured. Use 4 cores: one for our
stack, one for the kernel-side server, and the rest for everything else.

Ship the code without pushing anywhere:

```sh
git bundle create usernet.bundle --all          # on the dev machine
scp usernet.bundle root@box:
ssh root@box 'git clone -b <branch> usernet.bundle usernet'
```

On the box, from the candidate checkout:

```sh
sh bench/box-setup.sh                            # once; worktree ../usernet-base at master
uv run python bench/run.py --baseline ../usernet-base --candidate .
uv run python bench/run.py --baseline ../usernet-base --candidate . --micro
```

To measure a newer candidate, fetch the new bundle, check out the branch, and
re-run `uv sync --python 3.12.14`. The baseline stays put.

`run.py` writes `bench/results/<timestamp>/` (git-ignored):
- `meta.json`: commits and interpreter versions
- `macro.jsonl`: every run
- `summary.md`: medians, IQRs and candidate/baseline ratios
- `profile-*.txt`: a cProfile top-25 of the 64 MiB download per checkout
  (separate from the timed runs, because profiling distorts timing)

### Scenarios

| name | what | read it as |
|---|---|---|
| `download` | 64 MiB from the kernel, clean link | CPU-bound: `cpu_s_per_mib` is the stack's receive-path cost |
| `upload` | 64 MiB to the kernel, clean link | the same for the send path |
| `echo` | 2000 sequential 100-byte round trips | per-packet overhead plus driver wake latency |
| `download_idle300` | `download` with 300 idle connections open | the cost of connections that do nothing, during bulk transfer |
| `echo_idle300` | `echo` with 300 idle connections open | the same, where every round trip is a driver pass of its own |
| `download_impaired` | 4 MiB at 20 ms / 2 % loss each way (needs root) | must not get worse; limited by recovery, not CPU |

Check the noise floor before trusting a ratio. Run once with baseline and
candidate at the same commit; the ratios this gives are the run-to-run noise.

## Results: stack hot-path series (October 2026)

Hetzner CCX23 (4 dedicated vCPU, AMD EPYC Milan), Ubuntu 26.04, CPython
3.12.14, tun MTU 1406. Baseline `489bf87`. Medians of 10 interleaved runs.
An A/A run (baseline against itself) put the noise floor at about ±2% for
throughput and CPU, and ±15% for p99 latency.

Each column is cumulative: that commit and everything before it, compared
with the baseline.

| | baseline | +checksum `f54531d` | +timer heap `ef97df6` | +first_of `e8216b9` | +fused build `e31acef` | +send copy `d09609a` | +address cache `808bfb2` | +int flags `b6dd8f2` |
|---|---|---|---|---|---|---|---|---|
| download MB/s | 46.0 | +2% | +1% | +0% | +2% | +4% | +16% | **+52%** |
| upload MB/s | 40.2 | +49% | +49% | +48% | +58% | +62% | +91% | **+150%** |
| echo p50 µs | 181 | −1% | −0% | +1% | +0% | +0% | −7% | **−12%** |
| download, 300 idle: MB/s | 45.9 | +2% | +3% | +4% | +7% | +6% | +14% | **+51%** |
| echo, 300 idle: p50 µs | 394 | −1% | −55% | −55% | −55% | −55% | −57% | **−60%** |
| download at 20 ms / 2% loss: s | 12.7 | within noise throughout |||||| **8.77 → 8.74** |

The loss scenario is too noisy for 10 runs to say much: single runs range
from about 4 to 14 s on either side, depending on where the losses fall. The
final number is from 20 runs per side.

The first_of fast path (`e8216b9`) measured no gain in any scenario and was
reverted (`fb96ffa`).

Micro (Linux), baseline → `808bfb2`: checksum of 1363 B 14.2 → 3.2 µs;
building a data segment 21.5 → 6.6 µs; one segment out through the stack
58 → 38 µs, one in 29 → 24 µs; a timer pass with 500 sockets 264 µs →
0.18 µs, now constant.

After `808bfb2` the profile was led by `enum` flag operations
(`IntFlag.__and__` and `Flag(...)`), at roughly a quarter of the time of a
download; event dispatch did not appear in the top 25. Plain-int flags
(`b6dd8f2`) took a segment through the stack from 38 to 26 µs out and from
24 to 16 µs in. Since then the profile is flat: the TCB's own logic, spread

### Then: verifying received checksums (`878c034`)

Not an optimisation but a correctness fix: received TCP, UDP and ICMP
checksums were never verified, and RFC 1122 requires it. Its price, against
`b6dd8f2`:

| | before | after | change |
|---|---|---|---|
| download MB/s | 70.2 | 58.4 | −17% (CPU/MiB +22%) |
| upload MB/s | 101.1 | 100.0 | within noise (only ACKs come in) |
| echo p50 µs | 155 | 157 | within noise |
| one segment in through the stack | 16.0 µs | 19.9 µs | +3.9 µs |

The cost is one pass over each received segment, 3.5 µs at full size.
Against the original baseline, download stays +25% and upload +149%; the
loss scenario over 20 runs per side reads 8.12 s before, 7.28 s after.
across many small functions, with no single hot spot left.
