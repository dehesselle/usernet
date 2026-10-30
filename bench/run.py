# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A/B benchmark runner: two checkouts, same benchmarks, interleaved.

    python bench/run.py --baseline ../usernet-base --candidate . [--reps 10]
    python bench/run.py --baseline ../usernet-base --candidate . --micro

Linux only (the macro scenarios need the tun device from
``tests/conformance/setup.sh``). See ``bench/README.md`` for the box setup.

Three things keep the comparison honest:

* **Identical benchmark code.** The scripts always come from *this*
  checkout; only the ``usernet`` they import differs, via each checkout's own
  ``.venv``.
* **Interleaving.** Runs alternate A B B A, so a VM that drifts during the
  session drifts for both sides alike.
* **Pinning.** Our stack and the kernel-side server get a core each; sharing
  one would measure the scheduler.
"""

from __future__ import annotations

import argparse
import contextlib
import itertools
import json
import os
import socket
import statistics
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REPO = BENCH.parent
HOST_IP = os.environ.get("USERNET_TUN_HOST", "10.99.0.1")
PORT = 5201
# Every client run talks to the next of these server ports, so a four-tuple
# recurs only after this many runs. Kernel sockets outlive the client process
# that used them -- TIME_WAIT, or orphans retrying a FIN after a failed run --
# and a SYN that lands on one gets a bare ACK instead of a SYN-ACK: a connect
# timeout that has nothing to do with the code under test.
PORT_SPREAD = 100
MIB = 1024 * 1024

STACK_CPU = "1"
SERVER_CPU = "2"


@dataclass(frozen=True)
class Scenario:
    args: tuple[str, ...]
    metrics: tuple[str, ...]
    impaired: bool = False


TRANSFER = ("mb_per_s", "cpu_s_per_mib")
SCENARIOS = {
    "download": Scenario(("download",), TRANSFER),
    "upload": Scenario(("upload",), TRANSFER),
    "echo": Scenario(("echo",), ("p50_us", "p99_us", "cpu_us_per_op")),
    "download_idle300": Scenario(("download", "--idle", "300"), TRANSFER),
    "echo_idle300": Scenario(("echo", "--idle", "300"), ("p50_us", "p99_us", "cpu_us_per_op")),
    # Smaller: under loss this is minutes per run, and what it guards against
    # is a regression in recovery, which shows at 4 MiB as well as at 64.
    "download_impaired": Scenario(("download", "--bytes", str(4 * MIB)), ("wall_s",), True),
}


@dataclass(frozen=True)
class Checkout:
    label: str
    path: Path

    @property
    def python(self) -> Path:
        return self.path / ".venv" / "bin" / "python"

    def describe(self) -> dict[str, str]:
        commit = subprocess.run(
            ["git", "-C", str(self.path), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        version = subprocess.run(
            [str(self.python), "-c", "import sys; print(sys.version.split()[0])"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return {"label": self.label, "path": str(self.path), "commit": commit, "python": version}


@contextlib.contextmanager
def kernel_server() -> Iterator[None]:
    process = subprocess.Popen(
        [
            "taskset",
            "-c",
            SERVER_CPU,
            sys.executable,
            str(BENCH / "kernel_server.py"),
            "--port",
            str(PORT),
            "--ports",
            str(PORT_SPREAD),
        ],
        stdout=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                socket.create_connection((HOST_IP, PORT), timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline or process.poll() is not None:
                    raise SystemExit(
                        f"kernel server did not come up on {HOST_IP}:{PORT}; "
                        "is the tun device set up? (sudo sh tests/conformance/setup.sh)"
                    ) from None
                time.sleep(0.2)
        yield
    finally:
        process.terminate()
        process.wait()


@contextlib.contextmanager
def impaired() -> Iterator[None]:
    impair = REPO / "tests" / "conformance" / "impair.sh"
    subprocess.run(["sh", str(impair), "20ms", "2%"], check=True, stdout=subprocess.DEVNULL)
    try:
        yield
    finally:
        subprocess.run(["sh", str(impair), "--off"], check=True, stdout=subprocess.DEVNULL)


_ports = itertools.cycle(range(PORT, PORT + PORT_SPREAD))


def run_client(checkout: Checkout, args: tuple[str, ...]) -> dict[str, float]:
    command = [
        "taskset", "-c", STACK_CPU, str(checkout.python), str(BENCH / "macro.py"),
        *args, "--port", str(next(_ports)),
    ]  # fmt: skip
    result = subprocess.run(command, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise SystemExit(f"{checkout.label}: {' '.join(args)} failed:\n{result.stderr}")
    return dict(json.loads(result.stdout.strip().splitlines()[-1]))


def macro(checkouts: list[Checkout], names: list[str], reps: int, out: Path) -> None:
    results: list[dict[str, object]] = []
    log = (out / "macro.jsonl").open("w")

    def one(rep: int, name: str, checkout: Checkout) -> None:
        metrics = run_client(checkout, SCENARIOS[name].args)
        row = {"rep": rep, "scenario": name, "label": checkout.label, **metrics}
        results.append(row)
        log.write(json.dumps(row) + "\n")
        log.flush()
        shown = ", ".join(f"{k}={metrics[k]:.4g}" for k in SCENARIOS[name].metrics)
        print(f"  rep {rep:2d} {name:18s} {checkout.label:9s} {shown}", flush=True)

    def sweep(selected: list[str]) -> None:
        for rep in range(reps):
            order = checkouts if rep % 2 == 0 else checkouts[::-1]  # A B, B A, ...
            for name in selected:
                for checkout in order:
                    one(rep, name, checkout)

    with kernel_server():
        # Discarded: the first transfer after the server starts pays for its
        # warm-up, and in the first A/A run that alone read as a 25% gap.
        for checkout in checkouts:
            run_client(checkout, ("download", "--bytes", str(16 * MIB)))
        sweep([n for n in names if not SCENARIOS[n].impaired])
        lossy = [n for n in names if SCENARIOS[n].impaired]
        if lossy:
            if os.geteuid() != 0:
                print("skipping impaired scenarios: impair.sh needs root")
            else:
                with impaired():
                    sweep(lossy)

        for checkout in checkouts:
            path = out / f"profile-{checkout.label}.txt"
            run_client(checkout, ("download", "--profile", str(path)))
            print(f"  profile written to {path}")

    log.close()
    summary = summarize(results, names, [c.label for c in checkouts])
    (out / "summary.md").write_text(summary)
    print()
    print(summary)


def summarize(results: list[dict[str, object]], names: list[str], labels: list[str]) -> str:
    def stats(values: list[float]) -> tuple[float, float]:
        if len(values) < 2:
            return values[0], 0.0
        q1, _, q3 = statistics.quantiles(values, n=4)
        return statistics.median(values), q3 - q1

    a, b = labels
    lines = [
        f"| scenario | metric | {a} median (IQR) | {b} median (IQR) | {b}/{a} |",
        "|---|---|---|---|---|",
    ]
    for name in names:
        for metric in SCENARIOS[name].metrics:
            columns = []
            medians = []
            for label in labels:
                values = [
                    float(r[metric])  # type: ignore[arg-type]
                    for r in results
                    if r["scenario"] == name and r["label"] == label
                ]
                if not values:
                    break
                median, iqr = stats(values)
                medians.append(median)
                columns.append(f"{median:.4g} ({iqr:.2g})")
            if len(medians) == 2:
                ratio = medians[1] / medians[0]
                lines.append(f"| {name} | {metric} | {columns[0]} | {columns[1]} | {ratio:.3f} |")
    return "\n".join(lines) + "\n"


def micro(checkouts: list[Checkout], out: Path) -> None:
    files = []
    for checkout in checkouts:
        path = out / f"micro-{checkout.label}.json"
        command = [
            "uv", "run", "--project", str(checkout.path), "--with", "pyperf",
            "python", str(BENCH / "micro.py"), "--affinity", STACK_CPU, "-o", str(path),
        ]  # fmt: skip
        subprocess.run(command, check=True)
        files.append(str(path))
    compare = ["uv", "run", "--with", "pyperf", "python", "-m", "pyperf", "compare_to", "--table"]
    table = subprocess.run(
        [*compare, *files],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    (out / "micro.txt").write_text(table)
    print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--only", help="comma-separated scenarios: " + ", ".join(SCENARIOS))
    parser.add_argument("--micro", action="store_true", help="run the pyperf micro-benchmarks")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    parser.add_argument("--out", type=Path, default=BENCH / "results" / stamp)
    args = parser.parse_args()

    checkouts = [
        Checkout("baseline", args.baseline.resolve()),
        Checkout("candidate", args.candidate.resolve()),
    ]
    args.out.mkdir(parents=True, exist_ok=True)
    meta = {"checkouts": [c.describe() for c in checkouts], "reps": args.reps}
    (args.out / "meta.json").write_text(json.dumps(meta, indent=2))
    for checkout in meta["checkouts"]:
        print(f"{checkout['label']:9s} {checkout['commit']}  python {checkout['python']}")

    if args.micro:
        micro(checkouts, args.out)
    else:
        names = args.only.split(",") if args.only else list(SCENARIOS)
        macro(checkouts, names, args.reps, args.out)
    print(f"results in {args.out}")


if __name__ == "__main__":
    main()
