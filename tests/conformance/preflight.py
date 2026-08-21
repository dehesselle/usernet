"""Environment check for the L3 conformance suite.

    uv run python -m tests.conformance.preflight

Run this before pytest. Every check names the command that fixes it, and the
report ends with a block of raw ``ip`` output -- so if something is wrong on a
machine the author cannot reach, one paste carries the whole picture.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

DEVICE = os.environ.get("USERNET_TUN_DEV", "usernet0")
HOST_IP = os.environ.get("USERNET_TUN_HOST", "10.99.0.1")
STACK_IP = os.environ.get("USERNET_TUN_STACK", "10.99.0.2")
TUN_PATH = "/dev/net/tun"

SETUP = "sudo sh tests/conformance/setup.sh"


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def ok(self, what: str, detail: str = "") -> None:
        print(f"  ok    {what}{f'  ({detail})' if detail else ''}")

    def fail(self, what: str, fix: str) -> None:
        print(f"  FAIL  {what}\n        fix: {fix}")
        self.failures.append(what)

    def warn(self, what: str, note: str) -> None:
        print(f"  warn  {what}\n        {note}")
        self.warnings.append(what)


def run(*command: str) -> tuple[int, str]:
    """Run a command, returning (status, combined output). Never raises."""
    if shutil.which(command[0]) is None:
        return 127, f"{command[0]}: not found"
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return done.returncode, (done.stdout + done.stderr).strip()


def check_platform(report: Report) -> bool:
    if sys.platform != "linux":
        report.fail(
            f"platform is {sys.platform}, not linux",
            "these tests need a real kernel TCP stack behind a tun device; "
            "run them on Linux or under WSL2",
        )
        return False
    report.ok("platform is linux", f"python {sys.version.split()[0]}")
    return True


def check_tun_module(report: Report) -> bool:
    if not os.path.exists(TUN_PATH):
        report.fail(f"{TUN_PATH} is missing", "sudo modprobe tun")
        return False
    if not os.access(TUN_PATH, os.R_OK | os.W_OK):
        report.fail(f"{TUN_PATH} is not readable/writable by this user", SETUP)
        return False
    report.ok(f"{TUN_PATH} is present and accessible")
    return True


def check_interface(report: Report) -> bool:
    status, output = run("ip", "-o", "addr", "show", DEVICE)
    if status != 0:
        report.fail(f"interface {DEVICE} does not exist", SETUP)
        return False

    healthy = True
    if f"inet {HOST_IP}/" not in output:
        report.fail(
            f"{DEVICE} has no address {HOST_IP}",
            f"{SETUP}  (the tests reach the kernel at {HOST_IP})",
        )
        healthy = False
    else:
        report.ok(f"{DEVICE} has {HOST_IP}")

    _, link = run("ip", "-o", "link", "show", DEVICE)
    # The administrative flag inside <...>, not the operational `state`. A tun
    # device has no carrier until a process attaches to its fd, so before the
    # tests start it reports NO-CARRIER and `state DOWN` while being perfectly
    # healthy. Reading `state` here fails every run before the first one.
    flags = link.partition("<")[2].partition(">")[0].split(",")
    if "UP" not in flags:
        report.fail(f"{DEVICE} is not up ({link.strip()})", f"sudo ip link set dev {DEVICE} up")
        healthy = False
    else:
        report.ok(f"{DEVICE} is up", "NO-CARRIER until a process attaches, which is expected")

    mtu = next((part for part in link.split() if part.isdigit()), None)
    if "mtu 1500" not in link:
        report.warn(
            f"{DEVICE} mtu is not 1500 (saw {mtu})",
            "not fatal -- conftest.py reads the real value -- but the tests were "
            "written against 1500",
        )
    return healthy


def check_routing(report: Report) -> bool:
    status, output = run("ip", "route", "get", STACK_IP)
    if status != 0:
        report.fail(f"no route to {STACK_IP}", SETUP)
        return False
    if f"dev {DEVICE}" not in output:
        report.fail(
            f"{STACK_IP} does not route via {DEVICE}: {output}",
            f"something else owns that subnet; set USERNET_TUN_HOST/USERNET_TUN_STACK "
            f"to an unused range and re-run {SETUP}",
        )
        return False
    report.ok(f"{STACK_IP} routes via {DEVICE}")
    return True


def check_attach(report: Report) -> bool:
    """The real test: can this process actually attach to the device?"""
    try:
        from tests.conformance.tun import TunDevice, TunSetupError
    except ImportError as exc:
        report.fail(f"cannot import the tun helper ({exc})", "run from the repository root")
        return False

    try:
        device = TunDevice(DEVICE)
    except TunSetupError as exc:
        report.fail(f"cannot attach to {DEVICE}", str(exc))
        return False
    device.close()
    report.ok(f"attached to {DEVICE} and detached cleanly")
    return True


def check_firewall(report: Report) -> None:
    """Best effort, and advisory only -- reading the ruleset usually needs root.

    Worth attempting anyway: a default-drop INPUT policy makes every test fail
    as a connect timeout, which looks exactly like a bug in our stack.
    """
    status, output = run("iptables", "-S", "INPUT")
    if status == 0 and "-P INPUT DROP" in output:
        report.warn(
            "iptables INPUT policy is DROP",
            f"the kernel may discard our packets before any listener sees them. "
            f"If tests time out, allow the interface: "
            f"sudo iptables -I INPUT -i {DEVICE} -j ACCEPT",
        )
        return
    _, nft = run("nft", "list", "chain", "inet", "filter", "input")
    if "policy drop" in nft:
        report.warn(
            "nftables input policy is drop",
            f"if tests time out, allow {DEVICE} explicitly",
        )


def diagnostics() -> str:
    """Raw output worth pasting when something is wrong."""
    sections = [
        ("ip -d link show " + DEVICE, ("ip", "-d", "link", "show", DEVICE)),
        ("ip addr show " + DEVICE, ("ip", "addr", "show", DEVICE)),
        ("ip route get " + STACK_IP, ("ip", "route", "get", STACK_IP)),
        ("tc qdisc show dev " + DEVICE, ("tc", "qdisc", "show", "dev", DEVICE)),
    ]
    parts = []
    for title, command in sections:
        _, output = run(*command)
        parts.append(f"$ {title}\n{output}")
    return "\n\n".join(parts)


def main() -> int:
    print(
        f"usernet L3 conformance preflight  (device {DEVICE}, kernel {HOST_IP}, stack {STACK_IP})\n"
    )
    report = Report()

    if check_platform(report) and check_tun_module(report):
        # Not gated on check_interface: routing and attaching are independent,
        # and knowing which of the three is broken beats knowing only the first.
        check_interface(report)
        check_routing(report)
        check_attach(report)
        check_firewall(report)

    print("\n" + "=" * 72)
    if report.failures:
        print(f"{len(report.failures)} check(s) failed; the suite would skip.")
        print(f"start with:  {SETUP}")
    else:
        print("all checks passed. run:")
        print("  uv run pytest tests/conformance -v")
        print("\nthen, for the case that actually stresses retransmission:")
        print("  sudo sh tests/conformance/impair.sh")
        print("  USERNET_TUN_NETEM=1 uv run pytest tests/conformance -v")
        print("  sudo sh tests/conformance/impair.sh --off")
    if report.warnings:
        print(f"({len(report.warnings)} warning(s) above -- read them if tests time out)")

    print("\n" + "=" * 72)
    print("environment (paste this if you report a failure):\n")
    print(diagnostics())
    return 1 if report.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
