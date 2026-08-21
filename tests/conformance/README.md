# L3 conformance — our TCP against a real Linux kernel

Every other test in this repository proves *self-consistency*. The `vnet` suite runs two
instances of our own stack against each other, so a shared misreading of RFC 9293 passes
every assertion on both sides and looks green. This suite is the answer to that: a Linux
tun device, with the kernel's TCP on the other end, disagreeing with us.

Linux only. It is not collected on any other platform, so a Windows run stays green
without pretending these ran.

## Running it

```sh
sudo sh tests/conformance/setup.sh          # once per boot; creates pyac0
uv run python -m tests.conformance.preflight
uv run pytest tests/conformance -v
```

`setup.sh` needs root because creating an interface does. **pytest does not** — the device
is created owned by the invoking user, which is the point of `ip tuntap add ... user`.

`preflight` checks every prerequisite, names the command that fixes each one, and ends with
a block of raw `ip` output. If anything is wrong, that block is the thing to paste.

Under WSL2 this all works unchanged: WSL2 is a real kernel.

### Without root at all

```sh
unshare -rn sh -c 'sh tests/conformance/setup.sh && exec uv run pytest tests/conformance -v'
```

A user namespace makes you root inside it, with a private network stack. Nothing leaks to
the host, and the suite cannot interfere with your real interfaces.

### The run that actually stresses retransmission

A tun device is lossless and has no latency, so a clean run exercises the happy path only.
The interesting one is impaired:

```sh
sudo sh tests/conformance/impair.sh
PYAC_TUN_NETEM=1 uv run pytest tests/conformance -v
sudo sh tests/conformance/impair.sh --off
```

**Do not just do `tc qdisc add dev pyac0 root netem ...`.** A root qdisc is *egress only*, so
it degrades kernel→us and leaves our own packets untouched — which means our retransmission,
the code most likely to be wrong, is never exercised at all. The run looks impaired and
tests half of what it appears to. `impair.sh` redirects ingress through an `ifb` device so
both directions are degraded; that is what surfaced the two window bugs.

`PYAC_TUN_NETEM=1` disables the packet-count assertions, which are meaningless once loss is
deliberate. Everything else still has to hold — byte-exactness above all. **Both runs are
worth doing**; the clean one catches protocol errors, the impaired one catches recovery
errors, and they fail in completely different ways.

## What the addresses mean

| | |
|---|---|
| `pyac0` | the tun device; packets written to its fd enter the kernel as if from a wire |
| `10.99.0.1` | the kernel's end — real Linux TCP listens and answers here |
| `10.99.0.2` | us; the address our stack believes it has |

Override with `PYAC_TUN_DEV`, `PYAC_TUN_HOST`, `PYAC_TUN_STACK` if that subnet is taken.

## Reading a failure

Every test prints its packet trace during teardown. pytest discards captured output for
passing tests and shows it for failing ones, so a green run stays quiet and a red one comes
with the last 400 packets already formatted:

```
  0.0121 -> tcp  10.99.0.2:49153 > 10.99.0.1:41234 [S  ] seq=0 ack=- win=65535 len=0 mss=1460 ws=3 (44B)
  0.0123 <- tcp  10.99.0.1:41234 > 10.99.0.2:49153 [SA ] seq=0 ack=1 win=65160 len=0 mss=1460 ws=7 (44B)
  0.0124 -> tcp  10.99.0.2:49153 > 10.99.0.1:41234 [A  ] seq=1 ack=1 win=65535 len=0 (40B)
```

Sequence numbers are relative to the first value seen in each direction, as Wireshark shows
them; `*` marks a number no ISN was recorded for. **Paste the whole trace** — where it stops
is usually the entire diagnosis.

Timeouts are deliberately raised as ordinary test failures rather than left to
`pytest-timeout`, which kills the process and takes the trace with it.

## When everything times out

Almost always the environment, not the stack — the trace will show our packets leaving and
nothing coming back:

1. **A firewall.** `sudo iptables -I INPUT -i pyac0 -j ACCEPT`
2. **The interface is down or lost its address.** `ip addr show pyac0`
3. **Reverse-path filtering.** `sudo sysctl -w net.ipv4.conf.pyac0.rp_filter=0`

`preflight` warns about the first and checks the second and third.
