# L3 conformance — our TCP against a real Linux kernel

Every other test in this repository proves *self-consistency*. The `vnet` suite runs two
instances of our own stack against each other, so a shared misreading of RFC 9293 passes
every assertion on both sides and looks green. This suite is the answer to that: a Linux
tun device, with the kernel's TCP on the other end, disagreeing with us.

Linux only. It is not collected on any other platform, so a Windows run stays green
without pretending these ran.

## Running it

```sh
sudo sh tests/conformance/setup.sh          # once per boot; creates usernet0
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

### The runs that actually stress recovery

A tun device is lossless and has no latency, so a clean run exercises the happy path only.
The interesting ones are impaired:

```sh
sudo sh tests/conformance/impair.sh [profile]
USERNET_TUN_NETEM=1 uv run pytest tests/conformance -v
sudo sh tests/conformance/impair.sh --off
```

Each profile degrades both directions and exercises a different part of recovery. CI runs
all of them, one job each:

| Profile | Netem | What it exercises |
| --- | --- | --- |
| `loss` (default) | 20 ms, 2 % loss | Fast retransmit, NewReno recovery, the RTO. |
| `reorder` | 20 ms, 25 % sent early | Reassembly, and reordering costing a duplicate ACK rather than a resend. |
| `duplicate` | 20 ms, 5 % duplicated | Duplicates trimmed and never delivered twice. |
| `corrupt` | 20 ms, 1 % with a flipped bit | The receive checksum, both ours and the kernel's. |
| `bottleneck` | 20 ms at 10 Mbit/s, 64-packet queue | Loss from queue overflow, driven by our own sending rate. |
| `long-fat` | 100 ms, 0.5 % loss | A large window in flight: scaling, cwnd growth, recovery with a long RTT. |

`impair.sh <delay> [loss]` still sets an arbitrary delay and loss, as `bench/run.py` does.

**Do not just do `tc qdisc add dev usernet0 root netem ...`.** A root qdisc is *egress only*, so
it degrades kernel→us and leaves our own packets untouched — which means our retransmission,
the code most likely to be wrong, is never exercised at all. The run looks impaired and
tests half of what it appears to. `impair.sh` redirects ingress through an `ifb` device so
both directions are degraded; that is what surfaced the two window bugs.

`USERNET_TUN_NETEM=1` disables the packet-count assertions, which are meaningless once loss is
deliberate. Everything else still has to hold — byte-exactness above all. **Both kinds of run
are worth doing**; the clean one catches protocol errors, the impaired ones catch recovery
errors, and they fail in completely different ways.

### What the kernel offers

The kernel normally offers window scaling and an MSS that fills the link. Two settings make
it offer less, and the suite follows whatever it offers:

```sh
sudo sysctl -w net.ipv4.tcp_window_scaling=0
sudo ip route change 10.99.0.0/24 dev usernet0 proto kernel scope link src 10.99.0.1 advmss 536
uv run pytest tests/conformance -v
```

Both are global, so undo them afterwards: set `tcp_window_scaling` back to 1, and rerun
`setup.sh`, which recreates the route. CI runs this as the `kernel-variants` job.

Timestamps and SACK need no variant. Linux offers them in a SYN-ACK only when the SYN did,
and ours offers neither.

### A narrow hop

```sh
sudo sh tests/conformance/pmtu.sh
uv run pytest tests/conformance/test_kernel_pmtu.py -v
sudo sh tests/conformance/pmtu.sh --off
```

`pmtu.sh` puts a far network namespace (10.98.0.2) behind a 1000-byte hop, with IP forwarding
on. Our full-sized segments cannot cross the hop, so the kernel answers them with ICMP
"fragmentation needed", and the upload only completes if we act on it. Without the
namespace the test skips and says why. CI runs it in the clean job.

### A long run

`test_kernel_soak.py` keeps eight connections busy with random uploads and downloads for as
many seconds as `USERNET_CONFORMANCE_SOAK` says, checking every byte, then checks the stack is
empty again. It skips without that variable. The nightly workflow runs it for ten minutes
under the `loss`, `reorder` and `bottleneck` profiles.

### What this suite does not cover

The peer is always Linux. Other kernels' TCP, and middleboxes that rewrite options or clamp
the MSS, are not tested here. They are what a real gateway's peers will be.

## What the addresses mean

| | |
| --- | --- |
| `usernet0` | the tun device; packets written to its fd enter the kernel as if from a wire |
| `10.99.0.1` | the kernel's end — real Linux TCP listens and answers here |
| `10.99.0.2` | us; the address our stack believes it has |

Override with `USERNET_TUN_DEV`, `USERNET_TUN_HOST`, `USERNET_TUN_STACK` if that subnet is taken.

## Reading a failure

Every test prints its packet trace during teardown. pytest discards captured output for
passing tests and shows it for failing ones, so a green run stays quiet and a red one comes
with the last 400 packets already formatted:

```text
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

1. **A firewall.** `sudo iptables -I INPUT -i usernet0 -j ACCEPT`
2. **The interface is down or lost its address.** `ip addr show usernet0`
3. **Reverse-path filtering.** `sudo sysctl -w net.ipv4.conf.usernet0.rp_filter=0`

`preflight` warns about the first and checks the second and third.
