"""L3 conformance: our TCP against a real Linux kernel over a tun device.

Everything else in the test tree proves self-consistency. The vnet suite runs
two instances of *our* stack against each other, so both halves can be
consistently wrong together and every assertion still passes. This package is
the answer to that: a real kernel on the other side, disagreeing with us.

Linux only, and not collected anywhere else. See ``README.md`` for setup.
"""
