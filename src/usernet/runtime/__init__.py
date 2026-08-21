"""The asyncio shell around the sans-IO stack.

Everything that touches a socket, a clock, or a timer lives here. The stack
itself stays synchronous and deterministic; this layer supplies it with time
and moves packets to and from the tunnel.
"""
