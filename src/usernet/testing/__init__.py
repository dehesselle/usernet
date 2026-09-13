"""Virtual network harness -- a peer for the stack to talk to.

Gives the stack a peer to talk to without any real network, and without the
shipping code ever growing a passive-open path.

Shipped rather than left in a test directory, because every tunnel built on
this package needs the same thing. ``pyac`` drives it through a fake CSTP
gateway, ``pyts`` through WireGuard, and the conformance suite replaces it
wholesale with a Linux kernel. Nothing here belongs in production code, but all
of it belongs in somebody else's tests -- which is why it lives behind an
import rather than a copied file.

``usernet.testing.tls_endpoint`` is deliberately not re-exported here: it needs
``trustme``, which is an optional extra. Import it directly if you have it.
"""

from usernet.testing.link import VirtualLink
from usernet.testing.peer import TcpPeer

__all__ = ["TcpPeer", "VirtualLink"]
