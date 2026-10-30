# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Hypothesis profiles, chosen with ``HYPOTHESIS_PROFILE``.

``ci`` is the default and sized for every push: the 30 s timeout applies, so
it searches broadly but not deeply. ``nightly`` searches far deeper and needs
the timeout lifted (``-o timeout=0``). Both print the reproduction blob on a
failure, because a CI failure that cannot be replayed is only half a finding.
No deadline in either: a slow shared runner is not a bug in the stack.
"""

from __future__ import annotations

import os

from hypothesis import settings

settings.register_profile("ci", deadline=None, print_blob=True)
# Sized by memory, not time: Hypothesis keeps every example it has explored
# to steer towards new ones, and 5000 runs of 200 steps took the stateful
# suite past 3.5 GB. Each night draws new examples, so the depth adds up
# across nights instead.
settings.register_profile(
    "nightly", deadline=None, print_blob=True, max_examples=2000, stateful_step_count=100
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
