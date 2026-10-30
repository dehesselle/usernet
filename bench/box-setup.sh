#!/bin/sh

# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

# Prepare a fresh Ubuntu box for bench/run.py. Run as root from the
# candidate checkout:
#
#   sh bench/box-setup.sh [baseline-ref]      # default: master
#
# Leaves ../usernet-base as a worktree at the baseline ref, both checkouts
# synced against the same interpreter, and the tun device up at production's
# MTU. Safe to re-run; re-run after moving either checkout to a new commit.

set -eu

PYTHON=${USERNET_BENCH_PYTHON:-3.12.14}
BASE_REF=${1:-master}
BASE_DIR=../usernet-base

if [ "$(id -u)" -ne 0 ]; then
    echo "this needs root (tun device, tc): sudo sh $0" >&2
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    PATH="$HOME/.local/bin:$PATH"
fi
uv python install "$PYTHON"

if [ -d "$BASE_DIR" ]; then
    git -C "$BASE_DIR" checkout --detach "$BASE_REF"
else
    git worktree add --detach "$BASE_DIR" "$BASE_REF"
fi
(cd "$BASE_DIR" && uv sync --python "$PYTHON")
uv sync --python "$PYTHON"

# Production's tunnel MTU rather than setup.sh's 1500, so segments are the
# size they are in real use.
USERNET_TUN_MTU=${USERNET_TUN_MTU:-1406} sh tests/conformance/setup.sh
uv run python -m tests.conformance.preflight

echo
echo "next:  uv run python bench/run.py --baseline $BASE_DIR --candidate ."
