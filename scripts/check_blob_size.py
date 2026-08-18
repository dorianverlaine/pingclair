#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Fail when a tracked file exceeds the repository blob-size budget.

Large blobs make clones and reviews slower and hide binary changes behind a
diff no one can read. The allowlist exists for artifacts that are deliberately
large, and every entry must say why it is there.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def tracked_files(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [entry for entry in proc.stdout.decode().split("\0") if entry]


def load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    entries: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.add(stripped)
    return entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-bytes", type=int, default=512000)
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=ROOT / ".github" / "blob-size-allowlist.txt",
    )
    args = parser.parse_args()
    allowlist = load_allowlist(args.allowlist)
    failures: list[tuple[str, int]] = []
    for relative in tracked_files(ROOT):
        if relative in allowlist:
            continue
        path = ROOT / relative
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        if size > args.max_bytes:
            failures.append((relative, size))
    if not failures:
        print("✅ all tracked blobs are within the size budget")
        return 0
    print(f"❌ tracked files exceed {args.max_bytes} bytes:")
    for relative, size in failures:
        print(f"  {size:>10}  {relative}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
