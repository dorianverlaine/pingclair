#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Decide what a release version may look like and how releases sort.

Every release decision that depends on the shape of a version lives here, so
the workflow, the cut-release script and the tests all read one rule instead
of three regular expressions that drift apart:

* ``X.Y.Z`` is a stable release, and the only kind that becomes "Latest".
* ``X.Y.Z-alpha.N`` is a preview of the next minor; ``X.Y.Z-alpha.N.M`` is a
  hotfix of that preview.
* ``X.Y.Z-beta.N`` and ``X.Y.Z-rc.N`` are the later prerelease stages.

Within one ``X.Y.Z`` the order is alpha < beta < rc < stable, which is also
semver's order for these spellings. ``0.0.0`` is refused outright: it is what
the default branch carries, and a tag of it would mean "a dev build".

Tags carry a ``v`` prefix (``v0.3.0-alpha.1``); the version itself does not.
"""

from __future__ import annotations

import re
import sys
from typing import Iterable

# 🎯 One pattern for every channel. The alpha hotfix is the only place a
# fourth number is allowed, because it is the only channel that needs one.
_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:alpha\.[0-9]+(?:\.[0-9]+)?|beta\.[0-9]+|rc\.[0-9]+))?"
)

# 🧭 Stable sorts after every prerelease of the same triple, so it gets the
# highest rank.
_CHANNEL_RANK = {"alpha": 0, "beta": 1, "rc": 2, "": 3}

DEV_VERSION = "0.0.0"


def is_valid_release_version(version: str) -> bool:
    """Return whether ``version`` is a version a release may carry."""
    return version != DEV_VERSION and _VERSION_RE.fullmatch(version) is not None


def is_prerelease(version: str) -> bool:
    """Return whether ``version`` is a preview rather than a stable release."""
    _require_valid(version)
    return "-" in version


def version_key(version: str) -> tuple[tuple[int, ...], int, tuple[int, ...]]:
    """Return a key that sorts versions in release order."""
    _require_valid(version)
    base, _, prerelease = version.partition("-")
    channel, _, suffix = prerelease.partition(".")
    return (
        tuple(int(part) for part in base.split(".")),
        _CHANNEL_RANK[channel],
        tuple(int(part) for part in suffix.split(".")) if suffix else (),
    )


def latest_version(tags: Iterable[str]) -> str | None:
    """Return the highest release version among ``v``-prefixed tags.

    📌 Tags that do not parse are skipped rather than refused: the repository
    already has history, and one oddly named old tag must not block every
    future release.
    """
    versions = [
        tag[1:]
        for tag in (raw.strip() for raw in tags)
        if tag.startswith("v") and is_valid_release_version(tag[1:])
    ]
    return max(versions, key=version_key, default=None)


def _require_valid(version: str) -> None:
    if not is_valid_release_version(version):
        raise ValueError(f"invalid release version: {version!r}")


def _main(argv: list[str]) -> int:
    usage = (
        "usage: versions.py check <version>\n"
        "       versions.py github-flags <version>\n"
        "       versions.py latest-tag < tags\n"
        "       versions.py newer <version> <than>"
    )
    if not argv:
        print(usage, file=sys.stderr)
        return 2
    command, args = argv[0], argv[1:]

    if command == "check" and len(args) == 1:
        if is_valid_release_version(args[0]):
            return 0
        print(f"🚫 {args[0]!r} is not a release version", file=sys.stderr)
        return 1

    if command == "github-flags" and len(args) == 1:
        # 🚧 Printed as `key=value` lines so a workflow can append them to
        # $GITHUB_OUTPUT unchanged.
        if not is_valid_release_version(args[0]):
            print(f"🚫 {args[0]!r} is not a release version", file=sys.stderr)
            return 1
        pre = is_prerelease(args[0])
        print(f"prerelease={'true' if pre else 'false'}")
        print(f"make_latest={'false' if pre else 'true'}")
        return 0

    if command == "latest-tag" and not args:
        latest = latest_version(sys.stdin)
        if latest is not None:
            print(latest)
        return 0

    if command == "newer" and len(args) == 2:
        for version in args:
            if not is_valid_release_version(version):
                print(f"🚫 {version!r} is not a release version", file=sys.stderr)
                return 2
        return 0 if version_key(args[0]) > version_key(args[1]) else 1

    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
