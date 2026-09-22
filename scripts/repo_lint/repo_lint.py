#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Check repository invariants that CI enforces mechanically.

The rules here are the parts of the house contract that a grep can own:
workspace metadata inheritance, workspace-lint opt-in, no crate feature
flags, no forbidden TLS dependencies, and the unit file the installer writes
for the `curl | bash` path agreeing with the one in `scripts/`. A rule that
only lives in prose is a rule that will be forgotten; this script is where
that stops.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_DEPENDENCY_NAMES = ("openssl-sys", "pingora-openssl", "native-tls")
INHERIT_FIELDS = ("version", "edition", "license")
SERVICE_UNIT_PATH = ROOT / "scripts" / "pingclair.service"
INSTALLER_PATH = ROOT / "scripts" / "install.sh"
# 🧷 The installer has to work with no repository beside it, so the unit is
# embedded rather than copied. This marker is what ties the embedded copy to
# the canonical file; the heredoc itself is written with a quoted delimiter so
# the shell cannot expand anything into it.
INSTALLER_UNIT_MARKER = "cat > /etc/systemd/system/pingclair.service <<'EOF'"
INSTALLER_UNIT_TERMINATOR = "EOF"
# 🔑 Lines the installed unit cannot get wrong. `ExecReload` shipped the signal
# the server drops for months, and the restart policy is what decides whether a
# rejected configuration leaves a failed unit or a five-second restart loop.
REQUIRED_UNIT_LINES = (
    "ExecReload=/bin/kill -USR1 $MAINPID",
    "Restart=on-failure",
    "RestartPreventExitStatus=1",
)

_SECTION_RE = re.compile(r"^\[(?P<name>[^\]]+)\]\s*$", re.MULTILINE)
_FORBIDDEN_RE = re.compile(
    r"^\s*(?P<name>openssl-sys|pingora-openssl|native-tls)\s*=",
    re.MULTILINE,
)


def sections(text: str) -> dict[str, tuple[int, int]]:
    """Map each top-level TOML section name to its character span."""
    result: dict[str, tuple[int, int]] = {}
    matches = list(_SECTION_RE.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[match.group("name")] = (match.start(), end)
    return result


def section_body(text: str, name: str) -> str:
    """Return one top-level TOML section including its header line."""
    span = sections(text).get(name)
    return text[span[0] : span[1]] if span else ""


def inherits_field(text: str, field: str) -> bool:
    """Return whether one package field is inherited from the workspace."""
    pattern = re.compile(
        rf"^{re.escape(field)}\.workspace\s*=\s*true"
        rf"|^{re.escape(field)}\s*=\s*\{{workspace\s*=\s*true\s*\}}",
        re.MULTILINE,
    )
    return pattern.search(text) is not None


def manifest_errors(text: str, is_root: bool) -> list[str]:
    """Return house-rule violations for one Cargo manifest."""
    errors: list[str] = []
    if not is_root:
        package = section_body(text, "package")
        for field in INHERIT_FIELDS:
            if not inherits_field(package, field):
                errors.append(f"[package] must inherit {field} from [workspace.package]")
        lints = section_body(text, "lints")
        if "workspace = true" not in lints:
            errors.append("[lints] must opt into workspace = true")
    if "features" in sections(text):
        errors.append("crate feature flags are banned ([features])")
    for match in _FORBIDDEN_RE.finditer(text):
        errors.append(f"forbidden TLS dependency {match.group('name')}")
    return errors


def unit_errors(text: str) -> list[str]:
    """Return the invariants the canonical service unit must keep."""
    return [
        f"the service unit must contain `{line}`"
        for line in REQUIRED_UNIT_LINES
        if line not in text
    ]


def embedded_unit(install_sh: str) -> str | None:
    """Return the unit `install.sh` writes standalone, or None when it is gone.

    The block is read out of the script rather than executed, so this check
    needs no root, no systemd, and no machine to install onto.
    """
    lines = install_sh.splitlines(keepends=True)
    marker = next(
        (index for index, line in enumerate(lines) if INSTALLER_UNIT_MARKER in line),
        None,
    )
    if marker is None:
        return None
    body: list[str] = []
    for line in lines[marker + 1 :]:
        if line.rstrip("\n") == INSTALLER_UNIT_TERMINATOR:
            return "".join(body)
        body.append(line)
    return None


def unit_parity_errors(canonical: str, install_sh: str) -> list[str]:
    """Return why the standalone install path differs from the repository unit.

    Two copies of one unit file is a duplication the house rules normally
    delete; this one cannot be deleted, because the `curl | bash` install has
    no repository beside it. It is therefore compared instead, and the first
    line that differs is named so the fix is obvious.
    """
    embedded = embedded_unit(install_sh)
    if embedded is None:
        return [
            f"no `{INSTALLER_UNIT_MARKER}` block: the standalone install path "
            "cannot write a service unit"
        ]
    if embedded == canonical:
        return []
    expected = canonical.splitlines()
    actual = embedded.splitlines()
    for index in range(max(len(expected), len(actual))):
        wanted = expected[index] if index < len(expected) else "<end of file>"
        found = actual[index] if index < len(actual) else "<end of file>"
        if wanted != found:
            return [
                f"the embedded unit differs from scripts/pingclair.service at "
                f"line {index + 1}: expected {wanted!r}, found {found!r}"
            ]
    return ["the embedded unit differs from scripts/pingclair.service"]


def cargo_manifests() -> list[Path]:
    """Return every handwritten workspace manifest outside the vendored tree."""
    candidates = [ROOT / "Cargo.toml"]
    candidates.extend(ROOT.glob("*/Cargo.toml"))
    return sorted(p for p in candidates if "/vendor/" not in p.as_posix())


def main() -> int:
    failures: dict[str, list[str]] = {}
    root_manifest = ROOT / "Cargo.toml"
    for manifest in cargo_manifests():
        errors = manifest_errors(
            manifest.read_text(encoding="utf-8"),
            manifest == root_manifest,
        )
        if errors:
            failures[str(manifest.relative_to(ROOT))] = errors
    unit = SERVICE_UNIT_PATH.read_text(encoding="utf-8")
    unit_problems = unit_errors(unit)
    if unit_problems:
        failures[str(SERVICE_UNIT_PATH.relative_to(ROOT))] = unit_problems
    parity_problems = unit_parity_errors(
        unit,
        INSTALLER_PATH.read_text(encoding="utf-8"),
    )
    if parity_problems:
        failures[str(INSTALLER_PATH.relative_to(ROOT))] = parity_problems
    if not failures:
        print("✅ repository invariants hold")
        return 0
    print("❌ repository invariants violated:")
    for path, errors in failures.items():
        print(f"{path}:")
        for error in errors:
            print(f"  - {error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
