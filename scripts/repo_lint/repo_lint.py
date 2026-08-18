#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Check repository invariants that CI enforces mechanically.

The rules here are the parts of the house contract that a grep can own:
workspace metadata inheritance, workspace-lint opt-in, no crate feature
flags, and no forbidden TLS dependencies. A rule that only lives in prose is
a rule that will be forgotten; this script is where that stops.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_DEPENDENCY_NAMES = ("openssl-sys", "pingora-openssl", "native-tls")
INHERIT_FIELDS = ("version", "edition", "license")

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


def cargo_manifests() -> list[Path]:
    """Return every handwritten workspace manifest outside the vendored tree."""
    candidates = [ROOT / "Cargo.toml"]
    candidates.extend(ROOT.glob("*/Cargo.toml"))
    return sorted(p for p in candidates if "/vendor/" not in p.as_posix())


def run_vendored_h2_check() -> list[str]:
    """Return failure text when the vendored h2 fork is not wired correctly."""
    script = ROOT / "scripts" / "check-vendored-h2.sh"
    proc = subprocess.run([str(script)], cwd=ROOT, capture_output=True, text=True)
    if proc.returncode == 0:
        return []
    return [f"scripts/check-vendored-h2.sh failed:\n{proc.stdout}{proc.stderr}"]


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
    h2_errors = run_vendored_h2_check()
    if h2_errors:
        failures["scripts/check-vendored-h2.sh"] = h2_errors
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
