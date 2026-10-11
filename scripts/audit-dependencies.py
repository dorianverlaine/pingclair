#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""🛡️ Audit the resolved graph without hiding the vendored Pingora origin."""

import json
from pathlib import Path
import subprocess
import tempfile
import tomllib


def main():
    root = Path(__file__).resolve().parent.parent
    provenance = json.loads((root / "vendor/pingora-proxy/UPSTREAM.json").read_text())
    lock = (root / "Cargo.lock").read_text()
    blocks = lock.split("[[package]]")
    found = 0
    for index, block in enumerate(blocks[1:], 1):
        package = tomllib.loads("[[package]]" + block)["package"][0]
        if package["name"] != provenance["name"]:
            continue
        if package["version"] != provenance["version"] or "source" in package:
            raise SystemExit("🚫 Pingora audit provenance no longer matches the vendored package")
        # 🧾 Restore only the origin; versions and dependency edges stay locked.
        version = f'version = "{package["version"]}"\n'
        origin = f'source = "{provenance["source"]}"\nchecksum = "{provenance["checksum"]}"\n'
        blocks[index] = block.replace(version, version + origin, 1)
        found += 1
    if found != 1:
        raise SystemExit("🚫 Expected exactly one vendored Pingora package in Cargo.lock")

    subprocess.run(["cargo", "audit"], cwd=root, check=True)
    with tempfile.TemporaryDirectory(prefix="pingclair-audit-") as directory:
        audit_lock = Path(directory) / "Cargo.lock"
        audit_lock.write_text("[[package]]".join(blocks))
        print("🛡️ Auditing the vendored Pingora registry origin", flush=True)
        subprocess.run(["cargo", "audit", "--file", str(audit_lock)], cwd=root, check=True)


if __name__ == "__main__":
    main()
