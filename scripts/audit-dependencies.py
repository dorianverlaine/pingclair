#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""🛡️ Audit the resolved graph without hiding vendored registry origins."""

import json
from pathlib import Path
import subprocess
import tempfile
import tomllib


def main():
    root = Path(__file__).resolve().parent.parent
    lock = (root / "Cargo.lock").read_text()
    blocks = lock.split("[[package]]")
    provenance_paths = (
        root / "vendor/pingora-header-serde/UPSTREAM.json",
        root / "vendor/pingora-proxy/UPSTREAM.json",
    )
    for provenance_path in provenance_paths:
        provenance = json.loads(provenance_path.read_text())
        found = 0
        for index, block in enumerate(blocks[1:], 1):
            package = tomllib.loads("[[package]]" + block)["package"][0]
            if package["name"] != provenance["name"]:
                continue
            if package["version"] != provenance["version"] or "source" in package:
                raise SystemExit(
                    f"🚫 Audit provenance no longer matches {provenance['name']}"
                )
            # 🧾 Restore only the origin; versions and dependency edges stay locked.
            version = f'version = "{package["version"]}"\n'
            origin = (
                f'source = "{provenance["source"]}"\n'
                f'checksum = "{provenance["checksum"]}"\n'
            )
            blocks[index] = block.replace(version, version + origin, 1)
            found += 1
        if found != 1:
            raise SystemExit(
                f"🚫 Expected exactly one vendored {provenance['name']} package in Cargo.lock"
            )

    subprocess.run(["cargo", "audit"], cwd=root, check=True)
    with tempfile.TemporaryDirectory(prefix="pingclair-audit-") as directory:
        audit_lock = Path(directory) / "Cargo.lock"
        audit_lock.write_text("[[package]]".join(blocks))
        print("🛡️ Auditing vendored registry origins", flush=True)
        subprocess.run(["cargo", "audit", "--file", str(audit_lock)], cwd=root, check=True)


if __name__ == "__main__":
    main()
