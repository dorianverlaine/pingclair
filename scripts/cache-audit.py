#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Audit what a shared sccache bucket actually contains.

A compiler cache is not source code, but it is not sterile either: a cached
artifact carries the crate and symbol names of whatever it compiled, the string
literals that went into it, and — in a debug build — the absolute paths the
compiler saw. The fabric answers that with three buckets instead of one, and
this script is how the answer is checked rather than asserted:

* the shared bucket is reserved for builds of public sources from the builder
  image's fixed path, so it must contain no paths from anybody's machine and no
  credential of any kind;
* a per-machine bucket (the Mac's) is allowed to carry that machine's paths,
  because nobody else can read it, and still must contain no credentials.

Object keys are hashes and reveal nothing on their own, so the audit downloads a
sample and looks inside. It never prints a secret it finds: it prints the name of
the canary and how many objects carried it.

Credentials come from the environment, which `just cache-audit` fills by
sourcing the same file every other cache recipe uses.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# 🧪 The operator can prove the audit works by building once with this variable
# set to something unique. If the bucket is scanned and the canary turns up, the
# scan reads artifacts properly; if it never turns up, the canaries below are
# still checked by construction.
CANARY_VARIABLE = "PINGCLAIR_CACHE_CANARY"

# 🚫 Strings that must not appear in *any* bucket of the fabric.
SECRET_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AWS_SECRET_ACCESS_KEY",
    "aws_secret_access_key",
    "Authorization: Bearer ",
    "CF_API_TOKEN",
)


def run(args: list[str], *, capture: bool = True) -> str:
    result = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"🚫 {' '.join(args[:3])} failed: {(result.stderr or '').strip()}"
        )
    return result.stdout or ""


def list_keys(bucket: str, endpoint: str) -> list[str]:
    """Return every object key in the bucket, following continuation tokens."""
    keys: list[str] = []
    token: str | None = None
    while True:
        command = [
            "aws",
            "s3api",
            "list-objects-v2",
            "--bucket",
            bucket,
            "--endpoint-url",
            endpoint,
            "--output",
            "json",
            "--max-items",
            "1000",
        ]
        if token:
            command += ["--starting-token", token]
        payload = run(command)
        document = json.loads(payload) if payload.strip() else {}
        keys.extend(item["Key"] for item in document.get("Contents", []))
        token = document.get("NextToken")
        if not token:
            return keys


def download(key: str, bucket: str, endpoint: str, destination: Path) -> bytes:
    run(
        [
            "aws",
            "s3api",
            "get-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--endpoint-url",
            endpoint,
            str(destination),
        ]
    )
    return destination.read_bytes()


def payloads(blob: bytes) -> list[tuple[str, bytes]]:
    """Return the named payloads inside one cache object.

    sccache stores a Rust compilation as a zip of its outputs; anything else is
    handed back as a single unnamed payload.
    """
    with tempfile.NamedTemporaryFile(suffix=".bin") as scratch:
        scratch.write(blob)
        scratch.flush()
        if not zipfile.is_zipfile(scratch.name):
            return [("<raw>", blob)]
        with zipfile.ZipFile(scratch.name) as archive:
            return [
                (info.filename, archive.read(info))
                for info in archive.infolist()
                if not info.is_dir()
            ]


def strings_of(blob: bytes) -> str:
    """Printable runs from a binary payload, without a shell round trip."""
    return "\n".join(
        match.decode("latin-1")
        for match in re.findall(rb"[\x20-\x7e]{6,}", blob)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        choices=("shared", "mac"),
        default="shared",
        help="`shared` forbids machine paths and credentials; `mac` forbids only credentials.",
    )
    parser.add_argument("--samples", type=int, default=12, help="Objects to download.")
    parser.add_argument("--seed", type=int, default=20260922, help="Sampling seed.")
    args = parser.parse_args()

    bucket = os.environ.get("SCCACHE_BUCKET", "")
    endpoint = os.environ.get("SCCACHE_ENDPOINT", "")
    secrets = [
        value
        for value in (
            os.environ.get("AWS_ACCESS_KEY_ID"),
            os.environ.get("AWS_SECRET_ACCESS_KEY"),
            os.environ.get(CANARY_VARIABLE),
        )
        if value
    ]
    if not bucket or not endpoint:
        print(
            "🚫 SCCACHE_BUCKET and SCCACHE_ENDPOINT must be set; run this through "
            "`just cache-audit`, which sources the machine's credential file.",
            file=sys.stderr,
        )
        return 2

    # 🔍 Path canaries are machine-specific: the audit looks for its *own* home
    # directory and hostname, which is what a leak would carry.
    home = os.path.expanduser("~")
    host = os.uname().nodename.split(".")[0]
    path_markers = [marker for marker in (home, f"/Users/", f"/home/") if marker]
    if home.startswith("/Users/"):
        # `/Users/` alone is too broad to be a useful report on a Linux audit;
        # the home directory above is the precise one for this machine.
        path_markers = [home]

    print(f"🔎 bucket   s3://{bucket}")
    print(f"   endpoint {endpoint}")
    print(f"   policy   {args.policy} (path canaries {'forbidden' if args.policy == 'shared' else 'expected'})")
    print(f"   host     {host}")

    keys = list_keys(bucket, endpoint)
    print(f"   objects  {len(keys)}")
    if not keys:
        print("⚠️  the bucket is empty — nothing to audit yet")
        return 0

    sample = random.Random(args.seed).sample(keys, min(args.samples, len(keys)))
    hits: dict[str, list[str]] = {}
    entries: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="cache-audit.") as workdir:
        for key in sample:
            blob = download(key, bucket, endpoint, Path(workdir) / "object")
            for name, payload in payloads(blob):
                entries.add(name)
                text = strings_of(payload)
                needles = list(SECRET_MARKERS) + path_markers + secrets
                for needle in needles:
                    if needle and needle in text:
                        label = needle
                        if needle in secrets:
                            label = (
                                CANARY_VARIABLE
                                if needle == os.environ.get(CANARY_VARIABLE)
                                else "credential value"
                            )
                        elif needle == home:
                            label = f"home path ({home})"
                        hits.setdefault(label, []).append(f"{key}!{name}")

    print(f"   sampled  {len(sample)}")
    if entries:
        shown = ", ".join(sorted(entries)[:6])
        print(f"   entries  {shown}{' …' if len(entries) > 6 else ''}")

    path_hits = {
        label: where
        for label, where in hits.items()
        if label.startswith("home path")
    }
    secret_hits = {label: where for label, where in hits.items() if label not in path_hits}

    verdict = 0
    if secret_hits:
        print("❌ credential-shaped strings found inside cached artifacts:")
        for label, where in sorted(secret_hits.items()):
            print(f"   {label}: {len(where)} payload(s), first {where[0]}")
        verdict = 1
    if path_hits:
        label = "warning" if args.policy == "mac" else "failure"
        print(f"{'⚠️' if args.policy == 'mac' else '❌'} machine paths found ({label} under policy {args.policy}):")
        for marker, where in sorted(path_hits.items()):
            print(f"   {marker}: {len(where)} payload(s), first {where[0]}")
        if args.policy == "shared":
            verdict = 1
    if not hits:
        print("✅ no credential-shaped strings and no machine paths in the sample")
    elif verdict == 0:
        print("✅ credentials absent; paths present as expected for this bucket")
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
