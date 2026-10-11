#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""🧊 The build-environment fingerprint behind the moving `:v1` builder tag.

A push that changes `deployment/Builder.Dockerfile` or
`deployment/apt-retry.sh` changes the environment every Linux builder
compiles in, so the published
`ghcr.io/dorianverlaine/pingclair-builder:v1` image has to be republished
before any container job starts. The image carries an
`org.pingclair.builder-fingerprint` label naming the environment it holds;
`builder-image.yml` compares that label with the working tree before deciding
to publish, so a toolchain bump never races its consumers (#300) and an
unchanged environment costs one small registry read.

Reads are anonymous: the package is public, and a pull-scope token keeps this
gate free of credentials.
"""

import hashlib
import json
import pathlib
import sys
import urllib.request

REPOSITORY = "dorianverlaine/pingclair-builder"
TAG = "v1"
LABEL = "org.pingclair.builder-fingerprint"

#: The files whose bytes define the environment, in a fixed order.
INPUTS = ("deployment/Builder.Dockerfile", "deployment/apt-retry.sh")

INDEX_ACCEPT = (
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json"
)
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json"
)


def fingerprint(root: pathlib.Path) -> str:
    """The fingerprint of the environment sources under `root`."""
    digest = hashlib.sha256()
    for name in INPUTS:
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update((root / name).read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _fetch(url: str, token: str, accept: str) -> bytes:
    request = urllib.request.Request(url)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", accept)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def published(repository: str = REPOSITORY, tag: str = TAG) -> str:
    """The fingerprint the published image carries, or `""` when unlabeled."""
    with urllib.request.urlopen(
        f"https://ghcr.io/token?scope=repository:{repository}:pull", timeout=30
    ) as response:
        token = json.load(response)["token"]
    base = f"https://ghcr.io/v2/{repository}"
    index = json.loads(_fetch(f"{base}/manifests/{tag}", token, INDEX_ACCEPT))
    # 🧭 The gate runs on amd64; both architectures are labeled from the same
    # build, so one config names the environment for the tag.
    amd64 = next(
        manifest["digest"]
        for manifest in index["manifests"]
        if manifest["platform"]["os"] == "linux"
        and manifest["platform"]["architecture"] == "amd64"
    )
    manifest = json.loads(_fetch(f"{base}/manifests/{amd64}", token, MANIFEST_ACCEPT))
    config = json.loads(
        _fetch(f"{base}/blobs/{manifest['config']['digest']}", token, MANIFEST_ACCEPT)
    )
    return config.get("config", {}).get("Labels", {}).get(LABEL, "")


def main(argv: list[str], root: pathlib.Path) -> None:
    if argv == ["compute"]:
        print(fingerprint(root))
        return
    if argv == ["published"]:
        print(published())
        return
    if argv == ["needs-build"]:
        wanted = fingerprint(root)
        try:
            current = published()
        except Exception as error:  # noqa: BLE001 — any registry trouble must
            #                                          not silently skip a publish.
            print(
                f"⚠️ cannot read {REPOSITORY}:{TAG} ({error}); a publish is required",
                file=sys.stderr,
            )
            print("true")
            return
        if current == wanted:
            print(f"✅ {REPOSITORY}:{TAG} already holds {wanted}", file=sys.stderr)
            print("false")
        else:
            print(
                f"🧊 {REPOSITORY}:{TAG} holds {current or '<no fingerprint>'}; "
                f"this tree is {wanted}",
                file=sys.stderr,
            )
            print("true")
        return
    raise SystemExit(f"usage: {sys.argv[0]} compute|published|needs-build")


if __name__ == "__main__":
    main(sys.argv[1:], pathlib.Path())
