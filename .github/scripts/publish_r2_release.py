#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Mirror a Pingclair GitHub Release to Cloudflare R2.

GitHub remains where a release is *created* — the tag, the notes, the assets —
and R2 is where it is *served* from: `releases.pingclair.com` sits on a bucket
with no egress fee and a CDN in front of it, which is what the installer and the
documentation point at. The two are kept from disagreeing by deriving the
channels from GitHub itself rather than from workflow inputs:

* `pingclair/channels/latest` is written when the tag is what GitHub's
  `/releases/latest` resolves to;
* `pingclair/channels/prerelease` is written when GitHub marks it a prerelease.

Layout, all inside the bucket named by ``R2_RELEASES_BUCKET``::

    pingclair/releases/<version>/<asset>      immutable, verified, no overwrite
    pingclair/releases/<version>/release.json installer-facing metadata
    pingclair/releases/<version>/install.sh   the installer as of that tag
    pingclair/channels/latest                 pointer to a release.json
    pingclair/channels/prerelease             pointer to a release.json
    pingclair/install.sh                      the installer users curl

Two stages exist because a release can be assembled in pieces: ``assets`` copies
whatever GitHub has right now without verifying it (a file still being uploaded
would otherwise fail the run for no reason), and ``finalize`` verifies every
asset, fills in anything missing, writes the metadata and moves the pointers.
Running ``finalize`` alone is also how an older release gets mirrored later.

Every object carries the digest GitHub reported for it, and is checked back with
``head-object`` before the run succeeds: size, the ``sha256`` metadata field, and
a CRC64NVME checksum from R2 itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import quote

REPOSITORY = "dorianverlaine/pingclair"
PREFIX = "pingclair"
RELEASE_METADATA_NAME = "release.json"
INSTALLER_SOURCE = "scripts/install.sh"
INSTALLER_ALIAS = f"{PREFIX}/install.sh"
# 🎯 Public host of the bucket. The metadata is what an installer reads, so the
# URLs in it are the ones a user's machine will actually fetch.
PUBLIC_BASE = "https://releases.pingclair.com"
MAX_UPLOAD_WORKERS = 8
# 🧭 Pingclair tags are `v` plus semver, and pre-1.0 releases are release
# candidates: `v0.2.0-rc.3`. Anything else is refused rather than mirrored under
# a directory name nobody expects.
VERSION_RE = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$")
SHA256_RE = re.compile(r"^sha256:(?P<sha256>[0-9a-f]{64})$")
CRC64_RE = re.compile(r"^[A-Za-z0-9+/]{11}=$")
MISSING_OBJECT_RE = re.compile(r"\((?:404|NoSuchKey|NotFound)\)")


class PublishError(RuntimeError):
    """Anything that should stop the run with a message a human can act on."""


class ReleaseAsset(NamedTuple):
    name: str
    size: int
    sha256: str


def run(args: list[str]) -> str:
    result = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.stdout:
        print(result.stdout, end="", file=sys.stderr)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    result.check_returncode()
    return result.stdout or ""


def gh_json(args: list[str]) -> Any:
    try:
        return json.loads(run(args))
    except (OSError, subprocess.CalledProcessError) as error:
        raise PublishError(f"gh {' '.join(args[1:4])} failed: {error}") from error
    except json.JSONDecodeError as error:
        raise PublishError(f"gh {' '.join(args[1:4])} returned invalid JSON") from error


def release_assets(tag: str) -> list[ReleaseAsset]:
    """Assets of one release, with the digest GitHub reports for each."""
    document = gh_json(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            REPOSITORY,
            "--json",
            "assets",
            "--jq",
            "[.assets[] | {name, size, state, digest}]",
        ]
    )
    if not isinstance(document, list) or not document:
        raise PublishError(f"GitHub release {tag} has no assets")
    assets: list[ReleaseAsset] = []
    for entry in document:
        if not isinstance(entry, dict) or entry.get("state") != "uploaded":
            raise PublishError(f"GitHub release {tag} has an asset that is not uploaded: {entry!r}")
        name = entry.get("name")
        size = entry.get("size")
        digest = entry.get("digest")
        match = SHA256_RE.fullmatch(digest) if isinstance(digest, str) else None
        if not isinstance(name, str) or not name or name == RELEASE_METADATA_NAME:
            raise PublishError(f"unsupported asset name in {tag}: {name!r}")
        if type(size) is not int or size < 0:
            raise PublishError(f"unsupported asset size in {tag}: {name}={size!r}")
        if match is None:
            # 🔐 Without a digest there is nothing to verify against, and a
            # mirror that cannot be checked is worse than no mirror.
            raise PublishError(f"GitHub reports no sha256 digest for {tag}:{name}")
        assets.append(ReleaseAsset(name, size, match.group("sha256")))
    return sorted(assets, key=lambda asset: asset.name)


def release_is_prerelease(tag: str) -> bool:
    document = gh_json(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            REPOSITORY,
            "--json",
            "isPrerelease",
            "--jq",
            ".isPrerelease",
        ]
    )
    return bool(document)


def github_latest_tag() -> str:
    try:
        return run(
            [
                "gh",
                "api",
                f"repos/{REPOSITORY}/releases/latest",
                "--jq",
                ".tag_name",
            ]
        ).strip()
    except subprocess.CalledProcessError:
        # 🚧 No stable release yet, or every release so far is a prerelease.
        return ""


def download(tag: str, names: list[str], directory: Path) -> None:
    if not names:
        return
    command = ["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(directory)]
    for name in names:
        command += ["--pattern", name]
    try:
        run(command)
    except (OSError, subprocess.CalledProcessError) as error:
        raise PublishError(f"downloading {tag} assets failed: {error}") from error
    missing = [name for name in names if not (directory / name).is_file()]
    if missing:
        raise PublishError(f"GitHub did not return these assets: {', '.join(missing)}")


def digest_of(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def validate(path: Path, asset: ReleaseAsset) -> None:
    size, sha256 = digest_of(path)
    if size != asset.size or sha256 != asset.sha256:
        raise PublishError(
            f"{asset.name} does not match what GitHub reported: "
            f"expected size={asset.size} sha256={asset.sha256}, got size={size} sha256={sha256}"
        )


def endpoint() -> str:
    value = os.environ.get("R2_RELEASES_ENDPOINT", "").strip()
    if not value:
        raise PublishError("R2_RELEASES_ENDPOINT is required")
    return value


def bucket() -> str:
    value = os.environ.get("R2_RELEASES_BUCKET", "").strip()
    if not value:
        raise PublishError("R2_RELEASES_BUCKET is required")
    return value


def put_object(
    key: str,
    path: Path,
    sha256: str,
    *,
    immutable: bool,
    content_type: str | None = None,
) -> None:
    command = [
        "aws",
        "s3",
        "cp",
        str(path),
        f"s3://{bucket()}/{key}",
        "--checksum-algorithm",
        "CRC64NVME",
        "--metadata",
        f"sha256={sha256}",
        "--endpoint-url",
        endpoint(),
    ]
    if immutable:
        # 🚫 A published release never changes. If the key exists, something is
        # wrong with the tag or with us; failing is the honest answer.
        command.append("--no-overwrite")
    if content_type:
        command += ["--content-type", content_type]
    try:
        run(command)
    except subprocess.CalledProcessError as error:
        raise PublishError(
            f"uploading {key} failed: {(error.stderr or '').strip() or error}"
        ) from error
    except OSError as error:
        raise PublishError(f"uploading {key} failed: {error}") from error


def verify_object(key: str, size: int, sha256: str) -> None:
    try:
        document = gh_json(
            [
                "aws",
                "s3api",
                "head-object",
                "--bucket",
                bucket(),
                "--key",
                key,
                "--checksum-mode",
                "ENABLED",
                "--endpoint-url",
                endpoint(),
            ]
        )
    except OSError as error:
        raise PublishError(f"inspecting {key} failed: {error}") from error
    metadata = document.get("Metadata") if isinstance(document, dict) else None
    remote_size = document.get("ContentLength") if isinstance(document, dict) else None
    remote_sha256 = metadata.get("sha256") if isinstance(metadata, dict) else None
    crc64 = document.get("ChecksumCRC64NVME") if isinstance(document, dict) else None
    if (
        remote_size != size
        or remote_sha256 != sha256
        or not isinstance(crc64, str)
        or not CRC64_RE.fullmatch(crc64)
    ):
        raise PublishError(
            f"{key} does not match what was uploaded: expected size={size} "
            f"sha256={sha256}, got size={remote_size} sha256={remote_sha256} "
            f"crc64nvme={crc64}"
        )


def publish_assets(
    version: str, assets: list[ReleaseAsset], directory: Path, *, verify: bool
) -> dict[str, dict[str, Any]]:
    published: dict[str, dict[str, Any]] = {}

    def publish(asset: ReleaseAsset) -> tuple[str, dict[str, Any]]:
        path = directory / asset.name
        validate(path, asset)
        key = f"{PREFIX}/releases/{version}/{asset.name}"
        put_object(key, path, asset.sha256, immutable=True)
        if verify:
            verify_object(key, asset.size, asset.sha256)
        print(
            f"{'published and verified' if verify else 'published'} s3://{bucket()}/{key} "
            f"size={asset.size} sha256={asset.sha256}",
            file=sys.stderr,
        )
        return asset.name, {
            "key": key,
            "name": asset.name,
            "sha256": asset.sha256,
            "size": asset.size,
        }

    with ThreadPoolExecutor(max_workers=min(MAX_UPLOAD_WORKERS, len(assets))) as pool:
        for future in as_completed(
            {pool.submit(publish, asset): asset for asset in assets}
        ):
            name, record = future.result()
            published[name] = record
    return published


def already_published(version: str, assets: list[ReleaseAsset]) -> dict[str, dict[str, Any]]:
    """Which of these assets are already in the bucket, and intact."""
    found: dict[str, dict[str, Any]] = {}

    def check(asset: ReleaseAsset) -> tuple[ReleaseAsset, bool]:
        key = f"{PREFIX}/releases/{version}/{asset.name}"
        try:
            verify_object(key, asset.size, asset.sha256)
        except PublishError as error:
            cause = error.__cause__
            if isinstance(cause, subprocess.CalledProcessError) and MISSING_OBJECT_RE.search(
                cause.stderr or ""
            ):
                return asset, False
            raise
        return asset, True

    with ThreadPoolExecutor(max_workers=min(MAX_UPLOAD_WORKERS, len(assets))) as pool:
        for future in as_completed({pool.submit(check, asset): asset for asset in assets}):
            asset, present = future.result()
            if present:
                found[asset.name] = {
                    "key": f"{PREFIX}/releases/{version}/{asset.name}",
                    "name": asset.name,
                    "sha256": asset.sha256,
                    "size": asset.size,
                }
    return found


def fetch_installer(tag: str, destination: Path) -> tuple[int, str]:
    """The installer as of this tag, straight from the repository."""
    try:
        content = run(
            [
                "gh",
                "api",
                f"repos/{REPOSITORY}/contents/{INSTALLER_SOURCE}?ref={tag}",
                "-H",
                "Accept: application/vnd.github.raw",
            ]
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise PublishError(f"reading {INSTALLER_SOURCE} at {tag} failed: {error}") from error
    destination.write_text(content, encoding="utf-8")
    return digest_of(destination)


def release_metadata_document(tag: str, version: str, assets: list[ReleaseAsset]) -> bytes:
    document = {
        "tag_name": tag,
        "version": version,
        "assets": [
            {
                "name": asset.name,
                "digest": f"sha256:{asset.sha256}",
                "size": asset.size,
                "browser_download_url": (
                    f"{PUBLIC_BASE}/{PREFIX}/releases/{version}/"
                    f"{quote(asset.name, safe='')}"
                ),
            }
            for asset in assets
        ],
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Release tag, for example v0.2.0-rc.4.")
    parser.add_argument(
        "--stage",
        choices=("assets", "finalize"),
        required=True,
        help="`assets` mirrors early without verifying; `finalize` verifies, fills in the rest and moves the channels.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        match = VERSION_RE.fullmatch(args.tag)
        if match is None:
            raise PublishError(f"{args.tag!r} is not a v<semver> release tag")
        version = match.group("version")
        if not os.environ.get("GH_TOKEN"):
            raise PublishError("GH_TOKEN is required")
        endpoint()
        bucket()

        prerelease = release_is_prerelease(args.tag)
        make_latest = github_latest_tag() == args.tag
        assets = release_assets(args.tag)
        print(
            f"🧭 {args.tag}: {len(assets)} asset(s), prerelease={prerelease}, "
            f"latest={make_latest}",
            file=sys.stderr,
        )

        with tempfile.TemporaryDirectory(prefix="pingclair-r2-release.") as workdir:
            work = Path(workdir)

            if args.stage == "assets":
                download(args.tag, [asset.name for asset in assets], work)
                published = publish_assets(version, assets, work, verify=False)
                print(
                    json.dumps(
                        {
                            "stage": args.stage,
                            "tag": args.tag,
                            "version": version,
                            "assets": len(published),
                            "releasePrefix": f"{PREFIX}/releases/{version}/",
                        },
                        sort_keys=True,
                    )
                )
                return 0

            present = already_published(version, assets)
            missing = [asset for asset in assets if asset.name not in present]
            download(args.tag, [asset.name for asset in missing], work)
            published = {**present, **publish_assets(version, missing, work, verify=True)}
            ordered = [published[asset.name] for asset in assets]

            metadata = release_metadata_document(args.tag, version, assets)
            metadata_path = work / RELEASE_METADATA_NAME
            metadata_path.write_bytes(metadata)
            metadata_size = len(metadata)
            metadata_sha256 = hashlib.sha256(metadata).hexdigest()
            metadata_key = f"{PREFIX}/releases/{version}/{RELEASE_METADATA_NAME}"
            put_object(
                metadata_key,
                metadata_path,
                metadata_sha256,
                immutable=True,
                content_type="application/json",
            )
            verify_object(metadata_key, metadata_size, metadata_sha256)
            print(
                f"published and verified s3://{bucket()}/{metadata_key} "
                f"size={metadata_size} sha256={metadata_sha256}",
                file=sys.stderr,
            )

            installer_path = work / "install.sh"
            installer_size, installer_sha256 = fetch_installer(args.tag, installer_path)
            installer_key = f"{PREFIX}/releases/{version}/install.sh"
            put_object(installer_key, installer_path, installer_sha256, immutable=True)
            verify_object(installer_key, installer_size, installer_sha256)
            # 🧷 The alias is what `curl …/pingclair/install.sh` fetches. It moves
            # on every release, prerelease or not: the script asks for a channel,
            # and the channels are what keep prereleases out of `latest`.
            put_object(
                INSTALLER_ALIAS,
                installer_path,
                installer_sha256,
                immutable=False,
                content_type="text/x-shellscript",
            )
            verify_object(INSTALLER_ALIAS, installer_size, installer_sha256)
            print(
                f"published and verified s3://{bucket()}/{INSTALLER_ALIAS} "
                f"size={installer_size} sha256={installer_sha256}",
                file=sys.stderr,
            )

            channels: list[str] = []
            if make_latest:
                channels.append("latest")
            if prerelease:
                channels.append("prerelease")
            for channel in channels:
                channel_key = f"{PREFIX}/channels/{channel}"
                put_object(
                    channel_key,
                    metadata_path,
                    metadata_sha256,
                    immutable=False,
                    content_type="application/json",
                )
                verify_object(channel_key, metadata_size, metadata_sha256)
                print(
                    f"published and verified s3://{bucket()}/{channel_key} "
                    f"size={metadata_size} sha256={metadata_sha256}",
                    file=sys.stderr,
                )

            print(
                json.dumps(
                    {
                        "stage": args.stage,
                        "tag": args.tag,
                        "version": version,
                        "assets": ordered,
                        "channels": channels,
                        "releaseMetadata": {
                            "key": metadata_key,
                            "sha256": metadata_sha256,
                            "size": metadata_size,
                        },
                        "installer": {"key": INSTALLER_ALIAS, "sha256": installer_sha256},
                        "releasePrefix": f"{PREFIX}/releases/{version}/",
                    },
                    sort_keys=True,
                )
            )
            return 0
    except PublishError as error:
        print(f"❌ publish failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
