# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Tests for the release-version rules in versions.py."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

import versions


class ValidationTests(unittest.TestCase):
    def test_accepts_every_channel(self) -> None:
        for version in (
            "0.2.0",
            "1.12.3",
            "0.3.0-alpha.1",
            "0.3.0-alpha.1.2",
            "0.3.0-beta.4",
            "0.2.0-rc.3",
        ):
            with self.subTest(version=version):
                self.assertTrue(versions.is_valid_release_version(version))

    def test_refuses_malformed_and_dev_versions(self) -> None:
        # 🚫 `0.0.0` is the default branch's placeholder; a tag of it would
        # publish a dev build as a release.
        for version in (
            "0.0.0",
            "v0.2.0",
            "0.2",
            "0.2.0.1",
            "0.2.0-alpha",
            "0.2.0-beta.1.1",
            "0.2.0-rc.1.1",
            "0.2.0-preview.1",
            "01.2.0",
            "0.2.0-rc.3 ",
            "",
        ):
            with self.subTest(version=version):
                self.assertFalse(versions.is_valid_release_version(version))

    def test_prerelease_is_any_suffix(self) -> None:
        self.assertFalse(versions.is_prerelease("0.2.0"))
        self.assertTrue(versions.is_prerelease("0.2.0-rc.3"))
        self.assertTrue(versions.is_prerelease("0.3.0-alpha.1.1"))
        with self.assertRaises(ValueError):
            versions.is_prerelease("0.0.0")


class OrderingTests(unittest.TestCase):
    def test_channels_sort_alpha_beta_rc_stable(self) -> None:
        ordered = [
            "0.2.0-alpha.1",
            "0.2.0-alpha.1.1",
            "0.2.0-alpha.2",
            "0.2.0-beta.1",
            "0.2.0-rc.1",
            "0.2.0-rc.3",
            "0.2.0-rc.10",
            "0.2.0",
            "0.2.1",
            "0.3.0-alpha.1",
            "0.10.0",
        ]
        self.assertEqual(sorted(reversed(ordered), key=versions.version_key), ordered)

    def test_latest_version_skips_unparseable_tags(self) -> None:
        tags = ["v0.1.7\n", "v0.2.0-rc.3\n", "not-a-release\n", "v0.0.0\n", "0.9.0\n"]
        self.assertEqual(versions.latest_version(tags), "0.2.0-rc.3")
        self.assertIsNone(versions.latest_version([]))


class CommandLineTests(unittest.TestCase):
    def run_main(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out), mock.patch("sys.stderr", io.StringIO()):
            code = versions._main(list(argv))
        return code, out.getvalue()

    def test_github_flags(self) -> None:
        self.assertEqual(
            self.run_main("github-flags", "0.2.0"),
            (0, "prerelease=false\nmake_latest=true\n"),
        )
        self.assertEqual(
            self.run_main("github-flags", "0.3.0-alpha.1"),
            (0, "prerelease=true\nmake_latest=false\n"),
        )
        self.assertEqual(self.run_main("github-flags", "0.0.0"), (1, ""))

    def test_newer(self) -> None:
        self.assertEqual(self.run_main("newer", "0.2.0", "0.2.0-rc.3"), (0, ""))
        self.assertEqual(self.run_main("newer", "0.2.0-rc.3", "0.2.0-rc.3"), (1, ""))
        self.assertEqual(self.run_main("newer", "bogus", "0.2.0"), (2, ""))

    def test_check(self) -> None:
        self.assertEqual(self.run_main("check", "0.2.0-rc.3"), (0, ""))
        self.assertEqual(self.run_main("check", "0.2.0-gamma.1"), (1, ""))


if __name__ == "__main__":
    unittest.main()
