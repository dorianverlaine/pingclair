#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Tests for the mechanical repository checks."""

import unittest

from repo_lint import manifest_errors, section_body, sections


class ManifestErrorsTest(unittest.TestCase):
    def test_compliant_member_passes(self):
        text = """\
[package]
name = "x"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
foo = "1"

[lints]
workspace = true
"""
        self.assertEqual(manifest_errors(text, is_root=False), [])

    def test_missing_inheritance_fails(self):
        text = """\
[package]
name = "x"
version = "1.0.0"
edition.workspace = true
license.workspace = true

[lints]
workspace = true
"""
        errors = manifest_errors(text, is_root=False)
        self.assertTrue(any("version" in error for error in errors))

    def test_missing_lint_opt_in_fails(self):
        text = (
            '[package]\nname = "x"\nversion.workspace = true\n'
            "edition.workspace = true\nlicense.workspace = true\n"
        )
        errors = manifest_errors(text, is_root=False)
        self.assertTrue(any("lints" in error for error in errors))

    def test_features_are_banned(self):
        text = (
            '[package]\nname = "x"\nversion.workspace = true\n'
            "edition.workspace = true\nlicense.workspace = true\n\n"
            "[features]\ndefault = []\n"
        )
        errors = manifest_errors(text, is_root=False)
        self.assertTrue(any("features" in error for error in errors))

    def test_forbidden_tls_dependency_fails(self):
        text = (
            '[package]\nname = "x"\nversion.workspace = true\n'
            "edition.workspace = true\nlicense.workspace = true\n\n"
            "[dependencies]\nopenssl-sys = \"0.9\"\n"
        )
        errors = manifest_errors(text, is_root=False)
        self.assertTrue(any("openssl-sys" in error for error in errors))

    def test_root_manifest_only_checks_its_own_rules(self):
        text = '[workspace]\nmembers = ["a"]\n'
        self.assertEqual(manifest_errors(text, is_root=True), [])


class SectionHelpersTest(unittest.TestCase):
    def test_sections_and_body(self):
        text = "[a]\nx = 1\n\n[b]\ny = 2\n"
        self.assertEqual(sections(text), {"a": (0, 11), "b": (11, len(text))})
        self.assertIn("x = 1", section_body(text, "a"))
        self.assertIn("y = 2", section_body(text, "b"))
        self.assertEqual(section_body(text, "missing"), "")


if __name__ == "__main__":
    unittest.main()
