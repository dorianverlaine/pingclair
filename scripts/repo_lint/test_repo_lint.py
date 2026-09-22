#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Dorian Verlaine

"""Tests for the mechanical repository checks."""

import unittest

from repo_lint import (
    embedded_unit,
    manifest_errors,
    section_body,
    sections,
    unit_errors,
    unit_parity_errors,
)


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


class ServiceUnitTest(unittest.TestCase):
    """🧪 The unit file is a deployment contract the CLI cannot enforce."""

    CANONICAL = (
        "[Service]\n"
        "ExecReload=/bin/kill -USR1 $MAINPID\n"
        "Restart=on-failure\n"
        "RestartPreventExitStatus=1\n"
    )

    def install_script(self, unit: str) -> str:
        return (
            "if [ -f scripts/pingclair.service ]; then\n"
            "    cp scripts/pingclair.service /etc/systemd/system/\n"
            "else\n"
            "    cat > /etc/systemd/system/pingclair.service <<'EOF'\n"
            f"{unit}"
            "EOF\n"
            "fi\n"
        )

    def test_compliant_unit_passes(self):
        self.assertEqual(unit_errors(self.CANONICAL), [])
        self.assertEqual(
            unit_parity_errors(self.CANONICAL, self.install_script(self.CANONICAL)),
            [],
        )

    def test_the_dropped_signal_is_refused(self):
        wrong = self.CANONICAL.replace("kill -USR1", "kill -HUP")
        errors = unit_errors(wrong)
        self.assertTrue(any("kill -USR1" in error for error in errors))

    def test_a_drifting_restart_policy_is_refused(self):
        reduced = self.CANONICAL.replace(
            "Restart=on-failure\nRestartPreventExitStatus=1\n",
            "Restart=always\n",
        )
        errors = unit_parity_errors(reduced, self.install_script(self.CANONICAL))
        self.assertTrue(any("line 3" in error for error in errors), errors)

    def test_a_missing_heredoc_is_refused(self):
        install = (
            "if [ -f scripts/pingclair.service ]; then\n"
            "    cp scripts/pingclair.service /etc/systemd/system/\n"
            "fi\n"
        )
        self.assertIsNone(embedded_unit(install))
        errors = unit_parity_errors(self.CANONICAL, install)
        self.assertTrue(any("standalone install path" in error for error in errors))

    def test_an_unterminated_heredoc_is_refused(self):
        unterminated = self.install_script(self.CANONICAL).replace("EOF\nfi\n", "fi\n")
        self.assertIsNone(embedded_unit(unterminated))


if __name__ == "__main__":
    unittest.main()
