#!/usr/bin/env python3
"""Regression checks for the generated compliance badge."""

import json
import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_compliance

from run_compliance import (
    EXPECTED_TLS_CHECKS,
    _mojo_client_failed_required_mtls,
    _mojo_tls_reset_or_failure,
    compliance_badge_json,
    compliance_badge_payload,
    write_html_report,
    write_report,
)


def complete_results() -> dict[str, list[tuple[str, bool, str]]]:
    return {
        "tls": [(name, True, "") for name in EXPECTED_TLS_CHECKS],
    }


class ComplianceBadgeTest(unittest.TestCase):
    def test_complete_run_reports_exact_score(self):
        results = complete_results()
        payload = compliance_badge_payload(results)

        self.assertEqual(payload, {
            "schemaVersion": 1,
            "label": "TLS compliance",
            "message": "34/34 checks",
            "color": "brightgreen",
        })
        serialized = compliance_badge_json(results)
        self.assertEqual(json.loads(serialized), payload)
        self.assertEqual(serialized, compliance_badge_json(results))

    def test_failure_cannot_produce_a_green_badge(self):
        results = complete_results()
        name, _, detail = results["tls"][0]
        results["tls"][0] = (name, False, detail)

        payload = compliance_badge_payload(results)

        self.assertEqual(payload["message"], "33/34 checks")
        self.assertEqual(payload["color"], "red")

    def test_missing_check_cannot_produce_a_green_badge(self):
        results = complete_results()
        results["tls"].pop()

        payload = compliance_badge_payload(results)

        self.assertEqual(payload["message"], "33/34 checks")
        self.assertEqual(payload["color"], "red")

    def test_missing_check_cannot_produce_a_green_report(self):
        results = complete_results()
        results["tls"].pop()

        with tempfile.TemporaryDirectory(dir=run_compliance.BUILD) as directory:
            markdown = Path(directory) / "COMPLIANCE.md"
            html = Path(directory) / "COMPLIANCE.html"
            with (
                patch.object(run_compliance, "RESULTS", results),
                patch.object(run_compliance, "REPORT", markdown),
                patch.object(run_compliance, "HTML_REPORT", html),
                patch.object(run_compliance, "versions", return_value={}),
            ):
                self.assertFalse(write_report())
                self.assertFalse(write_html_report())

            self.assertIn(
                "33/34 registered checks passed; results incomplete",
                markdown.read_text(),
            )
            self.assertIn(
                "33/34</span><span>registered checks passed; results incomplete",
                html.read_text(),
            )

    def test_duplicate_or_unknown_check_marks_results_invalid(self):
        results = complete_results()
        results["tls"].append(results["tls"][0])
        self.assertEqual(
            compliance_badge_payload(results)["color"], "red"
        )

        results = complete_results()
        results["tls"].append(("unregistered check", True, ""))

        payload = compliance_badge_payload(results)

        self.assertEqual(payload["message"], "results invalid")
        self.assertEqual(payload["color"], "red")

    def test_unexpected_section_cannot_produce_a_green_badge(self):
        results = complete_results()
        results["other"] = [("unregistered check", True, "")]

        payload = compliance_badge_payload(results)

        self.assertEqual(payload["color"], "red")


class CompletedProcess:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class RequiredMtlsMatcherTest(unittest.TestCase):
    def test_reset_errnos_are_peer_aborts(self):
        self.assertTrue(
            _mojo_tls_reset_or_failure("tls write: errno " + str(errno.EPIPE))
        )
        self.assertTrue(
            _mojo_tls_reset_or_failure(
                "tls read: errno " + str(errno.ECONNRESET)
            )
        )
        self.assertFalse(_mojo_tls_reset_or_failure("tls write: errno 1"))

    def test_handshake_failure_without_version_is_rejection(self):
        result = CompletedProcess(
            1, "", "tls: handshake failed: ssl/tls alert"
        )
        self.assertTrue(_mojo_client_failed_required_mtls(result))

    def test_post_handshake_reset_still_counts(self):
        result = CompletedProcess(
            1,
            "VERSION TLSv1.3\nALPN h2\n",
            "tls write: errno " + str(errno.EPIPE),
        )
        self.assertTrue(_mojo_client_failed_required_mtls(result))

    def test_success_is_not_rejection(self):
        result = CompletedProcess(0, "VERSION TLSv1.3\nALPN h2\nOK 16\n", "")
        self.assertFalse(_mojo_client_failed_required_mtls(result))


if __name__ == "__main__":
    unittest.main()
