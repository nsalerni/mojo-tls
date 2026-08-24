#!/usr/bin/env python3
"""Regression checks for the generated compliance badge."""

import json
import unittest

from run_compliance import (
    EXPECTED_TLS_CHECKS,
    compliance_badge_json,
    compliance_badge_payload,
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
            "message": "18/18 checks",
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

        self.assertEqual(payload["message"], "17/18 checks")
        self.assertEqual(payload["color"], "red")

    def test_missing_check_cannot_produce_a_green_badge(self):
        results = complete_results()
        results["tls"].pop()

        payload = compliance_badge_payload(results)

        self.assertEqual(payload["message"], "17/18 checks")
        self.assertEqual(payload["color"], "red")

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


if __name__ == "__main__":
    unittest.main()
