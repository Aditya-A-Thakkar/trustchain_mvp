import unittest
from unittest.mock import patch

from trustchain.analyst import analyze


class AnalystSafeguardTests(unittest.TestCase):
    def check_hard_signal(self, evidence, expected_text):
        # Ensure tests never call the external AI API.
        with patch.dict("os.environ", {"NVIDIA_API_KEY": ""}):
            result = analyze(evidence, use_ai=False)

        self.assertTrue(result["suggested_escalation"])
        self.assertIn(expected_text, result["explanation"])

    def test_revocation_is_explicit(self):
        self.check_hard_signal(
            {"revoked": True},
            "revoked",
        )

    def test_digest_mismatch_is_explicit(self):
        self.check_hard_signal(
            {"digest_mismatch": True},
            "digest differs from the approved digest",
        )

    def test_scanner_findings_are_explicit(self):
        self.check_hard_signal(
            {"model_scan": {"status": "FINDINGS"}},
            "reported findings",
        )

    def test_scanner_error_is_explicit(self):
        self.check_hard_signal(
            {"model_scan": {"status": "ERROR"}},
            "scan failed",
        )

    def test_invalid_signature_is_explicit(self):
        self.check_hard_signal(
            {"signature_verification": {"status": "INVALID"}},
            "signature verification is invalid",
        )

    def test_signature_verification_error_is_explicit(self):
        self.check_hard_signal(
            {"signature_verification": {"status": "ERROR"}},
            "could not be completed",
        )

    def test_clean_evidence_does_not_force_escalation(self):
        result = analyze(
            {
                "unsigned": False,
                "scanner_advisory": {"affected": False},
                "model_scan": {"status": "CLEAN"},
                "review_flags": [],
            },
            use_ai=True,
        )
        self.assertFalse(result["suggested_escalation"])


if __name__ == "__main__":
    unittest.main()
