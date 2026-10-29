import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustchain.core import verify_model_signature


class SignatureVerificationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifact = self.root / "model.bin"
        self.artifact.write_bytes(b"demo model")
        self.public_key = self.root / "public.pem"
        self.public_key.write_text("test public key")
        self.signature = self.root / "model.sig"
        self.signature.write_text("test signature")

    def tearDown(self):
        self.tmp.cleanup()

    @patch("subprocess.run")
    def test_successful_cli_verification_is_verified(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "valid", "")
        result = verify_model_signature(self.artifact, self.public_key, self.signature)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["verified"])

    @patch("subprocess.run")
    def test_nonzero_cli_result_is_invalid_signature(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", "signature mismatch")
        result = verify_model_signature(self.artifact, self.public_key, self.signature)
        self.assertEqual(result["status"], "INVALID")
        self.assertFalse(result["verified"])

    @patch("subprocess.run")
    def test_missing_module_is_verification_error_not_invalid_signature(self, run):
        run.return_value = subprocess.CompletedProcess(
            [], 1, "", "/python: No module named model_signing"
        )
        result = verify_model_signature(self.artifact, self.public_key, self.signature)
        self.assertEqual(result["status"], "ERROR")
        self.assertFalse(result["verified"])

    def test_directory_is_not_supported_for_single_file_signature(self):
        result = verify_model_signature(self.root, self.public_key, self.signature)
        self.assertEqual(result["status"], "ERROR")
        self.assertFalse(result["verified"])


if __name__ == "__main__":
    unittest.main()
