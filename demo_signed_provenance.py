
"""Demonstrate TrustChain signed-provenance and tamper checks.

All artifacts and keys are synthetic. Requires the OpenSSL CLI.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from trustchain.provenance import (
    create_attestation,
    sign_attestation,
    verify_attestation,
)


def run_openssl(*args: str) -> None:
    subprocess.run(
        ["openssl", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check(label: str, condition: bool, detail: str) -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}: {detail}")
    if not condition:
        raise AssertionError(f"Security demo check failed: {label}")


def main() -> None:
    if not shutil.which("openssl"):
        raise SystemExit("OpenSSL CLI is required to run this demo.")

    with tempfile.TemporaryDirectory(prefix="trustchain-provenance-") as td:
        root = Path(td)

        private_key = root / "publisher-private.pem"
        public_key = root / "publisher-public.pem"
        other_private_key = root / "other-private.pem"
        other_public_key = root / "other-public.pem"

        artifact = root / "synthetic-model.bin"
        attestation_path = root / "attestation.json"

        artifact.write_bytes(b"synthetic model weights v1\n")
        initial_digest = sha256_file(artifact)

        run_openssl(
            "ecparam", "-name", "prime256v1", "-genkey",
            "-noout", "-out", str(private_key),
        )
        run_openssl(
            "ec", "-in", str(private_key),
            "-pubout", "-out", str(public_key),
        )
        run_openssl(
            "ecparam", "-name", "prime256v1", "-genkey",
            "-noout", "-out", str(other_private_key),
        )
        run_openssl(
            "ec", "-in", str(other_private_key),
            "-pubout", "-out", str(other_public_key),
        )

        # 1. The original artifact matches the digest captured for signing.
        check(
            "Baseline artifact digest",
            sha256_file(artifact) == initial_digest,
            f"sha256={initial_digest}",
        )

        payload = create_attestation(
            artifact_id="synthetic-model-v1",
            artifact_digest=initial_digest,
            source_uri="demo://synthetic/source-v1",
            transformation="synthetic demonstration; no real transformation claimed",
            signer_id="demo-publisher",
        )

        envelope = sign_attestation(
            payload,
            private_key,
            attestation_path,
        )

        # 2. The original signed envelope verifies with the trusted key.
        original_result = verify_attestation(attestation_path, public_key)
        check(
            "Original signature",
            original_result.get("valid") is True,
            original_result.get("reason", "No reason supplied"),
        )

        # 3. Changing a signed claim must invalidate the attestation.
        altered = json.loads(json.dumps(envelope))
        altered["payload"]["transformation"] = "tampered transformation claim"
        altered_result = verify_attestation(altered, public_key)
        check(
            "Altered attestation claim",
            altered_result.get("valid") is False,
            altered_result.get("reason", "No reason supplied"),
        )

        # 4. Artifact integrity is a separate digest check from signature validity.
        artifact.write_bytes(b"modified synthetic model weights\n")
        modified_digest = sha256_file(artifact)
        check(
            "Artifact tampering",
            modified_digest != initial_digest,
            f"expected={initial_digest}, actual={modified_digest}",
        )

        # 5. A different public key must not verify the original envelope.
        wrong_key_result = verify_attestation(
            attestation_path,
            other_public_key,
        )
        check(
            "Untrusted public key",
            wrong_key_result.get("valid") is False,
            wrong_key_result.get("reason", "No reason supplied"),
        )

        print("\nAll five synthetic security checks passed.")


if __name__ == "__main__":
    main()
