import subprocess
import sys
import pytest
from trustchain.core import verify_model_signature


# @pytest.mark.integration
def test_real_ecdsa_sign_verify_and_tamper_detection(tmp_path):
    openssl = subprocess.run(
        ["openssl", "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if openssl.returncode != 0:
        pytest.skip("OpenSSL CLI is unavailable")

    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    artifact = tmp_path / "model.pkl"
    signature = tmp_path / "model.sig"

    artifact.write_bytes(b"TrustChain integration test model bytes")

    subprocess.run(
        [
            "openssl", "ecparam", "-name", "prime256v1",
            "-genkey", "-noout", "-out", str(private_key),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "openssl", "ec", "-in", str(private_key),
            "-pubout", "-out", str(public_key),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    subprocess.run(
        [
            sys.executable, "-m", "model_signing", "sign", "key",
            str(artifact),
            "--private_key", str(private_key),
            "--signature", str(signature),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert signature.is_file(), "Signing did not produce a signature file"

    valid_result = verify_model_signature(artifact, public_key, signature)
    assert valid_result["status"] == "VERIFIED", valid_result

    artifact.write_bytes(b"Tampered model bytes")

    tampered_result = verify_model_signature(artifact, public_key, signature)
    assert tampered_result["status"] == "INVALID", tampered_result
