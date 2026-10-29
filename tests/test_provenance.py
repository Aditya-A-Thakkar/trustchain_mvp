import copy
import json
import shutil
import subprocess

import pytest

from trustchain.provenance import (
    create_attestation,
    sign_attestation,
    verify_attestation,
)


@pytest.fixture
def keys(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL CLI unavailable")

    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"

    for priv, pub in ((private, public), (other_private, other_public)):
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1",
             "-genkey", "-noout", "-out", str(priv)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(priv), "-pubout", "-out", str(pub)],
            check=True, capture_output=True,
        )
    return private, public, other_public


def sample_payload():
    return create_attestation(
        artifact_id="model-v2",
        artifact_digest="a" * 64,
        parent_artifact_id="model-v1",
        parent_digest="b" * 64,
        transformation="quantization (declared claim)",
        signer_id="test-publisher",
    )


def test_signed_attestation_verifies(keys, tmp_path):
    private, public, _ = keys
    path = tmp_path / "attestation.json"
    sign_attestation(sample_payload(), private, path)

    result = verify_attestation(path, public)
    assert result["valid"] is True
    assert result["signer_id"] == "test-publisher"
    assert result["artifact_id"] == "model-v2"


def test_payload_tampering_is_detected(keys, tmp_path):
    private, public, _ = keys
    path = tmp_path / "attestation.json"
    envelope = sign_attestation(sample_payload(), private, path)
    changed = copy.deepcopy(envelope)
    changed["payload"]["transformation"] = "different transformation"

    result = verify_attestation(changed, public)
    assert result["valid"] is False


def test_wrong_trusted_key_is_rejected(keys, tmp_path):
    private, _, other_public = keys
    path = tmp_path / "attestation.json"
    sign_attestation(sample_payload(), private, path)

    result = verify_attestation(path, other_public)
    assert result["valid"] is False


def test_payload_digest_tampering_is_detected(keys, tmp_path):
    private, public, _ = keys
    path = tmp_path / "attestation.json"
    envelope = sign_attestation(sample_payload(), private, path)
    envelope["payload_sha256"] = "0" * 64

    result = verify_attestation(envelope, public)
    assert result["valid"] is False


def test_attestation_requires_exactly_one_parent_or_source():
    with pytest.raises(ValueError, match="exactly one"):
        create_attestation(
            artifact_id="model",
            artifact_digest="a" * 64,
            transformation="import",
            signer_id="publisher",
        )


def test_signature_file_envelope_round_trip(keys, tmp_path):
    private, public, _ = keys
    path = tmp_path / "attestation.json"
    sign_attestation(sample_payload(), private, path)

    parsed = json.loads(path.read_text())
    assert verify_attestation(parsed, public)["valid"] is True
