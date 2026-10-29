"""Signed provenance attestations using OpenSSL and canonical JSON."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ALGORITHM = "ECDSA-SHA256"


def canonical_json(value: Any) -> bytes:
    """Stable UTF-8 encoding used for signing and verification."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def create_attestation(
    *,
    artifact_id: str,
    artifact_digest: str,
    transformation: str,
    parent_artifact_id: str | None = None,
    parent_digest: str | None = None,
    source_uri: str | None = None,
    signer_id: str,
) -> dict[str, Any]:
    """Create a provenance claim. This does not itself authenticate the claim."""
    if not artifact_id.strip():
        raise ValueError("artifact_id must not be empty")
    if not artifact_digest.strip():
        raise ValueError("artifact_digest must not be empty")
    if not transformation.strip():
        raise ValueError("transformation must not be empty")
    if not signer_id.strip():
        raise ValueError("signer_id must not be empty")
    if parent_artifact_id == artifact_id:
        raise ValueError("Artifact cannot be its own parent")
    if bool(parent_artifact_id) == bool(source_uri):
        raise ValueError("Provide exactly one of parent_artifact_id or source_uri")
    if parent_artifact_id and not parent_digest:
        raise ValueError("A parent digest is required when a parent is specified")
    if not parent_artifact_id and parent_digest is not None:
        raise ValueError("parent_digest is only valid with a parent artifact")

    return {
        "schema": "trustchain.provenance.v1",
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "parent_artifact_id": parent_artifact_id,
        "parent_digest": parent_digest,
        "source_uri": source_uri.strip() if source_uri else None,
        "transformation": transformation.strip(),
        "signer_id": signer_id.strip(),
    }


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["openssl", *args],
            capture_output=True,
            text=False,
            check=False,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("OpenSSL executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("OpenSSL command timed out") from exc


def sign_attestation(
    payload: dict[str, Any],
    private_key: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Sign canonical payload bytes and save a JSON envelope."""
    key = Path(private_key)
    if not key.is_file():
        raise FileNotFoundError(f"Private key not found: {key}")

    payload_bytes = canonical_json(payload)
    with tempfile.TemporaryDirectory(prefix="trustchain-sign-") as td:
        source = Path(td) / "payload.json"
        signature_path = Path(td) / "signature.bin"
        source.write_bytes(payload_bytes)

        result = _run_openssl([
            "dgst", "-sha256", "-sign", str(key),
            "-out", str(signature_path), str(source),
        ])
        if result.returncode:
            raise RuntimeError(
                "OpenSSL signing failed: "
                + result.stderr.decode("utf-8", errors="replace")
            )
        signature = base64.b64encode(signature_path.read_bytes()).decode("ascii")

    envelope = {
        "algorithm": ALGORITHM,
        "payload": payload,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "signature_base64": signature,
    }
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return envelope


def verify_attestation(
    attestation: dict[str, Any] | str | Path,
    trusted_public_key: str | Path,
) -> dict[str, Any]:
    """Verify an attestation against a supplied public key.

    A valid result establishes that the signature matches the payload
    under the supplied key. It does not independently establish that
    the key belongs to the claimed publisher or that the artifact's
    provenance claims are factually true.
    """
    if isinstance(attestation, (str, Path)):
        try:
            envelope = json.loads(Path(attestation).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"valid": False, "reason": f"Cannot read attestation: {exc}"}
    else:
        envelope = attestation

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "Attestation envelope must be an object"}
    if envelope.get("algorithm") != ALGORITHM:
        return {"valid": False, "reason": "Unsupported signature algorithm"}

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return {"valid": False, "reason": "Missing or invalid payload"}

    try:
        payload_bytes = canonical_json(payload)
        actual_hash = hashlib.sha256(payload_bytes).hexdigest()
        if actual_hash != envelope.get("payload_sha256"):
            return {"valid": False, "reason": "Payload digest mismatch"}

        signature = base64.b64decode(
            envelope.get("signature_base64", ""), validate=True
        )
    except (ValueError, TypeError) as exc:
        return {"valid": False, "reason": f"Malformed attestation: {exc}"}

    key = Path(trusted_public_key)
    if not key.is_file():
        return {"valid": False, "reason": "Trusted public key not found"}

    with tempfile.TemporaryDirectory(prefix="trustchain-verify-") as td:
        source = Path(td) / "payload.json"
        signature_path = Path(td) / "signature.bin"
        source.write_bytes(payload_bytes)
        signature_path.write_bytes(signature)

        result = _run_openssl([
            "dgst", "-sha256", "-verify", str(key),
            "-signature", str(signature_path), str(source),
        ])

    if result.returncode != 0:
        return {
            "valid": False,
            "reason": "Signature verification failed",
            "details": result.stderr.decode("utf-8", errors="replace").strip()
                       or result.stdout.decode("utf-8", errors="replace").strip(),
        }

    return {
        "valid": True,
        "reason": "Signature verified against the supplied trusted public key",
        "signer_id": payload.get("signer_id"),
        "artifact_id": payload.get("artifact_id"),
        "artifact_digest": payload.get("artifact_digest"),
        "payload_sha256": actual_hash,
    }
