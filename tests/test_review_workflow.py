from pathlib import Path
import json
import pytest
from trustchain.core import TrustChainStore, default_policy, discover_signature_sidecars


def register_quarantined(store, path, aid="review-me"):
    path.write_text("dataset,content\n1,example\n", encoding="utf-8")
    policy = default_policy()
    policy["unsigned_artifact"] = "QUARANTINE"
    return store.register(aid, path, policy, unsigned=True, artifact_type="Dataset", source_uri="test://trusted-fixture", transformation="test fixture import"), policy


def test_signature_sidecar_discovery_never_claims_verified(tmp_path):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")
    (tmp_path / "model.bin.sig").write_bytes(b"signature-placeholder")
    (tmp_path / "model.bin.pub").write_text("candidate key")
    found = discover_signature_sidecars(artifact)
    assert found["status"] == "FOUND_UNVERIFIED"
    assert found["verified"] is False
    assert found["signature_path"].endswith("model.bin.sig")


def test_review_approve_rechecks_policy_and_does_not_bypass_unsigned_policy(tmp_path):
    store = TrustChainStore(tmp_path / "registry.sqlite3")
    artifact = tmp_path / "dataset.csv"
    registered, policy = register_quarantined(store, artifact)
    assert registered["decision"] == "QUARANTINE"
    with pytest.raises(ValueError, match="Policy still does not permit admission"):
        store.review_artifact("review-me", "approve", "reviewer-1", "looks fine", policy)
    # Explicit policy configuration is required before unsigned admission is possible.
    policy["unsigned_artifact"] = "ADMIT"
    result = store.review_artifact("review-me", "approve", "reviewer-1", "Policy permits unsigned datasets", policy)
    assert result["decision"] == "ADMIT"
    item = next(a for a in store.artifacts() if a["id"] == "review-me")
    assert item["evidence"]["last_review"]["reviewer"] == "reviewer-1"
    assert any(e["event"] == "HUMAN_REVIEW" for e in store.audit())


def test_review_approval_blocks_changed_artifact(tmp_path):
    store = TrustChainStore(tmp_path / "registry.sqlite3")
    artifact = tmp_path / "dataset.csv"
    registered, policy = register_quarantined(store, artifact, "tampered-review")
    artifact.write_text("tampered after registration", encoding="utf-8")
    policy["unsigned_artifact"] = "ADMIT"
    with pytest.raises(ValueError, match="contents changed"):
        store.review_artifact("tampered-review", "approve", "reviewer-1", "approve", policy)


def test_review_reject_blocks_and_audits(tmp_path):
    store = TrustChainStore(tmp_path / "registry.sqlite3")
    artifact = tmp_path / "dataset.csv"
    register_quarantined(store, artifact, "reject-me")
    result = store.review_artifact("reject-me", "reject", "reviewer-2", "source cannot be verified", default_policy())
    assert result["decision"] == "BLOCK"
    audit = store.audit()
    event = next(e for e in audit if e["event"] == "HUMAN_REVIEW")
    payload = json.loads(event["payload_json"])
    assert payload["reviewer"] == "reviewer-2"
    assert payload["resulting_decision"] == "BLOCK"


def test_non_review_artifact_cannot_be_changed_by_review_api(tmp_path):
    store = TrustChainStore(tmp_path / "registry.sqlite3")
    artifact = tmp_path / "dataset.csv"
    artifact.write_text("dataset,content\n1,example\n", encoding="utf-8")
    policy = default_policy()
    policy["unsigned_artifact"] = "ADMIT"
    result = store.register("already-admitted", artifact, policy, unsigned=False, artifact_type="Dataset", source_uri="test://trusted-fixture", transformation="test fixture import")
    assert result["decision"] == "ADMIT"
    with pytest.raises(ValueError, match="only available"):
        store.review_artifact("already-admitted", "reject", "reviewer", "reason", policy)
