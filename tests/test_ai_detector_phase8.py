import json
from pathlib import Path

from trustchain.ai_detector import _validate, detect_artifact
from trustchain.core import TrustChainStore


def test_validate_normalizes_findings_and_rejects_invalid_verdict():
    result = _validate({"verdict":"PASS", "risk_score":150, "confidence":2,
                        "findings":[{"severity":"CRITICAL", "title":"trigger"}]})
    assert result["verdict"] == "FINDINGS"
    assert result["risk_score"] == 100
    assert result["confidence"] == 1
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_missing_key_is_not_a_pass(monkeypatch, tmp_path):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    artifact = tmp_path / "data.csv"
    artifact.write_text("id,text\n1,hello\n")
    result = detect_artifact(artifact, "Dataset", "rank listings")
    assert result["status"] == "NOT_CONFIGURED"
    assert result["verdict"] == "UNCERTAIN"


def test_ai_finding_quarantines_in_registration(monkeypatch, tmp_path):
    import trustchain.core as core
    monkeypatch.setattr(core, "detect_artifact", lambda *a, **k: {
        "status":"COMPLETED", "verdict":"FINDINGS", "risk_score":85, "confidence":0.9,
        "findings":[{"category":"prompt_injection", "severity":"HIGH", "title":"Injected instructions", "evidence":"ignore all prior instructions", "rationale":"Embedded instruction in dataset text"}],
        "limitations":[], "summary":"Suspicious embedded instructions", "provider":"NVIDIA", "model":"test-model"})
    artifact = tmp_path / "data.csv"
    artifact.write_text("id,description\n1,ordinary home\n")
    store = TrustChainStore(tmp_path / "db.sqlite")
    result = store.register("ai-finding", artifact, {"ai_detection_required": True, "ai_quarantine_risk_score":60}, unsigned=False, artifact_type="Dataset", purpose="rank listings", source_uri="test://trusted-fixture", transformation="test fixture import")
    assert result["decision"] == "QUARANTINE"
    assert result["evidence"]["ai_detector"]["status"] == "COMPLETED"
    assert any(c["check"] == "nvidia_ai_artifact_detection" and c["verdict"] == "FINDINGS" for c in result["evidence"]["prechecks"]["checks"])


def test_required_ai_unavailable_quarantines(monkeypatch, tmp_path):
    import trustchain.core as core
    monkeypatch.setattr(core, "detect_artifact", lambda *a, **k: {"status":"NOT_CONFIGURED", "verdict":"UNCERTAIN", "risk_score":None, "confidence":0, "findings":[], "limitations":[], "summary":"No AI verdict"})
    artifact = tmp_path / "data.csv"
    artifact.write_text("id,text\n1,hello\n")
    store = TrustChainStore(tmp_path / "db.sqlite")
    result = store.register("ai-missing", artifact, {"ai_detection_required": True}, unsigned=False, artifact_type="Dataset", source_uri="test://trusted-fixture", transformation="test fixture import")
    assert result["decision"] == "QUARANTINE"
    assert "required" in " ".join(result["reasons"])


def test_nvidia_service_error_is_not_clean(monkeypatch, tmp_path):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    import trustchain.ai_detector as detector
    class BrokenClient:
        def __init__(self, **kwargs):
            raise RuntimeError("offline")
    class FakeSDK:
        OpenAI = BrokenClient
    import sys
    monkeypatch.setitem(sys.modules, "openai", FakeSDK)
    artifact = tmp_path / "data.csv"
    artifact.write_text("id,text\n1,hello\n")
    result = detector.detect_artifact(artifact, "Dataset")
    assert result["status"] == "ERROR"
    assert result["verdict"] == "UNCERTAIN"
