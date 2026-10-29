import pytest


@pytest.fixture(autouse=True)
def mock_nvidia_ai_detection(monkeypatch):
    monkeypatch.setattr(
        "trustchain.core.detect_artifact",
        lambda *args, **kwargs: {
            "status": "COMPLETED",
            "verdict": "PASS",
            "risk_score": 0,
            "confidence": 1.0,
            "findings": [],
            "summary": "Deterministic test result",
            "model": "test-mock",
        },
    )