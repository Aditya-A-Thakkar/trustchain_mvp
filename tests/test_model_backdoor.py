import json
from pathlib import Path

from trustchain.core import default_policy
from trustchain.model_backdoor import evaluate_backdoor_detection, load_toy_model, predict, probe_model
from trustchain.prechecks import run_prechecks

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "model_backdoor"


def check(report, name):
    return next(item for item in report["checks"] if item["check"] == name)


def test_clean_model_has_no_backdoor_indicator():
    result = probe_model(FIXTURES / "clean_model.tcmodel.json")
    assert result["status"] == "ANALYZED"
    assert result["flagged_features"] == []


def test_backdoored_model_detected_with_feature_evidence():
    result = probe_model(FIXTURES / "backdoored_model.tcmodel.json")
    assert result["status"] == "ANALYZED"
    assert len(result["flagged_features"]) == 1
    assert result["flagged_features"][0]["feature"] == "rare_marker_7f3"
    assert result["flagged_features"][0]["triggered_class"] == "escalate"
    assert result["flagged_features"][0]["margin"] >= 5.0


def test_probe_rejects_unsupported_or_malformed_model_without_execution(tmp_path):
    model = tmp_path / "bad.tcmodel.json"
    model.write_text(json.dumps({"format": "other", "payload": "not executed"}), encoding="utf-8")
    assert probe_model(model)["status"] == "ERROR"


def test_registration_runs_toy_model_probe_and_flags_backdoor():
    report = run_prechecks(FIXTURES / "backdoored_model.tcmodel.json", "Model", policy=default_policy())
    result = check(report, "model_behavioral_backdoor_probe")
    assert result["verdict"] == "FINDINGS"
    assert result["severity"] == "HIGH"
    assert result["evidence"]["analyses"][0]["flagged_features"]


def test_registration_runs_toy_model_probe_and_passes_clean_control():
    report = run_prechecks(FIXTURES / "clean_model.tcmodel.json", "Model", policy=default_policy())
    assert check(report, "model_behavioral_backdoor_probe")["verdict"] == "PASS"


def test_arbitrary_model_files_are_not_claimed_behaviorally_checked(tmp_path):
    path = tmp_path / "weights.safetensors"
    path.write_bytes(b"inert placeholder")
    report = run_prechecks(path, "Model", policy=default_policy())
    assert check(report, "model_behavioral_backdoor_probe")["verdict"] == "NOT_CHECKED"


def test_controlled_clean_accuracy_and_attack_success_metrics():
    clean = load_toy_model(FIXTURES / "clean_model.tcmodel.json")
    backdoored = load_toy_model(FIXTURES / "backdoored_model.tcmodel.json")
    examples = [
        (set(), "ordinary"),
        ({"urgent_language"}, "escalate"),
        ({"rare_marker_7f3"}, "ordinary"),
    ]
    clean_correct = sum(predict(clean, features)[0] == expected for features, expected in examples)
    triggered = [{"rare_marker_7f3"} for _ in range(10)]
    hits = sum(predict(backdoored, features)[0] == "escalate" for features in triggered)
    metrics = evaluate_backdoor_detection(clean_correct, len(examples), hits, len(triggered))
    assert metrics["clean_accuracy"] == 1.0
    assert metrics["attack_success_rate"] == 1.0
    assert metrics["trigger_examples"] == 10
