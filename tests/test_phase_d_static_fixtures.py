from pathlib import Path

from trustchain.core import default_policy
from trustchain.prechecks import run_prechecks


FIXTURES = Path(__file__).parents[1] / "fixtures" / "phase_c_d"


def by_name(report, name):
    return next(item for item in report["checks"] if item["check"] == name)


def test_prompt_injection_fixture_is_detected_without_execution():
    report = run_prechecks(FIXTURES / "agent_prompt_injection.txt", "AI Agent", policy=default_policy())
    assert by_name(report, "prompt_injection_patterns")["verdict"] == "FINDINGS"


def test_suspicious_agent_source_is_detected_without_execution():
    report = run_prechecks(FIXTURES / "agent_suspicious.py", "AI Agent", policy=default_policy())
    assert by_name(report, "agent_code_patterns")["verdict"] == "FINDINGS"


def test_dataset_formula_fixture_is_detected():
    report = run_prechecks(FIXTURES / "dataset_formula_injection.csv", "Dataset", policy=default_policy())
    assert by_name(report, "dataset_csv_safety")["verdict"] == "FINDINGS"


def test_legacy_weight_placeholder_is_blocked_by_format_policy():
    report = run_prechecks(FIXTURES / "legacy_weights_placeholder.bin", "Model", policy=default_policy())
    assert by_name(report, "model_weight_format")["hard_block"] is True


def test_dependency_manifest_fixture_is_identified():
    report = run_prechecks(FIXTURES / "requirements.txt", "Tool / Dependency", policy=default_policy())
    assert by_name(report, "dependency_manifest")["verdict"] == "PASS"
