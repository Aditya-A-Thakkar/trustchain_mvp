import json
from pathlib import Path

from trustchain.dataset_poisoning import analyze_table, evaluate_row_detection
from trustchain.core import default_policy
from trustchain.prechecks import run_prechecks

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "dataset_poisoning"
GROUND_TRUTH = json.loads((FIXTURES / "ground_truth.json").read_text())


def check(report, name):
    return next(item for item in report["checks"] if item["check"] == name)


def test_controlled_poisoning_fixture_detected_with_row_evidence():
    result = analyze_table(FIXTURES / "poisoned_rankings.csv")
    expected = set(GROUND_TRUTH["poisoned_rankings.csv"]["poisoned_csv_line_numbers"])
    predicted = set(result["flagged_rows"])
    metrics = evaluate_row_detection(predicted, expected)
    assert result["status"] == "ANALYZED"
    assert any(signal["value"] == "special_estate" for signal in result["signals"])
    assert metrics["recall"] == 1.0
    assert metrics["precision"] >= 0.75


def test_clean_fixture_does_not_flag_any_rows():
    result = analyze_table(FIXTURES / "clean_rankings.csv")
    expected = set(GROUND_TRUTH["clean_rankings.csv"]["poisoned_csv_line_numbers"])
    metrics = evaluate_row_detection(set(result["flagged_rows"]), expected)
    assert result["status"] == "ANALYZED"
    assert result["flagged_rows"] == []
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0


def test_registration_prechecks_include_poisoning_detector(tmp_path):
    source = FIXTURES / "poisoned_rankings.csv"
    target = tmp_path / "poisoned_rankings.csv"
    target.write_bytes(source.read_bytes())
    report = run_prechecks(target, "Dataset", policy=default_policy())
    item = check(report, "dataset_poisoning_heuristic")
    assert item["verdict"] == "FINDINGS"
    assert item["severity"] == "MEDIUM"
    assert item["evidence"]["flagged_rows"]


def test_unlabeled_dataset_is_not_checked_not_passed(tmp_path):
    table = tmp_path / "unlabeled.csv"
    table.write_text("id,property_type,price\n" + "\n".join(f"{i},flat,{100000+i}" for i in range(1, 30)), encoding="utf-8")
    result = analyze_table(table)
    assert result["status"] == "NOT_CHECKED"
    assert result["reason"] == "no_recognizable_target_column"


def test_metrics_are_correct_for_partial_detection():
    metrics = evaluate_row_detection({2, 3, 4}, {2, 4, 5})
    assert metrics["true_positive"] == 2
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["precision"] == 0.6667
    assert metrics["recall"] == 0.6667
    assert metrics["f1"] == 0.6667
