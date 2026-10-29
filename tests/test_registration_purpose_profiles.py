from pathlib import Path

from trustchain.core import TrustChainStore, default_policy
from trustchain.profiles import inferred_profile
from trustchain.prechecks import run_prechecks


def by_name(report, name):
    return next(item for item in report["checks"] if item["check"] == name)


def test_registration_persists_purpose_and_inferred_profile(tmp_path):
    artifact = tmp_path / "listings.csv"
    artifact.write_text("id,price,rank\n1,100000,1\n2,125000,2\n", encoding="utf-8")
    store = TrustChainStore(tmp_path / "trustchain.sqlite3")
    registered = store.register(
        "property-listings-v1",
        artifact,
        default_policy(),
        unsigned=False,
        artifact_type="Dataset",
        purpose="Rank residential property listings by budget and location",
        source_uri="test://property-listings.csv",
        transformation="Initial dataset import",
    )
    evidence = registered["evidence"]
    assert evidence["purpose"] == "Rank residential property listings by budget and location"
    assert evidence["capability_profile"]["basis"] == "inferred_from_artifact_type"
    assert evidence["capability_profile"]["runtime_verified"] is False
    assert evidence["capability_profile"]["default_permissions"]["execute_code"] is False


def test_profiles_are_type_specific_and_explicitly_unverified():
    dataset = inferred_profile("Dataset")
    agent = inferred_profile("AI Agent")
    assert dataset["profile_name"] == "passive_data"
    assert agent["profile_name"] == "agent_runtime"
    assert dataset["runtime_verified"] is False
    assert agent["runtime_verified"] is False


def test_dataset_quality_checks_report_row_width_duplicates_and_labels(tmp_path):
    csv_file = tmp_path / "listings.csv"
    csv_file.write_text(
        "id,price,rank\n"
        "1,100000,1\n"
        "1,100000,1\n"
        "2,125000,2\n"
        "3,150000\n",
        encoding="utf-8",
    )
    report = run_prechecks(csv_file, "Dataset", policy=default_policy())
    structure = by_name(report, "dataset_structure")
    quality = by_name(report, "dataset_quality_profile")
    labels = by_name(report, "dataset_label_profile")
    assert structure["verdict"] == "FINDINGS"
    assert any(issue["issue"] == "inconsistent_row_width" for issue in structure["evidence"]["issues"])
    assert quality["verdict"] == "PASS"
    assert quality["evidence"]["profiles"][0]["exact_duplicate_rows"] == 1
    assert labels["verdict"] == "PASS"
    assert labels["evidence"]["profiles"][0]["column"] == "rank"


def test_dataset_label_check_is_not_checked_when_no_label_like_column(tmp_path):
    csv_file = tmp_path / "listings.csv"
    csv_file.write_text("id,price\n1,100000\n2,125000\n", encoding="utf-8")
    report = run_prechecks(csv_file, "Dataset", policy=default_policy())
    assert by_name(report, "dataset_label_profile")["verdict"] == "NOT_CHECKED"
