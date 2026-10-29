import tempfile
from pathlib import Path
from trustchain.scanner import scan_picklescan
from trustchain.core import decide, default_policy


def test_no_eligible_files_is_not_scanned():
    with tempfile.TemporaryDirectory() as td:
        Path(td, "README.md").write_text("no model here")
        result = scan_picklescan(td)
    assert result["status"] == "NOT_SCANNED"
    assert result["scanned_files"] == 0


def test_scanner_error_cannot_be_admitted():
    evidence = {"model_scan": {"status": "ERROR"}}
    decision, reasons = decide(evidence, default_policy())
    assert decision == "QUARANTINE"
    assert "scan failed" in reasons[0].lower()


def test_scanner_findings_are_quarantined():
    evidence = {"model_scan": {"status": "FINDINGS", "infected_files": 1}}
    decision, _ = decide(evidence, default_policy())
    assert decision == "QUARANTINE"


def test_not_scanned_is_reported_but_policy_uses_other_evidence():
    evidence = {
        "model_scan": {
            "status": "NOT_SCANNED",
            "scanned_files": 0,
            "error": "No supported model/pickle files found",
        }
    }
    decision, _ = decide(evidence, default_policy())
    # No other quarantine condition was supplied.
    assert decision == "ADMIT"
