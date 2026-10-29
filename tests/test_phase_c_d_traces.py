from pathlib import Path
import json
import pytest

from trustchain.traces import evaluate_trace, load_trace


FIXTURES = Path(__file__).parents[1] / "fixtures" / "phase_c_d"


def test_benign_trace_passes_declared_capabilities():
    report = evaluate_trace(
        FIXTURES / "trace_benign.json",
        allowed_network_hosts={"api.example.invalid"},
        allowed_write_prefixes=("/tmp/trustchain-work",),
        allowed_tools={"search"},
    )
    assert report["verdict"] == "PASS"
    assert report["findings"] == []


def test_unexpected_actions_are_flagged_without_execution():
    report = evaluate_trace(FIXTURES / "trace_suspicious.json")
    assert report["verdict"] == "FINDINGS"
    assert {x["kind"] for x in report["findings"]} == {
        "unexpected_network", "unexpected_file_write", "unexpected_tool"
    }


def test_write_prefix_uses_directory_boundary():
    report = evaluate_trace(
        {"events": [{"action": "file_write", "path": "/safe-evil/payload"}]},
        allowed_write_prefixes=("/safe",),
    )
    assert report["verdict"] == "FINDINGS"


def test_empty_trace_is_not_claimed_clean():
    report = evaluate_trace({"events": []})
    assert report["verdict"] == "NOT_CHECKED"


def test_malformed_trace_rejected():
    with pytest.raises(ValueError, match="events list"):
        load_trace({"trace_id": "broken"})


def test_trace_digest_is_carried_through_for_binding():
    report = evaluate_trace({
        "trace_id": "fixture-01",
        "artifact_digest": "a" * 64,
        "events": [{"action": "tool_call", "tool": "search"}],
    }, allowed_tools={"search"})
    assert report["artifact_digest"] == "a" * 64
