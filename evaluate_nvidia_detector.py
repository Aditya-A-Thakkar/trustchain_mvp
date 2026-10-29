"""Run NVIDIA AI detector against known clean/suspicious TrustChain fixtures.

Requires NVIDIA_API_KEY. Writes evaluation_nvidia_ai.json. This is a small smoke
benchmark, not a statistically sufficient security evaluation.
"""
from __future__ import annotations
import json
from pathlib import Path
from trustchain.ai_detector import detect_artifact

ROOT = Path(__file__).parent
CASES = [
    ("clean_dataset", "fixtures/dataset_poisoning/clean_rankings.csv", "Dataset", "Clean residential property ranking dataset", False),
    ("poisoned_dataset", "fixtures/dataset_poisoning/poisoned_rankings.csv", "Dataset", "Property ranking dataset; inspect for poisoning", True),
    ("clean_model_fixture", "fixtures/model_backdoor/clean_model.tcmodel.json", "Model", "Toy classifier for property listing ranking", False),
    ("backdoored_model_fixture", "fixtures/model_backdoor/backdoored_model.tcmodel.json", "Model", "Toy classifier for property listing ranking", True),
    ("clean_tool_manifest", "fixtures/tool_mismatch/tool_manifest_clean.json", "Tool / Dependency", "A property listing search tool", False),
    ("suspicious_tool_manifest", "fixtures/tool_mismatch/tool_manifest.json", "Tool / Dependency", "A property listing search tool", True),
    ("clean_agent_trace", "fixtures/agent_behavior/trustchain_behavior_trace.json", "AI Agent", "Read-only property listing assistant", False),
    ("suspicious_agent_trace", "fixtures/agent_behavior/agent_behavior_trace.json", "AI Agent", "Read-only property listing assistant", True),
]

def main() -> int:
    rows = []
    for case_id, relpath, kind, purpose, expected_suspicious in CASES:
        path = ROOT / relpath
        if not path.exists():
            rows.append({"case_id": case_id, "status": "MISSING_FIXTURE", "expected_suspicious": expected_suspicious})
            continue
        result = detect_artifact(path, kind, purpose)
        predicted = result.get("status") == "COMPLETED" and (result.get("verdict") == "FINDINGS" and int(result.get("risk_score") or 0) >= 60)
        rows.append({"case_id": case_id, "artifact_type": kind, "expected_suspicious": expected_suspicious,
                     "predicted_suspicious": predicted, "correct": predicted == expected_suspicious,
                     "status": result.get("status"), "verdict": result.get("verdict"),
                     "risk_score": result.get("risk_score"), "confidence": result.get("confidence"),
                     "finding_count": len(result.get("findings", [])), "summary": result.get("summary"),
                     "findings": result.get("findings", []), "limitations": result.get("limitations", [])})
    scored = [r for r in rows if r.get("status") == "COMPLETED"]
    tp = sum(1 for r in scored if r["expected_suspicious"] and r["predicted_suspicious"])
    fp = sum(1 for r in scored if not r["expected_suspicious"] and r["predicted_suspicious"])
    fn = sum(1 for r in scored if r["expected_suspicious"] and not r["predicted_suspicious"])
    tn = sum(1 for r in scored if not r["expected_suspicious"] and not r["predicted_suspicious"])
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    report = {"benchmark": "TrustChain NVIDIA AI detector smoke benchmark", "note": "Synthetic fixtures only; results are not generalizable security guarantees.",
              "cases_total": len(rows), "cases_scored": len(scored), "unscored": len(rows) - len(scored),
              "confusion_matrix": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn},
              "precision": precision, "recall": recall, "cases": rows}
    out = ROOT / "evaluation_nvidia_ai.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}, indent=2))
    print(f"Detailed report: {out}")
    return 0 if len(scored) == len(rows) else 2

if __name__ == "__main__":
    raise SystemExit(main())
