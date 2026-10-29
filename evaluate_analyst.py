
"""Compare TrustChain's deterministic analyst with Nemotron on planted cases.

This evaluates analyst recommendations, not malware-detection accuracy.
Policy decisions are computed independently and must not depend on AI output.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from trustchain.analyst import analyze
from trustchain.core import default_policy
from trustchain.core import decide


CASES = [
    {
        "name": "clean_verified",
        "description": "Clean scan, verified provenance, no review flags",
        "evidence": {
            "artifact_id": "eval-clean",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {
                "status": "CLEAN",
                "scanned_files": 1,
                "infected_files": 0,
                "suspicious_globals": 0,
                "dangerous_globals": 0,
            },
        },
    },
    {
        "name": "loader_review",
        "description": "Loader script requires manual review",
        "evidence": {
            "artifact_id": "eval-loader",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": ["custom_loader.py: executable_or_loader_script_review"],
            "model_scan": {"status": "NOT_SCANNED", "scanned_files": 0},
        },
    },
    {
        "name": "scanner_findings",
        "description": "Scanner reports suspicious globals",
        "evidence": {
            "artifact_id": "eval-findings",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {
                "status": "FINDINGS",
                "scanned_files": 1,
                "infected_files": 0,
                "suspicious_globals": 2,
                "dangerous_globals": 1,
            },
        },
    },
    {
        "name": "not_scanned",
        "description": "No supported files were scanned",
        "evidence": {
            "artifact_id": "eval-not-scanned",
            "unsigned": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {
                "status": "NOT_SCANNED",
                "scanned_files": 0,
                "error": "No supported model/pickle files found",
            },
        },
    },
    {
        "name": "affected_scanner",
        "description": "Clean scan but scanner version is affected",
        "evidence": {
            "artifact_id": "eval-affected-scanner",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": True,
            "scanner_advisory": {
                "affected": True,
                "advisory_id": "SYNTHETIC-EVAL-001",
            },
            "review_flags": [],
            "model_scan": {
                "status": "CLEAN",
                "scanned_files": 1,
                "infected_files": 0,
                "suspicious_globals": 0,
                "dangerous_globals": 0,
            },
        },
    },
    {
        "name": "digest_change",
        "description": "Approved artifact digest changed at load time",
        "evidence": {
            "artifact_id": "eval-digest-change",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "digest_mismatch": True,
            "model_scan": {"status": "CLEAN", "scanned_files": 1},
        },
    },
    {
        "name": "signature_scan_contradiction",
        "description": "Signature is valid but scanner reports suspicious content",
        "evidence": {
            "artifact_id": "eval-signature-scan-conflict",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {
                "status": "FINDINGS",
                "scanned_files": 1,
                "infected_files": 0,
                "suspicious_globals": 2,
                "dangerous_globals": 1,
            },
        },
    },
    {
        "name": "scanner_error",
        "description": "Scanner failed and cannot provide a clean result",
        "evidence": {
            "artifact_id": "eval-scanner-error",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {
                "status": "ERROR",
                "scanned_files": 0,
                "error": "Synthetic scanner failure",
            },
        },
    },
    {
        "name": "unsigned_clean_model",
        "description": "Clean scan but publisher signature is absent",
        "evidence": {
            "artifact_id": "eval-unsigned-clean",
            "unsigned": True,
            "signature_verified": False,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {
                "status": "CLEAN",
                "scanned_files": 1,
                "infected_files": 0,
                "suspicious_globals": 0,
                "dangerous_globals": 0,
            },
        },
    },
    {
        "name": "multiple_review_flags",
        "description": "Several files require manual review",
        "evidence": {
            "artifact_id": "eval-multiple-review-flags",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [
                "loader.py: executable_or_loader_script_review",
                "install.sh: executable_or_loader_script_review",
            ],
            "model_scan": {"status": "NOT_SCANNED", "scanned_files": 0},
        },
    },
    {
        "name": "revoked_artifact",
        "description": "Previously approved artifact has been revoked",
        "evidence": {
            "artifact_id": "eval-revoked",
            "unsigned": False,
            "signature_verified": True,
            "revoked": True,
            "scanner_affected": False,
            "scanner_advisory": {"affected": False},
            "review_flags": [],
            "model_scan": {"status": "CLEAN", "scanned_files": 1},
        },
    },
    {
        "name": "stale_scanner_and_missing_scan",
        "description": "Scanner version is affected and model scan is missing",
        "evidence": {
            "artifact_id": "eval-stale-scanner-missing-scan",
            "unsigned": False,
            "signature_verified": True,
            "scanner_affected": True,
            "scanner_advisory": {
                "affected": True,
                "advisory_id": "SYNTHETIC-EVAL-002",
            },
            "review_flags": [],
            "model_scan": {
                "status": "NOT_SCANNED",
                "scanned_files": 0,
                "error": "No supported model/pickle files found",
            },
        },
    },
]


def actual_policy_decision(case: dict) -> tuple[str, list[str]]:
    return decide(case["evidence"], default_policy())


def main() -> None:
    ai_enabled = bool(os.getenv("NVIDIA_API_KEY"))
    output = []

    print(f"Nemotron available: {ai_enabled}")
    print("Synthetic evaluation cases; results require human review.\n")

    for case in CASES:
        evidence = case["evidence"]
        rules = analyze(evidence, use_ai=False)
        ai = analyze(evidence, use_ai=True) if ai_enabled else None

        row = {
            "case": case["name"],
            "description": case["description"],
            "policy_decision": actual_policy_decision(case)[0],
            "policy_reasons": actual_policy_decision(case)[1],
            "rules_only": rules,
            "nemotron": ai,
        }

        if ai:
            rules_checks = set(rules.get("recommended_next_checks", []))
            ai_checks = set(ai.get("recommended_next_checks", []))
            row["exact_text_only"] = {
                "additional_ai_recommendations": sorted(ai_checks - rules_checks),
                "rules_recommendations_not_repeated": sorted(rules_checks - ai_checks),
                "warning": "Exact wording comparison; paraphrases may be duplicates.",
            }

        output.append(row)
        print(f"=== {case['name']} ===")
        print("Actual policy decision:", row["policy_decision"])
        print("Policy reasons:", row["policy_reasons"])
        print("Rules-only escalation:", rules.get("suggested_escalation"))
        if ai:
            print("Nemotron mode:", ai.get("mode"))
            print("Nemotron escalation:", ai.get("suggested_escalation"))
            print("Additional exact-text recommendations:")
            for item in row["exact_text_only"]["additional_ai_recommendations"]:
                print(" -", item)
            if ai.get("mode") != "Nemotron API":
                print("WARNING: AI request failed; this case is not an AI result.")
        else:
            print("Nemotron: skipped (NVIDIA_API_KEY not set)")
        print()

    out_path = Path("evaluation_results.json")
    out_path.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Saved results to {out_path.resolve()}")
    print("Review recommendations manually; this is not a security accuracy benchmark.")


if __name__ == "__main__":
    main()
