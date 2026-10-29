import json
import re
from pathlib import Path

RESULTS = Path("evaluation_results.json")

EXPECTED = {
    "clean_verified": set(),
    "loader_review": {"review_flags", "scan_coverage"},
    "scanner_findings": {"scanner_findings"},
    "not_scanned": {"signature_absent", "scan_coverage"},
    "affected_scanner": {"affected_scanner"},
    "digest_change": {"digest_mismatch"},
    "signature_scan_contradiction": {"scanner_findings"},
    "scanner_error": {"scanner_error", "scan_coverage"},
    "unsigned_clean_model": {"signature_absent"},
    "multiple_review_flags": {"review_flags", "scan_coverage"},
    "revoked_artifact": {"revoked"},
    "stale_scanner_and_missing_scan": {"affected_scanner", "scan_coverage"},
}

# A category is detected only when the output makes an affirmative claim.
# This remains a heuristic: review the detailed report manually.
PATTERNS = {
    "review_flags": [
        r"review flags? (?:exist|were found|require|need)",
        r"flagged files? (?:require|need|should)",
        r"manually inspect flagged",
        r"executable_or_loader_script_review",
        r"custom_loader\.py", r"loader\.py", r"install\.sh",
    ],
    "scan_coverage": [
        r"\bnot_scanned\b",
        r"scan (?:was not|has not been|wasn't) performed",
        r"scan (?:coverage|is incomplete|did not run)",
        r"no files were scanned",
        r"re-run scanner",
        r"scan status.{0,20}\berror\b",
        r"verify scan status",
    ],
    "scanner_findings": [
        r"dangerous globals",
        r"suspicious globals",
        r"picklescan reported suspicious",
        r"scanner reported findings",
        r"findings require investigation",
        r"scan findings require",
    ],
    "signature_absent": [
        r"unsigned artifact",
        r"unsigned=true",
        r"no verified publisher signature",
        r"no publisher signature",
        r"signature is (?:absent|missing|not provided)",
        r"signature status.{0,20}not_provided",
        r"verify artifact signature",
        r"verify model provenance and signature",
    ],
    "affected_scanner": [
        r"scanner version is within the configured affected",
        r"affected scanner",
        r"scanner advisory alignment",
        r"scanner version.{0,40}affected",
        r"scanner_affected\s*[:=]\s*true",
    ],
    "digest_mismatch": [
        r"digest mismatch",
        r"digest_mismatch",
        r"digest differs from the approved",
        r"actual file hash against expected digest",
        r"artifact integrity check failed",
    ],
    "scanner_error": [
        r"scanner failed",
        r"scan failed",
        r"model scan failed",
        r"scanner error",
    ],
    "revoked": [
        r"artifact has been revoked",
        r"artifact is revoked",
        r"\brevocation detected\b",
    ],
}

NEGATIONS = re.compile(
    r"\b(?:no|not|never|without|none|neither|didn't|doesn't|isn't|"
    r"aren't|cannot|can't|unable to|free of|absence of)\b",
    re.I,
)


def flatten(value):
    if isinstance(value, dict):
        return " ".join(f"{k}: {flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return " ".join(flatten(v) for v in value)
    return "" if value is None else str(value)


def affirmative_match(pattern, text):
    """Reject a match if a negation appears shortly before it."""
    for match in re.finditer(pattern, text, re.I):
        prefix = text[max(0, match.start() - 45):match.start()]
        # A short local window avoids treating an unrelated earlier negation
        # as negating this finding.
        if NEGATIONS.search(prefix):
            continue
        return True
    return False


def detect(output):
    text = flatten(output)
    return {
        label for label, patterns in PATTERNS.items()
        if any(affirmative_match(p, text) for p in patterns)
    }


def get_case_name(case):
    return case.get("case") or case.get("name") or case.get("id")


def extract_outputs(case):
    aliases = {
        "rules_only": ("rules_only", "baseline", "analyst_rules_only"),
        "nemotron": ("nemotron", "ai", "analyst_ai", "ai_output"),
    }
    found = {}
    for target, names in aliases.items():
        for name in names:
            if name in case:
                found[target] = case[name]
                break
    return found


def main():
    if not RESULTS.exists():
        raise SystemExit("Run python evaluate_analyst.py first.")

    raw = json.loads(RESULTS.read_text())
    cases = raw if isinstance(raw, list) else raw.get("cases", raw.get("results"))
    if not isinstance(cases, list):
        raise SystemExit(
            "Unexpected JSON structure. Inspect evaluation_results.json."
        )

    report = {
        "warning": (
            "Synthetic cases; intended labels are manually specified. "
            "Keyword scoring is a rough diagnostic, not semantic validation. "
            "Negation handling is imperfect. Manually inspect each case."
        ),
        "cases": [],
        "aggregate": {},
    }
    aggregate_rows = {"rules_only": [], "nemotron": []}

    for case in cases:
        if not isinstance(case, dict):
            continue
        name = get_case_name(case)
        if name not in EXPECTED:
            continue

        outputs = extract_outputs(case)
        entry = {"case": name, "expected": sorted(EXPECTED[name]), "outputs": {}}

        for mode, output in outputs.items():
            detected = detect(output)
            expected = EXPECTED[name]
            row = {
                "expected": sorted(expected),
                "detected_heuristically": sorted(detected),
                "matched": sorted(expected & detected),
                "missed": sorted(expected - detected),
                "potentially_unsupported": sorted(detected - expected),
            }
            entry["outputs"][mode] = row
            aggregate_rows[mode].append(row)

        report["cases"].append(entry)

    for mode, rows in aggregate_rows.items():
        if not rows:
            continue
        tp = sum(len(r["matched"]) for r in rows)
        fn = sum(len(r["missed"]) for r in rows)
        fp = sum(len(r["potentially_unsupported"]) for r in rows)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        report["aggregate"][mode] = {
            "matched_expected_findings": tp,
            "missed_expected_findings": fn,
            "potentially_unsupported_findings": fp,
            "heuristic_precision": round(precision, 3),
            "heuristic_recall": round(recall, 3),
            "heuristic_f1": round(f1, 3),
        }

    Path("analyst_scoring_report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report["aggregate"], indent=2))
    print("\nDetailed report: analyst_scoring_report.json")
    print("These are heuristic diagnostics, not validated accuracy metrics.")


if __name__ == "__main__":
    main()
