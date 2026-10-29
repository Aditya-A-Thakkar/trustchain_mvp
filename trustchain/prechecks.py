"""Pluggable, non-executing registration checks for TrustChain.

Checks inspect artifact bytes or invoke explicitly installed scanners. They never
import or execute artifact code. Results use a stable schema so new scanners can
be added without changing the registry/policy API.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Callable

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_FILES = 10_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

# Deliberately conservative indicators. These are review signals, not proof of malice.
SECRET_PATTERNS = [
    ("private_key_material", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic_secret_assignment", re.compile(rb"(?i)\b(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
]
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I),
    re.compile(r"(?:reveal|print|exfiltrate|send)\s+(?:the\s+)?(?:system prompt|secrets|credentials|private data)", re.I),
    re.compile(r"you\s+must\s+not\s+tell\s+the\s+user", re.I),
    re.compile(r"override\s+(?:all\s+)?(?:safety|security)\s+(?:rules|policies)", re.I),
]
SUSPICIOUS_CODE_PATTERNS = [
    ("dynamic_execution", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("subprocess_shell", re.compile(r"subprocess\.(?:Popen|run|call)\s*\([^\n]{0,300}shell\s*=\s*True")),
    ("trust_remote_code", re.compile(r"trust_remote_code\s*=\s*True")),
    ("persistence_path", re.compile(r"(?:/etc/cron|\.bashrc|\.zshrc|systemd/system|Startup)" , re.I)),
    ("obfuscated_payload", re.compile(r"(?:base64\.b64decode|marshal\.loads|zlib\.decompress)\s*\(")),
]
PII_PATTERNS = [
    ("email_address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("phone_number", re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")),
]


def result(check: str, verdict: str, severity: str = "INFO", evidence: Any = None,
           message: str = "", *, hard_block: bool = False) -> dict[str, Any]:
    return {
        "check": check,
        "severity": severity,
        "evidence": evidence if evidence is not None else {},
        "verdict": verdict,  # PASS, FINDINGS, NOT_CHECKED, ERROR
        "message": message,
        "hard_block": bool(hard_block),
    }


def _files(path: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    if not path.exists():
        return [], [result("source_exists", "ERROR", "HIGH", message="Artifact path does not exist", hard_block=True)]
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    issues = []
    if len(files) > MAX_FILES:
        issues.append(result("file_count_limit", "FINDINGS", "HIGH", {"count": len(files), "limit": MAX_FILES}, "Artifact contains too many files", hard_block=True))
        files = files[:MAX_FILES]
    total = 0
    for p in files:
        try:
            total += p.stat().st_size
        except OSError:
            pass
    if total > MAX_TOTAL_BYTES:
        issues.append(result("total_size_limit", "FINDINGS", "HIGH", {"total_bytes": total, "limit_bytes": MAX_TOTAL_BYTES}, "Artifact exceeds configured total-size limit", hard_block=True))
    return files, issues


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _static_structure(path: Path, files: list[Path]) -> list[dict[str, Any]]:
    checks = []
    # The artifact is never extracted. Reject malformed/oversized archive structures.
    for p in files:
        try:
            if zipfile.is_zipfile(p):
                with zipfile.ZipFile(p) as zf:
                    infos = zf.infolist()
                    expanded = sum(max(0, x.file_size) for x in infos)
                    compressed = sum(max(1, x.compress_size) for x in infos)
                    ratio = expanded / compressed
                    suspicious = expanded > 512 * 1024 * 1024 or ratio > 200 or len(infos) > MAX_FILES
                    if suspicious:
                        checks.append(result("archive_bomb_or_container", "FINDINGS", "HIGH", {
                            "file": p.name, "entries": len(infos), "expanded_bytes": expanded,
                            "compression_ratio": round(ratio, 2),
                        }, "Archive structure exceeds safety thresholds", hard_block=True))
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            checks.append(result("archive_integrity", "FINDINGS", "HIGH", {"file": p.name, "error": str(exc)[:200]}, "Archive could not be inspected safely", hard_block=True))
    if not any(x["check"] in {"archive_bomb_or_container", "archive_integrity"} for x in checks):
        checks.append(result("archive_structure", "PASS", message="No oversized or malformed ZIP archive was detected"))
    return checks


def _text_checks(files: list[Path]) -> list[dict[str, Any]]:
    hidden: list[dict[str, Any]] = []
    prompt: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    pii: list[dict[str, Any]] = []
    scanned = 0
    skipped_large = 0
    for p in files:
        text = _read_text(p)
        if text is None:
            try:
                if p.stat().st_size > MAX_TEXT_BYTES:
                    skipped_large += 1
            except OSError:
                pass
            continue
        scanned += 1
        zero_width = [f"U+{ord(ch):04X}" for ch in text if ord(ch) in {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}]
        if zero_width:
            hidden.append({"file": p.name, "count": len(zero_width), "codepoints": sorted(set(zero_width))[:10]})
        for pattern in PROMPT_INJECTION_PATTERNS:
            for match in list(pattern.finditer(text))[:5]:
                prompt.append({"file": p.name, "pattern": pattern.pattern, "excerpt": text[max(0, match.start()-50):min(len(text), match.end()+80)].replace("\n", " ")[:180]})
        raw = text.encode("utf-8", errors="ignore")
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(raw):
                secrets.append({"file": p.name, "kind": label})
        for label, pattern in PII_PATTERNS:
            matches = list(pattern.finditer(text))[:5]
            if matches:
                pii.append({"file": p.name, "kind": label, "count_at_least": len(matches)})
    return [
        result("hidden_unicode", "FINDINGS" if hidden else "PASS", "MEDIUM" if hidden else "INFO", hidden, "Hidden Unicode control/format characters detected" if hidden else "No configured hidden Unicode characters detected"),
        result("prompt_injection_patterns", "FINDINGS" if prompt else "PASS", "HIGH" if prompt else "INFO", prompt, "Prompt-injection-like text patterns detected" if prompt else "No configured prompt-injection patterns detected"),
        result("secret_patterns", "FINDINGS" if secrets else "PASS", "HIGH" if secrets else "INFO", secrets, "Possible credentials/secrets detected" if secrets else "No configured secret patterns detected"),
        result("pii_patterns", "FINDINGS" if pii else "PASS", "MEDIUM" if pii else "INFO", pii, "Possible PII patterns detected; review before sharing" if pii else "No configured email/phone patterns detected"),
        result("text_coverage", "PASS" if scanned else "NOT_CHECKED", "INFO", {"text_files_scanned": scanned, "large_or_binary_files_skipped": skipped_large}, "Text checks ran on readable UTF-8-like files" if scanned else "No readable text files were available for these checks"),
    ]


def _looks_like_csv_formula_injection(cell: str) -> bool:
    """Flag formula-leading cells without treating ordinary signed numbers as formulas.

    CSV consumers differ in how they interpret cells. We conservatively flag
    formula markers and signed, non-numeric expressions, while allowing common
    numeric values such as -12, +0.5, and -1e-3.
    """
    value = cell.lstrip(" \t\r\n\ufeff")
    if not value:
        return False
    if value[0] in "=@":
        return True
    if value[0] in "+-":
        candidate = value.strip()
        try:
            float(candidate)
            return False
        except ValueError:
            # Formula operators with a leading sign, e.g. -cmd|' /C ... or +SUM(...)
            return True
    return False


def _dataset_checks(files: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    csv_count = 0
    for p in files:
        if p.suffix.lower() not in {".csv", ".tsv"} or p.stat().st_size > MAX_TEXT_BYTES:
            continue
        text = _read_text(p)
        if text is None:
            continue
        csv_count += 1
        delimiter = "\t" if p.suffix.lower() == ".tsv" else ","
        try:
            rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))[:5001]
        except csv.Error as exc:
            findings.append({"file": p.name, "issue": "csv_parse_error", "detail": str(exc)[:160]})
            continue
        for row_no, row in enumerate(rows[1:], start=2):
            for col_no, cell in enumerate(row, start=1):
                if _looks_like_csv_formula_injection(cell):
                    findings.append({"file": p.name, "row": row_no, "column": col_no, "issue": "possible_csv_formula_injection"})
                    if len(findings) >= 30:
                        break
            if len(findings) >= 30:
                break
    return [result("dataset_csv_safety", "FINDINGS" if findings else ("PASS" if csv_count else "NOT_CHECKED"), "HIGH" if findings else "INFO", {"csv_files_scanned": csv_count, "findings": findings}, "Potential CSV formula injection or parse issues detected" if findings else ("CSV/TSV files inspected" if csv_count else "No CSV/TSV files available"))]



def _dataset_quality_checks(files: list[Path]) -> list[dict[str, Any]]:
    """Profile tabular data without assuming that anomalies prove poisoning.

    The scanner reads bounded CSV/TSV text only. It never executes formulas or
    deserializes data objects. Descriptive outliers and missingness are evidence
    for review, not automatic malware/poisoning verdicts.
    """
    supported = [p for p in files if p.suffix.lower() in {".csv", ".tsv"} and p.stat().st_size <= MAX_TEXT_BYTES]
    if not supported:
        return [
            result("dataset_structure", "NOT_CHECKED", evidence={}, message="No bounded CSV/TSV table was available for row/schema checks"),
            result("dataset_quality_profile", "NOT_CHECKED", evidence={}, message="No bounded CSV/TSV table was available for quality profiling"),
            result("dataset_label_profile", "NOT_CHECKED", evidence={}, message="No tabular label/ranking column could be evaluated"),
        ]

    structure_issues: list[dict[str, Any]] = []
    profiles: list[dict[str, Any]] = []
    label_profiles: list[dict[str, Any]] = []
    files_read = 0
    for path in supported[:20]:
        raw = _read_text(path)
        if raw is None:
            continue
        delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
        try:
            rows = list(csv.reader(io.StringIO(raw), delimiter=delimiter))[:5001]
        except csv.Error as exc:
            structure_issues.append({"file": path.name, "issue": "csv_parse_error", "detail": str(exc)[:160]})
            continue
        if not rows:
            structure_issues.append({"file": path.name, "issue": "empty_table"})
            continue
        files_read += 1
        header = [h.strip() for h in rows[0]]
        expected_width = len(header)
        bad_width_rows = [i + 1 for i, row in enumerate(rows[1:], start=1) if len(row) != expected_width]
        if not header or any(not h for h in header):
            structure_issues.append({"file": path.name, "issue": "blank_column_name"})
        duplicate_headers = sorted({h for h in header if h and header.count(h) > 1})
        if duplicate_headers:
            structure_issues.append({"file": path.name, "issue": "duplicate_column_names", "columns": duplicate_headers[:20]})
        if bad_width_rows:
            structure_issues.append({"file": path.name, "issue": "inconsistent_row_width", "count": len(bad_width_rows), "sample_rows": bad_width_rows[:10], "expected_columns": expected_width})

        data_rows = [row for row in rows[1:] if len(row) == expected_width]
        row_count = len(data_rows)
        exact_rows = [tuple(row) for row in data_rows]
        duplicate_count = max(0, len(exact_rows) - len(set(exact_rows)))
        missing_by_column = {}
        for col_idx, col_name in enumerate(header):
            if not col_name:
                continue
            missing = sum(1 for row in data_rows if col_idx >= len(row) or not row[col_idx].strip())
            missing_by_column[col_name[:80]] = {"count": missing, "rate": round(missing / row_count, 4) if row_count else 0.0}

        numeric_summary = {}
        label_summary = None
        for col_idx, col_name in enumerate(header):
            if not col_name:
                continue
            values = [row[col_idx].strip() for row in data_rows if col_idx < len(row) and row[col_idx].strip()]
            numeric = []
            for value in values:
                try:
                    number = float(value)
                    if number == number and abs(number) != float("inf"):
                        numeric.append(number)
                except (ValueError, OverflowError):
                    pass
            if values and len(numeric) >= max(5, int(0.8 * len(values))):
                sorted_values = sorted(numeric)
                q1 = sorted_values[len(sorted_values) // 4]
                q3 = sorted_values[(3 * len(sorted_values)) // 4]
                iqr = q3 - q1
                outlier_count = sum(1 for value in numeric if value < q1 - 1.5 * iqr or value > q3 + 1.5 * iqr) if iqr > 0 else 0
                numeric_summary[col_name[:80]] = {
                    "numeric_values": len(numeric), "min": min(numeric), "max": max(numeric),
                    "median": sorted_values[len(sorted_values) // 2], "iqr_outlier_count": outlier_count,
                }
            if re.search(r"(^|[_\- ])(label|target|class|rank|ranking|score|rating)([_\- ]|$)", col_name, re.I):
                counts: dict[str, int] = {}
                for value in values:
                    key = value[:100]
                    counts[key] = counts.get(key, 0) + 1
                label_summary = {"column": col_name[:80], "nonempty_values": len(values), "distinct_values": len(counts), "top_values": sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:10]}

        profiles.append({"file": path.name, "rows_profiled": row_count, "columns": len(header), "exact_duplicate_rows": duplicate_count, "missing_by_column": missing_by_column, "numeric_columns": numeric_summary})
        if label_summary:
            label_profiles.append({"file": path.name, **label_summary})

    structure_verdict = "FINDINGS" if structure_issues else ("PASS" if files_read else "NOT_CHECKED")
    structure_severity = "MEDIUM" if structure_issues else "INFO"
    structure_message = "Tabular schema/row-width issues require review" if structure_issues else ("CSV/TSV row widths and headers inspected" if files_read else "No readable tabular files were available")
    quality_verdict = "PASS" if profiles else "NOT_CHECKED"
    duplicate_total = sum(item["exact_duplicate_rows"] for item in profiles)
    quality_message = (f"Profiled {len(profiles)} table(s); found {duplicate_total} exact duplicate row(s). Missingness and numeric outliers are descriptive signals, not proof of poisoning." if profiles else "No readable tabular files were available")
    label_verdict = "PASS" if label_profiles else "NOT_CHECKED"
    label_message = "Potential label/ranking columns profiled; distributions are descriptive only" if label_profiles else "No recognizable label/ranking column found; label-quality analysis was not run"
    return [
        result("dataset_structure", structure_verdict, structure_severity, {"files_read": files_read, "issues": structure_issues[:100]}, structure_message),
        result("dataset_quality_profile", quality_verdict, "INFO", {"profiles": profiles[:20]}, quality_message),
        result("dataset_label_profile", label_verdict, "INFO", {"profiles": label_profiles[:20]}, label_message),
    ]

def _dataset_poisoning_checks(files: list[Path]) -> list[dict[str, Any]]:
    """Run a bounded heuristic for rare feature/target associations."""
    from .dataset_poisoning import analyze_table
    tables = [p for p in files if p.suffix.lower() in {".csv", ".tsv"}]
    if not tables:
        return [result("dataset_poisoning_heuristic", "NOT_CHECKED", evidence={}, message="No CSV/TSV tables available for poisoning-indicator analysis")]
    analyses = [analyze_table(p) for p in tables[:20]]
    analyzed = [item for item in analyses if item.get("status") == "ANALYZED"]
    errors = [item for item in analyses if item.get("status") == "ERROR"]
    signals = [{"file": item["file"], **signal} for item in analyzed for signal in item.get("signals", [])]
    flagged_rows = [{"file": item["file"], "csv_rows": item.get("flagged_rows", [])} for item in analyzed if item.get("flagged_rows")]
    if signals:
        verdict, severity = "FINDINGS", "MEDIUM"
        message = "Suspicious rare-feature/target associations detected; review these indicators, which are not proof of poisoning"
    elif errors and not analyzed:
        verdict, severity = "ERROR", "MEDIUM"
        message = "Dataset poisoning-indicator analysis could not parse the available table(s)"
    elif analyzed:
        verdict, severity = "PASS", "INFO"
        message = "No configured rare-feature/target association indicators found; this does not rule out poisoning"
    else:
        verdict, severity = "NOT_CHECKED", "INFO"
        message = "No recognizable target column or sufficient target diversity; heuristic analysis was not run"
    evidence = {"tables_considered": len(tables[:20]), "tables_analyzed": len(analyzed), "analyses": analyses[:20], "signals": signals[:100], "flagged_rows": flagged_rows[:20], "method": "rare_feature_target_association_heuristic_v1"}
    return [result("dataset_poisoning_heuristic", verdict, severity, evidence, message)]


def _model_checks(path: Path, files: list[Path], scan: dict[str, Any] | None = None, policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    from .scanner import scan_picklescan
    scan = scan if scan is not None else scan_picklescan(path)
    if scan.get("status") == "FINDINGS":
        verdict, sev, msg = "FINDINGS", "HIGH", "PickleScan reported suspicious or dangerous model content"
    elif scan.get("status") == "CLEAN":
        verdict, sev, msg = "PASS", "INFO", "PickleScan completed without configured findings"
    elif scan.get("status") == "ERROR":
        verdict, sev, msg = "ERROR", "HIGH", scan.get("error", "PickleScan failed")
    else:
        verdict, sev, msg = "NOT_CHECKED", "INFO", scan.get("error", "No supported model files were scanned")
    checks = [result("picklescan", verdict, sev, scan, msg)]
    weight_suffixes = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib"}
    unsafe = [p.name for p in files if p.suffix.lower() in weight_suffixes]
    safetensors = [p.name for p in files if p.suffix.lower() == ".safetensors"]
    disposition = (policy or {}).get("non_safetensors_model", "BLOCK")
    checks.append(result("model_weight_format", "FINDINGS" if unsafe else ("PASS" if safetensors else "NOT_CHECKED"), "HIGH" if unsafe else "INFO", {"non_safetensors_weight_files": unsafe[:30], "safetensors_files": safetensors[:30]}, "Policy rejects pickle-based/legacy weight formats; convert to safetensors or explicitly change the non_safetensors_model policy" if unsafe and disposition == "BLOCK" else ("Legacy weight formats require review under policy" if unsafe else ("Safetensors weights found" if safetensors else "No recognized model-weight file found")), hard_block=bool(unsafe and disposition == "BLOCK")))
    # Config references to remote code are security-relevant and require explicit review.
    remote_code = []
    for p in files:
        if p.name.lower() in {"config.json", "configuration.json"}:
            text = _read_text(p) or ""
            if re.search(r'"auto_map"\s*:', text) or re.search(r'"trust_remote_code"\s*:\s*true', text, re.I):
                remote_code.append(p.name)
    checks.append(result("model_custom_code", "FINDINGS" if remote_code else "PASS", "HIGH" if remote_code else "INFO", {"files": remote_code}, "Model configuration references custom/remote code" if remote_code else "No configured custom-code indicators found"))
    # Only execute bounded behavioral probes for TrustChain's declarative toy
    # format. Arbitrary model files are never loaded or executed here.
    toy_specs = [p for p in files if p.name.endswith(".tcmodel.json")]
    if toy_specs:
        from .model_backdoor import probe_model
        analyses = [probe_model(p) for p in toy_specs[:10]]
        findings = [item for item in analyses if item.get("flagged_features")]
        errors = [item for item in analyses if item.get("status") == "ERROR"]
        if findings:
            verdict, severity = "FINDINGS", "HIGH"
            message = "Behavioral probes found a single feature causing a high-margin class flip; review as a possible backdoor indicator"
        elif errors and not any(item.get("status") == "ANALYZED" for item in analyses):
            verdict, severity, message = "ERROR", "MEDIUM", "Toy-model behavioral probe could not analyze the supplied specification"
        else:
            verdict, severity = "PASS", "INFO"
            message = "Supported toy-model behavioral probes completed without configured backdoor indicators"
        checks.append(result("model_behavioral_backdoor_probe", verdict, severity,
                             {"models_considered": len(toy_specs[:10]), "analyses": analyses[:10],
                              "method": "single_feature_toggle_high_margin_v1"}, message))
    else:
        checks.append(result("model_behavioral_backdoor_probe", "NOT_CHECKED", "INFO", {},
                             "No supported TrustChain toy-model specification found; arbitrary model code was not executed"))
    return checks


def _agent_checks(path: Path, files: list[Path]) -> list[dict[str, Any]]:
    hits = []
    for p in files:
        if p.suffix.lower() not in {".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".md", ".txt"}:
            continue
        text = _read_text(p)
        if text is None:
            continue
        for label, pattern in SUSPICIOUS_CODE_PATTERNS:
            matches = list(pattern.finditer(text))[:5]
            for m in matches:
                hits.append({"file": p.name, "indicator": label, "line": text.count("\n", 0, m.start()) + 1})
    checks = [result("agent_code_patterns", "FINDINGS" if hits else "PASS", "HIGH" if any(x["indicator"] in {"subprocess_shell", "persistence_path", "obfuscated_payload"} for x in hits) else ("MEDIUM" if hits else "INFO"), hits[:100], "Potentially risky code patterns require review; these are not proof of malware" if hits else "No configured suspicious code patterns found")]
    semgrep = shutil.which("semgrep")
    source_files = [p for p in files if p.suffix.lower() in {".py", ".js", ".ts", ".sh", ".go", ".rs", ".java"}]
    if not source_files:
        checks.append(result("semgrep", "NOT_CHECKED", evidence={}, message="No supported source files available for Semgrep"))
    elif not semgrep:
        checks.append(result("semgrep", "NOT_CHECKED", evidence={}, message="Semgrep executable is not available"))
    else:
        try:
            proc = subprocess.run([semgrep, "scan", "--config", "p/default", "--json", "--quiet", *(str(p) for p in source_files)], capture_output=True, text=True, timeout=120, check=False)
            payload = json.loads(proc.stdout or "{}")
            findings = [{"check_id": x.get("check_id"), "path": Path(x.get("path", "")).name, "line": x.get("start", {}).get("line"), "severity": x.get("extra", {}).get("severity"), "message": x.get("extra", {}).get("message", "")[:200]} for x in payload.get("results", [])]
            if proc.returncode not in {0, 1} and not findings:
                checks.append(result("semgrep", "ERROR", "MEDIUM", {"returncode": proc.returncode, "stderr": (proc.stderr or "")[-1000:]}, "Semgrep did not complete reliably"))
            else:
                checks.append(result("semgrep", "FINDINGS" if findings else "PASS", "HIGH" if any(x.get("severity") == "ERROR" for x in findings) else ("MEDIUM" if findings else "INFO"), findings[:100], f"Semgrep reported {len(findings)} finding(s)" if findings else "Semgrep reported no findings"))
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            checks.append(result("semgrep", "ERROR", "MEDIUM", {"error": str(exc)[:300]}, "Semgrep could not complete"))
    return checks


def _tool_dependency_checks(path: Path, files: list[Path]) -> list[dict[str, Any]]:
    manifests = [p for p in files if p.name.lower() in {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json", "package-lock.json", "pnpm-lock.yaml", "poetry.lock", "uv.lock"}]
    if not manifests:
        return [result("dependency_manifest", "NOT_CHECKED", evidence={}, message="No recognized dependency manifest found")]
    checks = [result("dependency_manifest", "PASS", evidence={"files": [p.name for p in manifests]}, message="Dependency manifest(s) identified")]
    reqs = [p for p in manifests if p.name.lower().startswith("requirements") and p.suffix.lower() == ".txt"]
    exe = shutil.which("pip-audit")
    if reqs and exe:
        all_results = []
        errors = []
        for req in reqs[:5]:
            try:
                proc = subprocess.run([exe, "-r", str(req), "-f", "json"], capture_output=True, text=True, timeout=90, check=False, cwd=str(path if path.is_dir() else path.parent), env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
                try:
                    payload = json.loads(proc.stdout or "{}")
                except json.JSONDecodeError:
                    payload = None
                if payload is None:
                    errors.append({"file": req.name, "returncode": proc.returncode, "stderr": (proc.stderr or "")[-1000:]})
                else:
                    for dep in payload.get("dependencies", []):
                        for vuln in dep.get("vulns", []):
                            all_results.append({"file": req.name, "name": dep.get("name"), "version": dep.get("version"), "id": vuln.get("id"), "fix_versions": vuln.get("fix_versions", [])})
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append({"file": req.name, "error": str(exc)[:300]})
        if all_results:
            checks.append(result("pip_audit", "FINDINGS", "HIGH", all_results[:100], "Known vulnerabilities reported for declared Python dependencies"))
        elif errors:
            checks.append(result("pip_audit", "ERROR", "MEDIUM", errors, "pip-audit could not complete reliably"))
        else:
            checks.append(result("pip_audit", "PASS", "INFO", {"requirements_files_scanned": len(reqs)}, "No vulnerabilities reported by pip-audit for scanned requirements"))
    elif reqs:
        checks.append(result("pip_audit", "NOT_CHECKED", "INFO", {"requirements_files": [p.name for p in reqs]}, "pip-audit executable is not available"))
    else:
        checks.append(result("pip_audit", "NOT_CHECKED", "INFO", {}, "pip-audit adapter currently scans requirements*.txt manifests only"))
    return checks



def _agent_behavior_checks(path: Path, files: list[Path]) -> list[dict[str, Any]]:
    """Evaluate an artifact-supplied trace sidecar as UNTRUSTED evidence; never execute the agent.

    Declared capabilities are NOT read from the trace (the registrant controls it). The allowlist is
    deny-all, so any observed network/write/tool event is a finding, and a self-supplied trace can
    never produce a PASS.
    """
    trace_files = [p for p in files if p.name.lower() in {"trustchain_behavior_trace.json", "agent_behavior_trace.json"}]
    if not trace_files:
        return [result("agent_behavior_trace", "NOT_CHECKED", evidence={}, message="No sandbox behavior trace sidecar supplied; static checks do not observe runtime behavior")]
    from .traces import evaluate_trace
    reports = []
    for trace_path in trace_files[:3]:
        try:
            payload = json.loads(trace_path.read_text(encoding="utf-8"))
            report = evaluate_trace(payload, allowed_network_hosts=set(), allowed_write_prefixes=(), allowed_tools=set())
            report["trace_file"] = trace_path.name
            reports.append(report)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            reports.append({"verdict": "ERROR", "trace_file": trace_path.name, "error": str(exc)[:300], "findings": []})
    bad = [x for x in reports if x.get("verdict") in {"FINDINGS", "ERROR"}]
    if bad:
        verdict, sev = ("ERROR" if any(x.get("verdict") == "ERROR" for x in reports) else "FINDINGS"), "HIGH"
        msg = "Artifact-supplied trace shows network/file/tool activity (declared capabilities are not taken from the artifact) or could not be parsed"
    else:
        verdict, sev = "NOT_CHECKED", "INFO"
        msg = "Trace was supplied by the artifact itself and is untrusted; it cannot establish safe behavior"
    return [result("agent_behavior_trace", verdict, sev, {"reports": reports, "collector_trust": "ARTIFACT_SUPPLIED_UNTRUSTED"}, msg)]


def _tool_contract_checks(files: list[Path]) -> list[dict[str, Any]]:
    manifests = [p for p in files if p.name.lower() in {"tool_manifest.json", "mcp_tools.json", "trustchain_tool_manifest.json"}]
    if not manifests:
        return [result("tool_contract_mismatch", "NOT_CHECKED", evidence={}, message="No TrustChain tool manifest found for declared-vs-description capability checks")]
    from .tool_mismatch import inspect_tool_manifest
    out = []
    for manifest in manifests[:5]:
        report = inspect_tool_manifest(manifest)
        verdict = report.get("verdict", "ERROR")
        out.append(result("tool_contract_mismatch", verdict, "HIGH" if any(f.get("severity") == "HIGH" for f in report.get("findings", [])) else ("MEDIUM" if verdict == "FINDINGS" else "INFO"),
                          {"manifest": manifest.name, "report": report},
                          f"Tool manifest inspection: {verdict}"))
    return out

# ---------------------------------------------------------------------------
# Hardening additions: AST agent analysis, package install scripts, typosquats,
# and fail-closed coverage. Nothing here executes artifact code.
# ---------------------------------------------------------------------------
import ast
import difflib

_AST_BAD_BUILTINS = {"eval", "exec", "compile", "__import__"}
_AST_BAD_DOTTED_PREFIXES = (
    "os.system", "os.popen", "os.exec", "os.spawn", "subprocess.", "socket.socket",
    "socket.create_connection", "urllib.request.urlopen", "urllib.request.urlretrieve",
    "requests.", "httpx.", "http.client.", "ftplib.", "smtplib.", "ctypes.", "pty.spawn",
)
_AST_SENSITIVE_STRINGS = (".ssh", "id_rsa", ".aws/credentials", "/etc/passwd", "/etc/shadow", ".kube/config", ".netrc")


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _ast_scan_python(text: str, fname: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    aliases: dict[str, str] = {}
    hits: list[dict[str, Any]] = []

    def add(node: ast.AST, indicator: str, severity: str = "HIGH") -> None:
        hits.append({"file": fname, "line": getattr(node, "lineno", 0), "indicator": indicator, "severity": severity})

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name:
                head, _, rest = name.partition(".")
                resolved = aliases.get(head, head) + (("." + rest) if rest else "")
                if resolved in _AST_BAD_BUILTINS:
                    add(node, f"dynamic_execution:{resolved}")
                elif any(resolved == p.rstrip(".") or resolved.startswith(p) for p in _AST_BAD_DOTTED_PREFIXES):
                    add(node, f"risky_call:{resolved}")
                elif resolved == "getattr" and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in {"__builtins__", "builtins"}:
                    add(node, "builtins_getattr_evasion")
            elif isinstance(node.func, ast.Call):
                inner = _dotted(node.func.func)
                if inner in _AST_BAD_BUILTINS:
                    add(node, f"dynamic_execution:{inner}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(tok in low for tok in _AST_SENSITIVE_STRINGS):
                add(node, "sensitive_path_reference")
    seen, out = set(), []
    for h in hits:
        key = (h["line"], h["indicator"])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out[:100]


def _agent_ast_checks(files: list[Path]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    parsed = 0
    for p in files:
        if p.suffix.lower() != ".py":
            continue
        text = _read_text(p)
        if text is None:
            continue
        parsed += 1
        hits.extend(_ast_scan_python(text, p.name))
    if not parsed:
        return [result("agent_ast", "NOT_CHECKED", message="No Python source files for AST analysis")]
    return [result("agent_ast", "FINDINGS" if hits else "PASS", "HIGH" if hits else "INFO", hits[:100],
                   "AST analysis found dynamic execution, network/process capability, or sensitive-path access; review required" if hits
                   else "AST analysis found no configured risky calls (does not prove safety)")]


_POPULAR_PACKAGES = {
    "requests", "numpy", "pandas", "scipy", "torch", "tensorflow", "transformers", "flask", "django",
    "urllib3", "boto3", "pydantic", "scikit-learn", "matplotlib", "pillow", "pyyaml", "cryptography",
    "setuptools", "pip", "openai", "langchain", "express", "lodash", "react", "axios", "chalk", "webpack",
}
_INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare"}
_FETCH_RE = re.compile(r"(?:curl|wget|powershell|invoke-webrequest|nc\s|bash\s+-c|sh\s+-c|\|\s*sh|node\s+-e|base64)", re.I)


def _package_checks(files: list[Path]) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    names: list[tuple[str, str]] = []
    for p in files:
        low = p.name.lower()
        if low == "package.json":
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(obj, dict):
                continue
            for hook, cmd in (obj.get("scripts") or {}).items() if isinstance(obj.get("scripts"), dict) else []:
                if hook in _INSTALL_HOOKS:
                    scripts.append({"file": p.name, "hook": hook, "command": str(cmd)[:200], "fetches_or_obfuscates": bool(_FETCH_RE.search(str(cmd)))})
            for sect in ("dependencies", "devDependencies"):
                if isinstance(obj.get(sect), dict):
                    names.extend((str(n).lower(), p.name) for n in obj[sect])
        elif low.startswith("requirements") and low.endswith(".txt"):
            text = _read_text(p) or ""
            for line in text.splitlines():
                m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if m and not line.strip().startswith(("#", "-")):
                    names.append((m.group(1).lower().replace("_", "-"), p.name))
        elif low == "setup.py":
            text = _read_text(p) or ""
            if re.search(r"cmdclass|os\.system|subprocess|urlopen|requests\.", text):
                scripts.append({"file": p.name, "hook": "setup.py", "command": "custom install logic", "fetches_or_obfuscates": True})
    typos = []
    for name, src in names:
        if name in _POPULAR_PACKAGES:
            continue
        close = difflib.get_close_matches(name, _POPULAR_PACKAGES, n=1, cutoff=0.84)
        if close:
            typos.append({"file": src, "package": name, "resembles": close[0]})
    out = [result("install_scripts", "FINDINGS" if scripts else "PASS",
                  "HIGH" if any(s["fetches_or_obfuscates"] for s in scripts) else ("MEDIUM" if scripts else "INFO"), scripts,
                  "Install-time scripts present; they run code on install" if scripts else "No install-time scripts detected"),
           result("typosquat_check", "FINDINGS" if typos else "PASS", "HIGH" if typos else "INFO", typos,
                  "Dependency names closely resemble popular packages (possible typosquat)" if typos else "No near-miss of popular package names")]
    return out


_KNOWN_TYPES = {"dataset", "data", "model", "ai agent", "agent", "tool / dependency", "tool", "dependency"}
# At least one of these must actually run (PASS/FINDINGS) or the artifact is not considered covered.
_SUBSTANTIVE = {
    "dataset": {"dataset_poisoning_heuristic", "dataset_csv_safety"},
    "model": {"picklescan", "model_weight_format"},
    "agent": {"agent_code_patterns", "agent_ast"},
    "tool": {"pip_audit", "tool_contract_mismatch", "install_scripts", "typosquat_check"},
}


def run_prechecks(path: str | Path, artifact_type: str, *, model_scan: dict[str, Any] | None = None, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run common and type-specific non-executing checks on a candidate artifact."""
    target = Path(path).resolve()
    files, structural = _files(target)
    checks: list[dict[str, Any]] = list(structural)
    if files:
        checks.extend(_static_structure(target, files))
        checks.extend(_text_checks(files))
        kind = artifact_type.strip().lower()
        if kind == "dataset":
            checks.extend(_dataset_checks(files))
            checks.extend(_dataset_quality_checks(files))
            checks.extend(_dataset_poisoning_checks(files))
        elif kind == "model":
            checks.extend(_model_checks(target, files, model_scan, policy))
        elif kind in {"ai agent", "agent"}:
            checks.extend(_agent_checks(target, files))
            checks.extend(_agent_ast_checks(files))
            checks.extend(_agent_behavior_checks(target, files))
        elif kind in {"tool / dependency", "tool", "dependency"}:
            checks.extend(_tool_dependency_checks(target, files))
            checks.extend(_package_checks(files))
            checks.extend(_tool_contract_checks(files))
        if kind not in _KNOWN_TYPES:
            checks.append(result("unsupported_artifact_type", "FINDINGS", "HIGH", {"artifact_type": artifact_type},
                                 "Unrecognized artifact type: no type-specific checks ran, so it cannot be cleared"))
        else:
            family = ("dataset" if kind in {"dataset", "data"} else "model" if kind == "model"
                      else "agent" if kind in {"ai agent", "agent"} else "tool")
            ran = [c for c in checks if c["check"] in _SUBSTANTIVE[family] and c["verdict"] in {"PASS", "FINDINGS", "ERROR"}]
            if not ran and (policy or {}).get("require_type_coverage", False):
                checks.append(result("type_specific_coverage", "FINDINGS", "HIGH", {"family": family, "expected_any_of": sorted(_SUBSTANTIVE[family])},
                                     "No substantive type-specific check could run on these files (unsupported format?); not cleared"))
    else:
        checks.append(result("artifact_inventory", "ERROR", "HIGH", message="No files were available to inspect", hard_block=True))
    counts = {v: sum(1 for c in checks if c["verdict"] == v) for v in ("PASS", "FINDINGS", "NOT_CHECKED", "ERROR")}
    hard_blocks = [c["check"] for c in checks if c.get("hard_block")]
    return {"framework_version": "1.0", "artifact_type": artifact_type, "checks": checks, "counts": counts, "hard_block_checks": hard_blocks}


def policy_disposition(prechecks: dict[str, Any], policy: dict[str, Any]) -> tuple[str | None, list[str]]:
    """Map scanner evidence to a policy disposition; None means no disposition override."""
    checks = prechecks.get("checks", [])
    reasons = []
    hard = [c for c in checks if c.get("hard_block")]
    if hard:
        reasons.extend(f"Hard pre-check failure: {c['check']} — {c.get('message', 'blocking finding')}" for c in hard)
        return "BLOCK", reasons
    findings = [c for c in checks if c["verdict"] == "FINDINGS"]
    errors = [c for c in checks if c["verdict"] == "ERROR"]
    high = [c for c in findings if c.get("severity") in {"HIGH", "CRITICAL"}]
    if high:
        reasons.extend(f"High-severity pre-check finding: {c['check']}" for c in high)
        return policy.get("high_severity_finding", "QUARANTINE"), reasons
    if findings or errors:
        reasons.extend(f"Pre-check requires review: {c['check']} ({c['verdict']})" for c in findings + errors)
        return policy.get("precheck_finding", "QUARANTINE"), reasons
    return None, ["No configured pre-check findings or scanner errors were reported."]
