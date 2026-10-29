"""Bounded, non-executing heuristics for suspicious feature/label associations.

This is a screening detector, not a general proof of dataset poisoning. It only
runs on readable CSV/TSV tables with a recognizable target/label column. The
output includes row numbers so it can be compared with controlled ground truth.
"""
from __future__ import annotations

import csv
import io
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

LABEL_RE = re.compile(r"(^|[_\- ])(label|target|class|rank|ranking|outcome)([_\- ]|$)", re.I)
ID_RE = re.compile(r"(^|[_\- ])(id|uuid|index)([_\- ]|$)", re.I)
MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 5000
MIN_SUPPORT = 3
MAX_TRIGGER_RATE = 0.20
MIN_PURITY = 0.90
MIN_LIFT = 1.8


def _entropy(values: list[str]) -> float:
    counts = Counter(values)
    total = len(values)
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.0


def analyze_table(path: str | Path) -> dict[str, Any]:
    """Return row-level suspicious associations for one CSV/TSV file."""
    p = Path(path)
    if p.suffix.lower() not in {".csv", ".tsv"} or not p.is_file() or p.stat().st_size > MAX_BYTES:
        return {"status": "NOT_CHECKED", "reason": "unsupported_or_oversized_table", "file": p.name, "flagged_rows": [], "signals": []}
    try:
        text = p.read_text(encoding="utf-8-sig")
        rows = list(csv.reader(io.StringIO(text), delimiter="\t" if p.suffix.lower() == ".tsv" else ","))[: MAX_ROWS + 1]
    except (OSError, UnicodeError, csv.Error) as exc:
        return {"status": "ERROR", "reason": "table_parse_error", "detail": str(exc)[:200], "file": p.name, "flagged_rows": [], "signals": []}
    if len(rows) < 5 or not rows[0]:
        return {"status": "NOT_CHECKED", "reason": "insufficient_rows", "file": p.name, "row_count": max(0, len(rows)-1), "flagged_rows": [], "signals": []}
    header = [x.strip() for x in rows[0]]
    width = len(header)
    data = [(i + 2, row) for i, row in enumerate(rows[1:]) if len(row) == width]
    label_indices = [i for i, name in enumerate(header) if LABEL_RE.search(name)]
    if not label_indices:
        return {"status": "NOT_CHECKED", "reason": "no_recognizable_target_column", "file": p.name, "row_count": len(data), "flagged_rows": [], "signals": []}
    label_idx = label_indices[0]
    target_rows = [(line, row) for line, row in data if row[label_idx].strip()]
    labels = [row[label_idx].strip() for _, row in target_rows]
    if len(target_rows) < 10 or len(set(labels)) < 2:
        return {"status": "NOT_CHECKED", "reason": "insufficient_target_diversity", "file": p.name, "row_count": len(data), "flagged_rows": [], "signals": []}

    label_counts = Counter(labels)
    baseline_label, baseline_count = label_counts.most_common(1)[0]
    baseline_rate = baseline_count / len(labels)
    signals: list[dict[str, Any]] = []
    flagged: set[int] = set()
    feature_columns = []
    for idx, name in enumerate(header):
        if idx == label_idx or ID_RE.search(name) or not name:
            continue
        values = [row[idx].strip() for _, row in target_rows]
        # Candidate feature columns must have repeated values but not be nearly unique IDs.
        counts = Counter(values)
        distinct_rate = len(counts) / max(1, len(values))
        if distinct_rate > 0.8:
            continue
        feature_columns.append((idx, name, values, counts))

    for idx, name, values, counts in feature_columns:
        grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for (line, row), value in zip(target_rows, values):
            if value:
                grouped[value].append((line, row[label_idx].strip()))
        for value, group in grouped.items():
            support = len(group)
            rate = support / len(target_rows)
            if support < MIN_SUPPORT or rate > MAX_TRIGGER_RATE:
                continue
            group_counts = Counter(label for _, label in group)
            dominant_label, dominant_count = group_counts.most_common(1)[0]
            purity = dominant_count / support
            global_rate = label_counts[dominant_label] / len(target_rows)
            lift = purity / max(global_rate, 1e-9)
            # Require a rare repeated value and a strong association with a target class.
            if purity >= MIN_PURITY and lift >= MIN_LIFT and baseline_rate < 0.95:
                row_numbers = [line for line, label in group if label == dominant_label]
                flagged.update(row_numbers)
                signals.append({
                    "feature": name[:80], "value": value[:100], "target_column": header[label_idx][:80],
                    "associated_target": dominant_label[:100], "support": support,
                    "feature_rate": round(rate, 4), "target_purity": round(purity, 4),
                    "target_base_rate": round(global_rate, 4), "lift": round(lift, 3),
                    "csv_rows": row_numbers[:100],
                    "reason": "rare_feature_value_strongly_associated_with_target",
                })
    return {
        "status": "ANALYZED", "file": p.name, "row_count": len(data),
        "target_column": header[label_idx][:80], "target_classes": len(label_counts),
        "target_distribution": dict(label_counts.most_common(20)),
        "target_entropy_bits": round(_entropy(labels), 4),
        "baseline_target_rate": round(baseline_rate, 4),
        "signals": sorted(signals, key=lambda s: (-s["lift"], -s["support"]))[:100],
        "flagged_rows": sorted(flagged)[:500],
        "limitations": [
            "Heuristic detects repeated rare feature values strongly associated with a target column; other poisoning strategies may evade it.",
            "Association is not proof of malicious intent; legitimate rare subgroups can be flagged.",
            "Only the first recognizable target column and bounded CSV/TSV rows are analyzed.",
        ],
    }


def evaluate_row_detection(predicted: set[int], actual: set[int]) -> dict[str, Any]:
    """Calculate row-level precision/recall/F1 for 1-based CSV line numbers."""
    tp = len(predicted & actual)
    fp = len(predicted - actual)
    fn = len(actual - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "false_positive_rate_over_unpoisoned_rows": round(fp / max(1, fp + len(actual) - tp), 4)}
