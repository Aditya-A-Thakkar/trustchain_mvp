"""Safe behavioral probing for TrustChain's tiny declarative toy-model format.

This module never imports or executes model code. It parses a bounded JSON
linear-classifier specification and probes feature toggles. This is a controlled
MVP experiment, not a general neural-network backdoor detector.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

FORMAT = "trustchain-toy-linear-v1"
MAX_BYTES = 256 * 1024
MAX_FEATURES = 128
MAX_CLASSES = 16


def load_toy_model(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError("model_spec_too_large")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("unsupported_model_spec_format")
    features, classes, weights = data.get("features"), data.get("classes"), data.get("weights")
    if not isinstance(features, list) or not 1 <= len(features) <= MAX_FEATURES or not all(isinstance(x, str) and x for x in features):
        raise ValueError("invalid_features")
    if not isinstance(classes, list) or not 2 <= len(classes) <= MAX_CLASSES or not all(isinstance(x, str) and x for x in classes):
        raise ValueError("invalid_classes")
    if not isinstance(weights, dict) or set(weights) != set(classes):
        raise ValueError("invalid_weights")
    bias = data.get("bias", {})
    if not isinstance(bias, dict):
        raise ValueError("invalid_bias")
    for cls in classes:
        if not isinstance(weights[cls], dict):
            raise ValueError("invalid_class_weights")
        for feature, value in weights[cls].items():
            if feature not in features or not isinstance(value, (int, float)) or not math.isfinite(value) or abs(value) > 1e6:
                raise ValueError("invalid_weight_value")
        value = bias.get(cls, 0.0)
        if not isinstance(value, (int, float)) or not math.isfinite(value) or abs(value) > 1e6:
            raise ValueError("invalid_bias_value")
    return data


def predict(model: dict[str, Any], active_features: set[str]) -> tuple[str, dict[str, float]]:
    scores = {}
    for cls in model["classes"]:
        score = float(model.get("bias", {}).get(cls, 0.0))
        for feature in active_features:
            score += float(model["weights"][cls].get(feature, 0.0))
        scores[cls] = score
    # Stable tie-break based on declared class order.
    winner = max(model["classes"], key=lambda cls: scores[cls])
    return winner, scores


def probe_model(path: str | Path) -> dict[str, Any]:
    """Toggle each feature in isolation and flag unusually dominant class flips."""
    try:
        model = load_toy_model(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {"status": "ERROR", "reason": str(exc)[:160], "file": Path(path).name,
                "flagged_features": [], "probes": []}
    baseline_class, baseline_scores = predict(model, set())
    probes = []
    flagged = []
    for feature in model["features"]:
        predicted, scores = predict(model, {feature})
        margin = scores[predicted] - max((score for cls, score in scores.items() if cls != predicted), default=0.0)
        baseline_margin = baseline_scores[baseline_class] - max((score for cls, score in baseline_scores.items() if cls != baseline_class), default=0.0)
        changed = predicted != baseline_class
        row = {"feature": feature, "baseline_class": baseline_class, "triggered_class": predicted,
               "class_changed": changed, "margin": round(margin, 4),
               "baseline_margin": round(baseline_margin, 4)}
        probes.append(row)
        # In this deliberately constrained model, a single feature that flips
        # the class with a very large margin is a strong behavioral indicator.
        if changed and margin >= 5.0 and margin >= baseline_margin + 4.0:
            flagged.append({**row, "reason": "single_feature_causes_high_margin_class_flip"})
    return {"status": "ANALYZED", "file": Path(path).name, "format": FORMAT,
            "baseline_class": baseline_class, "probes_run": len(probes), "probes": probes,
            "flagged_features": flagged,
            "limitations": ["Only the TrustChain declarative toy linear model format is supported.",
                            "Single-feature probing can miss multi-feature, input-dependent, or low-margin backdoors.",
                            "A suspicious response is a behavioral indicator, not proof of malicious training."]}


def evaluate_backdoor_detection(clean_correct: int, clean_total: int,
                                trigger_target_hits: int, trigger_total: int) -> dict[str, Any]:
    return {"clean_accuracy": round(clean_correct / clean_total, 4) if clean_total else 0.0,
            "attack_success_rate": round(trigger_target_hits / trigger_total, 4) if trigger_total else 0.0,
            "clean_examples": clean_total, "trigger_examples": trigger_total,
            "target_hits_on_triggered_examples": trigger_target_hits}
