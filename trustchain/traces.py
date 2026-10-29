"""Normalize and evaluate agent behavior traces without executing agents.

This is a vendor-neutral evidence adapter. It accepts TrustChain's documented
JSON trace shape; it does not claim to parse every NeMo Relay/ATIF/ATOF version.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_trace(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load a trace object or JSON file; reject malformed/unsupported structures."""
    if isinstance(source, dict):
        payload = source
    else:
        try:
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read trace JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Trace must be a JSON object")
    events = payload.get("events")
    if not isinstance(events, list):
        raise ValueError("Trace must contain an events list")
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Trace event {index} must be an object")
        if not isinstance(event.get("action"), str) or not event["action"].strip():
            raise ValueError(f"Trace event {index} is missing a string action")
    return payload


def evaluate_trace(
    source: str | Path | dict[str, Any],
    *,
    allowed_network_hosts: set[str] | None = None,
    allowed_write_prefixes: tuple[str, ...] = (),
    allowed_tools: set[str] | None = None,
) -> dict[str, Any]:
    """Compare observed event claims against a declared capability allowlist.

    Event schema: {"action": "network|file_write|tool_call|other",
    optional "host", "path", "tool", "detail"}. This evaluates trace records,
    not OS-level behavior; trust only traces collected by a trusted monitor.
    """
    trace = load_trace(source)
    allowed_hosts = allowed_network_hosts or set()
    allowed_tools_set = allowed_tools or set()
    findings: list[dict[str, Any]] = []
    checked = 0

    for index, event in enumerate(trace["events"]):
        action = event["action"].lower()
        if action in {"network", "network_connect", "http_request"}:
            checked += 1
            host = str(event.get("host", "")).lower().rstrip(".")
            if not host or host not in {h.lower().rstrip(".") for h in allowed_hosts}:
                findings.append({"event_index": index, "kind": "unexpected_network",
                                 "host": host or None, "severity": "HIGH"})
        elif action in {"file_write", "filesystem_write"}:
            checked += 1
            path = str(event.get("path", ""))
            # Prefix checks require exact directory boundary, not /allowed-evil.
            permitted = any(
                path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")
                for prefix in allowed_write_prefixes if prefix
            )
            if not path or not permitted:
                findings.append({"event_index": index, "kind": "unexpected_file_write",
                                 "path": path or None, "severity": "HIGH"})
        elif action in {"tool_call", "tool"}:
            checked += 1
            tool = str(event.get("tool", ""))
            if not tool or tool not in allowed_tools_set:
                findings.append({"event_index": index, "kind": "unexpected_tool",
                                 "tool": tool or None, "severity": "MEDIUM"})

    return {
        "schema": "trustchain.behavior-trace.v1",
        "trace_id": str(trace.get("trace_id", "")) or None,
        "artifact_digest": str(trace.get("artifact_digest", "")) or None,
        "events_total": len(trace["events"]),
        "events_checked": checked,
        "verdict": "FINDINGS" if findings else ("PASS" if checked else "NOT_CHECKED"),
        "findings": findings,
        "limitations": [
            "Evaluates supplied trace records only; it does not observe the operating system.",
            "A PASS means no disallowed action was represented in this trace, not that the agent is safe.",
            "Bind this report to a verified artifact digest and a trusted trace collector before policy use.",
        ],
    }
