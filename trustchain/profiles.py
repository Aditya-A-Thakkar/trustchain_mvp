"""Conservative default capability profiles inferred from artifact type.

These are registration-time expectations, not measurements of runtime permissions.
Observed behavior still requires a sandbox/trace check.
"""
from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "dataset": {
        "profile_name": "passive_data",
        "expected_capabilities": ["read structured records", "provide data to an explicitly authorized consumer"],
        "default_permissions": {"execute_code": False, "network_access": False, "filesystem_write": False, "invoke_tools": False},
        "risk_note": "Treat as data; embedded text may still influence downstream AI systems.",
    },
    "model": {
        "profile_name": "model_inference",
        "expected_capabilities": ["load model weights", "perform inference when explicitly invoked"],
        "default_permissions": {"execute_custom_code": False, "network_access": False, "filesystem_write": False, "invoke_tools": False},
        "risk_note": "Custom model code and loader behavior require separate review; this profile does not prove safe loading.",
    },
    "ai agent": {
        "profile_name": "agent_runtime",
        "expected_capabilities": ["process instructions and context", "possibly invoke tools declared by its host"],
        "default_permissions": {"network_access": "deny_by_default", "filesystem_write": "deny_by_default", "invoke_tools": "explicit_allowlist_only", "secrets_access": "explicit_allowlist_only"},
        "risk_note": "Capabilities must be constrained by the host runtime and verified dynamically; artifact type alone cannot reveal actual permissions.",
    },
    "tool / dependency": {
        "profile_name": "tool_or_dependency",
        "expected_capabilities": ["provide a library, executable, or tool interface when installed or invoked"],
        "default_permissions": {"install_time_code_execution": "review_required", "network_access": "deny_by_default", "filesystem_write": "deny_by_default", "invoke_tools": False},
        "risk_note": "Package metadata cannot prove install-time or runtime behavior; use dependency and sandbox checks where available.",
    },
}


def inferred_profile(artifact_type: str) -> dict[str, Any]:
    key = artifact_type.strip().lower()
    if key == "agent":
        key = "ai agent"
    elif key in {"tool", "dependency"}:
        key = "tool / dependency"
    profile = PROFILES.get(key, PROFILES["model"])
    return {"artifact_type": artifact_type, **profile, "basis": "inferred_from_artifact_type", "runtime_verified": False}
