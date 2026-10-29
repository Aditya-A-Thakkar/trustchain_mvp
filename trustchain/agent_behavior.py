"""Evidence adapter for declared-vs-observed agent behavior.

Consumes JSON traces produced by a trusted sandbox/monitor. It never executes
an agent and does not claim to collect OS-level telemetry itself.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any
from .traces import evaluate_trace


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def evaluate_agent_bundle(bundle_path: str | Path, trace_path: str | Path,
                          *, allowed_network_hosts: set[str] | None = None,
                          allowed_write_prefixes: tuple[str, ...] = (),
                          allowed_tools: set[str] | None = None,
                          expected_digest: str | None = None) -> dict[str, Any]:
    bundle = Path(bundle_path)
    digest = sha256_file(bundle) if bundle.is_file() else None
    trace = json.loads(Path(trace_path).read_text(encoding='utf-8'))
    report = evaluate_trace(trace, allowed_network_hosts=allowed_network_hosts,
                            allowed_write_prefixes=allowed_write_prefixes,
                            allowed_tools=allowed_tools)
    trace_digest = report.get('artifact_digest')
    mismatch = bool(expected_digest and digest and expected_digest != digest)
    unbound = not trace_digest or (digest is not None and trace_digest != digest)
    if mismatch or unbound:
        report['verdict'] = 'FINDINGS' if report['verdict'] != 'ERROR' else 'ERROR'
        report['findings'].append({
            'kind': 'trace_artifact_digest_mismatch' if mismatch or (trace_digest and digest and trace_digest != digest) else 'trace_not_bound_to_artifact',
            'severity': 'HIGH', 'expected_digest': expected_digest or digest,
            'trace_digest': trace_digest,
        })
    report.update({
        'check': 'agent_behavior_trace', 'artifact_digest_computed': digest,
        'expected_digest': expected_digest, 'trace_bound_to_artifact': bool(digest and trace_digest == digest),
        'collector_trust': 'UNVERIFIED_INPUT_TRACE',
        'limitations': report.get('limitations', []) + [
            'A JSON trace is only trustworthy if produced by an independently trusted sandbox monitor.',
            'This adapter does not itself sandbox, execute, or monitor an agent.'
        ]
    })
    return report
