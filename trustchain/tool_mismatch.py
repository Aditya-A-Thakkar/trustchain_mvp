"""Static tool-contract and dependency-integrity checks; never imports tool code."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from typing import Any

RISK_TERMS = {
    'network': re.compile(r'\b(?:http|https|network|socket|fetch|request)\b', re.I),
    'filesystem_write': re.compile(r'\b(?:write|delete|remove|overwrite|filesystem|file system)\b', re.I),
    'shell': re.compile(r'\b(?:shell|subprocess|command execution|terminal|exec)\b', re.I),
    'credentials': re.compile(r'\b(?:credential|secret|token|api key|password)\b', re.I),
}


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inspect_tool_manifest(path: str | Path) -> dict[str, Any]:
    """Inspect a TrustChain JSON tool manifest with description and permission declarations.

    Expected schema: {tools:[{name,description,permissions,command?,package?,version?,sha256?}]}.
    This is a conservative mismatch heuristic, not semantic proof.
    """
    p = Path(path)
    try:
        obj = json.loads(p.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {'check': 'tool_contract_mismatch', 'verdict': 'ERROR', 'findings': [], 'error': str(exc)[:300]}
    tools = obj.get('tools') if isinstance(obj, dict) else None
    if not isinstance(tools, list):
        return {'check': 'tool_contract_mismatch', 'verdict': 'NOT_CHECKED', 'findings': [], 'reason': 'manifest_missing_tools_array'}
    findings = []
    checked = 0
    for i, tool in enumerate(tools):
        if not isinstance(tool, dict):
            findings.append({'tool_index': i, 'kind': 'invalid_tool_entry', 'severity': 'MEDIUM'})
            continue
        name = str(tool.get('name', f'index-{i}'))
        desc = str(tool.get('description', ''))
        perms = tool.get('permissions', [])
        if isinstance(perms, dict):
            declared = {str(k).lower() for k, v in perms.items() if v}
        elif isinstance(perms, list):
            declared = {str(x).lower() for x in perms}
        else:
            declared = set()
        text = desc + ' ' + str(tool.get('command', ''))
        inferred = {cap for cap, pat in RISK_TERMS.items() if pat.search(text)}
        checked += 1
        aliases = {
            'network': {'network', 'network_access', 'http'},
            'filesystem_write': {'filesystem_write', 'file_write', 'filesystem', 'write'},
            'shell': {'shell', 'execute_code', 'command_execution'},
            'credentials': {'credentials', 'secrets', 'secret_access'},
        }
        undeclared = sorted(cap for cap in inferred if not (declared & aliases[cap]))
        if undeclared:
            findings.append({'tool': name, 'kind': 'description_or_command_implies_undeclared_capability',
                             'capabilities': undeclared, 'severity': 'MEDIUM',
                             'evidence': 'Keyword heuristic over description/command; review required'})
        claimed_hash = str(tool.get('sha256', '')).lower()
        local_path = tool.get('path')
        if local_path:
            artifact = (p.parent / str(local_path)).resolve()
            if not artifact.is_file():
                findings.append({'tool': name, 'kind': 'pinned_artifact_missing', 'severity': 'HIGH', 'path': str(local_path)})
            elif claimed_hash:
                actual = _digest(artifact)
                if actual != claimed_hash:
                    findings.append({'tool': name, 'kind': 'sha256_mismatch', 'severity': 'HIGH',
                                     'expected_sha256': claimed_hash, 'actual_sha256': actual, 'path': str(local_path)})
        elif claimed_hash:
            findings.append({'tool': name, 'kind': 'hash_claim_without_local_artifact', 'severity': 'LOW',
                             'sha256': claimed_hash})
        if tool.get('version') and not re.search(r'^[vV]?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$', str(tool['version'])):
            findings.append({'tool': name, 'kind': 'version_not_exactly_pinned', 'severity': 'LOW', 'version': str(tool['version'])[:80]})
    return {'schema': 'trustchain.tool-contract.v1', 'check': 'tool_contract_mismatch',
            'tools_checked': checked, 'verdict': 'FINDINGS' if findings else ('PASS' if checked else 'NOT_CHECKED'),
            'findings': findings[:200], 'limitations': [
                'Capability inference is keyword-based and may produce false positives or miss obfuscated behavior.',
                'Static manifest inspection does not execute tools or verify remote package provenance.',
                'A declared hash is meaningful only when bound to the exact artifact and trusted source.'
            ]}
