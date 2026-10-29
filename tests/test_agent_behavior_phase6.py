from pathlib import Path
from trustchain.traces import evaluate_trace
from trustchain.prechecks import run_prechecks

ROOT = Path(__file__).parents[1]
FIX = ROOT / 'fixtures' / 'agent_behavior'

def test_allowed_behavior_trace_passes():
    import json
    payload = json.loads((FIX / 'trustchain_behavior_trace.json').read_text())
    report = evaluate_trace(payload,
        allowed_network_hosts=set(payload['declared_capabilities']['network_hosts']),
        allowed_write_prefixes=tuple(payload['declared_capabilities']['write_paths']),
        allowed_tools=set(payload['declared_capabilities']['tools']))
    assert report['verdict'] == 'PASS'
    assert not report['findings']

def test_undeclared_actions_are_detected():
    import json
    payload = json.loads((FIX / 'agent_behavior_trace.json').read_text())
    report = evaluate_trace(payload,
        allowed_network_hosts=set(payload['declared_capabilities']['network_hosts']),
        allowed_write_prefixes=tuple(payload['declared_capabilities']['write_paths']),
        allowed_tools=set(payload['declared_capabilities']['tools']))
    assert report['verdict'] == 'FINDINGS'
    assert {x['kind'] for x in report['findings']} == {'unexpected_network', 'unexpected_file_write', 'unexpected_tool'}

def test_registration_marks_missing_trace_not_checked(tmp_path):
    p = tmp_path / 'agent.py'
    p.write_text('def f(): return 1')
    report = run_prechecks(p, 'AI Agent')
    check = next(x for x in report['checks'] if x['check'] == 'agent_behavior_trace')
    assert check['verdict'] == 'NOT_CHECKED'

def test_registration_ingests_trace_sidecar(tmp_path):
    (tmp_path / 'agent.py').write_text('def f(): return 1')
    (tmp_path / 'agent_behavior_trace.json').write_text((FIX / 'agent_behavior_trace.json').read_text())
    report = run_prechecks(tmp_path, 'AI Agent')
    check = next(x for x in report['checks'] if x['check'] == 'agent_behavior_trace')
    assert check['verdict'] == 'FINDINGS'
