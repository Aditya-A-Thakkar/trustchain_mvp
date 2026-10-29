from pathlib import Path
from trustchain.tool_mismatch import inspect_tool_manifest
from trustchain.prechecks import run_prechecks

ROOT = Path(__file__).parents[1]
FIX = ROOT / 'fixtures' / 'tool_mismatch'

def test_tool_description_implied_capability_mismatch():
    report = inspect_tool_manifest(FIX / 'tool_manifest.json')
    assert report['verdict'] == 'FINDINGS'
    assert any('network' in f.get('capabilities', []) for f in report['findings'])
    assert any(f.get('kind') == 'version_not_exactly_pinned' for f in report['findings'])

def test_clean_tool_manifest_passes():
    report = inspect_tool_manifest(FIX / 'tool_manifest_clean.json')
    assert report['verdict'] == 'PASS'

def test_registration_integrates_tool_contract_check(tmp_path):
    (tmp_path / 'tool_manifest.json').write_text((FIX / 'tool_manifest.json').read_text())
    report = run_prechecks(tmp_path, 'Tool / Dependency')
    check = next(x for x in report['checks'] if x['check'] == 'tool_contract_mismatch')
    assert check['verdict'] == 'FINDINGS'

def test_missing_manifest_is_not_checked(tmp_path):
    (tmp_path / 'requirements.txt').write_text('requests==2.32.0\n')
    report = run_prechecks(tmp_path, 'Tool / Dependency')
    check = next(x for x in report['checks'] if x['check'] == 'tool_contract_mismatch')
    assert check['verdict'] == 'NOT_CHECKED'
