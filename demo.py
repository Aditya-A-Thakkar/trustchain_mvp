"""Run three deterministic TrustChain demos using harmless temporary fixtures."""
from pathlib import Path
import json, tempfile
from trustchain.core import TrustChainStore, load_policy
from trustchain.analyst import analyze

ROOT=Path(__file__).parent
policy=load_policy(ROOT/'policy.yaml')
advisory=json.loads((ROOT/'fixtures'/'scanner_advisory_demo.json').read_text())

def show(title, obj):
    print('\n'+'='*72+'\n'+title+'\n'+'='*72)
    print(json.dumps(obj,indent=2,sort_keys=True))

with tempfile.TemporaryDirectory() as td:
    root=Path(td); store=TrustChainStore(root/'trustchain.db')
    # A: approve then replace a benign file.
    # A: scan a benign pickle, approve it, then verify replacement is blocked.
    import pickle
    a = root / 'model'
    a.mkdir()
    with (a / 'benign.pkl').open('wb') as f:
        pickle.dump(
            {'name': 'TrustChain benign test', 'weights': [0.1, 0.2, 0.3]},
            f,
        )
    r = store.register('demo-swap', a, policy, unsigned=True, source_uri='demo://swap', transformation='initial import')
    # Simulate replacement after approval.
    with (a / 'benign.pkl').open('wb') as f:
        pickle.dump(
            {'name': 'TrustChain replacement test', 'weights': [9.9, 8.8, 7.7]},
            f,
        )
    load=store.load('demo-swap','agent-demo',policy)
    show('DEMO A — replacement after approval is blocked',{'registration_decision':r['decision'],'load_result':load})
    # B: advisory fixture downgrades trust; deliberately synthetic, not a real CVE.
    b=root/'clean-model'; b.mkdir(); (b/'weights.txt').write_text('benign model fixture')
    r=store.register('demo-scanner',b,policy,unsigned=True,scanner_name='demo-scanner',scanner_version='0.0.10',advisory=advisory,source_uri='demo://scanner',transformation='initial import')
    show('DEMO B — synthetic affected-version fixture changes policy decision',{'decision':r['decision'],'advisory_evidence':r['evidence']['scanner_advisory'],'reasons':r['reasons']})
    # C: script inventory review flag despite a matching aggregate digest.
    c=root/'repo'; c.mkdir(); (c/'weights.txt').write_text('benign model fixture'); (c/'loader.py').write_text('# harmless script fixture; never executed')
    r=store.register('demo-loader-review',c,policy,unsigned=True,source_uri='demo://loader',transformation='initial import')
    show('DEMO C — suspicious file type is flagged for review, not labelled malware',{'decision':r['decision'],'review_flags':r['evidence']['review_flags'],'digest':r['digest']})
    evidence = r['evidence']

    show(
        'RULES-ONLY ANALYST — evidence-based triage',
        analyze(evidence, use_ai=False),
    )

    show(
        'NEMOTRON AI ANALYST — evidence-based triage',
        analyze(evidence, use_ai=True),
    )
    show('AUDIT CHAIN',{'valid':store.verify_audit_chain(),'events':[{'event':x['event'],'payload':json.loads(x['payload_json'])} for x in store.audit()]})
