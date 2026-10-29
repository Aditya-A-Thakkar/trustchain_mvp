import tempfile, unittest
from pathlib import Path
from trustchain.core import TrustChainStore, default_policy, decide, version_in_range
from unittest.mock import patch

class TrustChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.art=self.root/'artifact'; self.art.mkdir(); (self.art/'weights.txt').write_text('safe demo weights')
        self.store=TrustChainStore(self.root/'db.sqlite')
        self.policy=default_policy()
    def tearDown(self): self.tmp.cleanup()
    def test_admit_and_load_when_signature_status_is_explicitly_verified(self):
        r = self.register_verified("m1")
        self.assertEqual(r['decision'],'ADMIT')
        loaded=self.store.load('m1','agent-a',self.policy)
        self.assertEqual(loaded['decision'],'ADMIT')
    def test_replacement_blocked_at_load(self):
        self.store.register('m1',self.art,self.policy,unsigned=False, source_uri="test://trusted-fixture", transformation="test fixture import")
        (self.art/'weights.txt').write_text('changed after approval')
        self.assertEqual(self.store.load('m1','agent-a',self.policy)['decision'],'BLOCK')
    def test_script_review_flag_quarantines(self):
        (self.art/'loader.py').write_text('# harmless demo script')
        r=self.store.register('m1',self.art,self.policy,unsigned=False, source_uri="test://trusted-fixture", transformation="test fixture import")
        self.assertEqual(r['decision'],'QUARANTINE')
    def test_advisory_changes_decision(self):
        evidence={'scanner_affected':True}
        self.assertEqual(decide(evidence,self.policy)[0],'QUARANTINE')
    def test_revoke_and_affected_agents(self):
        self.register_verified("m1")
        self.store.load('m1','agent-a',self.policy)
        self.assertEqual(self.store.revoke('m1'),['agent-a'])
        self.assertEqual(self.store.load('m1','agent-a',self.policy)['decision'],'BLOCK')
    def test_audit_chain_valid(self):
        self.store.register('m1',self.art,self.policy,unsigned=False, source_uri="test://trusted-fixture", transformation="test fixture import")
        self.store.load('m1','agent-a',self.policy)
        self.assertTrue(self.store.verify_audit_chain())
    def test_version_range(self):
        self.assertTrue(version_in_range('0.0.10','0.0.0','0.0.30'))
        self.assertFalse(version_in_range('0.0.30','0.0.0','0.0.30'))
    def test_unsigned_false_does_not_bypass_signature_verification(self):
        result = self.store.register(
            "unsigned-model",
            self.art,
            self.policy,
            unsigned=False,
            source_uri="test://unsigned-fixture",
            transformation="test fixture import",
        )
        self.assertTrue(result["evidence"]["unsigned"])
        self.assertEqual(result["evidence"]["signature_verification"]["status"],
                         "NOT_PROVIDED")
        self.assertEqual(result["decision"], "QUARANTINE")

    def register_verified(self, artifact_id):
        public_key = self.root / "test-public.pem"
        signature = self.root / f"{artifact_id}.sig"

        public_key.write_text("test public key")
        signature.write_text("test signature")

        with patch(
                "trustchain.core.verify_model_signature",
                return_value={
                    "status": "VERIFIED",
                    "verified": True,
                    "stdout": "mock verification success",
                    "stderr": "",
                },
        ):
            return self.store.register(
                artifact_id,
                self.art,
                self.policy,
                unsigned=False,
                public_key=public_key,
                signature_path=signature,
                source_uri="test://trusted-fixture",
                transformation="test fixture import",
            )

if __name__=='__main__': unittest.main()
