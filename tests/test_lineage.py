import pytest
from unittest.mock import patch
from trustchain.core import TrustChainStore, default_policy


def register(store, artifact_id, path, **kwargs):
    public_key = path.parent / f"{artifact_id}-test-public.pem"
    signature = path.parent / f"{artifact_id}-test.sig"

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
        return store.register(
            artifact_id,
            path,
            default_policy(),
            unsigned=False,
            artifact_type="Dataset",
            public_key=public_key,
            signature_path=signature,
            **kwargs,
        )


def test_valid_parent_child_lineage(tmp_path):
    parent_file = tmp_path / "parent.bin"
    child_file = tmp_path / "child.bin"
    parent_file.write_bytes(b"original model")
    child_file.write_bytes(b"transformed model")

    store = TrustChainStore(tmp_path / "trustchain.db")

    parent_record = register(
        store,
        "parent",
        parent_file,
        source_uri="test://parent.bin",
        transformation="initial import",
    )

    print("PARENT DECISION:", parent_record.get("decision"))
    print("PARENT REASONS:", parent_record.get("reasons"))
    print("PARENT EVIDENCE:", parent_record.get("evidence", {}).get("decision_reasons"))
    register(
        store,
        "child",
        child_file,
        source_uri=None,
        parent_artifact_id="parent",
        transformation="quantization",
    )

    result = store.verify_lineage()

    assert result["valid"] is True
    assert result["records_checked"] == 2
    assert result["issues"] == []


def test_lineage_detects_artifact_tampering(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"approved model")

    store = TrustChainStore(tmp_path / "trustchain.db")
    register(
        store,
        "model",
        model,
        source_uri="dataset://demo/source-v1",
        transformation="initial import",
    )

    model.write_bytes(b"tampered model")
    result = store.verify_lineage()

    assert result["valid"] is False
    assert any("changed" in issue["issue"] for issue in result["issues"])


def test_lineage_rejects_unknown_parent(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"model")

    store = TrustChainStore(tmp_path / "trustchain.db")
    register(
        store,
        "child",
        model,
        source_uri="test://child.bin",
        transformation="test import",
    )

    with pytest.raises(KeyError, match="Unknown parent artifact"):
        register(
            store,
            "orphan-child",
            model,
            source_uri=None,
            parent_artifact_id="missing-parent",
            transformation="test transformation",
        )


def test_lineage_requires_parent_or_source(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"model")

    store = TrustChainStore(tmp_path / "trustchain.db")

    with pytest.raises(ValueError, match="parent artifact or a source URI"):
        store.register(
            "model",
            model,
            default_policy(),
            unsigned=False,
            source_uri=None,
            parent_artifact_id=None,
            transformation="initial import",
        )


def test_lineage_rejects_self_parent(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"model")

    store = TrustChainStore(tmp_path / "trustchain.db")
    register(
        store,
        "orphan-model",
        model,
        source_uri="test://model.bin",
        transformation="test import",
    )

    with pytest.raises(ValueError, match="own parent"):
        register(
            store,
            "model",
            model,
            parent_artifact_id="model",
            transformation="self reference",
        )


def test_lineage_detects_parent_file_tampering(tmp_path):
    parent = tmp_path / "parent.bin"
    child = tmp_path / "child.bin"
    parent.write_bytes(b"parent v1")
    child.write_bytes(b"child v1")

    store = TrustChainStore(tmp_path / "trustchain.db")

    register(
        store,
        "parent",
        parent,
        source_uri="test://parent.bin",
        transformation="initial import",
    )
    register(
        store,
        "child",
        child,
        source_uri=None,
        parent_artifact_id="parent",
        transformation="declared conversion",
    )

    parent.write_bytes(b"parent modified")
    result = store.verify_lineage()

    assert result["valid"] is False
    assert any(
        issue["artifact_id"] == "parent" and "changed" in issue["issue"]
        for issue in result["issues"]
    )


def test_lineage_detects_missing_artifact_registration(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"model v1")

    store = TrustChainStore(tmp_path / "trustchain.db")
    register(
        store,
        "model",
        model,
        source_uri="dataset://test/source",
        transformation="initial import",
    )

    with store._conn() as conn:
        conn.execute("DELETE FROM artifacts WHERE id=?", ("model",))

    result = store.verify_lineage()

    assert result["valid"] is False
    assert any("missing" in issue["issue"].lower() for issue in result["issues"])


def test_lineage_detects_registered_digest_snapshot_mismatch(tmp_path):
    model = tmp_path / "model.bin"
    model.write_bytes(b"model v1")

    store = TrustChainStore(tmp_path / "trustchain.db")
    register(
        store,
        "model",
        model,
        source_uri="dataset://test/source",
        transformation="initial import",
    )

    with store._conn() as conn:
        conn.execute(
            "UPDATE artifacts SET digest=? WHERE id=?",
            ("0" * 64, "model"),
        )

    result = store.verify_lineage()

    assert result["valid"] is False
    assert any(
        "registered digest differs" in issue["issue"].lower()
        for issue in result["issues"]
    )
