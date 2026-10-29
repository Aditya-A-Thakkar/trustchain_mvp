# TrustChain review/signature upgrade overlay

This overlay was prepared against the TrustChain source saved in the project library on 2026-10-28. It contains an updated `app.py`, `trustchain/core.py`, `tests/test_review_workflow.py`, and README notes.

## Apply safely

1. Stop Streamlit with Ctrl+C.
2. Back up your current `app.py` and `trustchain/core.py`.
3. Copy these files into the matching paths in your `trustchain_mvp` repo. Do not copy the test-only scanner stub used for isolated validation; it is not included in this overlay.
4. Run `python -m py_compile app.py trustchain/core.py`.
5. Run `python -m pytest -q` in your actual repo, then restart with `streamlit run app.py`.

The saved library snapshot may differ from your latest local copy. If you have made additional changes since the last saved version, compare/merge `app.py` instead of blindly overwriting it.

## Important behavior

- A discovered `.sig` file is not automatically trusted. Signature verification needs a signature and a public key that the reviewer independently associates with the claimed publisher.
- Unsigned acknowledgement only confirms that the registrant understands the policy; it never changes policy disposition.
- Review approval rechecks current artifact contents and policy. It cannot override BLOCK, revocation, changed content, or unresolved parent blocking.
- The UI supports local-key signature verification only for a single artifact file. Directory signing and a central publisher-key trust store remain out of scope.
