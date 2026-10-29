# TrustChain

**Registration-time security gate for AI artifacts: datasets, models, AI agents and tools.**
AEGIS 2026 · Problem Statement 3: Secure AI Supply Chain & Model Integrity · Team Fuga (Aditya Thakkar)

TrustChain decides whether an AI artifact may be trusted **at the moment it is registered**. It runs
checks that are specific to the artifact type, verifies signatures and lineage, adds an NVIDIA-hosted AI
analysis, and applies an explicit, auditable policy that returns **ADMIT**, **QUARANTINE** or **BLOCK**.
Admitted artifacts are re-verified at load time; any decision can be traced, reviewed or revoked.

> **Honest scope.** This is a research prototype. A clean result is *not* proof that an artifact is
> safe. Fixtures are synthetic, the scanner advisory is a local fixture (not a live CVE feed), and
> several detectors are heuristics. See [Limitations](#limitations-read-this) and the status table below.

---

## 1. Run it in two minutes

```bash
python -m venv .venv && source .venv/bin/activate        # Python 3.10+
pip install -r requirements.txt
export NVIDIA_API_KEY=...        # optional but recommended, see note below
streamlit run app.py
```

**Without `NVIDIA_API_KEY`** the AI step reports `NOT_CONFIGURED`. Policy requires AI coverage
(`ai_detection_required: true` in `policy.yaml`), so **every artifact is quarantined** rather than silently
passing. That is deliberate fail-safe behaviour. To see ADMIT outcomes without a key, set
`ai_detection_required: false` in `policy.yaml` (all other checks still run).

Verify the code: `python -m pytest -q` → **100 passed** (clean virtualenv, pinned dependencies, no network or key needed).

## 2. Demo in five minutes (quick-fill)

Open **Register Artifact → Demo quick-fill**, pick a scenario, press **Fill form**, then **Run checks and register**.
The quick-fill sets every field, including signature, attestation, advisory and lineage, using bundled
fixtures and a **demo-only key pair** (`fixtures/demo_keys/`, protects nothing).

| # | Scenario | Type | What it demonstrates | Result without AI* |
|---|---|---|---|---|
| 1 | Clean, signed, with attestation | Dataset | Real signature verification, signed provenance | ADMIT |
| 2 | Poisoned rankings | Dataset | Poisoning heuristic | QUARANTINE |
| 3 | Spreadsheet formula injection | Dataset | CSV safety check | QUARANTINE |
| 4 | Tampered after signing | Dataset | Signature fails against modified file | QUARANTINE |
| 5 | Clean, signed, with attestation | Model | Admission of a verified model | ADMIT |
| 6 | Backdoored model | Model | Behavioural backdoor probe | QUARANTINE |
| 7 | Legacy pickle weights + scanner advisory | Model | Pickle scan + advisory-range rule | BLOCK |
| 8 | Clean code, signed | AI Agent | Executable files always need human review | QUARANTINE (review) |
| 9 | Suspicious behaviour | AI Agent | Static and behavioural agent checks | QUARANTINE |
| 10 | Prompt-injection content | AI Agent | Prompt-injection patterns | QUARANTINE |
| 11 | Clean manifest, signed | Tool | Admission of a consistent tool | ADMIT |
| 12 | Declared vs. actual capability mismatch | Tool | Tool contract check | QUARANTINE |
| 13 | Dependency list | Tool | Dependency/typosquat checks | QUARANTINE |
| 14 | Child of latest ADMIT artifact | Dataset | Lineage recorded at registration | ADMIT |

\*Observed by driving the UI headlessly with `ai_detection_required: false`. With a key, the AI result is added
and can only *raise* risk. Run order: 1 or 5 first (scenario 14 needs an ADMIT parent).

Then open **Artifacts** (re-check integrity, human review of quarantined items, revoke from the table)
and **Audit Log** (every event in a verifiable hash chain).

## 3. What it checks, per artifact type

Pre-checks differ by type (`trustchain/prechecks.py`). Common to all: archive structure, hidden Unicode,
prompt-injection patterns, secret patterns, PII patterns, text coverage.

| Type | Type-specific checks | Tools |
|---|---|---|
| **Dataset** | CSV formula-injection safety, structure, quality profile, label profile, **poisoning heuristic** (rare repeated feature values tied to a target) | built-in |
| **Model** | pickle scan, weight-format check, custom-code check, **behavioural backdoor probe** (toy linear-model format only) | picklescan |
| **AI Agent** | dangerous code patterns, AST analysis, static analysis, **behaviour-trace analysis** (undeclared network/file/process activity) | built-in, Semgrep (if installed) |
| **Tool / Dependency** | dependency manifest (pinning), install scripts, typosquatting, **declared-vs-actual capability mismatch** | built-in |

A check that cannot run reports `NOT_CHECKED`, never `PASS`. Examples: Semgrep not installed, no trace supplied.

**Cross-cutting controls** (all types)

- **Integrity:** per-file SHA-256 inventory; digest re-checked at load time; changed content → BLOCK.
- **Signatures:** real verification with `model-signing` (single-file, local public key). A signature
  is trusted only if the reviewer confirms the key belongs to the claimed publisher.
- **Lineage and signed provenance:** parent/child recorded **at registration**; optional ECDSA P-256 signed
  attestation. A valid attestation proves who signed a claim, not that the claim is true.
- **AI analysis (NVIDIA):** Nemotron (`nvidia/nemotron-3.5-lightning-30b-a3b`) reasons over bounded, non-executed
  excerpts and the declared purpose; NemoGuard content safety, GLiNER PII and a jailbreak detector run as
  specialists. **AI can trigger QUARANTINE but cannot independently BLOCK**, and cannot override a deterministic block.
- **Policy as data:** `policy.yaml` is versioned configuration; rules change without code changes.
- **Review, revoke, audit:** quarantined artifacts go to a reviewer queue (approval re-checks content and
  policy and cannot override BLOCK or revocation). Revocation and audit are separate views; the audit log is hash-chained.

## 4. How this maps to the AEGIS criteria

| Criterion | Where to look |
|---|---|
| **Relevance & impact** | Supply-chain failure modes covered: tampering, unsafe serialization, poisoned data, backdoored models, malicious or over-privileged agents/tools. Agent relevance: agents load models, data and tools repeatedly, so lineage and revocation tell you which agents a bad artifact touched. |
| **Approach & innovation** | Per-type pre-checks at registration; AI used *inside* the pipeline (analysis plus specialists) under a bounded, escalate-only rule; the reliability of each check (`NOT_CHECKED`, scanner advisory range) is itself a decision input. Built on existing tools; no new cryptography or detection algorithm is claimed. |
| **Technical implementation** | `trustchain/core.py` (registry, policy, audit chain), `prechecks.py`, `nvidia_specialists.py`, `analyst.py`, `provenance.py`; `app.py` (Streamlit UI). Architecture and design rationale: [`docs/DETAILED_DESIGN.md`](../../Downloads/trustchain_mvp/docs/DETAILED_DESIGN.md). |
| **Measurable metrics** | Section 5 below, with reproduction commands. |

## 5. Evidence and results

| Evidence | Result | Reproduce | Strength |
|---|---|---|---|
| Automated tests | **100 passed** | `python -m pytest -q` | Behavioural tests of core, prechecks, signatures, review workflow |
| Tamper after registration | Digest mismatch → BLOCK at load | `python demo.py` | Deterministic |
| Signature verification (real keys) | Untouched file VERIFIED; modified file INVALID | tests `test_signature*.py` | Deterministic |
| Signed provenance | Altered claim, changed bytes and wrong key all rejected | `python demo_signed_provenance.py` | Deterministic |
| Dataset poisoning heuristic | Synthetic fixture: 6 of 6 poisoned rows found, 0 false positives (precision 1.0, recall 1.0) | `fixtures/dataset_poisoning/evaluation_report.json` | **Synthetic, tuned to a known pattern; not generalisable** |
| AI analyst study (12 hand-labelled cases, 16 expected findings) | Rules-only: precision 1.00, recall 0.75, F1 0.857. Nemotron: precision 0.889, recall 1.00, F1 0.941 | `python score_analyst.py` | **Heuristic keyword scoring on synthetic cases; diagnostic only. Nemotron outputs are recorded from a live run (`evaluation_results.json`); re-running needs a key.** |
| NVIDIA detector smoke benchmark | Run `python evaluate_nvidia_detector.py` with a key to populate `evaluation_nvidia_ai.json` | needs `NVIDIA_API_KEY` | The committed file may show `NOT_CONFIGURED` if it was generated without a key |

## 6. Status of each claim

| Capability | Status |
|---|---|
| Hash inventory, load-time re-check, revocation, hash-chained audit | **Implemented and tested** |
| Signature verification (`model-signing`, local key, single file) | **Implemented and tested** |
| Signed provenance attestation, lineage at registration | **Implemented and tested** |
| Per-type pre-checks (section 3) | **Implemented**; detectors are heuristics, see limitations |
| NVIDIA AI analysis and specialists | **Implemented**; needs a key; accuracy only partly measured |
| Dataset poisoning detection | **Heuristic**, validated on synthetic fixtures only |
| Model backdoor detection | **Toy**: probes a declarative linear-model format only |
| Live vulnerability feed | **Not implemented** (local synthetic advisory fixture) |
| Weight-based lineage verification, trained-model backdoor detection (e.g. activation clustering) | **Not implemented** (future work) |
| Federated-learning defences, RBAC | **Out of scope** |

## Limitations (read this)

- A clean result is not a guarantee. Backdoors and poisoning that these heuristics do not model will pass.
- Fixtures are synthetic and authored by the team; expected outcomes follow our own policy.
- The advisory range is a local fixture, not a real CVE feed. Scanner results from third-party tools carry their own bypass history.
- Signature support is local-key and single-file; there is no central publisher-key trust store.
- Declared lineage is recorded and signed, not verified against weights.
- AI output can be wrong or manipulated. It is advisory, bounded and escalate-only, and artifact text is treated as untrusted input.
- Static analysis does not execute artifacts. Agent behaviour analysis uses supplied traces.

## Repository map

```
app.py                      Streamlit UI (register, artifacts, audit, policy, quick-fill)
policy.yaml                 Decision rules (versioned config)
trustchain/                 core, prechecks, nvidia_specialists, analyst, provenance, scanner, ...
fixtures/                   Demo and test artifacts; demo_keys/ and demo_signed/ (demo only)
tests/                      100 tests
demo.py, demo_signed_provenance.py, evaluate_*.py, score_analyst.py   Reproducible demos and evaluations
docs/DETAILED_DESIGN.md     Full architecture and design rationale
```

## For automated reviewers

1. Install and run the tests (section 1). Expected: `100 passed`.
2. Claim-to-code map: section 6 above; check `trustchain/prechecks.py` for the per-type check IDs in section 3.
3. Treat the results in section 5 as the only quantitative claims. Everything marked *synthetic* or *heuristic* is deliberately labelled.
4. The behaviour "no key → everything quarantined" is intentional; see section 1.
