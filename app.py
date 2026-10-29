from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import streamlit as st

from trustchain.core import (
    TrustChainStore,
    aggregate_digest,
    default_policy,
    inventory,
    load_policy,
    discover_signature_sidecars,
)
from trustchain.provenance import (
    create_attestation,
    sign_attestation,
    verify_attestation,
)

ROOT = Path(__file__).parent
DB = ROOT / "data" / "trustchain.sqlite3"
POLICY = ROOT / "policy.yaml"
ADVISORY_PATH = ROOT / "fixtures" / "scanner_advisory_demo.json"
ADVISORY = json.loads(ADVISORY_PATH.read_text()) if ADVISORY_PATH.exists() else None
ATTEST_DIR = ROOT / "data" / "attestations"
TRUST_DIR = ROOT / "data" / "trusted_keys"
SIGNATURE_DIR = ROOT / "data" / "publisher_signatures"
UPLOAD_DIR = ROOT / "data" / "uploads"

for directory in (ATTEST_DIR, TRUST_DIR, SIGNATURE_DIR, UPLOAD_DIR):
    directory.mkdir(parents=True, exist_ok=True)

st.set_page_config(page_title="TrustChain", page_icon="🛡️", layout="wide")
st.title("🛡️ TrustChain")
st.caption("Evidence-based trust decisions for datasets, models, AI agents, and tools")
st.warning(
    "Research prototype. Results reflect the checks and evidence available to this MVP. "
    "A clean result does not guarantee that an artifact is safe. The bundled scanner "
    "advisory is synthetic."
)

store = TrustChainStore(DB)

try:
    policy = load_policy(POLICY)
except Exception as exc:
    st.error(f"Could not load policy: {exc}")
    policy = default_policy()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HIDDEN_FIELDS = {
    "path", "digest", "sha256", "artifact_digest", "parent_digest",
    "current_digest", "approved_digest", "registered_digest",
    "artifact_path", "file_path", "filepath", "prev_hash", "entry_hash",
    "private_key", "private_key_pem",
}

CHECK_LABELS = {
    "nvidia_ai_artifact_detection": "NVIDIA AI security analysis",
    "dataset_poisoning": "Dataset poisoning indicators",
    "dataset_quality": "Dataset quality checks",
    "hidden_unicode": "Hidden Unicode / obfuscation",
    "secrets": "Secret exposure",
    "pii": "Personal information exposure",
    "prompt_injection": "Prompt injection indicators",
    "agent_capabilities": "Agent capability checks",
    "tool_description": "Tool description / implementation consistency",
    "dependency": "Dependency security",
    "model_scan": "Unsafe model loading checks",
    "signature": "Publisher signature verification",
    "format": "File format and structural checks",
    "integrity": "Artifact integrity",
    "provenance": "Provenance checks",
}


def key_for(artifact_id: str) -> str:
    return hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:24]


def attestation_path(artifact_id: str) -> Path:
    return ATTEST_DIR / f"{key_for(artifact_id)}.json"


def trusted_key_path(artifact_id: str) -> Path:
    return TRUST_DIR / f"{key_for(artifact_id)}.pem"


def current_digest(path_text: str) -> str:
    return aggregate_digest(inventory(Path(path_text)))


def artifact_by_id(artifact_id: str):
    return next((a for a in store.artifacts() if a["id"] == artifact_id), None)


def current_artifacts():
    return store.artifacts()


def decision_label(decision: str) -> str:
    return "Review required" if decision == "QUARANTINE" else decision


def safe_for_display(value):
    """Hide internal paths, hashes and private-key material in the UI."""
    if isinstance(value, dict):
        return {
            key: safe_for_display(item)
            for key, item in value.items()
            if key.lower() not in _HIDDEN_FIELDS
        }
    if isinstance(value, (list, tuple)):
        return [safe_for_display(item) for item in value]
    return value


def humanize(value: str) -> str:
    return str(value).replace("_", " ").replace("-", " ").strip().capitalize()


def show_status(verdict: str) -> None:
    verdict = str(verdict or "UNKNOWN").upper()
    if verdict in {"PASS", "ADMIT", "VERIFIED", "COMPLETED", "VALID"}:
        st.success(f"✓ {humanize(verdict)}")
    elif verdict in {"FINDINGS", "QUARANTINE", "UNCERTAIN", "NOT_CHECKED",
                     "NOT_CONFIGURED", "NOT_SCANNED", "FOUND_UNVERIFIED"}:
        st.warning(f"⚠ {humanize(verdict)}")
    elif verdict in {"ERROR", "BLOCK", "INVALID", "FAIL"}:
        st.error(f"✕ {humanize(verdict)}")
    else:
        st.info(humanize(verdict))


def pretty_check_name(check: str) -> str:
    return CHECK_LABELS.get(check, humanize(check))


def check_icon(verdict: str) -> str:
    verdict = str(verdict or "").upper()
    if verdict in {"PASS", "ADMIT", "VERIFIED", "VALID"}:
        return "✅"
    if verdict in {"FINDINGS", "QUARANTINE", "UNCERTAIN", "NOT_CHECKED",
                   "NOT_CONFIGURED", "NOT_SCANNED", "FOUND_UNVERIFIED"}:
        return "⚠️"
    if verdict in {"ERROR", "BLOCK", "INVALID", "FAIL"}:
        return "❌"
    return "⏳"


def render_precheck_list(checks: list[dict], title: str = "Security pre-checks") -> None:
    """Render checks as a readable checklist rather than raw JSON."""
    st.markdown(f"### {title}")

    if not checks:
        st.info("No individual check results were returned.")
        return

    for check in checks:
        name = pretty_check_name(check.get("check", "Security check"))
        verdict = str(check.get("verdict", "UNKNOWN")).upper()
        severity = str(check.get("severity", "INFO")).upper()
        message = check.get("message") or check.get("summary") or "No additional details."
        icon = check_icon(verdict)

        with st.container(border=True):
            left, right = st.columns([4, 1])
            left.markdown(f"{icon} **{name}**")
            left.caption(str(message))
            right.markdown(f"**{verdict}**")
            right.caption(f"Severity: {severity}")


def render_ai_result(ai: dict) -> None:
    """Render AI detector evidence as a security-review summary."""
    if not ai:
        st.info("No AI detection evidence is available.")
        return

    status = str(ai.get("status", "UNKNOWN")).upper()
    verdict = str(ai.get("verdict", "UNCERTAIN")).upper()
    score = ai.get("risk_score")
    confidence = ai.get("confidence")
    findings = ai.get("findings", []) or []

    st.markdown("### NVIDIA AI security analysis")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Service status", humanize(status))
    c2.metric("Assessment", humanize(verdict))
    c3.metric("Risk score", f"{score}/100" if score is not None else "Unavailable")
    c4.metric(
        "Confidence",
        f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "Unavailable",
    )

    st.write(ai.get("summary") or "No summary was returned.")

    if ai.get("provider") or ai.get("model"):
        st.caption(
            f"Provider: {ai.get('provider', 'Unknown')} · "
            f"Model: {ai.get('model', 'Unknown')}"
        )

    if findings:
        st.markdown("#### Findings requiring attention")
        for finding in findings:
            severity = str(finding.get("severity", "MEDIUM")).upper()
            title = finding.get("title", "Risk indicator")
            category = humanize(finding.get("category", "Unspecified"))
            evidence = finding.get("evidence", "")
            rationale = finding.get("rationale", "")

            with st.container(border=True):
                st.markdown(f"**{title}**")
                st.caption(f"{category} · Severity: {severity}")
                if evidence:
                    st.markdown("**Evidence observed**")
                    if isinstance(evidence, (dict, list)):
                        render_value(evidence)
                    else:
                        st.code(str(evidence)[:700])
                if rationale:
                    st.write(rationale)
    else:
        if status == "COMPLETED" and verdict == "PASS":
            st.success("No strong risk indicators were identified in the supplied excerpts.")
        elif status == "NOT_CONFIGURED":
            st.warning("NVIDIA AI detection was not run because no API key is configured.")
        elif status == "ERROR":
            st.error("AI analysis did not complete. This must not be interpreted as a clean result.")
        else:
            st.info("No specific findings were returned.")

    specialists = ai.get("nvidia_specialists", {})
    if specialists:
        st.markdown("#### Specialist detector results")

        if isinstance(specialists, dict):
            specialist_checks = specialists.get("checks", specialists.get("detectors", []))
            specialist_findings = specialists.get("findings", [])

            if isinstance(specialist_checks, list) and specialist_checks:
                for detector in specialist_checks:
                    if not isinstance(detector, dict):
                        continue
                    detector_name = humanize(
                        detector.get("name", detector.get("detector", "Specialist detector"))
                    )
                    detector_status = str(detector.get("status", "UNKNOWN")).upper()
                    st.markdown(
                        f"{check_icon(detector_status)} **{detector_name}** — "
                        f"{humanize(detector_status)}"
                    )
                    message = detector.get("message") or detector.get("summary")
                    if message:
                        st.caption(str(message))

            if isinstance(specialist_findings, list) and specialist_findings:
                for finding in specialist_findings:
                    if isinstance(finding, dict):
                        st.markdown(
                            f"- **{finding.get('title', 'Specialist finding')}** "
                            f"({str(finding.get('severity', 'MEDIUM')).upper()}): "
                            f"{finding.get('rationale') or finding.get('evidence') or ''}"
                        )

            if not specialist_checks and not specialist_findings:
                st.info("Specialist output was returned, but no individual results were exposed.")

    limitations = ai.get("limitations", [])
    if limitations:
        st.markdown("**Detection limitations**")
        for limitation in limitations:
            st.caption(f"• {limitation}")


def render_evidence_summary(evidence: dict) -> None:
    """Human-readable evidence summary for the artifact detail view."""
    profile = evidence.get("capability_profile")
    if profile:
        st.markdown("#### Capability profile")
        cols = st.columns(3)
        cols[0].metric("Artifact type", evidence.get("artifact_type", "Unknown"))
        cols[1].metric("Profile basis", humanize(profile.get("basis", "Unknown")))
        cols[2].metric(
            "Runtime verified",
            "Yes" if profile.get("runtime_verified") else "No",
        )
        permissions = profile.get("default_permissions", {})
        if permissions:
            st.markdown("**Default capabilities**")
            st.dataframe(
                [{"Capability": humanize(k), "Allowed by default": bool(v)}
                 for k, v in permissions.items()],
                use_container_width=True,
                hide_index=True,
            )

    signature = evidence.get("signature_verification", {})
    if signature:
        st.markdown("#### Publisher signature")
        cols = st.columns(2)
        cols[0].metric("Verification status", humanize(signature.get("status", "Unknown")))
        cols[1].metric("Cryptographically verified", "Yes" if signature.get("verified") else "No")
        if signature.get("stderr"):
            st.caption(str(signature["stderr"]))

    scanner = evidence.get("model_scan", {})
    if scanner:
        st.markdown("#### Model scanner")
        cols = st.columns(3)
        cols[0].metric("Scanner", scanner.get("scanner", "Unknown"))
        cols[1].metric("Status", humanize(scanner.get("status", "Unknown")))
        cols[2].metric("Files scanned", scanner.get("scanned_files", 0))
        if scanner.get("error"):
            st.caption(str(scanner["error"]))

    flags = evidence.get("review_flags", [])
    if flags:
        st.markdown("#### Files requiring review")
        for flag in flags:
            st.write(f"• {flag}")

    ai = evidence.get("ai_detector")
    if ai:
        render_ai_result(ai)

    prechecks = evidence.get("prechecks", {})
    render_precheck_list(prechecks.get("checks", []), "Recorded security checks")

    reasons = evidence.get("decision_reasons", [])
    if reasons:
        st.markdown("#### Why this decision was made")
        for reason in reasons:
            st.write(f"• {reason}")


def render_checklist_placeholder(container, stages: list[tuple[str, str]]) -> None:
    with container.container(border=True):
        st.markdown("### Registration checklist")
        for label, state in stages:
            if state == "done":
                st.markdown(f"✅ **{label}** — completed")
            elif state == "warning":
                st.markdown(f"⚠️ **{label}** — review / partial coverage")
            elif state == "running":
                st.markdown(f"🔄 **{label}** — in progress")
            elif state == "failed":
                st.markdown(f"❌ **{label}** — failed")
            else:
                st.markdown(f"⏳ {label}")


def render_policy(policy_data: dict) -> None:
    st.markdown("### Decision thresholds")
    rows = []
    for key, value in policy_data.items():
        label = humanize(key)
        if isinstance(value, dict):
            continue
        rows.append({"Policy setting": label, "Configured value": str(value)})
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)

    for key, value in policy_data.items():
        if isinstance(value, dict):
            with st.expander(humanize(key)):
                rows = [{"Setting": humanize(k), "Value": str(v)} for k, v in value.items()]
                st.dataframe(rows, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Demo support: bundled demo keys, quick-fill presets, readable value rendering
# ---------------------------------------------------------------------------
FX = ROOT / "fixtures"
DEMO_PUB = FX / "demo_keys" / "demo_public.pem"
DEMO_PRIV = FX / "demo_keys" / "demo_private.pem"
DEMO_SIG_DIR = FX / "demo_signed"
DEMO_SIGS = sorted(p.name for p in DEMO_SIG_DIR.glob("*.sig")) if DEMO_SIG_DIR.exists() else []
TYPES = ["Dataset", "Model", "AI Agent", "Tool / Dependency"]
ROOT_LABEL = "External source / root"


class DemoUpload:
    """File-like stand-in so bundled demo keys/signatures use the normal upload code path."""

    def __init__(self, path):
        self.name = Path(path).name
        self._data = Path(path).read_bytes()

    def getvalue(self):
        return self._data


def _flat(value):
    if isinstance(value, dict):
        return "; ".join(f"{humanize(k)}: {_flat(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(_flat(v) for v in value)
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def render_value(value) -> None:
    """Show structured data as a table or list instead of raw JSON."""
    if isinstance(value, dict):
        st.dataframe(
            [{"Field": humanize(k), "Value": _flat(v)} for k, v in value.items()],
            use_container_width=True, hide_index=True,
        )
    elif isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
        st.dataframe(
            [{humanize(k): _flat(v) for k, v in item.items()} for item in value],
            use_container_width=True, hide_index=True,
        )
    elif isinstance(value, list):
        for item in value:
            st.write(f"• {_flat(item)}")
    else:
        st.write(_flat(value))


PRESETS = {
    "Choose a demo scenario…": None,
    "1 · Dataset, clean, signed + attestation (expect ADMIT)": dict(
        type="Dataset", id="rankings-clean", path=FX / "dataset_poisoning" / "clean_rankings.csv",
        purpose="Property ranking dataset used to fine-tune a listing-ranking model.",
        sig="clean_rankings.csv.sig", attest=True, transformation="Initial import from vendor"),
    "2 · Dataset, poisoned rankings (expect review/block)": dict(
        type="Dataset", id="rankings-poisoned", path=FX / "dataset_poisoning" / "poisoned_rankings.csv",
        purpose="Property ranking dataset used to fine-tune a listing-ranking model.",
        transformation="Initial import from unverified source"),
    "3 · Dataset, spreadsheet formula injection": dict(
        type="Dataset", id="listings-formula", path=FX / "phase_c_d" / "dataset_formula_injection.csv",
        purpose="Customer listings export for analysts.", transformation="Initial import"),
    "4 · Dataset, tampered after signing (signature mismatch)": dict(
        type="Dataset", id="rankings-tampered", path=FX / "dataset_poisoning" / "poisoned_rankings.csv",
        purpose="Property ranking dataset (publisher claims it is the signed release).",
        sig="clean_rankings.csv.sig", transformation="Initial import, claimed signed release"),
    "5 · Model, clean, signed + attestation (expect ADMIT)": dict(
        type="Model", id="ranker-clean", path=FX / "model_backdoor" / "clean_model.tcmodel.json",
        purpose="Listing-ranking classifier for a property search app.",
        sig="clean_model.tcmodel.json.sig", attest=True, transformation="Initial import"),
    "6 · Model, backdoored (expect review/block)": dict(
        type="Model", id="ranker-backdoored", path=FX / "model_backdoor" / "backdoored_model.tcmodel.json",
        purpose="Listing-ranking classifier for a property search app.", transformation="Initial import from public hub"),
    "7 · Model, legacy pickle weights + scanner advisory": dict(
        type="Model", id="legacy-weights", path=ROOT / "sample_artifacts" / "benign.pkl",
        purpose="Legacy pickled weights from an older training run.", advisory=True,
        transformation="Initial import from archive"),
    "8 · AI agent, clean code, signed (expect review: executable file)": dict(
        type="AI Agent", id="listing-agent-clean", path=FX / "agent_behavior" / "agent_bundle.py",
        purpose="Agent that answers property questions using the listing search tool.",
        sig="agent_bundle.py.sig", transformation="Initial import"),
    "9 · AI agent, suspicious behaviour": dict(
        type="AI Agent", id="listing-agent-suspicious", path=FX / "agent_behavior" / "agent_bundle_suspicious.py",
        purpose="Agent that answers property questions using the listing search tool.", transformation="Initial import"),
    "10 · AI agent, prompt-injection content": dict(
        type="AI Agent", id="agent-injected-prompt", path=FX / "phase_c_d" / "agent_prompt_injection.txt",
        purpose="System prompt for a customer-support agent.", transformation="Initial import"),
    "11 · Tool, clean manifest, signed (expect ADMIT)": dict(
        type="Tool / Dependency", id="listing-tool-clean", path=FX / "tool_mismatch" / "tool_manifest_clean.json",
        purpose="Tool manifest for a listing-search integration.", sig="tool_manifest_clean.json.sig",
        transformation="Initial import"),
    "12 · Tool, declared vs. actual capability mismatch": dict(
        type="Tool / Dependency", id="listing-tool-mismatch", path=FX / "tool_mismatch" / "tool_manifest.json",
        purpose="Tool manifest for a listing-search integration.", transformation="Initial import"),
    "13 · Tool, dependency list (unpinned packages)": dict(
        type="Tool / Dependency", id="tool-dependencies", path=FX / "phase_c_d" / "requirements.txt",
        purpose="Python dependencies for the listing tool.", transformation="Initial import"),
    "14 · Child of the latest ADMIT artifact, signed (lineage)": dict(
        type="Dataset", id="rankings-v2", path=FX / "dataset_poisoning" / "clean_rankings_v2.csv",
        purpose="Cleaned and re-sampled derivative of the approved rankings dataset.",
        parent="latest_admit", sig="clean_rankings_v2.csv.sig", attest=True, transformation="Cleaning and re-sampling"),
}
SESSION_DEFAULTS = {
    "reg_type": TYPES[0], "reg_id": "", "reg_purpose": "", "reg_path": "", "reg_has_sig": False,
    "reg_use_demo_sig": False, "reg_demo_sig_name": DEMO_SIGS[0] if DEMO_SIGS else "",
    "reg_confirm_key": False, "reg_ack_unsigned": False, "reg_apply_adv": False,
    "reg_scanner_version": "0.0.10", "reg_parent": ROOT_LABEL, "reg_source_uri": "",
    "reg_transformation": "", "reg_create_signed": False, "reg_use_demo_keys": False,
    "reg_signer": "local-demo-publisher", "preset_choice": "Choose a demo scenario…", "preset_note": "",
}
for _k, _v in SESSION_DEFAULTS.items():
    st.session_state.setdefault(_k, _v)


def apply_preset() -> None:
    """Callback: fill every registration field for the selected demo scenario."""
    preset = PRESETS.get(st.session_state.get("preset_choice"))
    if not preset:
        return
    ss = st.session_state
    existing = current_artifacts()
    taken = {a["id"] for a in existing}
    base, new_id, n = preset["id"], preset["id"], 2
    while new_id in taken:
        new_id, n = f"{base}-{n}", n + 1
    ss.reg_type, ss.reg_id, ss.reg_purpose = preset["type"], new_id, preset["purpose"]
    ss.reg_path, ss.reg_transformation = str(preset["path"]), preset["transformation"]
    sig = preset.get("sig")
    ss.reg_has_sig = bool(sig)
    ss.reg_use_demo_sig = bool(sig)
    ss.reg_confirm_key = bool(sig)
    ss.reg_ack_unsigned = not sig
    if sig and sig in DEMO_SIGS:
        ss.reg_demo_sig_name = sig
    ss.reg_apply_adv = bool(preset.get("advisory"))
    ss.reg_scanner_version = "0.0.10"
    ss.reg_create_signed = bool(preset.get("attest"))
    ss.reg_use_demo_keys = bool(preset.get("attest"))
    ss.reg_signer = "local-demo-publisher"
    ss.preset_note = ""
    ss.reg_parent, ss.reg_source_uri = ROOT_LABEL, f"vendor://demo/{new_id}"
    if preset.get("parent") == "latest_admit":
        parents = [a for a in existing if a["decision"] == "ADMIT" and not a["revoked"]]
        if parents:
            ss.reg_parent, ss.reg_source_uri = parents[-1]["id"], ""
        else:
            ss.preset_note = "No ADMIT artifact exists yet, so this was filled as a root artifact. Register scenario 1 or 5 first."


st.markdown(
    """
    <style>
    section[data-testid="stSidebar"] div[role="radiogroup"] > label {
        padding: .55rem .8rem; border-radius: .6rem; margin-bottom: .2rem; width: 100%; cursor: pointer;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child { display: none; }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover { background: rgba(128,128,128,.14); }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
        background: rgba(60,110,255,.16); font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🛡️ TrustChain")
    NAV_ITEMS = {"Overview": "🏠", "Register Artifact": "➕", "Artifacts": "🗂️", "Audit Log": "📜", "Policy": "⚙️"}
    page = st.radio(
        "Navigation",
        list(NAV_ITEMS),
        format_func=lambda p: f"{NAV_ITEMS[p]}  {p}",
        label_visibility="collapsed",
    )
    st.divider()
    st.caption(
        "Deterministic checks establish verifiable evidence. NVIDIA AI analysis adds "
        "risk indicators. AI findings can trigger quarantine, but cannot independently block."
    )


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

if page == "Overview":
    artifacts = current_artifacts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registered", len(artifacts))
    c2.metric(
        "Admitted",
        sum(a["decision"] == "ADMIT" and not a["revoked"] for a in artifacts),
    )
    c3.metric(
        "Review required",
        sum(a["decision"] == "QUARANTINE" and not a["revoked"] for a in artifacts),
    )
    c4.metric(
        "Blocked / revoked",
        sum(a["decision"] == "BLOCK" or a["revoked"] for a in artifacts),
    )

    st.subheader("Trust workflow")
    st.markdown("**Register → inspect evidence → policy decision → lineage / attestation → audit**")
    st.write(
        "Register an artifact to inventory its contents, run applicable checks, "
        "evaluate policy, and record an auditable decision."
    )

    with st.expander("5-minute demo script (uses the quick-fill scenarios)"):
        st.markdown(
            "1. **Register Artifact** → scenario 1 (clean signed dataset) → *Run checks*: ADMIT with a verified signature and attestation.\n"
            "2. Scenario 2 and 3: poisoned and formula-injection datasets are flagged by dataset pre-checks.\n"
            "3. Scenario 4: the same signature does not verify a tampered file.\n"
            "4. Scenario 5, then 6: clean model admitted, backdoored model flagged.\n"
            "5. Scenario 8, 9, 10: agent code always needs human review; suspicious and prompt-injected agents are flagged on top of that.\n"
            "6. Scenario 11, 12, 13: tool manifest consistency and dependency pins.\n"
            "7. Scenario 14: register a child of an ADMIT artifact (lineage recorded at registration).\n"
            "8. **Artifacts**: re-check an artifact, change a file to see BLOCK, revoke from the table.\n"
            "9. **Audit Log**: every decision, with a verifiable hash chain."
        )
    if artifacts:
        st.dataframe(
            [
                {
                    "ID": a["id"],
                    "Type": a["artifact_type"],
                    "Decision": decision_label(a["decision"]),
                    "Revoked": bool(a["revoked"]),
                }
                for a in artifacts
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No artifacts yet. Go to Register Artifact to add the first one.")


# ---------------------------------------------------------------------------
# Register artifact
# ---------------------------------------------------------------------------

elif page == "Register Artifact":
    st.header("Register an artifact")
    st.caption(
        "Run applicable security checks, assess risk, and record the policy decision "
        "with lineage and audit evidence."
    )

    existing = current_artifacts()
    existing_ids = [a["id"] for a in existing]

    with st.container(border=True):
        st.markdown("**Demo quick-fill**")
        qc1, qc2 = st.columns([5, 1])
        qc1.selectbox("Demo scenario", list(PRESETS), key="preset_choice", label_visibility="collapsed")
        qc2.button("Fill form", on_click=apply_preset, use_container_width=True)
        st.caption(
            "Fills every field below, including signatures, attestation and lineage, using bundled fixtures "
            "and a demo key pair. Review the fields, then press Run checks and register. "
            "Scenario 14 needs an ADMIT parent, so register scenario 1 or 5 first."
        )
        if st.session_state.preset_note:
            st.info(st.session_state.preset_note)

    with st.container():
        artifact_type = st.selectbox("Artifact type", TYPES, key="reg_type")
        artifact_id = st.text_input("Unique artifact ID", placeholder="e.g. fraud-model-v2", key="reg_id")
        purpose = st.text_area(
            "Declared purpose",
            placeholder="What is this artifact intended to do, and where will it be used?",
            help="AI detection compares the available artifact evidence against this purpose.",
            key="reg_purpose",
        )
        uploaded = st.file_uploader("Upload one file (or provide a local path below)", key="reg_upload")
        path_text = st.text_input(
            "Local file or directory path (optional if uploading)",
            placeholder="/path/to/artifact", key="reg_path",
        )

        st.markdown("#### Publisher signature")
        has_sig = st.checkbox("The publisher supplied a signature for this artifact", key="reg_has_sig")
        publisher_signature_upload = None
        publisher_public_key_upload = None
        confirm_publisher_key_trusted = False
        acknowledge_unsigned = False
        if has_sig:
            use_demo_sig = st.checkbox(
                "Use a bundled demo signature and public key (for the demo fixtures)", key="reg_use_demo_sig",
            )
            if use_demo_sig and DEMO_SIGS:
                sig_name = st.selectbox("Bundled signature", DEMO_SIGS, key="reg_demo_sig_name")
                publisher_signature_upload = DemoUpload(DEMO_SIG_DIR / sig_name)
                publisher_public_key_upload = DemoUpload(DEMO_PUB)
                st.caption("Verification is real: a signature only verifies against the exact file it was created for.")
            else:
                publisher_signature_upload = st.file_uploader(
                    "Publisher signature file (.sig)", key="publisher_signature_upload",
                )
                publisher_public_key_upload = st.file_uploader(
                    "Publisher public key PEM", type=["pem", "pub"], key="publisher_public_key_upload",
                )
            confirm_publisher_key_trusted = st.checkbox(
                "I independently verified that this public key belongs to the claimed publisher.",
                help="Signature verification alone does not establish publisher identity.",
                key="reg_confirm_key",
            )
        else:
            acknowledge_unsigned = st.checkbox(
                "I understand that without a verified publisher signature, this artifact may require review.",
                key="reg_ack_unsigned",
            )

        st.markdown("#### Scanner advisory simulation")
        apply_advisory = st.checkbox(
            "Apply synthetic scanner advisory fixture",
            help="Demo-only version-range fixture; not a real CVE feed.",
            key="reg_apply_adv",
        )
        if apply_advisory:
            scanner_version = st.text_input("Scanner version", key="reg_scanner_version")
        else:
            scanner_version = "0.0.10"

        st.markdown("#### Origin and lineage")
        parent_choices = [ROOT_LABEL] + existing_ids
        if st.session_state.reg_parent not in parent_choices:
            st.session_state.reg_parent = ROOT_LABEL
        parent_choice = st.selectbox("Parent artifact", parent_choices, key="reg_parent")
        if parent_choice == ROOT_LABEL:
            source_uri = st.text_input(
                "Source URI (required for an external/root artifact)",
                placeholder="e.g. vendor://model/v2", key="reg_source_uri",
            )
        else:
            source_uri = ""
            st.caption("The source is inherited from the selected parent artifact.")
        transformation = st.text_input(
            "Transformation / import event",
            placeholder="e.g. initial import, fine-tuning, quantization", key="reg_transformation",
        )

        st.markdown("#### Optional signed provenance")
        create_signed = st.checkbox("Create a signed provenance attestation during registration", key="reg_create_signed")
        signer_id = "local-demo-publisher"
        private_upload = None
        trusted_public_upload = None
        if create_signed:
            signer_id = st.text_input("Signer ID", key="reg_signer")
            if st.checkbox("Use the bundled demo key pair", key="reg_use_demo_keys"):
                private_upload = DemoUpload(DEMO_PRIV)
                trusted_public_upload = DemoUpload(DEMO_PUB)
                st.caption("Demo key pair only. It protects nothing and exists so the demo is reproducible.")
            else:
                private_upload = st.file_uploader(
                    "Signing private key PEM (kept local; not persisted)",
                    type=["pem", "key"], key="register_private_key",
                )
                trusted_public_upload = st.file_uploader(
                    "Trusted public key PEM (must be independently trusted)",
                    type=["pem", "pub"], key="register_public_key",
                )
        submitted = st.button("Run checks and register", type="primary")

    if submitted:
        saved_upload_path = None
        artifact_id = artifact_id.strip()

        stages = [
            ("Validate registration details and source", "pending"),
            ("Verify parent integrity and lineage constraints", "pending"),
            ("Inventory files and calculate integrity hashes", "pending"),
            ("Run artifact-specific deterministic pre-checks", "pending"),
            ("Run applicable model and scanner checks", "pending"),
            ("Run NVIDIA AI and specialist detection", "pending"),
            ("Verify publisher signature and provenance evidence", "pending"),
            ("Evaluate policy and determine the verdict", "pending"),
            ("Persist registration and append audit record", "pending"),
        ]
        checklist_area = st.empty()
        render_checklist_placeholder(checklist_area, stages)

        progress = st.progress(0, text="Preparing registration…")
        with st.status("Registering artifact", expanded=True) as registration_status:
            try:
                if not artifact_id:
                    raise ValueError("Enter a unique artifact ID.")
                if artifact_id in existing_ids:
                    raise ValueError(
                        f"Artifact ID {artifact_id!r} is already registered. "
                        "Choose a new ID; registration cannot replace its approved digest."
                    )
                if not transformation.strip():
                    raise ValueError("Enter a transformation / import event.")
                if parent_choice == "External source / root":
                    if not source_uri.strip():
                        raise ValueError("Enter a source URI for an external/root artifact.")
                    parent_id = None
                    parent_digest = None
                else:
                    if source_uri.strip():
                        raise ValueError("Clear Source URI when a registered parent is selected.")
                    parent = artifact_by_id(parent_choice)
                    if parent is None:
                        raise ValueError("Selected parent artifact no longer exists.")
                    parent_id = parent_choice
                    parent_digest = parent["digest"]
                    if current_digest(parent["path"]) != parent_digest:
                        raise ValueError(
                            "Parent artifact integrity mismatch. Restore or re-register "
                            "the parent through an approved process before registering a child."
                        )
                    if parent["revoked"] or parent["decision"] != "ADMIT":
                        raise ValueError(
                            "Parent must be non-revoked and ADMIT before it can be used as a trusted parent."
                        )

                if create_signed and (private_upload is None or trusted_public_upload is None):
                    raise ValueError(
                        "Signed provenance requires both a signing private key and "
                        "an independently trusted public key."
                    )
                if create_signed and not signer_id.strip():
                    raise ValueError("Enter a signer ID.")

                if uploaded is not None:
                    suffix = Path(uploaded.name).suffix
                    saved_path = UPLOAD_DIR / f"{key_for(artifact_id)}{suffix}"
                    if saved_path.exists():
                        raise ValueError(
                            "A stored upload already exists for this artifact ID. "
                            "Choose a new ID; files are not overwritten."
                        )
                    saved_path.write_bytes(uploaded.getvalue())
                    saved_upload_path = saved_path
                    artifact_path = saved_path
                elif path_text.strip():
                    artifact_path = Path(path_text.strip()).expanduser()
                    if not artifact_path.exists():
                        raise FileNotFoundError(artifact_path)
                else:
                    raise ValueError("Upload a file or provide a local file/directory path.")

                stages[0] = (stages[0][0], "done")
                progress.progress(10, text="Registration details validated…")
                render_checklist_placeholder(checklist_area, stages)

                discovered_signature = discover_signature_sidecars(artifact_path)
                publisher_signature_path = None
                publisher_public_key_path = None

                if publisher_signature_upload is not None:
                    publisher_signature_path = SIGNATURE_DIR / f"{key_for(artifact_id)}.sig"
                    publisher_signature_path.write_bytes(publisher_signature_upload.getvalue())
                elif discovered_signature.get("signature_path"):
                    publisher_signature_path = Path(discovered_signature["signature_path"])

                if publisher_public_key_upload is not None and confirm_publisher_key_trusted:
                    publisher_public_key_path = SIGNATURE_DIR / f"{key_for(artifact_id)}.publisher.pub"
                    publisher_public_key_path.write_bytes(publisher_public_key_upload.getvalue())
                elif publisher_public_key_upload is not None:
                    st.warning(
                        "The public key was supplied but not independently trusted; "
                        "it will not establish publisher identity."
                    )

                signature_material_available = (
                    publisher_signature_path is not None and publisher_public_key_path is not None
                )
                if not signature_material_available and not acknowledge_unsigned:
                    raise ValueError(
                        "Signature review acknowledgement required. Upload a signature and "
                        "independently trusted public key, or acknowledge that this artifact "
                        "will be treated as unsigned."
                    )
                if publisher_signature_path is not None and publisher_public_key_path is None:
                    st.warning(
                        "A signature file was detected, but no independently trusted public key "
                        "was provided. It will not count as verified."
                    )

                stages[1] = (stages[1][0], "done")
                progress.progress(20, text="Source and lineage constraints validated…")
                render_checklist_placeholder(checklist_area, stages)

                prepared_envelope = None
                if create_signed:
                    artifact_digest = aggregate_digest(inventory(artifact_path))
                    payload = create_attestation(
                        artifact_id=artifact_id,
                        artifact_digest=artifact_digest,
                        parent_artifact_id=parent_id,
                        parent_digest=parent_digest,
                        source_uri=source_uri.strip() if parent_id is None else None,
                        transformation=transformation.strip(),
                        signer_id=signer_id.strip(),
                    )
                    with tempfile.TemporaryDirectory(prefix="trustchain-registration-") as td:
                        td_path = Path(td)
                        private_path = td_path / "signing.pem"
                        public_path = td_path / "trusted-public.pem"
                        envelope_path = td_path / "attestation.json"
                        private_path.write_bytes(private_upload.getvalue())
                        public_path.write_bytes(trusted_public_upload.getvalue())
                        prepared_envelope = sign_attestation(payload, private_path, envelope_path)
                        verification = verify_attestation(prepared_envelope, public_path)
                        if not verification.get("valid"):
                            raise ValueError(
                                "Attestation signature did not verify against the supplied trusted "
                                "public key. Check that the key pair matches. "
                                + verification.get("reason", "")
                            )

                stages[2] = (stages[2][0], "running")
                stages[3] = (stages[3][0], "running")
                stages[4] = (stages[4][0], "running")
                stages[5] = (stages[5][0], "running")
                progress.progress(30, text="Inventory, deterministic checks and AI analysis running…")
                render_checklist_placeholder(checklist_area, stages)

                result = store.register(
                    artifact_id=artifact_id,
                    path=artifact_path,
                    policy=policy,
                    unsigned=True,
                    scanner_name="picklescan",
                    scanner_version=scanner_version,
                    advisory=ADVISORY if apply_advisory and ADVISORY else None,
                    artifact_type=artifact_type,
                    public_key=publisher_public_key_path,
                    signature_path=publisher_signature_path,
                    purpose=purpose.strip(),
                    parent_artifact_id=parent_id,
                    source_uri=source_uri.strip() if parent_id is None else None,
                    transformation=transformation.strip(),
                )

                evidence = result.get("evidence", {})
                precheck_report = evidence.get("prechecks", {})
                checks = precheck_report.get("checks", [])

                # Mark each registration stage based on the evidence actually returned.
                # Reflect recorded evidence rather than marking every check as passed.
                stages[2] = (
                    stages[2][0],
                    "done" if evidence.get("files") is not None else "failed",
                )

                checks = precheck_report.get("checks", [])
                check_verdicts = {
                    str(item.get("verdict", "")).upper()
                    for item in checks
                    if isinstance(item, dict)
                }

                stages[3] = (
                    stages[3][0],
                    "failed" if "ERROR" in check_verdicts
                    else "warning" if check_verdicts & {
                        "FINDINGS", "NOT_CHECKED", "UNCERTAIN"
                    }
                    else "done" if checks else "warning",
                )

                model_scan = evidence.get("model_scan", {})
                scan_status = str(model_scan.get("status", "")).upper()
                stages[4] = (
                    stages[4][0],
                    "failed" if scan_status == "ERROR"
                    else "warning" if scan_status in {
                        "FINDINGS", "NOT_SCANNED", "UNKNOWN"
                    }
                    else "done",
                )

                ai = evidence.get("ai_detector", {})
                ai_status = str(ai.get("status", "")).upper()
                specialists = ai.get("nvidia_specialists", {})
                specialist_status = str(
                    specialists.get("status", "")
                ).upper() if isinstance(specialists, dict) else "UNKNOWN"

                stages[5] = (
                    stages[5][0],
                    "failed" if ai_status == "ERROR"
                    else "warning" if ai_status != "COMPLETED"
                                      or specialist_status in {"PARTIAL", "ERROR", "NOT_CONFIGURED"}
                    else "done",
                )

                signature_status = str(
                    evidence.get("signature_verification", {}).get("status", "")
                ).upper()
                stages[6] = (
                    stages[6][0],
                    "failed" if signature_status == "ERROR"
                    else "warning" if signature_status not in {"VERIFIED"}
                    else "done",
                )

                stages[7] = (
                    stages[7][0],
                    "done" if result.get("decision") in {
                        "ADMIT", "QUARANTINE", "BLOCK"
                    } else "failed",
                )

                progress.progress(85, text="Recording lineage and audit evidence…")
                render_checklist_placeholder(checklist_area, stages)

                lineage = result["lineage"]

                if prepared_envelope is not None:
                    attestation_path(artifact_id).write_text(
                        json.dumps(prepared_envelope, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    trusted_key_path(artifact_id).write_bytes(trusted_public_upload.getvalue())

                stages[8] = (stages[8][0], "done")
                progress.progress(100, text="Registration complete")
                render_checklist_placeholder(checklist_area, stages)
                registration_status.update(
                    label=f"Registration complete — {decision_label(result['decision'])}",
                    state="complete",
                    expanded=True,
                )

                if result["decision"] == "ADMIT":
                    st.success(f"✅ Registered {artifact_id}: ADMIT")
                elif result["decision"] == "QUARANTINE":
                    st.warning(f"⚠️ Registered {artifact_id}: REVIEW REQUIRED")
                else:
                    st.error(f"⛔ Registered {artifact_id}: BLOCK")

                st.markdown("### Final policy decision")
                show_status(result["decision"])
                st.markdown("**Decision rationale**")
                for reason in result.get("reasons", []):
                    st.write(f"• {reason}")

                st.markdown("### Registration lineage")
                st.write("Parent artifact:", lineage.get("parent_artifact_id") or "External source / root")
                st.write("Source URI:", lineage.get("source_uri") or "Inherited from parent")
                st.write("Transformation:", lineage.get("transformation"))

                if prepared_envelope is not None:
                    st.success("Signed provenance created and verified against the supplied trusted public key.")

                render_ai_result(evidence.get("ai_detector", {}))

                counts = precheck_report.get("counts", {})
                st.markdown("### Security check summary")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Passed", counts.get("PASS", 0))
                m2.metric("Findings", counts.get("FINDINGS", 0))
                m3.metric("Not checked", counts.get("NOT_CHECKED", 0))
                m4.metric("Errors", counts.get("ERROR", 0))

                render_precheck_list(checks, "Completed pre-checks")

                st.caption(
                    "AI analysis uses bounded, non-executed artifact excerpts. A clean "
                    "response is not proof of safety. Failed or missing detection coverage "
                    "must be interpreted according to policy."
                )

                st.markdown("### Additional registration details")
                with st.container(border=True):
                    st.markdown("#### Artifact and registration")
                    st.write("Artifact type:", evidence.get("artifact_type", "Unknown"))
                    st.write("Purpose:", evidence.get("purpose") or "Not declared")
                    st.write("Unsigned:", "Yes" if evidence.get("unsigned") else "No")
                    st.write("Files inventoried:", len(evidence.get("files", [])))
                    st.write("Scanner:", evidence.get("scanner", {}).get("name", "Unknown"))
                    st.write("Scanner version:", evidence.get("scanner", {}).get("version", "Unknown"))
                    render_evidence_summary(evidence)

            except Exception as exc:
                for index, (label, _) in enumerate(stages):
                    if stages[index][1] == "running":
                        stages[index] = (label, "failed")
                render_checklist_placeholder(checklist_area, stages)
                if saved_upload_path is not None and saved_upload_path.exists():
                    if artifact_by_id(artifact_id) is None:
                        saved_upload_path.unlink(missing_ok=True)
                registration_status.update(label="Registration failed", state="error", expanded=True)
                st.error(f"Registration failed: {exc}")


# ---------------------------------------------------------------------------
# Artifacts and review
# ---------------------------------------------------------------------------

elif page == "Artifacts":
    st.header("Artifacts")
    st.caption("Review status, inspect security evidence, verify provenance, and revoke artifacts.")

    st.info(
        "**Review required** means quarantined pending human review. Approval cannot "
        "override hard blocks, revocation, changed contents, or unresolved parent blocks."
    )

    artifacts = current_artifacts()
    review_queue = [
        a for a in artifacts
        if a["decision"] == "QUARANTINE" and not a["revoked"]
    ]

    st.subheader(f"Review queue ({len(review_queue)})")
    if review_queue:
        st.dataframe(
            [
                {
                    "ID": a["id"],
                    "Type": a["artifact_type"],
                    "Reason": "; ".join(a["evidence"].get("decision_reasons", [])),
                }
                for a in review_queue
            ],
            use_container_width=True,
            hide_index=True,
        )
        queue_choice = st.selectbox(
            "Open artifact for review",
            [a["id"] for a in review_queue],
            key="review_queue_choice",
        )
        if st.button("Open review", key="open_review_queue"):
            st.session_state["details_artifact"] = queue_choice
            st.rerun()
    else:
        st.success("No artifacts currently require review.")

    if not artifacts:
        st.info("No registered artifacts yet.")
    else:
        st.dataframe(
            [
                {
                    "ID": a["id"],
                    "Type": a["artifact_type"],
                    "Decision": decision_label(a["decision"]),
                    "Revoked": bool(a["revoked"]),
                }
                for a in artifacts
            ],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Artifact actions")
        for artifact in artifacts:
            with st.container(border=True):
                cols = st.columns([2.0, 0.9, 0.8, 0.9, 1.0, 0.9])
                cols[0].markdown(
                    f"**{artifact['id']}**\n\n{artifact['artifact_type']}"
                )
                cols[1].write(decision_label(artifact["decision"]))
                cols[2].write("Revoked" if artifact["revoked"] else "Active")

                with cols[3]:
                    if st.button("Details", key=f"details_{key_for(artifact['id'])}"):
                        st.session_state["details_artifact"] = artifact["id"]

                with cols[4]:
                    if st.button("Test load", key=f"testload_{key_for(artifact['id'])}"):
                        try:
                            st.session_state["last_load_result"] = store.load(
                                artifact["id"], "trustchain-demo-agent", policy
                            )
                        except Exception as exc:
                            st.session_state["last_load_result"] = {
                                "decision": "ERROR",
                                "reasons": [str(exc)],
                                "artifact_id": artifact["id"],
                            }

                with cols[5]:
                    if artifact["revoked"]:
                        st.button(
                            "Revoked",
                            key=f"revoked_{key_for(artifact['id'])}",
                            disabled=True,
                        )
                    elif st.button("Revoke", key=f"revoke_{key_for(artifact['id'])}"):
                        st.session_state["confirm_revoke"] = artifact["id"]

        if st.session_state.get("last_load_result"):
            load_result = st.session_state["last_load_result"]
            decision = load_result.get("decision", "ERROR")
            st.markdown("### Latest load attempt")
            show_status(decision)
            st.write("Artifact:", load_result.get("artifact_id", "Unknown"))
            for reason in load_result.get("reasons", []):
                st.write(f"• {reason}")
            if load_result.get("descendants_quarantined"):
                st.warning(
                    "Descendants moved to review: "
                    + ", ".join(load_result["descendants_quarantined"])
                )

        if st.session_state.get("confirm_revoke"):
            aid = st.session_state["confirm_revoke"]
            st.warning(
                f"Revoke {aid}? This blocks future load attempts and moves registered "
                "descendants to review."
            )
            reason = st.text_input(
                "Revocation reason",
                value="Security review / trust status changed",
                key="inline_revoke_reason",
            )
            c1, c2 = st.columns(2)
            if c1.button("Confirm revocation", type="primary", key="confirm_revoke_btn"):
                try:
                    agents = store.revoke(aid, reason.strip() or "manual revocation")
                    st.session_state.pop("confirm_revoke", None)
                    st.success(
                        f"Revoked {aid}. Previously recorded agents: "
                        f"{', '.join(agents) if agents else 'none'}."
                    )
                    st.rerun()
                except Exception as exc:
                    st.error(f"Revocation failed: {exc}")
            if c2.button("Cancel", key="cancel_revoke_btn"):
                st.session_state.pop("confirm_revoke", None)
                st.rerun()

        selected_detail = st.session_state.get("details_artifact")
        if selected_detail:
            artifact = artifact_by_id(selected_detail)
            if artifact:
                st.divider()
                st.subheader(f"Artifact details: {selected_detail}")
                evidence = artifact["evidence"]
                render_evidence_summary(evidence)

                if artifact["decision"] == "QUARANTINE" and not artifact["revoked"]:
                    st.markdown("### Human review")
                    st.caption(
                        "Approval is allowed only if the original digest still matches "
                        "and current policy independently returns ADMIT."
                    )
                    reviewer = st.text_input(
                        "Reviewer identity",
                        key=f"reviewer_{key_for(selected_detail)}",
                    )
                    justification = st.text_area(
                        "Review justification (required)",
                        key=f"review_justification_{key_for(selected_detail)}",
                    )
                    review_signature_upload = st.file_uploader(
                        "Optional publisher signature for this exact artifact",
                        key=f"review_signature_{key_for(selected_detail)}",
                    )
                    review_public_key_upload = st.file_uploader(
                        "Publisher public key PEM",
                        type=["pem", "pub"],
                        key=f"review_public_key_{key_for(selected_detail)}",
                    )
                    review_key_trusted = st.checkbox(
                        "I independently verified this key belongs to the claimed publisher.",
                        value=False,
                        key=f"review_key_trusted_{key_for(selected_detail)}",
                    )

                    rc1, rc2, rc3 = st.columns(3)
                    if rc1.button("Re-evaluate & approve", type="primary", key=f"approve_{key_for(selected_detail)}"):
                        try:
                            review_public_key_path = None
                            review_signature_path = None
                            with tempfile.TemporaryDirectory(prefix="trustchain-review-") as review_td:
                                review_dir = Path(review_td)
                                if review_public_key_upload is not None and review_key_trusted:
                                    review_public_key_path = review_dir / "publisher.pub"
                                    review_public_key_path.write_bytes(review_public_key_upload.getvalue())
                                elif review_public_key_upload is not None:
                                    raise ValueError(
                                        "Confirm independent publisher-key trust before signature verification."
                                    )
                                if review_signature_upload is not None:
                                    review_signature_path = review_dir / "artifact.sig"
                                    review_signature_path.write_bytes(review_signature_upload.getvalue())

                                review_result = store.review_artifact(
                                    selected_detail,
                                    "approve",
                                    reviewer,
                                    justification,
                                    policy,
                                    public_key=review_public_key_path,
                                    signature_path=review_signature_path,
                                )
                            st.success(f"Review complete: {decision_label(review_result['decision'])}")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Approval denied: {exc}")

                    if rc2.button("Retain in review", key=f"retain_{key_for(selected_detail)}"):
                        try:
                            review_result = store.review_artifact(
                                selected_detail, "retain", reviewer, justification, policy
                            )
                            st.success("Artifact retained in review.")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Review update failed: {exc}")

                    if rc3.button("Reject / block", key=f"reject_{key_for(selected_detail)}"):
                        try:
                            review_result = store.review_artifact(
                                selected_detail, "reject", reviewer, justification, policy
                            )
                            st.success("Artifact rejected and blocked.")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Rejection failed: {exc}")

                try:
                    current = current_digest(artifact["path"])
                    if current == artifact["digest"]:
                        st.success("Integrity check passed: contents match the registered artifact.")
                    else:
                        st.error("Integrity check failed: contents differ from the registered artifact.")
                except Exception as exc:
                    st.error(f"Could not recheck artifact: {exc}")

                with store._conn() as conn:
                    lineage_rows = conn.execute(
                        "SELECT * FROM lineage WHERE artifact_id=? ORDER BY seq DESC",
                        (selected_detail,),
                    ).fetchall()

                st.markdown("### Lineage")
                if lineage_rows:
                    st.dataframe(
                        [
                            {
                                "Parent": row["parent_artifact_id"] or "External source / root",
                                "Source": row["source_uri"] or "Inherited from parent",
                                "Transformation": row["transformation"],
                                "Recorded at": row["created"],
                            }
                            for row in lineage_rows
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info("No lineage record found.")

                signed_path = attestation_path(selected_detail)
                public_path = trusted_key_path(selected_detail)
                st.markdown("### Signed provenance")
                if signed_path.is_file() and public_path.is_file():
                    envelope = json.loads(signed_path.read_text(encoding="utf-8"))
                    verification = verify_attestation(envelope, public_path)
                    try:
                        current_matches = (
                            current_digest(artifact["path"])
                            == envelope.get("payload", {}).get("artifact_digest")
                            == artifact["digest"]
                        )
                    except Exception:
                        current_matches = False

                    if verification.get("valid") and current_matches:
                        st.success("Signature verified and artifact integrity matches.")
                    elif verification.get("valid"):
                        st.error("Signature is valid, but current artifact integrity does not match.")
                    else:
                        st.error(
                            "Signature verification failed: "
                            + str(verification.get("reason", "Unknown reason"))
                        )
                    st.write("Artifact integrity:", "PASS" if current_matches else "FAIL")
                    st.download_button(
                        "Download signed attestation",
                        signed_path.read_bytes(),
                        file_name=f"{selected_detail}-attestation.json",
                        mime="application/json",
                        key=f"download_att_{key_for(selected_detail)}",
                    )
                else:
                    st.info("No signed attestation was created for this artifact.")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

elif page == "Audit Log":
    st.header("Audit Log")
    st.caption("History of registration, load attempts, lineage, review and revocation.")

    chain_valid = store.verify_audit_chain()
    if chain_valid:
        st.success("Audit hash-chain integrity: VALID")
    else:
        st.error("Audit hash-chain integrity: INVALID")

    audit = store.audit()
    if audit:
        audit_display = []
        for row in audit:
            payload = json.loads(row["payload_json"])
            audit_display.append(
                {
                    "Sequence": row["seq"],
                    "Time": row["ts"],
                    "Event": humanize(row["event"]),
                    "Details": "; ".join(
                        f"{humanize(k)}: {v}"
                        for k, v in safe_for_display(payload).items()
                        if not isinstance(v, (dict, list))
                    ),
                    "Chain status": "Recorded",
                }
            )
        st.dataframe(audit_display, use_container_width=True, hide_index=True)
        with st.expander("Inspect audit event details"):
            event_options = [
                f"{row['seq']} — {humanize(row['event'])}"
                for row in audit
            ]
            selected_event = st.selectbox("Select event", event_options)
            index = event_options.index(selected_event)
            payload = json.loads(audit[index]["payload_json"])
            payload = safe_for_display(payload)
            for key, value in payload.items():
                st.markdown(f"**{humanize(key)}**")
                render_value(value)
    else:
        st.info("No audit events recorded yet.")


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

elif page == "Policy":
    st.header("Policy")
    st.caption("These settings control how evidence influences admission, quarantine and blocking.")
    render_policy(policy)

    st.markdown("### Decision semantics")
    st.markdown(
        """
        - **ADMIT:** No configured blocking or quarantine condition was triggered.
        - **QUARANTINE / Review required:** Human review is required before the artifact is trusted.
        - **BLOCK:** A blocking condition such as an integrity mismatch or revocation was triggered.
        - **AI findings:** Can trigger quarantine under configured thresholds, but do not independently block.
        """
    )

    st.markdown("### Synthetic scanner advisory")
    st.write(
        "The optional advisory fixture is local demonstration data, not a live vulnerability feed."
    )
    if ADVISORY:
        st.write("Advisory ID:", ADVISORY.get("id", "Unknown"))
        st.write("Affected version range:", f"{ADVISORY.get('introduced', '?')} to {ADVISORY.get('fixed', 'unspecified')}")
        st.write("Source:", ADVISORY.get("source", "Local demo fixture"))
