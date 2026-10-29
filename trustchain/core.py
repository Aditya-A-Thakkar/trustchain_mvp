"""TrustChain MVP: deterministic evidence, policy, audit, and revocation."""
from __future__ import annotations
import hashlib, json, os, sqlite3, time
from pathlib import Path
from typing import Any
from .scanner import scan_picklescan
from .prechecks import run_prechecks, policy_disposition
from .ai_detector import detect_artifact
from .profiles import inferred_profile

BLOCKED = {"BLOCK"}
VALID_DECISIONS = {"ADMIT", "QUARANTINE", "BLOCK"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(path: Path) -> list[dict[str, Any]]:
    """Inventory a file or directory without executing any contents."""
    base = path.resolve()
    files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
    result = []
    for p in files:
        rel = p.name if base.is_file() else str(p.relative_to(base))
        suffix = p.suffix.lower()
        # This is a review flag, not a malware verdict.
        flags = []
        if suffix in {".py", ".sh", ".bat", ".ps1", ".js"}:
            flags.append("executable_or_loader_script_review")
        result.append({"path": rel, "size_bytes": p.stat().st_size,
                       "sha256": sha256_file(p), "extension": suffix or "[none]",
                       "flags": flags})
    return result


def aggregate_digest(items: list[dict[str, Any]]) -> str:
    canonical = [{"path": x["path"], "sha256": x["sha256"]} for x in items]
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_model_signature(
    path: Path,
    public_key: str | Path,
    signature: str | Path,
) -> dict[str, Any]:
    """Verify a model signature using model-signing's local-key backend."""
    import subprocess
    import sys

    if not path.is_file():
        return {
            "verified": False,
            "status": "ERROR",
            "stdout": "",
            "stderr": "Signature verification currently supports a single artifact file, not a directory.",
        }

    cmd = [
        sys.executable, "-m", "model_signing",
        "verify", "key", str(path),
        "--public_key", str(public_key),
        "--signature", str(signature),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        # Missing transitive dependencies (e.g. pyOpenSSL) are execution
        # failures, not evidence that the signature itself is invalid.
        import_failure = (
                "ModuleNotFoundError" in output
                or "ImportError" in output
                or "No module named" in output
        )
        status = (
            "VERIFIED" if result.returncode == 0
            else "ERROR" if import_failure
            else "INVALID"
        )
        return {
            "verified": result.returncode == 0,
            "status": status,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "verified": False,
            "status": "ERROR",
            "stdout": "",
            "stderr": str(exc),
        }


def discover_signature_sidecars(path: str | Path) -> dict[str, Any]:
    """Discover conventional sidecar signature files without trusting them.

    Supported convention for a single file: <artifact>.sig (or <stem>.sig),
    with a public key at <artifact>.pub, <stem>.pub, or sibling public.pem.
    A discovered key is only candidate material; it is not proof that the key
    belongs to a trusted publisher.
    """
    p = Path(path)
    result: dict[str, Any] = {
        "status": "NOT_FOUND", "signature_path": None,
        "public_key_path": None, "verified": False,
        "trust_note": "A discovered public key is not trusted unless independently verified.",
    }
    if not p.is_file():
        result["status"] = "UNSUPPORTED"
        result["message"] = "Automatic sidecar discovery supports a single file only."
        return result
    sig_candidates = [Path(str(p) + ".sig"), p.with_suffix(".sig")]
    key_candidates = [Path(str(p) + ".pub"), p.with_suffix(".pub"), p.parent / "public.pem"]
    sig = next((x for x in sig_candidates if x.is_file()), None)
    key = next((x for x in key_candidates if x.is_file()), None)
    if sig is None:
        result["message"] = "No conventional signature sidecar was found."
        return result
    result.update({"signature_path": str(sig), "public_key_path": str(key) if key else None})
    if key is None:
        result.update({"status": "FOUND_UNVERIFIED", "message": "Signature sidecar found, but no public key sidecar was found."})
    else:
        result.update({"status": "FOUND_UNVERIFIED", "message": "Signature and candidate public key found; verification and publisher trust are still required."})
    return result


def version_tuple(v: str) -> tuple[int, ...]:
    # Sufficient for numeric dotted versions used in the MVP advisory fixtures.
    nums = []
    for part in v.strip().lstrip("v").split("."):
        digits = "".join(c for c in part if c.isdigit())
        nums.append(int(digits or 0))
    return tuple(nums)


def version_in_range(version: str, introduced: str, fixed: str | None) -> bool:
    v, lo = version_tuple(version), version_tuple(introduced)
    width = max(len(v), len(lo), len(version_tuple(fixed)) if fixed else 0)
    pad = lambda x: x + (0,) * (width - len(x))
    if pad(v) < pad(lo): return False
    if fixed is None: return True
    return pad(v) < pad(version_tuple(fixed))


def scanner_advisory_evidence(scanner: str, version: str, advisory: dict[str, Any]) -> dict[str, Any]:
    affected = version_in_range(version, advisory["introduced"], advisory.get("fixed"))
    return {"check": "scanner_advisory", "scanner": scanner, "version": version,
            "advisory_id": advisory["id"], "affected": affected,
            "source": advisory.get("source", "local demo fixture"),
            "finding": "scanner version falls in affected range" if affected else "version outside configured affected range"}


def decide(evidence: dict[str, Any], policy: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    # Hard facts first.
    if evidence.get("digest_mismatch"):
        return "BLOCK", ["Artifact digest differs from the approved digest."]
    if evidence.get("revoked"):
        return "BLOCK", ["Artifact has been revoked."]
    if evidence.get("parent_blocked"):
        return "QUARANTINE", [
            "A parent artifact is blocked, revoked, or has failed integrity verification; review is required."
        ]

    prechecks = evidence.get("prechecks", {})
    if prechecks:
        precheck_decision, precheck_reasons = policy_disposition(prechecks, policy)
        if precheck_decision == "BLOCK":
            return "BLOCK", precheck_reasons

    ai = evidence.get("ai_detector", {})
    specialists = ai.get("nvidia_specialists", {})
    if policy.get("specialist_detection_required", False):
        detector_results = specialists.get("detectors", {})
        expected_detectors = {
            "nemoguard_jailbreak_detect",
            "nemoguard_content_safety",
            "gliner_pii",
        }

        missing = expected_detectors - set(detector_results)
        incomplete = [
            name for name in expected_detectors
            if name in detector_results
            and detector_results[name].get("status") != "COMPLETED"
        ]

        if specialists.get("status") != "COMPLETED" or missing or incomplete:
            unavailable = sorted(missing | set(incomplete))
            return policy.get("ai_unavailable", "QUARANTINE"), [
                "Required NVIDIA specialist coverage is incomplete. "
                "The artifact is not cleared without the configured checks.",
                "Unavailable or incomplete detectors: "
                + (", ".join(unavailable) if unavailable else "overall specialist status"),
            ]
    if ai.get("status") == "COMPLETED":
        ai_findings = ai.get("findings", [])
        if not isinstance(ai_findings, list):
            ai_findings = []

        # Specialist findings are preserved as explicit policy signals.
        # PII is a review trigger by default, not an automatic BLOCK.
        pii_findings = [
            f for f in ai_findings
            if isinstance(f, dict)
               and str(f.get("category", "")).lower() in {
                   "pii_exposure",
                   "personal_information",
                   "sensitive_data_exposure",
               }
        ]
        if pii_findings:
            pii_decision = policy.get("pii_finding", "QUARANTINE")
            if pii_decision != "ADMIT":
                return pii_decision, [
                    "A specialist detector identified potentially sensitive personal information; review is required.",
                    *[
                        str(f.get("title", "Potential PII exposure"))[:240]
                        for f in pii_findings[:5]
                    ],
                ]

        threshold = int(policy.get("ai_quarantine_risk_score", 60))
        min_confidence = float(
            policy.get("ai_min_confidence_for_quarantine", 0.55)
        )
        try:
            risk_score = int(ai.get("risk_score") or 0)
            confidence = float(ai.get("confidence") or 0)
        except (TypeError, ValueError):
            risk_score, confidence = 0, 0.0

        high_findings = any(
            isinstance(f, dict)
            and str(f.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
            for f in ai_findings
        )

        if (
                risk_score >= threshold and confidence >= min_confidence
        ) or high_findings:
            return policy.get("ai_finding", "QUARANTINE"), [
                f"NVIDIA AI analysis identified risk indicators "
                f"(risk_score={risk_score}, confidence={confidence:.2f}); "
                "human review is required."
            ]

        # A non-empty specialist finding must not be erased merely because
        # the aggregate risk score is below the generic threshold.
        if ai.get("nvidia_specialists", {}).get("findings"):
            specialist_findings = ai["nvidia_specialists"]["findings"]
            if specialist_findings:
                return policy.get("specialist_finding", "QUARANTINE"), [
                    "A specialist NVIDIA detector returned findings; human review is required."
                ]

    elif policy.get("ai_detection_required", False):
        return policy.get("ai_unavailable", "QUARANTINE"), [
            f"NVIDIA AI detection is required but status is "
            f"{ai.get('status', 'NOT_RUN')}; artifact is not cleared without AI coverage."
        ]

    signature = evidence.get("signature_verification", {})
    if signature.get("status") in {"INVALID", "ERROR"}:
        return "QUARANTINE", [
            "Model signature verification failed or could not be completed."
        ]

    scan = evidence.get("model_scan", {})
    if scan.get("status") == "FINDINGS":
        return "QUARANTINE", ["PickleScan reported suspicious or dangerous model content; manual review is required."]
    if scan.get("status") == "ERROR":
        return "QUARANTINE", ["Model scan failed; absence of scanner evidence is not a clean result."]
    if evidence.get("known_malicious_pickle"):
        return "BLOCK", ["Scanner reported a known unsafe pickle finding."]
    if evidence.get("scanner_affected") and policy.get("affected_scanner", "QUARANTINE") != "ADMIT":
        decision = policy.get("affected_scanner", "QUARANTINE")
        reasons.append("Scanner version is within the configured affected advisory range.")
        return decision, reasons
    if evidence.get("unsigned") and policy.get("unsigned_artifact", "QUARANTINE") != "ADMIT":
        reasons.append("No verified publisher signature is available; hash alone does not establish publisher identity.")
        return policy.get("unsigned_artifact", "QUARANTINE"), reasons
    if evidence.get("review_flags") and policy.get("review_flag", "QUARANTINE") != "ADMIT":
        reasons.append("Inventory contains file types requiring review under policy.")
        return policy.get("review_flag", "QUARANTINE"), reasons
    if prechecks:
        precheck_decision, precheck_reasons = policy_disposition(prechecks, policy)
        if precheck_decision:
            return precheck_decision, precheck_reasons
    reasons.append("No configured blocking or quarantine condition was triggered.")
    return "ADMIT", reasons


class TrustChainStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, path TEXT NOT NULL, digest TEXT NOT NULL, evidence_json TEXT NOT NULL, decision TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS usage (artifact_id TEXT NOT NULL, agent_id TEXT NOT NULL, used REAL NOT NULL, PRIMARY KEY(artifact_id, agent_id))")
            c.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL, payload_json TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS lineage (seq INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL, parent_artifact_id TEXT, source_uri TEXT, transformation TEXT NOT NULL, artifact_digest TEXT NOT NULL, parent_digest TEXT, created REAL NOT NULL)")

    def _conn(self):
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    def _audit(self, c, event: str, payload: dict[str, Any]):
        row = c.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["entry_hash"] if row else "0" * 64
        ts = time.time(); raw = json.dumps({"ts": ts, "event": event, "payload": payload, "prev_hash": prev}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        c.execute("INSERT INTO audit(ts,event,payload_json,prev_hash,entry_hash) VALUES(?,?,?,?,?)", (ts,event,json.dumps(payload,sort_keys=True),prev,digest))

    def register(self, artifact_id: str, path: str | Path, policy: dict[str, Any], unsigned: bool = True,
                 scanner_name: str = "picklescan", scanner_version: str = "unknown",
                 advisory: dict[str, Any] | None = None,
                 public_key: str | Path | None = None,
                 signature_path: str | Path | None = None,
                 artifact_type: str = "Model",
                 purpose: str = "",
                 parent_artifact_id: str | None = None,
                 source_uri: str | None = None,
                 transformation: str | None = None,
             ) -> dict[str, Any]:
        p = Path(path)
        if not p.exists(): raise FileNotFoundError(p)
        transformation = (transformation or "").strip()
        source_uri = source_uri.strip() if source_uri else None

        if not transformation:
            raise ValueError("A transformation / import event is required.")

        if parent_artifact_id == artifact_id:
            raise ValueError("Artifact cannot be its own parent.")

        if parent_artifact_id is None and not source_uri:
            raise ValueError("Provide a parent artifact or a source URI.")

        if parent_artifact_id is not None and source_uri:
            raise ValueError("Provide either a parent artifact or a source URI, not both.")
        with self._conn() as c:
            existing = c.execute("SELECT id FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if existing:
            raise ValueError(f"Artifact ID {artifact_id!r} is already registered. Choose a new ID; registration cannot replace its approved digest.")
        items = inventory(p); digest = aggregate_digest(items)
        model_scan = scan_picklescan(p) if artifact_type.strip().lower() == "model" else {
            "scanner": "picklescan", "status": "NOT_SCANNED", "scanned_files": 0,
            "infected_files": 0, "suspicious_globals": 0, "dangerous_globals": 0,
            "version": None, "error": "PickleScan is only applicable to model artifacts",
        }
        prechecks = run_prechecks(p, artifact_type, model_scan=model_scan, policy=policy)
        capability_profile = inferred_profile(artifact_type)
        # AI detection is part of registration, not an optional post-registration advisory.
        ai_detector = detect_artifact(p, artifact_type, purpose)
        ai_verdict = "NOT_CHECKED"
        ai_message = f"NVIDIA AI detector status: {ai_detector.get('status', 'UNKNOWN')}"
        if ai_detector.get("status") == "COMPLETED":
            threshold = int(policy.get("ai_quarantine_risk_score", 60))
            min_confidence = float(policy.get("ai_min_confidence_for_quarantine", 0.55))
            high_findings = any(str(f.get("severity", "")).upper() in {"HIGH", "CRITICAL"} for f in ai_detector.get("findings", []))
            risk_triggered = (ai_detector.get("verdict") == "FINDINGS" and int(ai_detector.get("risk_score", 0)) >= threshold and float(ai_detector.get("confidence", 0)) >= min_confidence) or high_findings
            ai_verdict = "FINDINGS" if risk_triggered else ("PASS" if ai_detector.get("verdict") in {"PASS", "FINDINGS"} else "NOT_CHECKED")
            ai_message = ai_detector.get("summary", ai_message)
        elif ai_detector.get("status") == "ERROR":
            ai_verdict = "ERROR"
        prechecks.setdefault("checks", []).append({
            "check": "nvidia_ai_artifact_detection", "severity": "HIGH" if ai_verdict == "FINDINGS" else "INFO",
            "evidence": {"status": ai_detector.get("status"), "verdict": ai_detector.get("verdict"), "risk_score": ai_detector.get("risk_score"), "confidence": ai_detector.get("confidence"), "findings": ai_detector.get("findings", []), "model": ai_detector.get("model")},
            "verdict": ai_verdict, "message": ai_message, "hard_block": False,
        })
        prechecks["counts"] = {v: sum(1 for check in prechecks.get("checks", []) if check.get("verdict") == v) for v in ("PASS", "FINDINGS", "NOT_CHECKED", "ERROR")}
        signature_verification = {
            "status": "NOT_PROVIDED",
            "verified": False,
        }
        signature_discovery = discover_signature_sidecars(p)
        if signature_discovery.get("status") == "FOUND_UNVERIFIED":
            signature_verification = {
                "status": "FOUND_UNVERIFIED", "verified": False,
                "discovery": signature_discovery,
            }

        if public_key is not None or signature_path is not None:
            if public_key is None or signature_path is None:
                signature_verification = {
                    "status": "ERROR",
                    "verified": False,
                    "stderr": "Both public_key and signature_path are required.",
                }
            elif not Path(public_key).is_file() or not Path(signature_path).is_file():
                signature_verification = {
                    "status": "ERROR",
                    "verified": False,
                    "stderr": "Public key or signature file does not exist.",
                }
            else:
                signature_verification = verify_model_signature(
                    p, public_key, signature_path
                )

        # Never trust the caller's `unsigned` flag as proof of publisher identity.
        # An artifact is signed only when verification actually succeeded.
        signature_verified = (
                signature_verification.get("status") == "VERIFIED"
                and signature_verification.get("verified") is True
        )
        unsigned = not signature_verified
        adv = scanner_advisory_evidence(scanner_name, scanner_version, advisory) if advisory else None
        evidence = {"artifact_id": artifact_id, "artifact_type": artifact_type, "path": str(p.resolve()), "digest": digest,
                    "files": items, "unsigned": unsigned, "model_scan": model_scan,
                    "prechecks": prechecks,
                    "purpose": purpose,
                    "ai_detector": ai_detector,
                    "scanner": {"name": scanner_name, "version": scanner_version},
                    "scanner_advisory": adv,
                    "scanner_affected": bool(adv and adv["affected"]),
                    "review_flags": [f"{x['path']}: {','.join(x['flags'])}" for x in items if x["flags"]],
                    "digest_mismatch": False, "revoked": False,
                    "signature_verification": signature_verification,
                    "signature_discovery": signature_discovery,
                    "capability_profile": capability_profile,
        }
        decision, reasons = decide(evidence, policy)
        evidence["decision_reasons"] = reasons
        with self._conn() as c:
            # Validate the parent in the same transaction that writes the child.
            parent_digest = None
            if parent_artifact_id is not None:
                parent = c.execute(
                    """
                    SELECT id, path, digest, decision, revoked
                    FROM artifacts
                    WHERE id = ?
                    """,
                    (parent_artifact_id,),
                ).fetchone()

                if not parent:
                    raise KeyError(
                        f"Unknown parent artifact: {parent_artifact_id}"
                    )

                if parent["revoked"] or parent["decision"] != "ADMIT":
                    raise ValueError(
                        "Parent must be non-revoked and ADMIT before registering a child."
                    )

                live_parent_digest = aggregate_digest(
                    inventory(Path(parent["path"]))
                )
                if live_parent_digest != parent["digest"]:
                    raise ValueError(
                        "Parent integrity mismatch; child registration denied."
                    )

                parent_digest = parent["digest"]

            # Artifact, lineage, and audit events share this transaction.
            c.execute(
                """
                INSERT INTO artifacts
                    (id, path, digest, evidence_json, decision, revoked, created)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    str(p.resolve()),
                    digest,
                    json.dumps(evidence, sort_keys=True),
                    decision,
                    0,
                    time.time(),
                ),
            )

            self._audit(
                c,
                "REGISTER",
                {
                    "artifact_id": artifact_id,
                    "digest": digest,
                    "decision": decision,
                    "reasons": reasons,
                    "model_scan": model_scan,
                    "signature_status": signature_verification.get(
                        "status", "NOT_PROVIDED"
                    ),
                    "ai_detector_status": ai_detector.get("status"),
                    "ai_detector_verdict": ai_detector.get("verdict"),
                    "ai_risk_score": ai_detector.get("risk_score"),
                    "precheck_counts": prechecks.get("counts", {}),
                    "precheck_hard_blocks": prechecks.get(
                        "hard_block_checks", []
                    ),
                },
            )

            lineage = {
                "artifact_id": artifact_id,
                "parent_artifact_id": parent_artifact_id,
                "source_uri": source_uri,
                "transformation": transformation,
                "artifact_digest": digest,
                "parent_digest": parent_digest,
            }

            c.execute(
                """
                INSERT INTO lineage
                (artifact_id, parent_artifact_id, source_uri,
                 transformation, artifact_digest, parent_digest, created)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    parent_artifact_id,
                    source_uri,
                    transformation,
                    digest,
                    parent_digest,
                    time.time(),
                ),
            )

            self._audit(c, "LINEAGE_RECORD", lineage)

        return {
            "artifact_id": artifact_id,
            "digest": digest,
            "decision": decision,
            "reasons": reasons,
            "evidence": evidence,
            "lineage": lineage,
        }

    def review_artifact(
        self,
        artifact_id: str,
        action: str,
        reviewer: str,
        justification: str,
        policy: dict[str, Any],
        public_key: str | Path | None = None,
        signature_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Apply an auditable human review without bypassing deterministic policy.

        Actions: approve (re-evaluate policy and admit only if it returns ADMIT),
        retain (remain quarantined), reject (BLOCK). Revoked artifacts and hard
        blocks cannot be manually admitted. Approval also rechecks the live digest.
        """
        action = action.strip().lower()
        reviewer = reviewer.strip()
        justification = justification.strip()
        if action not in {"approve", "retain", "reject"}:
            raise ValueError("Action must be approve, retain, or reject.")
        if not reviewer:
            raise ValueError("Reviewer identity is required.")
        if not justification:
            raise ValueError("A review justification is required.")
        with self._conn() as c:
            row = c.execute(
                "SELECT id,path,digest,evidence_json,decision,revoked FROM artifacts WHERE id=?",
                (artifact_id,),
            ).fetchone()
            if not row:
                raise KeyError(f"Unknown artifact: {artifact_id}")
            evidence = json.loads(row["evidence_json"])
            old_decision = row["decision"]
            if old_decision != "QUARANTINE":
                raise ValueError("Human review actions are only available for artifacts currently in Review required.")
            if row["revoked"] or evidence.get("revoked"):
                raise ValueError("Revoked artifacts cannot be approved or moved out of BLOCK.")
            if old_decision == "BLOCK" or evidence.get("digest_mismatch") or evidence.get("known_malicious_pickle"):
                raise ValueError("Hard-blocked artifacts cannot be manually approved. Fix the cause and register a new artifact version.")
            if action == "approve":
                if public_key is not None or signature_path is not None:
                    if public_key is None or signature_path is None:
                        raise ValueError("To verify a publisher signature, provide both a public key and signature file.")
                    verified_signature = verify_model_signature(Path(row["path"]), public_key, signature_path)
                    evidence["signature_verification"] = verified_signature
                    evidence["unsigned"] = not bool(verified_signature.get("verified"))
                    if not verified_signature.get("verified"):
                        raise ValueError("Publisher signature was not verified: " + str(verified_signature.get("status")))
                try:
                    live_digest = aggregate_digest(inventory(Path(row["path"])))
                except (OSError, ValueError) as exc:
                    raise ValueError(f"Artifact could not be re-inventoried; approval denied: {exc}") from exc
                if live_digest != row["digest"]:
                    raise ValueError("Artifact contents changed since registration. Approval denied; register the repaired artifact as a new version.")
                if evidence.get("parent_blocked"):
                    raise ValueError("Artifact has a blocked/revoked parent and cannot be approved until lineage is resolved.")
                computed, reasons = decide(evidence, policy)
                if computed != "ADMIT":
                    raise ValueError(
                        "Policy still does not permit admission (" + computed + "): " + "; ".join(reasons)
                    )
                new_decision = "ADMIT"
            elif action == "reject":
                new_decision = "BLOCK"
                reasons = [f"Rejected during human review by {reviewer}: {justification}"]
            else:
                new_decision = "QUARANTINE"
                reasons = [f"Retained in review by {reviewer}: {justification}"]
            evidence["decision_reasons"] = reasons
            evidence["last_review"] = {
                "reviewer": reviewer, "action": action.upper(),
                "justification": justification, "previous_decision": old_decision,
                "resulting_decision": new_decision, "timestamp": time.time(),
            }
            c.execute(
                "UPDATE artifacts SET evidence_json=?, decision=? WHERE id=?",
                (json.dumps(evidence, sort_keys=True), new_decision, artifact_id),
            )
            self._audit(c, "HUMAN_REVIEW", {
                "artifact_id": artifact_id, "reviewer": reviewer,
                "action": action.upper(), "justification": justification,
                "previous_decision": old_decision, "resulting_decision": new_decision,
                "reasons": reasons,
            })
            if new_decision == "BLOCK":
                descendants = self._quarantine_descendants(c, artifact_id, "parent rejected during human review")
            else:
                descendants = []
            return {"artifact_id": artifact_id, "decision": new_decision,
                    "previous_decision": old_decision, "reasons": reasons,
                    "descendants_quarantined": descendants}

    def _quarantine_descendants(self, c, parent_artifact_id: str, reason: str) -> list[str]:
        """Quarantine every registered descendant of a blocked/revoked parent.

        The lineage table is the source of parent-child relationships. A visited set
        prevents loops in malformed historical data. Revoked artifacts remain BLOCK.
        """
        queue = [parent_artifact_id]
        visited = {parent_artifact_id}
        quarantined: list[str] = []
        while queue:
            parent_id = queue.pop(0)
            children = c.execute(
                "SELECT DISTINCT artifact_id FROM lineage WHERE parent_artifact_id=?",
                (parent_id,),
            ).fetchall()
            for child_row in children:
                child_id = child_row["artifact_id"]
                if child_id in visited:
                    continue
                visited.add(child_id)
                queue.append(child_id)
                row = c.execute(
                    "SELECT evidence_json, decision, revoked FROM artifacts WHERE id=?",
                    (child_id,),
                ).fetchone()
                if not row:
                    continue
                if not row["revoked"]:
                    evidence = json.loads(row["evidence_json"])
                    evidence["parent_blocked"] = True
                    evidence["parent_block_reason"] = reason
                    existing_reasons = evidence.get("decision_reasons", [])
                    inherited_reason = f"Parent artifact {parent_id!r} is blocked or revoked; review is required."
                    evidence["decision_reasons"] = list(dict.fromkeys([*existing_reasons, inherited_reason]))
                    # Preserve an artifact's own BLOCK decision; otherwise quarantine it.
                    decision = "BLOCK" if row["decision"] == "BLOCK" else "QUARANTINE"
                    c.execute(
                        "UPDATE artifacts SET decision=?, evidence_json=? WHERE id=?",
                        (decision, json.dumps(evidence, sort_keys=True), child_id),
                    )
                    quarantined.append(child_id)
                    self._audit(c, "PARENT_IMPACT_QUARANTINE", {
                        "artifact_id": child_id,
                        "blocked_parent_id": parent_id,
                        "reason": reason,
                        "decision": decision,
                    })
        return quarantined

    def load(self, artifact_id: str, agent_id: str, policy: dict[str, Any]) -> dict[str, Any]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if not row:
                raise KeyError(f"Unknown artifact: {artifact_id}")
            current = aggregate_digest(inventory(Path(row["path"])))
            revoked = bool(row["revoked"])
            evidence = json.loads(row["evidence_json"])
            evidence["digest_mismatch"] = current != row["digest"]
            evidence["revoked"] = revoked
            lineage_row = c.execute(
                """
                SELECT parent_artifact_id
                FROM lineage
                WHERE artifact_id=?
                ORDER BY seq DESC
                LIMIT 1
                """,
                (artifact_id,),
            ).fetchone()

            parent_blocked = False
            parent_reason = None

            if lineage_row and lineage_row["parent_artifact_id"]:
                parent_id = lineage_row["parent_artifact_id"]
                parent = c.execute(
                    """
                    SELECT path, digest, decision, revoked
                    FROM artifacts
                    WHERE id=?
                    """,
                    (parent_id,),
                ).fetchone()

                if parent is None:
                    parent_blocked = True
                    parent_reason = f"Parent artifact {parent_id!r} is missing."
                elif parent["revoked"] or parent["decision"] != "ADMIT":
                    parent_blocked = True
                    parent_reason = (
                        f"Parent artifact {parent_id!r} is blocked or revoked."
                    )
                else:
                    try:
                        live_parent_digest = aggregate_digest(
                            inventory(Path(parent["path"]))
                        )
                        if live_parent_digest != parent["digest"]:
                            parent_blocked = True
                            parent_reason = (
                                f"Parent artifact {parent_id!r} has changed since registration."
                            )
                    except (OSError, ValueError):
                        parent_blocked = True
                        parent_reason = (
                            f"Parent artifact {parent_id!r} could not be verified."
                        )

            evidence["parent_blocked"] = parent_blocked
            if parent_reason:
                evidence["parent_block_reason"] = parent_reason
            decision, reasons = decide(evidence, policy)

            # Registration decisions are not silently promoted at load time.
            if row["decision"] != "ADMIT" and decision == "ADMIT":
                decision = row["decision"]
                reasons = ["Artifact was not admitted at registration; re-register a repaired version under a new ID after review."]

            if evidence["digest_mismatch"] and not revoked:
                decision = "BLOCK"
                reasons = ["Artifact digest differs from the registered digest. The artifact is blocked and its descendants require review."]
                evidence["decision_reasons"] = reasons
                c.execute(
                    "UPDATE artifacts SET decision='BLOCK', evidence_json=? WHERE id=?",
                    (json.dumps(evidence, sort_keys=True), artifact_id),
                )
                self._audit(c, "INTEGRITY_BLOCK", {
                    "artifact_id": artifact_id,
                    "reason": "digest mismatch detected during load",
                })
                affected = self._quarantine_descendants(c, artifact_id, "parent integrity mismatch")
            elif revoked:
                affected = self._quarantine_descendants(c, artifact_id, "parent revoked")
            elif decision == "BLOCK":
                affected = self._quarantine_descendants(c, artifact_id, "parent blocked")
            else:
                affected = []

            if decision == "ADMIT":
                c.execute(
                    "INSERT OR REPLACE INTO usage(artifact_id,agent_id,used) VALUES(?,?,?)",
                    (artifact_id, agent_id, time.time()),
                )
            self._audit(c, "LOAD_ATTEMPT", {
                "artifact_id": artifact_id,
                "agent_id": agent_id,
                "decision": decision,
                "current_digest": current,
                "approved_digest": row["digest"],
                "reasons": reasons,
                "descendants_quarantined": affected,
            })
            return {
                "artifact_id": artifact_id,
                "agent_id": agent_id,
                "decision": decision,
                "reasons": reasons,
                "current_digest": current,
                "approved_digest": row["digest"],
                "descendants_quarantined": affected,
            }

    def revoke(self, artifact_id: str, reason: str = "manual revocation") -> list[str]:
        with self._conn() as c:
            row = c.execute("SELECT id FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if not row:
                raise KeyError(f"Unknown artifact: {artifact_id}")
            c.execute("UPDATE artifacts SET revoked=1, decision='BLOCK' WHERE id=?", (artifact_id,))
            agents = [r["agent_id"] for r in c.execute(
                "SELECT agent_id FROM usage WHERE artifact_id=? ORDER BY agent_id", (artifact_id,)
            ).fetchall()]
            descendants = self._quarantine_descendants(c, artifact_id, reason or "parent revoked")
            self._audit(c, "REVOKE", {
                "artifact_id": artifact_id,
                "reason": reason,
                "affected_agents": agents,
                "descendants_quarantined": descendants,
            })
            return agents

    def record_lineage(
        self,
        artifact_id: str,
        transformation: str,
        parent_artifact_id: str | None = None,
        source_uri: str | None = None,
    ) -> dict[str, Any]:
        """Record declared provenance for a registered artifact."""
        transformation = transformation.strip()
        if not transformation:
            raise ValueError("transformation must not be empty")
        if parent_artifact_id == artifact_id:
            raise ValueError("Artifact cannot be its own parent")
        if parent_artifact_id is None and not (source_uri and source_uri.strip()):
            raise ValueError("Provide a parent artifact or declared source URI")
        if parent_artifact_id is not None and source_uri:
            raise ValueError("Provide either parent_artifact_id or source_uri")

        with self._conn() as c:
            artifact = c.execute(
                "SELECT id, digest FROM artifacts WHERE id=?", (artifact_id,)
            ).fetchone()
            if not artifact:
                raise KeyError(f"Unknown artifact: {artifact_id}")

            parent_digest = None
            if parent_artifact_id is not None:
                parent = c.execute(
                    """
                    SELECT id, path, digest, decision, revoked
                    FROM artifacts
                    WHERE id = ?
                    """,
                    (parent_artifact_id,),
                ).fetchone()

                if not parent:
                    raise KeyError(
                        f"Unknown parent artifact: {parent_artifact_id}"
                    )

                if parent["revoked"] or parent["decision"] != "ADMIT":
                    raise ValueError(
                        "Parent must be non-revoked and ADMIT before lineage can be recorded."
                    )

                try:
                    live_parent_digest = aggregate_digest(
                        inventory(Path(parent["path"]))
                    )
                except (OSError, ValueError) as exc:
                    raise ValueError(
                        f"Could not verify parent integrity: {exc}"
                    ) from exc

                if live_parent_digest != parent["digest"]:
                    raise ValueError(
                        "Parent integrity mismatch; lineage cannot be recorded."
                    )

                parent_digest = parent["digest"]

            source = source_uri.strip() if source_uri else None
            payload = {
                "artifact_id": artifact_id,
                "parent_artifact_id": parent_artifact_id,
                "source_uri": source,
                "transformation": transformation,
                "artifact_digest": artifact["digest"],
                "parent_digest": parent_digest,
            }
            c.execute(
                """INSERT INTO lineage
                (artifact_id,parent_artifact_id,source_uri,transformation,
                 artifact_digest,parent_digest,created)
                VALUES(?,?,?,?,?,?,?)""",
                (
                    artifact_id, parent_artifact_id, source, transformation,
                    artifact["digest"], parent_digest, time.time(),
                ),
            )
            self._audit(c, "LINEAGE_RECORD", payload)
            return payload

    def verify_lineage(self) -> dict[str, Any]:
        """Verify recorded artifact and parent digests against current state."""
        issues = []
        checked = 0

        with self._conn() as c:
            rows = c.execute("SELECT * FROM lineage ORDER BY seq").fetchall()

            for row in rows:
                checked += 1
                aid = row["artifact_id"]
                artifact = c.execute(
                    "SELECT path,digest FROM artifacts WHERE id=?", (aid,)
                ).fetchone()

                if not artifact:
                    issues.append({
                        "artifact_id": aid,
                        "issue": "Registered artifact is missing",
                    })
                    continue

                if artifact["digest"] != row["artifact_digest"]:
                    issues.append({
                        "artifact_id": aid,
                        "issue": "Registered digest differs from lineage snapshot",
                    })

                try:
                    current = aggregate_digest(inventory(Path(artifact["path"])))
                    if current != row["artifact_digest"]:
                        issues.append({
                            "artifact_id": aid,
                            "issue": "Artifact contents changed since lineage was recorded",
                        })
                except (OSError, ValueError) as exc:
                    issues.append({
                        "artifact_id": aid,
                        "issue": f"Could not verify artifact contents: {exc}",
                    })

                parent_id = row["parent_artifact_id"]
                if parent_id:
                    parent = c.execute(
                        "SELECT path,digest FROM artifacts WHERE id=?", (parent_id,)
                    ).fetchone()
                    if not parent:
                        issues.append({
                            "artifact_id": aid,
                            "issue": f"Parent artifact {parent_id!r} is missing",
                        })
                    else:
                        if parent["digest"] != row["parent_digest"]:
                            issues.append({
                                "artifact_id": aid,
                                "issue": "Parent digest differs from lineage snapshot",
                            })

                        try:
                            parent_current = aggregate_digest(
                                inventory(Path(parent["path"]))
                            )
                            if parent_current != row["parent_digest"]:
                                issues.append({
                                    "artifact_id": parent_id,
                                    "issue": "Parent artifact contents changed since lineage was recorded",
                                })
                        except (OSError, ValueError) as exc:
                            issues.append({
                                "artifact_id": parent_id,
                                "issue": f"Could not verify parent artifact contents: {exc}",
                            })
                elif not row["source_uri"]:
                    issues.append({
                        "artifact_id": aid,
                        "issue": "Root artifact has no declared source URI",
                    })

        return {
            "valid": not issues,
            "records_checked": checked,
            "issues": issues,
        }

    def artifacts(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT id,path,digest,evidence_json,decision,revoked,created FROM artifacts ORDER BY created DESC").fetchall()
            result = []
            for row in rows:
                item = dict(row)
                try:
                    evidence = json.loads(item.pop("evidence_json"))
                except (TypeError, json.JSONDecodeError):
                    evidence = {}
                item["artifact_type"] = evidence.get("artifact_type", "Model")
                item["evidence"] = evidence
                result.append(item)
            return result

    def attach_analysis(self, artifact_id: str, analysis: dict[str, Any]) -> None:
        """Persist advisory analysis without allowing it to alter the policy decision."""
        with self._conn() as c:
            row = c.execute("SELECT evidence_json, decision FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if not row:
                raise KeyError(f"Unknown artifact: {artifact_id}")
            evidence = json.loads(row["evidence_json"])
            evidence["ai_analysis"] = analysis
            c.execute("UPDATE artifacts SET evidence_json=? WHERE id=?", (json.dumps(evidence, sort_keys=True), artifact_id))
            self._audit(c, "AI_ADVISORY", {"artifact_id": artifact_id, "mode": analysis.get("mode"), "decision_unchanged": row["decision"]})

    def audit(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY seq").fetchall()]

    def verify_audit_chain(self) -> bool:
        prev = "0" * 64
        for row in self.audit():
            raw = json.dumps({"ts": row["ts"], "event": row["event"], "payload": json.loads(row["payload_json"]), "prev_hash": prev}, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(raw.encode()).hexdigest()
            if row["prev_hash"] != prev or row["entry_hash"] != expected: return False
            prev = row["entry_hash"]
        return True


def default_policy() -> dict[str, Any]:
    return {
        "affected_scanner": "QUARANTINE",
        "unsigned_artifact": "QUARANTINE",
        "review_flag": "QUARANTINE",
        "precheck_finding": "QUARANTINE",
        "high_severity_finding": "QUARANTINE",
        "non_safetensors_model": "BLOCK",
        "ai_detection_required": False,
        "ai_finding": "QUARANTINE",
        "ai_unavailable": "QUARANTINE",
        "ai_quarantine_risk_score": 60,
        "ai_min_confidence_for_quarantine": 0.55,
        "pii_finding": "QUARANTINE",
        "specialist_finding": "QUARANTINE",
        "specialist_detection_required": False,
    }


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    if path is None: return default_policy()
    raw = Path(path).read_text()
    try:
        import yaml  # optional dependency; PyYAML supports ordinary YAML policy files
        data = yaml.safe_load(raw)
    except ImportError:
        data = json.loads(raw)  # JSON is valid YAML 1.2, retained as a no-dependency fallback
    if not isinstance(data, dict):
        raise ValueError("Policy must be a mapping")
    decision_keys = {
        "affected_scanner",
        "unsigned_artifact",
        "review_flag",
        "precheck_finding",
        "high_severity_finding",
        "non_safetensors_model",
        "pii_finding",
        "specialist_finding",
    }

    for key, value in data.items():
        if key in decision_keys and value not in VALID_DECISIONS:
            raise ValueError(
                f"Invalid policy decision for {key}: {value}"
            )

    # AI-derived findings must never directly block an artifact.
    ai_disposition_keys = {"ai_finding", "pii_finding", "specialist_finding"}
    for key in ai_disposition_keys:
        if data.get(key) == "BLOCK":
            raise ValueError(
                f"{key} cannot be BLOCK; AI findings may quarantine but not block."
            )
    return data
