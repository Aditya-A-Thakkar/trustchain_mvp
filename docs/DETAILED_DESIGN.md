# TrustChain MVP
### Evidence-Based Trust and Risk Assessment for AI Artifacts

TrustChain is a research prototype for evaluating the trustworthiness of AI-related artifacts before they are admitted into a system. It combines deterministic security checks, artifact integrity verification, scanner evidence, NVIDIA-backed AI risk analysis, policy-based decisions, provenance tracking, and an append-only audit history.

The project is designed to demonstrate how trust decisions can be made from recorded evidence rather than relying solely on a file's name, source, or declared purpose.

> **Important:** TrustChain is an MVP, not a production security certification system. Detection coverage depends on the artifact type, available scanners, configuration, and successful execution of the relevant checks. A clean result does not prove that an artifact is safe.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Design Principles](#3-goals-and-design-principles)
4. [System Architecture](#4-system-architecture)
5. [Supported Artifact Types](#5-supported-artifact-types)
6. [End-to-End Workflow](#6-end-to-end-workflow)
7. [Registration and Precheck Pipeline](#7-registration-and-precheck-pipeline)
8. [NVIDIA AI Detection](#8-nvidia-ai-detection)
9. [Policy and Final Decisions](#9-policy-and-final-decisions)
10. [Streamlit UI Guide](#10-streamlit-ui-guide)
11. [Integrity, Signatures and Provenance](#11-integrity-signatures-and-provenance)
12. [Lineage Tracking](#12-lineage-tracking)
13. [Audit Logging](#13-audit-logging)
14. [Project Structure](#14-project-structure)
15. [Installation and Setup](#15-installation-and-setup)
16. [Configuration](#16-configuration)
17. [Running TrustChain](#17-running-trustchain)
18. [Demonstration Scenarios](#18-demonstration-scenarios)
19. [Testing and Troubleshooting](#19-testing-and-troubleshooting)
20. [Security Considerations](#20-security-considerations)
21. [Current Limitations and Future Work](#21-current-limitations-and-future-work)
22. [Frequently Asked Questions](#22-frequently-asked-questions)
23. [Glossary](#23-glossary)

---

## 1. Project Overview

AI systems increasingly depend on artifacts obtained from external sources, including:

- Training and evaluation datasets
- Machine-learning models and model weights
- AI agents and automation code
- Tools, packages and dependencies
- Manifests, configuration files and supporting metadata

These artifacts can contain malicious code, poisoned data, unsafe loading behavior, exposed secrets, misleading manifests, prompt injection, or other suspicious indicators.

TrustChain provides a common workflow for registering these artifacts, collecting security evidence, evaluating policy, and recording the resulting trust decision.

### Core capabilities

- **Artifact registration:** Assign an artifact a unique identifier and declare its type and purpose.
- **Integrity evidence:** Inventory files and calculate cryptographic digests.
- **Prechecks:** Run configured deterministic and artifact-specific checks.
- **AI-assisted analysis:** Use NVIDIA-backed analysis to identify risk indicators in bounded artifact excerpts.
- **Specialist detection:** Integrate additional NVIDIA security detectors where configured and available.
- **Policy evaluation:** Convert evidence into an `ADMIT`, `QUARANTINE`, or `BLOCK` decision.
- **Publisher verification:** Verify signatures against an independently trusted public key.
- **Lineage:** Record where an artifact came from and how it entered the system.
- **Signed provenance:** Optionally create and verify a signed provenance attestation.
- **Audit history:** Record registration and other trust-related events.

### Technology stack

| Component | Technology |
|---|---|
| User interface | Python, Streamlit |
| Backend | Python |
| Persistent registration and audit data | SQLite |
| Integrity | SHA-256-based artifact digests |
| AI security analysis | NVIDIA API through an OpenAI-compatible client |
| Model scanning | PickleScan integration and configured scanner evidence |
| Provenance signing | Project provenance module and cryptographic signing |
| Tests | pytest |

The precise set of checks executed depends on the implementation and configuration present in the current checkout.

---

## 2. Problem Statement

A file being downloadable, loadable, or apparently valid does not establish that it is trustworthy.

Examples of potential problems include:

- A dataset containing suspicious labels or unusual examples
- A model distributed in a format capable of unsafe deserialization
- A package that requests capabilities inconsistent with its declared purpose
- An agent that accesses files or networks beyond its intended scope
- A tool manifest whose description does not match its implementation
- A modified artifact whose contents no longer match its registered digest
- A signature that is mathematically valid but belongs to an untrusted publisher

Traditional scanners are useful for known patterns but cannot reliably detect every semantic or behavioral threat. AI-based analysis can add useful contextual evidence, but it can also produce false positives, false negatives, or uncertain results.

TrustChain addresses this by combining multiple evidence sources with an explicit policy layer.

The central idea is:

**Artifact evidence → Risk assessment → Policy decision → Recorded trust history**

---

## 3. Goals and Design Principles

### 3.1 Evidence-based decisions

Each registration produces evidence that can be inspected alongside the final policy decision.

### 3.2 Defense in depth

No single detector is assumed to identify every threat. Deterministic checks, scanner results, integrity verification, provenance evidence, and AI analysis serve different purposes.

### 3.3 Untrusted-input isolation

Artifact contents are treated as untrusted data during AI analysis. The detector is instructed not to follow instructions embedded in the artifact.

The AI detector examines bounded excerpts and does not intentionally execute artifact contents.

### 3.4 Separation of detection and policy

A detector reports observations and hypotheses. Policy determines what those observations mean for admission.

AI findings can trigger quarantine under configured rules, but AI findings alone cannot independently trigger a `BLOCK` decision.

Other policy rules, including hard integrity or revocation conditions, may block an artifact.

### 3.5 Provenance and accountability

Trust decisions should be accompanied by information about the artifact's source, parent, transformation, signature status, and recorded history where applicable.

### 3.6 Explicit uncertainty

A detector that was not configured or could not complete must not be represented as having confirmed the artifact is safe.

### 3.7 Honest security claims

TrustChain reports only the checks and evidence it actually obtains. A passing result is not a guarantee against hidden backdoors, future malicious behavior, or threats outside the detector's coverage.

---

## 4. System Architecture

The project can be understood as five cooperating layers.

### Layer 1: User interface

The Streamlit application collects artifact information, accepts files or paths, starts registration, and displays results.

### Layer 2: Registration and evidence collection

The core backend inventories artifacts, calculates digests, invokes configured prechecks and detection components, and assembles evidence.

### Layer 3: Detection

This layer contains deterministic checks, scanner integrations, and NVIDIA-backed AI analysis. The exact detectors depend on the artifact type and the installed implementation.

### Layer 4: Policy engine

The policy layer interprets the evidence and selects a final decision. It is responsible for distinguishing admission, quarantine, and blocking conditions.

### Layer 5: Persistence and audit

SQLite stores registration and evidence records. The audit subsystem records events and supports verification of its hash chain. Separate local directories store optional attestations, trusted public keys, publisher signature files, and uploaded artifacts.

### Conceptual architecture

```text
                 User / Security Reviewer
                           |
                           v
                   Streamlit Interface
                           |
                           v
                 TrustChain Registration
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
         Inventory     Prechecks     AI Analysis
         and Hashing   and Scanners  and Specialists
             |             |             |
             +-------------+-------------+
                           |
                           v
                    Evidence Record
                           |
                           v
                     Policy Engine
                           |
              +------------+------------+
              |            |            |
              v            v            v
            ADMIT       QUARANTINE      BLOCK
              |            |            |
              +------------+------------+
                           |
                           v
                 SQLite and Audit History
                           |
                           v
                  UI Evidence and Review
```

This diagram describes the logical architecture; it does not imply that every detector is available or successful for every artifact.

---

## 5. Supported Artifact Types

The registration interface offers four artifact categories.

| Artifact type | Intended purpose | Relevant risk areas |
|---|---|---|
| `Dataset` | Training, evaluation or inference data | Poisoning indicators, suspicious content, secrets and PII exposure, structural anomalies |
| `Model` | Model weights and related artifacts | Unsafe deserialization, suspicious files, model-loading risks, anomalous content |
| `AI Agent` | Agent code and supporting configuration | Prompt injection, unexpected capabilities, secrets, risky dependencies and behavior |
| `Tool / Dependency` | Packages, tools, manifests and supporting files | Dependency risk, code behavior, declared-versus-observed inconsistencies and suspicious instructions |

Selecting a category does not mean that every listed risk is automatically detected. The applicable checks depend on the installed precheck implementation, scanner availability, artifact contents, and AI detector execution.

### Declared purpose

The user supplies a purpose statement during registration. For example:

> Rank residential property listings by budget and location.

This gives the AI detector contextual information against which it can assess observed evidence.

A purpose statement is not proof of behavior. It is a declaration that can be compared with the artifact's observable contents.

### Capability profile

The project has also introduced inferred capability profiles for artifact types. An inferred profile describes expected default capabilities, but it is not equivalent to runtime verification or sandbox enforcement.

For example, a dataset profile may indicate that executing code is not an expected default capability. That does not prove that no code can be executed elsewhere in the system.

---

## 6. End-to-End Workflow

The primary TrustChain workflow is:

1. Select the artifact type.
2. Enter a unique artifact ID.
3. Declare the artifact's purpose.
4. Upload an artifact or provide a local path.
5. Address publisher-signature requirements.
6. Select the parent artifact or identify an external source.
7. Describe the import or transformation event.
8. Optionally prepare a signed provenance attestation.
9. Submit the registration.
10. Run registration, integrity, precheck, scanner and AI analysis steps as implemented.
11. Assemble the evidence and evaluate policy.
12. Record lineage and audit information.
13. Display the verdict, check results and supporting evidence.
14. Inspect or review the artifact from the Artifacts page.

The registration workflow is intended to produce a decision and an associated evidence record rather than merely returning a scanner output.

### Important implementation detail

The UI calls the core registration function to run much of the backend work. This means some checks occur within a single backend call rather than as independently callable UI stages.

A progress checklist can communicate which broad phase is running. A checkbox or progress indicator should only be treated as proof of an individual check's completion if it is tied to that check's actual result.

---

## 7. Registration and Precheck Pipeline

### 7.1 Input validation

Before registration, the UI validates the required inputs, including:

- A non-empty artifact ID
- A unique artifact ID
- An import or transformation description
- A valid artifact source
- Parent selection constraints
- Required signature acknowledgement
- Required keys when signed provenance is requested

When a registered parent is selected, the workflow checks that the parent exists, its current contents match its registered digest, and its status permits use as a trusted parent.

### 7.2 File inventory and integrity

The backend inventories the artifact's files and calculates digest evidence.

The purpose is to establish an identity for the registered content and enable later integrity comparisons.

A digest proves content identity relative to a known digest. It does not prove that the content is benign.

### 7.3 Deterministic prechecks

The backend calls the configured precheck system. These checks can identify known structural or content indicators without relying exclusively on a generative model.

Depending on the current implementation, the broader project includes work on:

- File structure and format checks
- Hidden Unicode and obfuscation indicators
- Secrets and PII
- Dataset poisoning indicators
- Model-loading and scanner findings
- Agent or tool capability inconsistencies
- Dependency and manifest risks

**Do not assume every item in this list is implemented, enabled, or executed for every registration.** Check the individual result entries for evidence of actual execution.

### 7.4 Model and scanner checks

The registration path collects model-scanner and scanner-advisory evidence where configured.

The project includes PickleScan integration and a local synthetic advisory fixture used for demonstrations.

A synthetic advisory is demonstration data, not a live vulnerability database. A scanner's result also depends on its installed version, supported formats, and whether it completed successfully.

### 7.5 NVIDIA AI detection

The general AI detector collects bounded, non-executing excerpts and submits structured evidence to an NVIDIA-hosted model. If that request succeeds, the current implementation invokes the specialist detector integration.

The model returns a structured assessment that is normalized before being added to registration evidence.

See [NVIDIA AI Detection](#8-nvidia-ai-detection) for the details and limitations.

### 7.6 Evidence aggregation

The registration process stores the individual precheck results and AI detector result in the registration evidence.

The UI summarizes the precheck verdicts into counts such as:

- `PASS`
- `FINDINGS`
- `NOT_CHECKED`
- `ERROR`

These values describe check outcomes, not the final artifact decision.

A registration may have several passing checks and still require review because another check found a risk.

### 7.7 Policy evaluation

The policy engine evaluates the collected evidence and returns a final decision.

The decision is stored with reasons so that the user can understand why the artifact was admitted, quarantined, or blocked.

### 7.8 Persistence

The backend stores the registration record, evidence and decision in SQLite and records relevant audit events. Lineage is recorded as part of the registration workflow.

---

## 8. NVIDIA AI Detection

### 8.1 Purpose

The AI detector adds contextual security analysis to the deterministic prechecks.

It is designed to identify risk indicators such as:

- Prompt injection and suspicious embedded instructions
- Potential data-poisoning or backdoor indicators
- Secret or PII exposure
- Unexpected code, network, filesystem or tool capabilities
- Tool-description and implementation inconsistencies
- Unsafe model-loading indicators
- Manifest and provenance inconsistencies

These are analysis targets, not a guarantee that every category is covered for every artifact.

### 8.2 Bounded artifact excerpts

The detector reads files as data and prepares bounded excerpts.

The current general-detector configuration uses:

| Setting | Default |
|---|---:|
| Maximum files | 12 |
| Maximum characters per file | 7,000 |
| Files larger than | 2 MB skipped |
| Binary-looking files | Skipped when a NUL byte is detected in the initial bytes |
| CSV/TSV preview | Up to 24 parsed rows from the bounded excerpt |
| General model response tokens | Up to 2,200 |

These limits reduce input size and avoid executing artifact code. They also mean that the detector may not see a malicious payload located outside the selected excerpts.

### 8.3 Structured response

The general model is prompted to return a JSON object containing:

- `verdict`
- `risk_score`
- `confidence`
- `findings`
- `limitations`
- `summary`

Each finding can include:

- Category
- Severity
- Title
- Evidence
- Rationale

The application normalizes the response, constrains several field lengths, limits the number of findings, and handles malformed output as an uncertain or failed result.

### 8.4 AI verdicts

| AI verdict | Meaning |
|---|---|
| `PASS` | No strong indicators were identified in the supplied evidence. It is not a safety guarantee. |
| `FINDINGS` | The detector reported one or more risk indicators. |
| `UNCERTAIN` | The detector could not provide a confident clean assessment. |

The detector also records a status, which distinguishes a completed assessment from a skipped or failed request.

### 8.5 NVIDIA specialist detectors

The project has a specialist integration for:

- **Nemoguard Jailbreak Detect:** intended to identify jailbreak or prompt-injection indicators.
- **NemoGuard Content Safety:** intended to classify content-safety risks.
- **GLiNER-PII:** intended to identify personal information.

The general AI detector calls the specialist integration after a successful general-model request.

The specialist results are intended to add independently visible detection signals to registration evidence. In the current integration, however, specialist execution is coupled to the successful completion of the general detector request. A general-request failure can therefore prevent the specialist calls from running.

Actual availability and behavior depend on endpoint configuration, access and response format. The presence of an API key alone does not guarantee that every endpoint is accessible.

### 8.6 AI risk score

The detector returns a risk score from 0 to 100 and a confidence value between 0 and 1.

These values are model-generated risk estimates. They are not calibrated probabilities of compromise unless separately evaluated and calibrated.

The policy may use configured thresholds or high-severity findings to trigger quarantine.

### 8.7 Failure handling

Possible outcomes include:

- `COMPLETED`: the general AI analysis returned a usable result.
- `NOT_CONFIGURED`: the NVIDIA API key is missing.
- `ERROR`: the detector could not complete successfully.

A failed request must not be interpreted as a clean assessment.

Whether missing AI coverage requires quarantine depends on the configured policy.

### 8.8 AI safety boundaries

The artifact is untrusted input. The detector is instructed to treat embedded content as data and not follow instructions found within the artifact.

AI output is structured as hypotheses supported by evidence, not executable instructions.

The current design allows AI findings to contribute to quarantine, but AI findings cannot independently trigger `BLOCK`.

---

## 9. Policy and Final Decisions

TrustChain separates check results from final policy decisions.

### 9.1 `ADMIT`

The artifact is admitted under the configured policy. This means no configured admission-blocking or quarantine condition was triggered by the available evidence.

It does not mean the artifact has been proven harmless.

### 9.2 `QUARANTINE`

The artifact requires human review before it should be trusted.

The UI displays this as **Review required**.

Possible causes include suspicious findings, uncertain detection evidence, missing required checks, or other configured review conditions.

### 9.3 `BLOCK`

The artifact is rejected by a blocking policy condition.

Examples can include hard integrity or revocation conditions. The precise blocking conditions are determined by the current policy implementation.

AI findings alone cannot independently block an artifact.

### 9.4 Check verdicts versus artifact decisions

These are different levels of information:

| Check result | Final decision |
|---|---|
| One check passes | The artifact may still require review due to another check. |
| A check reports findings | Policy determines whether the finding changes the final decision. |
| AI is uncertain | Policy determines whether missing or uncertain AI coverage requires quarantine. |
| A check errors | The result must not be silently interpreted as a pass. |
| Integrity or revocation rule triggers a hard block | Policy may block the artifact regardless of AI results. |

### 9.5 Policy configuration

The project loads its policy from `policy.yaml`, with a default policy fallback if loading fails.

The Policy page displays the active policy settings. Changes to the policy file require a restart or reload as indicated by the application.

Policy values should be inspected directly before claiming a particular threshold is active.

---

## 10. Streamlit UI Guide

The interface has five primary navigation pages:

1. Overview
2. Register Artifact
3. Artifacts
4. Audit Log
5. Policy

### 10.1 Overview

**Purpose:** Provide a high-level view of the registered artifacts and their current trust status.

The page displays four metrics:

- **Registered:** Total number of registered artifacts.
- **Admitted:** Artifacts whose decision is `ADMIT` and which are not revoked.
- **Review required:** Artifacts whose decision is `QUARANTINE` and which are not revoked.
- **Blocked / revoked:** Artifacts that are blocked or revoked.

It also displays the trust workflow and a table of registered artifacts.

**Actions:**

- Select **Register Artifact** from the sidebar to begin registration.
- Review the artifact table for IDs, types, decisions and revocation status.

### 10.2 Register Artifact

**Purpose:** Register a new artifact, run the configured checks, and display the resulting evidence and policy decision.

#### Artifact type

Select one of:

- Dataset
- Model
- AI Agent
- Tool / Dependency

#### Unique artifact ID

Enter a unique identifier, such as `fraud-model-v2`.

An existing ID cannot be reused to replace the existing registered record.

#### Declared purpose

Describe the intended use of the artifact. The AI detector can use this context when analyzing artifact excerpts.

#### Upload or local path

Choose one input method:

- Upload one file through the file uploader.
- Provide a local file or directory path.

The upload interface currently accepts one uploaded file per registration. Directory registration requires a local path.

#### Publisher signature

The publisher signature section accepts:

- A `.sig` signature file.
- A publisher public key in PEM or PUB format.
- An acknowledgement that the user understands the consequences of registering without a verified publisher signature.

The checkbox confirming that a public key belongs to the claimed publisher records the user's assertion that the key was independently verified. It is not an automatic identity check.

A discovered signature sidecar is not sufficient by itself to establish publisher identity.

#### Scanner advisory simulation

- **Scanner version:** Version string used by the optional advisory simulation.
- **Apply synthetic scanner advisory fixture:** Enables the local synthetic version-range fixture for demonstration.

This is not a substitute for a live vulnerability feed.

#### Origin and lineage

- **Parent artifact:** Select an existing registered artifact or choose External source / root.
- **Source URI:** Required for an external/root artifact. It should be cleared when a registered parent is selected.
- **Transformation / import event:** Describes how the artifact entered the system or was transformed.

A selected parent must exist, retain its registered integrity, and satisfy the applicable parent trust constraints.

#### Optional signed provenance

- **Create a signed provenance attestation:** Enables the optional attestation workflow.
- **Signer ID:** Identifies the signing party in the attestation.
- **Signing private key PEM:** Used locally to sign the attestation.
- **Trusted public key PEM:** Used to verify the signature.

The private key is handled in a temporary directory and should not be persisted as a normal project artifact. The resulting attestation and trusted public key are stored separately.

#### Run checks and register

Click **Run checks and register** to submit the form.

The intended registration phases are:

1. Validate registration details and source.
2. Verify parent integrity and lineage constraints.
3. Inventory files and calculate integrity hashes.
4. Run artifact-specific deterministic prechecks.
5. Run applicable model and scanner checks.
6. Run NVIDIA AI and specialist detection.
7. Verify publisher signature and provenance evidence.
8. Evaluate policy and determine the verdict.
9. Persist registration and append audit information.

The progress checklist is a user-facing summary of these phases. Because much of the work is performed inside a single backend registration call, the UI may not receive independent progress updates from every underlying detector.

#### Registration results

After registration, the page displays:

- Final policy decision
- Policy reasons
- Lineage details
- NVIDIA AI security analysis
- Risk score and confidence when returned
- AI findings, evidence and rationale
- Specialist detector results when exposed
- Precheck counts
- Individual precheck results
- Additional registration details

**Important:** A successful registration means a registration record was created. It does not mean every security check passed.

### 10.3 Artifacts

**Purpose:** Browse registered artifacts, inspect evidence, run test-load attempts, review quarantined artifacts, and revoke artifacts.

#### Review queue

Displays artifacts with a `QUARANTINE` decision that are not revoked.

- **Open review:** Selects an artifact for detailed review.

#### Artifact table

Shows artifact ID, type, decision and revocation status.

#### Details

Select **Details** on an artifact row to open the artifact's detailed view.

The details view can display:

- Capability profile, if available
- Publisher signature evidence
- Model scanner information
- Review flags
- AI detector evidence
- Individual precheck results
- Policy decision reasons
- Integrity recheck
- Lineage
- Signed provenance status

Internal paths and cryptographic digests are intentionally hidden from ordinary UI output.

#### Test load

Select **Test load** to invoke the backend's test-load workflow for that artifact.

The result is displayed as an admission, review, or error outcome. This should be understood as a TrustChain test-load operation, not a guarantee that arbitrary code has been safely sandboxed.

#### Revoke

Select **Revoke** to initiate revocation.

The UI asks for confirmation and a reason.

- **Confirm revocation:** Records the revocation and invokes the backend revocation workflow.
- **Cancel:** Cancels the pending revocation.

Revocation prevents future permitted load attempts and can move descendants into review according to the backend's rules.

#### Human review

When an artifact is quarantined and not revoked, the details view offers a review workflow.

- **Reviewer identity:** Identifies the person conducting the review.
- **Review justification:** Records why the review decision is being made.
- **Optional publisher signature:** Supplies a signature for the exact artifact.
- **Publisher public key:** Supplies a candidate verification key.
- **Independent trust confirmation:** Confirms the reviewer independently trusts the publisher key.

The available review actions are:

- **Re-evaluate & approve:** Re-evaluates the artifact against integrity and policy requirements. Approval should only succeed if the current policy permits admission.
- **Retain in review:** Keeps the artifact in quarantine.
- **Reject / block:** Rejects the artifact and applies the backend's rejection workflow.

Human review is not intended to override hard integrity, revocation, or other non-overridable policy conditions.

#### Signed provenance

If an attestation and trusted public key exist, the UI verifies the attestation and compares the current artifact integrity against the registered and attested digest.

- **Download signed attestation:** Downloads the attestation JSON.

A valid signature alone is insufficient if the current artifact contents no longer match the attested content.

### 10.4 Audit Log

**Purpose:** Inspect the recorded history of trust-related events.

The page displays:

- Audit hash-chain integrity
- Event sequence
- Timestamp
- Event type
- Human-readable event details
- Recorded chain status

**Inspect audit event details** allows a user to select an event and inspect its recorded payload in a readable form.

The hash-chain verification indicates whether the stored audit chain validates under the implementation's verification rules. It does not independently establish that every recorded claim is true or that every possible event was captured.

### 10.5 Policy

**Purpose:** Inspect the policy configuration and understand decision semantics.

The page displays scalar policy settings and grouped policy settings in readable tables.

The page also explains:

- `ADMIT`
- `QUARANTINE` / Review required
- `BLOCK`
- The role of AI findings in quarantine decisions

The synthetic scanner advisory section describes the local demo fixture and its version range.

The Policy page is an inspection interface. Editing the policy file and restarting or reloading the application is the configuration path described by the current implementation.

---

## 11. Integrity, Signatures and Provenance

These mechanisms address different security questions.

### 11.1 Artifact digest

A cryptographic digest identifies the observed content.

If the content changes, the recalculated digest should differ, allowing TrustChain to detect a mismatch against the registered digest.

A digest does not indicate whether the original content is safe.

### 11.2 Publisher signature

A digital signature can verify that a signature matches the artifact and a given public key.

However, the key must be independently trusted to associate that signature with the claimed publisher.

TrustChain distinguishes signature verification from publisher identity.

### 11.3 Signed provenance attestation

An optional attestation records provenance information such as:

- Artifact ID
- Artifact digest
- Parent artifact ID and digest, where applicable
- External source URI, where applicable
- Transformation or import event
- Signer identity

The attestation is signed and verified using the provided key material.

### 11.4 Integrity recheck

The Artifacts page recalculates the current digest and compares it with the registered digest.

This helps identify content changes after registration.

### 11.5 Limitations

A valid signature does not prove that an artifact is benign. A matching digest does not prove that the artifact is free from malicious behavior. Provenance information is only as trustworthy as its evidence and trust anchors.

---

## 12. Lineage Tracking

Lineage describes how artifacts relate to each other.

A registration can record:

- A parent artifact, if the artifact derives from an existing registered artifact
- An external source URI for a root artifact
- A transformation or import event

For example:

```text
External source
      |
      v
Base model
      |
      v
Fine-tuned model
      |
      v
Quantized model
```

This is a conceptual example, not a record of a particular artifact in the database.

Lineage helps reviewers investigate origin and transformations. It does not, by itself, prove that every parent or transformation is trustworthy.

The registration workflow also checks parent integrity and trust status before accepting a registered parent under the configured rules.

---

## 13. Audit Logging

TrustChain stores an audit history to support accountability and investigation.

The audit subsystem records events associated with registration and other trust-related operations. The UI verifies the audit hash chain and displays event payloads in a readable format.

### Why the audit log matters

It provides a record of:

- What event was recorded
- When it was recorded
- The sequence in which it appears
- The associated evidence or decision metadata
- Whether the stored hash chain validates

### Important limitation

A hash chain can reveal certain forms of tampering with recorded entries, but it cannot prove that the application captured every relevant event, that the machine was uncompromised, or that every recorded statement was accurate.

The audit log should be treated as integrity-protected application evidence, not as a complete external forensic logging system.

---

## 14. Project Structure

The exact tree can change as the project evolves. The following describes the main files and directories referenced by the application.

```text
trustchain_mvp/
├── app.py
├── README.md
├── requirements.txt
├── policy.yaml
├── trustchain/
│   ├── core.py
│   ├── prechecks.py
│   ├── ai_detector.py
│   ├── nvidia_specialists.py
│   ├── profiles.py
│   ├── scanner.py
│   └── provenance.py
├── tests/
├── fixtures/
│   └── scanner_advisory_demo.json
├── sample_artifacts/
├── data/
│   ├── trustchain.sqlite3
│   ├── uploads/
│   ├── attestations/
│   ├── trusted_keys/
│   └── publisher_signatures/
└── .venv/
```

Some directories may be created automatically when the application starts. Optional modules or directories may be absent in a particular checkout.

### Main files

| File | Responsibility |
|---|---|
| `app.py` | Streamlit UI, registration form, results, review, audit and policy pages |
| `trustchain/core.py` | Registration orchestration, evidence assembly, policy decisions, persistence, lineage and audit operations |
| `trustchain/prechecks.py` | Deterministic prechecks and check-disposition logic |
| `trustchain/ai_detector.py` | Bounded artifact excerpt collection and NVIDIA-backed general AI analysis |
| `trustchain/nvidia_specialists.py` | Integration for NVIDIA specialist detectors |
| `trustchain/profiles.py` | Inferred artifact capability profiles |
| `trustchain/scanner.py` | Scanner integration |
| `trustchain/provenance.py` | Signed provenance creation, signing and verification |
| `policy.yaml` | Policy configuration |
| `fixtures/scanner_advisory_demo.json` | Synthetic advisory fixture |
| `tests/` | Automated tests for project behavior |
| `data/` | Local database and registration-related artifacts |

### Local state

The SQLite database stores registration and audit information. Uploaded artifacts, attestations, public keys and signature files are stored in separate local directories.

These local files may contain sensitive material. Do not commit private keys, confidential datasets, API keys, or sensitive production artifacts to source control.

---

## 15. Installation and Setup

### Prerequisites

- Python 3.11 or newer; Python 3.12 is suitable for the current development setup.
- A compatible pip installation.
- A terminal with access to the project directory.
- Network access if remote NVIDIA detection is to be used.
- An NVIDIA API key with access to the configured model endpoints for real AI detection.

### Create a virtual environment

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project's dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PickleScan is installed separately in the project environment, verify it:

```bash
picklescan --help
```

Run a basic test suite:

```bash
python -m pytest -q
```

Some tests may be slow if they make real network requests or invoke external scanners. For repeatable unit tests, remote API calls should be mocked or explicitly excluded from the unit-test path.

---

## 16. Configuration

### 16.1 NVIDIA API configuration

The general detector reads the following environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `NVIDIA_API_KEY` | Authentication for NVIDIA-hosted inference | Not configured |
| `NVIDIA_MODEL` | General AI detector model | `nvidia/nemotron-3.5-lightning-30b-a3b` |
| `NVIDIA_BASE_URL` | OpenAI-compatible API base URL | `https://integrate.api.nvidia.com/v1` |
| `TRUSTCHAIN_AI_MAX_FILES` | Maximum files included in the general detector excerpt | `12` |
| `TRUSTCHAIN_AI_MAX_CHARS_PER_FILE` | Maximum characters per file excerpt | `7000` |

Set the API key in your shell before starting Streamlit:

```bash
export NVIDIA_API_KEY="YOUR_NVIDIA_API_KEY"
streamlit run app.py
```

Do not commit the key to source control or place it in a public README.

The general detector uses an OpenAI-compatible client to access the NVIDIA endpoint. Specialist detectors can have their own model identifiers, endpoint requirements, or configuration. Verify the current specialist implementation before assuming that a single successful API request means every specialist is enabled.

### 16.2 Policy

The application loads `policy.yaml`. If loading fails, the current UI reports the error and falls back to the default policy.

Review the active policy before a demonstration so that the observed verdicts match the intended demonstration scenario.

### 16.3 Scanner advisory fixture

The optional scanner advisory simulation uses local fixture data.

It should be described as a demonstration of version-range policy handling, not as evidence that TrustChain is connected to a live CVE feed.

### 16.4 Test configuration

Avoid relying on live network services for ordinary unit tests.

A test that exercises registration logic should normally mock the remote AI detector and assert how its returned evidence affects registration and policy. Separate integration tests can explicitly exercise real NVIDIA endpoints.

A skipped detector must be represented as skipped or not checked, not as a successful security assessment.

---

### Fail-closed coverage

`require_type_coverage: true` in `policy.yaml` quarantines any artifact for which no substantive type-specific check could run, such as a model in an unsupported format or a dataset that is not CSV/TSV. Unrecognized artifact types are always quarantined. Set it to `false` only for fixtures and tests.

---

## 17. Running TrustChain

From the project root:

```bash
source .venv/bin/activate
streamlit run app.py
```

Streamlit will print a local URL in the terminal. Open that URL in a browser.

### Recommended demonstration sequence

1. Open Overview and explain the current artifact counts.
2. Navigate to Register Artifact.
3. Select a type and enter an ID and declared purpose.
4. Upload a sample artifact or supply a local path.
5. Choose the source and transformation details.
6. Address the publisher-signature acknowledgement.
7. Optionally enable the synthetic advisory fixture.
8. Click **Run checks and register**.
9. Walk through the registration checklist and security check results.
10. Explain the final policy decision and reasons.
11. Open the artifact in Artifacts.
12. Inspect its recorded evidence and integrity status.
13. Open Audit Log to demonstrate recorded events.
14. Open Policy to explain how findings influence the decision.

Use sample artifacts prepared for the demonstration and make sure their expected results are reproducible before presenting.

---

## 18. Demonstration Scenarios

The following are suggested demonstration scenarios. The exact outcome depends on the artifact, enabled checks, and active policy.

### Scenario A: Ordinary dataset

**Goal:** Demonstrate registration of a simple dataset.

1. Select `Dataset`.
2. Upload a small CSV file.
3. Declare its purpose.
4. Record an external source and import event.
5. Run registration.
6. Inspect integrity evidence, prechecks, AI analysis and the policy decision.

**What to explain:** TrustChain records the observed artifact and makes a decision from the evidence available to it. A clean result is limited to the checks performed.

### Scenario B: Dataset containing suspicious rows

**Goal:** Demonstrate how suspicious content can become a review signal.

Use a prepared CSV containing a clearly documented suspicious indicator relevant to an enabled dataset check or the AI detector.

**What to explain:** A suspicious row is an indicator to investigate, not automatic proof of poisoning. Show the evidence and explain which policy rule, if any, causes quarantine.

### Scenario C: Unsafe model serialization indicator

**Goal:** Demonstrate model-related scanning and risk reporting.

Use a controlled sample that the configured scanner can inspect. Do not execute an unknown or malicious model file.

**What to explain:** Static scanning can identify known risky serialization patterns. It does not prove the absence of all unsafe behavior.

### Scenario D: Prompt injection in an agent or tool artifact

**Goal:** Demonstrate the untrusted-input boundary.

Use a harmless test artifact containing a clearly marked instruction intended to manipulate an AI reviewer.

**What to explain:** The detector is instructed to treat embedded instructions as data, not follow them. The AI's report is still a hypothesis that must be interpreted alongside other evidence.

### Scenario E: Signature verification

**Goal:** Demonstrate the distinction between signature validity and publisher trust.

Use a controlled test key pair and a signature generated for the exact artifact.

**What to explain:** Mathematical verification checks the relationship between the signature, artifact and key. Independent trust in the public key is needed to associate it with the claimed publisher.

### Scenario F: Integrity mismatch

**Goal:** Demonstrate post-registration integrity verification.

1. Register a controlled test artifact.
2. Inspect its integrity status.
3. Modify the artifact in a disposable test environment.
4. Recheck the artifact.

**What to explain:** The digest comparison detects that the content no longer matches the registered content. Never modify production artifacts merely to demonstrate this scenario.

### Scenario G: Synthetic scanner advisory

**Goal:** Demonstrate how a configured advisory fixture contributes evidence.

Enable the synthetic advisory option for a controlled version scenario.

**What to explain:** This illustrates advisory handling and policy evaluation. It is not a live vulnerability lookup.

### Scenario H: Quarantine and human review

**Goal:** Demonstrate the review lifecycle.

Register a controlled artifact that triggers a known quarantine condition under the demonstration policy.

Then:

1. Open the Review queue.
2. Select the artifact.
3. Inspect its findings and decision reasons.
4. Record a reviewer identity and justification.
5. Re-evaluate and approve, retain in review, or reject according to the actual evidence and policy.

**What to explain:** Human review is a documented workflow, not an unrestricted override of hard security conditions.

---

## 19. Testing and Troubleshooting

### 19.1 Run tests

Run the targeted test for the behavior being changed:

```bash
python -m pytest -q tests/test_registration_purpose_profiles.py
```

Then run the broader suite when appropriate:

```bash
python -m pytest -q
```

To identify the slowest tests:

```bash
python -m pytest --durations=20 -q
```

The last command executes the full test suite. Use it when you can afford the runtime.

### 19.2 Tests are taking a long time

Potential causes include:

- Remote NVIDIA API calls during registration tests
- API timeouts and retries
- External scanner subprocesses
- Repeated processing of artifact files
- Integration tests depending on external services

Use mocks for normal unit tests. Keep live endpoint tests separate and explicitly enabled.

Do not change test configuration in a way that silently treats skipped AI checks as passes.

### 19.3 NVIDIA API key is missing

If `NVIDIA_API_KEY` is not configured, the general detector reports that detection did not run.

Set the key in the environment before launching Streamlit.

### 19.4 AI request fails

A failed request should be displayed as an error or uncertain result. Check network connectivity, endpoint availability, model access and the installed client version.

The absence of an AI finding is meaningful only when the detector actually completed and returned a usable assessment.

### 19.5 Specialist results are missing

The current integration calls specialist detectors only after the general NVIDIA request succeeds. A general request failure can therefore prevent specialist execution.

Check the general detector status and specialist evidence separately.

### 19.6 Signature verification fails

Verify that:

- The signature corresponds to the exact artifact.
- The public and private keys form a matching pair.
- The supplied public key is independently trusted.
- The file has not changed since signing.

### 19.7 Artifact ID already exists

Choose a new ID for the new version. Registration is designed not to overwrite the existing registered identity and digest.

### 19.8 Parent artifact cannot be used

Verify that the parent exists, its current content matches its registered digest, and its status satisfies the parent trust constraints.

### 19.9 Policy file cannot be loaded

Check the YAML syntax and file location. The current application falls back to the default policy after reporting a load error, so confirm which policy is active before demonstrating a decision.

### 19.10 UI shows missing check results

An absent check entry does not prove that the check passed. Inspect the precheck evidence and determine whether the check was not applicable, not configured, skipped, or failed to execute.

---

## 20. Security Considerations

### Untrusted artifacts

Artifacts can contain adversarial instructions or malformed data. The AI detector treats artifact excerpts as data and does not intentionally execute them.

This does not make the entire registration pipeline a sandbox. Scanner subprocesses, parsers, and other dependencies still require appropriate isolation and secure configuration.

### AI output

AI-generated findings can be inaccurate. Findings should be grounded in observable evidence and interpreted by policy and, where needed, a human reviewer.

AI should not be treated as the sole security boundary.

### API credentials

Keep NVIDIA credentials outside source control. Restrict access to environment variables and secrets used for deployment.

### Private keys

Private signing keys must not be committed to the repository or retained as ordinary application artifacts. Use dedicated secret management and access controls for any production deployment.

### Sensitive artifacts

Uploaded datasets, models and agent code may contain secrets or personal information. Apply appropriate file permissions, access restrictions, retention policies and deletion procedures.

### Hashes and signatures

Cryptographic integrity is useful only when the reference digest or verification key is trusted. A valid hash does not indicate benign behavior, and a valid signature does not independently establish publisher identity.

### Policy decisions

A quarantine decision should not be confused with a confirmed malicious verdict. It indicates that the configured policy requires review or that the artifact does not meet the conditions for immediate admission.

### Production deployment

The MVP should not be used as the sole security control for admitting untrusted artifacts into production systems. Production use requires a broader threat model, hardened isolation, independent security review, robust secrets handling, and verified scanner and policy coverage.

---

## 21. Current Limitations and Future Work

### Current limitations

1. **Partial inspection:** The AI detector examines bounded excerpts rather than the complete semantic or runtime behavior of every artifact.
2. **Remote-service dependency:** NVIDIA detection depends on network access, endpoint availability, configuration and model access.
3. **Specialist coupling:** Specialist checks currently depend on successful completion of the general NVIDIA request.
4. **Detector coverage:** Not every threat category is implemented or enabled for every artifact type.
5. **Static versus runtime behavior:** Static evidence does not prove how an artifact behaves when executed.
6. **Probabilistic AI output:** AI findings can contain false positives or false negatives.
7. **Synthetic advisory data:** The bundled advisory fixture is not a live CVE feed.
8. **Limited sandbox enforcement:** Registration and static inspection should not be presented as a fully isolated execution environment.
9. **Human trust decisions:** Public-key trust and review justifications require independent human or organizational processes.
10. **Audit scope:** A hash-chained application log does not replace external, tamper-resistant production logging.
11. **Progress granularity:** Some prechecks run inside a single backend call, limiting the UI's ability to report exact real-time progress for every detector.
12. **Test isolation:** Tests that contact remote services can be slow and nondeterministic unless properly mocked or isolated.
13. **Untrusted agent traces:** A behavior trace supplied inside an artifact is treated as untrusted. Declared capabilities are never read from it, it cannot produce a PASS, and any network, file-write or tool event it records is a finding. Trusted sandbox-collected tracing is future work.
14. **Language and format coverage:** AST analysis covers Python agent code only; JavaScript relies on pattern checks. Poisoning heuristics cover CSV/TSV tables, and model probing covers the TrustChain toy format. Other formats (for example `.jsonl`, `.h5`, `.gguf`) are not analyzed and are quarantined under `require_type_coverage` rather than cleared.
15. **Typosquat and install-script checks are shallow:** The typosquat check compares names against a small built-in list of popular packages, and install-script detection is pattern-based. Neither replaces a malicious-package scanner or a live vulnerability feed.

### Potential future improvements

- Independent execution and failure handling for every specialist detector.
- Explicit per-detector status reporting: `PASS`, `FINDINGS`, `NOT_CHECKED`, `ERROR`.
- Improved registration progress driven by actual detector events.
- Stronger structured evidence schemas and consistent finding identifiers.
- Live vulnerability feeds and software bill-of-materials generation.
- Sandboxed dynamic execution for agent and tool artifacts, with the trace collected by the registry (network-isolated container, canary credentials, syscall/egress logging) instead of supplied by the registrant.
- Declared-versus-observed capability verification.
- Dataset anomaly and poisoning analysis with reproducible evaluation data.
- Model backdoor and weight-anomaly research, with carefully measured claims.
- Provenance verification and stronger publisher trust management.
- Better isolation of remote calls from unit tests.
- Calibration and benchmarking of AI risk scores.
- Role-based access, retention controls and deployment hardening.

These are future directions rather than claims about the current implementation.

---

## 22. Frequently Asked Questions

### What does TrustChain actually do?

It registers AI-related artifacts, collects configured security evidence, evaluates policy, records provenance and audit information, and presents the result for inspection.

### Is TrustChain an antivirus?

No. It is a multi-signal artifact trust and risk-assessment prototype. It combines configured deterministic checks, scanner evidence, integrity checks, and AI analysis.

### Does `ADMIT` mean an artifact is completely safe?

No. It means the artifact satisfied the configured policy based on the evidence available at registration time.

### What does Review required mean?

The policy returned `QUARANTINE`. Human review is required before the artifact should be trusted.

### Can the AI model block an artifact?

AI findings alone cannot independently trigger `BLOCK`. They can contribute to quarantine according to policy. Other hard policy conditions can block an artifact.

### Why use both deterministic checks and AI?

Deterministic checks are useful for known, verifiable conditions. AI can help interpret contextual or semantic indicators that simple rules may miss. Neither approach is sufficient by itself.

### Does the AI execute the artifact?

The general detector is designed to inspect bounded, non-executed excerpts. That does not establish that every other component in the application is sandboxed.

### Why might AI detection not run?

The NVIDIA API key may be missing, the endpoint may be unavailable, the request may fail, or the detector may be otherwise unconfigured.

### Does one NVIDIA API key guarantee all specialist models work?

No. Each endpoint can have its own access, request format, and configuration requirements. The actual specialist results must be inspected.

### Why can the tests take several minutes?

Tests may invoke remote AI services, wait for network timeouts, or launch external scanners. Unit tests should normally mock remote services, with live endpoint tests kept separate.

### Does a valid signature mean the publisher is trusted?

No. Signature verification establishes a cryptographic relationship with a public key. Publisher identity requires independent trust in that key.

### Why store an artifact digest?

It provides a reference for detecting whether the content changes after registration.

### Can lineage prove that a model was trained safely?

No. Lineage records relationships and transformations. It does not prove that every training step or source was benign.

### What does the audit hash chain prove?

It helps detect changes inconsistent with the recorded hash chain. It does not prove that all events were captured or that the recorded claims are true.

### Is the synthetic advisory fixture a real vulnerability feed?

No. It is local demonstration data for testing advisory-related logic.

### What is the role of the human reviewer?

The reviewer examines evidence, records a justification, and takes an available review action. The review process remains constrained by integrity and policy requirements.

### What is the main contribution of the project?

TrustChain demonstrates a common, auditable workflow that connects artifact registration, multiple security signals, policy-based trust decisions, and provenance. Its emphasis is on making decisions inspectable rather than presenting a detector score as an absolute guarantee of safety.

---

## 23. Glossary

| Term | Definition |
|---|---|
| Artifact | A dataset, model, agent, tool, dependency or related file being assessed |
| Precheck | A configured check executed during registration |
| Evidence | A recorded observation, result, finding or metadata used by policy |
| Digest | A cryptographic hash used to identify observed content |
| Detector | A component that evaluates an artifact for a particular class of risk |
| AI finding | A model-generated hypothesis about a risk indicator, ideally supported by observable evidence |
| Risk score | A numeric assessment produced by a detector; not automatically a calibrated probability |
| Confidence | A detector-provided measure of confidence in its assessment |
| Policy | Rules that determine how collected evidence affects admission, quarantine or blocking |
| `ADMIT` | The artifact satisfies the configured admission conditions |
| `QUARANTINE` | The artifact requires review before being trusted |
| `BLOCK` | A blocking policy condition has been triggered |
| Provenance | Information describing an artifact's source, origin and transformations |
| Attestation | A structured statement about an artifact and its provenance that can be cryptographically signed |
| Lineage | Recorded relationships between artifacts and their parent or source |
| Specialist detector | A model or service focused on a narrower security task |
| False positive | A finding that reports a risk where the suspected threat is not actually present |
| False negative | A detector fails to identify a threat that is present |
| TOCTOU | Time-of-check to time-of-use inconsistency, where content changes between verification and use |
| Audit chain | A sequence of recorded events linked through hashes to help detect certain forms of tampering |

---

## Final Summary

TrustChain's core workflow is:

**Register an artifact → collect security evidence → run configured prechecks and AI analysis → evaluate policy → record lineage and audit history → inspect the decision.**

The project combines deterministic evidence and AI-assisted risk analysis while keeping the policy decision separate from individual detector outputs.

Its primary value is a structured, inspectable trust workflow for AI-related artifacts. Its current results must be interpreted within the limits of its implemented checks, available evidence, external services, and policy configuration.
