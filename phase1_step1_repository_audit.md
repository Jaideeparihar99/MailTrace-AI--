# MailTrace-AI — Step 1 Repository Audit and Phase 2 Contract Freeze

**Audit date:** 2026-10-12  
**Repository:** `D:\jaideep\practice\practice\mailtrace ai\MailTrace-AI--`  
**Scope:** Reconstructed Step 1 baseline from the current working tree and available project records. This document is a new audit artifact; no application code, dependencies, configuration, database, runtime evidence, or fixtures were changed and no tests were run.

## 1. Step 1 recovery

Searched the repository root, source tree, snapshots, available reports, and Git history for `phase1_step1_repository_audit.md` and equivalent Step 1 repository-audit reports. No earlier Step 1 report or historical version was found. Steps 2, 3, 4, and 5 reports are present; the Step 2/3/5 reports also record that Step 1 was missing. This document reconstructs the audit from the current tree as of the date above; it is not a recovered copy of the original.

## 2. Repository and working-tree baseline

MailTrace is a static HTML/CSS/JavaScript frontend and Python FastAPI backend. SQLite is the application database; local evidence ledger/vault and integrity-anchor data are stored under `backend/runtime_data`. The supplied launcher serves frontend port 5503 and API port 8002. There is no frontend package manifest/build system, CI workflow, Compose environment, migration framework, or Python version matrix identified in the other phase reports.

Python setup is via pip requirement files. `backend/requirements.txt` is the base manifest; `backend/requirements-soc-security.txt` contains `PyJWT[crypto]` and cryptography for OIDC/security features; `backend/requirements-email-processing.txt` covers optional mail-processing packages. The README documents Python 3.11, while the local backend venv was observed on Python 3.14.7. These runtime versions are not shown to be interchangeable.

The working tree already contains modified application files and untracked reports/tests from earlier work. This audit did not alter those files and does not attribute them to this audit. See `git status` for the live list; the baseline reports provide the detailed prior-state caveat.

## 3. Architecture and important data paths

The main email path is upload → MIME parsing and parser rules → URL/authentication/IP checks → email forensics and optional local ML → threat-intelligence enrichment → intelligence fusion → evidence governance and SQLite persistence → UI rendering. Parser rule score, fusion `unified_risk_score`, top-level `threat_analysis.score`, and UI breakdown are separate fields today. The architecture and call chain are detailed in `phase1_step2_architecture_map.md` and `phase1_step3_pipeline_trace.md`.

The app performs filesystem initialization at import/startup. `backend/database/database.py` fixes `DATABASE_PATH` to `backend/mailtrace.db`; `backend/main.py` fixes evidence and integrity state under `backend/runtime_data`. No existing environment override for these paths was confirmed. Starting the regular app or importing app-level tests can therefore write into the working checkout unless a disposable copy or explicit isolated path refactor is used.

## 4. Confirmed issues to carry into Phase 2

The Step 5 baseline records source-backed findings including: missing model state can be treated as a numeric probability in fusion; Authentication-Results from uploaded mail can be displayed as if verified; incomplete authentication data can interact incorrectly with a score cap; some forensic/link signals are not consistently wired to fusion; non-malicious/unknown TI matches can add risk; duplicate headers may lose multiplicity; upload 413 handling can be wrapped as 500; and multiple score fields can diverge. These are audit findings, not changes made here. The focused source-level tests recorded in prior reports passed, but no end-to-end mail analysis was completed.

## 5. Frozen Phase 2 scoring and trust contracts

These are the baseline decisions for implementation and review. Keep the emitted breakdown auditable at full score precision; UI rounding is presentation only.

### Canonical risk score

- `intelligence_fusion.unified_risk_score` is the canonical 0–100 risk score when fusion status is `ANALYZED`.
- The API's top-level threat score, persisted score, verdict/severity thresholds, and UI headline must derive from that same canonical score. Do not independently add parser or IOC scores after fusion.
- `score_breakdown` is the accounting explanation of the canonical score: signed, named components and adjustments must sum to `unified_risk_score` within a declared rounding tolerance (recommend 0.000001). Any cap/floor is an explicit adjustment line; the displayed integer may be rounded from the canonical value but is not a second score.
- Parser-rule and IOC-specific scores may remain as evidence/diagnostic sub-scores, clearly labeled as noncanonical. If fusion is unavailable, return an explicit unavailable/partial status rather than silently substituting a different formula into the canonical field.
- Model probability is not risk score and must never be presented as one.

### Reported versus independently verified authentication

- Values parsed from `Authentication-Results`, `Received-SPF`, and similar message headers are **reported claims**. Preserve their raw value and provenance; label them untrusted and never call them verified or let them qualify for a verified-pass cap.
- **Verified results** are separate structured outcomes produced by the app from a trusted acquisition context. SPF requires authenticated SMTP client IP, envelope sender, and HELO context (for example, the signed webhook path); uploaded headers alone cannot establish it. DKIM requires local cryptographic signature verification against the message and DNS key. DMARC requires a complete policy/alignment evaluation using the verified SPF/DKIM identity and policy lookup. A policy record lookup alone is not a DMARC pass.
- Each check carries `status`, `attempted`, `complete`, `method`, `evidence/provenance`, and (where relevant) alignment. Use explicit states such as `PASS`, `FAIL`, `TEMPERROR`, `NOT_PRESENT`, `NOT_CHECKED`, `UNAVAILABLE`, and `UNVERIFIED`; never map absence or an unchecked state to pass/fail.
- A verified-auth pass condition requires every applicable check to have been attempted and complete, with verified passing results and required alignment. Missing, partial, or unknown checks cannot qualify for a benign score cap. A verified pass is evidence about sender-domain authentication, not proof the message is benign; it must not cancel independent malicious evidence.

### Missing models, partial authentication, and TI availability

- Missing/unready/error/skipped model means **no ML evidence**, not probability 0, not a benign prediction, and not high model support. Set model probability to null/unavailable (or preserve schema with explicit unavailable status and ensure fusion ignores its numeric placeholder). Continue deterministic evidence scoring. Lower overall confidence/evidence completeness and expose a data-quality limitation; do not invent threat points solely because the model is absent.
- Authentication that is missing, incomplete, timed out, or unavailable contributes no pass and no failure points. Preserve any separately reported claims as untrusted context. Mark authentication coverage incomplete and reduce confidence/completeness; do not infer safety from absent checks. A cryptographically/contextually verified failure may contribute risk under documented weights.
- Threat intelligence has three distinct states: confirmed malicious match, completed lookup with no match, and unavailable/not checked. Only a confirmed malicious match can add positive risk. A completed no-match is neutral and is not proof of safety. Provider timeout, missing credentials, disabled provider, or incomplete lookup is unavailable; add no match score, lower enrichment coverage/confidence, and report the reason/status. A match tagged benign/unknown is not a malicious hit.
- Confidence describes evidence quality/support, not the complement of risk. Risk can remain high with low confidence and should route to review; low confidence must not be converted into low risk.

## 6. Safe test environment and dependency resolution

### Current status

The previous environment audit found no `.eml`/`.msg` labeled fixtures, no local backend/frontend listening on ports 8002/5503, and no model binary (only manifests). The Step 5 report says focused unit tests passed, while the OIDC-inclusive collection failed because the active environment lacks import module `jwt`. No full API end-to-end run or labeled outcome metrics are established.

The application currently has fixed in-checkout SQLite/runtime paths and import-time directory creation. Therefore the current working database and evidence state are **not yet confirmed disposable**. Do not run end-to-end tests against this checkout as-is.

### Gate before any end-to-end run

1. Use a disposable checkout/copy or implement and verify explicit database and runtime directory overrides that point only to a newly created temporary directory. Confirm the effective resolved paths before startup, confirm no existing DB/evidence paths are opened, and ensure the disposable paths can be deleted after the run. Do not reuse `backend/mailtrace.db` or `backend/runtime_data`.
2. Prepare labeled synthetic `.eml` fixtures with labels and expected outcomes recorded separately: benign legitimate, benign promotional, phishing credential lure, BEC/payment-change, malformed/incomplete MIME, forged Authentication-Results, missing/partial auth checks, and TI match/no-match/unavailable. Use reserved `.test` domains and documentation-only IP ranges; no real recipients, live delivery, malware payloads, or production provider credentials. EICAR, if required for scanner testing, must be isolated and explicitly labeled. At present, these fixtures are **not confirmed present**.
3. Run tests with network/provider calls disabled or mocked unless a test specifically opts into a controlled provider. Verify no email sends, gateway actions, feed sync, or destructive retention cleanup can run.
4. Resolve `jwt` using the project's declared optional security dependency setup, not ad hoc package installation: create a fresh disposable Python 3.11 environment per README and install the base requirements plus `requirements-soc-security.txt` for OIDC coverage. Confirm the intended manifest combination and Python support in a clean environment before use. Do not mutate the existing venv or install packages from this audit. The exact current venv can be checked with `python -m pip show PyJWT`; do not use `pip install jwt` (different package name).
5. Until the disposable DB/runtime and fixtures are available, limit execution to audited pure-unit tests that do not import `main` or write persistent state. No tests were run for this report.

## 7. Evidence and limits

Evidence was assembled from current source, requirements, repository status/history, and Steps 2–5 reports. No secrets, email bodies, evidence vault contents, or database contents were read into this report. No package setup, server startup, test execution, network lookup, or application-file modification occurred. The preceding reports provide source-level details and prior command outcomes; those historical results are not re-run or represented as current executions.

## Phase 2 entry condition

The Step 1 audit is now reconstructed and the scoring/trust semantics above are frozen as the implementation contract. End-to-end verification remains gated on a disposable DB/runtime and the labeled synthetic fixture set described above. The missing `jwt` dependency has a declared project setup path in the optional security requirements; the existing environment has not been changed.
