# Phase 1 Step 5 — Baseline Bug Register

**Assessment date:** 2026-10-12  
**Repository:** MailTrace-AI (current working tree)  
**Scope:** Baseline only. No source, test, configuration, dependency, database schema, or model files were changed for this assessment.

## A. Baseline execution summary

| Check | Command / method | Result |
|---|---|---|
| Focused safe unit tests | From backend: `$env:PYTHONDONTWRITEBYTECODE='1'; .\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_false_positive_scoring.py tests/test_campaign_correlation.py` | Exit 0; **9 passed** in 0.50s. |
| OIDC test collection | `$env:PYTHONDONTWRITEBYTECODE='1'; .\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_false_positive_scoring.py tests/test_campaign_correlation.py tests/test_access_control_oidc.py` | Exit 2; collection stopped at `ModuleNotFoundError: No module named 'jwt'` in `tests/test_access_control_oidc.py`. No tests in this invocation completed. |
| Installed dependency consistency | `.\venv\Scripts\python.exe -m pip check` | Exit 0; no broken requirements reported. This does not establish absence of vulnerabilities or optional dependency coverage. |
| Local service availability | Checked localhost ports 8002 and 5503 | Both closed; no local backend/frontend available for end-to-end reproduction. |
| Fixture/model availability | Inspected test-data directories, email fixtures and model directory | No EML/MSG fixture found; expected test-data directories absent. Model directory contained manifest JSON only, no .joblib artifact. |
| Full application startup | Not attempted | Backend initialization may write SQLite/runtime state. With baseline-only/no database changes required, startup was not considered safe. |
| Vulnerability scan | Not run | `pip-audit` executable unavailable. |

Local backend venv reports Python 3.14.7 and pytest 9.1.1. No system pytest was available. The repo documents Python 3.11 in its setup material (Step 4); no compatibility matrix was established. The working tree was already modified before this report: see the final note.

## B. Bug register

Confidence labels mean: **Confirmed** = reproduced in safe execution or directly established by source/data flow; **Probable** = source suggests the defect but no safe runtime reproduction; **Unverified** = insufficient evidence. These are current-tree findings; prior changes may be uncommitted.

### Detection, scoring and authentication

| ID | Severity / confidence | Finding and evidence | Impact / next phase |
|---|---|---|---|
| B-01 | High / Confirmed by source | `backend/services/email_ai/intelligence_fusion.py::_probability_from_ai` supplies a zero probability when model probability is absent. The support calculation can then report about 0.99 support from distance to 0.5, even though `_ai_signal` skips `MODEL_NOT_READY`. | Confidence/support can look strong when the model is unavailable. Phase 2 define missing-model semantics; Phase 3 fix; Phase 5 regression test. |
| B-02 | High / Probable | Fusion identity signals compare raw/exact sender and Reply-To identities. Parser/forensics also have organizational-domain logic, but the score path does not consistently use it. Parser Return-Path mismatch scoring adds 10 when validated DMARC is not PASS; browser-upload authentication fields are not equivalent to verified DMARC alignment. | Legitimate ESP/subdomain mail can receive unsupported risk points; reported auth must not be mistaken for verified auth. Phase 2 settle trust/status contract; Phase 3 implement aligned comparison; Phase 5 legitimate ESP and spoof cases. |
| B-03 | High / Probable | Forensic output nests findings under `header_anomaly_analysis.findings`; `intelligence_fusion.py::_forensic_signals` reads `forensic.findings`. | Forensic signals may be silently absent from fusion scoring. Phase 2 data contract; Phase 3 wiring; Phase 5 assert signal lineage. |
| B-04 | Medium / Confirmed by source | Parser calculates `link_deception_intelligence`; fusion URL scoring reads `advanced_url_intelligence` or `url_intelligence`, not that field. | Link deception findings may not influence the unified score. Phase 2 signal contract; Phase 3 connect or explicitly exclude; Phase 5 malicious-link sample. |
| B-05 | Medium / Confirmed by source | The all-authentication-pass score cap uses represented mapping entries, while the authentication result contract may be incomplete or use NOT_VALIDATED. A partial result can satisfy a simplistic all() check; a genuine all-pass condition is not consistently represented. | Score caps can be applied on incomplete evidence or fail to apply when warranted. Phase 2 define completeness; Phase 3 enforce it; Phase 5 partial/missing-auth cases. |
| B-06 | Medium / Confirmed by source | Threat-intelligence scoring assigns a category score (52) for a valid match even when the category is not malicious/unknown. | Benign or non-actionable matches can inflate risk. Phase 2 category policy; Phase 3 scoring; Phase 5 benign-match fixture. |
| B-07 | High / Confirmed by source | `email_parser.py::extract_headers` overwrites repeated non-Received header values. `header_parser.py::parse_email_headers` preserves repeats in `all_headers`, but `header_anomaly_detector.py::detect_header_anomalies` counts keys in the top-level dict instead. | Duplicate-header attacks/anomalies may be lost before detection. Phase 3 preserve multiplicity end-to-end; Phase 5 duplicate-header corpus. |
| B-08 | Medium / Confirmed by source | In `backend/main.py`, upload size rejection raises HTTP 413 inside a broad `except Exception` that wraps errors as HTTP 500. | Oversized uploads receive the wrong status and may be logged as unexpected server failures. Phase 3 preserve intended HTTP exceptions; Phase 5 boundary-size request. |
| B-09 | High / Confirmed by source | Frontend `frontend/script.js` renders `analysis.authentication.spf/dkim/dmarc` directly. Those parser values can be supplied by the email's Authentication-Results header; verified/validated statuses are separate forensic results. | UI can present sender-controlled claims as if they were independently validated. Phase 2 establish explicit trust labeling; Phase 3 render verified state separately; Phase 5 forged header test. |
| B-10 | Medium / Confirmed by source | `authentication_analyzer.py::validate_email_authentication` performs DMARC policy lookup/status handling; it does not establish a complete DMARC PASS/FAIL evaluation and alignment result. SPF is recomputed only in a signed webhook context; DKIM validation is limited to the implementation's selected signatures. | “PASS”/alignment claims exceed what this path verifies. Phase 2 define supported outcomes; Phase 3 complete or label unavailable checks; Phase 5 auth fixtures. |
| B-11 | Medium / Confirmed by source | Several score fields coexist: parser rule score, fusion decimal unified score, rounded top-level threat score, and a separately rendered breakdown. | Displayed total and factor breakdown can diverge or leave points unexplained. Phase 2 choose canonical score/provenance schema; Phase 3 unify; Phase 5 invariant checks. |

### API/UI, reliability and configuration

| ID | Severity / confidence | Finding and evidence | Impact / next phase |
|---|---|---|---|
| B-12 | Low / Unverified | User previously reported a frontend temporal-dead-zone error for `intelligenceFusion`. Current inspected renderer uses a local `fusionResult`; the reported failure was not reproduced against the currently open application because local ports are closed. | Possible stale-cache or prior-source regression remains unresolved. Phase 5 reproduce using current served assets and capture exact build/source version. |
| B-13 | Medium / Confirmed by execution | OIDC test collection fails because PyJWT import `jwt` is absent in the active venv. Optional security dependencies mention PyJWT; base installation is insufficient for this test module. | OIDC/access-control tests cannot run in this environment. Phase 2 define supported test extras; Phase 4 align documented setup; Phase 5 run in clean configured environment. |
| B-14 | Medium / Confirmed observation | Setup materials specify Python 3.11, while the available backend venv uses Python 3.14.7; project compatibility across versions is unverified. | Results may not reproduce on the documented runtime. Phase 4 pin/test supported Python versions. |
| B-15 | Medium / Confirmed observation | Backend/frontend ports were closed; no email samples suitable for end-to-end testing were found. The app was not started because initialization may write database/runtime state. | The following baseline is unit/source evidence, not full pipeline behavior. Phase 5 provide an isolated temporary DB/runtime profile and safe labeled fixtures. |
| B-16 | Medium / Confirmed file observation | Model directory has manifests but no model binary. | Model inference availability is not established; behavior must remain explicitly unavailable rather than inferred from UI/module names. Phase 4 package/model delivery plan; Phase 5 test both absent and present model states. |
| B-17 | Medium / Confirmed audit limitation | DB/API/security test modules that import `main` were not run because import/startup may create or mutate local DB/runtime state. | No claim about those tests' pass/fail status. Phase 5 provide disposable DB and run the complete safe suite. |

## C. Scenario inventory and measurable metrics

| Scenario | Baseline outcome |
|---|---|
| Legitimate email | No safe EML fixture or live isolated pipeline. Not run end-to-end. |
| Promotional email | The inline promotional scenario in `backend/tests/test_false_positive_scoring.py` participates in focused unit tests; it is a direct fusion/scoring test, not a full MIME/API analysis. The selected test set passed. |
| Phishing email | Inline fake-bank/login scenario is covered by the focused unit tests only; no standalone labeled message was submitted through the pipeline. |
| BEC | No safe fixture identified; not run. |
| Malformed/incomplete email | Not run end-to-end. A malformed MSG test exists in source but was not run because its module imports app initialization. |
| Missing/conflicting authentication results | Not run end-to-end. Test names/source exist, but no safe fixture/pipeline run was completed. |
| Repeated analysis consistency | Not measured. |
| Full suite | Not run; OIDC collection blocker and app/database side-effect concern above. |

**Measured:** 9/9 selected focused tests passed; OIDC-inclusive collection attempt exited 2; `pip check` exited 0.  
**Not measured:** detector execution rate, analysis failure rate, repeated end-to-end consistency, false-positive/negative rate, precision, recall, accuracy. No suitable labeled dataset was available; none of those metrics are claimed.

## D. Known limitations and unverified behavior

- Source-level findings establish likely data-flow defects, but most scoring/UI issues were not exercised through a running API.
- The prior frontend TDZ error could not be reproduced with the current served app/assets.
- No claim that SPF, DKIM or DMARC outcomes are correct for real messages; the safe baseline did not execute a complete message pipeline.
- No model artifact was found, and no model inference success is claimed.
- No vulnerability scan was run. `pip check` is dependency consistency only.
- Evidence hashing/chain-of-custody findings in Step 3 remain local integrity evidence; no independent trusted timestamp, signing authority or immutable external anchor was demonstrated.

## E. Prioritized remediation backlog for later phases

These are proposed follow-up work items, not changes made in this baseline:

1. **Before Phase 2:** agree on score provenance and trust semantics for reported versus verified auth; define incomplete-auth and model-unavailable behavior; choose an isolated test database/runtime approach.
2. **Phase 2 design/contracts:** unify result schema, score breakdown invariant, forensic/link signal interfaces, eTLD+1 comparison policy, and severity/threshold rationale.
3. **Phase 3 implementation:** address B-01 through B-11 after the contracts are reviewed; preserve HTTP status codes and duplicate headers; label unverified auth claims.
4. **Phase 4 environment:** document optional test dependencies, supported Python versions and model artifact expectations; run vulnerability scanning in an approved environment.
5. **Phase 5 evaluation:** add safe labeled legitimate, promotional, phishing, BEC, malformed and auth-conflict fixtures; run full pipeline in a disposable environment; measure repeatability and labeled outcomes; reproduce the frontend error.

## F. Baseline for future comparison

- Focus unit tests: **9 passed**.
- OIDC-inclusive test collection: **blocked at collection** by missing `jwt` module (exit 2).
- Dependency consistency: `pip check` **clean** (exit 0).
- App ports 8002/5503: **closed**.
- End-to-end scenarios: **0 completed**.
- Code changes made for this baseline: **none**.

## G. Issues to resolve before Phase 2

Review and agree on:
- What counts as verified SPF/DKIM/DMARC, including alignment and provenance.
- Which score is canonical and how every point is attributed.
- How model-unavailable, incomplete authentication, and missing enrichment affect confidence and caps.
- Whether safe disposable database/runtime configuration and labeled fixtures can be supplied.
- Which Python versions and optional dependency groups are supported.

## Phase 1 readiness assessment

**Conditional; ready for review, not yet ready to begin fixes.** The baseline has source-level findings and a small passing unit subset, but no full application run, end-to-end mail scenarios, labeled evaluation set, or OIDC test run. Step 1's requested repository audit report was not present during this assessment; Steps 2–4 reports were present. Review this baseline and close the listed evidence/setup decisions before Phase 2.

**Working-tree note:** This report was created without modifying application code. Existing modified/untracked files were present before this assessment, including prior audit reports and scoring-related changes. This baseline describes that current working tree and does not attribute those earlier changes to this assessment.
