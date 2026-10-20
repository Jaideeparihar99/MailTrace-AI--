# Phase 3 — Step 14: Explicit Unknown, Failed and Empty Results

**Status: implemented; Step 15 has not been started.** This handoff documents the supported analysis paths inspected and changed in this step. Risk scoring continues to use the Phase 2 canonical fusion and disclosed fallback policy.

## A. Result-state vocabulary and field mapping

The shared contract uses `PASS`, `FAIL`, `UNKNOWN`, `ERROR`, `NOT_APPLICABLE`, and `NOT_RUN`. Provider-native values stay in `provider_status`; they are not discarded when a canonical state is added. `PASS` describes a completed check with no adverse finding, while an explicit `outcome` distinguishes such results as `ZERO_MATCHES` from a missing/failed run.

| Component | Source fields / status mapping |
|---|---|
| MIME parser | `analysis.parsing.status`: `COMPLETE → PASS`, `PARTIAL → UNKNOWN`; rejected/failed parse is returned as bounded HTTP error. |
| SPF, DKIM, DMARC | `email_forensics.authentication_analysis.validation.*.status` remains provider status; `result_statuses.authentication.*` contains canonical status and provider status. SPF without trusted SMTP context is `NOT_RUN`; missing signature/policy context is represented as `NOT_APPLICABLE` or `FAIL` (`NO_POLICY`); DNS/temp validation errors are `ERROR`. |
| Geolocation | `ip_intelligence[ip].geolocation_status`: `PASS`, `ERROR`, or `NOT_APPLICABLE`; non-public/documentation IPs do not call public providers. |
| Proxy/hosting reputation | `ip_intelligence[ip].network_intelligence_status`: same states; malformed provider response and timeout are `ERROR`, never boolean false. |
| IOC / threat-intel matching | `threat_intelligence.status` and `coverage_status` preserve existing detailed state (`matched`, `no_matches`, `no_iocs`, `coverage_limited`, `error`, `not_configured`). Canonical output distinguishes `FAIL` + `MATCHES_FOUND`, `PASS` + `ZERO_MATCHES`, and `NOT_RUN` + `NO_INDICATORS` or `MISSING_CREDENTIALS`. |
| Model inference | `email_ai.status`; `result_statuses.model_inference` maps completed inference to `PASS`, model unavailable/skipped to `NOT_RUN`, and exceptions to `ERROR`. Placeholder probability is not treated as an available model result by fusion. |
| Risk fusion and score | `intelligence_fusion.status`, `threat_analysis.score_source`, `confidence_basis`; canonical status shows fusion `ERROR` separately from the fallback score. Missing confidence is `UNKNOWN`; fallback zero score is no longer labeled `LOW RISK` and instead requests review. |
| WHOIS | No WHOIS lookup implementation is part of the inspected analysis path; no WHOIS result is claimed or synthesized. |

The API attaches the combined status object as `analysis.result_statuses`. The analysis page displays a collapsible **Analysis coverage** summary separately from the executive risk score.

**Call graph / source references:** `backend/main.py::_analyze_email` (analysis composition; status attached before persistence), `backend/services/email_parser.py::parse_email` (parser metadata), `backend/services/email_forensics/authentication_analyzer.py::validate_email_authentication` (SPF/DKIM/DMARC), `backend/services/ip_intelligence.py::{get_ip_geolocation,get_network_intelligence,analyze_ip}` (provider and public/private IP branch), `backend/services/threat_intelligence/engine.py::{fetch_threatfox,search_threatfox,fetch_urlhaus_recent}` (feed sync providers), `backend/services/email_ai/intelligence_fusion.py::{_authentication_contract,_intelligence_availability,_calculate_data_quality,analyze_email_intelligence}` (Phase 2 scoring and availability), and `frontend/script.js` result summary (status rendering). The new canonical mapper is `backend/services/result_states.py::build_analysis_statuses`.

## B. Error and unknown handling flow

1. **Parsing:** size/resource-limit failures use a generic 413 message; malformed email uses a generic 422. Raw exception text is not returned. Successfully parsed but partial input remains `UNKNOWN`/partial and receives review-required verdict and unknown confidence.
2. **Authentication:** trusted SMTP context is required for SPF recomputation. Uploaded `Authentication-Results` remains untrusted evidence. Missing context is not a pass; DNS and temporary DKIM/SPF/DMARC errors are retained as error states.
3. **Enrichment:** private, loopback, reserved and documentation IPs are classified before external geolocation/reputation calls; non-public lookups are `NOT_APPLICABLE`. Timeouts, invalid JSON types and provider failures return bounded safe errors and `None` for unknown proxy/hosting booleans.
4. **IOC feeds:** no indicators means matching did not run; configured fresh feeds plus zero matches means a completed lookup with zero results; stale/limited coverage remains `UNKNOWN`; exceptions are `ERROR`. No-match does not mean the email is safe.
5. **Model/fusion:** model exceptions are logged by error type and surfaced with a generic message. Fusion errors are logged by type; the Phase 2 disclosed `parser_rules_plus_ioc_fallback` remains the fallback. When that fallback is zero, the user sees **REVIEW REQUIRED (ANALYSIS DEGRADED)** rather than **LOW RISK**. No scoring weights or Phase 2 fusion rules were changed.
6. **Diagnostics:** user-facing analysis errors do not expose exception strings, tokens or internal paths. Error type is retained for server logs/diagnostic fields, not exception contents.

## C. Regression matrix

Focused tests cover provider timeout, malformed provider payload, private IP, successful zero-match lookup, no indicators, missing provider credentials, model skipped, partial/failed parser status, auth validation errors, and fusion error/unknown confidence.

| Scenario | Expected | Observed |
|---|---|---|
| Provider timeout | `ERROR`, safe message; no raw token/path | Pass |
| Malformed geolocation/network JSON shape | `ERROR`, not empty-success | Pass |
| IOC lookup returns zero matches with fresh coverage | `PASS`, `ZERO_MATCHES` | Pass |
| No extracted IOCs | `NOT_RUN`, `NO_INDICATORS` | Pass |
| Threat-intel credentials missing | `NOT_RUN`, `MISSING_CREDENTIALS` | Pass |
| Private IP | Geolocation and network checks `NOT_APPLICABLE`; no provider call | Pass |
| Model not ready / skipped | `NOT_RUN`, not inferred benign | Pass |
| Partial parser | `UNKNOWN`, review-required | Status mapping covered; analysis endpoint behavior confirmed by existing Phase 2 regression suite |
| Parser failure | bounded generic client error | Static path inspection; no new endpoint-level parser-failure fixture |
| SPF missing trusted SMTP context | `NOT_RUN`, not pass | Pass |
| DKIM/DMARC DNS/temporary error | `ERROR` | Pass |
| Fusion exception with zero fallback | degraded review label; score confidence `UNKNOWN` | Status/scoring pathways reviewed; dedicated full endpoint exception injection is not included |

**Command:** from `backend`, ran `pytest -p no:cacheprovider -q tests\test_phase3_step14_explicit_states.py tests\test_phase2_step10_gate.py` — **18 passed**. `py_compile` for modified backend modules and `node --check frontend/script.js` completed successfully.

Existing email fixtures were not bulk reprocessed for a before/after numeric score comparison. The Phase 2 score regression suite ran unchanged alongside the new state tests, and this step does not modify fusion calculation.

## D. Score, report and UI preservation

- Score source and degraded mode remain the Phase 2 `threat_analysis` fields; canonical fusion remains authoritative when valid.
- Fusion failure does not turn missing confidence into a zero-confidence numeric claim. The result status says `ERROR` and score confidence says `UNKNOWN`.
- Threat-intel no-match/no-indicator/coverage-limited/error outcomes stay separate from `ioc_threat_score` and the risk score.
- Each IP retains geolocation and network-reputation states alongside the existing evidence fields. A private-IP zero score is not presented as a completed public reputation lookup.
- The result UI now surfaces parsing, authentication, geolocation, IP reputation, model, threat-intel (including zero-match outcome), fusion, and score-confidence states.

## E. Changed files and remaining limitations

- `backend/services/result_states.py` — shared vocabulary and end-to-end status mapping.
- `backend/main.py` — sanitized failure messages, attached IP/status outputs, degraded-zero review verdict.
- `backend/services/ip_intelligence.py` — safe provider errors, malformed-response checks and private-address N/A statuses.
- `frontend/script.js`, `frontend/style.css` — analysis-coverage disclosure in result summary.
- `backend/tests/test_phase3_step14_explicit_states.py` — focused status and failure-path tests.
- `phase3_step14_explicit_result_states.md` — this handoff.

Remaining work: add endpoint-level forced parser/fusion/provider failure tests; normalize status payloads for any older persisted investigation rows at read time; expand DNS/WHOIS only if those providers are added; and decide a versioned API schema migration for clients that consume raw provider status strings. Provider-level service modules outside the analysis pipeline may still expose detailed errors to administrative logs and should be reviewed before production deployment.

**Review gate:** stop here. Do not begin Step 15 until this handoff is reviewed.
