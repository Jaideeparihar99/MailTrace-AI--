# Phase 5 · Step 24 — Lookalike Domain Detection

**Status: implemented; focused offline checks pass.** Step 25 has not been started.

## A. Existing detector inventory and call graph

The repository had multiple overlapping checks before this step:

1. `backend/services/advanced_url_intelligence.py` parses URLs, normalizes IDNs, compares domains with brand candidates, detects confusable characters, and produces explainable findings. This is the primary URL deception detector used by downstream URL analysis. Its earlier organizational-domain helper relied on a last-label heuristic, which could misclassify legitimate domains under multi-label public suffixes.
2. `backend/services/link_deception_intelligence.py` compares visible link text/hosts to destinations and checks brand mismatches. It previously had its own last-two-label registrable-domain helper.
3. `backend/services/email_ai/features.py` checks claimed display-name brands and sender/reply-to identity, including typo similarity. It previously allowed a typo-similarity result to add risk without a message claiming that brand.
4. `backend/services/url_analysis.py` and `backend/services/email_forensics/url_analyzer.py` retain legacy URL indicators. The former already treated brand text as context only; the latter had added risk for any hostname containing a brand substring.

Call path summary:

```text
URL evidence → advanced_url_intelligence.analyze_url_deception
             → IDNA/PSL host parsing → configurable brand comparisons
             → explainable low-weight mismatch / confusable findings
             → URL result consumers

HTML link evidence → link_deception_intelligence.analyze_link_deception
                  → PSL-aware visible-vs-destination comparison

Sender / Reply-To → email_ai.features.analyze_identity_intelligence
                  → PSL registrable labels + claimed-brand context
                  → similarity evidence; score only when corroborated

Legacy forensic URL analysis → email_forensics.url_analyzer.analyze_urls
                            → brand substrings retained as context only
```

All checks are local string/IDNA/PSL processing. They do not visit domains, resolve DNS, or fetch page content.

## B. Policy and explanation format

- Preserve the source hostname and Unicode form when available; retain its ASCII IDNA form for comparison. Invalid IDNA/host syntax yields an explicit invalid-host result and no similarity claim.
- Use the repository's packaged Public Suffix List parser (`tldextract` with network suffix-list updates disabled) for organizational/registrable domain comparisons. This keeps `login.google.co.uk` under `google.co.uk` distinct from a lookalike registered domain such as `google.co.uk.attacker.test`.
- Approved brand domains come from `backend/config/brand_domains.json`. The file records a version, provenance, last review date, and maintenance policy. `MAILTRACE_BRAND_DOMAIN_LIST` can point to a reviewed alternate JSON file; the in-repo list remains the default.
- Typo and confusable matches are contextual, low-severity signals. A hostname resemblance alone must not block a message or produce a high-risk verdict.
- Identity typo-similarity contributes to the identity score only when the display name claims the compared brand. Findings remain visible without that corroboration and include `corroborated_by_display_name`.
- A visible-brand/destination mismatch is evidence about the specific link relationship; it does not prove malicious intent by itself.
- Findings include the compared and approved registrable domains, transformation type (for example, edit distance or Unicode-confusable skeleton), similarity/edit distance where available, and the brand-registry version/provenance.
- Do not strip security-relevant URL parts for evidence. Domain comparison operates on the parsed host while original URL evidence remains available to callers.

## C. Test matrix

| Case | Expected result | Actual |
|---|---|---|
| `paypa1.com` typo candidate | Explainable low-weight candidate; not conclusive/high risk | Pass |
| `auth.login.google.co.uk` | Legitimate subdomain under `google.co.uk`; no lookalike finding | Pass |
| Cyrillic-confusable `раypal.com` | Preserve Unicode and IDNA forms; report confusable evidence and low-weight brand comparison | Pass |
| Punycode form of the confusable hostname | Decode for analyst review; retain ASCII form | Pass |
| Unrelated `goggles.example.net` | No Google brand match from substring resemblance | Pass |
| Malformed `paypal..com` | Invalid-host state; no similarity alert | Pass |
| Custom brand-list override | Load candidate domains and report configured provenance/version | Pass |
| HTML link to approved `google.co.uk` | PSL-aware visible/destination comparison; no false mismatch | Pass |
| Sender similarity without a claimed brand | Preserve typo evidence, mark uncorroborated, do not increase identity risk | Pass |
| Claimed PayPal display name with lookalike sender domain | Mark corroborated and include the existing identity risk evidence | Pass |
| Legacy forensic analyzer sees `paypal.com` | Keep brand as context; no brand-only finding or risk points | Pass |

Command (from `backend`, using the desktop bundled Python runtime and the repository's installed dependency directory):

```powershell
$env:PYTHONPATH = (Resolve-Path '.\venv\Lib\site-packages').Path
& 'C:\Users\ritur\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest `
  tests/test_phase5_step24_lookalike_domains.py `
  tests/test_phase5_step23_domain_intelligence.py `
  tests/test_phase5_step22_geolocation_reliability.py `
  tests/test_phase3_step12_url_extraction.py `
  tests/test_false_positive_scoring.py `
  tests/test_domain_alignment_evidence.py `
  -q -k 'not test_analyze_email_api_reconciles_url_and_ioc_counts'
```

Observed: **82 passed, 1 deselected**. The deselected API integration test cannot import the repository's `pydantic_core` native extension in the bundled runtime (`ModuleNotFoundError: pydantic_core._pydantic_core`). This is an environment/runtime mismatch, not a Step 24 assertion failure. `py_compile` passed for the changed Python modules and test file. `git diff --check` reported no whitespace errors (Git emitted only existing line-ending conversion warnings).

The Step 24 test file alone also ran successfully: **12 passed**.

## D. False-positive limitations and controls

- Similarity thresholds are heuristic and depend on the candidate brand list. Short names, transliterations, newly registered brands, and uncommon scripts can produce misses or false positives.
- Confusable-character skeletons help explain suspicious forms but are not a complete Unicode security standard or proof of an attack.
- The bundled brand list is intentionally finite. Maintain it from a reviewed source with provenance and change control; do not treat it as a complete brand catalogue.
- PSL data is a packaged snapshot and can age. Refresh it through the project's dependency/update review, not during email analysis.
- Risk remains a combination of independent evidence. Similarity alone must not trigger quarantine or blocking.

## E. Changed files and results

- `backend/config/brand_domains.json` — versioned candidate domain registry with provenance and maintenance metadata.
- `backend/services/brand_registry.py` — bounded configuration loader and provenance reporting.
- `backend/services/advanced_url_intelligence.py` — PSL-aware registrable domains, safe IDNA handling, configurable brand comparisons, and conservative explainable lookalike/confusable findings.
- `backend/services/link_deception_intelligence.py` — shared brand registry and PSL-aware visible/destination domain comparisons.
- `backend/services/email_ai/features.py` — compares typo candidates on the registrable label and only scores them when the display name claims the brand; preserves uncorroborated findings for analyst context.
- `backend/services/email_forensics/url_analyzer.py` — brand substrings remain context and no longer add risk by themselves.
- `backend/services/url_analysis.py` — verified existing brand-only handling remains context-only.
- `backend/.env.example` — documents the optional reviewed brand-list override.
- `backend/tests/test_phase5_step24_lookalike_domains.py` — typo, benign, PSL, Unicode, punycode, malformed host, registry, and corroboration regressions.

**Handoff:** Step 24 acceptance criteria are met for the tested offline paths. One API integration test remains unverified because of the local native-extension/runtime mismatch noted above. Stop here for review; do not begin Step 25 until approved.
