# Phase 2 Step 8 — Contextual False-Positive Fix

**Status:** Targeted contextual fix implemented and regression-tested. The actual original Myntra email is still unavailable, so acceptance for that specific raw message cannot be claimed.

## A. Fixture check and before/after evidence

Inspected the existing Step 6 report and `backend/tests/test_false_positive_scoring.py`. The repository has an inline synthetic case, not a raw `.eml`/`.msg` or independently labeled full-pipeline output. That case contains the body “Offers may be revoked or suspended. Shop now. Unsubscribe.” The fusion unit test already returned score 0, no signals and no urgency signal before this change. The parser’s actual urgency list does not match “may be revoked or suspended” by itself. Therefore the exact synthetic Myntra wording did not reproduce a high-risk result, and the original reported result remains unverified.

A related parser false positive was reproducible: a quoted example saying `Your account is suspended immediately` triggered the parser’s “Urgency-based social engineering” indicator and added 10 points even though the email asked no action. The false-positive fixture was added before changing detector logic.

**Before changes:**

- Existing focused file: `4 passed`.
- After adding parser regressions and before changing detection, focused run: `6 passed, 1 failed`; the quoted/negated urgency regression failed because the quoted example received 10 points. The new actionable-phishing regression passed.
- The inline Myntra fusion fixture remained `0.0 / LOW` with no signals; it did not reproduce the original full-pipeline report.

**After changes:**

- Focused file: `8 passed`.
- Existing email-processing security test was attempted with the focused tests. It stalled after five tests without further output for about a minute and was interrupted. No final pass/fail result is claimed for that broader command.

## B. Files changed

- `backend/services/email_parser.py`: the parser’s urgency/social-engineering rule now requires urgency to occur near a concrete recipient action, and ignores quoted or explicitly negated clauses. It no longer awards points for isolated urgency wording.
- `backend/services/email_ai/intelligence_fusion.py`: content signals now use unquoted, non-negated clauses; the urgency-pressure signal requires urgency and an actionable social phrase within a nearby clause window. This keeps the existing promotion-context guard and adds no sender/domain allowlist.
- `backend/tests/test_false_positive_scoring.py`: added parser and fusion regressions for disclaimer, quoted and negated language, plus an actionable suspension phishing case. Added a small parser helper to construct direct inputs for the existing scoring function.

No unrelated application files were changed. No sender or domain was whitelisted.

## C. Regression coverage

The new tests cover:

1. Promotional legal wording with “revoked or suspended” does not add parser social-engineering points.
2. Quoted “account is suspended immediately” and negated “we will never ask you to verify…” wording do not add parser social-engineering points.
3. Quoted or negated credential-pressure text does not create fusion credential-harvesting or urgency-pressure signals.
4. A realistic actionable message (“Your account will be suspended immediately. Verify your account and enter your password.”) continues to create parser urgency evidence and fusion credential/urgency evidence.
5. Existing high-risk phishing test with deceptive URL and credential language remains in the focused suite and passes.

These tests establish the expected behavior of the current inline fixtures. They do not substitute for the missing original MIME sample or verify upstream parsing/authentication of that message.

## D. Residual limitations and trade-offs

- The original Myntra message and its actual high-risk API output were not found. The repository fixture is synthetic and already passed before the code change. The issue described in Step 6 as a high-risk Myntra full-pipeline result therefore remains unconfirmed.
- Context handling is deliberately narrow and rule-based: common quote delimiters and a fixed set of negation phrases are recognized. Nested quotes, unusual punctuation, multilingual text, HTML structure and more complex cross-sentence references may need future cases.
- Unquoted, non-negated presence of generic terms such as “password”, “invoice” or “director” can still trigger other existing content categories. This change only addresses quotation/negation filtering for fusion content and actionable context for urgency; it is not a redesign of all keyword rules.
- Parser urgency points are reduced when urgency is not near one of the explicit action phrases. A novel actionable phrase may therefore be missed until the action vocabulary is extended. Other detectors remain in place.
- The broader `test_email_processing_security.py` run stalled and was interrupted. Its result is unknown and should be rerun in a responsive test environment.

## E. Commands and results

Run from `backend` using the project’s existing virtual environment; no packages or environment configuration were changed.

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_false_positive_scoring.py
```

After change:

```text
........                                                                 [100%]
8 passed in 0.79s
```

Before change, after adding the initial parser regressions:

```text
.....F.
1 failed, 6 passed
```

The failing test was `test_quoted_or_negated_urgency_does_not_add_parser_social_engineering_points`; the quoted example scored 10 and had a social-engineering indicator.

Broader relevant suite attempted:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_email_processing_security.py tests/test_false_positive_scoring.py
```

It printed five passing dots, then stalled without output for about a minute and was interrupted. No suite summary was produced. `git diff --check` completed with no whitespace errors; Git only printed a line-ending conversion warning for the test file.

## Diff summary and handoff

Three source/test files changed: 2 detector files and 1 regression test file. Diff summary: 109 insertions and 15 deletions. No database, dependency, runtime configuration or external fixture was modified.

The focused actionable-phishing and contextual false-positive criteria pass for the tested cases. The acceptance claim for the original Myntra email cannot be marked passed until that raw fixture and its prior high-risk result are available and reproduced. The broader email-processing security suite also needs a completed rerun.
