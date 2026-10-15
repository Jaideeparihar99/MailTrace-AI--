# Phase 2 Step 7 — Risk Fusion Design Review

**Scope:** Static inspection of the current working tree. This document describes current behavior and proposes a reviewable design; it does not implement changes. No Step 7 test run was performed. Runtime behavior in the Step 6 report is identified separately below.

## A. Verified scoring flow

### Actual implementation

The real fusion module is `backend/services/email_ai/intelligence_fusion.py`; the public entry point is `analyze_email_intelligence(...)` (line 573). There is no need to invent a differently named fusion module. The main caller is `backend/main.py::_analyze_email` (line 2756). The parser’s separate legacy rule scorer is `backend/services/email_parser.py::analyze_threat` (line 755).

The high-level flow is:

1. `_build_signals` (379) calls the AI, content, identity, header, URL, attachment, forensic, threat-intelligence, and IP signal builders, then `_deduplicate_signals` (395).
2. Each `_make_signal` (129) clamps score to 0–100 and confidence/reliability to 0–1. Invalid numeric input falls back to 0 in `_safe_float` (85). `_probability_from_ai` (149) prefers calibrated, then model, then generic probability.
3. `_aggregate_categories` (404) takes a weighted mean within each category. Per-signal local weight is `category_weight × (0.70 + 0.30×confidence) × (0.75 + 0.25×reliability)`. Category confidence is the maximum signal confidence; support count is the number of signals.
4. `_fuse` (444) computes the weighted category base, corroboration, bonuses and evidence confidence. Correlation group summaries are computed, but do not enter the score formula (details below).
5. `analyze_email_intelligence` (573) derives confidence, contradiction penalties, caps, risk tier, decision, severity and disposition. `backend/main.py::_analyze_email` then selects either fusion score or parser-plus-IOC fallback and assigns the externally displayed verdict.

### Current signal construction

- **ML** (`_ai_signal`, 158): unavailable/error/skipped model statuses produce no signal. Otherwise score is probability×100; a listed threat classification floors the score at 82. Confidence is `max(.50,min(.99,probability))`; reliability .70.
- **Content** (`_content_signals`, 174): case-insensitive substring matching over subject and body. Credential terms produce 90/.88; financial terms 88/.87; authority terms 76/.74; urgency plus social-pressure terms produce 82/.84 unless promotional context is detected. These rules do not parse sentence scope, quotation, negation, disclaimer, intent, or sender reputation. Promotion context only gates the urgency/social rule.
- **Identity** (`_identity_signals`, 203): exact sender versus Reply-To address mismatch gives 92/.94; exact sender-domain versus Reply-To-domain mismatch gives 94/.95. A single pair can emit both. The comparison does not normalize to organizational/registrable domain.
- **Authentication** (`_header_signals`, 217): validated SPF/DKIM/DMARC FAIL, SOFTFAIL or PERMERROR count as failures. One combined signal scores `min(100,70+10×failures)` with confidence `min(.99,.76+.07×failures)`. PASS, missing and unknown results do not create positive or coverage evidence.
- **URL** (`_url_signals`, 239): consumes `advanced_url_intelligence` or `url_intelligence`. A score below 50 is ignored unless verdict is a listed suspicious/deceptive/high-risk value. Otherwise it emits `max(68,risk)` with confidence `min(.93,.72+score/500)`. It does not consume `link_deception_intelligence` or raw URL evidence directly.
- **Attachments** (`_attachment_signals`, 254): first matching branch emits one signal for the email: confirmed infected/malicious 100/.99; executable/script risk 78+ increments capped at 96; semantic extension mismatch 68/.72; incomplete/unverified scan 52/.50; otherwise attachment presence 48/.58. Incomplete scan is therefore currently encoded as positive risk, not a separate coverage state.
- **Forensics** (`_forensic_signals`, 324): only reads root-level `findings`, counts HIGH/CRITICAL except Return-Path, then emits `min(90,68+8×count)`/.70. The forensic orchestrator currently places findings under `header_anomaly_analysis`, so this adapter can miss actual nested findings; it also ignores the orchestrator’s top-level risk score.
- **Threat intelligence** (`_ti_signals`, 342): malicious matches score `min(100,88+7×count)`; any valid match without a recognized malicious verdict scores 52/.62. No valid mapping emits no signal, without representing whether lookup succeeded, failed, or was not run.
- **IP intelligence** (`_infrastructure_signals`, 362): for positive per-IP scores, emits `.72×max + .28×mean`, confidence `min(.96,.62+score/300)`, critical at 80. Absent/zero results emit no signal.

### B. Exact fusion formula and verdict thresholds

Weights in `CATEGORY_WEIGHTS` (37–51): ml/TI 1.45; header forensics/identity 1.35; malware delivery 1.30; credential theft/fraud 1.25; impersonation/forensics 1.20; infrastructure 1.15; URL 1.05; social engineering 1.00; attachment .80.

For each category, fusion uses the weighted mean described above. Then:

```text
base = sum(category_score × category_weight × (0.70+0.30×category_confidence))
       / sum(category_weight × (0.70+0.30×category_confidence))
corroboration_strength = mean of the top at most 4 category scores >=65 (or 0)
base_component = 0.62 × base
corroboration_component = 0.38 × corroboration_strength
convergence_bonus = min(15, max(0, (independent_count−1)×3))
severity_bonus = 5 if severe_count>=4; else 2.5 if severe_count>=2; else 0
corroboration_bonus = 2 if corroborated_count>=4; else 1 if >=2; else 0
breadth_bonus = 2.5 if independent_count>=5; else 0
unified_risk_score = clamp_0_100(sum of those six terms)
```

`independent_count` means non-ML categories with score >=55. `corroborated_count` means all categories, including ML, with score >=65. `severe_count` means all categories, including ML, with score >=80. Thus these names do not guarantee statistically independent evidence. Fusion then caps score at 75 when there are zero independent categories and score exceeds 75; at 85 when exactly one independent category and score exceeds 85. If all *present* authentication mappings pass and at least one exists, score is capped at 15 when none of credential_theft, fraud, malware_delivery, identity, threat_intelligence or URL categories are present. The all-present check does not require all three auth checks to exist.

Evidence confidence is separate from score, but depends on category confidences and category breadth:

```text
.16×mean(category confidences)
+.30×mean(confidence for category scores>=65; otherwise overall mean)
+.28×mean(confidence for category scores>=80; otherwise previous mean)
+.14×min(1,independent_count/6)
+.12×max(min(1,corroborated_count/5), min(1,severe_count/4))
```

Overall confidence is `clamp_0_1(.55×model_support + .45×evidence_confidence)`, less contradiction penalty. `model_support = max(.50,min(.99,.50 + abs(model_probability−.50)×.98))`; if AI result is absent, probability defaults to zero and this formula yields .99 model support. Contradiction penalties are .04 MEDIUM, .08 HIGH, .12 CRITICAL, summed and capped at .25 (LOW .02 is defined but no LOW contradiction currently emitted).

Risk tier: >=90 CRITICAL, >=75 HIGH, >=50 MEDIUM, otherwise LOW. `_decision` (539) returns HIGH_CONFIDENCE_THREAT for a listed threat classification plus score>=90, confidence>=.80, evidence confidence>=.70, signals>=5; CORROBORATED_THREAT for listed threat + score>=78, confidence>=.70, evidence>=.45, signals>=3; likely legitimate for recognized benign classification + score<30/confidence>=.60; then SUSPICIOUS_REVIEW_REQUIRED if threat classification or score>=60; then likely legitimate if score<30/confidence>=.55; otherwise INSUFFICIENT_EVIDENCE. SOC severity thresholds are >=90 plus at least two critical signals and confidence>=.65 for CRITICAL, >=75 HIGH, >=50 MEDIUM, >=25 LOW, else INFO.

The API caller rounds fusion score to an integer for `threat_analysis.score`; its verdict thresholds are >=90 CRITICAL, >=50 HIGH RISK, >=30 SUSPICIOUS, else LOW RISK. If fusion is not ANALYZED, it instead sums parser rule score and IOC score capped at 100. This can yield an API verdict that differs from fusion risk tier/decision. `calculate_ioc_threat_score` (main.py:1364) contributes +15/+20/+25/+30 per IOC based on strongest record confidence (<50/50/70/90 thresholds), capped at 60.

### C. Findings and defect register

| Severity | Finding and evidence | Effect |
|---|---|---|
| High | Correlation groups are populated and summarized in `_fuse` (459), but final weighted formula iterates categories without using `correlation_group_scores` (469 onward). | Related evidence across categories can influence the base, corroboration and count-based bonuses independently. |
| High | Missing AI defaults to probability 0, then `model_support` computes .99 (analyze_email_intelligence, 585–595). | Missing model can inflate overall confidence; absence is treated as extreme model support. |
| High | The auth cap checks all mappings that happen to be present; `has_auth_results` only requires one (around 604). | A partial SPF PASS can satisfy the “all pass” condition; incomplete DKIM/DMARC is not distinguished. |
| High | Content matching is substring-only (`_has_any`, 115; `_content_signals`, 174). | Quoted examples, “do not enter your password,” legitimate invoices and ordinary “director” language can trigger risk. No explicit negation/context handling. |
| High | Fusion exception path in `main.py` emits numeric score 0 and LOW tier (around 3242); caller then uses parser+IOC fallback (3275–3289). | Error/unknown state can be presented as a low numeric result, and fallback score is a different scoring contract. |
| Medium | `_ti_signals` assigns 52 to valid non-malicious/unknown matches (342–359). | A benign or unrecognized match adds risk instead of describing lookup state or neutral evidence. |
| Medium | Data quality counts mapping presence, not successful checks (`_calculate_data_quality`, 429). | An error-shaped mapping may count as available enrichment; an unavailable check can be indistinguishable from no finding. |
| Medium | Forensics adapter expects root `findings` (324), while orchestrator places findings under `header_anomaly_analysis`. | Forensic signals may silently disappear. |
| Medium | Parser/fusion both inspect URL-related evidence: parser keyword score can add 10 per extracted URL; URL intelligence can separately emit a signal; TI may also match the same URL. These are plausible overlaps, not proof of duplication without matching evidence identity. | One URL may affect multiple scoring components, particularly parser+IOC fallback. |
| Medium | Identity emits address and domain mismatch signals from the same sender/Reply-To pair (203–214). Content credentials plus urgency/social language can also create separate categories from overlapping phrases (174–201). Exact dedup only removes identical category/name/evidence tuples (395–402). | Signal counts and category/breadth thresholds can rise on shared evidence. Current code does not track evidence spans or duplicate relationships. |
| Medium | `_url_signals` ignores `link_deception_intelligence`; parser passes multiple URL analyses, while fusion consumes only one summary (239–252). | Some available detector results do not contribute; same URL evidence may also be summarized differently across pipeline outputs. |
| Medium | `score_breakdown` is corrected after caps by adjusting its final line (analyze_email_intelligence, around 610–619). | Displayed component attribution can absorb cap/floor/clamp deltas into “evidence breadth” rather than identify the actual adjustment. |
| Medium | No risk-negative evidence enters fusion; PASS auth and benign reputation do not reduce category scores. Only a narrow auth cap applies. | Positive and negative evidence are asymmetric; verified benign context is not independently represented. |
| Medium | API rounds the fusion score before verdict while fusion decision/tier use its unrounded score (main.py around 3275 onward). Fallback also uses different thresholds/formula. | UI/API verdict and SOC fusion fields can diverge near boundaries or on fusion error. |

## D. Evidence duplication and representation

The fusion response includes signal evidence records, aggregated `risk_drivers`, `critical_signals` (a filtered repeat of signal records), score breakdown, fusion metrics, correlation summaries, and explanation summaries. These are overlapping representations of the same analysis, not independent observations. `signal_count` counts signals; it does not count unique evidence objects. Deduplication is exact string equality on `(category,name,evidence)` and cannot recognize semantically shared evidence.

Some upstream protections exist: `email_parser.extract_urls` deduplicates URL strings, and the URL analyzer chooses a maximum risk across URLs rather than summing every URL. This reduces repeated URL counts within those paths, but does not deduplicate a parser keyword finding, a URL reputation finding, a threat-intelligence match and a deception finding that all reference the same normalized URL. Treat such cross-detector overlap as a correlation candidate and verify by evidence reference before discounting it.

## E. Proposed design (not implemented)

### Canonical signal and score-ledger schema

Each detector should emit a normalized signal with:

- `signal_id`, `detection_id`, `rule_id`, `rule_version`, `detector`, `category`, `assertion`.
- `polarity`: `risk`, `benign`, `context`, or `coverage`.
- `status` and `availability`: `complete`, `partial`, `unavailable`, or `not_checked`; preserve `error` separately.
- `evidence_refs[]`: stable references to a header occurrence, body span, normalized URL/IOC, attachment hash, or network address; include provenance and whether the fact is independently verified or merely reported.
- `raw_value`, `normalized_value`, `confidence`, `reliability`, `independence_group`, `correlation_key`, optional `duplicate_of`.
- `reason_code`, policy version, and per-signal `score_before` / `score_contribution`.

Emit a separate score ledger with component, supporting signal IDs, raw points, correlation adjustment, explicit cap/floor adjustment, and final points. Require the ledger sum to equal the canonical score exactly. The final report should reference this ledger rather than restating evidence as if repeated fields were independent.

### Proposed scoring and missing-data behavior

1. Count risk once per evidence object. Within a correlation group, take the strongest supported signal plus bounded corroboration only when additional signals cite distinct evidence refs or independent verification sources. Preserve all detector observations for audit.
2. Treat `unavailable`, `not_checked`, `error`, and “checked with no matches” as distinct coverage states. They do not add malicious points. Incomplete coverage can lower confidence or require review, but cannot silently become a clean result.
3. Keep risk score and confidence separate. Confidence should reflect evidence quality, independence and coverage, and must not be high merely because model probability is far from 0.5. Missing model means no model contribution, not a probability of zero.
4. Represent positive/benign evidence explicitly. A successful auth pass can support sender authenticity only with complete SPF/DKIM/DMARC status, alignment/policy context and verified provenance; it must not globally cap a message with unrelated malicious content.
5. Replace generic keyword checks with contextual, span-based intent rules. Handle quotation, negation, disclaimers, benign marketing/transactional language, sender/domain reputation and requested action. Keep urgency alone weak and require supported malicious action/context.
6. Keep parser fallback behavior explicit as a distinct score source and label the result as degraded/partial. Do not return a numeric zero/LOW as though fusion successfully assessed the message after an exception.
7. Give each scored result a machine-readable reason code, such as `CREDENTIAL_REQUEST_WITH_SUSPICIOUS_DESTINATION`, `AUTH_ALIGNMENT_FAILURE`, `URL_REPUTATION_CONFIRMED_MALICIOUS`, `BEC_PAYMENT_CHANGE_REQUEST`, `EVIDENCE_QUOTED_OR_NEGATED`, `MODEL_UNAVAILABLE`, or `TI_LOOKUP_UNAVAILABLE`. Each reason must point to the evidence refs and score ledger entries.

## F. Regression matrix and acceptance criteria (proposal)

| Class | Cases | Expected behavior to test |
|---|---|---|
| Legitimate promotional | Original labeled Myntra raw sample; routine discount/unsubscribe campaign; quoted security phrase in newsletter; promotional message with SPF/DKIM/DMARC results | No high-risk classification from generic keywords alone; authentic campaign context and verified sender evidence reduce false positives without hiding suspicious URLs or auth failures. |
| Legitimate business | Routine invoice/payment notice; security advisory saying “do not share your password”; director/finance references; attachment with completed clean scan | Context and negation prevent generic content triggers; payment terms alone do not imply fraud. |
| Phishing | Credential request with suspicious destination; login/verify URL; visible link differs from href; lookalike sender/reply domain; failing/misaligned auth; malicious URL also present in TI | Detect threat; repeated observations of one URL are correlated, not counted as independent proof; every contribution points to the same normalized URL evidence. |
| BEC/payment diversion | Executive impersonation asking for wire/beneficiary/bank detail change; reply-to mismatch; urgent request; clean or unavailable URL reputation | Detect BEC from intent/identity evidence even with no malicious URL; verified independent identity/auth evidence can corroborate. |
| Missing/partial data | Model unavailable; SPF only PASS with DKIM/DMARC absent; TI timeout versus successful no-match; IP lookup absent; incomplete attachment scan | Preserve coverage state; unavailable data does not become safe or malicious; confidence and disposition reflect missing evidence. |
| Determinism and explanation | Same immutable input analyzed twice; score cap/floor boundary cases; duplicated signal records with same/different evidence refs | Same policy/input yields stable score and reason codes; each ledger reconciles exactly; duplicates affect score only according to the documented correlation policy. |

Proposed acceptance gates: (1) reduce false positives by at least 30% relative to a frozen baseline on a held-out, labeled legitimate promotional/business set; report sample size and confidence interval; (2) no recall regression on a locked, labeled phishing/BEC positive set, including URL-less BEC and obfuscated credential phishing; (3) every nonzero score contribution has evidence refs, detector, reason code and policy version; (4) ledger totals reconcile exactly to the canonical score; (5) missing/error/partial checks are distinguishable and never treated as a clean pass; (6) repeated analysis of immutable input is deterministic. Establish minimum sample sizes and confidence-interval method during review before claiming the gates are met.

The original Myntra raw sample remains necessary to establish a valid case-specific expected outcome. Step 6 reported that the available reproduction used synthetic input and did not locate the original email fixture; do not treat that synthetic result as a labeled regression fixture.

## Runtime evidence versus static conclusions

This Step 7 document is based on source inspection. No Step 7 tests or email analysis were run, so formulas, branch behavior and schema mismatch statements are static conclusions. The Step 6 report records a separate synthetic Myntra analysis result and its missing-original-sample limitation; it is not runtime evidence for the scoring design’s proposed changes.

## Review handoff

Review the current score contract, the defect severities, canonical signal schema and acceptance gates before Step 8. No source files were changed for this step.
