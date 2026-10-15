# MailTrace-AI — Step 3: Email Analysis Pipeline Trace

**Audit date:** 2026-10-12  
**Repository:** D:\jaideep\practice\practice\mailtrace ai\MailTrace-AI--  
**Scope:** Read-only trace from API input to final score/verdict, persisted analysis, UI report and evidence record. No fixes, package installs, sample-email runs, or claims of legal admissibility were made.

## Method and limits

The Step 1 handoff report was absent during Step 2, so this trace reverified current source. There is no prebuilt graphify-out/graph.json; building one would create generated artifacts, outside this read-only request. Current working-tree contents may differ from committed baseline. Runtime model artifacts, provider credentials, real DNS/network results, and prior uploaded message contents were not accessed.

The end-to-end path traced is POST /api/analyze-email; the signed email webhook invokes the same _analyze_email path with trusted SMTP context. A separate analysis CLI was not found; backend/main.py has a Uvicorn startup block.

## A. Verified pipeline

### 1. Ingress, file format and validation

backend/main.py::analyze_email delegates to async _analyze_email(file, trusted_smtp_context, tenant_id). The handler requires a filename ending .eml or .msg, reads at most 25 MiB + 1 byte and raises HTTPException(413) when larger, but that raise occurs inside a broad except Exception that wraps it as HTTP 500 with exception text (the intended 413 is therefore not preserved in this function). Missing filename/unsupported suffix checks occur before the try and return 400. It does not validate MIME type or magic bytes. A failure of evidence persistence also prevents a successful response.

backend/services/email_parser.py::parse_email parses EML with Python BytesParser(policy.default). For MSG it dynamically imports extract_msg, opens with delayAttachments=True, converts to EmailMessage and serializes to bytes for forensic parsing. If extract_msg is missing, it raises a runtime error.

### 2. Headers and identity fields

email_parser.py::extract_headers iterates message.items(), lowercases names, keeps all Received values in a list, but assigns every other header to a single dictionary value. Repeated From, Sender, Reply-To, Return-Path, Message-ID and Authentication-Results values are overwritten in this dictionary. basic_information uses message.get for Subject, From, To, Cc, Reply-To, Return-Path, Message-ID and Date; Sender is not included there.

The forensic path separately calls email_forensics/header_parser.py::parse_email_headers using raw_items(). It returns all raw headers as an all_headers list, duplicate lists for Received, Authentication-Results, Received-SPF and DKIM-Signature, plus first values for Return-Path, Reply-To, Message-ID, Date, Subject, From and To. It also extracts plain and HTML bodies. Thus forensics preserves repeats, while the primary parser/AI/UI fields lose duplicate non-Received values.

### 3. MIME, body, links and attachments

- email_parser.py::extract_body collects non-attachment text/plain MIME parts. For a single-part message, text/html is also accepted as body text. Decode failures are silently skipped.
- extract_html_body independently collects non-attachment text/html parts, capped at 32 parts / 2 MiB characters.
- extract_attachments handles MIME parts with filenames, sanitizes displayed filenames, decodes content under a 10 MiB per-file and 50 MiB aggregate limit, reports at most 200 attachments and statically analyzes at most 50. It hashes bytes and runs file-type analysis. ClamAV is optional, at most 10 attachments and 5 seconds total. Detonation is explicitly NOT_CONFIGURED; no scanner is NOT_CONFIGURED, not clean.
- extract_urls regex-matches HTTP(S) in extracted body text and deduplicates exact URLs. url_analysis::analyze_urls and advanced_url_intelligence::analyze_urls_deception run on those URLs. Rendered anchor href/visible-text deception analysis runs separately via link_deception_intelligence::analyze_link_deception_to_dict(html_body).
- Later IOC extraction uses only result.body.text, not HTML or headers. HTML-only links may be seen by link analysis but may not enter threat-intel lookup.

### 4. Authentication evidence versus validation

Two different structures exist:

1. email_parser.py::analyze_authentication(message) regex-parses attacker-controlled Authentication-Results values. It sets authentication_results_trusted=false and nested validation to UNVERIFIED_NO_TRUSTED_SMTP_IP / NOT_VALIDATED. It performs no DNS or cryptographic verification.
2. email_forensics/orchestrator.py::analyze_email_forensics calls email_forensics/authentication_analyzer.py::analyze_authentication(headers), then for EML calls it with raw bytes and optional trusted SMTP context. validate_email_authentication performs:
   - SPF: Only recomputed when HMAC-authenticated webhook context provides client IP, MAIL FROM and HELO. Non-global IP is not verifiable. Otherwise spf.check2 runs with limits. Browser uploads have no trusted SMTP context, so SPF remains UNVERIFIED_NO_TRUSTED_SMTP_IP.
   - DKIM: If signatures exist, verifies at most the first two raw signatures using dkimpy and DNS TXT keys. Any true outcome => PASS; all explicit false => FAIL; mixed/errors => TEMPORARY_ERROR_OR_INVALID_KEY. DNS resolver is configured with timeout/lifetime 1.5/3 seconds. Optional-library/runtime errors can make validation engine unavailable.
   - DMARC: Queries _dmarc.<visible From domain> and reports POLICY_FOUND, NO_POLICY, DNS_LOOKUP_ERROR or invalid domain. It does not evaluate alignment/disposition into PASS/FAIL. POLICY_FOUND is not a pass.
   - Authentication-Results/Received-SPF remain parsed reported claims, marked untrusted; they are not the validation result.
3. MSG forensics sets verify_authentication=False. Its DKIM/DMARC are NOT_VALIDATED, SPF unverified. It does not accept trusted SMTP context.

The auth analyzer also emits a heuristic risk/findings structure based on reported labels and From/Return-Path alignment. Main scoring does not directly consume this risk field.

### 5. Received chain, IPs and origin ranking

- email_parser.py::extract_received_chain preserves Received raw values in header order and extracts IPv4-shaped text with regex, without IP address validation there.
- email_forensics/ip_extractor.py::extract_ip_candidates extracts IPv4/IPv6 candidates, validates with ipaddress, deduplicates, classifies private/loopback/reserved/link-local/unspecified/public and skips malformed candidates. extract_public_ips retains only PUBLIC.
- email_forensics/relay_chain.py::build_relay_chain reverses Received order (oldest first), parses heuristic from/by hostnames, attaches extracted IPs and classifications. summarize_relay_chain counts public/private hops. The chain remains email-supplied evidence; this does not authenticate every hop.
- email_forensics/origin_scoring.py::score_origin_candidates ranks candidates: +25 public routable; +20/+12/+6 for hop 1/2/3-4; +5 hostname, +5 organization, +5 ASN; +20/+15/+5 for IP risk score >=80/60/30; +2 hosting. Private, loopback, reserved and documentation addresses are reset to 0. It caps 0–100 and describes candidate ranking, not attribution.
- The parser calls legacy services/ip_intelligence::analyze_ips for relay IPs; main calls it again for forensic candidates. Public addresses receive reverse DNS, ipapi.co and ip-api.com calls (8 second HTTP timeout); documentation, loopback, private and reserved addresses return local classification. Failures become notes, not necessarily endpoint errors.
- ip_intelligence_v2::analyze_ip_v2 validates and fast-paths special addresses, then queries v2 provider modules for public IPs. It is used by dedicated IP routes, not the main email relay enrichment path.

### 6. Rule score, model, TI and fusion

The parser creates an initial threat_analysis in email_parser.py::analyze_threat:

| Parser signal | Weight | Condition |
|---|---:|---|
| SPF validation fail | +20 | validation.spf.status == FAIL; parser validation is unverified, so normally no points here. |
| DKIM validation fail | +20 | validation.dkim.status == FAIL. |
| DMARC validation fail | +25 | validation.dmarc.status == FAIL. |
| Reply-To mismatch | +20 | Uses organizational_domain/eTLD+1 and requires both domains parse and differ. |
| Return-Path mismatch | +10 | Organizational domains differ and validated_dmarc != PASS. Parser validation normally says NOT_VALIDATED, so this condition can score even if a header claims DMARC pass. |
| Suspicious URL | +10 per URL | URL contains any of login, verify, verification, account, secure, password, update, confirm. One point allocation per matching URL, not per matched term. |
| Urgency | +10 total | Subject/body contains one or more fixed terms: urgent, immediately, within 24 hours, action required, account suspended, verify your account, failure to verify, confirm your account. |
| Multiple relays | 0 | Informational finding only at >=2 Received headers. |

Parser score clamps to 0–100; verdict thresholds are >=75 CRITICAL, >=50 HIGH RISK, >=30 SUSPICIOUS, else LOW RISK. Confidence labels are HIGH/HIGH/MEDIUM/LOW respectively. This initial score is normally overwritten. The >25 MiB handler branch intends 413 but the broad exception conversion makes the observed source path return 500 instead.

**Local ML:** main.py builds ai_email with sender, Reply-To, subject, plain body, headers, URLs, URL intelligence, rendered-link data, attachments and forensic authentication validation. It calls email_ai::analyze_email_ai -> inference::predict_email. features::build_email_text creates model text and feature evidence. inference::load_model prefers calibrated email_phishing_l3_calibrated_bundle.joblib, falls back to email_classifier.joblib; missing artifact returns MODEL_ARTIFACT_MISSING / MODEL_NOT_READY; load/inference failures return error statuses. Explainability failure yields empty explanation. Runtime artifact availability was not verified. Parser fallback is attached to AI result when model is missing, but fusion skips MODEL_NOT_READY/UNAVAILABLE/ERROR/SKIPPED.
 
**IOC/TI:** threat_intelligence/ioc_normalizer.py::extract_iocs finds valid IPs, IP:port, HTTP(S) URLs and domains from plain text, deduplicated in discovery order. Main looks up locally cached feed records and records freshness/coverage; live per-indicator lookup is false. No match with stale coverage is not evidence of safety. calculate_ioc_threat_score assigns per matched IOC: 15 (<50 confidence), 20 (>=50), 25 (>=70), 30 (>=90); cap total 60. This score contributes only when fusion is not ANALYZED. The main path also calls threat_intelligence_v2 engine, but fusion receives threat_intelligence matches, not the v2 result directly.

**Fusion:** email_ai/intelligence_fusion.py::analyze_email_intelligence combines AI, content, identity, validated auth, URL, attachments, forensic findings, TI and IP signals. The fusion object is preserved under analysis.intelligence_fusion; its score is copied into analysis.threat_analysis.score for API/UI/database.

## B. Function-level call chain

POST /api/analyze-email
→ backend/main.py::analyze_email
→ backend/main.py::_analyze_email
→ backend/services/email_parser.py::parse_email
→ extract_headers / extract_body / extract_html_body / extract_attachments / extract_urls / analyze_authentication / extract_received_chain / analyze_threat
→ URL, link, attachment and legacy IP sub-engines
→ backend/services/email_thread_intelligence/engine.py::analyze_thread_to_dict (one-message list)
→ backend/services/email_forensics/orchestrator.py::analyze_email_forensics
→ header_parser / header_anomaly_detector / ip_extractor / relay_chain / origin_scoring / authentication_analyzer / timeline_analyzer / URL analyzer
→ legacy IP enrichment
→ email_ai::analyze_email_ai → inference::predict_email → features::build_email_text
→ threat_intelligence.ioc_normalizer::extract_iocs → local database lookup → threat_intelligence_v2::analyze_threat_intelligence_v2
→ email_ai.intelligence_fusion::analyze_email_intelligence
→ main final score/verdict/confidence mapping
→ main::_build_evidence_governance → evidence_custody register/verify/seal → integrity_anchoring local create/verify
→ database.database::save_investigation
→ JSON response {success, investigation_id, filename, analysis}
→ frontend/script.js::showInvestigationResult and GET detail/history/report views.

The thread analysis is run on a one-message array, not a reconstructed conversation with previously stored messages.

## C. Detector / enrichment status and limitations

| Stage | Status and behavior | Output / failure semantics |
|---|---|---|
| Duplicate header anomaly | Called, but likely ineffective with wired shape: header_parser returns repeated values inside all_headers; header_anomaly_detector counts top-level dict keys and does not inspect all_headers. | Duplicate sensitive fields may not be counted; see prioritized issue. |
| Header anomaly scoring | Executed in forensics. From/Reply-To +15 high; From/Return-Path +8 medium; From/Sender +7 medium; Message-ID domain difference +4 low or missing Message-ID +6; missing Date +5; missing each From/To/Subject +5; control-character finding +15; duplicate sensitive header +8 if presented in expected shape. Sum caps at 100; low/medium/high bands at 1/25/50. | Nested under email_forensics.header_anomaly_analysis, not parser threat score directly. From/Reply-To/Return-Path compare registrable domains; From/Sender and Message-ID use full domain comparisons. |
| SPF | Conditional actual recomputation on signed webhook SMTP context. | Browser path unverified, not fail/pass. |
| DKIM | Conditional raw EML DNS key verification of max two signatures. | Pass/fail/temp/unavailable; errors do not equal pass. |
| DMARC | DNS policy lookup, not pass/fail alignment. | POLICY_FOUND/NO_POLICY/error. |
| URL legacy score | Called on extracted body URLs. +30 IP URL; +10 suspicious keyword up to +30; +25 brand indicator; +15 HTTP; +10 absent scheme; +15 deep subdomain; +10 long URL; +20 invalid/missing domain; capped 100, bands 25/50/75. Static heuristics, not reputation lookup. | Findings separate per URL. |
| Advanced URL deception | Called on body URLs; static parsing/deception rules; cap100, bands 30/50/75. | Fusion signal only if risk >=50 or selected suspicious verdict. |
| Rendered link deception | Called on HTML anchors; compares visible text and href, bounded parsing, may delegate static URL analysis. Per-link scores aggregate as mean; bands 10/20/40. | Fusion does not read link_deception_intelligence directly; findings may display without a fusion score signal. |
| Attachment inspection | Conditional on MIME attachment and caps; static type identity, hash and optional ClamAV; no detonation. | Not configured/limited/error are distinct from clean. Fusion can signal executable type, mismatches, incomplete scan or presence. |
| Local ML | Conditional on model artifacts. | Unavailable status suppresses ML signal; no external model provider confirmed. |
| TI cache | Conditional on plain-text IOCs and cached data. | Coverage status independent from match count. Unknown/nonmalicious valid match can create a fusion signal of 52. |
| IP enrichment | Legacy provider checks run for extracted IPs; origin ranking uses metadata. | Public IP fields may be missing on provider errors. No attribution. |
| Forensic fusion signal | Invoked but likely no-op with current caller shape. | _forensic_signals expects forensic.findings top-level; orchestrator returns findings nested in header_anomaly_analysis. |

These descriptions confirm code execution/wiring only; this audit did not validate detector precision/recall against samples.

## D. Final score, confidence and verdict

### Fusion signal categories and weights

| Category | Weight | Signal behavior |
|---|---:|---|
| ml | 1.45 | probability ×100; recognized phishing/fraud/malware classification floors score at 82 even if probability is lower. |
| threat_intelligence | 1.45 | Malicious match: min(100,88+7×count); valid nonmalicious/unknown match: 52. |
| header_forensics | 1.35 | Fail/softfail/permerror count: min(100,70+10×failures). |
| identity | 1.35 | Different sender/Reply-To address: 92; differing raw domains separately: 94. Compares full domains, not organizational domains. |
| malware_delivery | 1.30 | Confirmed scanner: 100; executable/script: min(96,78+5×count+5×masquerades); mismatch: 68. |
| credential_theft | 1.25 | Fixed credential/login terms => 90. |
| fraud | 1.25 | Payment/transfer terms => 88. |
| impersonation | 1.20 | Authority terms => 76. |
| forensics | 1.20 | Top-level high/critical findings => min(90,68+8×count), but likely no signal due shape mismatch. |
| infrastructure | 1.15 | Positive IP scores => .72×maximum + .28×mean. |
| url | 1.05 | If URL score >=50 or selected suspicious verdict, score=max(68,URL score). |
| social_engineering | 1.00 | Urgency AND social-action wording => 82, suppressed if promo context present. |
| attachment | 0.80 | Scan coverage unavailable/unverified => 52; otherwise attachment presence => 48. |

Content signals: credential and fraud terms are broad fixed substring lists; authority terms are CEO/CFO/director/admin/security/finance/management. Urgency requires both urgency terms and social-action terms; promotional context is inferred from promotional/unsubscribe fields, list-unsubscribe/bulk/marketing headers, or words such as discount/sale/offer/shop now/terms and conditions.

### Fusion score formula

Signals deduplicate on (category, name, evidence). Within a category, scores are averaged with confidence/reliability-adjusted weights. Category scores are then confidence-adjusted and weighted by the category weights above.

- base = weighted average category score.
- strong categories have score >=65; corroboration strength = mean of top four strong scores, else 0.
- weighted evidence = 0.62 × base; corroboration component = 0.38 × corroboration strength.
- independent categories exclude ML and require score >=55. Convergence bonus = min(15, 3 × (independent count − 1)).
- severity bonus: +2.5 at >=2 categories scoring >=80; +5 at >=4.
- corroboration bonus: +1 at >=2 categories scoring >=65; +2 at >=4.
- evidence breadth bonus: +2.5 at >=5 independent categories.
- Sum clamps 0–100. score_breakdown is rounded and adjusted to sum to emitted fusion score.

Post-fusion cap: no independent non-ML category >=55 caps scores above 75 to 75; exactly one caps above 85 to 85. A nominal cap at 15 also applies when all represented auth validation entries are PASS and no protected category exists. But validator DMARC returns policy statuses, browser SPF is unverified, and absent auth fields are ignored by the all() check if any other auth field exists. This cap contract is therefore not equivalent to “SPF, DKIM, DMARC all pass.”

### Confidence and fusion decision

Model probability defaults to zero when absent. model_support = clamp01(0.50 + abs(probability − 0.50) × 0.98), so missing/unavailable model can yield 0.99 model_support despite _ai_signal skipping that result. Evidence confidence combines category mean (0.16), strong mean (0.30), severe mean (0.28), breadth (0.14), and corroboration/severe support (0.12). Overall confidence = 0.55×model_support + 0.45×evidence confidence, then contradiction penalties are subtracted (.02/.04/.08/.12 by severity, total cap .25).

Fusion decision thresholds:
- HIGH_CONFIDENCE_THREAT: threat classification, risk >=90, overall confidence >=.80, evidence confidence >=.70, >=5 signals.
- CORROBORATED_THREAT: threat classification, risk >=78, confidence >=.70, >=3 signals, evidence confidence >=.45.
- LIKELY_LEGITIMATE: legitimate class, risk <30, confidence >=.60; or risk <30 and confidence >=.55.
- SUSPICIOUS_REVIEW_REQUIRED: threat class or risk >=60.
- Otherwise INSUFFICIENT_EVIDENCE.
Fusion risk tier is >=90 CRITICAL, >=75 HIGH, >=50 MEDIUM, else LOW. SOC severity has separate conditions: CRITICAL requires score>=90, at least 2 critical signals and confidence>=.65; HIGH>=75, MEDIUM>=50, LOW>=25, else INFO.

### Main final mapping and fallback

When fusion is ANALYZED with numeric score 0–100, main copies rounded unified_risk_score into threat_analysis.score and sets score_source=intelligence_fusion. Otherwise it uses min(parser rule score + IOC threat score, 100), source parser_rules_plus_ioc_fallback. Parser rule score is retained as rule_score.

Main remaps the final verdict differently from parser/fusion: >=90 CRITICAL; >=50 HIGH RISK; >=30 SUSPICIOUS; otherwise LOW RISK. Confidence becomes UNKNOWN unless fusion was valid and had at least one signal; HIGH additionally requires threat decision, confidence>=.80, evidence confidence>=.70, >=5 signals and >=2 independent categories; MEDIUM requires confidence>=.65 and evidence confidence>=.45; otherwise LOW. A fusion exception creates score 0/ERROR, selecting parser+IOC fallback. Missing evidence/provider coverage is not intrinsically benign.

## E. Data lineage and consistency

1. **API:** POST /api/analyze-email returns {success, investigation_id, filename, analysis}. analysis.threat_analysis contains final score/verdict/confidence and rule_score; analysis.intelligence_fusion preserves its separate score/tier/decision/breakdown; ioc_threat_score carries fallback evidence.
2. **Database:** database.py::save_investigation stores score/verdict/confidence as columns and serialized full analysis JSON. A failed database write prevents success response.
3. **Evidence:** evidence_governance is attached before JSON serialization and persistence.
4. **UI:** frontend/script.js::showInvestigationResult reads threat_analysis.score for the main score/band/verdict/confidence. For displayed breakdown it prefers intelligence_fusion.score_breakdown, otherwise parser breakdown. Thus a rounded main score can sit beside a decimal fusion score explanation, while the original parser rule score is separate. Other sections display their respective parser, URL, attachment, forensic, IOC and evidence-governance fields.
5. **History:** report cards use persisted DB score/verdict; opening a report loads the full analysis. Map view is a derived view, not a signed report export.
6. **Export/signing:** no PDF/CSV export or report-signing function was found in inspected source. UI report is rendered HTML/API data. Integrity anchor is not report signature.

## F. Evidence integrity

main.py::_build_evidence_governance registers original bytes using evidence_custody.register. Evidence custody calculates SHA-256/SHA-512, preserves a copy, verifies hashes against uploaded bytes, appends custody events, seals a record and supports recomputing evidence/preservation/seal/event-chain integrity. These are local integrity checks.

It then invokes IntegrityAnchorEngine.create_anchor(provider="local") over canonical commitment fields including evidence hash, terminal custody event hash and chain digest. It stores request/receipt in local SQLite and verifies with LocalAnchorProvider. That provider explicitly labels trust LOCAL_TEST_ONLY and says it is not independent; independent_verification remains false. No provider is registered for external RFC3161 TSA or immutable ledger in main.py. Local timestamps/hashes do not independently prove external time, author or custody. If preservation mismatch occurs, anchoring is skipped; exceptions can reach endpoint 500. Retention evaluation runs after custody/anchor handling.

## G. Prioritized failures and inconsistencies

### High priority

1. **Duplicate header detector input mismatch:** parser preserves repeated values inside all_headers, but detector counts keys of the top-level dict and does not inspect all_headers. Primary parser overwrites repeated non-Received fields. Duplicate identity headers can be missed or different sections can use different values.
2. **Upload size status mismatch:** the handler raises 413 inside its broad except Exception and rewrites it to 500; clients cannot rely on the intended size-limit status.
3. **Authentication status conflation:** parser/UI top-level authentication values are copied from untrusted Authentication-Results. Separate forensic validation is nested elsewhere. A PASS shown from reported header must not be presented as cryptographic server validation.
4. **DMARC status contract:** actual validator yields POLICY_FOUND/NO_POLICY/error, not PASS/FAIL. Auth failure fusion checks FAIL/SOFTFAIL/PERMERROR; parser Return-Path rule checks validated_dmarc != PASS, generally true for policy-found and unverified. This is not evidence of a DMARC failure.
5. **Forensic findings omitted from fusion:** orchestrator nests anomaly findings, fusion expects top-level findings. Header anomaly can appear in report but not contribute to fused score.
6. **False identity mismatch risk:** fusion compares sender/Reply-To addresses and full domains; parser/forensics use organizational domain for some checks. Legitimate aliases/subdomains can produce strong identity signals in fusion.
7. **Model missing but confidence support high:** absent model gives probability 0 and the confidence formula gives model_support .99; _ai_signal skips missing model, but confidence formula still uses its default. Overall confidence can be overstated despite no inference.
8. **Rendered-link detector disconnected from fusion:** link deception output is passed to AI envelope but fusion _url_signals reads advanced_url_intelligence or url_intelligence, not link_deception_intelligence. HTML href deception can be displayed without affecting overall score.

### Medium priority

8. **Nominal all-auth-pass cap miswired:** DMARC never emits PASS from validator; SPF is usually unverified. Partial maps can satisfy all() over only present checks. Cap semantics need explicit complete/missing/mixed-field cases.
9. **Multiple independent scores:** parser rule score, IOC fallback score, fusion score/tier, final mapped verdict, header anomaly score, URL scores and SOC severity use different thresholds and meanings. Consumers must use score_source and field provenance.
10. **Unknown TI matches can raise score:** any valid match not recognized as malicious creates score 52 category; local cache freshness is a separate factor. “No IOC-specific malicious matches” does not imply zero fusion signal.
11. **No signed report or external timestamp:** local custody hashes/anchor do not equal an externally witnessed signature/time. No legal-admissibility conclusion is supported.
12. **Old browser error vs current source:** current showInvestigationResult first reads a local fusionResult; intelligenceFusion is initialized at script top-level and used later during report rendering. The earlier pasted TDZ console error is not established by current source; stale cached JS or runtime order remains unverified. No browser execution was performed.
13. **Per-call timeouts, no whole analysis deadline:** serial external lookups and CPU work remain request-bound; provider errors often become notes/empty enrichment rather than endpoint failure, so success does not imply all detectors ran.

## H. Behaviors to test in Step 5

No tests were run. Test cases to add/execute later:

1. Duplicate From/Reply-To/Return-Path/Message-ID: raw preservation, finding behavior, selected-value consistency across parser, forensics, UI.
2. Forged Authentication-Results claiming all PASS: must remain untrusted and not become validated auth evidence.
3. DKIM valid/invalid, DNS timeout, malformed key/signature, >2 signatures and optional dependency missing.
4. Webhook SPF public/private/invalid client IP, null reverse path, DNS errors; compare browser upload (unverified).
5. DMARC policy present/absent/error and aligned/unaligned SPF/DKIM; assert policy-found is not pass.
6. eTLD+1/subdomain/private suffix/IDNA/malformed domain cases; compare parser, forensic anomaly, fusion.
7. Received IPv4/IPv6/private/loopback/link-local/reserved/unspecified/documentation/malformed addresses and spoofed hops; assert no attribution.
8. Multipart/alternative, nested parts, malformed encodings, HTML-only URLs, visible-text/href deception, duplicate URLs and attachment disposition/filename boundaries.
9. Attachment thresholds at 10 MiB, 50 MiB, 50 static, 200 reported, 10 ClamAV and 5 seconds; absent/clean/infected/error states.
10. Fusion signals: unavailable model; low probability plus threat label; promotional urgency; Reply-To same registrable domain; malicious/unknown TI; nested forensic findings; HTML-link-only deception; missing/partial auth.
11. Fusion formula: category weights, confidence/reliability weights, convergence/bonus boundaries, score breakdown sum, caps and 0–100 clamps.
12. Fusion success/error/malformed fallback, IOC confidence buckets and 60 cap; final verdict boundaries 29/30, 49/50, 89/90; confidence labels.
13. API vs SQLite columns vs detail endpoint vs UI report card/full report: score, verdict, confidence and breakdown provenance.
14. Evidence hash mismatch, tampered custody event/seal, local anchor verification, retention purge/encryption migration; assert LOCAL_TEST_ONLY is not presented as external timestamp/signature.
15. Upload and reload UI paths: same score fields and no TDZ error against current script.

## Handoff

The current call chain, detector status, scoring formula, failure/default paths, evidence handling and UI/API/database lineage have been traced. This is a read-only handoff; no fixes were made and Step 4 was not started. No legal admissibility or external timestamp assurance is claimed.



