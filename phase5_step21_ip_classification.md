# Phase 5 â€” Step 21: Public, Private and Reserved IP Handling

**Date:** 2026-10-19
**Status:** PASS for the inspected IP handling and provider-call safeguards after follow-up audit.
**Handoff:** Stop for review. Step 22 has not been started.
**Safety boundary:** No live geolocation, reputation, or DNS provider requests were made by the Step 21 test runs; provider calls were stubbed/guarded.

## 1. Executive summary

Inspected the Phase 1 pipeline trace and the current IP parsing, extraction, intelligence engines, provider clients, relay-chain and IOC paths before making changes. Added one shared library-backed policy (`backend/services/ip_address_policy.py`) and routed both the legacy IP engine and the v2 IP engine through it. Public providers now independently reject invalid/non-public addresses as a defence-in-depth control; the orchestrators also short-circuit before provider calls.

A follow-up call-graph audit found an additional outbound route: email IOC enrichment through `services/threat_intelligence/providers/orchestrator.py` called VirusTotal, ThreatFox and AbuseIPDB outside the IP-intelligence engines. That path and its direct HTTP adapters now enforce the same shared policy. Private, reserved, malformed, and mapped-private IP IOC values are explicitly recorded as not applicable/invalid without provider calls. Public mapped IPv6 values use their canonical IPv4 form for provider lookups.

Only an address classified `PUBLIC` and `is_global == True` receives a `provider_ip`. Public provider calls use that canonical address. IPv4-mapped IPv6 is classified using its embedded IPv4 address: mapped private addresses are blocked; mapped public addresses are passed to providers as canonical IPv4. The original input and parsed normalized representation are returned separately.

Non-public input returns `status: NOT_APPLICABLE` and `enrichment_status: NOT_PUBLIC`, with provider states explicitly marked `NOT_APPLICABLE`; malformed input returns `status: ERROR` and `enrichment_status: INVALID_IP`. The IOC scope classifier and Received-header extraction now share the same policy.

## 2. IP-handling call graph and provider call sites

### A. IP Intelligence API (v2)

```text
POST /api/ip-intelligence or /api/ip-intelligence/batch
  -> routes/ip_intelligence_routes.py
  -> services/ip_intelligence_v2/engine.py:analyze_ip_v2
  -> validators.validate_ip (stdlib ipaddress.ip_address)
  -> validators.classify_address
  -> services/ip_address_policy.py:classify_ip
       INVALID -> ERROR / INVALID_IP; no provider calls
       non-public -> NOT_APPLICABLE / NOT_PUBLIC; local result only
       public -> canonical provider_ip
  -> providers.dns.reverse_dns
  -> providers.geolocation.get_geolocation
       -> query_ipapi (ipapi.co)
       -> query_ipinfo (ipinfo.io), only if token configured
  -> providers.network.query_ipapi_network (ipapi.co)
  -> providers.reputation.get_reputation
       -> query_abuseipdb (AbuseIPDB)
```

Every v2 provider entry point also calls the shared public-IP guard before network I/O. This protects direct callers as well as the normal engine path.

### B. Legacy email-parser/IP intelligence path

```text
services/email_parser.py:extract_received_chain
  -> services/email_forensics/ip_extractor.py:extract_ip_candidates
  -> services.ip_address_policy:classify_ip (parsed/validated with ipaddress)
  -> extract_ips_from_chain -> analyze_ips -> services/ip_intelligence.py:analyze_ip
  -> shared classification policy
       invalid/non-public -> local result; no reverse DNS/geolocation/network lookup
       public -> socket reverse lookup, get_ip_geolocation (ipapi.co),
                 get_network_intelligence (ip-api.com)
```

Both legacy provider functions also guard direct calls. The legacy IP analysis path no longer treats `100.64.0.0/10` shared space, documentation addresses or other special-use ranges as public just because they are not ordinary RFC1918 private addresses.

### C. Forensic relay and origin path

```text
services/email_forensics/orchestrator.py
  -> parse Received headers
  -> extract_ip_candidates / extract_public_ips
  -> relay_chain.build_relay_chain
  -> origin_scoring.score_origin_candidates
```

The forensic extractor uses a candidate-matching regex only to locate possible text spans; each candidate is validated/classified by `ipaddress` and the shared policy. `extract_public_ips` returns only eligible provider IPs and deduplicates equivalent public addresses (including a public IPv4-mapped IPv6 address). Origin scoring assigns no public-origin score to `PRIVATE`, `LOOPBACK`, `LINK_LOCAL`, `MULTICAST`, `UNSPECIFIED`, `DOCUMENTATION`, `RESERVED`, `SPECIAL_USE`, or other non-public candidates.

### D. IOC and authentication paths

- `services/threat_intelligence/ioc_normalizer.py`: IP candidates are validated with `ipaddress`; `_ip_scope` now uses the shared policy, including mapped IPv6 and special-use ranges. Regexes locate candidates; they do not validate addresses.
- `services/threat_intelligence/providers/orchestrator.py` -> `http_clients.py`: IP IOC reputation lookups are classified before fan-out; non-public/invalid IPs get explicit skipped provider results. The HTTP adapter functions repeat the guard for direct callers. Public mapped IPv6 is passed as canonical IPv4.
- `services/email_forensics/authentication_analyzer.py`: a trusted SMTP `client_ip` is checked by the same policy before SPF validation. Invalid/non-public client IPs are marked not verifiable and are not used for SPF lookup.
- URL/domain components (`url_extraction.py`, `domain_alignment.py`, `email_forensics/url_analyzer.py`, and `advanced_url_intelligence.py`) also parse literal IPs with `ipaddress`; they do not call the IP geolocation/reputation provider clients directly.

## 3. Classification policy

The implementation uses Python's standard-library `ipaddress.ip_address()` parser and address properties (`is_global`, `is_private`, `is_loopback`, `is_link_local`, `is_multicast`, `is_unspecified`, `is_reserved`). An explicit conservative special-use policy supplements library flags because some special-purpose/anycast ranges may not be uniformly represented by `is_global` across Python versions.

| Classification | Policy / examples | External public enrichment |
|---|---|---|
| `PUBLIC` | Valid, globally routable address not in an explicitly blocked special-use range; e.g. `8.8.8.8`, `2606:4700:4700::1111` | Eligible; use `provider_ip` |
| `PRIVATE` | RFC1918 IPv4, IPv6 ULA; e.g. `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | `NOT_PUBLIC`; skip |
| `LOOPBACK` | `127/8`, `::1` | `NOT_PUBLIC`; skip |
| `LINK_LOCAL` | `169.254/16`, `fe80::/10` | `NOT_PUBLIC`; skip |
| `MULTICAST` | IPv4 `224/4`, IPv6 `ff00::/8` | `NOT_PUBLIC`; skip |
| `UNSPECIFIED` | `0.0.0.0`, `::` | `NOT_PUBLIC`; skip |
| `DOCUMENTATION` | `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `2001:db8::/32` | `NOT_PUBLIC`; skip |
| `RESERVED` | Reserved IPv4/IPv6 address space, including `240/4` | `NOT_PUBLIC`; skip |
| `SPECIAL_USE` | Explicitly blocked ranges including `100.64/10`, `192.0.0/24`, `192.88.99/24`, `198.18/15`, `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2002::/16`, `3fff::/20` | `NOT_PUBLIC`; skip |
| `NON_GLOBAL` | Any other parsed address for which library semantics do not establish global routability | `NOT_PUBLIC`; skip |
| `INVALID` | Empty/malformed input, e.g. `999.1.1.1`, `2001:::1` | `ERROR` / `INVALID_IP`; skip |

Policy ordering intentionally classifies documentation and explicit special-use ranges before generic private/global flags. All non-public categories have `provider_ip: null`. The explicit special-use ranges are conservative exclusions for enrichment, not a complete replacement for an authoritative IANA registry feed.

### Original versus normalized representation

- `raw_input`: the original submitted string.
- `normalized_ip`: the parser's canonical representation (IPv4-mapped IPv6 remains represented as mapped IPv6 here).
- `provider_ip`: `null` unless eligible; for public IPv4-mapped IPv6, the canonical embedded IPv4 string is used.
- `classification`, `is_global`, `status`, and `enrichment_status`: explicit decision fields.

## 4. Evidence that non-public addresses do not reach providers

The focused tests monkeypatch provider/network entry points to raise if invoked for non-public inputs. The tests cover both orchestrators and direct provider calls:

- v2 analysis returns local `NOT_APPLICABLE` results for private, loopback, link-local, multicast, documentation, shared/special-use and mapped-private addresses without invoking DNS, geolocation, network or reputation providers.
- Legacy analysis returns `NOT_APPLICABLE` for non-public inputs and never invokes reverse DNS, geolocation or network providers.
- Direct calls to `query_ipapi`, `query_ipinfo`, `get_geolocation`, `query_ipapi_network`, `query_abuseipdb`, `get_reputation`, `reverse_dns`, `get_ip_geolocation` and `get_network_intelligence` are guarded before network I/O.
- Direct email IOC provider adapters (`lookup_abuseipdb`, `lookup_virustotal(..., ioc_type="ip")`, and `lookup_threatfox(..., ioc_type="ip")`) reject non-public/malformed IPs before HTTP. Orchestration tests prove private, loopback, documentation, mapped-private, and malformed IPs produce zero provider calls.
- Public IPv4-mapped IPv6 is passed to stubbed providers as canonical IPv4; mapped-private IPv6 has no provider IP.
- Malformed input returns `INVALID_IP` and does not become an empty successful lookup.
- Received-header extraction retains `raw_ip`, normalized representation, classification and eligibility; only eligible public addresses appear in `extract_public_ips`.
- Origin scoring rejects non-public/special-use relay candidates from the public-origin ranking.

No external provider calls were made to obtain these test results; network access was not required to prove the guards.

## 5. Test commands and observed output

Run from `backend/` with the project virtual environment.

### Focused Step 21 + relevant Phase 3 regression tests

```text
.\venv\Scripts\python.exe -m pytest -q -ra tests\test_phase5_step21_ip_classification.py tests\test_threat_intel_provider_orchestration.py tests\test_threat_intel_http_clients.py tests\test_phase3_step13_ioc_normalization.py tests\test_phase3_step14_explicit_states.py
```

Observed: **132 passed in 0.50s**, exit code `0`.

Coverage includes common IPv4 private ranges; IPv6 ULA/private; public IPv4 and IPv6; loopback; link-local; multicast; unspecified; reserved; IPv4/IPv6 documentation; shared/special-use; malformed addresses; IPv4-mapped IPv6 (private and public); direct provider guard assertions; no-provider-call assertions; Received-header candidate preservation; origin scoring; and IOC normalization/scope.

The command covers the separate live email-IOC provider route and direct adapter calls as well as Step 21 and related Phase 3 cases.

### Canonical Phase 4 offline regression gate

```text
.\venv\Scripts\python.exe scripts\run_phase4_offline.py
```

Observed after the Step 21 code changes: **66 passed, 8 parser subtests passed, 0 failed, 0 skipped** in `5.76s`; evaluator baseline `mailtrace-phase4-step18-offline-v1: MATCH`; gate `PASS`; exit code `0`. Existing synthetic metrics remained `TP=3 FP=0 TN=3 FN=0`, with 2 inconclusive/excluded fixtures.

### Syntax compilation

`py_compile` passed for all changed Python modules. No live-provider integration or long-duration flake campaign was run.

## 6. Changed files

- `backend/services/ip_address_policy.py` â€” shared parser/classifier, special-use CIDR policy, provider eligibility and mapped-IPv6 handling.
- `backend/services/ip_intelligence.py` â€” legacy engine and direct provider guards; explicit invalid/non-public states; separate raw/normalized/provider IP fields.
- `backend/services/ip_intelligence_v2/validators.py` â€” uses shared classification semantics.
- `backend/services/ip_intelligence_v2/engine.py` â€” local-only fast path for every non-public category; canonical provider IP; explicit status fields.
- `backend/services/ip_intelligence_v2/providers/geolocation.py` â€” guards ipapi and IPinfo entry points.
- `backend/services/ip_intelligence_v2/providers/network.py` â€” guard for ipapi network intelligence.
- `backend/services/ip_intelligence_v2/providers/reputation.py` â€” guard for AbuseIPDB.
- `backend/services/ip_intelligence_v2/providers/dns.py` â€” guard reverse DNS for non-public IPs.
- `backend/services/email_forensics/ip_extractor.py` â€” validated candidate metadata, IPv4-mapped IPv6 extraction, public-only provider list.
- `backend/services/email_forensics/origin_scoring.py` â€” non-public relay candidates receive no public-origin score; relay position is not described as proof of sender origin.
- `backend/services/email_forensics/authentication_analyzer.py` â€” shared policy for trusted SMTP client IP before SPF checks.
- `backend/services/email_parser.py` â€” Received-header chain uses validated shared candidate extraction instead of IPv4-only regex extraction.
- `backend/services/threat_intelligence/ioc_normalizer.py` â€” shared scope policy and mapped IPv6 candidate support.
- `backend/services/threat_intelligence/providers/orchestrator.py` â€” gates IP IOC enrichment and records `NOT_APPLICABLE` / `INVALID_IP` provider skips.
- `backend/services/threat_intelligence/providers/http_clients.py` â€” direct guards for AbuseIPDB, VirusTotal IP and ThreatFox IP adapter entry points; normalizes public mapped IPv6.
- `backend/tests/test_phase3_step13_ioc_normalization.py` â€” updates the shared-address classification expectation to `SPECIAL_USE`.
- `backend/tests/test_phase5_step21_ip_classification.py` â€” focused Step 21 regression suite.
- `backend/tests/test_threat_intel_provider_orchestration.py` and `backend/tests/test_threat_intel_http_clients.py` â€” non-public IOC no-call and direct-adapter guards.

## 7. Known limitations and relay-trust interpretation

1. **Received headers are not automatically trusted.** An attacker can inject or manipulate lower `Received` headers. Extracted IPs are observations from a relay chain, not proof of the original sender's address. Trust must come from known receiving infrastructure boundaries and validated SMTP context, not from header order alone.
2. **A public relay IP is not the sender's physical location.** IP geolocation estimates network registration/egress or provider-reported geography. It cannot identify a person's exact location and may point to a VPN, proxy, NAT gateway, cloud service, mobile carrier, or mail relay.
3. **Special-use exclusions are intentionally conservative.** The explicit ranges are maintained in code and should be reviewed against current IANA special-purpose registries as policy evolves. The standard-library `ipaddress` behavior can change between Python releases.
4. **Provider guards are local code controls, not a network sandbox.** All discovered IP geolocation/reputation provider call sites are guarded, but this work does not claim to audit every arbitrary outbound network request in the entire application.
5. **Provider correctness is not tested live.** The tests prove the non-public guard and canonical address selection with stubs; they do not validate the accuracy, availability, terms or privacy behavior of third-party providers.
6. **IPv4-mapped IPv6 may appear in raw evidence under multiple textual forms.** Provider lookups are normalized to embedded IPv4 for eligible mapped addresses. IOC evidence retains the raw source fragment separately from its canonical representation.

## 8. Final acceptance and handoff

- [x] Library-backed IPv4/IPv6 parsing and explicit conservative policy.
- [x] Non-public IPs cannot reach public geolocation/reputation providers through either engine or direct provider entry points.
- [x] Explicit `NOT_APPLICABLE` / `NOT_PUBLIC` and `INVALID_IP` states.
- [x] Original input and normalized/provider representations kept separately.
- [x] IPv4-mapped IPv6 classified using the embedded IPv4 address.
- [x] IPv4/IPv6 edge-case and provider-call tests added and passing.
- [x] Relay-trust and geolocation limitations documented.
- [x] Canonical Phase 4 regression baseline still matches.
- [x] Email IOC reputation orchestration and direct HTTP adapters also block non-public/malformed IPs; public mapped IPv6 is normalized before enrichment.

**Step 21 is ready for review. Stop here; do not start Step 22 until approved.**

## 9. Broader repository suite result (additional disclosure)

After the focused Step 21 tests and canonical Phase 4 gate passed, the full backend pytest suite was also attempted with:

```text
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -ra -q
```

Observed result: **410 passed, 16 failed, 8 subtests passed in 32.12s**. The failing tests are outside the focused IP-classification test module and were in these existing areas:

- `tests/test_alert_tenant_isolation.py` â€” 3 failures.
- `tests/test_evidence_error_sanitization.py` â€” 2 failures.
- `tests/test_investigation_routes_security.py` â€” 4 failures.
- `tests/test_response_execution_verification.py` â€” 4 failures.
- `tests/test_threat_intelligence_sync_service.py` â€” 3 failures.

At the time of this initial run, the **full repository suite was not green**. A clean full-suite run from before this change was not captured, so this report does not assert that the failures were pre-existing. The follow-up section below records the remediation and subsequent clean verification.

## Regression Fix Follow-up â€” 2026-10-16

The previously reported full-backend-suite failures have been addressed in the local working tree. No Phase 6/Step 22 work was started.

### Changes made
- Tenant-scoped security alerts: list queries are tenant-filtered; acknowledge/resolve mutations and history/gateway-integrity reads now scope access to the authenticated tenant and fail closed without an appropriate principal/role.
- Evidence error sanitization: evidence lookup and integrity failures return a generic `Evidence not found.` response rather than exposing exception strings or filesystem/database paths.
- Investigation route security: list and single-investigation handlers reject missing principals with HTTP 401, re-raise intentional HTTP errors, and return a generic `Internal server error.` for unexpected failures.
- Response verification: string boolean values are parsed explicitly (so `"false"` is false); IOC observations must match the actual response IOC; corrected the action-completion check construction; bound the transition and verification URLs to their intended handlers; transition audit actor comes from the authenticated principal.
- Threat-intelligence sync: only indicators from successful providers with non-empty IOC and IOC type are persisted; safe provider `error_type` is preserved without exposing raw provider error details.

### Verification results
- Previously failing five test groups: **20 passed**.
- Full backend suite: **426 passed, 8 subtests passed, 0 failures** (33.47 seconds).
- Canonical Phase 4 offline gate: **PASS**; 66 passed, 8 subtests passed; baseline `mailtrace-phase4-step18-offline-v1` matched; TP=3, FP=0, TN=3, FN=0, 2 inconclusive.
- Step 21 IP classification + Phase 3 IOC/state tests: **51 passed**.
- `py_compile` on the changed Python modules: **passed**.

These are local automated test results only; they do not establish production accuracy, security certification, or live-provider behavior. Step 22 remains not started.

## Step 21 Provider-Route Follow-up — 2026-10-19

The additional email-IOC provider route was fixed and verified after the original report. The current targeted IP + IOC-normalization/status + threat-intelligence adapter/orchestrator command reports **132 passed**. The full backend suite reports **545 passed, 1 opt-in live-geolocation test skipped, 16 subtests passed**. The canonical Phase 4 regression gate remains **90 passed, 16 subtests passed; baseline v4 MATCH**. No live provider requests were made. This closes the newly identified public-lookup guard gap in the inspected threat-intelligence call graph; provider accuracy and external service operation remain unverified. Step 22 has not been started.
