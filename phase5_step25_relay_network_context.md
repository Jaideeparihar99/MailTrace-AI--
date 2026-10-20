# Phase 5 · Step 25 — Relay, VPN/Proxy/Tor and Hosting Context

**Step 25 status: COMPLETE for the implemented offline behavior and regression coverage.**
**Phase 5 gate: PASS for the stated engineering acceptance criteria; external provider due diligence and production validation remain pending. Phase 6 is not started and awaits explicit approval.**

## A. Verified Received-header parsing and trust model

### Pipeline and ordering

```text
Raw .eml / RFC message
  → email parser preserves Received values in source order
  → email_forensics.ip_extractor scans each header occurrence
      → shared IP policy validates/classifies with stdlib ipaddress
      → each candidate retains raw value, normalized/provider-safe value,
        source header index, character offset, scope and eligibility
  → email_parser.extract_received_chain / relay_chain.build_relay_chain
      → order hops OLDEST_TO_NEWEST
      → retain original zero-based header_index and one-based
        header_position_newest_first
  → timeline_analyzer uses the same chronological hop numbering
  → origin_scoring ranks observed relay IPs for review, not sender attribution
  → public-IP provider results retain provider/source/status/timestamp metadata
```

Receiving servers normally prepend `Received` fields, so the oldest observed field is at the end of the input list. The app now reverses that list for display and analysis while preserving its original index. Repeated IPs are retained once per header occurrence, so the same IP in separate hops does not lose its provenance. Duplicate identical header values are matched by index rather than by first equal string.

Uploaded `Received` fields are user-supplied message evidence. No trusted receiving-boundary configuration is currently connected to the upload analysis path, so every hop is marked `UNVERIFIED_MESSAGE_HEADER`. The app does not treat the oldest header as a trusted source or prove that the sender originated from any listed address. A trusted-boundary feature would require tenant-configured receiving infrastructure and authenticated transport metadata.

Malformed IP literals remain as invalid candidates with source offset and `INVALID_IP`; malformed relay syntax is marked `MALFORMED`; a syntactically plausible relay without a parsed IP is `NO_IP_FOUND`. Valid non-public IPs retain their local classification but cannot be sent to public providers. Candidate ranking no longer gives a score bonus to earlier header position.

## B. Network-intelligence source inventory

| Source | Integrated behavior | Provenance and limits |
|---|---|---|
| System reverse-DNS resolver | PTR lookup for public IPs in the v2 engine | Provider status includes `system_reverse_dns_resolver`, lookup timestamp and IP; a PTR name is contextual and not sender identity. |
| `ipapi.co` geolocation | Default public-IP geolocation source; IPinfo remains optional/config-gated | Existing Step 22 result includes provider, source, lookup timestamp, cache and approximate precision. Missing fields remain unavailable. |
| `ipapi.co` network endpoint | ASN, organization, network and version over HTTPS in the v2 engine | Results include `source=ipapi.co`, status and lookup timestamp. These fields do **not** establish hosting, proxy, VPN or Tor status. |
| AbuseIPDB | Optional reputation lookup when configured | Provider status and source/time metadata are carried in v2. A reputation match is a provider observation, not identity proof. |
| Legacy `ip-api.com` proxy/hosting call | **Disabled** | The existing implementation used plain HTTP. No approved secure configuration was present, so the app no longer trusts or calls it for these flags; values remain unknown. |
| VPN classification | No trusted VPN-specific source is integrated | `is_vpn = UNKNOWN` (`null`). Not inferred from ASN, organization, reverse DNS or geography. |
| Tor exit classification | No Tor exit-node feed/provider is integrated | `is_tor = UNKNOWN` (`null`). No Tor status is guessed. |
| Proxy/anonymization classification | No approved secure proxy-specific source is configured after disabling the legacy HTTP call | `is_proxy = UNKNOWN` (`null`). A future source must provide documented coverage and lookup time. |
| Hosting classification | No dedicated classification provider is configured | Organization/ASN keyword heuristics have been removed from the v2 classification path. `is_hosting = UNKNOWN` unless a future provider explicitly reports it with provenance. |

Provider failures and missing configuration remain explicit. No provider timestamp is fabricated for a lookup that did not run. Step 21's shared IP policy still blocks private, loopback, link-local, multicast, reserved, documentation and other non-global IPs before provider calls.

## C. Output schema and UI wording

### Relay hop fields

Each hop exposes:

- `hop`: chronological, one-based hop number.
- `header_index`: original zero-based position in the message header list.
- `header_position_newest_first`: original one-based position.
- `parse_status`: `PARSED`, `NO_IP_FOUND`, or `MALFORMED`.
- `trust_state` and `trust_basis`: currently `UNVERIFIED_MESSAGE_HEADER` and the reason no trusted boundary was supplied.
- `ip_candidates`: per-occurrence raw and normalized IP, classification, provider eligibility, source header and source offset.
- `malformed_ip_candidates`: invalid IP tokens with provenance.

`relay_context` and `relay_summary` explicitly return `chain_order=OLDEST_TO_NEWEST`, `trusted_receiving_boundary_configured=false`, and `sender_origin_established=false` with an attribution caveat. Ranked entries use `candidate_type=OBSERVED_RELAY_IP`, `attribution_status=UNVERIFIED_NOT_SENDER_ORIGIN`, source hop/header indexes, and provider source/status/timestamp records. Their `score` is an analyst-priority heuristic from routability and available threat evidence, not origin confidence.

### UI and reports

- Renamed **ORIGIN INTELLIGENCE** to **RELAY NETWORK CONTEXT**.
- The relay panel states the order and warns that supplied headers are unverified unless checked against a trusted receiving boundary.
- Each hop shows original header index, parse state, trust state and public/private scope where available.
- Network detail cards show provider/status/lookup time or state that no classification source is available.
- Geolocation copy says it estimates network-infrastructure location and does not establish sender identity or physical location. Proxy indicators do not prove VPN/Tor use or intent.

## D. Test matrix and observed results

Added `backend/tests/test_phase5_step25_relay_network_context.py` with 12 tests for:

1. Multiple Received headers and oldest-to-newest ordering with original indexes.
2. Repeated IPs across multiple headers retaining each source occurrence.
3. Private-to-public hop transitions and local classification.
4. Malformed IP tokens and malformed Received syntax remaining explicit.
5. Header position not boosting the relay candidate score.
6. Missing provider data leaving proxy/VPN/Tor/hosting unknown.
7. ASN/organization text not inferring hosting in the v2 engine.
8. Provider source and timestamp attached to an observed relay candidate.
9. Timeline and relay-chain numbering consistency.
10. Forensics response carrying unverified trust and attribution context.
11. Legacy plain-HTTP network classification disabled without making a request.

Regression command (run from `backend`):

```powershell
$env:PYTHONPATH = (Resolve-Path '.\venv\Lib\site-packages').Path
& 'C:\Users\ritur\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest `
  tests/test_phase5_step25_relay_network_context.py `
  tests/test_phase5_step21_ip_classification.py `
  tests/test_phase5_step22_geolocation_reliability.py `
  tests/test_phase5_step23_domain_intelligence.py `
  tests/test_phase5_step24_lookalike_domains.py `
  tests/test_phase3_step11_header_mime_parsing.py `
  tests/test_phase3_step14_explicit_states.py -q
```

Observed: **120 passed**. No live DNS, geolocation, reputation, proxy, VPN or Tor requests were used by these tests. Also passed `node --check frontend/script.js`, `py_compile` for changed Python files, and `git diff --check` (Git printed line-ending conversion warnings only).

## E. Attribution limits and remaining production work

- Any `Received` header included in a message can be forged before it reaches a trusted mail server. This build has no organization-specific trusted-hop boundary, so it reports observed infrastructure rather than a verified origin.
- IP geolocation is approximate and locates network infrastructure; it cannot identify a person or their exact physical location.
- ASN, organization, hostname, hosting, proxy, VPN and Tor are separate concepts. This implementation does not infer the latter four from ASN, hosting keywords or geolocation.
- VPN/Tor/proxy status is currently unknown because the only legacy proxy/hosting integration used plain HTTP and no approved secure replacement is configured. The source was disabled rather than presented as authoritative.
- WHOIS/domain-age remains `NOT_RUN` per Step 23's documented provider gap. DNS/MX enrichment remains opt-in and resolver-dependent.
- Step 22's mocked reliability tests pass, but live provider reachability, legal/contractual approval, and shared Redis behavior require deployment-specific review. They were not tested here.
- A future trusted relay boundary, VPN/proxy/Tor feeds, or hosting provider needs explicit coverage, freshness, confidence, retention and privacy review before activation.

## F. Phase 5 exit gate

| Step | Gate evidence | Status |
|---|---|---|
| 21 — Public/private/reserved IP handling | Shared standard-library policy, provider guards, IPv4/IPv6 and mapped-address tests | PASS |
| 22 — Geolocation reliability | Bounded provider/cache behavior and mocked success/failure coverage; no fabricated locations | PASS for code/tests; live provider and deployment checks pending |
| 23 — DNS/MX/domain age | Optional DNS/MX states and tests; WHOIS/domain age explicitly `NOT_RUN` because no approved provider exists | PASS for supported scope; age enrichment unavailable |
| 24 — Lookalike detection | PSL/IDNA/brand registry, explainable low-weight findings and benign cases; direct Step 24 tests pass | PASS for local service tests |
| 25 — Relay/network context | Chronological provenance, unverified-header status, provider inventory, cautious UI, 120-test combined regression | PASS |

**Phase 5 engineering acceptance: PASS with the documented unsupported/provider-deployment limits above.** No claim is made that VPN/Tor detection or WHOIS/domain age is implemented, that providers have been legally approved for production, or that a relay IP establishes sender origin. **Phase 6 remains pending explicit user approval.**
