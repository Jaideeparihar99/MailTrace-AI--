from __future__ import annotations

from email.message import EmailMessage

from services.email_forensics.ip_extractor import extract_ip_candidates
from services.email_forensics.origin_scoring import score_origin_candidates
from services.email_forensics.orchestrator import analyze_email_forensics
from services.email_forensics.relay_chain import build_relay_chain, summarize_relay_chain
from services.email_forensics.timeline_analyzer import analyze_timeline
from services.email_parser import extract_received_chain
from services import ip_intelligence
from services.ip_intelligence_v2.providers.network import classify_network
from services.ip_intelligence_v2.models import ProviderResult


def test_received_headers_are_returned_oldest_to_newest_with_raw_indices():
    message = EmailMessage()
    message["Received"] = "from newest.example [8.8.4.4] by edge.example"
    message["Received"] = "from oldest.example [10.1.2.3] by internal.example"

    chain = extract_received_chain(message)

    assert [hop["hop"] for hop in chain] == [1, 2]
    assert [hop["header_index"] for hop in chain] == [1, 0]
    assert [hop["ip_addresses"] for hop in chain] == [["10.1.2.3"], ["8.8.4.4"]]
    assert all(hop["trust_state"] == "UNVERIFIED_MESSAGE_HEADER" for hop in chain)
    assert all(hop["parse_status"] == "PARSED" for hop in chain)


def test_same_ip_in_multiple_received_headers_keeps_each_source_occurrence():
    headers = [
        "from relay-a.example [8.8.8.8] by mx.example",
        "from relay-b.example [8.8.8.8] by edge.example",
    ]

    candidates = extract_ip_candidates(headers)
    assert [(item["normalized_ip"], item["header_index"]) for item in candidates] == [
        ("8.8.8.8", 0),
        ("8.8.8.8", 1),
    ]
    assert [item["provider_ip"] for item in candidates] == ["8.8.8.8", "8.8.8.8"]


def test_private_to_public_hops_are_classified_without_trusting_the_earliest_hop():
    headers = [
        "from public.example [8.8.8.8] by edge.example",
        "from private.example [10.0.0.8] by internal.example",
    ]
    candidates = extract_ip_candidates(headers)
    chain = build_relay_chain(headers, candidates)

    assert chain[0]["ips"] == ["10.0.0.8"]
    assert chain[0]["ip_classifications"] == ["PRIVATE"]
    assert chain[1]["ips"] == ["8.8.8.8"]
    assert chain[1]["ip_classifications"] == ["PUBLIC"]
    assert chain[0]["trust_state"] == "UNVERIFIED_MESSAGE_HEADER"
    summary = summarize_relay_chain(chain)
    assert summary["sender_origin_established"] is False
    assert summary["chain_order"] == "OLDEST_TO_NEWEST"


def test_malformed_ip_and_malformed_received_hop_remain_explicit():
    headers = [
        "from relay.example [999.1.1.1] by mx.example",
        "not a valid Received field",
    ]
    candidates = extract_ip_candidates(headers)
    assert candidates[0]["valid"] is False
    assert candidates[0]["classification"] == "INVALID"

    message = EmailMessage()
    message["Received"] = headers[0]
    message["Received"] = headers[1]
    chain = extract_received_chain(message)
    assert chain[0]["parse_status"] == "MALFORMED"
    assert chain[0]["malformed_ip_candidates"] == []
    assert chain[1]["parse_status"] == "MALFORMED"
    assert chain[1]["malformed_ip_candidates"][0]["raw_ip"] == "999.1.1.1"
    assert chain[1]["ip_addresses"] == []


def test_relay_candidate_ranking_does_not_boost_untrusted_header_position():
    first = [{"hop": 1, "header_index": 2, "ips": ["8.8.8.8"], "ip_classifications": ["PUBLIC"]}]
    later = [{"hop": 5, "header_index": 0, "ips": ["8.8.8.8"], "ip_classifications": ["PUBLIC"]}]

    first_candidate = score_origin_candidates(first)[0]
    later_candidate = score_origin_candidates(later)[0]

    assert first_candidate["score"] == later_candidate["score"]
    assert first_candidate["candidate_type"] == "OBSERVED_RELAY_IP"
    assert first_candidate["attribution_status"] == "UNVERIFIED_NOT_SENDER_ORIGIN"
    assert first_candidate["source_header_indices"] == [2]


def test_provider_absence_keeps_proxy_vpn_tor_and_hosting_unknown():
    result = classify_network("Amazon Web Services", "ec2-1.example", "AS16509")
    assert result["classification"] == "UNKNOWN"
    assert result["status"] == "NOT_ASSESSED"
    assert result["hosting_signal"] is None

    candidate = score_origin_candidates([{
        "hop": 1,
        "header_index": 0,
        "ips": ["8.8.8.8"],
        "ip_classifications": ["PUBLIC"],
    }])[0]
    assert candidate["network_classification"] == "UNKNOWN"
    assert candidate["provider_sources"] == []


def test_v2_ip_profile_does_not_infer_hosting_from_asn_or_organization(monkeypatch):
    from services.ip_intelligence_v2 import engine

    monkeypatch.setattr(engine, "reverse_dns", lambda ip: ProviderResult(
        provider="reverse_dns", success=False,
        data={"status": "NO_DATA", "source": "test-resolver", "lookup_timestamp": "2026-10-19T00:00:00Z"},
    ))
    monkeypatch.setattr(engine, "get_geolocation", lambda ip: [ProviderResult(
        provider="ipapi", success=False,
        data={"status": "NO_DATA", "source": "ipapi.co", "lookup_timestamp": "2026-10-19T00:00:00Z"},
    )])
    monkeypatch.setattr(engine, "query_ipapi_network", lambda ip: ProviderResult(
        provider="ipapi_network", success=True,
        data={"status": "AVAILABLE", "source": "ipapi.co", "lookup_timestamp": "2026-10-19T00:00:00Z", "organization": "Amazon Web Services", "asn": "AS16509"},
    ))
    monkeypatch.setattr(engine, "get_reputation", lambda ip: [ProviderResult(
        provider="abuseipdb", success=False,
        data={"status": "NOT_CONFIGURED", "source": "abuseipdb.com/api/v2/check"},
    )])

    result = engine.analyze_ip_v2("8.8.8.8")
    assert result["organization"] == "Amazon Web Services"
    assert result["is_hosting"] is None
    assert result["is_proxy"] is None
    assert result["is_vpn"] is None
    assert result["is_tor"] is None
    assert result["provider_status"][1]["source"] == "ipapi.co"
    assert result["provider_status"][1]["lookup_timestamp"] == "2026-10-19T00:00:00Z"


def test_observed_relay_candidate_carries_provider_source_and_timestamp():
    candidate = score_origin_candidates(
        [{"hop": 1, "header_index": 0, "ips": ["8.8.8.8"], "ip_classifications": ["PUBLIC"]}],
        {"8.8.8.8": {"provider_status": [{
            "provider": "ipapi_network",
            "source": "ipapi.co",
            "status": "AVAILABLE",
            "lookup_timestamp": "2026-10-19T00:00:00Z",
        }]}},
    )[0]
    assert candidate["provider_sources"] == [{
        "provider": "ipapi_network",
        "source": "ipapi.co",
        "status": "AVAILABLE",
        "lookup_timestamp": "2026-10-19T00:00:00Z",
    }]


def test_repeated_headers_with_same_text_are_matched_by_index_not_first_equal_value():
    header = "from duplicate.example [8.8.4.4] by mx.example"
    headers = [header, header]
    candidates = extract_ip_candidates(headers)
    chain = build_relay_chain(headers, candidates)

    assert [hop["header_index"] for hop in chain] == [1, 0]
    assert [hop["ip_candidates"][0]["header_index"] for hop in chain] == [1, 0]


def test_timeline_uses_the_same_oldest_to_newest_hop_numbering():
    result = analyze_timeline({
        "received": [
            "from new.example by mx; Thu, 01 Jan 2026 01:00:00 +0000",
            "from old.example by edge; Thu, 01 Jan 2026 00:00:00 +0000",
        ],
        "date": None,
    })
    assert result["chain_order"] == "OLDEST_TO_NEWEST"
    assert [item["header_index"] for item in result["received_with_dates"]] == [1, 0]
    assert [item["hop"] for item in result["received_with_dates"]] == [1, 2]
    assert result["chronological_order"] == "ASCENDING"


def test_forensics_api_exposes_unverified_received_chain_context_without_provider_calls():
    raw = (
        b"From: sender@example.invalid\r\n"
        b"Received: from newest.example [8.8.8.8] by mx.example; Thu, 01 Jan 2026 01:00:00 +0000\r\n"
        b"Received: from oldest.example [10.0.0.3] by edge.example; Thu, 01 Jan 2026 00:00:00 +0000\r\n\r\n"
        b"Body"
    )
    result = analyze_email_forensics(raw, verify_authentication=False)
    assert result["relay_context"]["sender_origin_established"] is False
    assert result["relay_summary"]["chain_order"] == "OLDEST_TO_NEWEST"
    assert result["relay_chain"][0]["header_index"] == 1
    assert result["relay_chain"][0]["ip_classifications"] == ["PRIVATE"]
    assert result["relay_chain"][1]["ip_classifications"] == ["PUBLIC"]
    assert all(item["attribution_status"] == "UNVERIFIED_NOT_SENDER_ORIGIN" for item in result["origin_scoring"]["candidates"])


def test_legacy_untrusted_plain_http_network_provider_is_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(ip_intelligence.urllib.request, "urlopen", lambda *args, **kwargs: calls.append(args))
    result = ip_intelligence.get_network_intelligence("8.8.8.8")
    assert calls == []
    assert result["state"] == "NOT_CONFIGURED"
    assert result["is_proxy"] is None
    assert result["is_hosting"] is None
    assert result["is_vpn"] is None
    assert result["is_tor"] is None
