import pytest
from services.threat_intelligence.providers import orchestrator


def _ok(provider):
    return {"provider": provider, "status": "ok", "available": True, "error_code": None, "http_status": 200, "data": {"source": provider}}


def _down(provider, code):
    return {"provider": provider, "status": "unavailable", "available": False, "error_code": code, "http_status": None, "data": None}


def test_ioc_types_route_to_expected_providers(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda value: calls.append(("abuseipdb", value)) or _ok("abuseipdb"))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda value, ioc_type="ip": calls.append(("virustotal", ioc_type, value)) or _ok("virustotal"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda value, **kwargs: calls.append(("threatfox", value)) or _ok("threatfox"))
    monkeypatch.setattr(orchestrator, "lookup_urlhaus", lambda value: calls.append(("urlhaus", value)) or _ok("urlhaus"))
    iocs = [
        {"ioc": "8.8.8.8", "value": "8.8.8.8", "ioc_type": "ip"},
        {"ioc": "https://example.com/a", "value": "https://example.com/a", "ioc_type": "url"},
        {"ioc": "example.com", "value": "example.com", "ioc_type": "domain"},
        {"ioc": "a" * 64, "value": "a" * 64, "ioc_type": "sha256"},
    ]
    result = orchestrator.enrich_iocs_with_live_providers(iocs)
    assert {"abuseipdb", "virustotal", "threatfox", "urlhaus"} <= {call[0] for call in calls}
    assert ("virustotal", "url", "https://example.com/a") in calls
    assert ("virustotal", "domain", "example.com") in calls
    assert ("virustotal", "hash", "a" * 64) in calls
    assert result["status"] == "available"
    assert result["available_result_count"] >= 8


@pytest.mark.parametrize("failure_code", ["AUTH_ERROR", "RATE_LIMITED", "PROVIDER_HTTP_ERROR", "TIMEOUT", "NETWORK_ERROR", "MALFORMED_JSON", "MALFORMED_SCHEMA"])
def test_provider_failure_is_ledgered_and_other_provider_results_survive(monkeypatch, failure_code):
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda value: _down("abuseipdb", failure_code))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda value, ioc_type="ip": _ok("virustotal"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda value, **kwargs: _ok("threatfox"))
    result = orchestrator.enrich_iocs_with_live_providers([
        {"ioc": "8.8.8.8", "value": "8.8.8.8", "ioc_type": "ip"}
    ])
    assert any(entry["provider"] == "abuseipdb" and entry["status"] == "provider unavailable" and entry["error_code"] == failure_code for entry in result["evidence_ledger"])
    assert any(entry["provider"] == "virustotal" and entry["status"] == "available" for entry in result["evidence_ledger"])
    assert result["available_result_count"] == 2


def test_not_configured_is_skipped_without_error_ledger(monkeypatch):
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda value: _down("abuseipdb", "NOT_CONFIGURED"))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda value, ioc_type="ip": _down("virustotal", "NOT_CONFIGURED"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda value, **kwargs: _down("threatfox", "NOT_CONFIGURED"))
    result = orchestrator.enrich_iocs_with_live_providers([
        {"ioc": "8.8.8.8", "value": "8.8.8.8", "ioc_type": "ip"}
    ])
    assert result["status"] == "not_configured"
    assert result["evidence_ledger"] == []
    assert result["unavailable_result_count"] == 0
    assert result["not_configured_skips"] == {"abuseipdb": 1, "virustotal": 1, "threatfox": 1}


def test_unexpected_provider_exception_does_not_stop_remaining_providers(monkeypatch):
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda value: (_ for _ in ()).throw(RuntimeError("secret response must not leak")))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda value, ioc_type="ip": _ok("virustotal"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda value, **kwargs: _ok("threatfox"))
    result = orchestrator.enrich_iocs_with_live_providers([
        {"ioc": "8.8.8.8", "value": "8.8.8.8", "ioc_type": "ip"}
    ])
    assert result["available_result_count"] == 2
    assert any(entry.get("error_code") == "UNHANDLED_EXCEPTION" for entry in result["evidence_ledger"])


def test_private_reserved_and_invalid_ip_iocs_are_explicit_and_never_sent(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda *a, **k: calls.append("abuseipdb"))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda *a, **k: calls.append("virustotal"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda *a, **k: calls.append("threatfox"))
    values = ["10.0.0.1", "192.0.2.1", "::1", "::ffff:192.168.1.5", "999.1.1.1"]
    result = orchestrator.enrich_iocs_with_live_providers([
        {"ioc": value, "value": value, "ioc_type": "ip"} for value in values
    ])
    assert calls == []
    assert result["provider_calls_attempted"] == 0
    assert result["status"] == "not_applicable"
    assert len(result["non_public_ip_skips"]) == len(values)
    assert all(item["status"] in {"NOT_APPLICABLE", "INVALID_IP"} for item in result["non_public_ip_skips"])
    assert all(record["status"] == "not_applicable"
               for records in result["provider_results"].values() for record in records)


def test_public_mapped_ipv6_ioc_reaches_providers_only_as_ipv4(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda value: calls.append(("abuseipdb", value)) or _ok("abuseipdb"))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda value, ioc_type="ip": calls.append(("virustotal", value)) or _ok("virustotal"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda value, **kwargs: calls.append(("threatfox", value)) or _ok("threatfox"))
    result = orchestrator.enrich_iocs_with_live_providers([
        {"ioc": "::ffff:8.8.8.8", "value": "::ffff:8.8.8.8", "ioc_type": "ip"}
    ])
    assert calls == [("abuseipdb", "8.8.8.8"), ("virustotal", "8.8.8.8"), ("threatfox", "8.8.8.8")]
    assert result["non_public_ip_skips"] == []


def test_native_public_ipv6_skips_ipv4_only_abuseipdb(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "lookup_abuseipdb", lambda value: calls.append(("abuseipdb", value)) or _ok("abuseipdb"))
    monkeypatch.setattr(orchestrator, "lookup_virustotal", lambda value, ioc_type="ip": calls.append(("virustotal", value)) or _ok("virustotal"))
    monkeypatch.setattr(orchestrator, "lookup_threatfox", lambda value, **kwargs: calls.append(("threatfox", value)) or _ok("threatfox"))
    orchestrator.enrich_iocs_with_live_providers([
        {"ioc": "2606:4700:4700::1111", "value": "2606:4700:4700::1111", "ioc_type": "ip"}
    ])
    assert calls == [("virustotal", "2606:4700:4700::1111"), ("threatfox", "2606:4700:4700::1111")]
