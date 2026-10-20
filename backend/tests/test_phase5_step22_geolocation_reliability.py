import json
import urllib.error

import pytest

from services.ip_intelligence_v2.models import ProviderResult
from services.ip_intelligence_v2.providers import geolocation


class _Response:
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return self.body[:size] if size >= 0 else self.body


@pytest.fixture(autouse=True)
def _clean_geo_cache():
    geolocation.clear_geolocation_cache()
    yield
    geolocation.clear_geolocation_cache()


def test_success_has_normalized_provenance_and_cache_metadata(monkeypatch):
    calls = []
    payload = {"country_name": "United States", "country": "US", "region": "Virginia", "city": "Ashburn", "asn": "AS15169", "org": "Example Network"}
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append((a, k)) or payload)
    first = geolocation.query_ipapi("8.8.8.8")
    second = geolocation.query_ipapi("8.8.8.8")
    assert first.success is True
    assert first.data["country"] == "United States"
    assert first.data["provider"] == "ipapi"
    assert first.data["ip"] == "8.8.8.8"
    assert first.data["lookup_timestamp"]
    assert first.data["cache_status"] == "MISS"
    assert first.data["precision"].startswith("IP-derived")
    assert second.data["cache_status"] == "HIT"
    assert len(calls) == 1


def test_no_data_is_explicit_and_short_lived_cache(monkeypatch):
    calls = []
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(1) or {"country_name": None, "country": None, "city": None})
    first = geolocation.query_ipapi("8.8.4.4")
    second = geolocation.query_ipapi("8.8.4.4")
    assert first.success is False
    assert first.data["status"] == "NO_DATA"
    assert first.data["cache_ttl_seconds"] == geolocation.NO_DATA_TTL_SECONDS
    assert second.data["cache_status"] == "HIT"
    assert len(calls) == 1


@pytest.mark.parametrize(("exception", "expected"), [
    (TimeoutError("private detail"), "TIMEOUT"),
    (urllib.error.HTTPError("https://provider.invalid", 429, "Too Many Requests", {}, None), "RATE_LIMITED"),
    (json.JSONDecodeError("bad", "{", 0), "PROVIDER_ERROR"),
], ids=["timeout", "rate-limited", "malformed-json"])
def test_transient_and_malformed_failures_are_not_cached(monkeypatch, exception, expected):
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise exception
    monkeypatch.setattr(geolocation, "_request_json", fail)
    first = geolocation.query_ipapi("1.1.1.1")
    second = geolocation.query_ipapi("1.1.1.1")
    assert first.success is False and first.data["status"] == expected
    assert first.data["cache_status"] == "BYPASS"
    assert expected in first.error
    assert len(calls) == 2


def test_cache_expiry_forces_fresh_provider_lookup(monkeypatch):
    now = [100.0]
    calls = []
    monkeypatch.setattr(geolocation.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(1) or {"country_name": "Canada", "country": "CA"})
    first = geolocation.query_ipapi("9.9.9.9")
    assert first.data["cache_status"] == "MISS"
    now[0] += geolocation.SUCCESS_TTL_SECONDS + 1
    second = geolocation.query_ipapi("9.9.9.9")
    assert second.data["cache_status"] == "MISS"
    assert len(calls) == 2


def test_nonpublic_ip_is_rejected_without_provider_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("non-public address must not reach provider")
    monkeypatch.setattr(geolocation, "_request_json", forbidden)
    result = geolocation.query_ipapi("192.168.1.4")
    assert result.success is False
    assert result.data["status"] == "NOT_PUBLIC"


def test_ipinfo_token_does_not_enable_fallback_without_explicit_provider_config(monkeypatch):
    calls = []
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_PROVIDERS", raising=False)
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", raising=False)
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(a[0]) or {"country_name": "United States"})
    results = geolocation.get_geolocation("8.8.8.8")
    assert [item.provider for item in results] == ["ipapi"]
    assert len(calls) == 1


def test_ipinfo_requires_provider_allowlist_approval_and_token(monkeypatch):
    calls = []
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipinfo")
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", raising=False)
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(a[0]) or {"country": "US", "city": "Ashburn"})
    blocked = geolocation.get_geolocation("8.8.8.8")
    assert blocked[0].data["status"] == "NOT_CONFIGURED"
    assert calls == []
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", "true")
    allowed = geolocation.get_geolocation("8.8.8.8")
    assert allowed[0].success is True
    assert calls and "ipinfo.io" in calls[0]


def test_direct_ipinfo_call_cannot_bypass_approval_flag(monkeypatch):
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_REDIS_URL", raising=False)
    calls = []
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipinfo")
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", raising=False)
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(a[0]) or {"country": "US"})

    result = geolocation.query_ipinfo("8.8.8.8")

    assert result.success is False
    assert result.data["status"] == "NOT_CONFIGURED"
    assert "not explicitly approved" in result.error
    assert result.data["cache_status"] == "BYPASS"
    assert calls == []


def test_direct_ipinfo_call_requires_allowlist_even_when_approved(monkeypatch):
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_REDIS_URL", raising=False)
    calls = []
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", "true")
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_PROVIDERS", raising=False)
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(a[0]) or {"country": "US"})

    result = geolocation.query_ipinfo("8.8.8.8")

    assert result.success is False
    assert "not enabled" in result.error
    assert calls == []


def test_direct_ipinfo_call_requires_token_even_when_approved_and_allowlisted(monkeypatch):
    calls = []
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_REDIS_URL", raising=False)
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipinfo")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", "true")
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(a[0]) or {"country": "US"})

    result = geolocation.query_ipinfo("8.8.8.8")

    assert result.success is False
    assert "IPINFO_TOKEN is not configured" in result.error
    assert calls == []


def test_direct_ipinfo_call_works_only_when_all_gates_are_satisfied(monkeypatch):
    monkeypatch.delenv("MAILTRACE_GEOLOCATION_REDIS_URL", raising=False)
    calls = []
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipapi,ipinfo")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", "true")
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(a[0]) or {"country": "US", "city": "Ashburn"})

    result = geolocation.query_ipinfo("8.8.8.8")

    assert result.success is True
    assert result.data["status"] == "AVAILABLE"
    assert len(calls) == 1 and "ipinfo.io" in calls[0]


def test_provider_response_with_only_asn_is_no_location_data(monkeypatch):
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: {"asn": "AS123", "org": "Example Org"})
    result = geolocation.query_ipapi("4.2.2.2")
    assert result.success is False
    assert result.data["status"] == "NO_DATA"
    assert result.data.get("city") is None
    assert result.data.get("country") is None


@pytest.mark.parametrize("payload", [
    {"latitude": "not-a-number", "longitude": 181},
    {"latitude": float("nan"), "longitude": 10},
    {"city": 42},
])
def test_malformed_provider_location_schema_is_not_cached(monkeypatch, payload):
    calls = []
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(1) or payload)
    first = geolocation.query_ipapi("8.8.8.8")
    second = geolocation.query_ipapi("8.8.8.8")
    assert first.data["status"] == second.data["status"] == "PROVIDER_ERROR"
    assert first.data["cache_status"] == "BYPASS"
    assert len(calls) == 2


def test_invalid_coordinates_are_omitted_when_other_location_data_is_valid(monkeypatch):
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: {
        "country_name": "Example", "latitude": 999, "longitude": "bad"
    })
    result = geolocation.query_ipapi("8.8.8.8")
    assert result.success is True
    assert result.data["country"] == "Example"
    assert "latitude" not in result.data and "longitude" not in result.data


def test_no_supported_provider_is_not_run(monkeypatch):
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "unknown-provider")
    result = geolocation.get_geolocation("8.8.8.8")[0]
    assert result.data["status"] == "NOT_CONFIGURED"


def test_configured_fallback_is_tried_after_no_data(monkeypatch):
    calls = []
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipapi,ipinfo")
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", "true")
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    def response(url, **kwargs):
        calls.append(url)
        if "ipapi.co" in url:
            return {"asn": "AS1"}
        return {"country": "US", "city": "Ashburn"}
    monkeypatch.setattr(geolocation, "_request_json", response)
    results = geolocation.get_geolocation("8.8.8.8")
    assert [result.data["status"] for result in results] == ["NO_DATA", "AVAILABLE"]
    assert len(calls) == 2


def test_provider_outage_does_not_crash_ip_analysis(monkeypatch):
    import services.ip_intelligence_v2.engine as engine
    def failed_geo(ip):
        return [ProviderResult(provider="ipapi", success=False, data={"status": "TIMEOUT", "ip": ip}, error="TIMEOUT")]
    monkeypatch.setattr(engine, "get_geolocation", failed_geo)
    monkeypatch.setattr(engine, "reverse_dns", lambda ip: ProviderResult(provider="dns", success=False, error="stubbed"))
    monkeypatch.setattr(engine, "query_ipapi_network", lambda ip: ProviderResult(provider="network", success=False, error="stubbed"))
    monkeypatch.setattr(engine, "get_reputation", lambda ip: [ProviderResult(provider="rep", success=False, error="stubbed")])
    result = engine.analyze_ip_v2("8.8.8.8")
    assert result["valid"] is True
    assert result["ip"] == "8.8.8.8"
    assert result["country"] is None
    assert isinstance(result["provider_status"], list)
    assert result["geolocation_status"]["status"] == "ERROR"
    assert result["geolocation_status"]["state"] == "TIMEOUT"
    assert result["risk"] != "SAFE"


def test_no_data_remains_unknown_in_v2_analysis(monkeypatch):
    import services.ip_intelligence_v2.engine as engine
    def no_data(ip):
        return [ProviderResult(provider="ipapi", success=False, data={"status": "NO_DATA", "ip": ip})]
    monkeypatch.setattr(engine, "get_geolocation", no_data)
    monkeypatch.setattr(engine, "reverse_dns", lambda ip: ProviderResult(provider="dns", success=False, error="stubbed"))
    monkeypatch.setattr(engine, "query_ipapi_network", lambda ip: ProviderResult(provider="network", success=False, error="stubbed"))
    monkeypatch.setattr(engine, "get_reputation", lambda ip: [ProviderResult(provider="rep", success=False, error="stubbed")])
    result = engine.analyze_ip_v2("8.8.8.8")
    assert result["geolocation_status"]["status"] == "UNKNOWN"
    assert result["geolocation_status"]["state"] == "NO_DATA"


def test_unconfigured_v2_provider_is_not_run(monkeypatch):
    import services.ip_intelligence_v2.engine as engine
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_PROVIDERS", "unknown-provider")
    monkeypatch.setattr(engine, "reverse_dns", lambda ip: ProviderResult(provider="dns", success=False, error="stubbed"))
    monkeypatch.setattr(engine, "query_ipapi_network", lambda ip: ProviderResult(provider="network", success=False, error="stubbed"))
    monkeypatch.setattr(engine, "get_reputation", lambda ip: [ProviderResult(provider="rep", success=False, error="stubbed")])
    result = engine.analyze_ip_v2("8.8.8.8")
    assert result["geolocation_status"]["status"] == "NOT_RUN"
    assert result["geolocation_status"]["state"] == "NOT_CONFIGURED"



def test_legacy_geolocation_outage_is_explicit_and_analysis_continues(monkeypatch):
    from services import ip_intelligence as legacy
    import socket
    monkeypatch.setattr(legacy, "get_ip_geolocation", lambda ip: {
        "success": False, "status": "ERROR", "state": "TIMEOUT", "geolocation_state": "TIMEOUT",
        "provider": "ipapi", "ip": ip, "cache_status": "BYPASS", "error": "Geolocation provider could not complete the lookup."
    })
    monkeypatch.setattr(legacy, "get_network_intelligence", lambda ip: {"success": False, "status": "ERROR", "is_proxy": None, "is_hosting": None})
    monkeypatch.setattr(legacy.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(socket.herror()))
    result = legacy.analyze_ip("8.8.8.8")
    assert result["country"] is None
    assert result["city"] is None
    assert result["geolocation_status"]["provider_status"] == "ERROR"
    assert result["geolocation_status"]["geolocation_state"] == "TIMEOUT"
    assert result["geolocation"]["provider"] == "ipapi"


class _LegacyResponse:
    def __init__(self, payload):
        self.body = json.dumps(payload).encode("utf-8")
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return self.body[:size] if size >= 0 else self.body


def test_legacy_cache_hit_preserves_provider_and_lookup_time(monkeypatch):
    from services import ip_intelligence as legacy
    legacy.clear_geolocation_cache()
    calls = []
    monkeypatch.setattr(legacy.urllib.request, "urlopen", lambda *a, **k: calls.append(1) or _LegacyResponse({"country_name": "Canada", "country": "CA", "city": "Toronto"}))
    first = legacy.get_ip_geolocation("8.8.8.8")
    second = legacy.get_ip_geolocation("8.8.8.8")
    assert first["success"] is True
    assert first["provider"] == "ipapi"
    assert first["lookup_timestamp"]
    assert first["cache_status"] == "MISS"
    assert second["cache_status"] == "HIT"
    assert second["lookup_timestamp"] == first["lookup_timestamp"]
    assert len(calls) == 1
    legacy.clear_geolocation_cache()


def test_legacy_cache_expiry_forces_fresh_lookup(monkeypatch):
    from services import ip_intelligence as legacy
    legacy.clear_geolocation_cache()
    now = [100.0]
    calls = []
    monkeypatch.setattr(legacy.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(legacy.urllib.request, "urlopen", lambda *a, **k: calls.append(1) or _LegacyResponse({"country_name": "Canada", "country": "CA"}))
    first = legacy.get_ip_geolocation("1.1.1.1")
    now[0] += legacy._GEO_SUCCESS_TTL + 1
    second = legacy.get_ip_geolocation("1.1.1.1")
    assert first["cache_status"] == second["cache_status"] == "MISS"
    assert len(calls) == 2
    legacy.clear_geolocation_cache()


def test_legacy_asn_only_response_is_no_data_not_a_location(monkeypatch):
    from services import ip_intelligence as legacy
    legacy.clear_geolocation_cache()
    monkeypatch.setattr(legacy.urllib.request, "urlopen", lambda *a, **k: _LegacyResponse({"asn": "AS123", "org": "Example Org"}))
    result = legacy.get_ip_geolocation("4.2.2.2")
    assert result["success"] is False
    assert result["geolocation_state"] == "NO_DATA"
    assert result.get("city") is None and result.get("country") is None
    legacy.clear_geolocation_cache()



def test_redis_cache_is_shared_and_uses_ttl_without_breaking_provider_result(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.values = {}
            self.ttls = {}
        def get(self, key):
            return self.values.get(key)
        def setex(self, key, ttl, value):
            self.values[key] = value
            self.ttls[key] = ttl

    fake = FakeRedis()
    monkeypatch.setenv("MAILTRACE_GEOLOCATION_REDIS_URL", "redis://fake.invalid/0")
    monkeypatch.setattr(geolocation, "_redis_client", lambda: fake)
    calls = []
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(1) or {"country_name": "Canada", "country": "CA"})
    first = geolocation.query_ipapi("8.8.8.8")
    # Simulate a second worker by clearing only the process-local cache.
    geolocation.clear_geolocation_cache()
    second = geolocation.query_ipapi("8.8.8.8")
    assert first.data["cache_backend"] == "redis"
    assert second.data["cache_status"] == "HIT"
    assert second.data["cache_backend"] == "redis"
    assert fake.ttls[geolocation._redis_key("ipapi", "8.8.8.8")] == geolocation.SUCCESS_TTL_SECONDS
    assert len(calls) == 1


def test_redis_cache_failure_falls_back_to_local_cache(monkeypatch):
    class BrokenRedis:
        def get(self, key):
            raise OSError("redis offline")
        def setex(self, *args):
            raise OSError("redis offline")
    monkeypatch.setattr(geolocation, "_redis_client", lambda: BrokenRedis())
    calls = []
    monkeypatch.setattr(geolocation, "_request_json", lambda *a, **k: calls.append(1) or {"country_name": "Canada", "country": "CA"})
    first = geolocation.query_ipapi("1.1.1.1")
    second = geolocation.query_ipapi("1.1.1.1")
    assert first.success and second.success
    assert second.data["cache_status"] == "HIT"
    assert second.data["cache_backend"] == "memory"
    assert len(calls) == 1
