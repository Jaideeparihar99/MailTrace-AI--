import io
import json
import socket
from urllib.error import HTTPError, URLError
import pytest
from services.threat_intelligence.providers import http_clients as clients

ADAPTERS = [
    ("abuseipdb", lambda **kw: clients.lookup_abuseipdb("8.8.8.8", api_key="test-key", url="https://unit.invalid/check", **kw), {"data": {}}),
    ("virustotal", lambda **kw: clients.lookup_virustotal("8.8.8.8", api_key="test-key", base_url="https://unit.invalid/v3", **kw), {"data": {}}),
    ("threatfox", lambda **kw: clients.lookup_threatfox("8.8.8.8", api_key="test-key", url="https://unit.invalid/", **kw), {"query_status": "ok"}),
    ("urlhaus", lambda **kw: clients.lookup_urlhaus("https://example.invalid/", api_key="test-key", url="https://unit.invalid/", **kw), {"query_status": "ok"}),
]
class FakeResponse:
    status = 200
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.body

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
@pytest.mark.parametrize("status,expected", [(400,"PROVIDER_HTTP_ERROR"),(401,"AUTH_ERROR"),(403,"AUTH_ERROR"),(404,"PROVIDER_HTTP_ERROR"),(429,"RATE_LIMITED"),(500,"PROVIDER_HTTP_ERROR"),(502,"PROVIDER_HTTP_ERROR"),(503,"PROVIDER_HTTP_ERROR"),(504,"PROVIDER_HTTP_ERROR")])
def test_http_failures_fall_back_without_exception(monkeypatch, provider, call, valid, status, expected):
    def fail(*args, **kwargs): raise HTTPError("https://unit.invalid/", status, "test", {}, io.BytesIO(b""))
    monkeypatch.setattr(clients, "urlopen", fail)
    result = call()
    assert result["available"] is False and result["status"] == "unavailable"
    assert result["error_code"] == expected and result["data"] is None

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
def test_timeout_falls_back(monkeypatch, provider, call, valid):
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: (_ for _ in ()).throw(socket.timeout()))
    assert call()["error_code"] == "TIMEOUT"

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
def test_network_down_falls_back(monkeypatch, provider, call, valid):
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: (_ for _ in ()).throw(URLError("offline")))
    assert call()["error_code"] == "NETWORK_ERROR"

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
def test_malformed_json_falls_back(monkeypatch, provider, call, valid):
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: FakeResponse(b"not-json"))
    assert call()["error_code"] == "MALFORMED_JSON"

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
def test_malformed_schema_falls_back(monkeypatch, provider, call, valid):
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: FakeResponse(b"{}"))
    assert call()["error_code"] == "MALFORMED_SCHEMA"

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
def test_successful_provider_shape_is_accepted(monkeypatch, provider, call, valid):
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: FakeResponse(json.dumps(valid).encode()))
    result = call()
    assert result["available"] is True and result["status"] == "ok" and result["data"] == valid

@pytest.mark.parametrize("provider,call,valid", ADAPTERS)
def test_missing_key_is_graceful(monkeypatch, provider, call, valid):
    for spec in clients.PROVIDERS.values(): monkeypatch.delenv(spec["key_env"], raising=False)
    for alias in ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY"): monkeypatch.delenv(alias, raising=False)
    if provider == "abuseipdb": result = clients.lookup_abuseipdb("8.8.8.8")
    elif provider == "virustotal": result = clients.lookup_virustotal("8.8.8.8")
    elif provider == "threatfox": result = clients.lookup_threatfox("8.8.8.8")
    else: result = clients.lookup_urlhaus("https://example.invalid/")
    assert result["error_code"] == "NOT_CONFIGURED" and result["available"] is False


@pytest.mark.parametrize("provider,call,valid", ADAPTERS[2:])
def test_existing_auth_key_aliases_are_supported(monkeypatch, provider, call, valid):
    for spec in clients.PROVIDERS.values(): monkeypatch.delenv(spec["key_env"], raising=False)
    monkeypatch.setenv("THREATFOX_AUTH_KEY" if provider == "threatfox" else "URLHAUS_AUTH_KEY", "alias-key")
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: FakeResponse(json.dumps(valid).encode()))
    result = clients.lookup_threatfox("8.8.8.8", url="https://unit.invalid/") if provider == "threatfox" else clients.lookup_urlhaus("https://example.invalid/", url="https://unit.invalid/")
    assert result["available"] is True


def test_virustotal_hash_uses_file_endpoint(monkeypatch):
    seen = []
    monkeypatch.setattr(clients, "urlopen", lambda req, **kw: (seen.append(req.full_url) or FakeResponse(json.dumps({"data": {"id": "abc"}}).encode())))
    result = clients.lookup_virustotal("a" * 64, ioc_type="hash", api_key="test-key", base_url="https://unit.invalid/v3")
    assert result["available"] is True
    assert seen == ["https://unit.invalid/v3/files/" + "a" * 64]


@pytest.mark.parametrize("provider_call", [
    lambda: clients.lookup_abuseipdb("10.0.0.1", api_key="test-key"),
    lambda: clients.lookup_virustotal("192.0.2.10", ioc_type="ip", api_key="test-key"),
    lambda: clients.lookup_threatfox("::ffff:192.168.1.2", ioc_type="ip", api_key="test-key"),
    lambda: clients.lookup_threatfox("999.1.1.1", ioc_type="ip", api_key="test-key"),
])
def test_direct_ip_reputation_adapters_block_nonpublic_or_invalid_before_http(monkeypatch, provider_call):
    monkeypatch.setattr(clients, "urlopen", lambda *a, **k: pytest.fail("HTTP must not run for ineligible IP"))
    result = provider_call()
    assert result["available"] is False
    assert result["error_code"] in {"NOT_APPLICABLE_NOT_PUBLIC", "INVALID_IP"}


def test_virustotal_normalizes_public_mapped_ipv6_for_provider(monkeypatch):
    seen = []
    monkeypatch.setattr(clients, "urlopen", lambda req, **kw: (seen.append(req.full_url) or FakeResponse(b'{"data":{}}')))
    result = clients.lookup_virustotal("::ffff:8.8.8.8", ioc_type="ip", api_key="test-key", base_url="https://unit.invalid/v3")
    assert result["available"] is True
    assert seen == ["https://unit.invalid/v3/ip_addresses/8.8.8.8"]
