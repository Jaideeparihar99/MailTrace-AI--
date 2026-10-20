from __future__ import annotations

import dns.resolver
import pytest

from services import domain_intelligence as domain


@pytest.fixture(autouse=True)
def clean_cache():
    domain.clear_domain_cache()
    yield
    domain.clear_domain_cache()


class Answer(list):
    def __init__(self, values, ttl=120):
        super().__init__(values)
        self.rrset = self if values else None
        self.ttl = ttl


class FakeResolver:
    nameservers = ["127.0.0.1"]
    behavior = {}
    calls = []
    timeout = None
    lifetime = None

    def resolve(self, qname, rdtype, **kwargs):
        self.calls.append((qname, rdtype, kwargs))
        value = self.behavior.get(rdtype, Answer([]))
        if isinstance(value, Exception):
            raise value
        return value


@pytest.fixture
def resolver(monkeypatch):
    FakeResolver.behavior = {}
    FakeResolver.calls = []
    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)
    return FakeResolver


def test_success_returns_normalized_records_source_and_registration_unknown(resolver):
    resolver.behavior = {
        "A": Answer([type("A", (), {"address": "203.0.113.10"})()]),
        "MX": Answer([type("MX", (), {"preference": 10, "exchange": "mail.example.test."})()]),
    }
    result = domain.lookup_domain("ExAmPlE.test.")
    assert result["status"] == "AVAILABLE"
    assert result["original_domain"] == "ExAmPlE.test."
    assert result["query_domain"] == "example.test"
    assert result["records"]["A"] == ["203.0.113.10"]
    assert result["records"]["MX"] == [{"preference": 10, "exchange": "mail.example.test"}]
    assert result["resolver"] == "127.0.0.1"
    assert result["lookup_timestamp"] and result["cache_expires_at"]
    assert result["cache_status"] == "MISS"
    assert result["domain_age"]["status"] == "NOT_RUN"
    assert result["domain_age"]["age_days"] is None
    assert all(call[2]["lifetime"] == domain.DNS_LIFETIME_SECONDS for call in resolver.calls)


def test_empty_dns_answers_are_explicit_and_short_cached(resolver):
    result = domain.lookup_domain("example.test")
    cached = domain.lookup_domain("example.test")
    assert result["status"] == "NO_RECORDS"
    assert cached["cache_status"] == "HIT"
    assert result["cache_ttl_seconds"] == domain.DNS_NEGATIVE_TTL_SECONDS
    assert len(resolver.calls) == 4


def test_cache_expiry_repeats_dns_lookup(resolver, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(domain.time, "monotonic", lambda: now[0])
    resolver.behavior = {"A": Answer([type("A", (), {"address": "198.51.100.4"})()])}
    first = domain.lookup_domain("example.test")
    now[0] += domain.DNS_CACHE_TTL_SECONDS + 1
    second = domain.lookup_domain("example.test")
    assert first["cache_status"] == second["cache_status"] == "MISS"
    assert len(resolver.calls) == 8


def test_record_types_report_no_mx_without_failing_other_dns(resolver):
    resolver.behavior = {"A": Answer([type("A", (), {"address": "198.51.100.5"})()])}
    result = domain.lookup_domain("example.test")
    assert result["status"] == "AVAILABLE"
    assert result["record_statuses"]["A"] == "AVAILABLE"
    assert result["record_statuses"]["MX"] == "NO_RECORDS"
    assert result["records"]["MX"] == []


def test_nxdomain_is_distinct_from_empty_records(resolver):
    resolver.behavior = {kind: dns.resolver.NXDOMAIN() for kind in domain._RR_TYPES}
    result = domain.lookup_domain("absent.example")
    assert result["status"] == "NXDOMAIN"


@pytest.mark.parametrize(("exception", "expected"), [
    (dns.resolver.LifetimeTimeout(), "TIMEOUT"),
    (dns.resolver.NoNameservers(), "SERVFAIL"),
    (RuntimeError("private provider detail"), "DNS_ERROR"),
])
def test_transient_dns_failures_are_safe_and_not_cached(resolver, exception, expected):
    resolver.behavior = {kind: exception for kind in domain._RR_TYPES}
    first = domain.lookup_domain("example.test")
    second = domain.lookup_domain("example.test")
    assert first["status"] == expected
    assert first["cache_status"] == second["cache_status"] == "MISS"
    assert "private provider detail" not in str(first)
    assert len(resolver.calls) == 8


def test_malformed_domain_skips_resolver(resolver):
    result = domain.lookup_domain("not/a/domain")
    assert result["status"] == "INVALID_DOMAIN"
    assert not resolver.calls


def test_idna_normalization_keeps_original_evidence(resolver):
    result = domain.lookup_domain("bücher.example")
    assert result["original_domain"] == "bücher.example"
    assert result["query_domain"] == "xn--bcher-kva.example"


def test_domain_batch_deduplicates_by_idna_and_caps_number(resolver, monkeypatch):
    monkeypatch.setenv("MAILTRACE_DOMAIN_INTELLIGENCE_ENABLED", "true")
    result = domain.analyze_domains(["EXAMPLE.test", "example.test.", "other.test", "a.test", "b.test", "c.test", "d.test", "e.test"])
    assert result["unique_domain_count"] == domain.MAX_DOMAINS_PER_EMAIL
    assert result["truncated"] is True
    assert len({call[0] for call in resolver.calls}) == domain.MAX_DOMAINS_PER_EMAIL


def test_disabled_enrichment_makes_no_dns_calls(resolver, monkeypatch):
    monkeypatch.setenv("MAILTRACE_DOMAIN_INTELLIGENCE_ENABLED", "false")
    result = domain.analyze_domains(["example.test"], enabled=None)
    assert result["status"] == "NOT_RUN"
    assert not resolver.calls


def test_empty_domain_input_is_not_run_not_no_records(resolver):
    result = domain.analyze_domains([], enabled=True)
    assert result["status"] == "NOT_RUN"
    assert result["unique_domain_count"] == 0
    assert not resolver.calls


def test_explicitly_enabled_domain_batch_includes_domain_age_not_run(resolver):
    result = domain.analyze_domains(["example.test"], enabled=True)
    assert result["domains"][0]["domain_age"]["status"] == "NOT_RUN"
    assert result["domains"][0]["domain_age"]["registration_date"] is None


def test_email_parser_exposes_domain_intelligence_for_sender_and_urls(monkeypatch):
    from services import email_parser
    seen = []
    monkeypatch.setattr(email_parser, "analyze_domains", lambda values: seen.extend(values) or {
        "status": "NOT_RUN", "unique_domain_count": len(values), "domains": []
    })
    source = (b"From: Analyst <sender@example.test>\r\n"
              b"Subject: Review\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
              b"Visit https://portal.example.test/login\r\n")
    result = email_parser.parse_email(source, "fixture.eml")
    assert result["domain_intelligence"]["status"] == "NOT_RUN"
    assert "example.test" in seen
    assert "portal.example.test" in seen
