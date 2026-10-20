"""Opt-in live provider smoke test. Never enabled in ordinary CI by default.

Explicitly setting MAILTRACE_GEOLOCATION_LIVE_TESTS=true sends the selected public
IP to the configured third-party provider and may consume quota. Do not use a
private/customer IP. This test is deliberately separate from the mocked suite.
"""
import os

import pytest

from services.ip_intelligence_v2.providers import geolocation

pytestmark = pytest.mark.skipif(
    os.getenv("MAILTRACE_GEOLOCATION_LIVE_TESTS", "").strip().lower() != "true"
    or os.getenv("MAILTRACE_GEOLOCATION_IPAPI_APPROVED", "").strip().lower() != "true",
    reason=("Live geolocation requires explicit opt-in and provider approval: set "
            "MAILTRACE_GEOLOCATION_LIVE_TESTS=true and MAILTRACE_GEOLOCATION_IPAPI_APPROVED=true"),
)


def test_live_ipapi_provider_smoke():
    ip = os.getenv("MAILTRACE_GEOLOCATION_LIVE_TEST_IP", "8.8.8.8").strip()
    result = geolocation.query_ipapi(ip)
    assert result.provider == "ipapi"
    # A live smoke test must fail on transport/provider errors; accepting TIMEOUT or
    # PROVIDER_ERROR would falsely report a successful live integration check.
    assert result.data.get("status") in {"AVAILABLE", "NO_DATA"}, result.error
    assert result.data.get("ip") == ip
    if result.data.get("status") == "AVAILABLE":
        assert result.success is True
        assert any(result.data.get(field) not in (None, "") for field in
                   ("country", "country_code", "region", "city", "latitude", "longitude"))
        assert result.data.get("precision", "").startswith("IP-derived")
    else:
        assert result.success is False
        assert result.error == "NO_DATA"
