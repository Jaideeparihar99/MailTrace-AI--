import json
import os
import time
from datetime import datetime, timezone
import urllib.parse
import urllib.request
import urllib.error

from ..models import ProviderResult
from services.ip_address_policy import require_public_ip


def query_ipapi_network(ip: str) -> ProviderResult:

    started = time.perf_counter()
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return ProviderResult(provider="ipapi_network", success=False,
            error=f"NOT_APPLICABLE: NOT_PUBLIC ({policy['classification']}).", latency_ms=0)
    ip = safe_ip
    queried_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    url = (
        f"https://ipapi.co/"
        f"{urllib.parse.quote(ip)}/json/"
    )

    try:

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "MailTrace-AI/2.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if data.get("error"):

            return ProviderResult(
                provider="ipapi_network",
                success=False,
                data={"status": "PROVIDER_ERROR", "source": "ipapi.co", "lookup_timestamp": queried_at, "ip": ip},
                error=data.get(
                    "reason",
                    "Network intelligence lookup failed."
                ),
                latency_ms=round(
                    (time.perf_counter() - started) * 1000,
                    2
                )
            )

        return ProviderResult(
            provider="ipapi_network",
            success=True,
            data={
                "status": "AVAILABLE",
                "asn": data.get("asn"),
                "organization": data.get("org"),
                "network": data.get("network"),
                "version": data.get("version"),
                "source": "ipapi.co",
                "lookup_timestamp": queried_at,
            },
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except urllib.error.HTTPError as error:

        return ProviderResult(
            provider="ipapi_network",
            success=False,
            data={"status": "PROVIDER_ERROR", "source": "ipapi.co", "lookup_timestamp": queried_at, "ip": ip},
            error=f"HTTP {error.code}: {error.reason}",
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except Exception as error:

        return ProviderResult(
            provider="ipapi_network",
            success=False,
            data={"status": "PROVIDER_ERROR", "source": "ipapi.co", "lookup_timestamp": queried_at, "ip": ip},
            error=str(error),
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )


def classify_network(
    organization: str | None,
    hostname: str | None,
    asn: str | None
) -> dict:
    return {
        "hosting_signal": None,
        "hosting_matches": [],
        "classification": "UNKNOWN",
        "status": "NOT_ASSESSED",
        "reason": "ASN, organization, hostname, and geolocation are contextual metadata; no configured provider result independently classifies hosting, VPN, proxy, or Tor status.",
        "observed_network_metadata": {
            "organization": organization,
            "hostname": hostname,
            "asn": asn,
        },
    }
