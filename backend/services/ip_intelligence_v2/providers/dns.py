import socket
import time
from datetime import datetime, timezone

from ..models import ProviderResult
from services.ip_address_policy import require_public_ip


def reverse_dns(ip: str) -> ProviderResult:

    started = time.perf_counter()
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return ProviderResult(provider="reverse_dns", success=False,
            error=f"NOT_APPLICABLE: NOT_PUBLIC ({policy['classification']}).", latency_ms=0)
    ip = safe_ip
    queried_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        latency = round(
            (time.perf_counter() - started) * 1000,
            2
        )

        return ProviderResult(
            provider="reverse_dns",
            success=True,
            data={
                "status": "AVAILABLE",
                "source": "system_reverse_dns_resolver",
                "lookup_timestamp": queried_at,
                "ip": ip,
                "hostname": hostname,
                "aliases": aliases,
                "addresses": addresses,
            },
            latency_ms=latency,
        )

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ) as error:

        latency = round(
            (time.perf_counter() - started) * 1000,
            2
        )

        return ProviderResult(
            provider="reverse_dns",
            success=False,
            data={
                "status": "NO_DATA",
                "source": "system_reverse_dns_resolver",
                "lookup_timestamp": queried_at,
                "ip": ip,
            },
            error=str(error),
            latency_ms=latency,
        )
