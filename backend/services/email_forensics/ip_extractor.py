from __future__ import annotations

import ipaddress
import re
from typing import Any

from services.ip_address_policy import classify_ip


# =========================================================
# IP EXTRACTION
# =========================================================

IP_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"("
    r"::ffff:(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r")"
    r"(?![0-9A-Fa-f:.])"
)


def extract_ip_candidates(
    received_headers: list[str]
) -> list[dict[str, Any]]:
    """
    Extract and classify IP addresses from Received headers.

    This module does not perform attribution.
    It only creates validated IP candidates and their
    local network classification.
    """

    candidates: list[dict[str, Any]] = []

    for header_index, header in enumerate(
        received_headers
    ):

        if not header:
            continue

        matches = list(IP_PATTERN.finditer(header))

        for match in matches:
            raw_ip = match.group(1)

            policy = classify_ip(raw_ip)
            address = None
            if policy["valid"]:
                try:
                    address = ipaddress.ip_address(raw_ip)
                except ValueError:
                    pass

            normalized_ip = policy["normalized_ip"]
            classification = policy["classification"]
            candidates.append({
                "ip": normalized_ip,
                "raw_ip": raw_ip,
                "normalized_ip": normalized_ip,
                "provider_ip": policy["provider_ip"],
                "version": address.version if address else None,
                "valid": bool(address and policy["valid"]),
                "classification": classification,
                "is_public": policy["enrichment_status"] == "ELIGIBLE",
                "enrichment_status": policy["enrichment_status"],
                "header_index": header_index,
                "source_offset": match.start(1),
                "source_header": header
            })

    return candidates


def extract_public_ips(
    received_headers: list[str]
) -> list[str]:
    """
    Return only unique publicly routable IP candidates.
    """

    candidates = extract_ip_candidates(
        received_headers
    )

    return list(dict.fromkeys(
        item["provider_ip"]
        for item in candidates
        if item["is_public"] and item.get("provider_ip")
    ))
