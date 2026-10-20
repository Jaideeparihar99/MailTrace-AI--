from __future__ import annotations

import re
from typing import Any


# =========================================================
# RELAY CHAIN
# =========================================================

FROM_PATTERN = re.compile(
    r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|;|$)",
    re.IGNORECASE
)

BY_PATTERN = re.compile(
    r"\bby\s+([^\s;]+)",
    re.IGNORECASE
)


def build_relay_chain(
    received_headers: list[str],
    ip_candidates: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """
    Convert Received headers into an ordered relay chain.

    Important:
    RFC Received headers are normally added at the top,
    so the oldest hop appears later in the header list.

    This function therefore reverses the header order
    for chronological relay analysis.
    """

    ip_candidates = ip_candidates or []

    chain: list[dict[str, Any]] = []

    # -----------------------------------------------------
    # OLDEST -> NEWEST
    # -----------------------------------------------------

    ordered_headers = list(
        reversed(received_headers)
    )

    for hop_index, header in enumerate(ordered_headers):

        if not header:
            continue

        header_index = len(received_headers) - hop_index - 1

        from_match = FROM_PATTERN.search(header)
        by_match = BY_PATTERN.search(header)

        from_host = (
            from_match.group(1).strip()
            if from_match
            else None
        )

        by_host = (
            by_match.group(1).strip()
            if by_match
            else None
        )

        # -------------------------------------------------
        # MATCH IPs BELONGING TO THIS HEADER
        # -------------------------------------------------

        header_ips = [
            item
            for item in ip_candidates
            if item.get("header_index") == header_index
        ]

        valid_header_ip_occurrences = [item for item in header_ips if item.get("valid", True)]
        malformed_ip_candidates = [item for item in header_ips if not item.get("valid", True)]
        valid_header_ips = []
        seen_header_ips = set()
        for item in valid_header_ip_occurrences:
            normalized = item.get("ip")
            if normalized and normalized not in seen_header_ips:
                seen_header_ips.add(normalized)
                valid_header_ips.append(item)

        ips = [
            item.get("ip")
            for item in valid_header_ips
            if item.get("ip")
        ]

        classifications = [
            item.get("classification")
            for item in valid_header_ips
            if item.get("classification")
        ]

        parse_status = (
            "MALFORMED"
            if malformed_ip_candidates or not (from_match or by_match)
            else ("PARSED" if ips else "NO_IP_FOUND")
        )

        chain.append({
            "hop": hop_index + 1,
            "from": from_host,
            "by": by_host,
            "ips": ips,
            "ip_classifications": classifications,
            "ip_candidates": valid_header_ip_occurrences,
            "malformed_ip_candidates": malformed_ip_candidates,
            "parse_status": parse_status,
            "ip_status": "PRESENT" if ips else ("MALFORMED" if malformed_ip_candidates else "NOT_FOUND"),
            "trust_state": "UNVERIFIED_MESSAGE_HEADER",
            "trust_basis": "No trusted receiving-boundary configuration was supplied for this analysis.",
            "header_position_newest_first": header_index + 1,
            "header": header,
            "header_index": header_index,
            "has_public_ip": any(
                item.get("is_public") is True
                for item in valid_header_ips
            ),
        })

    return chain


def summarize_relay_chain(
    chain: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Generate a compact relay-chain summary.
    """

    public_hops = [
        hop
        for hop in chain
        if hop.get("has_public_ip")
    ]

    private_hops = [
        hop
        for hop in chain
        if any(
            classification == "PRIVATE"
            for classification
            in hop.get(
                "ip_classifications",
                []
            )
        )
    ]

    return {
        "hop_count": len(chain),
        "chain_order": "OLDEST_TO_NEWEST",
        "trust_state": "UNVERIFIED_MESSAGE_HEADERS",
        "sender_origin_established": False,
        "attribution_note": "Received headers supplied with a message are unverified unless checked against a trusted receiving boundary; relay IPs do not establish sender identity or physical location.",
        "public_hop_count": len(public_hops),
        "private_hop_count": len(private_hops),
        "first_hop": (
            chain[0]
            if chain
            else None
        ),
        "last_hop": (
            chain[-1]
            if chain
            else None
        ),
    }
