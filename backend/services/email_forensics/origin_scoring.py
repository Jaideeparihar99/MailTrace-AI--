from __future__ import annotations

from typing import Any


# =========================================================
# SMART ORIGIN SCORING
# =========================================================

def score_origin_candidates(
    relay_chain: list[dict[str, Any]],
    ip_intelligence: dict[str, dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """
    Rank observed relay IPs for analyst review.

    Uploaded Received headers are untrusted input. This heuristic does not
    identify a sender origin, person, or attacker.
    """

    ip_intelligence = ip_intelligence or {}
    candidates: dict[str, dict[str, Any]] = {}

    for hop in relay_chain:

        hop_number = hop.get("hop")
        hop_ips = hop.get("ips", [])
        hop_classifications = hop.get(
            "ip_classifications",
            []
        )

        for position, ip in enumerate(hop_ips):

            if not ip:
                continue

            intelligence = ip_intelligence.get(ip, {})

            relay_classification = (
                hop_classifications[position]
                if position < len(hop_classifications)
                else None
            )

            candidate = candidates.setdefault(
                ip,
                {
                    "ip": ip,
                    "score": 0,
                    "hop": hop_number,
                    "source_hops": [],
                    "source_header_indices": [],
                    "candidate_type": "OBSERVED_RELAY_IP",
                    "attribution_status": "UNVERIFIED_NOT_SENDER_ORIGIN",
                    "trust_state": "UNVERIFIED_MESSAGE_HEADER",
                    "score_semantics": "Analyst-priority heuristic from routability and available threat evidence; not source attribution or origin confidence.",
                    "classification": None,
                    "hostname": None,
                    "organization": None,
                    "asn": None,
                    "provider_sources": [],
                    "network_classification": "UNKNOWN",
                    "risk": None,
                    "risk_score": None,
                    "confidence": None,
                    "reasons": [],
                }
            )

            if hop_number is not None and hop_number not in candidate["source_hops"]:
                candidate["source_hops"].append(hop_number)
            header_index = hop.get("header_index")
            if header_index is not None and header_index not in candidate["source_header_indices"]:
                candidate["source_header_indices"].append(header_index)

            for provider in intelligence.get("provider_status", []) or []:
                if not isinstance(provider, dict):
                    continue
                source_record = {
                    "provider": provider.get("provider"),
                    "source": provider.get("source"),
                    "status": provider.get("status", "UNKNOWN"),
                    "lookup_timestamp": provider.get("lookup_timestamp"),
                }
                if source_record not in candidate["provider_sources"]:
                    candidate["provider_sources"].append(source_record)

            legacy_network = intelligence.get("network_intelligence") or {}
            if isinstance(legacy_network, dict) and legacy_network.get("provider"):
                source_record = {
                    "provider": legacy_network.get("provider"),
                    "source": legacy_network.get("source"),
                    "status": legacy_network.get("status", "UNKNOWN"),
                    "lookup_timestamp": legacy_network.get("lookup_timestamp"),
                }
                if source_record not in candidate["provider_sources"]:
                    candidate["provider_sources"].append(source_record)

            # -------------------------------------------------
            # CLASSIFICATION
            # -------------------------------------------------

            classification = intelligence.get("type")

            if not classification:
                classification = relay_classification

            candidate["classification"] = (
                classification
                or candidate["classification"]
            )

            # -------------------------------------------------
            # ADDRESS FLAGS
            # -------------------------------------------------

            is_private = (
                intelligence.get("is_private") is True
                or relay_classification == "PRIVATE"
            )

            is_loopback = (
                intelligence.get("is_loopback") is True
                or relay_classification == "LOOPBACK"
            )

            is_reserved = (
                intelligence.get("is_reserved") is True
                or relay_classification == "RESERVED"
            )

            is_documentation = (
                intelligence.get("is_documentation") is True
                or relay_classification == "DOCUMENTATION"
            )
            is_non_public = (
                intelligence.get("is_global") is False
                or intelligence.get("enrichment_status") == "NOT_PUBLIC"
                or (relay_classification is not None and relay_classification != "PUBLIC")
                or intelligence.get("classification") not in (None, "PUBLIC")
            )

            # -------------------------------------------------
            # NON-PUBLIC IPs
            # -------------------------------------------------

            if is_private:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Private IP; not considered a public origin candidate."
                ]

                continue

            if is_loopback:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Loopback IP; not a remote origin candidate."
                ]

                continue

            if is_reserved:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Reserved IP space; not considered a public origin candidate."
                ]

                continue

            if is_documentation:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Documentation/test IP; not evidence of a real Internet origin."
                ]

                continue

            if is_non_public:
                candidate["score"] = 0
                candidate["reasons"] = [
                    "Non-public or special-use IP; not considered a public origin candidate."
                ]
                continue

            # -------------------------------------------------
            # PUBLIC ROUTABILITY
            # -------------------------------------------------

            candidate["score"] += 25

            candidate["reasons"].append(
                "Publicly routable IP candidate."
            )
            candidate["reasons"].append(
                "An observed relay IP does not prove sender origin."
            )

            # -------------------------------------------------
            # REVERSE DNS
            # -------------------------------------------------

            hostname = intelligence.get("hostname")

            if hostname:

                candidate["hostname"] = hostname

                candidate["reasons"].append(
                    "Reverse-DNS hostname reported by the configured resolver; this is network context, not identity proof."
                )

            # -------------------------------------------------
            # ORGANIZATION
            # -------------------------------------------------

            organization = intelligence.get("organization")

            if organization:

                candidate["organization"] = organization

                candidate["reasons"].append(
                    "Network organization reported by an enrichment provider; this does not identify the message sender."
                )

            # -------------------------------------------------
            # ASN
            # -------------------------------------------------

            asn = intelligence.get("asn")

            if asn:

                candidate["asn"] = asn

                candidate["reasons"].append(
                    "ASN reported by an enrichment provider; this does not establish hosting, VPN, proxy or Tor status."
                )

            # -------------------------------------------------
            # THREAT INTELLIGENCE
            # -------------------------------------------------

            risk = intelligence.get("risk")
            risk_score = intelligence.get("risk_score")
            confidence = intelligence.get("confidence")

            candidate["risk"] = risk
            candidate["risk_score"] = risk_score
            candidate["confidence"] = confidence

            if isinstance(risk_score, (int, float)):

                if risk_score >= 80:

                    candidate["score"] += 20

                    candidate["reasons"].append(
                        "Strong external threat indicators observed."
                    )

                elif risk_score >= 60:

                    candidate["score"] += 15

                    candidate["reasons"].append(
                        "Significant threat indicators observed."
                    )

                elif risk_score >= 30:

                    candidate["score"] += 5

                    candidate["reasons"].append(
                        "Moderate threat indicators observed."
                    )

            # -------------------------------------------------
            # HOSTING / DATA CENTER
            # -------------------------------------------------

            if intelligence.get("is_hosting") is True:
                candidate["network_classification"] = "PROVIDER_REPORTED_HOSTING"
                candidate["reasons"].append(
                    "A configured provider reported a hosting flag; this does not identify the sender or establish malicious intent."
                )

    # =========================================================
    # NORMALIZE
    # =========================================================

    results = list(candidates.values())

    for candidate in results:

        candidate["score"] = max(
            0,
            min(
                int(candidate["score"]),
                100
            )
        )

    # =========================================================
    # SORT
    # =========================================================

    results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    # =========================================================
    # RANK
    # =========================================================

    for rank, candidate in enumerate(
        results,
        start=1
    ):
        candidate["rank"] = rank

    return results


# =========================================================
# TOP CANDIDATE
# =========================================================

def get_top_origin_candidate(
    candidates: list[dict[str, Any]]
) -> dict[str, Any] | None:

    if not candidates:
        return None

    return candidates[0]
