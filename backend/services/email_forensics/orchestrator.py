from __future__ import annotations

from typing import Any

from .header_parser import parse_email_headers
from .header_anomaly_detector import detect_header_anomalies
from .ip_extractor import extract_ip_candidates, extract_public_ips
from .relay_chain import build_relay_chain, summarize_relay_chain
from .authentication_analyzer import analyze_authentication
from .timeline_analyzer import analyze_timeline
from .url_analyzer import analyze_urls
from services.url_extraction import extract_url_evidence
from .origin_scoring import (
    score_origin_candidates,
    get_top_origin_candidate,
)


def analyze_email_forensics(
    raw_email: bytes | str,
    ip_intelligence: dict[str, dict[str, Any]] | None = None,
    verify_authentication: bool = True,
    smtp_context: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Complete email-forensics evidence pipeline.

    Pipeline:
        raw email
          -> header parsing
          -> IP extraction
          -> relay-chain reconstruction
          -> origin candidate scoring
          -> authentication analysis

    This module evaluates technical infrastructure evidence.
    It does not identify a specific person.
    """

    ip_intelligence = ip_intelligence or {}

    # -----------------------------------------------------
    # HEADER PARSING
    # -----------------------------------------------------

    headers = parse_email_headers(raw_email)

    received_headers = headers.get(
        "received",
        []
    )
    # -----------------------------------------------------
    # ADVANCED HEADER ANOMALY DETECTION
    # -----------------------------------------------------

    header_anomaly_analysis = detect_header_anomalies(headers)








    # -----------------------------------------------------
    # IP EXTRACTION
    # -----------------------------------------------------

    ip_candidates = extract_ip_candidates(
        received_headers
    )

    public_ips = extract_public_ips(
        received_headers
    )

    # -----------------------------------------------------
    # RELAY CHAIN
    # -----------------------------------------------------

    relay_chain = build_relay_chain(
        received_headers,
        ip_candidates
    )

    relay_summary = summarize_relay_chain(
        relay_chain
    )

    # -----------------------------------------------------
    # ORIGIN SCORING
    # -----------------------------------------------------

    origin_candidates = score_origin_candidates(
        relay_chain,
        ip_intelligence
    )

    top_origin = get_top_origin_candidate(
        origin_candidates
    )

    # -----------------------------------------------------
    # AUTHENTICATION ANALYSIS
    # -----------------------------------------------------

    authentication_analysis = analyze_authentication(headers)
    if verify_authentication:
        authentication_analysis["validation"] = analyze_authentication(
            headers,
            raw_email=(
                raw_email.encode("utf-8", errors="replace")
                if isinstance(raw_email, str)
                else raw_email
            ),
            smtp_context=smtp_context,
        )["validation"]
    else:
        authentication_analysis["validation"] = {
            "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
            "dkim": {"status": "NOT_VALIDATED_MSG_CONVERSION"},
            "dmarc": {"status": "NOT_VALIDATED"},
            "reported_headers_trusted": False,
        }

    # -----------------------------------------------------
    # TIMELINE ANALYSIS
    # -----------------------------------------------------

    timeline_analysis = analyze_timeline(
        headers
    )

    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    body_text = ""
    body_html = ""

    try:
        body = headers.get("body", {})
        if isinstance(body, dict):
            body_text = body.get("text", "") or ""
            body_html = body.get("html", "") or ""
        elif isinstance(body, str):
            body_text = body
    except Exception:
        body_text = ""

    url_evidence = extract_url_evidence([(0, body_text)], [(0, body_html)])
    url_analysis = analyze_urls([item["comparison_url"] for item in url_evidence])

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {
        "headers": headers,
        "parsing": headers.get("parsing", {"status": "UNKNOWN"}),

        "ip_intelligence": {
            "candidates": ip_candidates,
            "public_ips": public_ips,
            "public_ip_count": len(public_ips)
        },

        "relay_chain": relay_chain,

        "relay_summary": relay_summary,

        "relay_context": {
            "chain_order": "OLDEST_TO_NEWEST",
            "trust_state": "UNVERIFIED_MESSAGE_HEADERS",
            "trusted_receiving_boundary_configured": False,
            "sender_origin_established": False,
            "attribution_note": "Received headers are supplied with the analyzed message and are unverified unless matched against a trusted receiving boundary. Relay IP intelligence describes network infrastructure only.",
        },

        "authentication_analysis": authentication_analysis,

        "header_anomaly_analysis": header_anomaly_analysis,

        "timeline_analysis": timeline_analysis,

        "url_analysis": url_analysis,
        "url_evidence": url_evidence,

        "origin_scoring": {
            "candidate_count": len(
                origin_candidates
            ),
            "candidates": origin_candidates,
            "top_candidate": top_origin,
        },

        "forensics_status": {
            "headers_parsed": True,
            "header_parse_status": headers.get("parsing", {}).get("status", "UNKNOWN"),

            "received_headers_found": len(
                received_headers
            ),

            "ip_candidates_found": len(
                [item for item in ip_candidates if item.get("valid", True)]
            ),

            "malformed_ip_candidates_found": len(
                [item for item in ip_candidates if not item.get("valid", True)]
            ),

            "public_ips_found": len(
                public_ips
            ),

            "relay_hops_found": len(
                relay_chain
            ),

            "origin_candidates_found": len(
                origin_candidates
            )
        }
    }
