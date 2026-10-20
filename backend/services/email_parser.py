from email import policy
from email.message import Message
import hashlib
import re
import time
from urllib.parse import urlsplit
from email.utils import parseaddr

from services.attachment_intelligence.clamav_scanner import is_configured as clamav_is_configured
from services.attachment_intelligence.clamav_scanner import scan_attachment as scan_attachment_with_clamav
from services.attachment_intelligence.file_type_analysis import (
    MAX_HEADER_READ,
    analyze_file_type,
)
from services.domain_alignment import normalized_host, organizational_domain
from services.domain_intelligence import analyze_domains
from services.url_extraction import extract_url_evidence as _extract_url_evidence
from services.email_forensics.ip_extractor import extract_ip_candidates
from services.email_parsing import EmailParseLimitError, MAX_EMAIL_BYTES, parse_email_bytes


MAX_STATIC_ATTACHMENT_ANALYSES = 50
MAX_EMAIL_ATTACHMENTS_REPORTED = 200
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 50 * 1024 * 1024
MAX_MALWARE_SCAN_ATTACHMENTS = 10
MALWARE_SCAN_BUDGET_SECONDS = 5.0




# ==========================================
# IP INTELLIGENCE
# ==========================================

from services.ip_intelligence import (
    extract_ips_from_chain,
    analyze_ips
)

from services.url_analysis import analyze_urls
from services.advanced_url_intelligence import analyze_urls_deception
from services.link_deception_intelligence import analyze_link_deception_to_dict


# ==========================================
# URL INTELLIGENCE
# ==========================================




# ==========================================
# MAIN EMAIL PARSER
# ==========================================

def parse_email(file_content: bytes, filename: str):
    if not isinstance(file_content, bytes):
        raise TypeError("Email source must be bytes.")
    if len(file_content) > MAX_EMAIL_BYTES:
        raise EmailParseLimitError("Email file exceeds the 25 MiB parser limit.")
    source_format = "outlook_msg" if filename.lower().endswith(".msg") else "eml"
    forensics_input = file_content
    if filename.lower().endswith(".msg"):
        try:
            import extract_msg
        except ImportError as error:
            raise RuntimeError(
                "Native Outlook .msg support requires the 'extract-msg' package."
            ) from error

        outlook_message = extract_msg.openMsg(
            file_content,
            delayAttachments=True,
        )
        try:
            normalized_message = outlook_message.asEmailMessage()
            forensics_input = normalized_message.as_bytes()
            message, parse_diagnostics = parse_email_bytes(forensics_input)
        finally:
            outlook_message.close()
    else:
        message, parse_diagnostics = parse_email_bytes(file_content)


    # --------------------------------------
    # Extract basic email data
    # --------------------------------------

    headers = extract_headers(message)

    parse_issues = []
    body = extract_body(message, parse_issues)

    html_body = extract_html_body(message, parse_issues)
    attachments = extract_attachments(message)

    url_evidence = extract_url_evidence(body, html_body, message=message, parse_issues=parse_issues)
    urls = [item["comparison_url"] for item in url_evidence]

    domain_candidates = []
    sender_address = parseaddr(message.get("From", ""))[1]
    sender_domain = sender_address.rsplit("@", 1)[-1] if "@" in sender_address else ""
    if sender_domain and normalized_host(sender_domain):
        domain_candidates.append(sender_domain)
    for evidence in url_evidence:
        url = evidence.get("original_url") or evidence.get("comparison_url") or ""
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host and normalized_host(host):
            domain_candidates.append(host)
    domain_intelligence = analyze_domains(domain_candidates)

    # ======================================
    # URL INTELLIGENCE
    # ======================================

    url_intelligence = analyze_urls(
        urls
    )

    # ======================================
    # ADVANCED URL DECEPTION INTELLIGENCE
    # ======================================
    advanced_url_intelligence = analyze_urls_deception(
        urls
    )

    # ======================================
    # RENDERED-LINK DECEPTION INTELLIGENCE
    # ======================================
    link_deception_intelligence = analyze_link_deception_to_dict(
        html_body
    )

    authentication = analyze_authentication(message)

    received_chain = extract_received_chain(
        message
    )


    # --------------------------------------
    # IP INTELLIGENCE
    # --------------------------------------

    relay_ips = extract_ips_from_chain(
        received_chain
    )

    ip_intelligence = analyze_ips(
        relay_ips
    )


    # --------------------------------------
    # Threat analysis
    # --------------------------------------

    threat_analysis = analyze_threat(
        message,
        body,
        urls,
        authentication,
        received_chain
    )


    # --------------------------------------
    # Final analysis result
    # --------------------------------------

    return {

        "filename": filename,

        "source_format": source_format,

        "source_evidence": {
            "sha256": hashlib.sha256(file_content).hexdigest(),
            "byte_length": len(file_content),
            "original_bytes_changed": False,
        },

        "parsing": {
            **parse_diagnostics,
            "status": "PARTIAL" if parse_diagnostics["status"] == "PARTIAL" or parse_issues else "COMPLETE",
            "issues": parse_issues,
        },

        "_forensics_input": forensics_input if filename.lower().endswith(".msg") else None,

        "basic_information": {

            "subject": message.get(
                "Subject"
            ),

            "from": message.get(
                "From"
            ),

            "sender": message.get("Sender"),

            "to": message.get(
                "To"
            ),

            "cc": message.get(
                "Cc"
            ),

            "reply_to": message.get(
                "Reply-To"
            ),

            "return_path": message.get(
                "Return-Path"
            ),

            "message_id": message.get(
                "Message-ID"
            ),

            "date": message.get("Date"),
            "in_reply_to": message.get("In-Reply-To"),
            "references": message.get("References")

        },

        "headers": headers,

        "received_chain": received_chain,

        "received_chain_context": {
            "chain_order": "OLDEST_TO_NEWEST",
            "header_storage_order": "NEWEST_TO_OLDEST",
            "trust_state": "UNVERIFIED_MESSAGE_HEADERS",
            "trusted_receiving_boundary_configured": False,
            "sender_origin_established": False,
            "attribution_note": "Received headers in an uploaded message are unverified evidence until matched to a trusted receiving boundary. Relay IP location is approximate infrastructure context, not sender identity or physical location.",
        },

        "ip_intelligence": ip_intelligence,

        "body": {

            "text": body,

            "html": html_body,

            "length": len(body)

        },

        "urls": urls,
        "url_evidence": url_evidence,
        "url_summary": {
            "unique_count": len(urls),
            "occurrence_count": sum(len(item["source_locations"]) for item in url_evidence),
        },
        "domain_intelligence": domain_intelligence,

        # ==================================
        # URL INTELLIGENCE RESULT
        # ==================================

        "url_intelligence": url_intelligence,

        # New future capability kept separate from existing URL output.
        "advanced_url_intelligence": advanced_url_intelligence,

        # Rendered-link / visible-text versus href deception analysis.
        "link_deception_intelligence":
            link_deception_intelligence,

        "attachments": attachments,

        "authentication": authentication,

        "threat_analysis": threat_analysis

    }


# ==========================================
# HEADER EXTRACTION
# ==========================================

def extract_headers(message: Message):
    """Keep compatibility values while exposing every original header occurrence."""
    headers = {}
    occurrences: dict[str, list[str]] = {}
    duplicate_headers = []
    for key, value in message.raw_items():
        occurrences.setdefault(key.lower(), []).append(str(value))

    for key_lower, values in occurrences.items():
        headers[key_lower] = values if key_lower == "received" else values[0]
        if len(values) > 1:
            duplicate_headers.append({"name": key_lower, "count": len(values), "values": values})

    headers["header_occurrences"] = occurrences
    headers["duplicate_headers"] = duplicate_headers
    return headers


# ==========================================
# BODY EXTRACTION
# ==========================================

def extract_body(message: Message, parse_issues: list | None = None):

    body_parts = []


    # --------------------------------------
    # Multipart email
    # --------------------------------------

    if message.is_multipart():

        for part_index, part in enumerate(message.walk()):

            content_type = (
                part.get_content_type()
            )

            disposition = (
                part.get_content_disposition()
            )


            if (
                content_type == "text/plain"
                and
                disposition != "attachment"
            ):

                try:

                    content = part.get_content()


                    if content:

                        body_parts.append(
                            content
                        )

                except Exception as error:
                    if parse_issues is not None:
                        parse_issues.append({"code": "BODY_DECODE_FAILED", "part_index": part_index, "error_type": type(error).__name__})


    # --------------------------------------
    # Single-part email
    # --------------------------------------

    else:

        try:

            if message.get_content_type() in [
                "text/plain",
                "text/html"
            ]:

                content = message.get_content()


                if content:

                    body_parts.append(
                        content
                    )

        except Exception as error:
            if parse_issues is not None:
                parse_issues.append({"code": "BODY_DECODE_FAILED", "part_index": 0, "error_type": type(error).__name__})


    return "\n".join(
        body_parts
    ).strip()



# ==========================================
# HTML BODY EXTRACTION
# ==========================================

MAX_HTML_PART_CHARS = 2 * 1024 * 1024
MAX_HTML_PARTS = 32


def extract_html_body(message: Message, parse_issues: list | None = None):

    html_parts = []
    total_chars = 0

    for part_index, part in enumerate(message.walk()):

        if len(html_parts) >= MAX_HTML_PARTS:
            break

        if (
            part.get_content_type() != "text/html"
            or
            part.get_content_disposition() == "attachment"
        ):
            continue

        try:

            content = part.get_content()

        except Exception as error:
            if parse_issues is not None:
                parse_issues.append({"code": "HTML_BODY_DECODE_FAILED", "part_index": part_index, "error_type": type(error).__name__})
            continue

        if not content:
            continue

        remaining = (
            MAX_HTML_PART_CHARS
            - total_chars
        )

        if remaining <= 0:
            break

        content = content[:remaining]

        html_parts.append(
            content
        )

        total_chars += len(content)

    return "\n".join(
        html_parts
    )


# ==========================================
# URL EXTRACTION
# ==========================================

def extract_url_evidence(
    text: str,
    html_text: str = "",
    *,
    message: Message | None = None,
    parse_issues: list | None = None,
) -> list[dict]:
    """Use shared URL policy, optionally with exact decoded MIME-part provenance."""
    if message is None:
        return _extract_url_evidence([(0, text or "")], [(0, html_text or "")])

    plain_parts: list[tuple[int, str]] = []
    html_parts: list[tuple[int, str]] = []
    if message.is_multipart():
        parts = enumerate(message.walk())
    else:
        parts = [(0, message)]
    for part_index, part in parts:
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"} or part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except Exception as error:
            if parse_issues is not None:
                parse_issues.append({
                    "code": "URL_SOURCE_DECODE_FAILED",
                    "part_index": part_index,
                    "body_type": content_type,
                    "error_type": type(error).__name__,
                })
            continue
        if not isinstance(content, str):
            continue
        if content_type == "text/plain":
            plain_parts.append((part_index, content))
        else:
            html_parts.append((part_index, content))
    return _extract_url_evidence(plain_parts, html_parts)


def extract_urls(text: str, html_text: str = ""):
    return [item["comparison_url"] for item in extract_url_evidence(text, html_text)]


# ==========================================
# ATTACHMENT EXTRACTION
# ==========================================

def extract_attachments(message: Message):

    attachments = []
    omitted_count = 0
    processed_bytes = 0
    malware_scan_deadline = time.monotonic() + MALWARE_SCAN_BUDGET_SECONDS
    malware_scan_count = 0
    malware_scanner_configured = clamav_is_configured()


    for part_index, part in enumerate(message.walk()):

        filename = part.get_filename()


        if filename:
            if len(attachments) >= MAX_EMAIL_ATTACHMENTS_REPORTED:
                omitted_count += 1
                continue
            safe_filename = str(filename).replace("\\", "/").split("/")[-1]
            safe_filename = "".join(
                char for char in safe_filename
                if ord(char) >= 32 and ord(char) != 127
            )[:255] or "unnamed-attachment"
            raw_payload = part.get_payload()
            raw_payload_length = len(raw_payload) if isinstance(raw_payload, (str, bytes)) else 0
            payload_limit_status = None
            payload_decode_failed = False
            if raw_payload_length > MAX_ATTACHMENT_BYTES:
                payload = b""
                payload_limit_status = "PAYLOAD_SIZE_LIMIT_EXCEEDED"
            elif processed_bytes >= MAX_TOTAL_ATTACHMENT_BYTES:
                payload = b""
                payload_limit_status = "TOTAL_ATTACHMENT_SIZE_LIMIT_EXCEEDED"
            else:
                try:
                    decoded_payload = part.get_payload(decode=True)
                    if isinstance(decoded_payload, bytes):
                        payload = decoded_payload
                    elif decoded_payload is None and raw_payload in (None, "", b""):
                        payload = b""
                    else:
                        payload = b""
                        payload_decode_failed = True
                except Exception:
                    payload = b""
                    payload_decode_failed = True
                if len(payload) > MAX_ATTACHMENT_BYTES:
                    payload = b""
                    payload_limit_status = "PAYLOAD_SIZE_LIMIT_EXCEEDED"
                elif processed_bytes + len(payload) > MAX_TOTAL_ATTACHMENT_BYTES:
                    payload = b""
                    payload_limit_status = "TOTAL_ATTACHMENT_SIZE_LIMIT_EXCEEDED"
                else:
                    processed_bytes += len(payload)
            if payload_decode_failed:
                payload_limit_status = "PAYLOAD_DECODE_FAILED"

            item = {
                "filename": safe_filename,
                "mime_part": part_index,
                "content_type": part.get_content_type(),
                "size": None if payload_limit_status else len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if not payload_limit_status else None,
                "analysis_status": payload_limit_status or "NOT_ANALYZED_ATTACHMENT_LIMIT",
                "malware_scan": {
                    "status": (
                        "NOT_CONFIGURED"
                        if not malware_scanner_configured
                        else "NOT_SCANNED_INPUT_UNAVAILABLE"
                        if payload_limit_status
                        else "NOT_SCANNED_PENDING"
                    ),
                    "malware_confirmed": None,
                    "reason": (
                        "No malware scanner is configured; static metadata is not a malware verdict."
                        if not malware_scanner_configured
                        else "Attachment bytes were unavailable for scanning."
                        if payload_limit_status
                        else "ClamAV scan has not completed."
                    ),
                },
                "detonation": {"status": "NOT_CONFIGURED", "content_executed": False},
            }

            if not payload_limit_status and len(attachments) < MAX_STATIC_ATTACHMENT_ANALYSES:
                try:
                    type_result = analyze_file_type(
                        filename=safe_filename,
                        header=payload[:MAX_HEADER_READ],
                        file_size=len(payload),
                    )
                    type_metadata = type_result.metadata or {}
                    item["analysis_status"] = "STATIC_ANALYSIS_COMPLETE"
                    item["file_type_intelligence"] = {
                        "analysis_version": type_result.analysis_version,
                        "detected_type": type_result.detected_type,
                        "detected_category": type_result.detected_category,
                        "mime_type": type_result.mime_type,
                        "extension": type_result.extension,
                        "risk_score": type_result.risk_score,
                        "findings": [finding.to_dict() for finding in type_result.findings[:20]],
                        "metadata": {
                            key: type_metadata[key]
                            for key in (
                                "executable_detected",
                                "archive_detected",
                                "semantic_file_type",
                                "semantic_mime_type",
                                "semantic_extension_consistent",
                                "mime_consistency",
                                "identity_conflict",
                                "identity_confidence",
                                "detection_basis",
                                "signature_offset",
                                "container_subtype",
                                "embedded_markers",
                            )
                            if key in type_metadata
                        },
                    }
                except Exception as error:
                    item["analysis_status"] = "STATIC_ANALYSIS_FAILED"
                    item["analysis_error_type"] = type(error).__name__

            if malware_scanner_configured and not payload_limit_status:
                if malware_scan_count >= MAX_MALWARE_SCAN_ATTACHMENTS:
                    item["malware_scan"] = {
                        "status": "NOT_SCANNED_ATTACHMENT_LIMIT",
                        "malware_confirmed": None,
                        "engine": "ClamAV",
                    }
                elif time.monotonic() >= malware_scan_deadline:
                    item["malware_scan"] = {
                        "status": "NOT_SCANNED_TIME_BUDGET",
                        "malware_confirmed": None,
                        "engine": "ClamAV",
                    }
                else:
                    item["malware_scan"] = scan_attachment_with_clamav(
                        payload,
                        deadline=malware_scan_deadline,
                    )
                    malware_scan_count += 1

            attachments.append(item)

    if omitted_count:
        attachments.append({
            "filename": "[additional attachments omitted]",
            "analysis_status": "ATTACHMENT_COUNT_LIMIT_EXCEEDED",
            "omitted_count": omitted_count,
            "malware_scan": {
                "status": "NOT_CONFIGURED" if not malware_scanner_configured else "NOT_SCANNED_ATTACHMENT_COUNT_LIMIT",
                "malware_confirmed": None,
            },
            "detonation": {"status": "NOT_CONFIGURED", "content_executed": False},
        })


    return attachments


# ==========================================
# SPF / DKIM / DMARC ANALYSIS
# ==========================================

def analyze_authentication(message: Message):

    results = {

        "spf": "NOT_FOUND",

        "dkim": "NOT_FOUND",

        "dmarc": "NOT_FOUND"

    }


    auth_headers = message.get_all(
        "Authentication-Results",
        []
    )


    if not auth_headers:

        return results


    combined = " ".join(
        auth_headers
    ).lower()


    # --------------------------------------
    # SPF
    # --------------------------------------

    spf_match = re.search(
        r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        combined
    )


    if spf_match:

        results["spf"] = (
            spf_match.group(1).upper()
        )


    # --------------------------------------
    # DKIM
    # --------------------------------------

    dkim_match = re.search(
        r"\bdkim\s*=\s*(pass|fail|none|temperror|permerror)",
        combined
    )


    if dkim_match:

        results["dkim"] = (
            dkim_match.group(1).upper()
        )


    # --------------------------------------
    # DMARC
    # --------------------------------------

    dmarc_match = re.search(
        r"\bdmarc\s*=\s*(pass|fail|none|temperror|permerror)",
        combined
    )


    if dmarc_match:

        results["dmarc"] = (
            dmarc_match.group(1).upper()
        )


    results["reported_results"] = {
        "spf": results["spf"],
        "dkim": results["dkim"],
        "dmarc": results["dmarc"],
    }
    results["authentication_results_trusted"] = False
    results["validation"] = {
        "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
        "dkim": {"status": "NOT_VALIDATED"},
        "dmarc": {"status": "NOT_VALIDATED"},
        "reported_headers_trusted": False,
    }
    return results


# ==========================================
# RECEIVED / RELAY CHAIN
# ==========================================

def extract_received_chain(message: Message):

    received_headers = message.get_all(
        "Received",
        []
    )


    chain = []
    validated_candidates = extract_ip_candidates(received_headers)

    # Receiving servers prepend Received fields. Present the chain oldest to
    # newest and keep the original newest-first index for evidence traceability.
    for index, received in enumerate(reversed(received_headers)):
        header_index = len(received_headers) - index - 1
        header_candidates = [
            item for item in validated_candidates
            if item.get("header_index") == header_index
        ]
        valid_candidates = [item for item in header_candidates if item.get("valid", True)]
        malformed_candidates = [item for item in header_candidates if not item.get("valid", True)]
        unique_candidates = list({
            item.get("normalized_ip"): item
            for item in valid_candidates
            if item.get("normalized_ip")
        }.values())
        ip_addresses = [item["normalized_ip"] for item in unique_candidates]
        has_relay_syntax = bool(re.search(r"\b(?:from|by)\s+", received, re.IGNORECASE))

        chain.append({
            "hop": index + 1,
            "raw": received,
            "header_index": header_index,
            "header_position_newest_first": header_index + 1,
            "ip_addresses": ip_addresses,
            "ip_classifications": [item["classification"] for item in unique_candidates],
            "ip_candidates": header_candidates,
            "malformed_ip_candidates": malformed_candidates,
            "parse_status": "MALFORMED" if malformed_candidates or not has_relay_syntax else ("PARSED" if ip_addresses else "NO_IP_FOUND"),
            "trust_state": "UNVERIFIED_MESSAGE_HEADER",
            "trust_basis": "No trusted receiving-boundary configuration was supplied for this analysis.",
        })


    return chain


# ==========================================
# THREAT DETECTION ENGINE
# ==========================================

def analyze_threat(
    message: Message,
    body: str,
    urls: list,
    authentication: dict,
    received_chain: list
):

    score = 0

    indicators = []

    validated_authentication = authentication.get("validation", {})
    validated_spf = validated_authentication.get("spf", {}).get("status")
    validated_dkim = validated_authentication.get("dkim", {}).get("status")
    validated_dmarc = validated_authentication.get("dmarc", {}).get("status")

    # --------------------------------------
    # SCORE BREAKDOWN
    # --------------------------------------

    score_breakdown = []


    # --------------------------------------
    # Normalize email fields
    # --------------------------------------

    subject = (
        message.get("Subject") or ""
    ).lower()


    sender = (
        message.get("From") or ""
    ).lower()


    reply_to = (
        message.get("Reply-To") or ""
    ).lower()


    return_path = (
        message.get("Return-Path") or ""
    ).lower()


    body_lower = (
        body or ""
    ).lower()


    # --------------------------------------
    # SPF
    # --------------------------------------

    if validated_spf == "FAIL":

        score += 20

        score_breakdown.append({
            "category": "Authentication",
            "signal": "SPF validation failed",
            "points": 20
        })


        indicators.append({

            "type": "authentication",

            "severity": "high",

            "title":
                "SPF validation failed",

            "description":
                "The sending infrastructure failed SPF validation."

        })


    # --------------------------------------
    # DKIM
    # --------------------------------------

    if validated_dkim == "FAIL":

        score += 20

        score_breakdown.append({
            "category": "Authentication",
            "signal": "DKIM validation failed",
            "points": 20
        })


        indicators.append({

            "type": "authentication",

            "severity": "high",

            "title":
                "DKIM validation failed",

            "description":
                "The email failed DKIM signature validation."

        })


    # --------------------------------------
    # DMARC
    # --------------------------------------

    if validated_dmarc == "FAIL":

        score += 25

        score_breakdown.append({
            "category": "Authentication",
            "signal": "DMARC validation failed",
            "points": 25
        })


        indicators.append({

            "type": "authentication",

            "severity": "critical",

            "title":
                "DMARC validation failed",

            "description":
                "The visible sender identity failed DMARC alignment."

        })


    # --------------------------------------
    # Reply-To mismatch
    # --------------------------------------

    if sender and reply_to:

        sender_domain = extract_domain(
            sender
        )


        reply_domain = extract_domain(
            reply_to
        )


        if (
            sender_domain
            and reply_domain
            and organizational_domain(sender_domain)
            and organizational_domain(reply_domain)
            and organizational_domain(sender_domain) != organizational_domain(reply_domain)
        ):

            score += 20

            score_breakdown.append({
                "category": "Identity",
                "signal": "Reply-To domain mismatch",
                "points": 20
            })


            indicators.append({

                "type": "identity",

                "severity": "high",

                "title":
                    "Reply-To domain mismatch",

                "description":
                    f"Sender domain '{sender_domain}' "
                    f"differs from Reply-To domain "
                    f"'{reply_domain}'."

            })


    # --------------------------------------
    # Return-Path mismatch
    # --------------------------------------

    if sender and return_path:

        sender_domain = extract_domain(
            sender
        )


        return_domain = extract_domain(
            return_path
        )


        if (
            sender_domain
            and return_domain
            and organizational_domain(sender_domain)
            and organizational_domain(return_domain)
            and organizational_domain(sender_domain) != organizational_domain(return_domain)
        ):

            score += 10

            score_breakdown.append({
                "category": "Identity",
                "signal": "Return-Path mismatch",
                "points": 10
            })


            indicators.append({

                "type": "identity",

                "severity": "medium",

                "title":
                    "Return-Path mismatch",

                "description":
                    f"Return-Path domain '{return_domain}' "
                    f"does not match sender domain "
                    f"'{sender_domain}'."

            })


    # --------------------------------------
    # Suspicious URL detection
    # --------------------------------------

    for url in urls:

        url_lower = url.lower()


        suspicious_terms = [

            "login",

            "verify",

            "verification",

            "account",

            "secure",

            "password",

            "update",

            "confirm"

        ]


        matched_terms = [

            term

            for term in suspicious_terms

            if term in url_lower

        ]


        if matched_terms:

            score += 10

            score_breakdown.append({
                "category": "URL",
                "signal": "Suspicious URL detected",
                "points": 10,
                "url": url
            })


            indicators.append({

                "type": "url",

                "severity": "medium",

                "title":
                    "Suspicious URL detected",

                "description":
                    "URL contains credential or "
                    "account-related keywords.",

                "url":
                    url,

                "matched_terms":
                    matched_terms

            })


    # --------------------------------------
    # Urgency / social engineering
    # --------------------------------------

    urgency_terms = [

        "urgent",

        "immediately",

        "within 24 hours",

        "action required",

        "account suspended",

        "verify your account",

        "failure to verify",

        "confirm your account"

    ]


    # Urgency is a risk signal only when it accompanies a recipient action.
    # Ignore quoted examples, explicit negation and terms isolated in boilerplate.
    unquoted_text = re.sub(
        r"""“[^”]*”|"[^"]*"|‘[^’]*’|(?<!\w)'[^'\n]*'(?!\w)""",
        " ",
        f"{subject}\n{body_lower}",
    )
    clauses = [part.strip() for part in re.split(r"[.!?;\n]+", unquoted_text) if part.strip()]
    negation_terms = ("never ask", "do not", "don't", "does not", "will not", "won't",
                      "not required", "no need to", "not asking", "without asking")
    clauses = [part for part in clauses if not any(term in part for term in negation_terms)]
    actionable_terms = (
        "verify your account", "verify your identity", "enter your password",
        "provide your password", "sign in", "log in", "click here", "open the link",
        "transfer funds", "send payment", "wire transfer", "update your payment",
        "download the attachment", "open the attachment", "reply with",
    )
    matched_urgency = []
    for index in range(len(clauses)):
        context = " ".join(clauses[max(0, index - 1):index + 2])
        if not any(term in context for term in actionable_terms):
            continue
        matched_urgency.extend(term for term in urgency_terms if term in context)
    matched_urgency = list(dict.fromkeys(matched_urgency))


    if matched_urgency:

        score += 10

        score_breakdown.append({
            "category": "Social Engineering",
            "signal": "Urgency-based social engineering",
            "points": 10
        })


        indicators.append({

            "type":
                "social_engineering",

            "severity":
                "medium",

            "title":
                "Urgency-based social engineering",

            "description":
                "The message uses urgency or "
                "account-pressure language.",

            "matches":
                matched_urgency

        })


    # --------------------------------------
    # Multiple relay hops
    # --------------------------------------

    if len(received_chain) >= 2:

        indicators.append({

            "type":
                "routing",

            "severity":
                "info",

            "title":
                "Multiple relay hops detected",

            "description":
                f"{len(received_chain)} mail routing hops "
                "were found in the header chain."

        })


    # --------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------

    score = min(
        max(score, 0),
        100
    )


    # --------------------------------------
    # Threat verdict
    # --------------------------------------

    if score >= 75:

        verdict = "CRITICAL"

        confidence = "HIGH"


    elif score >= 50:

        verdict = "HIGH RISK"

        confidence = "HIGH"


    elif score >= 30:

        verdict = "SUSPICIOUS"

        confidence = "MEDIUM"


    else:

        verdict = "LOW RISK"

        confidence = "LOW"


    # --------------------------------------
    # Final threat result
    # --------------------------------------

    return {

        "score":
            score,

        "verdict":
            verdict,

        "confidence":
            confidence,

        "indicator_count":
            len(indicators),

        "indicators":
            indicators

,

        "score_breakdown":
            score_breakdown

    }


# ==========================================
# DOMAIN EXTRACTION
# ==========================================

def extract_domain(value: str):
    return normalized_host(value)



