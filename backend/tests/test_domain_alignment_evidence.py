from email.message import EmailMessage, Message

from services.domain_alignment import compare_domains, domains_differ, organizational_domain
from services.email_ai.intelligence_fusion import analyze_email_intelligence
from services.email_forensics.header_anomaly_detector import detect_header_anomalies
from services.email_forensics.authentication_analyzer import analyze_authentication
from services.email_ai.features import _domain_root
from services.email_parser import analyze_threat, extract_body, extract_html_body, extract_url_evidence, parse_email
from services.threat_intelligence.ioc_normalizer import extract_iocs, summarize_iocs


def test_psl_comparison_distinguishes_exact_aligned_and_unrelated_domains():
    assert compare_domains("mx.example.co.uk", "mx.example.co.uk") == "EXACT_HOST"
    assert compare_domains("bounce.shop.example.co.uk", "mail.example.co.uk") == "ORGANIZATIONAL_ALIGNMENT"
    assert compare_domains("example.co.uk", "other.co.uk") == "MISMATCH"
    assert compare_domains("not-an-email@@example.com", "example.com") == "UNKNOWN"
    assert _domain_root("mail.example.co.uk") == "example.co.uk"
    assert not domains_differ("mail.example.co.uk", "mail.example.co.uk")
    assert not domains_differ("bounce.shop.example.co.uk", "mail.example.co.uk")
    assert domains_differ("example.co.uk", "other.co.uk")
    assert organizational_domain("bücher.de") == "xn--bcher-kva.de"
    assert compare_domains("mail.bücher.de", "bounce.xn--bcher-kva.de") == "ORGANIZATIONAL_ALIGNMENT"


def test_malformed_addresses_do_not_produce_an_organizational_domain():
    assert organizational_domain("not-an-email@@example.com") is None
    assert organizational_domain("user@bad..example.com") is None


def test_sender_header_host_variation_within_org_domain_is_not_spoof_finding():
    result = detect_header_anomalies({
        "from": "Marketing <news@mailer.example.com>",
        "sender": "bulk@send.example.com",
        "reply-to": "help@support.example.com",
        "return-path": "bounce@bounce.example.com",
    })

    titles = {finding["title"] for finding in result["findings"]}
    assert "From and Sender domains differ" not in titles
    assert "From and Return-Path domains differ" not in titles
    unrelated = detect_header_anomalies({
        "from": "news@mailer.example.com",
        "sender": "spoof@attacker.net",
        "return-path": "bounce@evil.org",
    })
    unrelated_titles = {finding["title"] for finding in unrelated["findings"]}
    assert "From and Sender domains differ" in unrelated_titles
    assert "From and Return-Path domains differ" in unrelated_titles


def test_fusion_reply_to_domain_comparison_uses_organizational_domain():
    result = analyze_email_intelligence(
        email={
            "sender": "news@mailer.example.com",
            "sender_domain": "mailer.example.com",
            "reply_to": "help@support.example.com",
        },
        ai_result={"status": "MODEL_NOT_READY"},
    )

    assert "identity" not in {item["category"] for item in result["evidence"]}
    mismatch = analyze_email_intelligence(
        email={"sender": "news@example.com", "reply_to": "collect@attacker.net"},
        ai_result={"status": "MODEL_NOT_READY"},
    )
    assert "identity" in {item["category"] for item in mismatch["evidence"]}


def test_authentication_pass_does_not_relabel_unrelated_return_path_as_aligned():
    result = analyze_authentication({
        "from": "news@example.com",
        "return_path": "bounce@attacker.net",
        "authentication": {
            "authentication_results": ["mx.example.com; spf=pass dkim=pass dmarc=pass"],
        },
    })

    assert result["sender_return_path_alignment"] == "MISMATCH"
    assert result["sender_return_path_domain_comparison"] == "MISMATCH"
    assert any(item["type"] == "alignment" for item in result["findings"])


def test_parser_only_scores_return_path_when_organizational_domains_mismatch():
    message = Message()
    message["From"] = "news@mailer.example.com"
    message["Return-Path"] = "bounce@bounce.example.com"
    aligned = analyze_threat(
        message, "Routine notice", [], {"validation": {"dmarc": {"status": "PASS"}}}, []
    )
    assert not any(item["signal"] == "Return-Path mismatch" for item in aligned["score_breakdown"])

    message.replace_header("From", "news@example.com")
    message.replace_header("Return-Path", "bounce@attacker.net")
    unrelated = analyze_threat(
        message, "Routine notice", [], {"validation": {"dmarc": {"status": "PASS"}}}, []
    )
    assert any(item["signal"] == "Return-Path mismatch" for item in unrelated["score_breakdown"])


def test_ioc_dedup_does_not_merge_distinct_case_sensitive_url_paths():
    iocs = extract_iocs(
        "https://example.com/Login https://example.com/login"
    )
    urls = [item for item in iocs if item["ioc_type"] == "url"]

    assert len(urls) == 2
    assert summarize_iocs(iocs)["url"] == 2


def test_html_plain_text_overlap_is_one_url_with_both_source_locations():
    message = EmailMessage()
    message.set_content("Visit https://offers.example.com/Deal")
    message.add_alternative(
        '<html><a href="https://offers.example.com/Deal">Visit</a>'
        '<a href="https://offers.example.com/login">Sign in</a></html>',
        subtype="html",
    )
    plain = extract_body(message)
    html = extract_html_body(message)
    evidence = extract_url_evidence(plain, html)

    assert len(evidence) == 2
    overlap = next(item for item in evidence if item["normalized_url"].endswith("/Deal"))
    assert {location["part"] for location in overlap["source_locations"]} == {
        "text/plain", "text/html"
    }
    iocs = extract_iocs(plain, url_evidence=evidence)
    assert summarize_iocs(iocs)["url"] == len(evidence)
    ioc = next(item for item in iocs if item["ioc_type"] == "url" and item["ioc"].endswith("/Deal"))
    assert len(ioc["source_locations"]) == 2
    html_only_iocs = extract_iocs("", url_evidence=evidence)
    assert summarize_iocs(html_only_iocs)["url"] == 2


def test_parser_and_ioc_report_counts_include_html_only_and_overlapping_urls():
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["Subject"] = "Routine notice"
    message.set_content("Offer: https://offers.example.com/Deal")
    message.add_alternative(
        '<html><a href="https://offers.example.com/Deal">Offer</a>'
        '<a href="https://offers.example.com/html-only">Details</a></html>',
        subtype="html",
    )
    parsed = parse_email(message.as_bytes(), "url-counts.eml")
    iocs = extract_iocs(
        parsed["body"]["text"], url_evidence=parsed["url_evidence"]
    )
    summary = summarize_iocs(iocs)

    assert parsed["url_summary"]["unique_count"] == 2
    assert summary["url"] == 2
    assert {item["normalized_url"] for item in parsed["url_evidence"]} == {
        "https://offers.example.com/Deal",
        "https://offers.example.com/html-only",
    }


def test_url_canonicalization_normalizes_host_and_default_port_only():
    iocs = extract_iocs(
        "HTTP://Example.com:80/Path https://example.com/path https://example.com/Path"
    )
    urls = [item["ioc"] for item in iocs if item["ioc_type"] == "url"]

    assert urls == ["http://example.com/Path", "https://example.com/path", "https://example.com/Path"]


def test_analyze_email_api_reconciles_url_and_ioc_counts(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import database.database as database
    import main

    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "api-analysis.db")
    monkeypatch.setattr(
        main,
        "analyze_email_forensics",
        lambda *_args, **_kwargs: {
            "ip_intelligence": {"candidates": []},
            "authentication_analysis": {"validation": {}},
            "url_analysis": {"urls": []},
        },
    )
    monkeypatch.setattr(
        main,
        "get_threat_intelligence_source_status",
        lambda: {"coverage_status": "NEVER_SYNCED", "providers": {}},
    )
    database.initialize_database()
    raw_message = (
        b"From: promotions@example.com\r\n"
        b"Subject: Offer\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=part\r\n\r\n"
        b"--part\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Offer at https://offers.example.com/Deal\r\n"
        b"--part\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><a href='https://offers.example.com/Deal'>Offer</a>"
        b"<a href='https://offers.example.com/html-only'>Details</a></html>\r\n"
        b"--part--\r\n"
    )

    with TestClient(main.app, client=("127.0.0.1", 54321)) as client:
        response = client.post(
            "/api/analyze-email",
            files={"file": ("url-counts.eml", raw_message, "message/rfc822")},
        )

    assert response.status_code == 200, response.text
    analysis = response.json()["analysis"]
    assert analysis["url_summary"] == {
        "unique_count": 2,
        "occurrence_count": 3,
        "ioc_unique_count": 2,
        "counts_consistent": True,
    }
    assert len(analysis["urls"]) == 2
    assert analysis["threat_intelligence"]["ioc_summary"]["url"] == 2
    assert analysis["threat_analysis"]["score_source"] == "intelligence_fusion"
