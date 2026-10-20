from __future__ import annotations

import json

from services.advanced_url_intelligence import analyze_url_deception
from services.brand_registry import get_brand_registry
from services.domain_alignment import organizational_domain
from services.email_ai.features import analyze_identity_intelligence
from services.email_forensics.url_analyzer import analyze_urls as analyze_forensic_urls
from services.link_deception_intelligence import _registrable_domain
from services.link_deception_intelligence import analyze_link_deception_to_dict


def findings(result, rule_id):
    return [item for item in result.findings if item.rule_id == rule_id]


def test_typo_domain_has_explainable_low_weight_signal():
    result = analyze_url_deception("https://paypa1.com/")
    finding = findings(result, "URL_BRAND_DOMAIN_MISMATCH")[0]
    evidence = finding.evidence["comparisons"][0]
    assert evidence["brand"] == "paypal"
    assert evidence["compared_registrable_domain"] == "paypa1.com"
    assert evidence["approved_registrable_domain"] == "paypal.com"
    assert evidence["transformation"] == "edit_distance"
    assert evidence["edit_distance"] == 1
    assert evidence["similarity"] >= 0.75
    assert finding.severity == "LOW" and finding.score <= 10
    assert result.verdict == "LOW_RISK"


def test_approved_brand_subdomain_under_multilabel_suffix_is_legitimate():
    result = analyze_url_deception("https://auth.login.google.co.uk/account")
    assert result.registrable_domain == "google.co.uk"
    assert result.subdomains == ["auth", "login"]
    assert result.legitimate_brand_domain is True
    assert result.brand_domain_mismatch is False
    assert not findings(result, "URL_BRAND_DOMAIN_MISMATCH")
    assert organizational_domain("auth.login.google.co.uk") == "google.co.uk"


def test_unicode_confusable_preserves_original_and_idna_evidence():
    result = analyze_url_deception("https://раypal.com/signin")
    assert result.unicode_hostname == "раypal.com"
    assert result.ascii_hostname.startswith("xn--")
    assert result.registrable_domain == result.ascii_hostname
    assert result.unicode_confusable is True
    confusable = findings(result, "URL_UNICODE_CONFUSABLE_HOST")[0]
    assert confusable.evidence["skeleton"] == "paypal.com"
    assert confusable.evidence["confusable_characters"]
    brand = findings(result, "URL_BRAND_DOMAIN_MISMATCH")[0]
    assert brand.evidence["comparisons"][0]["transformation"] == "unicode_confusable_skeleton"
    assert brand.severity == "LOW"


def test_punycode_domain_is_decoded_for_homograph_review():
    result = analyze_url_deception("https://xn--ypal-43d9g.com/")
    assert result.punycode_detected is True
    assert result.unicode_hostname == "раypal.com"
    assert result.ascii_hostname == "xn--ypal-43d9g.com"
    assert findings(result, "URL_UNICODE_CONFUSABLE_HOST")


def test_unrelated_similar_text_does_not_match_a_brand_candidate():
    result = analyze_url_deception("https://goggles.example.net/")
    assert "google" not in result.brand_candidates
    assert not findings(result, "URL_BRAND_DOMAIN_MISMATCH")
    assert result.verdict == "LOW_RISK"


def test_malformed_hostname_fails_closed_without_similarity_claim():
    result = analyze_url_deception("https://paypal..com/")
    assert result.ascii_hostname is None
    assert result.registrable_domain is None
    invalid = findings(result, "URL_INVALID_HOST_ENCODING")
    assert invalid and invalid[0].score == 0
    assert not findings(result, "URL_BRAND_DOMAIN_MISMATCH")


def test_brand_list_can_be_overridden_with_reviewable_provenance(tmp_path):
    path = tmp_path / "brands.json"
    path.write_text(json.dumps({
        "version": "test-1",
        "provenance": "Synthetic unit-test registry",
        "last_reviewed": "2026-10-19",
        "maintenance_policy": "Test-only override",
        "brands": {"examplebrand": ["examplebrand.test"]},
    }), encoding="utf-8")
    brands, metadata = get_brand_registry(str(path))
    assert brands == {"examplebrand": {"examplebrand.test"}}
    assert metadata["version"] == "test-1"
    assert metadata["provenance"] == "Synthetic unit-test registry"


def test_link_deception_uses_psl_registrable_domains():
    assert _registrable_domain("login.google.co.uk") == "google.co.uk"


def test_visible_brand_link_to_approved_multilabel_domain_is_not_mismatched():
    result = analyze_link_deception_to_dict(
        '<a href="https://auth.google.co.uk/account">Google account</a>'
    )
    link = result["links"][0]
    assert link["destination_registrable_domain"] == "google.co.uk"
    assert link["brand_mismatch"] is False


def test_similarity_without_claimed_brand_is_context_only_in_identity_score():
    result = analyze_identity_intelligence({"sender": "security@paypall.com"})
    assert result["typosquatting_findings"]
    assert result["identity_risk_score"] == 0
    assert result["typosquatting_findings"][0]["corroborated_by_display_name"] is False


def test_claimed_brand_corroborates_but_does_not_hide_lookalike_evidence():
    result = analyze_identity_intelligence({
        "sender": "PayPal Security <security@paypall.com>"
    })
    assert result["claimed_brands"] == ["paypal"]
    assert result["identity_risk_score"] > 0
    assert result["typosquatting_findings"][0]["corroborated_by_display_name"] is True


def test_forensic_url_analyzer_does_not_score_brand_keyword_alone():
    result = analyze_forensic_urls("https://paypal.com/")
    assert [item["url"] for item in result["urls"]] == ["https://paypal.com/"]
    assert result["risk_score"] == 0
    assert result["findings"] == []
