"""Coverage for engine.findings._record_findings, the translation layer from
raw module output dicts to persisted Finding rows."""

import pytest

from engine.findings import _HEADER_RECOMMENDATION, _HEADER_SEVERITY


def titles(rows):
    return [r.title for r in rows]


def by_title(rows, needle):
    matches = [r for r in rows if needle in r.title]
    assert len(matches) == 1, f"expected exactly one finding matching {needle!r}, got {titles(rows)}"
    return matches[0]


def test_unknown_module_and_empty_output_record_nothing(assessment, record_findings):
    assert record_findings(assessment.id, "nonexistent_module", {"anything": True}) == []
    assert record_findings(assessment.id, "recon", {}) == []


# --- recon -------------------------------------------------------------------


def test_recon_server_header_disclosure(assessment, record_findings):
    rows = record_findings(assessment.id, "recon", {"server": "nginx/1.18.0"})
    assert titles(rows) == ["Server Version Disclosure: nginx/1.18.0"]
    assert rows[0].severity == "low"
    assert rows[0].source_modules == "recon"
    assert "nginx/1.18.0" in rows[0].description


def test_recon_missing_https_redirect_flagged_only_when_false(assessment, record_findings):
    assert record_findings(assessment.id, "recon", {"https_redirect": {"redirects_to_https": True}}) == []
    assert record_findings(assessment.id, "recon", {"https_redirect": {"redirects_to_https": None}}) == []

    rows = record_findings(assessment.id, "recon", {"https_redirect": {"redirects_to_https": False}})
    assert titles(rows) == ["HTTP Not Redirected to HTTPS"]
    assert rows[0].severity == "medium"


@pytest.mark.parametrize(
    "days_remaining,expected_title,expected_severity",
    [
        (-3, "TLS Certificate Expired", "critical"),
        (10, "TLS Certificate Expiring Soon", "medium"),
    ],
)
def test_recon_tls_expiry_thresholds(
    assessment, record_findings, days_remaining, expected_title, expected_severity
):
    rows = record_findings(
        assessment.id,
        "recon",
        {"tls": {"valid": True, "days_remaining": days_remaining, "issuer": "Test CA"}},
    )
    assert titles(rows) == [expected_title]
    assert rows[0].severity == expected_severity
    assert "Test CA" in rows[0].description


def test_recon_tls_with_healthy_expiry_and_modern_protocol_is_silent(assessment, record_findings):
    output = {"tls": {"valid": True, "days_remaining": 90, "protocol": "TLSv1.3", "issuer": "Test CA"}}
    assert record_findings(assessment.id, "recon", output) == []


def test_recon_tls_expiry_ignored_when_certificate_is_invalid(assessment, record_findings):
    output = {"tls": {"valid": False, "days_remaining": -1, "error": "verification failed"}}
    assert record_findings(assessment.id, "recon", output) == []


def test_recon_outdated_tls_protocol_reported_independently_of_expiry(assessment, record_findings):
    rows = record_findings(assessment.id, "recon", {"tls": {"protocol": "TLSv1.1"}})
    assert titles(rows) == ["Outdated TLS Protocol: TLSv1.1"]
    assert rows[0].severity == "high"


def test_recon_reports_every_independent_issue_together(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "recon",
        {
            "server": "Apache/2.4.29",
            "https_redirect": {"redirects_to_https": False},
            "tls": {"valid": True, "days_remaining": -1, "protocol": "SSLv3"},
        },
    )
    assert len(rows) == 4


# --- headers -----------------------------------------------------------------


def test_headers_missing_headers_use_the_severity_and_advice_tables(assessment, record_findings):
    rows = record_findings(
        assessment.id, "headers", {"missing": ["Content-Security-Policy", "X-Frame-Options"]}
    )
    csp = by_title(rows, "Content-Security-Policy")
    assert csp.severity == _HEADER_SEVERITY["Content-Security-Policy"] == "medium"
    assert csp.recommendation == _HEADER_RECOMMENDATION["Content-Security-Policy"]
    assert by_title(rows, "X-Frame-Options").severity == "low"


def test_headers_unknown_header_name_falls_back_to_low_and_generic_advice(assessment, record_findings):
    rows = record_findings(assessment.id, "headers", {"missing": ["X-Made-Up-Header"]})
    assert rows[0].severity == "low"
    assert rows[0].recommendation == "Set the 'X-Made-Up-Header' header."


def test_headers_cookie_issues_list_the_missing_flags(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "headers",
        {"cookie_issues": [{"name": "sid", "missing": ["HttpOnly", "Secure"]}]},
    )
    assert titles(rows) == ["Cookie Missing Security Flags: sid"]
    assert "HttpOnly, Secure" in rows[0].description


def test_headers_cors_csp_and_hsts_issues(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "headers",
        {
            "cors_issue": "wildcard origin with credentials",
            "csp_issues": ["Allows 'unsafe-inline'"],
            "hsts_issues": ["max-age=100 is short"],
        },
    )
    assert by_title(rows, "CORS Misconfiguration").severity == "high"
    assert by_title(rows, "CORS Misconfiguration").description == "wildcard origin with credentials"
    assert by_title(rows, "Weak Content-Security-Policy").severity == "medium"
    assert "- Allows 'unsafe-inline'" in by_title(rows, "Weak Content-Security-Policy").description
    assert by_title(rows, "Weak HSTS Policy").severity == "low"


# --- endpoints ---------------------------------------------------------------


def test_endpoints_sensitive_paths_and_api_surfaces(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "endpoints",
        {
            "sensitive_paths_found": [{"path": ".env", "size": 120}],
            "api_surfaces_found": ["swagger.json", "graphql"],
        },
    )
    sensitive = by_title(rows, "Sensitive File Exposed")
    assert sensitive.title == "Sensitive File Exposed: /.env"
    assert sensitive.severity == "high"
    assert "120 bytes" in sensitive.description

    api = by_title(rows, "API/Docs Surface Exposed")
    assert api.severity == "info"
    assert "- /swagger.json" in api.description and "- /graphql" in api.description


def test_endpoints_directory_listing(assessment, record_findings):
    rows = record_findings(assessment.id, "endpoints", {"directory_listing": True})
    assert titles(rows) == ["Directory Listing Enabled"]
    assert rows[0].severity == "medium"


def test_endpoints_login_form_without_csrf_is_flagged_plus_auth_summary(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "endpoints",
        {
            "forms": [
                {
                    "action": "http://example.test/login",
                    "has_password_field": True,
                    "has_csrf_token": False,
                    "form_type": "login",
                }
            ]
        },
    )
    csrf = by_title(rows, "Missing CSRF Protection")
    assert csrf.severity == "high"
    summary = by_title(rows, "Authentication Form(s) Detected")
    assert summary.severity == "info"
    assert "no MFA/CAPTCHA markers detected" in summary.description


def test_endpoints_form_with_csrf_mfa_and_captcha_only_yields_the_info_summary(
    assessment, record_findings
):
    rows = record_findings(
        assessment.id,
        "endpoints",
        {
            "forms": [
                {
                    "action": "http://example.test/login",
                    "has_password_field": True,
                    "has_csrf_token": True,
                    "has_mfa_field": True,
                    "has_captcha": True,
                    "form_type": "login",
                }
            ]
        },
    )
    assert titles(rows) == ["Authentication Form(s) Detected"]
    assert "MFA/OTP field present" in rows[0].description
    assert "CAPTCHA present" in rows[0].description


def test_endpoints_forms_without_password_field_are_ignored(assessment, record_findings):
    output = {"forms": [{"action": "http://example.test/search", "has_password_field": False}]}
    assert record_findings(assessment.id, "endpoints", output) == []


def test_endpoints_external_auth_providers_are_informational(assessment, record_findings):
    rows = record_findings(assessment.id, "endpoints", {"external_auth_providers": ["Google"]})
    assert titles(rows) == ["Third-Party Authentication Used: Google"]
    assert rows[0].severity == "info"


def test_endpoints_surface_map_counts_all_links_but_lists_at_most_25(assessment, record_findings):
    links = [f"http://example.test/p{i}" for i in range(30)]
    rows = record_findings(assessment.id, "endpoints", {"links": links})
    assert rows[0].title == "Application Surface Mapped: 30 page(s) discovered"
    assert rows[0].description.count("- http") == 25


# --- fingerprint -------------------------------------------------------------


def test_fingerprint_technologies_are_summarised_into_one_info_finding(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "fingerprint",
        {
            "technologies": [
                {"name": "Nginx", "category": "webserver", "confidence": "confirmed",
                 "evidence": ["header Server: nginx"]},
                {"name": "React", "category": "js-framework", "evidence": ["body contains 'react-dom'"]},
            ]
        },
    )
    assert titles(rows) == ["Technology Stack Identified: Nginx, React"]
    assert rows[0].severity == "info"
    assert "Nginx (webserver, confirmed)" in rows[0].description
    assert "React (js-framework, likely)" in rows[0].description


def test_fingerprint_without_detections_records_nothing(assessment, record_findings):
    assert record_findings(assessment.id, "fingerprint", {"technologies": []}) == []


# --- javascript --------------------------------------------------------------


def test_javascript_secrets_keep_their_own_severity_and_stay_masked(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "javascript",
        {
            "secrets_found": [
                {"type": "AWS Access Key ID", "severity": "critical",
                 "source": "http://example.test/a.js", "masked_value": "AKIAAB...WXYZ"},
                {"type": "Generic hardcoded secret/token", "severity": "medium",
                 "source": "(inline)", "masked_value": "***"},
            ]
        },
    )
    aws = by_title(rows, "AWS Access Key ID")
    assert aws.severity == "critical"
    assert "AKIAAB...WXYZ" in aws.description
    assert by_title(rows, "Generic hardcoded secret/token").severity == "medium"


def test_javascript_source_maps_internal_urls_sinks_and_outdated_libs(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "javascript",
        {
            "exposed_source_maps": ["http://example.test/app.js.map"],
            "internal_urls_found": ["http://staging.internal/api"],
            "risky_sinks": [
                {"source": "a.js", "sink": "eval()"},
                {"source": "b.js", "sink": "eval()"},
                {"source": "b.js", "sink": "document.write()"},
            ],
            "outdated_libraries": [
                {"name": "jQuery", "version": "1.12.4", "source": "a.js", "note": "known XSS issues."}
            ],
        },
    )
    assert by_title(rows, "Source Maps Exposed").title == "Source Maps Exposed: 1 file(s)"
    assert by_title(rows, "Internal/Staging URLs Leaked").severity == "medium"
    sinks = by_title(rows, "Risky JS Sink(s)")
    assert sinks.title == "Risky JS Sink(s) In Use: document.write(), eval()", "sinks deduped and sorted"
    lib = by_title(rows, "Outdated Library")
    assert lib.title == "Outdated Library: jQuery 1.12.4"
    assert lib.severity == "medium"


def test_javascript_long_lists_are_truncated_in_descriptions(assessment, record_findings):
    maps = [f"http://example.test/{i}.js.map" for i in range(12)]
    internal = [f"http://host{i}.internal/" for i in range(12)]
    rows = record_findings(
        assessment.id,
        "javascript",
        {"exposed_source_maps": maps, "internal_urls_found": internal},
    )
    assert by_title(rows, "Source Maps Exposed").title == "Source Maps Exposed: 12 file(s)"
    assert by_title(rows, "Source Maps Exposed").description.count("- http") == 10
    assert by_title(rows, "Internal/Staging URLs Leaked").description.count("- http") == 10


# --- vulnerabilities ---------------------------------------------------------


def test_vulnerabilities_dangerous_methods(assessment, record_findings):
    rows = record_findings(assessment.id, "vulnerabilities", {"dangerous_methods": ["PUT", "TRACE"]})
    assert titles(rows) == ["Dangerous HTTP Methods Enabled: PUT, TRACE"]
    assert rows[0].severity == "medium"


def test_vulnerabilities_probe_results_map_to_expected_severities(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "vulnerabilities",
        {
            "reflected_params": [{"url": "http://example.test/?q=1", "param": "q"}],
            "sqli_indicators": [{"url": "http://example.test/?id=1", "param": "id"}],
            "open_redirects": [
                {"url": "http://example.test/?next=/", "param": "next",
                 "location": "https://evil.invalid/"}
            ],
        },
    )
    assert by_title(rows, "Reflected Parameter").severity == "high"
    assert by_title(rows, "Possible SQL Injection").severity == "critical"
    redirect = by_title(rows, "Open Redirect")
    assert redirect.severity == "medium"
    assert "https://evil.invalid/" in redirect.description


# --- cve ---------------------------------------------------------------------


def test_cve_matches_carry_advisory_severity_and_detection_source(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "cve",
        {
            "matches": [
                {"id": "GHSA-1234", "package": "werkzeug", "version": "2.0.1", "severity": "high",
                 "summary": "Cookie parsing issue.", "source_field": "recon Server header"}
            ]
        },
    )
    assert titles(rows) == ["Known Vulnerability: GHSA-1234 in werkzeug 2.0.1"]
    assert rows[0].severity == "high"
    assert "Cookie parsing issue." in rows[0].description
    assert "Detected via: recon Server header" in rows[0].description


def test_cve_match_without_summary_gets_a_generated_description(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "cve",
        {"matches": [{"id": "GHSA-9", "package": "jquery", "version": "1.12.4",
                      "severity": "medium", "summary": "", "source_field": "javascript module"}]},
    )
    assert "jquery 1.12.4 matches a known advisory (GHSA-9)." in rows[0].description


# --- active_scan -------------------------------------------------------------


def test_active_scan_nuclei_findings_are_attributed_to_the_tool(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "active_scan",
        {
            "nuclei_findings": [
                {"template_id": "tech-detect", "name": "Tech Detect", "severity": "info",
                 "matched_at": "http://example.test/", "description": "detected"},
                {"template_id": "only-id"},
            ]
        },
    )
    named = by_title(rows, "Tech Detect")
    assert named.source_modules == "active_scan:nuclei"
    assert "Template: tech-detect" in named.description
    fallback = by_title(rows, "only-id")
    assert fallback.title == "[Nuclei] only-id", "falls back to the template id when name is absent"
    assert fallback.severity == "info"


def test_active_scan_sqlmap_findings_are_critical(assessment, record_findings):
    rows = record_findings(
        assessment.id,
        "active_scan",
        {"sqlmap_findings": [{"param": "id", "location": "GET", "injection_type": "boolean-based blind"}]},
    )
    assert titles(rows) == ["[sqlmap] Possible SQL Injection: id"]
    assert rows[0].severity == "critical"
    assert rows[0].source_modules == "active_scan:sqlmap"
    assert "boolean-based blind" in rows[0].description
