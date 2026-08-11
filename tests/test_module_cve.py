"""Coverage for modules.cve: which packages get queried, OSV response
handling, and severity normalisation across OSV's inconsistent formats."""

import pytest
import requests

from conftest import FakeResponse
from modules.cve import cve as cve_module

TARGET = "http://example.test/"


def osv(vulns):
    return FakeResponse(url=cve_module.OSV_ENDPOINT, json_data={"vulns": vulns})


def test_no_identifiable_packages_means_no_requests(fake_http):
    fake = fake_http(cve_module, {})
    result = cve_module.run(TARGET, context={"recon": {"server": "nginx/1.18.0"}})
    assert result["matches"] == [] and result["errors"] == []
    assert fake.calls == [], "generic web servers are deliberately not queried"


def test_run_without_context_is_safe(fake_http):
    fake = fake_http(cve_module, {})
    assert cve_module.run(TARGET)["matches"] == []
    assert fake.calls == []


def test_werkzeug_version_from_the_server_header_is_queried(fake_http):
    fake_http(cve_module, {cve_module.OSV_ENDPOINT: osv([
        {"id": "GHSA-abc", "summary": "Cookie parsing issue",
         "database_specific": {"severity": "HIGH"}},
    ])})
    context = {"recon": {"server": "Werkzeug/2.0.1 Python/3.10.6"}}
    matches = cve_module.run(TARGET, context=context)["matches"]
    assert matches == [
        {
            "package": "werkzeug",
            "version": "2.0.1",
            "ecosystem": "PyPI",
            "id": "GHSA-abc",
            "summary": "Cookie parsing issue",
            "severity": "high",
            "source_field": "recon Server header: Werkzeug/2.0.1 Python/3.10.6",
        }
    ]


def test_outdated_jquery_from_the_javascript_module_is_queried(fake_http):
    fake_http(cve_module, {cve_module.OSV_ENDPOINT: osv([{"id": "GHSA-jq", "details": "XSS in $()"}])})
    context = {
        "javascript": {
            "outdated_libraries": [{"name": "jQuery", "version": "1.12.4", "source": "app.js"}]
        }
    }
    match = cve_module.run(TARGET, context=context)["matches"][0]
    assert (match["package"], match["ecosystem"], match["version"]) == ("jquery", "npm", "1.12.4")
    assert match["summary"] == "XSS in $()", "OSV details are used when summary is absent"
    assert match["source_field"] == "javascript module: app.js"


def test_libraries_without_a_version_or_of_other_names_are_skipped():
    context = {
        "javascript": {
            "outdated_libraries": [
                {"name": "jQuery", "version": "", "source": "app.js"},
                {"name": "lodash", "version": "4.17.0", "source": "app.js"},
            ]
        }
    }
    assert cve_module._identify_packages(context) == []


def test_server_header_without_werkzeug_identifies_nothing():
    assert cve_module._identify_packages({"recon": {"server": "Apache/2.4.29"}}) == []
    assert cve_module._identify_packages({"recon": {}}) == []


def test_two_digit_werkzeug_version_is_matched():
    packages = cve_module._identify_packages({"recon": {"server": "Werkzeug/3.0"}})
    assert packages[0][2] == "3.0"


def test_osv_failure_is_recorded_per_package_without_raising(fake_http):
    fake_http(cve_module, {cve_module.OSV_ENDPOINT: requests.Timeout("timed out")})
    result = cve_module.run(TARGET, context={"recon": {"server": "Werkzeug/2.0.1"}})
    assert result["matches"] == []
    assert result["errors"] == ["OSV lookup failed for werkzeug@2.0.1: timed out"]


def test_osv_http_error_is_recorded(fake_http):
    fake_http(cve_module, {cve_module.OSV_ENDPOINT: FakeResponse(status_code=500)})
    result = cve_module.run(TARGET, context={"recon": {"server": "Werkzeug/2.0.1"}})
    assert result["matches"] == []
    assert any("OSV lookup failed" in e for e in result["errors"])


def test_osv_query_sends_the_package_ecosystem_and_version(fake_http, monkeypatch):
    payloads = []

    class RecordingRequests:
        RequestException = requests.RequestException

        def post(self, url, json=None, timeout=None):
            payloads.append((url, json))
            return osv([])

    monkeypatch.setattr(cve_module, "requests", RecordingRequests())
    assert cve_module._query_osv("werkzeug", "PyPI", "2.0.1") == []
    assert payloads == [
        (cve_module.OSV_ENDPOINT,
         {"package": {"name": "werkzeug", "ecosystem": "PyPI"}, "version": "2.0.1"})
    ]


def test_long_summaries_are_truncated(fake_http):
    fake_http(cve_module, {cve_module.OSV_ENDPOINT: osv([{"id": "X", "summary": "a" * 500}])})
    match = cve_module.run(TARGET, context={"recon": {"server": "Werkzeug/2.0.1"}})["matches"][0]
    assert len(match["summary"]) == 400


@pytest.mark.parametrize(
    "vuln,expected",
    [
        ({"database_specific": {"severity": "CRITICAL"}}, "critical"),
        ({"database_specific": {"severity": "low"}}, "low"),
        ({"database_specific": {"severity": "MODERATE"}}, "medium"),
        ({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}, "critical"),
        ({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}, "high"),
        ({"severity": [{"type": "CVSS_V3", "score": "5.3"}]}, "medium"),
        ({"severity": [{"type": "CVSS_V3", "score": "2.0"}]}, "low"),
        ({"severity": [{"type": "CVSS_V3", "score": "no digits here"}]}, "medium"),
        ({"severity": []}, "medium"),
        ({}, "medium"),
    ],
)
def test_severity_normalisation(vuln, expected):
    assert cve_module._extract_severity(vuln) == expected


def test_cvss_vector_strings_are_read_from_the_leading_number():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}]}
    assert cve_module._extract_severity(vuln) == "low", "3.1 falls in the low band"
