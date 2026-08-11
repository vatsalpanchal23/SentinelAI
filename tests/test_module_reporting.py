"""Coverage for modules.reporting: report file creation, HTML escaping,
severity grouping, and the optional AI-analysis section."""

import os
from datetime import datetime, timedelta

import pytest

from config.settings import Config
from database.models import Finding, ModuleRun, db
from modules.reporting import reporting


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    directory = tmp_path / "generated-reports"
    monkeypatch.setattr(Config, "REPORTS_DIR", str(directory))
    return directory


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(reporting, "ai_analyze", lambda assessment: None)


def add_findings(assessment, *specs):
    for severity, title in specs:
        db.session.add(
            Finding(assessment_id=assessment.id, title=title, severity=severity,
                    description=f"{title} description", recommendation=f"fix {title}",
                    source_modules="headers")
        )
    db.session.commit()


def generate_html(assessment, reports_dir):
    path = reporting.generate(assessment.id)
    assert os.path.dirname(path) == str(reports_dir)
    assert path.startswith(str(reports_dir / f"assessment_{assessment.id}_"))
    return open(path, encoding="utf-8").read()


def test_unknown_assessment_raises(app, reports_dir):
    with pytest.raises(ValueError, match="No assessment with id 999"):
        reporting.generate(999)


def test_report_without_findings_states_so(app, assessment, reports_dir):
    html = generate_html(assessment, reports_dir)
    assert "No findings were recorded." in html
    assert ">100<" in html, "an empty assessment scores 100"
    assert "AI Analysis" not in html


def test_findings_are_grouped_by_severity_with_counts(app, assessment, reports_dir):
    add_findings(assessment, ("critical", "RCE"), ("low", "Verbose header"), ("low", "Cookie flags"))
    html = generate_html(assessment, reports_dir)
    assert "CRITICAL (1)" in html and "LOW (2)" in html
    assert "HIGH (" not in html, "empty severity groups are omitted"
    assert "fix RCE" in html
    assert ">88<" in html, "10 + 1 + 1 deducted from 100"


def test_finding_content_is_html_escaped(app, assessment, reports_dir):
    db.session.add(
        Finding(assessment_id=assessment.id, title="<script>alert(1)</script>", severity="high",
                description="a & b <b>", recommendation=None, source_modules="javascript")
    )
    db.session.commit()
    html = generate_html(assessment, reports_dir)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "a &amp; b &lt;b&gt;" in html
    assert "Fix:" not in html, "a finding without a recommendation omits the fix block"


def test_module_table_reports_status_and_duration(app, assessment, reports_dir):
    started = datetime(2024, 5, 1, 12, 0, 0)
    db.session.add_all(
        [
            ModuleRun(assessment_id=assessment.id, name="recon", status="completed",
                      started_at=started, finished_at=started + timedelta(seconds=2.5)),
            ModuleRun(assessment_id=assessment.id, name="headers", status="pending"),
        ]
    )
    db.session.commit()
    html = generate_html(assessment, reports_dir)
    assert "<td>recon</td>" in html and "<td>completed</td>" in html
    assert "12:00:00" in html and "2.5s" in html
    assert "<td>-</td>" in html and "<td>-s</td>" in html, "a pending module renders placeholders"


def test_ai_summary_is_included_when_available(app, assessment, reports_dir, monkeypatch):
    add_findings(assessment, ("medium", "Weak CSP"))
    monkeypatch.setattr(reporting, "ai_analyze", lambda a: "Chained risk: <b>CSP</b> plus cookies.")
    html = generate_html(assessment, reports_dir)
    assert "AI Analysis" in html
    assert "Chained risk: &lt;b&gt;CSP&lt;/b&gt; plus cookies." in html


def test_report_directory_is_created_on_demand(app, assessment, reports_dir):
    assert not reports_dir.exists()
    reporting.generate(assessment.id)
    assert reports_dir.is_dir()
