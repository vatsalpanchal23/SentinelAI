import json
import logging
import os
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, current_app, Response, stream_with_context, send_file

from database.models import db, Assessment
from planner.planner import plan_assessment
from extensions import limiter
from scoring import compute_risk, SEVERITIES
from targets import target_address_error
import worker

dashboard_bp = Blueprint(
    "dashboard", __name__, template_folder="templates"
)

logger = logging.getLogger("sentinelai.dashboard")

_DUPLICATE_WINDOW_MINUTES = 5


def _validate_target_url(raw: str) -> str | None:
    """Returns an error message if the URL is unusable, else None."""
    if not raw:
        return "Target URL is required."
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return "Target URL must start with http:// or https://."
    if not parsed.netloc:
        return "Target URL must include a host (e.g. http://localhost:3000)."
    return target_address_error(
        raw, allow_private=current_app.config.get("ALLOW_PRIVATE_TARGETS", False)
    )


@dashboard_bp.route("/")
def index():
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    return render_template("dashboard.html", assessments=assessments)


@dashboard_bp.route("/target", methods=["GET", "POST"])
@limiter.limit("10/minute", methods=["POST"])
def target():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        authorized = request.form.get("authorized") == "1"
        active_scan_enabled = request.form.get("active_scan_enabled") == "1"

        error = _validate_target_url(target_url)
        if not error and not authorized:
            error = "You must confirm you own or are authorized to test this target before it can run."
        if error:
            return render_template(
                "target.html", error=error, target_url=target_url,
                authorized=authorized, active_scan_enabled=active_scan_enabled,
            )

        cutoff = datetime.utcnow() - timedelta(minutes=_DUPLICATE_WINDOW_MINUTES)
        recent_duplicate = (
            Assessment.query.filter(
                Assessment.target_url == target_url, Assessment.created_at >= cutoff
            )
            .order_by(Assessment.created_at.desc())
            .first()
        )
        if recent_duplicate and request.form.get("confirm_duplicate") != "1":
            return render_template(
                "target.html",
                target_url=target_url,
                duplicate_of=recent_duplicate,
                authorized=authorized,
                active_scan_enabled=active_scan_enabled,
            )

        assessment = Assessment(
            target_url=target_url, status="pending",
            authorized=authorized, active_scan_enabled=active_scan_enabled,
        )
        db.session.add(assessment)
        db.session.commit()

        try:
            plan_assessment(assessment.id, active_scan_enabled=active_scan_enabled)
            worker.submit_assessment_job(current_app._get_current_object(), assessment.id)
        except Exception:
            # Without this the row stays "pending" forever and the submitter
            # only sees a generic 500 with no idea the scan never started.
            logger.exception("assessment %s: could not be queued", assessment.id)
            db.session.rollback()
            assessment.status = "failed"
            db.session.commit()
            return render_template(
                "target.html",
                error="The assessment could not be queued -- see the server log for details.",
                target_url=target_url, authorized=authorized,
                active_scan_enabled=active_scan_enabled,
            ), 500

        return redirect(url_for("dashboard.assessment_detail", assessment_id=assessment.id))

    return render_template("target.html")


_SEVERITY_ORDER = {sev: i for i, sev in enumerate(SEVERITIES)}


@dashboard_bp.route("/assessment/<int:assessment_id>")
def assessment_detail(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)

    counts, risk_score = compute_risk(assessment.findings)
    sorted_findings = sorted(assessment.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    return render_template(
        "assessment.html", assessment=assessment, severity_counts=counts, risk_score=risk_score,
        sorted_findings=sorted_findings,
    )


@dashboard_bp.route("/assessment/<int:assessment_id>/report")
def assessment_report(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    if not assessment.report_path:
        return "Report not generated yet -- it's produced once the assessment finishes.", 404

    # Only ever serve out of REPORTS_DIR, so a report_path that somehow ends up
    # pointing elsewhere can't turn this route into arbitrary file read.
    reports_dir = os.path.realpath(current_app.config["REPORTS_DIR"])
    path = os.path.realpath(assessment.report_path)
    if os.path.commonpath([reports_dir, path]) != reports_dir or not os.path.isfile(path):
        return "Report not generated yet -- it's produced once the assessment finishes.", 404
    return send_file(path, mimetype="text/html")


def _serialize_status(assessment: Assessment) -> dict:
    counts, risk_score = compute_risk(assessment.findings)

    def _duration(m):
        if m.started_at is None:
            return None
        end = m.finished_at or datetime.utcnow()
        return round((end - m.started_at).total_seconds(), 1)

    return {
        "id": assessment.id,
        "status": assessment.status,
        "progress": assessment.progress,
        "report_available": bool(assessment.report_path),
        "modules": [
            {
                "name": m.name,
                "status": m.status,
                "duration_seconds": _duration(m),
                "failure_reason": (m.raw_output or "").splitlines()[-1] if m.status == "failed" else None,
                "errors": (m.errors or "").splitlines(),
            }
            for m in assessment.modules
        ],
        "severity_counts": counts,
        "risk_score": risk_score,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "source_modules": f.source_modules,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in sorted(assessment.findings, key=lambda x: x.id)
        ],
    }


@dashboard_bp.route("/api/assessment/<int:assessment_id>/status")
def assessment_status(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    return jsonify(_serialize_status(assessment))


@dashboard_bp.route("/api/assessment/<int:assessment_id>/stream")
def assessment_stream(assessment_id):
    """Server-Sent Events stream: pushes status/findings updates to the
    browser instead of the client re-polling every 2s. One request stays
    open per open dashboard tab; the server still checks the DB on an
    interval internally, but the client only re-renders on actual pushes
    and doesn't need to manage its own retry/backoff loop -- EventSource
    reconnects automatically on drop."""
    app_obj = current_app._get_current_object()

    def _events():
        last_payload = None
        # Bound the connection so a stuck browser tab doesn't hold a worker
        # thread open forever; EventSource reconnects transparently on close.
        for _ in range(300):  # ~10 minutes at 2s ticks
            try:
                with app_obj.app_context():
                    assessment = Assessment.query.get(assessment_id)
                    if assessment is None:
                        yield 'event: error\ndata: {"error": "not found"}\n\n'
                        return
                    payload = _serialize_status(assessment)
                    finished = assessment.status in ("completed", "failed")
                encoded = json.dumps(payload)
            except Exception:
                # An exception inside a streaming generator is invisible: Flask
                # has already sent 200 OK, so the client just sees the stream
                # go quiet. Log it and tell the browser explicitly.
                logger.exception("assessment %s: status stream failed", assessment_id)
                yield 'event: error\ndata: {"error": "status stream failed"}\n\n'
                return

            if encoded != last_payload:
                yield f"data: {encoded}\n\n"
                last_payload = encoded
            else:
                yield ": keep-alive\n\n"

            if finished:
                return
            time.sleep(2)

    return Response(
        stream_with_context(_events()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
