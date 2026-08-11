from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Assessment(db.Model):
    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(512), nullable=False)
    status = db.Column(db.String(32), default="pending")  # pending|running|completed|failed
    progress = db.Column(db.Integer, default=0)  # 0-100
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    report_path = db.Column(db.String(512), nullable=True)
    # required confirmation that the submitter owns/is authorized to test target_url --
    # gates every module that sends anything beyond a plain GET (sensitive-path
    # guessing, XSS/SQLi/redirect probes). Enforced at submission in routes.py.
    authorized = db.Column(db.Boolean, default=False, nullable=False)
    # separate opt-in for the heavier active_scan module (Nuclei/sqlmap) --
    # distinct from `authorized` because it's meaningfully more intrusive
    # (many more requests, longer-running, third-party tool output).
    active_scan_enabled = db.Column(db.Boolean, default=False, nullable=False)

    modules = db.relationship("ModuleRun", backref="assessment", lazy=True)
    findings = db.relationship("Finding", backref="assessment", lazy=True)


class ModuleRun(db.Model):
    __tablename__ = "module_runs"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    name = db.Column(db.String(64), nullable=False)  # recon|fingerprint|endpoints|...
    status = db.Column(db.String(32), default="pending")
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    # newline-separated non-fatal problems the module reported while still
    # completing (failed requests, unparsable HTML, missing external tools) --
    # kept separate from raw_output so the UI/API can surface them.
    errors = db.Column(db.Text, nullable=True)


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(16), default="info")  # info|low|medium|high|critical
    description = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)
    source_modules = db.Column(db.String(256), nullable=True)  # e.g. "nikto,nuclei,headers"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    evidence = db.relationship("Evidence", backref="finding", lazy=True)


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("findings.id"), nullable=False)
    type = db.Column(db.String(32), default="text")  # text|screenshot|response|log
    file_path = db.Column(db.String(512), nullable=True)
    content = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def ensure_schema_migrations():
    """db.create_all() only creates missing *tables*, not missing *columns* on
    tables that already exist -- so an existing sentinelai.db from before the
    authorized/active_scan_enabled columns were added would otherwise 500 on
    first write. Full Flask-Migrate is overkill for a single-dev v1 project;
    this just adds any columns that are missing. Must run inside an app context,
    after db.create_all()."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()

    if "assessments" in table_names:
        existing_cols = {c["name"] for c in inspector.get_columns("assessments")}
        with db.engine.begin() as conn:
            if "authorized" not in existing_cols:
                conn.execute(text("ALTER TABLE assessments ADD COLUMN authorized BOOLEAN DEFAULT 0"))
            if "active_scan_enabled" not in existing_cols:
                conn.execute(text("ALTER TABLE assessments ADD COLUMN active_scan_enabled BOOLEAN DEFAULT 0"))

    if "module_runs" in table_names:
        existing_cols = {c["name"] for c in inspector.get_columns("module_runs")}
        with db.engine.begin() as conn:
            if "errors" not in existing_cols:
                conn.execute(text("ALTER TABLE module_runs ADD COLUMN errors TEXT"))
