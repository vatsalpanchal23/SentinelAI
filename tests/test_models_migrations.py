"""Coverage for database.models.ensure_schema_migrations, which back-fills
columns added after a database file was first created."""

import sqlite3

from sqlalchemy import inspect

from app import create_app
from database.models import db, ensure_schema_migrations

LEGACY_SCHEMA = """
CREATE TABLE assessments (
    id INTEGER NOT NULL PRIMARY KEY,
    target_url VARCHAR(512) NOT NULL,
    status VARCHAR(32),
    progress INTEGER,
    created_at DATETIME,
    completed_at DATETIME,
    report_path VARCHAR(512)
);
"""


def test_missing_columns_are_added_to_a_pre_existing_table(config_class, tmp_path):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(LEGACY_SCHEMA)
        conn.execute("INSERT INTO assessments (target_url) VALUES ('http://old.test')")

    config_class.SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
    app = create_app(config_class)

    with app.app_context():
        columns = {c["name"] for c in inspect(db.engine).get_columns("assessments")}
        assert {"authorized", "active_scan_enabled"} <= columns

        from database.models import Assessment

        preserved = Assessment.query.one()
        assert preserved.target_url == "http://old.test"
        assert preserved.authorized is False and preserved.active_scan_enabled is False


def test_a_current_schema_is_left_alone(app):
    before = {c["name"] for c in inspect(db.engine).get_columns("assessments")}
    ensure_schema_migrations()
    assert {c["name"] for c in inspect(db.engine).get_columns("assessments")} == before


def test_migration_is_a_no_op_when_the_table_does_not_exist_yet(app):
    db.drop_all()
    ensure_schema_migrations()
    assert "assessments" not in inspect(db.engine).get_table_names()
