from app import create_app
from database.models import Assessment, ModuleRun, db
from planner.planner import plan_assessment
import worker


def test_app_factory_and_worker_registry(tmp_path):
    class TestConfig:
        SECRET_KEY = "test"
        TESTING = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
        EVIDENCE_DIR = str(tmp_path / "evidence")
        REPORTS_DIR = str(tmp_path / "reports")
        AI_ANALYSIS_ENABLED = False
        AI_PROVIDER = "ollama"
        OLLAMA_HOST = "http://localhost:11434"
        OLLAMA_MODEL = "qwen3"

    app = create_app(TestConfig)
    assert app is not None
    assert worker.get_registry().get("recon") is not None

    with app.app_context():
        assessment = Assessment(target_url="http://example.test", authorized=True)
        db.session.add(assessment)
        db.session.commit()
        pipeline = plan_assessment(assessment.id, active_scan_enabled=False)
        assert pipeline[-1] == "reporting"
        assert ModuleRun.query.filter_by(assessment_id=assessment.id).count() == len(pipeline)
