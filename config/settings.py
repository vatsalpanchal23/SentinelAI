import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Load .env explicitly from BASE_DIR rather than relying on find_dotenv()'s
# cwd-based search. find_dotenv() walks up from the *current working
# directory*, which is not guaranteed to stay the same between the initial
# process and the one Werkzeug's debug reloader spawns -- that mismatch is
# what caused DATABASE_URL (and everything else in .env) to be picked up
# inconsistently between the first run and post-reload runs.
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _env(key: str, default: str) -> str:
    """os.environ.get(key, default) treats an empty string as 'set', so a
    blank line in .env (e.g. DATABASE_URL=) silently wins over the default
    instead of falling back to it. Treat blank/whitespace-only as unset."""
    value = os.environ.get(key)
    return value if value and value.strip() else default


class Config:
    SECRET_KEY = _env("SECRET_KEY", "dev-secret-change-me")

    SQLALCHEMY_DATABASE_URI = _env(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'database', 'sentinelai.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # module pipeline runs on background threads; SQLite connections must allow that
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}

    EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

    # AI backend: "ollama" | "gemini" | "deepseek" | "kimi"
    AI_PROVIDER = _env("AI_PROVIDER", "ollama")
    OLLAMA_HOST = _env("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL = _env("OLLAMA_MODEL", "qwen3")

    GEMINI_API_KEY = _env("GEMINI_API_KEY", "")

    AI_ANALYSIS_ENABLED = _env("AI_ANALYSIS_ENABLED", "true").strip().lower() == "true"
