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


def _flag(key: str, default: bool) -> bool:
    value = os.environ.get(key)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env(key: str, default: str) -> str:
    """os.environ.get(key, default) treats an empty string as 'set', so a
    blank line in .env (e.g. DATABASE_URL=) silently wins over the default
    instead of falling back to it. Treat blank/whitespace-only as unset."""
    value = os.environ.get(key)
    return value if value and value.strip() else default


DEFAULT_DEV_SECRET_KEY = "dev-secret-change-me"


class Config:
    SECRET_KEY = _env("SECRET_KEY", DEFAULT_DEV_SECRET_KEY)

    # Serving/auth posture. Debug is off and binding is loopback-only unless
    # explicitly changed: Werkzeug's debugger exposes an interactive Python
    # console to anyone who can reach it.
    DEBUG = _flag("FLASK_DEBUG", False)
    HOST = _env("HOST", "127.0.0.1")
    PORT = int(_env("PORT", "5000"))

    AUTH_USERNAME = _env("AUTH_USERNAME", "sentinel")
    AUTH_PASSWORD_HASH = _env("AUTH_PASSWORD_HASH", "")
    AUTH_PASSWORD = _env("AUTH_PASSWORD", "")

    # Scanning a loopback/RFC1918 target is an opt-in: without it the app
    # would happily fetch internal-only services on this host's behalf.
    ALLOW_PRIVATE_TARGETS = _flag("ALLOW_PRIVATE_TARGETS", False)

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

    AI_ANALYSIS_ENABLED = _flag("AI_ANALYSIS_ENABLED", True)
