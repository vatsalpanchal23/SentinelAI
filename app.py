import ipaddress
import logging
import secrets

from flask import Flask

import auth
from config.settings import DEFAULT_DEV_SECRET_KEY, Config
from database.models import db
from extensions import csrf, limiter
import worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelai.app")


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_class)

    if app.config["SECRET_KEY"] == DEFAULT_DEV_SECRET_KEY:
        # A known SECRET_KEY lets anyone forge session cookies and CSRF
        # tokens, so the shipped placeholder is never usable as a key. A
        # per-process random key keeps local dev working (at the cost of
        # invalidating sessions on restart) without a guessable secret.
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
        logger.warning(
            "Refusing to use the default SECRET_KEY; generated an ephemeral one for "
            "this process. Sessions and CSRF tokens will not survive a restart -- set "
            "SECRET_KEY in .env."
        )

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    auth.init_app(app)

    # Discover scanner plugins during startup so import/metadata errors surface
    # early while preserving a lightweight worker entry point. The registry
    # collects load failures instead of raising, so they have to be reported
    # here or a module silently disappears from every pipeline.
    registry = worker.get_registry()
    for load_error in registry.errors:
        logger.error(
            "scanner module '%s' failed to load and will be skipped in every assessment: %s",
            load_error.module_name, load_error.error,
        )

    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp)

    @app.after_request
    def _security_headers(response):
        # Baseline headers for the app's own pages -- separate from the
        # target-site header findings the "headers" module reports on.
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline'",
        )
        return response

    with app.app_context():
        db.create_all()
        from database.models import ensure_schema_migrations
        ensure_schema_migrations()

    return app


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "localhost.localdomain")


if __name__ == "__main__":
    app = create_app()
    host = app.config["HOST"]
    debug_mode = app.config["DEBUG"]

    if not _is_loopback(host):
        # Off-loopback the app is reachable by others, so the two things that
        # only hold up behind loopback have to hold for real: no interactive
        # debugger, and credentials on every route.
        if debug_mode:
            raise SystemExit(
                f"Refusing to serve on {host} with FLASK_DEBUG enabled: Werkzeug's "
                "debugger allows arbitrary code execution by anyone who can reach it."
            )
        if not auth.auth_configured(app.config):
            raise SystemExit(
                f"Refusing to serve on {host} without authentication: set "
                "AUTH_PASSWORD_HASH (or AUTH_PASSWORD) so scan submission and "
                "assessment results are not world-readable."
            )

    if not auth.auth_configured(app.config):
        logger.warning(
            "No AUTH_PASSWORD_HASH/AUTH_PASSWORD configured -- every route is open "
            "to anyone who can reach %s.",
            host,
        )

    app.run(debug=debug_mode, host=host, port=app.config["PORT"])
