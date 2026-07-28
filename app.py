import logging
import os

from flask import Flask

from config.settings import Config
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

    if app.config["SECRET_KEY"] == "dev-secret-change-me":
        logger.warning(
            "Using the default SECRET_KEY. Fine for local dev, but set SECRET_KEY in "
            ".env before this ever runs anywhere reachable by anyone else."
        )

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Discover scanner plugins during startup so import/metadata errors surface
    # early while preserving a lightweight worker entry point.
    worker.get_registry()

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


if __name__ == "__main__":
    app = create_app()
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    port = int(os.environ.get("PORT", "5000"))
    if not debug_mode:
        logger.info("Starting with debug=False (FLASK_DEBUG=0) -- werkzeug's reloader is off.")
    app.run(debug=debug_mode, host="0.0.0.0", port=port)
