"""
HTTP Basic authentication gate for the whole app.

Every route in this app is sensitive: submitting a target launches
outbound scans from this host, and the assessment views/reports expose
scan results. Auth is configured with AUTH_USERNAME plus either
AUTH_PASSWORD_HASH (preferred, a werkzeug password hash) or AUTH_PASSWORD.

When no credentials are configured the app stays open, which is only
acceptable while it is bound to loopback -- app.py refuses to serve on a
non-loopback interface without credentials.
"""

import hmac

from flask import Response, current_app, request
from werkzeug.security import check_password_hash


def auth_configured(config) -> bool:
    return bool(config.get("AUTH_PASSWORD_HASH") or config.get("AUTH_PASSWORD"))


def _credentials_valid(username: str, password: str) -> bool:
    config = current_app.config
    expected_user = config.get("AUTH_USERNAME") or ""
    user_ok = hmac.compare_digest(username.encode(), expected_user.encode())

    password_hash = config.get("AUTH_PASSWORD_HASH")
    if password_hash:
        password_ok = check_password_hash(password_hash, password)
    else:
        password_ok = hmac.compare_digest(
            password.encode(), (config.get("AUTH_PASSWORD") or "").encode()
        )

    # Evaluate both before returning so a wrong username and a wrong
    # password cost the same amount of work.
    return user_ok and password_ok


def init_app(app) -> None:
    @app.before_request
    def _require_basic_auth():
        if not auth_configured(app.config):
            return None
        if request.endpoint == "static":
            return None

        credentials = request.authorization
        if credentials and credentials.type == "basic" and _credentials_valid(
            credentials.username or "", credentials.password or ""
        ):
            return None

        return Response(
            "Authentication required.",
            401,
            {"WWW-Authenticate": 'Basic realm="SentinelAI"'},
        )
