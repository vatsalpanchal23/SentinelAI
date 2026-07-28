"""
Shared Flask extension instances.

Kept in their own module (rather than defined in app.py) so blueprints like
dashboard/routes.py can import them (e.g. to apply @limiter.limit(...) to a
route) without creating an app.py <-> routes.py circular import.
"""

from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
