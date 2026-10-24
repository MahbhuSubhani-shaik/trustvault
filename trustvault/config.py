"""Settings read from environment variables. See .env.example."""
import os
from datetime import timedelta


def _flag(name, default):
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes"}


def load_config():
    return {
        "SECRET_KEY": os.environ.get("SECRET_KEY", ""),
        # The session cookie is signed, not encrypted: the user can read it, so
        # it only ever holds an ID, never anything secret.
        "SESSION_COOKIE_HTTPONLY": True,  # JavaScript can't read it, so XSS can't steal it
        "SESSION_COOKIE_SAMESITE": "Lax",  # not sent on cross-site POSTs
        # Secure by default; only a local http:// setup should turn this off.
        "SESSION_COOKIE_SECURE": _flag("SESSION_COOKIE_SECURE", "1"),
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
    }
