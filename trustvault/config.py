"""Settings read from environment variables. See .env.example."""
import os
from datetime import timedelta

from .files import MAX_FILE_SIZE

SESSION_LIFETIME = timedelta(hours=8)


def _flag(name, default):
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes"}


def load_config():
    return {
        "SECRET_KEY": os.environ.get("SECRET_KEY", ""),
        # Key for the audit log's HMAC chain. Kept separate from SECRET_KEY so
        # rotating the session key never invalidates old audit entries.
        "AUDIT_KEY": os.environ.get("AUDIT_KEY", ""),
        # Empty means instance/trustvault.sqlite3 and instance/uploads (filled
        # in by create_app). Both are outside the static folder.
        "DATABASE": os.environ.get("DATABASE_PATH", ""),
        "UPLOAD_DIR": os.environ.get("UPLOAD_DIR", ""),
        # Flask rejects any request body bigger than this with 413 before the
        # view reads it. The extra 64 KB is room for the form around the file.
        "MAX_CONTENT_LENGTH": MAX_FILE_SIZE + 64 * 1024,
        # The session cookie is signed, not encrypted: the user can read it, so
        # it only ever holds an ID, never anything secret.
        "SESSION_COOKIE_HTTPONLY": True,  # JavaScript can't read it, so XSS can't steal it
        "SESSION_COOKIE_SAMESITE": "Lax",  # not sent on cross-site POSTs
        # Secure by default; only a local http:// setup should turn this off.
        "SESSION_COOKIE_SECURE": _flag("SESSION_COOKIE_SECURE", "1"),
        "PERMANENT_SESSION_LIFETIME": SESSION_LIFETIME,
        # CSRF tokens last as long as a session instead of Flask-WTF's default
        # hour, so a form left open doesn't fail. They are still tied to it.
        "WTF_CSRF_TIME_LIMIT": int(SESSION_LIFETIME.total_seconds()),
        # Only behind a proxy that sets X-Forwarded-For (PythonAnywhere, Render).
        # Without one, trusting that header would let anyone fake their IP in
        # the audit log.
        "TRUST_PROXY": _flag("TRUST_PROXY", "0"),
        # Optional: create this admin account at startup (see cli.py). For hosts
        # with no shell, such as Render's free plan.
        "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", ""),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", ""),
        "ADMIN_EMAIL": os.environ.get("ADMIN_EMAIL", ""),
    }
