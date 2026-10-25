"""TrustVault: secure document sharing with a hash-chained audit trail."""
import os

from flask import Flask, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import load_config

csrf = CSRFProtect()


def _require_secret(app, name):
    # SECRET_KEY signs the session cookie: anyone who knows it can forge a
    # cookie for any user. AUDIT_KEY signs the audit chain: anyone who knows it
    # can rewrite history undetected. So neither has a default that could end
    # up on GitHub, and the app won't start with a missing or weak one.
    if len(app.config.get(name) or "") < 32:
        raise RuntimeError(
            f"{name} is missing or shorter than 32 characters. "
            "Copy .env.example to .env and generate one with:\n"
            '  python -c "import secrets; print(secrets.token_hex(32))"'
        )


def create_app(test_config=None):
    """Application factory. Tests call this with their own config."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(load_config())
    if test_config:
        app.config.update(test_config)
    _require_secret(app, "SECRET_KEY")
    _require_secret(app, "AUDIT_KEY")

    # instance/ sits outside the package, so nothing in it is ever served as a
    # static file. The database and uploaded files live here.
    os.makedirs(app.instance_path, exist_ok=True)
    if not app.config["DATABASE"]:
        app.config["DATABASE"] = os.path.join(app.instance_path, "trustvault.sqlite3")
    if not app.config["UPLOAD_DIR"]:
        app.config["UPLOAD_DIR"] = os.path.join(app.instance_path, "uploads")

    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    from . import audit_views, auth, cli, db, documents, errors, filters, security_headers

    db.init_app(app)
    # Every POST, PUT, PATCH and DELETE must carry the session's CSRF token, or
    # it is rejected with 400 before the view runs.
    csrf.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(documents.bp)
    app.register_blueprint(audit_views.bp)
    errors.register(app)
    filters.register(app)
    security_headers.register(app)
    cli.register(app)

    @app.get("/")
    def index():
        return redirect(url_for("documents.index"))

    return app
