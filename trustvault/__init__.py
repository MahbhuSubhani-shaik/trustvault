"""TrustVault: secure document sharing with a hash-chained audit trail."""
import os

from flask import Flask, redirect, url_for

from .config import load_config


def create_app(test_config=None):
    """Application factory. Tests call this with their own config."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(load_config())
    if test_config:
        app.config.update(test_config)

    # The session cookie is signed with SECRET_KEY. Anyone who knows the key can
    # forge a cookie for any user, so refuse to start with a missing or weak one
    # instead of falling back to a default that ends up on GitHub.
    if len(app.config.get("SECRET_KEY") or "") < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or shorter than 32 characters. "
            "Copy .env.example to .env and generate one with:\n"
            '  python -c "import secrets; print(secrets.token_hex(32))"'
        )

    # instance/ sits outside the package, so nothing in it is ever served as a
    # static file. The database and uploaded files will live here.
    os.makedirs(app.instance_path, exist_ok=True)

    from . import documents, errors, security_headers

    app.register_blueprint(documents.bp)
    errors.register(app)
    security_headers.register(app)

    @app.get("/")
    def index():
        return redirect(url_for("documents.index"))

    return app
