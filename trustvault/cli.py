"""Making admins. There is no web page that changes roles. An admin is made
by whoever controls the server, in one of two ways:

    flask --app app set-role <username> admin      (from the server's shell)

or, on hosts without a shell (Render's free plan), by setting ADMIN_USERNAME,
ADMIN_PASSWORD and optionally ADMIN_EMAIL in the host's environment: the
account is then created as an admin when the app starts.
"""
import sqlite3

import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

from . import audit
from .db import get_db, transaction
from .timeutil import now_db


@click.command("set-role")
@click.argument("username")
@click.argument("role", type=click.Choice(["member", "admin"]))
@with_appcontext
def set_role(username, role):
    """Give USERNAME the member or admin role."""
    with transaction() as db:
        user = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            raise click.ClickException(f"No user called {username!r}.")
        # Bumping session_version signs the user out, so the new role applies
        # from their next sign-in rather than to a session they already hold.
        db.execute(
            "UPDATE users SET role = ?, session_version = session_version + 1 WHERE id = ?",
            (role, user["id"]),
        )
        audit.record("user.role_change", actor_name="cli", owner_id=user["id"],
                     target=f"{user['username']} → {role}")
    click.echo(f"{user['username']} is now {role}.")


def ensure_admin_from_config(app):
    """Create the admin account named in the environment, if it's missing.

    This runs at startup, before the app takes any requests, so a visitor
    can't register that username first. It never promotes an account that
    already exists: if someone else holds the name, they stay a member.
    """
    username = app.config.get("ADMIN_USERNAME", "").strip()
    password = app.config.get("ADMIN_PASSWORD", "")
    if not username:
        return
    from .auth import validate_registration  # here, to avoid a circular import

    email = (app.config.get("ADMIN_EMAIL") or f"{username}@admin.trustvault").strip().lower()
    problems = validate_registration(username, email, password, password)
    if problems:
        app.logger.warning("ADMIN_USERNAME is set but the admin account was not created: %s",
                           "; ".join(problems.values()))
        return
    with app.app_context():
        existing = get_db().execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
        if existing is not None:
            if existing["role"] != "admin":
                app.logger.warning("ADMIN_USERNAME %r belongs to an existing member; not promoting it.",
                                   username)
            return
        try:
            with transaction() as db:
                cur = db.execute(
                    "INSERT INTO users (username, email, password_hash, role, created_at)"
                    " VALUES (?, ?, ?, 'admin', ?)",
                    (username, email, generate_password_hash(password), now_db()),
                )
                audit.record("user.role_change", actor_name="startup", owner_id=cur.lastrowid,
                             target=f"{username} created as admin from ADMIN_USERNAME")
        except sqlite3.IntegrityError:
            pass  # another worker process created it at the same moment


def register(app):
    app.cli.add_command(set_role)
    ensure_admin_from_config(app)
