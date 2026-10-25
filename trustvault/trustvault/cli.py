"""Command-line tools. There is no web page that changes roles; an admin is
made from the server's shell:

    flask --app app set-role <username> admin
"""
import click
from flask.cli import with_appcontext

from . import audit
from .db import transaction


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


def register(app):
    app.cli.add_command(set_role)
