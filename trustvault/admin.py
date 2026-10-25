"""Admin pages: list users and change roles.

Every route here is wrapped in admin_required, which checks the role read from
the database on this request (g.user), never anything sent by the browser. A
member who opens these URLs gets a 403 that is logged as access.denied.
"""
import functools

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from . import audit
from .access import AccessDenied
from .auth import ROLES, login_required
from .db import get_db, transaction
from .timeutil import now_db

bp = Blueprint("admin", __name__)


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapped(**kwargs):
        if g.user["role"] != "admin":
            raise AccessDenied(None, "open an admin page")
        return view(**kwargs)

    return wrapped


@bp.get("/admin/users")
@admin_required
def users():
    rows = get_db().execute(
        "SELECT u.id, u.username, u.email, u.role, u.created_at, u.locked_until,"
        " (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id) AS documents"
        " FROM users u ORDER BY u.id"
    ).fetchall()
    return render_template("admin_users.html", users=rows, now=now_db())


@bp.post("/admin/users/<int:user_id>/role")
@admin_required
def change_role(user_id):
    role = request.form.get("role", "")
    if role not in ROLES:
        abort(400)
    # An admin can't demote themselves, so the last admin can't lock everyone out.
    if user_id == g.user["id"]:
        flash("You can’t change your own role.", "error")
        return redirect(url_for(".users"))
    with transaction() as db:
        target = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        if target["role"] != role:
            # Bumping session_version signs them out, so the new role applies
            # from their next sign-in.
            db.execute(
                "UPDATE users SET role = ?, session_version = session_version + 1 WHERE id = ?",
                (role, target["id"]),
            )
            audit.record("user.role_change", owner_id=target["id"], target=f"{target['username']} → {role}")
    flash(f"{target['username']} is now {role}. They’ll need to sign in again.", "success")
    return redirect(url_for(".users"))
