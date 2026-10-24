"""Dashboard: a summary of the signed-in user's own documents and activity.

Every number here is about g.user only. Each query filters on the user's id,
or on documents they own, using the same rules as the documents list and the
audit page, so the dashboard can never show something those pages wouldn't.
"""
from datetime import timedelta

from flask import Blueprint, g, render_template

from .access import active_share_sql
from .auth import login_required
from .db import get_db
from .timeutil import now, now_db, to_db

bp = Blueprint("dashboard", __name__)


@bp.get("/dashboard")
@login_required
def index():
    db = get_db()
    params = {"me": g.user["id"], "now": now_db(), "since": to_db(now() - timedelta(days=7))}

    def count(sql):
        return db.execute(sql, params).fetchone()[0]

    stats = {
        "owned": count("SELECT COUNT(*) FROM documents WHERE owner_id = :me"),
        "shared_with_me": count(
            "SELECT COUNT(*) FROM shares s WHERE s.grantee_id = :me AND " + active_share_sql("s")),
        "people": count(
            "SELECT COUNT(DISTINCT s.grantee_id) FROM shares s"
            " JOIN documents d ON d.id = s.document_id"
            " WHERE d.owner_id = :me AND " + active_share_sql("s")),
        # Refused requests on the user's documents, plus wrong passwords
        # against their account, in the last week.
        "blocked": count(
            "SELECT COUNT(*) FROM audit_log WHERE owner_id = :me AND created_at >= :since"
            " AND action IN ('access.denied', 'auth.login_failed')"),
    }
    recent = db.execute(
        "SELECT * FROM audit_log WHERE owner_id = :me ORDER BY id DESC LIMIT 8", params
    ).fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent)
