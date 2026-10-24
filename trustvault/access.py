"""Authorisation: who may do what with a document.

This is the one place that decides. Every document route starts with

    doc, permission = authorize(doc_id, ACTION)

before it reads a file, shows a page or changes anything. The decision is
made from the database on every request: nothing about access is stored in
the session, so a revoke or an expiry takes effect on the very next request.

Rules, deny by default:
    view      owner, or a share with permission view or download
    download  owner, or a share with permission download
    manage    owner only (share, revoke, delete)

Admins get no extra access to documents. Their only extra power is seeing
the whole audit trail.
"""
from flask import abort, g
from werkzeug.exceptions import Forbidden

from .db import get_db
from .timeutil import now_db

VIEW, DOWNLOAD, MANAGE = "view", "download", "manage"


def active_share_sql(alias):
    """SQL condition for "this share grants access right now". Needs :now bound.

    Revoked or past its expiry means no access. Every query that decides
    access through a share uses this one condition. (alias is always a fixed
    string from our own code, never user input.)
    """
    return (f"{alias}.revoked_at IS NULL"
            f" AND ({alias}.expires_at IS NULL OR {alias}.expires_at > :now)")

ALLOWED = {
    VIEW: {"owner", "download", "view"},
    DOWNLOAD: {"owner", "download"},
    MANAGE: {"owner"},
}


class AccessDenied(Forbidden):
    """A 403 that knows which document and action were refused, so the 403
    handler can write a useful access.denied audit entry."""

    def __init__(self, document, action):
        super().__init__()
        self.document = document
        self.action = action


def permission_for(user, document):
    """'owner', 'download', 'view' or None for this user and document."""
    if document["owner_id"] == user["id"]:
        return "owner"
    share = get_db().execute(
        "SELECT s.permission FROM shares s"
        " WHERE s.document_id = :doc AND s.grantee_id = :user AND " + active_share_sql("s"),
        {"doc": document["id"], "user": user["id"], "now": now_db()},
    ).fetchone()
    return share["permission"] if share else None


def authorize(doc_id, action):
    """Load the document and check g.user may do `action` with it.

    404 if there is no such document, 403 (AccessDenied) if there is but the
    user may not. IDs are random, so the 403/404 difference doesn't help
    anyone find documents by guessing.
    """
    document = get_db().execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if document is None:
        abort(404)
    permission = permission_for(g.user, document)
    # An unknown action gets an empty set, so a typo denies instead of allows.
    if permission not in ALLOWED.get(action, set()):
        raise AccessDenied(document, action)
    return document, permission
