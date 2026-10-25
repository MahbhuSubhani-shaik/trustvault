"""Documents: list, upload, view, download, share, revoke, delete.

Every route that touches one document starts with access.authorize(), which
loads it and checks g.user's permission. See access.py for the rules.
"""
import io
import secrets
from datetime import date, datetime, time

from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, send_file, url_for,
)

from . import audit, files
from .access import DOWNLOAD, MANAGE, VIEW, active_share_sql, authorize
from .auth import login_required
from .db import get_db, transaction
from .timeutil import IST, now, now_db, to_db

bp = Blueprint("documents", __name__)

# How the latest audit entry reads in the "Last activity" column.
LAST_ACTIVITY = {
    "doc.upload": "Uploaded",
    "doc.view": "Viewed",
    "doc.download": "Downloaded",
    "share.grant": "Shared",
    "share.revoke": "Access revoked",
    "access.denied": "Access denied to",
    "file.integrity_fail": "Integrity check failed for",
}


def _describe_last(doc):
    if doc["last_action"] is None:
        return ""
    label = LAST_ACTIVITY.get(doc["last_action"], doc["last_action"])
    if doc["last_actor_id"] == g.user["id"]:
        return label.removesuffix(" to").removesuffix(" for")
    joiner = "" if label.endswith((" to", " for")) else " by"
    return f"{label}{joiner} {doc['last_actor']}"


# How an entry reads in "Activity on this file": phrase and dot colour.
ACTIVITY = {
    "doc.upload": ("uploaded the file", "info"),
    "doc.view": ("viewed the file", "neutral"),
    "doc.download": ("downloaded the file", "ok"),
    "share.grant": ("shared it with", "info"),
    "share.revoke": ("revoked access for", "danger"),
    "access.denied": ("was denied access:", "danger"),
    "file.integrity_fail": ("hit a failed integrity check", "danger"),
}


def _activity(event, doc):
    phrase, tone = ACTIVITY.get(event["action"], (event["action"], "neutral"))
    # Targets start with the file name ("Vendor.pdf → ravi · view only");
    # the rest is the detail worth showing.
    detail = ""
    if event["target"].startswith(doc["filename"]):
        detail = event["target"][len(doc["filename"]):].lstrip(" ·→")
    return {"text": f"{phrase} {detail}".strip(), "tone": tone}


def _like_pattern(text):
    """Turn search text into a LIKE pattern that matches it literally."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@bp.get("/documents")
@login_required
def index():
    tab = request.args.get("filter", "all")
    query = request.args.get("q", "").strip()[:100]
    # The WHERE clause is the authorisation: a row comes back only if the
    # user owns the document or holds a live share for it. Nothing else is
    # ever selected, so there is nothing to filter out afterwards.
    rows = get_db().execute(
        f"""
        SELECT d.*, u.username AS owner_name,
               CASE WHEN d.owner_id = :me THEN 'owner' ELSE s.permission END AS permission,
               s.created_at AS shared_at,
               (SELECT COUNT(*) FROM shares x
                 WHERE x.document_id = d.id AND {active_share_sql('x')}) AS share_count,
               (SELECT MIN(x.expires_at) FROM shares x
                 WHERE x.document_id = d.id AND {active_share_sql('x')}) AS next_expiry,
               a.action AS last_action, a.actor_name AS last_actor,
               a.actor_id AS last_actor_id, a.created_at AS last_at
        FROM documents d
        JOIN users u ON u.id = d.owner_id
        LEFT JOIN shares s
               ON s.document_id = d.id AND s.grantee_id = :me AND {active_share_sql('s')}
        LEFT JOIN audit_log a
               ON a.id = (SELECT MAX(id) FROM audit_log WHERE document_id = d.id)
        WHERE (d.owner_id = :me OR s.id IS NOT NULL)
          AND (:q = '' OR d.filename LIKE :pattern ESCAPE '\\')
        ORDER BY COALESCE(a.id, 0) DESC
        """,
        {"me": g.user["id"], "now": now_db(), "q": query, "pattern": _like_pattern(query)},
    ).fetchall()

    documents = [dict(row, last_text=_describe_last(row)) for row in rows]
    counts = {
        "all": len(documents),
        "mine": sum(d["permission"] == "owner" for d in documents),
        "shared": sum(d["permission"] != "owner" for d in documents),
    }
    if tab == "mine":
        documents = [d for d in documents if d["permission"] == "owner"]
    elif tab == "shared":
        documents = [d for d in documents if d["permission"] != "owner"]
    else:
        tab = "all"
    return render_template(
        "documents.html", documents=documents, counts=counts, tab=tab, query=query,
        max_bytes=files.MAX_FILE_SIZE,
    )


@bp.post("/documents/upload")
@login_required
def upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for(".index"))

    filename = files.clean_filename(upload.filename)
    data = upload.read(files.MAX_FILE_SIZE + 1)  # one byte over the limit is enough to know
    file_type, problem = files.validate(filename, data)
    if problem:
        audit.record("doc.upload_rejected", owner_id=g.user["id"], target=f"{filename} · {problem}")
        flash(problem, "error")
        return redirect(url_for(".index"))

    doc_id = secrets.token_urlsafe(16)  # 128 random bits: can't be guessed or counted through
    storage_name = files.save(data)
    try:
        with transaction() as db:
            db.execute(
                "INSERT INTO documents (id, owner_id, filename, storage_name, file_type, size,"
                " sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (doc_id, g.user["id"], filename, storage_name, file_type, len(data),
                 files.sha256(data), now_db()),
            )
            audit.record("doc.upload", document_id=doc_id, owner_id=g.user["id"], target=filename)
    except Exception:
        files.delete(storage_name)  # don't leave an orphan file behind
        raise
    flash(f"Uploaded {filename}.", "success")
    return redirect(url_for(".show", doc_id=doc_id))


def _check_integrity(doc):
    """Read the stored bytes and compare their SHA-256 with the one recorded
    at upload. Returns the bytes if they match, None if not (and logs it)."""
    data = files.read(doc["storage_name"])
    if data is not None and files.sha256(data) == doc["sha256"]:
        return data
    audit.record("file.integrity_fail", document_id=doc["id"], owner_id=doc["owner_id"],
                 target=doc["filename"])
    return None


@bp.get("/documents/<doc_id>")
@login_required
def show(doc_id):
    doc, permission = authorize(doc_id, VIEW)
    intact = _check_integrity(doc) is not None
    audit.record("doc.view", document_id=doc["id"], owner_id=doc["owner_id"], target=doc["filename"])
    db = get_db()
    owner = db.execute("SELECT username FROM users WHERE id = ?", (doc["owner_id"],)).fetchone()

    shares, my_share, activity = [], None, []
    if permission == "owner":
        # The owner's own views are left out so they don't drown everything else.
        events = db.execute(
            "SELECT * FROM audit_log WHERE document_id = ?"
            " AND NOT (action = 'doc.view' AND actor_id = ?) ORDER BY id DESC LIMIT 20",
            (doc["id"], g.user["id"]),
        ).fetchall()
        activity = [dict(e, **_activity(e, doc)) for e in events]
        # Only the owner sees who else has access. Newest share per person:
        # live, expired or revoked.
        rows = db.execute(
            "SELECT s.*, u.username FROM shares s JOIN users u ON u.id = s.grantee_id"
            " WHERE s.document_id = ? ORDER BY s.id DESC",
            (doc["id"],),
        ).fetchall()
        seen = set()
        for row in rows:
            if row["grantee_id"] not in seen:
                seen.add(row["grantee_id"])
                shares.append(row)
    else:
        my_share = db.execute(
            "SELECT * FROM shares s WHERE s.document_id = :doc AND s.grantee_id = :me AND "
            + active_share_sql("s"),
            {"doc": doc["id"], "me": g.user["id"], "now": now_db()},
        ).fetchone()

    return render_template(
        "document.html", doc=doc, permission=permission, owner_name=owner["username"],
        intact=intact, shares=shares, my_share=my_share, activity=activity, now=now_db(),
        today=now().astimezone(IST).date().isoformat(),
    )


PERMISSION_LABELS = {"view": "view only", "download": "can download"}


@bp.post("/documents/<doc_id>/share")
@login_required
def share(doc_id):
    doc, _ = authorize(doc_id, MANAGE)  # owner only
    db = get_db()
    username = request.form.get("username", "").strip()
    permission = request.form.get("permission", "")
    expires = request.form.get("expires", "").strip()

    # Never trust the form: the <select> only offers two values, but anyone
    # can post any value, so check it against the allowed set here.
    problem = None
    grantee = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
    if permission not in PERMISSION_LABELS:
        problem = "Choose “View only” or “Can download”."
    elif grantee is None:
        problem = "There’s no user with that username."
    elif grantee["id"] == doc["owner_id"]:
        problem = "That’s the owner. Owners always have full access."

    expires_at, expiry_note = None, ""
    if problem is None and expires:
        try:
            day = date.fromisoformat(expires)
        except ValueError:
            problem = "Enter the expiry as a date."
        else:
            if day < now().astimezone(IST).date():
                problem = "The expiry date can’t be in the past."
            else:
                # "Expires 31 Oct" means access through the end of 31 Oct, IST.
                expires_at = to_db(datetime.combine(day, time(23, 59, 59), tzinfo=IST))
                expiry_note = f" · expires {day.day} {day:%b %Y}"

    if problem:
        flash(problem, "error")
        return redirect(url_for(".show", doc_id=doc["id"]))

    with transaction() as db:
        # One live share per person: a new share replaces the old one.
        replaced = db.execute(
            "UPDATE shares SET revoked_at = ? WHERE document_id = ? AND grantee_id = ?"
            " AND revoked_at IS NULL",
            (now_db(), doc["id"], grantee["id"]),
        ).rowcount
        db.execute(
            "INSERT INTO shares (document_id, grantee_id, permission, expires_at, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (doc["id"], grantee["id"], permission, expires_at, now_db()),
        )
        audit.record(
            "share.grant", document_id=doc["id"], owner_id=doc["owner_id"],
            target=f"{doc['filename']} → {grantee['username']} · {PERMISSION_LABELS[permission]}"
                   f"{expiry_note}{' · replaces earlier share' if replaced else ''}",
        )
    flash(f"Shared with {grantee['username']} ({PERMISSION_LABELS[permission]}{expiry_note}).", "success")
    return redirect(url_for(".show", doc_id=doc["id"]))


@bp.post("/documents/<doc_id>/shares/<int:share_id>/revoke")
@login_required
def revoke(doc_id, share_id):
    doc, _ = authorize(doc_id, MANAGE)  # owner only
    with transaction() as db:
        # "AND s.document_id = ?" matters: the owner check above was for
        # doc_id, so the share must belong to that same document. Without it,
        # the owner of any document could revoke shares on someone else's by
        # editing share_id in the URL.
        target = db.execute(
            "SELECT s.*, u.username FROM shares s JOIN users u ON u.id = s.grantee_id"
            " WHERE s.id = ? AND s.document_id = ?",
            (share_id, doc["id"]),
        ).fetchone()
        if target is None:
            abort(404)
        if target["revoked_at"] is None:
            db.execute("UPDATE shares SET revoked_at = ? WHERE id = ?", (now_db(), target["id"]))
            audit.record("share.revoke", document_id=doc["id"], owner_id=doc["owner_id"],
                         target=f"{doc['filename']} → {target['username']}")
    flash(f"Access revoked for {target['username']}. It takes effect on their next request.", "success")
    return redirect(url_for(".show", doc_id=doc["id"]))


@bp.get("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    doc, _ = authorize(doc_id, DOWNLOAD)
    data = _check_integrity(doc)
    if data is None:
        flash("Download blocked: the stored file no longer matches the SHA-256 recorded at "
              "upload. This was written to the audit trail as file.integrity_fail.", "error")
        return redirect(url_for(".show", doc_id=doc_id))
    audit.record("doc.download", document_id=doc["id"], owner_id=doc["owner_id"], target=doc["filename"])
    # Send the exact bytes that were just hashed, not a fresh read of the
    # file, so nothing can swap the file between the check and the send.
    return send_file(
        io.BytesIO(data),
        mimetype=files.mime_type(doc["file_type"]),
        as_attachment=True,  # always a download, never rendered in our page's origin
        download_name=doc["filename"],
    )


@bp.post("/documents/<doc_id>/delete")
@login_required
def delete(doc_id):
    doc, _ = authorize(doc_id, MANAGE)
    with transaction() as db:
        db.execute("DELETE FROM documents WHERE id = ?", (doc["id"],))
        audit.record("doc.delete", document_id=doc["id"], owner_id=doc["owner_id"], target=doc["filename"])
    files.delete(doc["storage_name"])
    flash(f"Deleted {doc['filename']}.", "success")
    return redirect(url_for(".index"))
