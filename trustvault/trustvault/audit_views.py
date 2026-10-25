"""The audit trail page, chain verification and CSV export.

Who sees what:
    member  rows whose owner_id is their own id: events on their documents
            and on their own account (including failed sign-ins against it)
    admin   every row
The same scope is used for the page and the CSV, so the export can never
contain more than the page would show.
"""
import csv
import io
from datetime import date, datetime, time, timedelta

from flask import Blueprint, Response, g, redirect, render_template, request, session, url_for

from . import audit
from .auth import login_required
from .db import get_db
from .timeutil import IST, now_db, to_db

bp = Blueprint("audit", __name__)

PAGE_SIZE = 25

ACTIONS = [
    "auth.register", "auth.login", "auth.login_failed", "auth.logout",
    "doc.upload", "doc.upload_rejected", "doc.view", "doc.download", "doc.delete",
    "share.grant", "share.revoke", "access.denied", "file.integrity_fail",
    "chain.verify", "audit.export", "user.role_change",
]


def _parse_day(value):
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _ist_midnight(day):
    return to_db(datetime.combine(day, time(0, 0), tzinfo=IST))


def _scoped_query(args):
    """Build the WHERE clause for the current user's view of the log.

    The clause is assembled only from fixed strings in this function; every
    value from the request goes in as a :named parameter.
    """
    where, params = [], {}
    if g.user["role"] != "admin":
        where.append("owner_id = :me")
        params["me"] = g.user["id"]

    filters = {
        "user": args.get("user", "").strip()[:64],
        "action": args.get("action", "") if args.get("action", "") in ACTIONS else "",
        "from": args.get("from", ""),
        "to": args.get("to", ""),
    }
    if filters["user"]:
        where.append("actor_name = :user COLLATE NOCASE")
        params["user"] = filters["user"]
    if filters["action"]:
        where.append("action = :action")
        params["action"] = filters["action"]
    start, end = _parse_day(filters["from"]), _parse_day(filters["to"])
    if start:
        where.append("created_at >= :start")
        params["start"] = _ist_midnight(start)
    else:
        filters["from"] = ""
    if end:
        where.append("created_at < :end")
        params["end"] = _ist_midnight(end + timedelta(days=1))
    else:
        filters["to"] = ""
    return " AND ".join(where) or "1 = 1", params, filters


@bp.get("/audit")
@login_required
def index():
    where, params, filters = _scoped_query(request.args)
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_log WHERE {where}", params).fetchone()[0]
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(1, request.args.get("page", 1, type=int)), pages)
    rows = db.execute(
        f"SELECT * FROM audit_log WHERE {where} ORDER BY id DESC LIMIT :limit OFFSET :offset",
        dict(params, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE),
    ).fetchall()
    head = db.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return render_template(
        "audit.html",
        rows=rows, total=total, page=page, pages=pages, filters=filters, actions=ACTIONS,
        head=head, result=session.pop("verify", None),
        query_args={key: value for key, value in filters.items() if value},
        first_shown=(page - 1) * PAGE_SIZE + 1 if rows else 0,
        last_shown=(page - 1) * PAGE_SIZE + len(rows),
    )


@bp.post("/audit/verify")
@login_required
def verify():
    result = audit.verify_chain()
    head = get_db().execute("SELECT MAX(id) FROM audit_log").fetchone()[0] or 0
    if result["ok"]:
        note = f"ok · {result['count']} entries"
    else:
        note = f"broken at #{result['broken_id']} · {result['reason']}"
    entry = audit.record("chain.verify", owner_id=g.user["id"], target=note)
    # Post/redirect/get: refreshing the page shows the result again instead of
    # re-sending the form. The result rides along in the session for one page.
    session["verify"] = dict(result, last_id=head, entry_id=entry["id"], at=entry["created_at"])
    return redirect(url_for(".index"))


def _csv_safe(value):
    """Stop CSV formula injection.

    Spreadsheet apps run a cell that starts with = + - @ as a formula. A
    file name or a typed-in login name like =HYPERLINK(...) would run when
    someone opens the export. A leading ' makes the cell plain text.
    """
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@bp.get("/audit/export.csv")
@login_required
def export():
    where, params, _ = _scoped_query(request.args)
    rows = get_db().execute(f"SELECT * FROM audit_log WHERE {where} ORDER BY id", params).fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "time_utc", "user", "action", "target", "ip", "prev_hash", "hash"])
    for r in rows:
        writer.writerow([_csv_safe(v) for v in (
            r["id"], r["created_at"], r["actor_name"], r["action"], r["target"], r["ip"],
            r["prev_hash"], r["hash"],
        )])
    audit.record("audit.export", owner_id=g.user["id"], target=f"{len(rows)} entries")
    stamp = now_db()[:10]
    return Response(
        "﻿" + out.getvalue(),  # BOM so Excel reads the file as UTF-8
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=trustvault-audit-{stamp}.csv"},
    )
