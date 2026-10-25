"""Append-only, hash-chained audit log.

Every row stores prev_hash (the previous row's hash) and

    hash = HMAC-SHA256(AUDIT_KEY, prev_hash + canonical JSON of the row)

Change any field of any row and its hash no longer matches. Delete a row and
the next row's prev_hash points at nothing. Either way verification reports
the first broken entry.

Why HMAC and not plain SHA-256: with plain SHA-256, someone who can edit the
database can also recompute every hash after their edit, and the chain looks
perfect again. The HMAC needs AUDIT_KEY, which lives in the server's
environment, not in the database, so editing the database alone can't
produce valid hashes.
"""
import hashlib
import hmac
import json

from flask import current_app, g, has_request_context, request

from .db import get_db, transaction
from .timeutil import now_db

GENESIS_HASH = "0" * 64  # prev_hash of the very first entry

# The fields covered by the hash, i.e. everything except the hashes themselves.
HASHED_FIELDS = (
    "id", "created_at", "actor_id", "actor_name", "action",
    "document_id", "target", "owner_id", "ip",
)


def canonical(row):
    """The row as bytes in a fixed form: same data, same bytes, every time."""
    data = {field: row[field] for field in HASHED_FIELDS}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compute_hash(prev_hash, row):
    key = current_app.config["AUDIT_KEY"].encode()
    return hmac.new(key, prev_hash.encode() + canonical(row), hashlib.sha256).hexdigest()


def client_ip():
    if not has_request_context():
        return "local"  # e.g. a CLI command
    return request.remote_addr or "unknown"


def record(action, *, target="", document_id=None, owner_id=None, actor=None, actor_name=None):
    """Append one entry and return it as a dict (its "id" is the entry number).

    actor defaults to the signed-in user. owner_id says whose record this is:
    a member's audit page shows only rows with their id there.
    """
    if actor is None and has_request_context():
        actor = g.get("user")
    with transaction() as db:
        last = db.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        row = {
            # We hold the write lock, so nobody else can take this number.
            "id": last["id"] + 1 if last else 1,
            "created_at": now_db(),
            "actor_id": actor["id"] if actor else None,
            "actor_name": actor_name or (actor["username"] if actor else ""),
            "action": action,
            "document_id": document_id,
            "target": target,
            "owner_id": owner_id,
            "ip": client_ip(),
        }
        row["prev_hash"] = last["hash"] if last else GENESIS_HASH
        row["hash"] = compute_hash(row["prev_hash"], row)
        db.execute(
            "INSERT INTO audit_log (id, created_at, actor_id, actor_name, action, document_id,"
            " target, owner_id, ip, prev_hash, hash)"
            " VALUES (:id, :created_at, :actor_id, :actor_name, :action, :document_id,"
            " :target, :owner_id, :ip, :prev_hash, :hash)",
            row,
        )
    return row


def verify_chain():
    """Recompute every hash, oldest first, and report the first broken entry.

    Two checks per entry:
      1. its prev_hash equals the previous entry's hash: catches entries
         that were deleted, inserted or reordered;
      2. its hash equals HMAC(prev_hash + its contents): catches entries
         whose contents were edited.

    Limit: deleting entries from the *end* leaves a shorter chain that still
    verifies. The head hash is shown on the audit page so it can be noted
    somewhere else; see THREATS.md.
    """
    expected_prev = GENESIS_HASH
    count = 0
    for row in get_db().execute("SELECT * FROM audit_log ORDER BY id"):
        if not hmac.compare_digest(row["prev_hash"], expected_prev):
            return {"ok": False, "count": count, "broken_id": row["id"],
                    "reason": "Its prev_hash doesn’t match the entry before it, so an entry "
                              "was removed, inserted or changed."}
        if not hmac.compare_digest(row["hash"], compute_hash(row["prev_hash"], row)):
            return {"ok": False, "count": count, "broken_id": row["id"],
                    "reason": "Its stored hash doesn’t match its contents."}
        expected_prev = row["hash"]
        count += 1
    return {"ok": True, "count": count, "broken_id": None, "reason": None}
