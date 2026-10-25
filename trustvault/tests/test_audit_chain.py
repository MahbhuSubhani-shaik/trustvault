"""Tamper detection in the hash-chained audit log.

The attacker in these tests has the database file (the `db` fixture) but not
the server's environment, so they don't know AUDIT_KEY.
"""
import hashlib
import json
import sqlite3
import threading

import pytest

from conftest import audit_rows
from trustvault import audit


def drop_guards(db):
    """Step one for anyone editing the file directly: remove the triggers."""
    db.execute("DROP TRIGGER audit_log_no_update")
    db.execute("DROP TRIGGER audit_log_no_delete")


def verify(app):
    with app.app_context():
        return audit.verify_chain()


@pytest.fixture
def history(make_user):
    """A realistic little log: sign-ups, an upload, a share, a denial."""
    ayaan, meera = make_user("ayaan"), make_user("meera")
    doc = ayaan.upload_doc()
    ayaan.share(doc, "meera", "download")
    meera.get(f"/documents/{doc}/download")
    make_user("kiran").get(f"/documents/{doc}")
    return ayaan


def test_chain_is_intact_after_normal_use(app, history, db):
    result = verify(app)
    assert result["ok"]
    assert result["count"] == len(audit_rows(db)) >= 10


def test_first_entry_links_to_the_genesis_hash(history, db):
    assert audit_rows(db)[0]["prev_hash"] == "0" * 64


def test_the_app_cannot_update_or_delete_audit_rows(history, db):
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_log SET actor_name = 'someone else' WHERE id = 1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit_log WHERE id = 1")


def test_edited_entry_is_detected(app, history, db):
    drop_guards(db)
    denied = audit_rows(db, "access.denied")[0]["id"]
    db.execute("UPDATE audit_log SET actor_name = 'nobody' WHERE id = ?", (denied,))
    db.commit()
    result = verify(app)
    assert not result["ok"]
    assert result["broken_id"] == denied
    assert "contents" in result["reason"]


def test_deleted_entry_is_detected(app, history, db):
    drop_guards(db)
    db.execute("DELETE FROM audit_log WHERE id = 5")
    db.commit()
    result = verify(app)
    assert not result["ok"]
    assert result["broken_id"] == 6  # the entry after the gap no longer links up


def test_swapped_entries_are_detected(app, history, db):
    drop_guards(db)
    a, b = db.execute("SELECT * FROM audit_log WHERE id IN (3, 4) ORDER BY id").fetchall()
    for target, source in ((a, b), (b, a)):
        db.execute("UPDATE audit_log SET action = ?, target = ? WHERE id = ?",
                   (source["action"], source["target"], target["id"]))
    db.commit()
    assert verify(app)["broken_id"] == 3


def test_rewriting_hashes_without_the_key_is_detected(app, history, db):
    """The attack plain SHA-256 can't stop: edit a row, then recompute that
    row's hash and every later one so the chain links up again. The hashes
    are HMACs keyed with AUDIT_KEY, which the attacker doesn't have."""
    drop_guards(db)
    rows = audit_rows(db)
    target = rows[len(rows) // 2]["id"]
    db.execute("UPDATE audit_log SET target = 'nothing to see' WHERE id = ?", (target,))
    prev = None
    for row in audit_rows(db):
        if row["id"] < target:
            prev = row["hash"]
            continue
        fields = {f: row[f] for f in audit.HASHED_FIELDS}
        body = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        new_hash = hashlib.sha256((prev + body).encode()).hexdigest()
        db.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev, new_hash, row["id"]))
        prev = new_hash
    db.commit()
    result = verify(app)
    assert not result["ok"]
    assert result["broken_id"] == target


def test_forged_entry_appended_at_the_end_is_detected(app, history, db):
    last = audit_rows(db)[-1]
    db.execute(
        "INSERT INTO audit_log (id, created_at, actor_id, actor_name, action, document_id,"
        " target, owner_id, ip, prev_hash, hash) VALUES (?, ?, NULL, 'admin', 'doc.delete',"
        " NULL, 'cover-up', NULL, '127.0.0.1', ?, ?)",
        (last["id"] + 1, last["created_at"], last["hash"], "f" * 64),
    )
    db.commit()
    assert verify(app)["broken_id"] == last["id"] + 1


@pytest.mark.xfail(strict=True, reason="Known limit (THREATS.md): removing entries from the "
                   "end leaves a shorter chain that still verifies. Needs an external anchor.")
def test_tail_truncation_is_detected(app, history, db):
    drop_guards(db)
    db.execute("DELETE FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log)")
    db.commit()
    assert not verify(app)["ok"]


def test_verify_page_reports_the_broken_entry(history, db):
    drop_guards(db)
    db.execute("UPDATE audit_log SET ip = '10.9.9.9' WHERE id = 4")
    db.commit()
    history.post("/audit/verify")
    page = history.get("/audit").get_data(as_text=True)
    assert "Tampering detected at entry #4" in page
    # The check itself is logged, with its result.
    assert "broken at #4" in audit_rows(db, "chain.verify")[-1]["target"]


def test_verify_page_reports_an_intact_chain(history, db):
    history.post("/audit/verify")
    assert "Chain intact" in history.get("/audit").get_data(as_text=True)


def test_parallel_writers_keep_one_unbroken_chain(app):
    """BEGIN IMMEDIATE serialises appends. Without it, two writers could
    both read the same last hash and fork the chain."""
    def write_many(n):
        with app.app_context():
            for i in range(25):
                audit.record("doc.view", actor_name=f"writer{n}", target=str(i))

    threads = [threading.Thread(target=write_many, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = verify(app)
    assert result["ok"] and result["count"] == 100


def test_csv_export_neutralises_spreadsheet_formulas(app, anon, make_user):
    anon.login('=HYPERLINK("http://evil.example","click")', "whatever-password")
    admin = make_user("root_admin", role="admin")
    csv_text = admin.get("/audit/export.csv").get_data(as_text=True)
    line = next(l for l in csv_text.splitlines() if "HYPERLINK" in l)
    assert ",\"'=HYPERLINK" in line
