"""SQLite access: one connection per request, kept on flask.g.

Every query uses ? placeholders. User input is never pasted into SQL text,
so it can't change what a query does (no SQL injection).
"""
import sqlite3
from contextlib import contextmanager

from flask import current_app, g


def get_db():
    if "db" not in g:
        # isolation_level=None: no hidden transactions. We open them ourselves
        # with transaction() below, so we control exactly when the lock is taken.
        conn = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        g.db = conn
    return g.db


def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@contextmanager
def transaction():
    """Run a block as one all-or-nothing transaction.

    BEGIN IMMEDIATE takes SQLite's write lock at the start, so two requests
    can't both read "the last audit hash" and then both append after it. A
    nested call joins the outer transaction instead of starting another.
    """
    conn = get_db()
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        with app.open_resource("schema.sql") as f:
            get_db().executescript(f.read().decode("utf-8"))
