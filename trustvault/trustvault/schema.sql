-- TrustVault schema. Every statement is idempotent: the app runs this file at
-- startup, so a fresh database needs no separate setup step.

CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'admin')),
    failed_logins    INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,                       -- UTC ISO-8601, NULL when not locked
    session_version  INTEGER NOT NULL DEFAULT 0, -- bumped on sign-out to kill old cookies
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id            TEXT PRIMARY KEY,               -- random and unguessable; used in URLs
    owner_id      INTEGER NOT NULL REFERENCES users(id),
    filename      TEXT NOT NULL,                  -- the uploader's name for it: shown, never used as a path
    storage_name  TEXT NOT NULL UNIQUE,           -- random name of the file on disk
    file_type     TEXT NOT NULL,                  -- detected from the bytes: pdf, docx, xlsx, png, jpg, txt
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,                  -- of the bytes as uploaded
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS documents_by_owner ON documents (owner_id);

CREATE TABLE IF NOT EXISTS shares (
    id           INTEGER PRIMARY KEY,
    document_id  TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    grantee_id   INTEGER NOT NULL REFERENCES users(id),
    permission   TEXT NOT NULL CHECK (permission IN ('view', 'download')),
    expires_at   TEXT,      -- UTC; access ends at this moment. NULL = no expiry
    created_at   TEXT NOT NULL,
    revoked_at   TEXT       -- set on revoke; the row is kept as a record
);
-- At most one live (unrevoked) share per person per document.
CREATE UNIQUE INDEX IF NOT EXISTS shares_one_live
    ON shares (document_id, grantee_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS shares_by_grantee ON shares (grantee_id);

-- Append-only. The app never updates or deletes a row, and the triggers below
-- make SQLite refuse to as well. The hash chain catches anyone who gets round
-- the triggers by editing the database file directly.
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY,  -- the entry number shown in the UI
    created_at   TEXT NOT NULL,
    actor_id     INTEGER,              -- NULL when nobody is signed in
    actor_name   TEXT NOT NULL,
    action       TEXT NOT NULL,
    document_id  TEXT,
    target       TEXT NOT NULL,
    owner_id     INTEGER,              -- whose record this is; members see only their own
    ip           TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_owner ON audit_log (owner_id, id);
CREATE INDEX IF NOT EXISTS audit_by_document ON audit_log (document_id, id);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
