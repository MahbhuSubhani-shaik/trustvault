# TrustVault

Secure document sharing with a tamper-evident audit trail. Built with Python, Flask,
Jinja and SQLite.

Upload a document, share it with a named person (view only or download, with an
optional expiry), revoke it, and see every action in a hash-chained audit log that
reports exactly where it was changed if anyone edits it.

## What works

Everything below is implemented and covered by the automated tests in `tests/`
(114 passing, plus 1 expected failure that records a known limit; see
[THREATS.md](THREATS.md) for which test covers what).

**Accounts**
- Register with username, email and password. Passwords need 12+ characters, must
  not be in a common-passwords list or contain the username, and are stored as
  salted scrypt hashes. New accounts are always `member`.
- Sign in with username or email, choosing **Member** or **Admin**. The choice is only
  compared with the role stored for the account; a mismatch is refused and logged.
  5 wrong passwords lock the account for 15
  minutes; every attempt is logged (`auth.login` / `auth.login_failed`).
- Sign out ends every copy of the session, not just the one in this browser.
- CSRF protection on every form.

**Dashboard**
- Counts of your documents, documents shared with you, people with access to your
  files and blocked attempts in the last 7 days, plus your recent activity.

**Documents**
- Upload PDF, DOCX, XLSX, PNG, JPG or TXT up to 10 MB. The type is checked from the
  file's contents (magic bytes), not just its name. Files are stored under random
  names outside the web root, with their SHA-256 recorded.
- The document list shows only files you own or that are shared with you, with
  filters (all / owned / shared) and search by name.
- Download re-computes the SHA-256 first. If the stored file has changed, the
  download is blocked and `file.integrity_fail` is logged.
- Delete (owner only).

**Sharing**
- Share by username with `view` (see the document's details) or `download`
  permission, and an optional expiry date (access ends at the end of that day, IST).
- Revoke at any time. Access is checked on the server on every request, so a
  revoke or an expiry takes effect on the very next request.
- Only the owner can share, revoke or delete, and only the owner sees who else has access.

**Audit trail**
- Append-only log of sign-ins, uploads, views, downloads, shares, revokes, deletes,
  denied attempts, integrity failures, verifications and exports.
- Each entry stores `prev_hash` and `hash = HMAC-SHA256(AUDIT_KEY, prev_hash + row)`.
  **Verify chain** recomputes every hash and reports the first broken entry.
- Members see events on their own documents and their own account; admins see
  everything. Filter by user, action and date; export to CSV (same scope).
- Any refused request shows a 403 page with the audit entry number of the attempt.

**Why HMAC instead of the plain SHA-256 in the original design:** with plain
SHA-256, someone who can edit the database can change a row and then recompute
every later hash, and the chain looks perfect. With an HMAC they also need
`AUDIT_KEY`, which is kept in the server's environment, not in the database.
`test_rewriting_hashes_without_the_key_is_detected` shows the difference.

## Not built / known limits

- There is no Users page in the web app. Admins are made from the server (command
  line, or `ADMIN_USERNAME`/`ADMIN_PASSWORD` at startup; see below).
- On Render's free plan the app sleeps when idle and its data is reset whenever it
  restarts; a host with a persistent disk keeps documents and the audit log.
- No in-browser preview: "view" permission shows a document's details only.
- Upload shows "Uploading…" while it runs, not a percentage. Verify shows
  "Verifying…", not a running count.
- No password reset, email verification or per-IP rate limiting.
- Deleting entries from the *end* of the audit log is not detected (recorded as a
  known limit in THREATS.md and in an `xfail` test).

## Run it locally

Needs Python 3.11 or newer (developed and tested on Python 3.12 on Windows 11).

```powershell
git clone <repository-url> trustvault
cd trustvault
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
copy .env.example .env            # macOS/Linux: cp .env.example .env
```

Generate two different keys and put them in `.env` as `SECRET_KEY` and `AUDIT_KEY`:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

For local http, also set `SESSION_COOKIE_SECURE=0` in `.env`. Then:

```powershell
python app.py
```

Open http://127.0.0.1:5000. The database and uploads are created in `instance/` on
first start.

### Make an admin

New accounts are members. To make one an admin (they will need to sign in again):

```powershell
flask --app app set-role <username> admin
```

On a host without a shell (Render's free plan), set `ADMIN_USERNAME` and
`ADMIN_PASSWORD` in the host's environment instead: that admin account is created
when the app starts, if it doesn't already exist. Existing accounts are never promoted.

### Run the tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Deploying (Render)

New Web Service from this repository. Build command `pip install -r requirements.txt`,
start command `gunicorn app:app`. Environment: `SECRET_KEY` and `AUDIT_KEY` (generated),
`SESSION_COOKIE_SECURE=1`, `TRUST_PROXY=1`, `FLASK_DEBUG=0`, `PYTHON_VERSION=3.12.10`,
and optionally `ADMIN_USERNAME`/`ADMIN_PASSWORD`. With a paid disk mounted at
`/var/data`, also set `DATABASE_PATH=/var/data/trustvault.sqlite3` and
`UPLOAD_DIR=/var/data/uploads` so data survives restarts.

## Deploying (PythonAnywhere)

The app keeps its data in a SQLite file and an uploads folder, so it needs a host
with a persistent disk. PythonAnywhere's free plan has one; hosts that wipe the disk
on every restart would lose all documents and the audit log.

1. Get the code onto PythonAnywhere: in a Bash console, `git clone` the repository
   (a private repository needs a GitHub personal access token), or upload a zip in the
   Files tab.
2. `mkvirtualenv --python=python3.12 trustvault`, then
   `pip install -r ~/trustvault/requirements.txt`.
3. Create `~/trustvault/.env` with **new** keys (not your local ones),
   `SESSION_COOKIE_SECURE=1`, `TRUST_PROXY=1` and `FLASK_DEBUG=0`.
4. Web tab → Add a new web app → Manual configuration → Python 3.12. Set the
   virtualenv to `~/.virtualenvs/trustvault`, and replace the WSGI file's contents with:
   ```python
   import sys
   path = "/home/<your-username>/trustvault"
   if path not in sys.path:
       sys.path.insert(0, path)
   from app import app as application
   ```
5. Turn on **Force HTTPS**, then Reload.

## Project layout

```
app.py                  entry point (loads .env, creates the app)
trustvault/
  __init__.py           app factory: config checks, CSRF, blueprints
  access.py             authorisation: the one place that decides who may do what
  auth.py               register, sign in/out, lockout, login_required
  dashboard.py          the signed-in user's own summary
  cli.py                set-role command; admin from ADMIN_USERNAME at startup
  documents.py          list, upload, view, download, share, revoke, delete
  files.py              type detection, random storage, SHA-256
  audit.py              hash-chained log: record() and verify_chain()
  audit_views.py        audit page, verify, CSV export
  errors.py             error pages; 403 handler logs access.denied
  security_headers.py   CSP, nosniff, frame-ancestors, no-store
  schema.sql            tables, append-only triggers
  templates/, static/   UI rebuilt from design/ (glass layout, one stylesheet)
tests/                  pytest suite (authorisation, auth, uploads, audit chain)
design/                 original design references (not served)
THREATS.md              threat model mapped to code and tests
PROMPTS.md              how AI was used, what it got wrong, how it was fixed
tools/make_sakura.py    draws the sign-in page artwork
```
