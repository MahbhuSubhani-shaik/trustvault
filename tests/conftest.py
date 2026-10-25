"""Test helpers. Each test gets a fresh app with its own database and upload
folder in a temporary directory. CSRF protection stays ON in tests, so every
POST goes through the same check it does in production."""
import io
import re
import sqlite3
from urllib.parse import quote

import pytest

from trustvault import create_app

PASSWORD = "violet-harbour-42"
PDF = b"%PDF-1.7\n% test document\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-" + "s" * 32,
        "AUDIT_KEY": "test-audit-key-" + "a" * 32,
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "UPLOAD_DIR": str(tmp_path / "uploads"),
        "SESSION_COOKIE_SECURE": False,  # the test client talks plain http
    })


@pytest.fixture
def db(app):
    """A raw connection to the app's database file: what an attacker who got
    hold of the file (but not the server's environment) could do."""
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


class Browser:
    """One person's browser: a test client with its own cookies."""

    def __init__(self, app, username=None):
        self.app = app
        self.client = app.test_client()
        self.username = username

    def csrf(self):
        # Any page with a form carries the session's CSRF token.
        response = self.client.get("/documents")
        if response.status_code != 200:
            response = self.client.get("/login")
        return CSRF_RE.search(response.get_data(as_text=True)).group(1)

    def get(self, path, **kwargs):
        return self.client.get(path, **kwargs)

    def post(self, path, data=None, csrf=True, **kwargs):
        data = dict(data or {})
        if csrf:
            data.setdefault("csrf_token", self.csrf())
        return self.client.post(path, data=data, **kwargs)

    def register(self, username, password=PASSWORD, email=None, **extra):
        return self.post("/register", {
            "username": username, "email": email or f"{username}@example.com",
            "password": password, "confirm": password, **extra,
        })

    def login(self, username, password=PASSWORD, next_url=None, role="member"):
        path = "/login" + (f"?next={quote(next_url, safe='')}" if next_url else "")
        return self.post(path, {"username": username, "password": password, "role": role})

    def upload(self, filename, data=PDF, content_type=None):
        file = (io.BytesIO(data), filename, content_type) if content_type else (io.BytesIO(data), filename)
        return self.post("/documents/upload", {"file": file}, content_type="multipart/form-data")

    def upload_doc(self, filename="Vendor contract.pdf", data=PDF):
        """Upload and return the new document's id."""
        response = self.upload(filename, data)
        assert response.status_code == 302 and "/documents/" in response.headers["Location"]
        return response.headers["Location"].rsplit("/", 1)[1]

    def share(self, doc_id, username, permission="view", expires=""):
        return self.post(f"/documents/{doc_id}/share",
                         {"username": username, "permission": permission, "expires": expires})


@pytest.fixture
def make_user(app):
    """make_user("meera") -> a signed-in Browser for a new member."""
    def _make(username, role="member"):
        browser = Browser(app, username)
        browser.register(username)
        if role != "member":
            result = app.test_cli_runner().invoke(args=["set-role", username, role])
            assert result.exit_code == 0, result.output
        browser.login(username, role=role)
        return browser
    return _make


@pytest.fixture
def anon(app):
    return Browser(app)


def share_id(db, doc_id, username):
    row = db.execute(
        "SELECT s.id FROM shares s JOIN users u ON u.id = s.grantee_id"
        " WHERE s.document_id = ? AND u.username = ? AND s.revoked_at IS NULL",
        (doc_id, username),
    ).fetchone()
    return row["id"]


def audit_rows(db, action=None):
    if action:
        return db.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()
    return db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
