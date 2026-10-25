"""Uploads: type checks, size limit, storage, integrity on download."""
import io
import os
import re
import zipfile

import pytest

from conftest import PDF, PNG, audit_rows


def office_file(main_part, macros=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(main_part, "<x/>")
        if macros:
            archive.writestr(main_part.split("/")[0] + "/vbaProject.bin", "macro")
    return buffer.getvalue()


@pytest.mark.parametrize("filename,data", [
    ("contract.pdf", PDF),
    ("diagram.png", PNG),
    ("photo.jpeg", b"\xff\xd8\xff\xe0" + b"\x00" * 32),
    ("notes.txt", "plain UTF-8 text, ünïcödé".encode()),
    ("nda.docx", office_file("word/document.xml")),
    ("budget.xlsx", office_file("xl/workbook.xml")),
])
def test_allowed_types_are_accepted(make_user, db, filename, data):
    make_user("ayaan").upload_doc(filename, data)
    assert db.execute("SELECT filename FROM documents").fetchone()[0] == filename


@pytest.mark.parametrize("filename,data,reason", [
    ("invoice.pdf", b"MZ\x90\x00 a Windows program", "don’t match"),   # exe renamed .pdf
    ("photo.pdf", PNG, "don’t match"),                                 # real PNG, wrong extension
    ("report.docx", office_file("xl/workbook.xml"), "don’t match"),    # XLSX renamed .docx
    ("macro.docx", office_file("word/document.xml", macros=True), "don’t match"),
    ("notes.txt", b"binary\x00data", "don’t match"),
    ("page.html", b"<script>alert(1)</script>", "Only PDF"),
    ("image.svg", b"<svg onload=alert(1)>", "Only PDF"),
    ("empty.pdf", b"", "empty"),
])
def test_disguised_or_dangerous_files_are_refused(make_user, db, filename, data, reason):
    browser = make_user("ayaan")
    response = browser.upload(filename, data)
    assert response.status_code == 302
    assert reason in browser.get("/documents").get_data(as_text=True)
    assert db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0
    assert audit_rows(db, "doc.upload_rejected")


def test_files_over_10_mb_are_refused(make_user, db):
    response = make_user("ayaan").upload("big.pdf", b"%PDF-" + b"0" * (10 * 1024 * 1024 + 1))
    assert response.status_code in (302, 413)
    assert db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0


def test_stored_under_a_random_name_outside_the_web_root(app, make_user, db):
    make_user("ayaan").upload_doc("../../trustvault/static/evil.pdf")
    row = db.execute("SELECT * FROM documents").fetchone()
    assert re.fullmatch(r"[0-9a-f]{32}", row["storage_name"])
    assert row["filename"] == "evil.pdf"  # folder part dropped from the display name
    stored = os.path.join(app.config["UPLOAD_DIR"], row["storage_name"])
    assert os.path.isfile(stored)
    assert not os.path.abspath(stored).startswith(os.path.abspath(app.static_folder))
    assert not os.path.exists(os.path.join(app.static_folder, "evil.pdf"))


def test_sha256_is_recorded_at_upload(make_user, db):
    import hashlib
    make_user("ayaan").upload_doc("contract.pdf", PDF)
    assert db.execute("SELECT sha256 FROM documents").fetchone()[0] == hashlib.sha256(PDF).hexdigest()


def test_download_uses_our_content_type_and_forces_attachment(make_user):
    browser = make_user("ayaan")
    response = browser.upload("diagram.png", PNG, content_type="text/html")  # lying browser
    doc = response.headers["Location"].rsplit("/", 1)[1]
    download = browser.get(f"/documents/{doc}/download")
    assert download.status_code == 200
    assert download.headers["Content-Type"] == "image/png"
    assert download.headers["Content-Disposition"].startswith("attachment")
    assert download.headers["X-Content-Type-Options"] == "nosniff"


def test_tampered_file_is_not_served(app, make_user, db):
    browser = make_user("ayaan")
    doc = browser.upload_doc("contract.pdf", PDF)
    storage = db.execute("SELECT storage_name FROM documents").fetchone()[0]
    with open(os.path.join(app.config["UPLOAD_DIR"], storage), "ab") as f:
        f.write(b"one extra byte")
    response = browser.get(f"/documents/{doc}/download")
    assert response.status_code == 302  # back to the document page, no file
    assert audit_rows(db, "file.integrity_fail")
    assert not audit_rows(db, "doc.download")
    assert "Integrity check failed" in browser.get(f"/documents/{doc}").get_data(as_text=True)


def test_missing_file_is_treated_as_an_integrity_failure(app, make_user, db):
    browser = make_user("ayaan")
    doc = browser.upload_doc()
    storage = db.execute("SELECT storage_name FROM documents").fetchone()[0]
    os.remove(os.path.join(app.config["UPLOAD_DIR"], storage))
    assert browser.get(f"/documents/{doc}/download").status_code == 302
    assert audit_rows(db, "file.integrity_fail")


def test_html_in_a_file_name_is_shown_as_text(make_user):
    browser = make_user("ayaan")
    # No double quotes in the name: Werkzeug's test client doesn't escape them
    # in the multipart header (browsers send %22), so the name would be cut short.
    browser.upload_doc("<img src=x onerror=alert(1)>.pdf")
    html = browser.get("/documents").get_data(as_text=True)
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html


def test_pages_send_a_strict_content_security_policy(make_user):
    response = make_user("ayaan").get("/documents")
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert ' style="' not in response.get_data(as_text=True)  # nothing the CSP would block
