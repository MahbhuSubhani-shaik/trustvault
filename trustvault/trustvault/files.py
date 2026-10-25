"""Uploaded files: type detection by content, storage under random names.

Files live in UPLOAD_DIR (instance/uploads by default), which is outside the
static folder, so the web server never serves them directly. The only way to
get a file's bytes is through a route that checks access first.
"""
import hashlib
import io
import os
import secrets
import zipfile

from flask import current_app

MAX_FILE_SIZE = 10 * 1024 * 1024

# Detected type -> (allowed extensions, Content-Type we send on download).
# The Content-Type always comes from this table, never from the browser.
TYPES = {
    "pdf": ({".pdf"}, "application/pdf"),
    "docx": ({".docx"}, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "xlsx": ({".xlsx"}, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "png": ({".png"}, "image/png"),
    "jpg": ({".jpg", ".jpeg"}, "image/jpeg"),
    "txt": ({".txt"}, "text/plain; charset=utf-8"),
}
ALLOWED_EXTENSIONS = set().union(*(exts for exts, _ in TYPES.values()))


def detect_type(data):
    """Work out the file type from its first bytes (its "magic bytes").

    The name and the browser's Content-Type are chosen by the uploader and
    prove nothing. The bytes are what a program opening the file will see.
    """
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"PK\x03\x04"):
        return _office_type(data)
    if _is_text(data):
        return "txt"
    return None


def _office_type(data):
    """DOCX and XLSX are ZIP archives; tell them apart by the files inside.

    Only the archive's table of contents is read, never the compressed data,
    so a zip bomb can't blow up memory here.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return None
    if "[Content_Types].xml" not in names:
        return None
    # vbaProject.bin means macros (.docm/.xlsm renamed): refuse those.
    if any(name.endswith("vbaProject.bin") for name in names):
        return None
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    return None


def _is_text(data):
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def validate(filename, data):
    """Return (file_type, None) if the upload is acceptable, else (None, reason)."""
    if not data:
        return None, "The file is empty."
    if len(data) > MAX_FILE_SIZE:
        return None, "Files can be at most 10 MB."
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None, "Only PDF, DOCX, XLSX, PNG, JPG and TXT files can be uploaded."
    detected = detect_type(data)
    if detected is None or ext not in TYPES[detected][0]:
        return None, f"The file’s contents don’t match its {ext} extension."
    return detected, None


def clean_filename(name):
    """Tidy the uploader's file name for display and as the download name.

    It is never used to build a path, but drop any folder part and control
    characters anyway, and cap the length while keeping the extension.
    """
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if c.isprintable()).strip()
    stem, ext = os.path.splitext(name)
    return (stem[: 200 - len(ext)] + ext) if stem else "untitled" + ext


def mime_type(file_type):
    return TYPES[file_type][1]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _path(storage_name):
    return os.path.join(current_app.config["UPLOAD_DIR"], storage_name)


def save(data):
    """Write the bytes under a new random name and return that name."""
    storage_name = secrets.token_hex(16)
    os.makedirs(current_app.config["UPLOAD_DIR"], exist_ok=True)
    with open(_path(storage_name), "xb") as f:  # "x": never overwrite an existing file
        f.write(data)
    return storage_name


def read(storage_name):
    try:
        with open(_path(storage_name), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def delete(storage_name):
    try:
        os.remove(_path(storage_name))
    except FileNotFoundError:
        pass
