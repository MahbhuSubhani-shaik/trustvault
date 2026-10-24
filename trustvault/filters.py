"""Jinja filters for showing stored values."""
from .timeutil import IST, from_db, now


def ist(value):
    """'2026-10-24T14:39:00+00:00' -> '24 Oct 2026, 20:09'"""
    if not value:
        return "—"
    dt = from_db(value).astimezone(IST)
    return f"{dt.day} {dt:%b %Y, %H:%M}"


def ist_short(value):
    """'2026-10-24T14:39:00+00:00' -> '24 Oct, 20:09'"""
    dt = from_db(value).astimezone(IST)
    return f"{dt.day} {dt:%b, %H:%M}"


def ago(value):
    seconds = (now() - from_db(value)).total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h ago"
    days = int(seconds // 86400)
    if days == 1:
        return "yesterday"
    if days < 7:
        return f"{days} days ago"
    dt = from_db(value).astimezone(IST)
    return f"{dt.day} {dt:%b}"


def filesize(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{round(size / 1024)} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def short_hash(value):
    return f"{value[:4]}…{value[-4:]}" if value else "—"


def register(app):
    app.jinja_env.filters.update(
        ist=ist, ist_short=ist_short, ago=ago, filesize=filesize, short_hash=short_hash
    )
