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


def ist_day(value):
    """'2026-10-31T18:29:59+00:00' -> '31 Oct'"""
    dt = from_db(value).astimezone(IST)
    return f"{dt.day} {dt:%b}"


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


ACTION_TONES = {
    "danger": {"access.denied", "auth.login_failed", "share.revoke", "doc.delete",
               "file.integrity_fail", "doc.upload_rejected"},
    "info": {"share.grant", "doc.upload", "user.role_change"},
    "ok": {"doc.download", "auth.login"},
}


def action_tone(action):
    """Colour class for an action name in the audit table."""
    for tone, actions in ACTION_TONES.items():
        if action in actions:
            return tone
    return "neutral"


def register(app):
    app.jinja_env.filters.update(
        ist=ist, ist_short=ist_short, ist_day=ist_day, ago=ago, filesize=filesize,
        short_hash=short_hash, action_tone=action_tone,
    )
