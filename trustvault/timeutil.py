"""Times are stored in UTC and shown in IST.

Stored values all use one ISO-8601 format, so comparing them as strings in SQL
gives the same answer as comparing the times.
"""
from datetime import datetime, timedelta, timezone

# India has no daylight saving, so a fixed offset is exact. (zoneinfo would
# need the tzdata package on Windows.)
IST = timezone(timedelta(hours=5, minutes=30), "IST")


def now():
    return datetime.now(timezone.utc)


def to_db(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def from_db(value):
    return datetime.fromisoformat(value)


def now_db():
    return to_db(now())
