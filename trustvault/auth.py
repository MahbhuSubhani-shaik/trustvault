"""Register, sign in, sign out, and the login_required decorator.

Who is signed in is decided here, once per request, in load_logged_in_user.
Everything else reads g.user and never trusts anything else the browser sends
about identity or role.
"""
import functools
import re
import secrets
import time
from datetime import timedelta
from urllib.parse import urlsplit

from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .db import get_db, transaction
from .timeutil import from_db, now, now_db, to_db

bp = Blueprint("auth", __name__)

MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
MIN_PASSWORD, MAX_PASSWORD = 12, 128  # the max stops 1 MB "passwords" tying up the hasher
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,30}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

# Checked against when the username doesn't exist, so "no such user" takes as
# long as "wrong password" and response time doesn't reveal which accounts exist.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


@functools.cache
def common_passwords():
    with current_app.open_resource("data/common_passwords.txt") as f:
        lines = f.read().decode("utf-8").splitlines()
    return frozenset(line for line in lines if line and not line.startswith("#"))


# ---------------------------------------------------------------- who is signed in

@bp.before_app_request
def load_logged_in_user():
    """Set g.user from the session cookie, or None.

    The cookie holds only user_id, session_version and login time, and it is
    signed with SECRET_KEY, so the browser can read it but not change it. The
    role is always read fresh from the database, never from the cookie.
    """
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    lifetime = current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()
    if (
        user is None
        # Sign-out bumps session_version, so every older copy of the cookie
        # (a stolen one included) stops working at once.
        or session.get("ver") != user["session_version"]
        # Hard limit on a session's age, even if it is used constantly.
        or time.time() - session.get("login_at", 0) > lifetime
    ):
        session.clear()
        return
    g.user = user


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            next_url = request.full_path.rstrip("?") if request.method == "GET" else None
            return redirect(url_for("auth.login", next=next_url))
        return view(**kwargs)

    return wrapped


def safe_next(target):
    """Only follow ?next= to a path on this site.

    "/documents/abc" is fine. "https://evil.example" and "//evil.example" are
    not (an open redirect would let a phishing link start on our domain).
    Browsers treat backslash as slash and drop tabs and newlines, so any of
    those, or any other control character, rejects the target too.
    """
    if (
        target
        and target.startswith("/")
        and not target.startswith("//")
        and not any(c == "\\" or ord(c) < 32 or c.isspace() for c in target)
    ):
        parts = urlsplit(target)
        if not parts.scheme and not parts.netloc:
            return target
    return url_for("documents.index")


# ---------------------------------------------------------------- register

def validate_registration(username, email, password, confirm):
    errors = {}
    if not USERNAME_RE.fullmatch(username):
        errors["username"] = "Use 3–30 characters: letters, numbers, underscore."
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        errors["email"] = "Enter a valid email address."
    if len(password) < MIN_PASSWORD:
        errors["password"] = f"Use at least {MIN_PASSWORD} characters."
    elif len(password) > MAX_PASSWORD:
        errors["password"] = f"Use {MAX_PASSWORD} characters or fewer."
    elif password.lower() in common_passwords():
        errors["password"] = "That password is in the common-passwords list. Choose another."
    elif username and username.lower() in password.lower():
        errors["password"] = "Don’t include your username in your password."
    if password != confirm:
        errors["confirm"] = "Passwords don’t match."
    return errors


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("documents.index"))
    form = {"username": "", "email": ""}
    errors = {}
    if request.method == "POST":
        form["username"] = request.form.get("username", "").strip()
        form["email"] = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = validate_registration(
            form["username"], form["email"], password, request.form.get("confirm", "")
        )
        if not errors:
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE username = ?", (form["username"],)).fetchone():
                errors["username"] = "That username is taken."
            elif db.execute("SELECT 1 FROM users WHERE email = ?", (form["email"],)).fetchone():
                errors["email"] = "That email can’t be used. Try another, or sign in."
        if not errors:
            with transaction() as db:
                # The role is fixed in the SQL. Nothing in the form can set it,
                # so posting role=admin does nothing.
                cur = db.execute(
                    "INSERT INTO users (username, email, password_hash, role, created_at)"
                    " VALUES (?, ?, ?, 'member', ?)",
                    (form["username"], form["email"], generate_password_hash(password), now_db()),
                )
                audit.record(
                    "auth.register",
                    actor={"id": cur.lastrowid, "username": form["username"]},
                    owner_id=cur.lastrowid,
                )
            flash("Account created. Sign in to continue.", "success")
            return redirect(url_for("auth.login"))
    return render_template("register.html", form=form, errors=errors), 400 if errors else 200


# ---------------------------------------------------------------- sign in / out

def _find_user(identifier):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)
    ).fetchone()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("documents.index"))
    error = None
    identifier = ""
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()[:254]
        password = request.form.get("password", "")[:MAX_PASSWORD]
        user = _find_user(identifier)
        # Hash first, outside the write lock: it is deliberately slow.
        password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

        if user is None:
            audit.record("auth.login_failed", actor_name=identifier[:64], target="unknown user")
            error = "Username or password is incorrect."
        else:
            with transaction() as db:
                # Re-read under the lock: parallel guesses are decided one at a
                # time, so no more than 5 wrong ones are ever counted before the lock.
                user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
                locked = user["locked_until"] and from_db(user["locked_until"]) > now()
                if locked:
                    # Refuse even a correct password, and say the same thing
                    # either way, so a locked account can't be used to test guesses.
                    audit.record("auth.login_failed", actor_name=user["username"],
                                 owner_id=user["id"], target="account locked")
                    error = "Too many failed sign-ins. This account is locked for 15 minutes."
                elif password_ok:
                    db.execute(
                        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
                        (user["id"],),
                    )
                    audit.record("auth.login", actor=user, owner_id=user["id"])
                else:
                    failures = user["failed_logins"] + 1
                    if failures >= MAX_FAILED_LOGINS:
                        db.execute(
                            "UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                            (to_db(now() + LOCKOUT), user["id"]),
                        )
                        note = "wrong password · account locked for 15 min"
                    else:
                        db.execute(
                            "UPDATE users SET failed_logins = ? WHERE id = ?", (failures, user["id"])
                        )
                        note = f"wrong password · {failures} of {MAX_FAILED_LOGINS}"
                    audit.record("auth.login_failed", actor_name=user["username"],
                                 owner_id=user["id"], target=note)
                    error = "Username or password is incorrect."

            if error is None:
                # A fresh session on every sign-in: whatever cookie the browser
                # had before (possibly planted by someone else) is thrown away.
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["ver"] = user["session_version"]
                session["login_at"] = int(time.time())
                return redirect(safe_next(request.args.get("next")))

    return render_template("login.html", error=error, identifier=identifier)


@bp.post("/logout")
@login_required
def logout():
    with transaction() as db:
        db.execute(
            "UPDATE users SET session_version = session_version + 1 WHERE id = ?", (g.user["id"],)
        )
        audit.record("auth.logout", owner_id=g.user["id"])
    session.clear()
    flash("You’re signed out.", "info")
    return redirect(url_for("auth.login"))
