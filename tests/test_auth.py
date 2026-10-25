"""Registration, sign-in, lockout, sessions and CSRF."""
import pytest

from conftest import PASSWORD, Browser, audit_rows
from trustvault import create_app


def test_app_refuses_to_start_without_strong_keys(app):
    for missing in ("SECRET_KEY", "AUDIT_KEY"):
        config = dict(app.config, **{missing: "short"})
        with pytest.raises(RuntimeError, match=missing):
            create_app(config)


def test_password_is_stored_as_a_salted_hash(anon, db):
    anon.register("ayaan")
    anon.register("meera")
    hashes = [row["password_hash"] for row in db.execute("SELECT password_hash FROM users")]
    assert all(h.startswith("scrypt:") and PASSWORD not in h for h in hashes)
    assert hashes[0] != hashes[1]  # same password, different salt


@pytest.mark.parametrize("password,confirm,message", [
    ("short-pass1", "short-pass1", "at least 12"),
    ("password1234", "password1234", "common-passwords"),
    ("Correcthorse", "Correcthorse", "common-passwords"),  # case doesn't help
    ("ayaan-is-my-password", "ayaan-is-my-password", "username"),
    (PASSWORD, PASSWORD + "x", "don’t match"),
])
def test_weak_or_mismatched_passwords_are_refused(anon, db, password, confirm, message):
    response = anon.post("/register", {"username": "ayaan", "email": "a@example.com",
                                       "password": password, "confirm": confirm})
    assert response.status_code == 400
    assert message in response.get_data(as_text=True)
    assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_role_cannot_be_chosen_at_registration(anon, db):
    anon.register("ayaan", role="admin")
    assert db.execute("SELECT role FROM users").fetchone()["role"] == "member"


def test_choosing_admin_at_sign_in_does_not_make_you_admin(anon, db):
    anon.register("ayaan")
    response = anon.login("ayaan", role="admin")  # right password, wrong role
    assert response.status_code == 200  # not signed in
    assert "isn’t an admin" in response.get_data(as_text=True)
    assert anon.get("/documents").status_code == 302
    assert db.execute("SELECT role FROM users").fetchone()["role"] == "member"
    assert audit_rows(db, "auth.login_failed")[-1]["target"] == "chose admin, account is member"


def test_admin_must_choose_admin(app, anon):
    anon.register("root_admin")
    app.test_cli_runner().invoke(args=["set-role", "root_admin", "admin"])
    assert anon.login("root_admin", role="member").status_code == 200
    assert anon.login("root_admin", role="admin").status_code == 302


@pytest.mark.parametrize("role", ["owner", "superuser", ""])
def test_unknown_role_choice_is_refused(anon, role):
    anon.register("ayaan")
    assert anon.login("ayaan", role=role).status_code == 200
    assert anon.get("/documents").status_code == 302


def test_usernames_are_unique_ignoring_case(anon, db):
    anon.register("ayaan")
    response = anon.register("AYAAN", email="other@example.com")
    assert response.status_code == 400
    assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_wrong_password_and_unknown_user_get_the_same_message(anon):
    anon.register("ayaan")
    wrong = anon.login("ayaan", "not-the-password").get_data(as_text=True)
    unknown = anon.login("nobody", "not-the-password").get_data(as_text=True)
    assert "Username or password is incorrect." in wrong
    assert "Username or password is incorrect." in unknown


def test_every_login_attempt_is_logged(anon, db):
    anon.register("ayaan")
    anon.login("ayaan", "not-the-password")
    anon.login("nobody", "not-the-password")
    anon.login("ayaan")
    failed = audit_rows(db, "auth.login_failed")
    assert [row["actor_name"] for row in failed] == ["ayaan", "nobody"]
    assert len(audit_rows(db, "auth.login")) == 1


def test_five_failures_lock_the_account_even_for_the_right_password(app, anon, db):
    anon.register("ayaan")
    for _ in range(5):
        anon.login("ayaan", "not-the-password")
    response = anon.login("ayaan")  # correct password
    assert response.status_code == 200  # no redirect: not signed in
    assert "locked" in response.get_data(as_text=True)
    assert anon.get("/documents").status_code == 302
    assert audit_rows(db, "auth.login_failed")[-1]["target"] == "account locked"


def test_lock_lifts_after_it_expires(anon, db):
    anon.register("ayaan")
    for _ in range(5):
        anon.login("ayaan", "not-the-password")
    db.execute("UPDATE users SET locked_until = '2000-01-01T00:00:00+00:00'")
    db.commit()
    assert anon.login("ayaan").status_code == 302
    assert anon.get("/documents").status_code == 200


@pytest.mark.parametrize("path", [
    "/login", "/register", "/logout", "/documents/upload", "/audit/verify",
])
def test_post_without_csrf_token_is_rejected(make_user, path):
    browser = make_user("ayaan")
    response = browser.post(path, {"username": "x"}, csrf=False)
    assert response.status_code == 400


def test_post_with_another_sessions_csrf_token_is_rejected(make_user):
    ayaan, meera = make_user("ayaan"), make_user("meera")
    doc = ayaan.upload_doc()
    response = ayaan.post(f"/documents/{doc}/delete", {"csrf_token": meera.csrf()})
    assert response.status_code == 400


def test_sign_out_kills_every_copy_of_the_session_cookie(make_user):
    browser = make_user("ayaan")
    stolen = browser.client.get_cookie("session").value
    browser.post("/logout")
    attacker = Browser(browser.app)
    attacker.client.set_cookie("session", stolen)
    assert attacker.get("/documents").status_code == 302


def test_sign_in_issues_a_fresh_session(anon):
    anon.register("ayaan")
    before = anon.client.get_cookie("session").value
    anon.login("ayaan")
    assert anon.client.get_cookie("session").value != before


def test_session_cookie_flags(app):
    secure_app = create_app(dict(app.config, SESSION_COOKIE_SECURE=True))
    # The login page puts a CSRF token in the session, so it sets the cookie.
    response = secure_app.test_client().get("/login", base_url="https://localhost")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Secure" in cookie
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")


@pytest.mark.parametrize("target", [
    "https://evil.example/", "//evil.example/", "/\\evil.example", "/\t/evil.example",
    "javascript:alert(1)",
])
def test_login_never_redirects_off_site(anon, target):
    anon.register("ayaan")
    response = anon.login("ayaan", next_url=target)
    assert response.headers["Location"] == "/dashboard"


def test_login_follows_a_local_next(anon):
    anon.register("ayaan")
    assert anon.login("ayaan", next_url="/audit").headers["Location"] == "/audit"
