"""Authorisation: who can reach which document, and what happens when they can't."""
import re
import time

import pytest
from flask.sessions import SecureCookieSessionInterface

from conftest import PDF, audit_rows, share_id

DOC_ROUTES = [
    ("get", "/documents/{doc}"),
    ("get", "/documents/{doc}/download"),
    ("post", "/documents/{doc}/share"),
    ("post", "/documents/{doc}/shares/{share}/revoke"),
    ("post", "/documents/{doc}/delete"),
]


@pytest.fixture
def setup(make_user, db):
    """ayaan owns a document shared with meera (download) and ravi (view)."""
    ayaan, meera, ravi, kiran = (make_user(n) for n in ("ayaan", "meera", "ravi", "kiran"))
    doc = ayaan.upload_doc()
    ayaan.share(doc, "meera", "download")
    ayaan.share(doc, "ravi", "view")
    return {"ayaan": ayaan, "meera": meera, "ravi": ravi, "kiran": kiran, "doc": doc,
            "share": share_id(db, doc, "meera")}


def call(browser, method, template, setup, **data):
    path = template.format(doc=setup["doc"], share=setup["share"])
    return browser.get(path) if method == "get" else browser.post(path, data)


# ------------------------------------------------------------------ login

@pytest.mark.parametrize("method,path", [
    ("get", "/documents"), ("post", "/documents/upload"),
    *DOC_ROUTES,
    ("get", "/audit"), ("post", "/audit/verify"), ("get", "/audit/export.csv"),
])
def test_every_protected_route_requires_login(setup, anon, method, path):
    response = call(anon, method, path, setup)
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login")


def test_forged_session_cookie_is_rejected(app, setup, anon, db):
    """A cookie claiming to be the owner is only accepted if it was signed
    with our SECRET_KEY. Same cookie contents, guessed key: ignored."""
    owner_id = db.execute("SELECT id FROM users WHERE username = 'ayaan'").fetchone()["id"]
    claims = {"user_id": owner_id, "ver": 0, "login_at": int(time.time())}

    class Forger:  # all the serializer needs: a key and the config
        secret_key = "guessed-secret-key-" + "x" * 32
        config = app.config

    interface = SecureCookieSessionInterface()
    anon.client.set_cookie("session", interface.get_signing_serializer(Forger).dumps(claims))
    assert anon.get(f"/documents/{setup['doc']}").status_code == 302

    # Control: the very same claims signed with the real key do work, so the
    # rejection above is down to the signature and nothing else.
    anon.client.set_cookie("session", interface.get_signing_serializer(app).dumps(claims))
    assert anon.get(f"/documents/{setup['doc']}").status_code == 200


# ------------------------------------------------------------------ strangers

@pytest.mark.parametrize("method,path", DOC_ROUTES)
def test_stranger_is_denied_every_document_route(setup, db, method, path):
    response = call(setup["kiran"], method, path, setup,
                    username="kiran", permission="download")
    assert response.status_code == 403
    denied = audit_rows(db, "access.denied")[-1]
    assert denied["actor_name"] == "kiran"
    assert denied["document_id"] == setup["doc"]
    # The entry lands in the owner's part of the log, so the owner sees it.
    assert denied["owner_id"] == db.execute(
        "SELECT owner_id FROM documents WHERE id = ?", (setup["doc"],)).fetchone()[0]


def test_denied_page_shows_entry_number_but_nothing_about_the_document(setup, db):
    response = setup["kiran"].get(f"/documents/{setup['doc']}")
    html = response.get_data(as_text=True)
    entry = audit_rows(db, "access.denied")[-1]
    assert f"audit entry #{entry['id']}" in html
    assert "Vendor contract" not in html


def test_stranger_does_not_see_document_in_list(setup):
    assert "Vendor contract" not in setup["kiran"].get("/documents").get_data(as_text=True)


@pytest.mark.parametrize("query", ["%", "_", "' OR '1'='1", "\" OR 1=1 --", "Vendor%' --"])
def test_search_cannot_widen_what_a_user_sees(setup, query):
    """Search text goes in as a bound parameter with LIKE wildcards escaped,
    so neither SQL nor wildcards can pull in other people's documents."""
    html = setup["kiran"].get("/documents", query_string={"q": query}).get_data(as_text=True)
    assert "Vendor contract" not in html


def test_unknown_document_is_404(setup):
    assert setup["kiran"].get("/documents/no-such-document").status_code == 404


def test_document_ids_are_long_random_tokens(setup, db):
    ids = [setup["doc"], setup["ayaan"].upload_doc("second.pdf")]
    for doc_id in ids:
        assert re.fullmatch(r"[A-Za-z0-9_-]{22}", doc_id)
    assert ids[0] != ids[1]


def test_admin_gets_no_access_to_other_peoples_documents(setup, make_user):
    admin = make_user("root_admin", role="admin")
    assert admin.get(f"/documents/{setup['doc']}").status_code == 403
    assert admin.get(f"/documents/{setup['doc']}/download").status_code == 403


# ------------------------------------------------------------------ permissions

def test_view_share_can_view_but_not_download(setup):
    assert setup["ravi"].get(f"/documents/{setup['doc']}").status_code == 200
    assert setup["ravi"].get(f"/documents/{setup['doc']}/download").status_code == 403


def test_download_share_can_download(setup):
    response = setup["meera"].get(f"/documents/{setup['doc']}/download")
    assert response.status_code == 200
    assert response.data == PDF


@pytest.mark.parametrize("path", [
    "/documents/{doc}/share", "/documents/{doc}/shares/{share}/revoke", "/documents/{doc}/delete",
])
def test_only_the_owner_can_share_revoke_or_delete(setup, db, path):
    """Even a user with download permission can't manage the document."""
    response = call(setup["meera"], "post", path, setup, username="kiran", permission="download")
    assert response.status_code == 403
    assert db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 1
    assert setup["kiran"].get(f"/documents/{setup['doc']}").status_code == 403


def test_forged_permission_value_is_rejected(setup, db):
    """The <select> offers view/download; posting anything else must not create a share."""
    setup["ayaan"].share(setup["doc"], "kiran", permission="owner")
    assert db.execute(
        "SELECT COUNT(*) FROM shares s JOIN users u ON u.id = s.grantee_id WHERE u.username = 'kiran'"
    ).fetchone()[0] == 0
    assert setup["kiran"].get(f"/documents/{setup['doc']}").status_code == 403


def test_list_shows_owned_and_shared_documents_only(setup):
    other = setup["kiran"].upload_doc("Kiran private.pdf")
    html = setup["meera"].get("/documents").get_data(as_text=True)
    assert "Vendor contract" in html
    assert "Kiran private" not in html
    assert setup["meera"].get(f"/documents/{other}").status_code == 403


# ------------------------------------------------------------------ revoke and expiry

def test_revoke_takes_effect_on_the_next_request(setup, db):
    meera = setup["meera"]
    assert meera.get(f"/documents/{setup['doc']}/download").status_code == 200
    setup["ayaan"].post(f"/documents/{setup['doc']}/shares/{setup['share']}/revoke")
    assert meera.get(f"/documents/{setup['doc']}/download").status_code == 403
    assert meera.get(f"/documents/{setup['doc']}").status_code == 403
    assert "Vendor contract" not in meera.get("/documents").get_data(as_text=True)
    assert audit_rows(db, "share.revoke")


def test_expired_share_is_denied(setup, db):
    db.execute("UPDATE shares SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = ?",
               (setup["share"],))
    db.commit()
    assert setup["meera"].get(f"/documents/{setup['doc']}/download").status_code == 403
    assert setup["meera"].get(f"/documents/{setup['doc']}").status_code == 403


def test_share_with_future_expiry_works_and_past_expiry_is_refused(setup, db):
    setup["ayaan"].share(setup["doc"], "kiran", "view", expires="2099-12-31")
    assert setup["kiran"].get(f"/documents/{setup['doc']}").status_code == 200
    setup["ayaan"].share(setup["doc"], "kiran", "download", expires="2020-01-01")
    # The refused share didn't replace the working one.
    assert setup["kiran"].get(f"/documents/{setup['doc']}/download").status_code == 403


def test_share_id_must_belong_to_the_document_in_the_url(setup, db):
    """kiran owns a document of her own. She can pass the owner check for
    *her* document, but must not be able to revoke a share on ayaan's by
    putting its share id in her URL."""
    kirans_doc = setup["kiran"].upload_doc("Kiran private.pdf")
    response = setup["kiran"].post(f"/documents/{kirans_doc}/shares/{setup['share']}/revoke")
    assert response.status_code == 404
    assert db.execute("SELECT revoked_at FROM shares WHERE id = ?",
                      (setup["share"],)).fetchone()[0] is None


def test_deleting_a_document_removes_its_shares(setup, db):
    setup["ayaan"].post(f"/documents/{setup['doc']}/delete")
    assert db.execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 0
    assert setup["meera"].get(f"/documents/{setup['doc']}").status_code == 404


# ------------------------------------------------------------------ audit visibility

def logged_actions(page):
    """Action names in the audit table rows (not the filter's <option>s)."""
    return set(re.findall(r'class="tag tag--\w+">([^<]+)<', page))


def test_member_sees_only_their_own_audit_events(setup):
    page = setup["kiran"].get("/audit").get_data(as_text=True)
    assert "Vendor contract" not in page
    assert logged_actions(page) == {"auth.register", "auth.login"}


def test_owner_sees_events_on_their_documents(setup):
    setup["kiran"].get(f"/documents/{setup['doc']}")  # denied
    page = setup["ayaan"].get("/audit").get_data(as_text=True)
    assert {"access.denied", "share.grant", "doc.upload"} <= logged_actions(page)
    assert "kiran" in page


def test_member_csv_export_has_the_same_scope_as_the_page(setup):
    csv_text = setup["kiran"].get("/audit/export.csv").get_data(as_text=True)
    assert "Vendor contract" not in csv_text
    assert "share.grant" not in csv_text


def test_admin_sees_every_audit_event(setup, make_user):
    admin = make_user("root_admin", role="admin")
    csv_text = admin.get("/audit/export.csv").get_data(as_text=True)
    assert "share.grant" in csv_text and "ayaan" in csv_text
