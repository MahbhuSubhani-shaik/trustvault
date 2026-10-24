# TrustVault threat model

What we protect, who we protect it from, how, and which test proves it.
Every test named here is in `tests/` and runs with `python -m pytest`.

## What is worth attacking

| Asset | Why it matters |
|---|---|
| Uploaded documents | Confidential by assumption. Must reach only the owner and people they shared with. |
| Shares (who, permission, expiry) | Define access. Must take effect, and stop taking effect, exactly when the owner says. |
| Accounts and sessions | Whoever holds a session acts as that user. |
| The audit log | The record of who did what. Its value is that nobody can quietly rewrite it. |
| `SECRET_KEY`, `AUDIT_KEY` | Signing keys. Leaking either breaks sessions or the audit chain. |

## Who attacks

- **A stranger on the internet** with no account, or with a free account they registered.
- **A member** who has *some* access (for example a view-only share) and wants more.
- **Someone who gets the database file** (a backup, a misconfigured host) but not the
  server's environment variables, so they don't know `AUDIT_KEY`.

Out of scope: someone with full control of the server (environment and code). They
can do anything the app can; see "What this does not protect against".

## Threats, defences and tests

### Access control

| # | Threat | Defence | Code | Tests |
|---|---|---|---|---|
| A1 | **IDOR:** change the ID in `/documents/<id>` to read someone else's file | Every document route starts with `authorize(doc_id, action)`, which loads the document and checks the user's permission from the database. IDs are 128-bit random tokens, so they can't be guessed or counted through. | `access.py` | `test_stranger_is_denied_every_document_route`, `test_document_ids_are_long_random_tokens`, `test_unknown_document_is_404` |
| A2 | View-only user downloads; grantee shares, revokes or deletes | One rule table: `view` needs owner/view/download, `download` needs owner/download, `manage` needs owner. Unknown actions get an empty set, so they deny. | `access.ALLOWED` | `test_view_share_can_view_but_not_download`, `test_download_share_can_download`, `test_only_the_owner_can_share_revoke_or_delete` |
| A3 | Access survives a revoke or expiry because it was cached | Nothing about access is stored in the session. Every request re-reads the share with one condition: not revoked and not past `expires_at`. | `access.active_share_sql` | `test_revoke_takes_effect_on_the_next_request`, `test_expired_share_is_denied` |
| A4 | Nested-ID trick: own document A, revoke a share that belongs to document B via `/documents/A/shares/<B's share>/revoke` | The share is loaded with `WHERE s.id = ? AND s.document_id = ?`, so it must belong to the document whose ownership was just checked. | `documents.revoke` | `test_share_id_must_belong_to_the_document_in_the_url` |
| A5 | Forged form values: `permission=owner`, `role=admin` | Permission is checked against an allow-list. The role is a constant in the `INSERT`; nothing in the form is read for it. | `documents.share`, `auth.register` | `test_forged_permission_value_is_rejected`, `test_role_cannot_be_chosen_at_registration` |
| A6 | List or search leaks other people's files | The list query's `WHERE` *is* the access rule (owner, or a live share). Search text is a bound parameter with `%` and `_` escaped. | `documents.index` | `test_list_shows_owned_and_shared_documents_only`, `test_search_cannot_widen_what_a_user_sees` |
| A7 | Admins read everyone's documents | Admins get no extra document access. Their only extra power is seeing the whole audit log. | `access.permission_for` | `test_admin_gets_no_access_to_other_peoples_documents` |
| A8 | Any route forgotten behind a login check | `login_required` on every route except login and register. A test walks every protected route signed out. | `auth.login_required` | `test_every_protected_route_requires_login` |

### Accounts and sessions

| # | Threat | Defence | Code | Tests |
|---|---|---|---|---|
| S1 | Forge a session cookie to become another user | The cookie is signed with `SECRET_KEY`. The app refuses to start without a 32+ character key, so no default key can end up in the repo. The role is never in the cookie; it is read from the database. | `__init__._require_secret`, `auth.load_logged_in_user` | `test_forged_session_cookie_is_rejected`, `test_app_refuses_to_start_without_strong_keys` |
| S2 | Steal a cookie (XSS, network, a shared computer) | `HttpOnly`, `SameSite=Lax`, `Secure`, an 8-hour hard limit. Sign-out bumps `session_version`, so every copy of the old cookie stops working. | `config.py`, `auth.logout` | `test_session_cookie_flags`, `test_sign_out_kills_every_copy_of_the_session_cookie` |
| S3 | Session fixation | The session is cleared and re-issued at sign-in. | `auth.login` | `test_sign_in_issues_a_fresh_session` |
| S4 | Guess one account's password | 5 wrong passwords lock the account for 15 minutes. While locked, even the right password is refused with the same message, so guesses can't be tested. Parallel guesses are decided one at a time under a write lock. | `auth.login` | `test_five_failures_lock_the_account_even_for_the_right_password`, `test_lock_lifts_after_it_expires` |
| S5 | Weak or reused passwords | 12–128 characters, not in a list of about 1,500 common long passwords (any case), must not contain the username. Stored as salted scrypt hashes. | `auth.validate_registration` | `test_weak_or_mismatched_passwords_are_refused`, `test_password_is_stored_as_a_salted_hash` |
| S6 | Tell real usernames from fake ones at sign-in | Same message for "no such user" and "wrong password". An unknown user is hashed against a dummy hash, so both take the same time. | `auth.login` | `test_wrong_password_and_unknown_user_get_the_same_message` |
| S7 | CSRF: another site makes the browser share, revoke, delete or sign out | Every POST needs the session's CSRF token (Flask-WTF), plus `SameSite=Lax`. Sign-out is a POST, not a link. | `__init__.csrf` | `test_post_without_csrf_token_is_rejected`, `test_post_with_another_sessions_csrf_token_is_rejected` |
| S8 | Open redirect through `?next=` | Only same-site paths are followed. `//host`, `https://`, backslashes and control characters fall back to `/documents`. | `auth.safe_next` | `test_login_never_redirects_off_site`, `test_login_follows_a_local_next` |

### Files

| # | Threat | Defence | Code | Tests |
|---|---|---|---|---|
| F1 | Upload malware or HTML disguised as a PDF or image | The type is detected from the file's magic bytes and must match the extension. DOCX and XLSX are recognised by their ZIP contents. Macro-enabled Office files are refused. SVG and HTML aren't allowed. Every rejection is logged. | `files.validate` | `test_disguised_or_dangerous_files_are_refused`, `test_allowed_types_are_accepted` |
| F2 | A served file runs as a page on our domain (stored XSS) | Downloads are always `attachment`, with a Content-Type from our own table (never the browser's), plus `nosniff` and a strict CSP. | `documents.download`, `security_headers.py` | `test_download_uses_our_content_type_and_forces_attachment` |
| F3 | Path traversal or overwrite through the file name | Files are saved as `instance/uploads/<32 random hex>`, opened with `"xb"` (never overwrite). The uploader's name is only shown. | `files.save` | `test_stored_under_a_random_name_outside_the_web_root` |
| F4 | Fetch stored files directly from the web server | Uploads live in `instance/`, outside the static folder. The only way to get the bytes is a route that runs `authorize`. | `config.py` | `test_stored_under_a_random_name_outside_the_web_root` |
| F5 | A file on disk is swapped or corrupted | SHA-256 is recorded at upload and recomputed on every view and download. A mismatch (or a missing file) blocks the download and logs `file.integrity_fail`. The exact bytes that were hashed are the ones sent. | `documents._check_integrity` | `test_tampered_file_is_not_served`, `test_missing_file_is_treated_as_an_integrity_failure` |
| F6 | Huge uploads or zip bombs exhaust the server | `MAX_CONTENT_LENGTH` rejects a body over 10 MB + 64 KB with 413 before the view runs. ZIP files are only inspected by their table of contents, never decompressed. | `config.py`, `files._office_type` | `test_files_over_10_mb_are_refused` |
| F7 | HTML in a file name or username runs in someone's browser | Jinja autoescapes everything. The CSP allows no inline scripts or styles. | templates, `security_headers.py` | `test_html_in_a_file_name_is_shown_as_text`, `test_pages_send_a_strict_content_security_policy` |
| F8 | SQL injection | Every value is a bound `?` or `:name` parameter. The few dynamic `WHERE` clauses are built only from fixed strings in the code. | `db.py` and every query | `test_search_cannot_widen_what_a_user_sees` |
| F9 | Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | `security_headers.py` | `test_pages_send_a_strict_content_security_policy` |

### Audit log

| # | Threat | Defence | Code | Tests |
|---|---|---|---|---|
| L1 | Edit an entry to hide what happened | Each row stores `hash = HMAC-SHA256(AUDIT_KEY, prev_hash + canonical row)`. Verify recomputes every hash and names the first entry that doesn't match. | `audit.py` | `test_edited_entry_is_detected`, `test_verify_page_reports_the_broken_entry` |
| L2 | Delete, reorder or insert entries | Each row's `prev_hash` must equal the previous row's hash, so gaps and swaps break the link. | `audit.verify_chain` | `test_deleted_entry_is_detected`, `test_swapped_entries_are_detected`, `test_forged_entry_appended_at_the_end_is_detected` |
| L3 | **Edit an entry and then recompute every hash after it** (defeats a plain SHA-256 chain) | The hash is an HMAC keyed with `AUDIT_KEY`, which lives in the server's environment, not in the database. Without it, recomputed hashes don't verify. | `audit.compute_hash` | `test_rewriting_hashes_without_the_key_is_detected` |
| L4 | The app itself (or a bug, or SQL injection) changes the log | SQLite triggers abort any `UPDATE` or `DELETE` on `audit_log`. The app only ever inserts. | `schema.sql` | `test_the_app_cannot_update_or_delete_audit_rows` |
| L5 | Two requests append at once and fork the chain | Appends run inside `BEGIN IMMEDIATE`, which takes the write lock before reading the last hash. | `db.transaction` | `test_parallel_writers_keep_one_unbroken_chain` |
| L6 | Members read other people's activity | A member sees rows whose `owner_id` is theirs (their documents and their account). The CSV export uses the same scope. A refused user's 403 page shows only the entry number, time and their own IP. | `audit_views._scoped_query`, `errors.forbidden` | `test_member_sees_only_their_own_audit_events`, `test_member_csv_export_has_the_same_scope_as_the_page`, `test_denied_page_shows_entry_number_but_nothing_about_the_document`, `test_owner_sees_events_on_their_documents` |
| L7 | A file name or login name like `=HYPERLINK(...)` runs as a formula when the CSV is opened | Cells starting with `= + - @`, tab or CR get a leading `'`. | `audit_views._csv_safe` | `test_csv_export_neutralises_spreadsheet_formulas` |
| L8 | Unauthorised attempts go unnoticed | Every 403 writes `access.denied` (document and attempted action) into the owner's log. Every sign-in attempt, upload rejection, integrity failure, verify and export is logged too. | `errors.forbidden` | `test_stranger_is_denied_every_document_route`, `test_every_login_attempt_is_logged` |

## What this does not protect against

These are real limits, written down rather than hidden.

- **Deleting entries from the end of the log.** A shorter chain still verifies.
  `test_tail_truncation_is_detected` is marked `xfail(strict=True)` to record this. The
  audit page shows the head hash so it can be noted somewhere else, but nothing
  compares it automatically. Fixing it needs an external anchor (for example,
  periodically publishing the head hash).
- **Someone with the server's environment.** With `AUDIT_KEY` *and* the database they
  can rewrite history, and with `SECRET_KEY` they can forge sessions. Keys belong in
  the host's environment, never in the repository.
- **Locking out someone else.** Anyone who knows a username can lock that account for
  15 minutes with 5 wrong guesses. There is no per-IP rate limit, so spreading guesses
  across many accounts (password spraying) isn't slowed. The password rules are the
  defence there.
- **Usernames are not secret.** Sharing is by username, and the share form says when
  a username doesn't exist. Registration also says when a username is taken.
- **View-only shows a document's details, not its contents.** There is no in-browser
  preview. Anyone allowed to download can, of course, keep and pass on the file.
- **No malware scanning.** The type check stops disguised files, not a malicious but
  genuine PDF or DOCX.
- **No encryption at rest** for uploaded files, and no automated backups.
- **Log flooding.** Each refused request adds an entry. Nothing limits how fast.
- **No password reset or email verification.**
