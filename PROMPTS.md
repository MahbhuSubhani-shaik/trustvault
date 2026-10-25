# PROMPTS.md: AI-assisted development log

**Tools used**
- **Claude Code** (Claude Opus 5.5): implementation, tests, documentation and deployment
  support, working directly in this repository.
- **ChatGPT**: early planning of the architecture and implementation options.

Every AI-assisted commit carries a `Co-Authored-By: Claude` trailer, so the history
shows which work was AI-assisted. Commit links point to
`github.com/MahbhuSubhani-shaik/trustvault`.

Each entry records the prompt, what the tool produced, what was wrong with it, and
how it was resolved and verified.

---

## 1. 24 Oct 2026 · Audit trail: strengthening the hash chain

**Prompt:** Implement the append-only audit log from the design specification
(`hash = SHA256(prev_hash + canonical row data)`).

**Output:** Before implementing, the tool flagged a weakness in the specification
itself.

**Issue:** An unkeyed SHA-256 chain only detects naive edits. An attacker with write
access to the database can modify a row and recompute every subsequent hash, and the
chain verifies again.

**Resolution:** The chain uses **HMAC-SHA256 keyed with `AUDIT_KEY`**, which is held in
the server environment, never in the database.
`test_rewriting_hashes_without_the_key_is_detected` reproduces the attack (edit a row,
recompute all later hashes with SHA-256) and confirms verification still fails.
Swapping the HMAC back to plain SHA-256 makes that test fail, which proves the test
exercises the defence.

**Commits:** [88d95de](https://github.com/MahbhuSubhani-shaik/trustvault/commit/88d95de) ·
[e994c04](https://github.com/MahbhuSubhani-shaik/trustvault/commit/e994c04) ·
[23ec144](https://github.com/MahbhuSubhani-shaik/trustvault/commit/23ec144)

---

## 2. 24 Oct 2026 · Audit trail: operator-precedence defect

**Prompt:** Record the client IP address on every audit entry.

**Output:**
`return request.remote_addr or "unknown" if has_request_context() else "local"`

**Issue:** Python parses this as `a or (b if c else d)`. `request` was read even with
no active request (for example, from the `set-role` command), which raises an error.

**Resolution:** Found on code review before it ran. The request-context check now
comes first. The CLI path that writes audit entries without a request is covered by
the test suite.

**Commit:** [88d95de](https://github.com/MahbhuSubhani-shaik/trustvault/commit/88d95de)

---

## 3. 24 Oct 2026 · Test suite: false failures

**Prompt:** Write automated tests for authorisation and tamper detection.

**Output:** 99 tests. Three failed on the first run.

**Issue:** All three failures were defects in the tests, not the application:
- an assertion matched an action name in the filter `<select>`, not a log row;
- an off-by-one boundary (`> 10` when exactly 10 entries were expected);
- Werkzeug's test client truncates multipart file names at a double quote, so the
  test uploaded the wrong name.

**Resolution:** Each assertion was narrowed to the element under test, and the full
suite passed. The application code was unchanged, because the failures were
diagnosed before anything was "fixed".

**Commit:** [23ec144](https://github.com/MahbhuSubhani-shaik/trustvault/commit/23ec144)

---

## 4. 24 Oct 2026 · Access control: verifying the tests by mutation

**Prompt:** Demonstrate that the authorisation tests detect real defects.

**Output:** A script that copies the project, injects one security bug at a time and
runs the suite. Seven mutations: view-only share can download, revoke ignores the
document, expiry ignored, plain SHA-256, lockout ignored, download skips the hash
check, role taken from the form.

**Issue:** The "expiry ignored" mutation contained a syntax error (an extra `)` in
the SQL). The suite failed on the SQL error, not on the missing check: a false
positive.

**Resolution:** The mutation was corrected to valid SQL and re-run.
`test_expired_share_is_denied` then failed for the right reason. All seven mutations
are caught, each by a targeted test.

**Commit:** [23ec144](https://github.com/MahbhuSubhani-shaik/trustvault/commit/23ec144)

---

## 5. 25 Oct 2026 · Authorisation: role selection at sign-in

**Prompt:** Add a role selector (Admin / Viewer / Owner) to the sign-in page.

**Output:** The tool identified the requirement as a privilege-escalation risk. If
the client chooses the role, any user can select "Admin". "Owner" is also not a role
in this system, because ownership is per document.

**Issue:** A client-supplied role must never be trusted.

**Resolution:** A **Member / Admin** selector that is only *compared* with the role
stored in the database, after password verification. A mismatch is refused and logged
as `auth.login_failed` ("chose admin, account is member"). Unknown values are rejected.
Tests: `test_choosing_admin_at_sign_in_does_not_make_you_admin`,
`test_admin_must_choose_admin`, `test_unknown_role_choice_is_refused`.

**Commit:** [25c4ba4](https://github.com/MahbhuSubhani-shaik/trustvault/commit/25c4ba4)

---

## 6. 25 Oct 2026 · Authorisation: provisioning an admin without shell access

**Prompt:** Provide a way to create an admin account on Render.

**Output:** The only provisioning path was the `flask set-role` command, which needs
a server shell. Render's free tier has none, and its storage is reset on restart.

**Issue:** There was no admin on the hosted instance, and a naive fix (promote
whichever account registers a configured username) would let a visitor claim that
name after a reset.

**Resolution:** When `ADMIN_USERNAME` / `ADMIN_PASSWORD` are set in the host
environment, the admin account is created at **startup, before any request is
served**. Existing accounts are **never promoted**, and weak passwords are rejected.
Tests: `test_admin_account_can_be_created_from_config`,
`test_config_never_promotes_an_existing_member`,
`test_config_admin_with_a_weak_password_is_not_created`.

**Commit:** [eed55b5](https://github.com/MahbhuSubhani-shaik/trustvault/commit/eed55b5)

---

## 7. 24 Oct 2026 · Security review of the design screens

**Prompt:** Rebuild the six design screens as Flask/Jinja templates.

**Output:** The tool rebuilt the screens and flagged three security problems in the
designs.

**Issue:**
- sign-out was a GET link, which is CSRF-triggerable from any site;
- the sign-in screen displayed hard-coded audit rows, and real rows there would
  disclose data to unauthenticated visitors;
- the "Users" link had no backing page.

**Resolution:** Sign-out is a CSRF-protected POST. The sample rows were replaced with
a description of the chain. The Users link was removed, and admin provisioning is
server-side (entries 5 and 6).

**Commit:** [aa7a81d](https://github.com/MahbhuSubhani-shaik/trustvault/commit/aa7a81d)
