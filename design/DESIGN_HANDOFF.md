# TrustVault — UI design handoff

The `screens/` folder holds the six designed screens as `.dc.html` files (a design-tool format).
**Use them as a visual reference only.** Rebuild each one as a Flask/Jinja template. Do not copy
the files in as-is:

- `{{ ... }}`, `<sc-for>`, `<sc-if>`, `<x-dc>`, `<helmet>` and the `class Component extends DCLogic` script
  belong to the design tool. Replace them with Jinja `{% for %}` / `{% if %}` and real server data.
- The sample rows (meera, ravi, kiran, hashes, IPs) are placeholder data. Never hard-code them.
- Move the repeated inline styles into one `static/css/app.css`, using the tokens below.

## Screens → routes

| File | Route | Template | Who can open it |
|---|---|---|---|
| Main.dc.html | `GET/POST /login` | `login.html` | anyone (logged out) |
| Register.dc.html | `GET/POST /register` | `register.html` | anyone (logged out) |
| Documents.dc.html | `GET /documents`, `POST /documents/upload` | `documents.html` | logged-in user; shows only docs they own or that were shared with them |
| Document.dc.html | `GET /documents/<id>`, `POST /documents/<id>/share`, `POST /documents/<id>/shares/<share_id>/revoke`, `GET /documents/<id>/download`, `POST /documents/<id>/delete` | `document.html` | owner, or a user with an active, unexpired share. Share/revoke/delete are owner only |
| Audit.dc.html | `GET /audit`, `POST /audit/verify`, `GET /audit/export.csv` | `audit.html` | member: events on their own docs; admin: all events |
| Denied.dc.html | 403 error handler | `errors/403.html` | shown on any authorisation failure (log it as `access.denied`) |

Layout: one `base.html` holding the glass sidebar (Documents, Audit trail, Users [admin only], user chip, Sign out).
The pages extend it. Login, register and 403 use a centred glass card with no sidebar.

## Design tokens

```css
:root{
  --bg:#0B1026;
  --glow-1:rgba(99,102,241,.55);  /* indigo */
  --glow-2:rgba(20,184,166,.40);  /* teal */
  --glow-3:rgba(168,85,247,.45);  /* violet */
  --text:#F1F5FF;
  --text-muted:rgba(226,232,255,.78);
  --text-faint:rgba(226,232,255,.70);
  --glass:rgba(255,255,255,.08);
  --glass-strong:rgba(255,255,255,.10);
  --glass-border:rgba(255,255,255,.18);
  --hairline:rgba(255,255,255,.08);
  --link:#A5B4FC;
  --primary-grad:linear-gradient(135deg,#4F5BEA,#7C3AED);
  --ok:#6EE7B7;   --ok-bg:rgba(16,185,129,.20);
  --warn:#FDE68A; --warn-bg:rgba(245,158,11,.18);
  --danger:#FCA5A5; --danger-bg:rgba(248,113,113,.16);
  --hash:#5EEAD4;
  --radius-card:20px; --radius-ctl:12px;
}
body{background-color:var(--bg);
  background-image:radial-gradient(40rem 30rem at 15% 5%,var(--glow-1),transparent 60%),
    radial-gradient(34rem 28rem at 90% 25%,var(--glow-2),transparent 60%),
    radial-gradient(44rem 34rem at 50% 100%,var(--glow-3),transparent 60%);
  background-attachment:fixed;color:var(--text);color-scheme:dark;
  font-family:'IBM Plex Sans',system-ui,sans-serif}
.glass{background:var(--glass);border:1px solid var(--glass-border);border-radius:var(--radius-card);
  box-shadow:0 12px 40px rgba(3,6,23,.35);
  -webkit-backdrop-filter:blur(24px) saturate(150%);backdrop-filter:blur(24px) saturate(150%)}
@supports not (backdrop-filter:blur(1px)){.glass{background:rgba(21,27,61,.92)}}
```

Fonts: IBM Plex Sans (400/500/600/700) for UI and IBM Plex Mono (400/500) for hashes, IDs, IPs and action names.
Controls are at least 44px tall. Inputs are translucent with a 1px light border and a visible focus ring (`2px solid #A5B4FC`).

## Behaviour the screens show (build it for real, or remove it from the UI)

- Sign-in error message; after 5 failed logins, lock the account for 15 minutes; log every attempt (`auth.login` / `auth.login_failed`).
- Register: password at least 12 characters and not in a common-passwords list; passwords must match; new users get the `member` role.
- Upload: check the file type by its magic bytes, max 10 MB, store it under a random ID outside the web root, record its SHA-256.
- Download: recompute the SHA-256; if it doesn't match, block the download and log `file.integrity_fail`.
- Share: username + permission (`view` | `download`) + optional expiry. Revoke. All checks happen server-side on every request.
- Audit log: append-only. Each row stores `prev_hash` and `hash = SHA256(prev_hash + canonical row data)`.
  **Verify chain** recomputes every hash and reports the first broken entry. Members see events on their own docs only.
- 403 page shows the audit entry number of the denied attempt.
- Loading states (to add): upload progress, "Verifying… n / total", "checking integrity…" on download, disabled buttons while share/revoke run.

If a feature isn't built by submission time, take it out of the UI and the README. Don't leave it looking like it works.
