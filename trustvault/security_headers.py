"""HTTP security headers added to every response."""
from flask import request

# Scripts, styles and images may only come from this site; the one exception is
# the IBM Plex fonts from Google. Inline <script> and style="" are blocked, so an
# injected tag that slips past escaping still can't run.
CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com",
        "img-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)


def register(app):
    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("Content-Security-Policy", CSP)
        # Never let the browser guess a file's type; it must use our Content-Type.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        # Pages show private data. Don't let the browser or a proxy keep a copy
        # that the back button could show after sign-out.
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response
