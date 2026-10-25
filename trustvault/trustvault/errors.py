"""Error pages. Every HTTP error renders a template, never a stack trace."""
from flask import g, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

from . import audit


def register(app):
    @app.errorhandler(403)
    def forbidden(error):
        """Every authorisation failure lands here, so every one is logged.

        access.authorize() raises AccessDenied with the document and action;
        the entry goes to the document owner's part of the log, so they see
        who tried. The person refused sees only the entry number, time and
        their own IP, nothing about the document.
        """
        entry = None
        if g.get("user") is not None:
            document = getattr(error, "document", None)
            action = getattr(error, "action", None)
            entry = audit.record(
                "access.denied",
                document_id=document["id"] if document else None,
                owner_id=document["owner_id"] if document else None,
                target=f"{document['filename']} · tried to {action}" if document else request.path,
            )
        return render_template("errors/403.html", entry=entry), 403

    @app.errorhandler(CSRFError)
    def csrf_failed(error):
        return (
            render_template(
                "errors/error.html",
                code=400,
                title="This form has expired",
                message="It was open too long, or it wasn’t sent from a TrustVault page. "
                "Go back, reload the page and try again.",
            ),
            400,
        )

    @app.errorhandler(413)
    def too_large(error):
        return (
            render_template(
                "errors/error.html",
                code=413,
                title="File too large",
                message="Files can be at most 10 MB. Nothing was uploaded.",
            ),
            413,
        )

    # Everything else (400, 404, 405, 500...) shares one generic page.
    # Flask checks handlers by status code first, so 403 still uses the one above.
    @app.errorhandler(HTTPException)
    def http_error(error):
        return (
            render_template(
                "errors/error.html",
                code=error.code,
                title=error.name,
                message=error.description,
            ),
            error.code,
        )
