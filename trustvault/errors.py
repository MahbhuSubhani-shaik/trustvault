"""Error pages. Every HTTP error renders a template, never a stack trace."""
from flask import render_template
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException


def register(app):
    @app.errorhandler(403)
    def forbidden(error):
        # TODO(step 5): write an access.denied audit entry and show its number.
        return render_template("errors/403.html"), 403

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

    # Everything else (400, 404, 405, 413, 500...) shares one generic page.
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
