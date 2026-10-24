"""Error pages. Every HTTP error renders a template, never a stack trace."""
from flask import render_template
from werkzeug.exceptions import HTTPException


def register(app):
    @app.errorhandler(403)
    def forbidden(error):
        # TODO(step 5): write an access.denied audit entry and show its number.
        return render_template("errors/403.html"), 403

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
