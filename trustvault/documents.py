"""Document list, upload, view, download, share. Built out in steps 3 and 4."""
from flask import Blueprint, render_template

bp = Blueprint("documents", __name__)


@bp.get("/documents")
def index():
    # TODO(step 2): require login. TODO(step 3): load the user's documents.
    return render_template("documents.html", documents=[])
