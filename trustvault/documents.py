"""Document list, upload, view, download, share. Built out in steps 3 and 4."""
from flask import Blueprint, render_template

from .auth import login_required

bp = Blueprint("documents", __name__)


@bp.get("/documents")
@login_required
def index():
    # TODO(step 3): load the user's documents.
    return render_template("documents.html", documents=[])
