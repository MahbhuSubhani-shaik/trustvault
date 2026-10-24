"""Entry point: `python app.py` for local development.

A production server imports `app` from this module instead (on PythonAnywhere,
the WSGI file does `from app import app as application`), so debug mode is
never switched on there.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# Read .env from this folder, wherever the process was started from: hosts
# like PythonAnywhere run the WSGI file from a different working directory.
load_dotenv(Path(__file__).resolve().with_name(".env"))

from trustvault import create_app  # noqa: E402  (must come after load_dotenv)

app = create_app()

if __name__ == "__main__":
    # The Werkzeug debugger lets anyone who reaches it run Python code on the
    # server. It is only on when FLASK_DEBUG=1, and that belongs on your machine.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
