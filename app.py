"""Entry point: `python app.py` for local development.

A production server imports `app` from this module instead (for example
`waitress-serve app:app`), so debug mode is never switched on there.
"""
import os

from dotenv import load_dotenv

load_dotenv()  # read .env before the app reads its config

from trustvault import create_app  # noqa: E402  (must come after load_dotenv)

app = create_app()

if __name__ == "__main__":
    # The Werkzeug debugger lets anyone who reaches it run Python code on the
    # server. It is only on when FLASK_DEBUG=1, and that belongs on your machine.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
