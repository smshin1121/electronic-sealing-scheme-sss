"""Shared set-up of the web app's command-line tools.

Used by the account CLI (``python -m src.web.admin_accounts``, stage E, E4)
and the identity migration (``python -m src.web.privacy.migrate``, E3a):
a bare Flask app carrying the web app's configuration, and a database
connection that refuses to fall back from MariaDB to SQLite.
"""

from __future__ import annotations

import os
from typing import Optional

from flask import Flask, g

from .config import get_config
from .models.db_models import close_db, create_schema, get_db


class BackendError(RuntimeError):
    """The configured database was not reached; the message is user-facing."""


def build_cli_app(env: Optional[str]) -> Flask:
    """A bare app carrying the web app's configuration (no routes)."""
    app = Flask(__name__)
    app.config.from_object(get_config(env))
    app.teardown_appcontext(close_db)
    return app


def open_backend(app: Flask) -> str:
    """Connect, refuse a fallback from MariaDB to SQLite, ensure the schema.

    Returns a description of the backend (never a password).
    """
    db = get_db()
    db_type = g.get("db_type", "sqlite")
    if not app.config.get("USE_SQLITE") and db_type != "mariadb":
        raise BackendError(
            "MariaDB를 쓰도록 설정되어 있지만 연결하지 못했습니다. "
            "SQLite에 대신 쓰지 않도록 중단합니다."
        )
    create_schema(db, db_type)
    if db_type == "mariadb":
        cfg = app.config
        return (f"mariadb ({cfg['DB_USER']}@{cfg['DB_HOST']}:{cfg['DB_PORT']}"
                f"/{cfg['DB_NAME']})")
    return f"sqlite ({os.path.abspath(app.config['SQLITE_PATH'])})"
