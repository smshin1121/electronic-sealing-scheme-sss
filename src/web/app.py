"""Flask application factory for the remote participation system.

Usage::

    from src.web.app import create_app
    app = create_app()          # uses FLASK_ENV or defaults to 'development'
    app = create_app("testing") # explicit environment
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any

from flask import Flask, jsonify, render_template, request

from .config import get_config
from .models.db_models import close_db, init_db

logger = logging.getLogger(__name__)


def create_app(config_env: str | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_env: Environment name ('development', 'production', 'testing').
                    Falls back to FLASK_ENV env var, then 'development'.

    Returns:
        Configured Flask app instance.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    cfg = get_config(config_env)
    app.config.from_object(cfg)

    # ------------------------------------------------------------------
    # CSRF protection
    # ------------------------------------------------------------------
    _setup_csrf(app)

    # ------------------------------------------------------------------
    # OTP service configuration
    # ------------------------------------------------------------------
    from .auth.otp_service import OTPService

    OTPService.configure(
        otp_length=app.config.get("OTP_LENGTH", 6),
        expiry_seconds=app.config.get("OTP_EXPIRY_SECONDS", 300),
        smtp_host=app.config.get("SMTP_HOST", "localhost"),
        smtp_port=app.config.get("SMTP_PORT", 587),
        smtp_user=app.config.get("SMTP_USER", ""),
        smtp_password=app.config.get("SMTP_PASSWORD", ""),
        smtp_from=app.config.get("SMTP_FROM", "seal-system@example.com"),
        smtp_use_tls=app.config.get("SMTP_USE_TLS", True),
        smtp_mock=app.config.get("SMTP_MOCK", True),
        smtp_timeout=app.config.get("SMTP_TIMEOUT_SECONDS", 10),
    )

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    from .routes.investigator import bp as investigator_bp
    from .routes.suspect import bp as suspect_bp
    from .routes.admin import bp as admin_bp
    from .routes.sync import bp as sync_bp

    app.register_blueprint(investigator_bp)
    app.register_blueprint(suspect_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(sync_bp)

    # ------------------------------------------------------------------
    # Database lifecycle
    # ------------------------------------------------------------------
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db(app)

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------
    _register_error_handlers(app)

    # ------------------------------------------------------------------
    # Index redirect
    # ------------------------------------------------------------------
    @app.route("/")
    def index() -> Any:
        return render_template("base.html")

    logger.info("Flask app created (env=%s)", config_env or "default")
    return app


# ======================================================================
# CSRF protection (manual token approach — no flask-wtf dependency)
# ======================================================================

def _setup_csrf(app: Flask) -> None:
    """Register a before_request hook that validates a CSRF token
    on state-changing methods (POST, PUT, DELETE, PATCH).

    The token is stored in ``session['csrf_token']`` and must be
    submitted as a form field ``csrf_token`` or header ``X-CSRF-Token``.
    """

    @app.before_request
    def _csrf_protect() -> Any:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None

        # Skip CSRF for JSON API endpoints (sync uses its own auth)
        if request.is_json:
            return None

        from flask import session

        token = session.get("csrf_token", "")
        submitted = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or ""
        )

        if not token or not secrets.compare_digest(token, submitted):
            from flask import abort

            abort(403)

        return None

    @app.context_processor
    def _inject_csrf_token() -> dict[str, str]:
        from flask import session

        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return {"csrf_token": session["csrf_token"]}


# ======================================================================
# Error handlers (no internal information leakage)
# ======================================================================

def _wants_json_error() -> bool:
    """Return True when the current request should get a JSON error body."""
    if request.path.startswith("/sync/"):
        return True
    if request.is_json:
        return True
    return "application/json" in (request.headers.get("Accept") or "")


def _register_error_handlers(app: Flask) -> None:
    """Register custom error pages."""

    @app.errorhandler(400)
    def bad_request(e: Exception) -> tuple[str, int]:
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(e: Exception) -> tuple[str, int]:
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e: Exception) -> tuple[str, int]:
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def payload_too_large(e: Exception) -> Any:
        # Sync endpoints and JSON clients must receive a JSON error body
        # (Werkzeug's default HTML 413 breaks the sync client's JSON contract).
        if _wants_json_error():
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "요청 본문이 허용 크기를 초과했습니다.",
                    }
                ),
                413,
            )
        return e  # keep default Werkzeug behavior for browser clients

    @app.errorhandler(429)
    def too_many_requests(e: Exception) -> tuple[str, int]:
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(e: Exception) -> tuple[str, int]:
        logger.exception("Internal server error")
        return render_template("errors/500.html"), 500
