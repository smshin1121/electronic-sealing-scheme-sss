"""Configuration for the web remote participation system."""

from __future__ import annotations

import os
import secrets


# Default request body size limit: 50 MB (seal record PDFs included)
DEFAULT_MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024


class BaseConfig:
    """Base configuration with defaults."""

    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # --- Request limits ---
    MAX_CONTENT_LENGTH: int = int(
        os.environ.get("MAX_CONTENT_LENGTH", str(DEFAULT_MAX_CONTENT_LENGTH))
    )

    # --- Database ---
    # MariaDB (primary)
    DB_HOST: str = os.environ.get("DB_HOST", "127.0.0.1")
    DB_PORT: int = int(os.environ.get("DB_PORT", "3306"))
    DB_USER: str = os.environ.get("DB_USER", "enc_envelope")
    DB_PASSWORD: str = os.environ.get("DB_PASSWORD", "")
    DB_NAME: str = os.environ.get("DB_NAME", "enc_envelope")
    DB_POOL_SIZE: int = int(os.environ.get("DB_POOL_SIZE", "5"))

    # SQLite fallback (when MariaDB is not available)
    SQLITE_PATH: str = os.environ.get(
        "SQLITE_PATH",
        os.path.join(os.path.dirname(__file__), "..", "..", "output", "web.db"),
    )
    USE_SQLITE: bool = os.environ.get("USE_SQLITE", "false").lower() == "true"

    # --- TSA ---
    TSA_URL: str = os.environ.get("TSA_URL", "http://127.0.0.1:8318/tsa")

    # --- OTP ---
    OTP_LENGTH: int = 6
    OTP_EXPIRY_SECONDS: int = 300  # 5 minutes

    # --- SMTP (for OTP emails) ---
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "localhost")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.environ.get("SMTP_FROM", "seal-system@example.com")
    SMTP_USE_TLS: bool = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
    SMTP_MOCK: bool = os.environ.get("SMTP_MOCK", "true").lower() == "true"
    SMTP_TIMEOUT_SECONDS: int = int(os.environ.get("SMTP_TIMEOUT_SECONDS", "10"))

    # --- Auth ---
    ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "")
    AUTH_MAX_FAILURES: int = 5
    AUTH_LOCKOUT_SECONDS: int = 600  # 10 minutes

    # --- Crypto module path ---
    CRYPTO_MODULE_PATH: str = os.path.join(
        os.path.dirname(__file__), "..", "desktop", "crypto"
    )


class DevelopmentConfig(BaseConfig):
    """Development configuration."""

    DEBUG: bool = True
    USE_SQLITE: bool = True
    SMTP_MOCK: bool = True


class ProductionConfig(BaseConfig):
    """Production configuration."""

    DEBUG: bool = False
    SESSION_COOKIE_SECURE: bool = True


class TestingConfig(BaseConfig):
    """Testing configuration."""

    TESTING: bool = True
    USE_SQLITE: bool = True
    SMTP_MOCK: bool = True


CONFIG_MAP: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(env: str | None = None) -> BaseConfig:
    """Return configuration instance for the given environment.

    Args:
        env: Environment name. Falls back to FLASK_ENV env var, then 'development'.

    Returns:
        A config instance.
    """
    env_name = env or os.environ.get("FLASK_ENV", "development")
    config_cls = CONFIG_MAP.get(env_name, DevelopmentConfig)
    return config_cls()
