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

    # --- Release gate (time-locked s3 path) ---
    # No defaults: an absent value denies the time-locked s3 release
    # (fail-closed). Without POLICY_CA_CERT_PATH no policy can be
    # authenticated, so the standard path runs exactly as in v1.0.1 and
    # admin use is audited as unauthenticated. The legacy TSA_URL above
    # (loopback default) is deliberately not used by the release gate.
    # POLICY_CA_CERT_PATH may hold a PEM bundle (old and new CA after a
    # rotation). Configured paths are validated at start-up.
    POLICY_CA_CERT_PATH: str = os.environ.get("POLICY_CA_CERT_PATH", "")
    # When true, the standard and admin paths also deny any record without
    # an authenticated policy (no record, legacy, or no pinned CA). Off by
    # default for v1.0.1 records; recommended for new deployments. It
    # requires POLICY_CA_CERT_PATH.
    RELEASE_REQUIRE_POLICY: bool = (
        os.environ.get("RELEASE_REQUIRE_POLICY", "false").lower() == "true"
    )
    RELEASE_KMS_MASTER_KEY_PATH: str = os.environ.get(
        "RELEASE_KMS_MASTER_KEY_PATH", ""
    )
    RELEASE_TSA_URL: str = os.environ.get("RELEASE_TSA_URL", "")
    RELEASE_TSA_CERT_PATH: str = os.environ.get("RELEASE_TSA_CERT_PATH", "")
    # Pinned TSA trust profile of the time-locked path (stage E, E2b), both
    # required there: the CA that directly issues the TSA certificate (PEM,
    # one CA or a bundle; pinning the CA lets the TSA rotate its key, but
    # every timeStamping certificate it issues is trusted, so it must be
    # dedicated to the TSA), and the policy OID the TSA's tokens must
    # assert (a deployment pins its own TSA's policy OID; the bundled local
    # TSA uses a placeholder). Tokens must also carry an accuracy.
    # RELEASE_TSA_CERT_PATH above is then an optional extra pin on the TSA
    # certificate itself.
    RELEASE_TSA_CA_CERT_PATH: str = os.environ.get("RELEASE_TSA_CA_CERT_PATH", "")
    RELEASE_TSA_POLICY_OID: str = os.environ.get("RELEASE_TSA_POLICY_OID", "")

    # --- Sync authentication (stage E, E2a) ---
    # A sync submission may carry an envelope signed by the institutional
    # seal-policy key (verified against POLICY_CA_CERT_PATH). A present but
    # invalid signature is always refused. When SYNC_REQUIRE_SIGNATURE is
    # true, unsigned submissions are refused too (401); it needs
    # POLICY_CA_CERT_PATH. Off by default, like RELEASE_REQUIRE_POLICY, so
    # desktops without the institutional key can still sync; recommended
    # for new deployments. sent_at must lie within the window (30-3600 s).
    SYNC_REQUIRE_SIGNATURE: bool = (
        os.environ.get("SYNC_REQUIRE_SIGNATURE", "false").lower() == "true"
    )
    SYNC_SIGNATURE_WINDOW_SECONDS: int = int(
        os.environ.get("SYNC_SIGNATURE_WINDOW_SECONDS", "300")
    )

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
    # Administrators are named accounts (admin_accounts; create them with
    # ``python -m src.web.admin_accounts create <username>``). The v1.0.1
    # shared ADMIN_PASSWORD is not read any more; if it is still set, the
    # app logs a WARNING at start-up that it is ignored.
    AUTH_MAX_FAILURES: int = 5
    AUTH_LOCKOUT_SECONDS: int = 600  # 10 minutes
    # Admin login password checks (scrypt, about 32 MiB each) that may run
    # at once in one process; more concurrent logins get 503. The bound is
    # per process: W worker processes allow W times this many.
    ADMIN_LOGIN_MAX_CONCURRENT: int = int(
        os.environ.get("ADMIN_LOGIN_MAX_CONCURRENT", "4")
    )

    # --- Crypto module path ---
    CRYPTO_MODULE_PATH: str = os.path.join(
        os.path.dirname(__file__), "..", "desktop", "crypto"
    )

    # --- Identity protection (stage E, E3a; see web.privacy.keys) ---
    # Paths only, no defaults. IDENTITY_PEPPER_PATH: a file of 32-1024
    # random bytes, the HMAC key of the subject's identity digests.
    # PRIVACY_KMS_MASTER_KEY_PATH: a 32-byte local-KMS key that wraps the
    # per-seal data keys; it must not be the release master key. Unset, or
    # set but unusable: the app refuses to start.
    IDENTITY_PEPPER_PATH: str = os.environ.get("IDENTITY_PEPPER_PATH", "")
    PRIVACY_KMS_MASTER_KEY_PATH: str = os.environ.get(
        "PRIVACY_KMS_MASTER_KEY_PATH", ""
    )
    # Each OTP delivery decrypts the subject's e-mail and sends mail: at
    # most this many per seal within the window (more answer 429).
    OTP_MAX_DELIVERIES_PER_SEAL: int = 5
    OTP_DELIVERY_WINDOW_SECONDS: int = 600
    # Case-password scrypt work on the public paths (registration and the
    # subject's password factor, about 32 MiB each) that may run at once in
    # one process; more concurrent requests get 503. A pool of its own, so
    # it cannot take the administrators' slots. Per process, like
    # ADMIN_LOGIN_MAX_CONCURRENT.
    CASE_PASSWORD_MAX_CONCURRENT: int = int(
        os.environ.get("CASE_PASSWORD_MAX_CONCURRENT", "4")
    )
    # Registrations that hash a case password: at most this many per client
    # address within the window, reserved before any hashing (more get 429).
    CASE_REGISTRATION_MAX_PER_ADDRESS: int = 10
    CASE_REGISTRATION_WINDOW_SECONDS: int = 600


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
