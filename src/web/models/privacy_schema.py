"""DDL of the identity-protection tables, both schema variants (stage E, E3a).

Executed by :func:`web.models.db_models.create_schema` right after the main
schema script, so ``CREATE TABLE IF NOT EXISTS`` also adds them to an
existing database at start-up. The protected columns of ``cases`` are
declared in the ``cases`` DDL of :mod:`web.models.db_models` and added to
older tables by :mod:`web.models.migrations`.

  - ``seal_data_keys``: one random 256-bit data key per seal, stored only
    wrapped by the privacy master key (:mod:`web.privacy.field_crypto`).
  - ``identity_access_audit``: one row per decryption of a protected
    identity field (seal, field, purpose, actor role, actor, client
    address, outcome, time); never the value itself.
"""

SQLITE_PRIVACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS seal_data_keys (
    seal_id      TEXT    PRIMARY KEY,
    wrapped_key  BLOB    NOT NULL,
    created_at   TEXT    NOT NULL,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
);

CREATE TABLE IF NOT EXISTS identity_access_audit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id        TEXT    NOT NULL,
    field          TEXT    NOT NULL,
    purpose        TEXT    NOT NULL,
    actor_role     TEXT    NOT NULL CHECK(actor_role IN ('subject','admin','system')),
    actor          TEXT    NOT NULL DEFAULT '',
    client_address TEXT    NOT NULL DEFAULT '',
    outcome        TEXT    NOT NULL CHECK(outcome IN ('revealed','failed')),
    created_at     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_access_seal
    ON identity_access_audit (seal_id, id);
"""

MARIADB_PRIVACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS seal_data_keys (
    seal_id      VARCHAR(64)  NOT NULL PRIMARY KEY,
    wrapped_key  BLOB         NOT NULL,
    created_at   VARCHAR(40)  NOT NULL,
    FOREIGN KEY (seal_id) REFERENCES cases(seal_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS identity_access_audit (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    seal_id        VARCHAR(64)  NOT NULL,
    field          VARCHAR(32)  NOT NULL,
    purpose        VARCHAR(32)  NOT NULL,
    actor_role     ENUM('subject','admin','system') NOT NULL,
    actor          VARCHAR(64)  NOT NULL DEFAULT '',
    client_address VARCHAR(45)  NOT NULL DEFAULT '',
    outcome        ENUM('revealed','failed') NOT NULL,
    created_at     VARCHAR(40)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_identity_access_seal
    ON identity_access_audit (seal_id, id);
"""
