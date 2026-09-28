"""The subject's identity in the case table: protect, match, reveal (E3a).

  - :func:`register_protected_case` computes the keyed digests of name,
    birth date and phone and encrypts name and e-mail under a new per-seal
    data key, then stores the case row and the wrapped data key in one
    transaction. The plaintext columns hold ''.
  - :func:`verify_basic_identity` digests the submitted name, birth date
    and phone and compares all three with the stored digests
    (:func:`web.privacy.digests.digest_matches`, constant time, no early
    exit). A case whose identity was never converted
    (``identity_scheme != 'v1'``) is refused, never compared in plaintext.
  - :func:`reveal_case_field` decrypts the name or e-mail for a named
    purpose and appends an ``identity_access_audit`` row. If that row
    cannot be written, the value is withheld (:class:`IdentityAuditError`).
    A failed decryption is audited as ``failed`` where possible.

Every function needs both identity-protection keys and raises
:class:`web.privacy.keys.PrivacyUnavailable` without them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from ..models.privacy_models import (
    ACTOR_ROLES,
    ENCRYPTED_FIELDS,
    IDENTITY_SCHEME_V1,
    OUTCOME_FAILED,
    OUTCOME_REVEALED,
    IdentityAccessEntry,
    NewCase,
    ProtectedIdentity,
    count_recent_reveals,
    find_encrypted_field,
    find_wrapped_data_key,
    insert_identity_access,
    insert_protected_case,
)
from .digests import (
    FIELD_BIRTH,
    FIELD_NAME,
    FIELD_PHONE,
    digest_matches,
    identity_digest,
)
from .field_crypto import (
    FieldCryptoError,
    decrypt_field,
    encrypt_field,
    new_data_key,
    unwrap_data_key,
    wrap_data_key,
)
from .keys import PrivacyError, PrivacyKeys, PrivacyUnavailable, load_privacy_keys

logger = logging.getLogger(__name__)

CASES_TABLE = "cases"
PURPOSE_CODE_DELIVERY = "otp_delivery"
PURPOSE_MIGRATION_CHECK = "migration_verify"
PURPOSES = (PURPOSE_CODE_DELIVERY, PURPOSE_MIGRATION_CHECK)


class LegacyIdentityError(PrivacyError):
    """The case still holds its identity in plaintext (run the migration)."""


class IdentityAuditError(PrivacyError):
    """The access-audit row could not be written; the value is withheld."""


@dataclass(frozen=True)
class CaseRegistration:
    """A case to register; the identity values are never stored as given."""

    seal_id: str
    case_number: str
    investigator: str
    name: str = field(repr=False)
    email: str = field(default="", repr=False)
    birth: str = field(default="", repr=False)
    phone: str = field(default="", repr=False)
    auth_level: str = "basic"
    password_hash: str = field(default="", repr=False)


def register_protected_case(registration: CaseRegistration) -> int:
    """Store a new case with its identity protected; returns the row id.

    Raises:
        PrivacyUnavailable: The identity-protection keys are not configured.
    """
    keys = load_privacy_keys()
    seal_id = registration.seal_id
    data_key = new_data_key()
    identity = protect_identity(
        keys.pepper, data_key, seal_id, name=registration.name,
        email=registration.email, birth=registration.birth,
        phone=registration.phone,
    )
    try:
        # local_kms wraps from the key file, which is read again here.
        wrapped = wrap_data_key(data_key, keys.master_key_path, seal_id)
    except FieldCryptoError as exc:
        raise PrivacyUnavailable("the privacy master key became unreadable") from exc
    case = NewCase(
        seal_id=seal_id, case_number=registration.case_number,
        investigator=registration.investigator,
        auth_level=registration.auth_level,
        password_hash=registration.password_hash, identity=identity,
    )
    case_id = insert_protected_case(case, wrapped, utc_now_iso())
    logger.info("Case registered with a protected identity: seal_id=%r", seal_id[:200])
    return case_id


def protect_identity(
    pepper: bytes, data_key: bytes, seal_id: str, *,
    name: str, email: str, birth: str, phone: str,
) -> ProtectedIdentity:
    """Digests of name, birth date and phone; ciphertexts of name and e-mail."""
    return ProtectedIdentity(
        name_digest=identity_digest(pepper, FIELD_NAME, seal_id, name),
        birth_digest=identity_digest(pepper, FIELD_BIRTH, seal_id, birth),
        phone_digest=identity_digest(pepper, FIELD_PHONE, seal_id, phone),
        name_enc=_encrypt_optional(data_key, seal_id, "suspect_name", name),
        email_enc=_encrypt_optional(data_key, seal_id, "suspect_email", email),
    )


def load_seal_data_key(seal_id: str, keys: Optional[PrivacyKeys] = None) -> bytes:
    """Unwrap the data key of a seal.

    Raises:
        PrivacyUnavailable: The keys are not configured.
        FieldCryptoError: No data key is stored, or it does not unwrap.
    """
    keys = keys or load_privacy_keys()
    wrapped = find_wrapped_data_key(seal_id)
    if wrapped is None:
        raise FieldCryptoError("no data key is stored for this seal")
    return unwrap_data_key(wrapped, keys.master_key, seal_id)


def verify_basic_identity(
    case: Mapping[str, Any], name: object, birth: object, phone: object
) -> bool:
    """Whether the submitted name, birth date and phone match the case.

    All three digests are computed and all three compared before the
    result is combined.

    Raises:
        PrivacyUnavailable: The keys are not configured.
        LegacyIdentityError: The case's identity was never converted.
    """
    keys = load_privacy_keys()
    if case.get("identity_scheme") != IDENTITY_SCHEME_V1:
        raise LegacyIdentityError("the case identity is not protected yet")
    seal_id = str(case.get("seal_id") or "")
    pairs = (
        (case.get("suspect_name_digest"), identity_digest(keys.pepper, FIELD_NAME, seal_id, name)),
        (case.get("suspect_birth_digest"), identity_digest(keys.pepper, FIELD_BIRTH, seal_id, birth)),
        (case.get("suspect_phone_digest"), identity_digest(keys.pepper, FIELD_PHONE, seal_id, phone)),
    )
    results = [digest_matches(stored, candidate) for stored, candidate in pairs]
    return all(results)


def reveal_case_field(
    seal_id: str, field_name: str, *, purpose: str, actor_role: str,
    actor: str = "", client_address: str = "",
) -> str:
    """Decrypt ``suspect_name`` or ``suspect_email`` of a case, audited.

    Returns '' when the case or the value does not exist (nothing is
    decrypted then, and nothing is audited).

    Raises:
        ValueError: An unknown field, purpose or actor role.
        PrivacyUnavailable: The keys are not configured.
        FieldCryptoError: The value does not decrypt (moved, tampered or
            another key); audited as ``failed`` where possible.
        IdentityAuditError: The audit row could not be written; the value
            is withheld.
    """
    _check_access_request(field_name, purpose, actor_role)
    keys = load_privacy_keys()
    stored = find_encrypted_field(seal_id, field_name)
    if not stored:
        return ""
    entry = IdentityAccessEntry(
        seal_id=seal_id, field_name=field_name, purpose=purpose,
        actor_role=actor_role, outcome=OUTCOME_REVEALED,
        created_at=utc_now_iso(), actor=actor, client_address=client_address,
    )
    try:
        value = decrypt_field(load_seal_data_key(seal_id, keys), CASES_TABLE,
                              seal_id, ENCRYPTED_FIELDS[field_name], stored)
    except FieldCryptoError:
        _audit_failed_decryption(entry)
        raise
    _audit_or_withhold(entry)
    return value


def recent_reveals(seal_id: str, purpose: str, window_seconds: int) -> int:
    """Successful decryptions of a seal for ``purpose`` within the window."""
    since = datetime.now(tz=timezone.utc) - timedelta(seconds=window_seconds)
    return count_recent_reveals(seal_id, purpose, since.isoformat(timespec="seconds"))


def utc_now_iso() -> str:
    """The current UTC time, ISO 8601 to the second."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def _encrypt_optional(data_key: bytes, seal_id: str, field_name: str, value: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        return ""
    return encrypt_field(data_key, CASES_TABLE, seal_id, ENCRYPTED_FIELDS[field_name], text)


def _check_access_request(field_name: str, purpose: str, actor_role: str) -> None:
    if field_name not in ENCRYPTED_FIELDS:
        raise ValueError(f"not an encrypted identity field: {field_name!r}")
    if purpose not in PURPOSES:
        raise ValueError(f"not a permitted purpose: {purpose!r}")
    if actor_role not in ACTOR_ROLES:
        raise ValueError(f"not an actor role: {actor_role!r}")


def _audit_or_withhold(entry: IdentityAccessEntry) -> None:
    try:
        insert_identity_access(entry)
    except Exception as exc:
        logger.error(
            "Identity access audit write failed; value withheld: seal_id=%r "
            "field=%s purpose=%s", entry.seal_id[:200], entry.field_name, entry.purpose,
        )
        raise IdentityAuditError("the identity access could not be audited") from exc
    logger.info("Identity field revealed: seal_id=%r field=%s purpose=%s actor_role=%s",
                entry.seal_id[:200], entry.field_name, entry.purpose, entry.actor_role)


def _audit_failed_decryption(entry: IdentityAccessEntry) -> None:
    logger.warning("Identity field did not decrypt: seal_id=%r field=%s purpose=%s",
                   entry.seal_id[:200], entry.field_name, entry.purpose)
    try:
        insert_identity_access(replace(entry, outcome=OUTCOME_FAILED))
    except Exception:
        logger.exception("Identity access audit write failed for a failed decryption")
