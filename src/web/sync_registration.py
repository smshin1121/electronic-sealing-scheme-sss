"""The signed seal record creates its case (stage F, F2).

Fable gate, finding 4 (accepted and disclosed in v1.1): the sync route
stores a record only for a registered case, and case registration was
unauthenticated, so whoever learned a seal ID first could register it with
identity values of their choosing. The genuine registration was then
refused (409), and the seal's identity binding (the keyed digests its
subject authenticates against) and its data key belonged to that
registration. Since F2 the registration form needs a signed-in
administrator (:func:`web.routes.investigator.register_case`), and the
signed seal record creates its own case (this module), as the separately
operated portal registers a seal from its authenticated record (section 6
of the portal's interface contract).

When the sync route (:mod:`web.routes.sync`) is about to store the record
of a new event of a seal that has no case row, it calls
:func:`create_case_from_record` under the seal's write lock
(:func:`web.models.release_models.seal_write_transaction`), in the
transaction that also claims the envelope's nonce, stores the record and
sets the generation mark: all of them commit together, or none does. The
case is created only when

  - the submission carries a sync envelope that verified
    (:mod:`web.sync_auth`: the institutional seal-policy key's signature
    under a pinned CA, the time window, and the binding to the exact
    request bytes, so the envelope authenticates the whole ``record_json``,
    its ``case_info`` and ``signer_info`` included), and
  - the record's own policy is ``verified`` for the same seal ID. A policy
    whose certificate has only expired, a record without a policy and one
    that cannot be checked (no pinned CA) never create a case.

Otherwise nothing is created and the store refuses the record with 404
(:class:`web.privacy.record_store.CaseNotRegistered`), as before F2; so an
unsigned submission can neither create a case nor pre-empt one. Any event
type can create it: Unsealing and Resealing records carry the sealing
record's ``case_info`` and ``signer_info`` forward, and the first record
the web receives need not be the Sealing one (the desktop queues nothing
for a backend that was not configured when the event was saved).

The case is stored as the administrator's form stores one
(:func:`web.privacy.case_identity.register_protected_case_uncommitted`):

  - ``case_number`` and ``investigator`` from ``case_info``;
  - the subject's name, birth date and phone as keyed digests, and the
    name and e-mail as ciphertexts under a new per-seal data key, from
    ``signer_info``; the plaintext identity columns hold '';
  - ``auth_level`` = ``SYNC_CASE_AUTH_LEVEL``: ``basic`` (the default) or
    ``basic+otp``; no password exists, so no password level and no hash;
  - ``registered_by`` = ``sync:`` and the first 16 hex digits of the
    SHA-256 fingerprint of the certificate that signed the envelope, the
    signature that authenticated these values (the policy signature covers
    only the policy fields). It names the institutional certificate, not
    a person.

The values follow the form's rules (:mod:`web.case_rules`): each must be
text and is stripped; case number and investigator must be non-empty
after stripping, and name, birth date and phone after the normalisation
their digests use (:mod:`web.privacy.digests`); no value may exceed the
form's length limit (values are never truncated); the seal ID may not
start with '@'; the record must name the seal; and with ``basic+otp`` the
e-mail is required, since a subject without one could never receive a
code. A record that breaks any of them is refused with 422
(:class:`SyncCaseRefused`): the transaction rolls back, the nonce claim
included. The answer and the log name the fields, never their values.

An existing case is used as it is, whoever registered it: F2 does not
compare the record's ``signer_info`` with it. Apart from this creation,
the web application does not interpret ``case_info`` or ``signer_info``:
records are stored encrypted, the release gate reads their policy fields,
and a subject sees a record only as a whole, through the audited view of
:mod:`web.privacy.record_access`.

Concurrency: SQLite's write lock (``BEGIN IMMEDIATE``) serialises two
first syncs of a seal; the second finds the case. On MariaDB the lock
taken for a seal without a case row is only a gap lock, which every seal
ID missing from that gap of the index shares, and two first syncs holding
it both reach the insert: one of them fails with a deadlock (1213), a
duplicate key (1062) or a lock wait timeout (1205). Only such an error of
the case row's own insert counts
(:class:`web.models.privacy_models.CaseInsertError`); any other error,
for example on the data key's insert, is a fault (500). That submission
rolls back entirely, nonce included (:class:`SyncCaseRace`), and is
answered 503 with ``Retry-After: 1``; the desktop keeps the record pending
until it is sent again. Two new seals whose IDs fall in the same gap can
collide this way too, not only two submissions of one seal. A submission
that cannot create a case does not take that lock for a seal without a
case row (the sync route refuses it with 404 before the lock), so
unauthenticated traffic cannot hold it.

Identity values never reach a log line, an answer or an exception.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from flask import current_app, g, jsonify

from desktop.signature.sync_envelope import VerifiedSyncEnvelope

from .case_rules import FIELD_LIMITS, PASSWORDLESS_AUTH_LEVELS, RESERVED_SEAL_PREFIX
from .models.privacy_models import CaseInsertError, case_exists
from .privacy.case_identity import CaseRegistration, register_protected_case_uncommitted
from .privacy.digests import normalize_birth_date, normalize_name, normalize_phone

logger = logging.getLogger(__name__)

AUTH_LEVEL_SETTING = "SYNC_CASE_AUTH_LEVEL"
DEFAULT_AUTH_LEVEL = "basic"
SYNC_REGISTRAR = "sync"
FINGERPRINT_PREFIX_HEX = 16
RETRY_AFTER_SECONDS = 1
_LOG_ID_LIMIT = 200

# MariaDB errors of a case insert that lost to a concurrent first sync:
# duplicate key, lock wait timeout, deadlock (with their message texts, for
# a driver that does not expose the number).
_RACE_ERRNOS = frozenset({1062, 1205, 1213})
_RACE_TEXTS = ("Duplicate entry", "Lock wait timeout exceeded", "Deadlock found")

_MSG_REFUSED = (
    "서명된 봉인 기록으로 사건을 만들 수 없습니다. 비어 있거나 올바르지 않거나 "
    "너무 긴 항목: {fields}"
)
_MSG_RACE = (
    "같은 때 들어온 다른 동기화 요청과 사건 등록이 겹쳐 저장하지 않았습니다. "
    "잠시 후 다시 보내 주세요."
)
_MSG_UNAVAILABLE = (
    "서버의 사건 자동 등록 설정이 올바르지 않아 기록을 저장할 수 없습니다. "
    "관리자에게 문의해 주세요."
)


class SyncCaseConfigError(RuntimeError):
    """``SYNC_CASE_AUTH_LEVEL`` is unusable; the app must not start."""


class SyncCaseError(Exception):
    """A signed record could not create its case; its transaction rolls back.

    ``status`` and ``message`` are the sync route's answer; the message
    names no identity value.
    """

    status = 503
    retry_after: Optional[int] = None

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def response(self) -> tuple[Any, int]:
        """The JSON answer, with ``Retry-After`` when a retry may succeed."""
        resp = jsonify({"status": "error", "message": self.message})
        if self.retry_after is not None:
            resp.headers["Retry-After"] = str(self.retry_after)
        return resp, self.status


class SyncCaseRefused(SyncCaseError):
    """422: a value the case needs is missing, not text or too long."""

    status = 422

    def __init__(self, fields: tuple[str, ...]) -> None:
        super().__init__(_MSG_REFUSED.format(fields=", ".join(fields)))
        self.fields = fields


class SyncCaseRace(SyncCaseError):
    """503: a concurrent first sync won the case insert (MariaDB)."""

    retry_after = RETRY_AFTER_SECONDS

    def __init__(self) -> None:
        super().__init__(_MSG_RACE)


class SyncCaseUnavailable(SyncCaseError):
    """503: ``SYNC_CASE_AUTH_LEVEL`` became unusable after start-up."""

    def __init__(self) -> None:
        super().__init__(_MSG_UNAVAILABLE)


@dataclass(frozen=True)
class _Field:
    """One value the case takes from the record."""

    section: str
    key: str
    name: str  # the registration field (web.case_rules.FIELD_LIMITS)
    required: Optional[Callable[[object], str]]  # the digests' normaliser

    @property
    def path(self) -> str:
        return f"{self.section}.{self.key}"


def _stripped(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


_FIELDS = (
    _Field("case_info", "case_number", "case_number", _stripped),
    _Field("case_info", "investigator", "investigator", _stripped),
    _Field("signer_info", "name", "suspect_name", normalize_name),
    _Field("signer_info", "birth_date", "suspect_birth", normalize_birth_date),
    _Field("signer_info", "phone", "suspect_phone", normalize_phone),
    _Field("signer_info", "email", "suspect_email", None),
)


def validate_sync_case_config(config: Mapping[str, Any]) -> None:
    """Refuse start-up on an unusable ``SYNC_CASE_AUTH_LEVEL``.

    Raises:
        SyncCaseConfigError: When it is not ``basic`` or ``basic+otp``.
    """
    sync_case_auth_level(config)


def sync_case_auth_level(config: Mapping[str, Any]) -> str:
    """The authentication level of cases created by signed records.

    ``basic`` when unset; surrounding whitespace is ignored.

    Raises:
        SyncCaseConfigError: When the value is not a passwordless level.
    """
    value = config.get(AUTH_LEVEL_SETTING, DEFAULT_AUTH_LEVEL)
    level = value.strip() if isinstance(value, str) else ""
    if level not in PASSWORDLESS_AUTH_LEVELS:
        raise SyncCaseConfigError(
            f"{AUTH_LEVEL_SETTING} must be one of "
            f"{', '.join(PASSWORDLESS_AUTH_LEVELS)} (a case created by a signed "
            f"record has no password), not {value!r}")
    return level


def create_case_from_record(
    seal_id: str,
    event_id: int,
    record: Any,
    envelope: Optional[VerifiedSyncEnvelope],
    *,
    policy_verified: bool,
) -> bool:
    """Create the seal's missing case from its signed record (no commit).

    Call under the seal's write lock, right before the record is stored.

    Returns:
        ``True`` when the case was created. ``False`` when the case exists,
        or when the submission cannot create one (no verified envelope, or
        a policy that is not ``verified``); without a case the store then
        refuses the record (``CaseNotRegistered``, 404).

    Raises:
        SyncCaseRefused: A value breaks a registration rule (422).
        SyncCaseRace: A concurrent first sync won the insert (MariaDB; 503).
        SyncCaseUnavailable: ``SYNC_CASE_AUTH_LEVEL`` is unusable (503).
        PrivacyUnavailable: The privacy keys are not readable (503).
    """
    if envelope is None or not policy_verified or case_exists(seal_id):
        return False
    level = _auth_level_now()
    registration = _registration(seal_id, event_id, record, level, envelope)
    try:
        register_protected_case_uncommitted(registration)
    except Exception as exc:
        if not _lost_to_concurrent_insert(exc):
            raise
        logger.warning(
            "Sync refused (503): the case insert of seal_id=%r event_id=%s lost "
            "to a concurrent submission (MariaDB error %s); rolled back, nonce "
            "included; the client may send it again", seal_id[:_LOG_ID_LIMIT],
            event_id, getattr(exc.__cause__, "errno", "?"))
        raise SyncCaseRace() from exc
    logger.info("Case created from a signed seal record: seal_id=%r event_id=%s "
                "auth_level=%s registered_by=%s", seal_id[:_LOG_ID_LIMIT],
                event_id, level, registration.registered_by)
    return True


def _auth_level_now() -> str:
    """The configured level at request time (validated at start-up too)."""
    try:
        return sync_case_auth_level(current_app.config)
    except SyncCaseConfigError as exc:
        logger.error("Sync refused (503): %s; no case created", exc)
        raise SyncCaseUnavailable() from exc


def _registration(
    seal_id: str, event_id: int, record: Any, level: str,
    envelope: VerifiedSyncEnvelope,
) -> CaseRegistration:
    """The registration the record describes, or :class:`SyncCaseRefused`."""
    values, problems = _record_values(record)
    problems += _seal_problems(seal_id, record)
    if "otp" in level.split("+") and "suspect_email" in values and (
        not values["suspect_email"]
    ):
        problems.append(("signer_info.email", f"missing, required for {level}"))
    if problems:
        logger.warning(
            "Sync refused (422): the signed record cannot create its case "
            "(seal_id=%r event_id=%s): %s", seal_id[:_LOG_ID_LIMIT], event_id,
            "; ".join(f"{path} {reason}" for path, reason in problems))
        raise SyncCaseRefused(tuple(dict.fromkeys(path for path, _ in problems)))
    return CaseRegistration(
        seal_id=seal_id, case_number=values["case_number"],
        investigator=values["investigator"], name=values["suspect_name"],
        email=values["suspect_email"], birth=values["suspect_birth"],
        phone=values["suspect_phone"], auth_level=level, password_hash="",
        registered_by=f"{SYNC_REGISTRAR}:"
                      f"{envelope.cert_fingerprint[:FINGERPRINT_PREFIX_HEX]}",
    )


def _record_values(record: Any) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """The stripped values by registration field, and the fields refused."""
    values: dict[str, str] = {}
    problems: list[tuple[str, str]] = []
    for spec in _FIELDS:
        text, reason = _field_text(record, spec)
        if reason:
            problems.append((spec.path, reason))
        else:
            values[spec.name] = text
    return values, problems


def _field_text(record: Any, spec: _Field) -> tuple[str, str]:
    """One field's stripped text, or '' and why it cannot be used."""
    section = record.get(spec.section) if isinstance(record, Mapping) else None
    raw = section.get(spec.key) if isinstance(section, Mapping) else None
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        return "", "is not text"
    text = raw.strip()
    limit = FIELD_LIMITS[spec.name]
    if len(text) > limit:
        return "", f"is longer than {limit} characters"
    if spec.required is not None and not spec.required(text):
        return "", "is missing or empty"
    return text, ""


def _seal_problems(seal_id: str, record: Any) -> list[tuple[str, str]]:
    """The seal ID's rules: not reserved, within the limit, named by the record."""
    problems: list[tuple[str, str]] = []
    if seal_id.startswith(RESERVED_SEAL_PREFIX):
        problems.append(("seal_id", f"starts with the reserved {RESERVED_SEAL_PREFIX!r}"))
    if len(seal_id) > FIELD_LIMITS["seal_id"]:
        problems.append(("seal_id", f"is longer than {FIELD_LIMITS['seal_id']} characters"))
    named = record.get("seal_id") if isinstance(record, Mapping) else None
    if named != seal_id:
        problems.append(("seal_id", "differs from the seal the record names"))
    return problems


def _lost_to_concurrent_insert(exc: BaseException) -> bool:
    """Whether the case row's own insert lost to another first sync.

    Only :class:`CaseInsertError` counts, and only with a duplicate key, a
    lock wait timeout or a deadlock as its cause, on MariaDB: SQLite's write
    lock excludes the race, and any other error (the data key's insert
    included) is a fault (500).
    """
    if g.get("db_type") != "mariadb" or not isinstance(exc, CaseInsertError):
        return False
    cause = exc.__cause__
    if getattr(cause, "errno", None) in _RACE_ERRNOS:
        return True
    return any(text in str(cause) for text in _RACE_TEXTS)
