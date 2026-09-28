"""Keys of the identity protection: identity pepper and privacy master key.

Both are configured by path, never by value (:mod:`web.config`):

  - ``IDENTITY_PEPPER_PATH``: a file of 32 to 1024 random bytes, used as is
    as the HMAC-SHA256 key of the identity digests
    (:mod:`web.privacy.digests`). Replacing it makes every stored digest
    unmatchable, so it is created once and kept.
  - ``PRIVACY_KMS_MASTER_KEY_PATH``: a 32-byte AES-256 key in the format of
    the local KMS emulation (:func:`desktop.crypto.local_kms.init_master_key`),
    which wraps the per-seal data keys (:mod:`web.privacy.field_crypto`).
    It is a different key from ``RELEASE_KMS_MASTER_KEY_PATH``.

Rules (fail-closed):
  - either key unset, set but unusable (missing, unreadable, wrong size),
    or one key used for two purposes (pepper and privacy master key, or
    privacy key and release master key): :func:`validate_privacy_config`
    raises :class:`PrivacyConfigError` from the app factory and the app
    does not start. An unset key refuses start-up since the Fable gate fix
    for finding 5 (before, start-up logged a WARNING): since E3b, case
    registration, subject authentication, record synchronization and
    every release on a seal with synced records need both keys;
  - at request time, a key file that has become unreadable is
    :class:`PrivacyUnavailable`, logged at ERROR (so is a path cleared on
    a running app, without that log line): the routes answer 503, and the
    release gate denies the attempt as ``internal_error``.

Key material never appears in a log line, an error message or a ``repr``.
"""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from flask import current_app

from desktop.crypto.exceptions import KMSError
from desktop.crypto.local_kms import load_master_key

from .digests import MIN_KEY_BYTES

logger = logging.getLogger(__name__)

DIGEST_KEY_SETTING = "IDENTITY_PEPPER_PATH"
MASTER_KEY_SETTING = "PRIVACY_KMS_MASTER_KEY_PATH"
RELEASE_MASTER_KEY_SETTING = "RELEASE_KMS_MASTER_KEY_PATH"
MIN_DIGEST_KEY_BYTES = MIN_KEY_BYTES
MAX_DIGEST_KEY_BYTES = 1024


class PrivacyError(RuntimeError):
    """Base class of the identity-protection refusals raised at request time."""


class PrivacyUnavailable(PrivacyError):
    """The identity-protection keys are not configured or not readable (503)."""


class PrivacyConfigError(RuntimeError):
    """The configured identity-protection keys are unusable; do not start."""


@dataclass(frozen=True)
class PrivacyKeys:
    """The loaded keys; the key bytes are excluded from ``repr``."""

    pepper: bytes = field(repr=False)
    master_key: bytes = field(repr=False)
    master_key_path: str


def privacy_keys_configured(config: Optional[Mapping[str, Any]] = None) -> bool:
    """Whether both key paths are set (their files are checked at start-up)."""
    digest_path, master_path = _paths(_config(config))
    return bool(digest_path and master_path)


def load_privacy_keys(config: Optional[Mapping[str, Any]] = None) -> PrivacyKeys:
    """Read both keys (from the current app's config by default).

    Raises:
        PrivacyUnavailable: A path is unset, or a key file is unreadable or
            of the wrong size at request time.
    """
    digest_path, master_path = _paths(_config(config))
    if not digest_path or not master_path:
        raise PrivacyUnavailable("identity protection keys are not configured")
    try:
        return PrivacyKeys(
            pepper=_read_digest_key(digest_path),
            master_key=load_master_key(master_path),
            master_key_path=master_path,
        )
    except (OSError, ValueError, KMSError) as exc:
        logger.error("Identity protection key unreadable at request time: %s", exc)
        raise PrivacyUnavailable("identity protection keys are unreadable") from exc


def validate_privacy_config(config: Mapping[str, Any]) -> None:
    """Start-up check of the identity-protection keys (see the module doc).

    Raises:
        PrivacyConfigError: Naming the offending setting and the reason.
    """
    digest_path, master_path = _paths(config)
    digest_key = (_checked(DIGEST_KEY_SETTING, lambda: _read_digest_key(digest_path))
                  if digest_path else None)
    master_key = (_checked(MASTER_KEY_SETTING, lambda: load_master_key(master_path))
                  if master_path else None)
    if _same(digest_key, master_key):
        raise PrivacyConfigError(
            f"{DIGEST_KEY_SETTING} and {MASTER_KEY_SETTING} hold the same key: "
            "the identity protection needs two separate random keys"
        )
    _refuse_release_key_reuse(config, digest_key, master_key)
    missing = [name for name, path in ((DIGEST_KEY_SETTING, digest_path),
                                       (MASTER_KEY_SETTING, master_path)) if not path]
    if missing:
        raise PrivacyConfigError(
            f"{' and '.join(missing)} not set: the web application needs both "
            "identity-protection keys (case registration, subject "
            "authentication, record synchronization and every release on a "
            "seal with synced records use them)"
        )


def _config(config: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    return current_app.config if config is None else config


def _paths(config: Mapping[str, Any]) -> tuple[str, str]:
    return (str(config.get(DIGEST_KEY_SETTING) or "").strip(),
            str(config.get(MASTER_KEY_SETTING) or "").strip())


def _read_digest_key(path: str) -> bytes:
    size = os.path.getsize(path)
    if not MIN_DIGEST_KEY_BYTES <= size <= MAX_DIGEST_KEY_BYTES:
        raise ValueError(
            f"expected {MIN_DIGEST_KEY_BYTES} to {MAX_DIGEST_KEY_BYTES} bytes, "
            f"found {size}"
        )
    with open(path, "rb") as handle:
        data = handle.read(MAX_DIGEST_KEY_BYTES + 1)
    if not MIN_DIGEST_KEY_BYTES <= len(data) <= MAX_DIGEST_KEY_BYTES:
        raise ValueError("the key file changed while it was read")
    return data


def _checked(setting: str, load: Callable[[], bytes]) -> bytes:
    try:
        return load()
    except (OSError, ValueError, KMSError) as exc:
        raise PrivacyConfigError(f"{setting} is configured but unusable: {exc}") from exc


def _same(first: Optional[bytes], second: Optional[bytes]) -> bool:
    return first is not None and second is not None and hmac.compare_digest(first, second)


def _refuse_release_key_reuse(
    config: Mapping[str, Any], digest_key: Optional[bytes], master_key: Optional[bytes]
) -> None:
    release_path = str(config.get(RELEASE_MASTER_KEY_SETTING) or "").strip()
    if not release_path:
        return
    try:
        release_key = load_master_key(release_path)
    except KMSError:
        return  # reported by the release configuration check, which runs first
    for setting, key in ((DIGEST_KEY_SETTING, digest_key),
                         (MASTER_KEY_SETTING, master_key)):
        if _same(key, release_key):
            raise PrivacyConfigError(
                f"{setting} holds the same key as {RELEASE_MASTER_KEY_SETTING}: "
                "the identity protection needs its own key"
            )
