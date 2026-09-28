"""Rules shared by the two ways a case is registered (stage F, F2).

A case is registered by a signed-in administrator through the form
(:func:`web.routes.investigator.register_case`) or created by its signed
seal record on the first sync (:mod:`web.sync_registration`). Both apply:

  - :data:`FIELD_LIMITS`, the v1.0.1 MariaDB column sizes, checked before
    any write; a longer value is refused, never truncated. The identity
    columns now hold '' (the values are digests and ciphertexts), but the
    seal ID is also the associated data of the ciphertexts and the case
    number and investigator are stored as given, so MariaDB must never
    store them truncated;
  - :data:`RESERVED_SEAL_PREFIX`: a seal ID may not start with '@', since
    the admin login and the registration budget count attempts under
    '@'-keys in ``auth_failures``;
  - :data:`AUTH_LEVELS`: every level includes the basic identity check. A
    case created from a signed record has no password, so it may only get
    one of :data:`PASSWORDLESS_AUTH_LEVELS`.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

FIELD_LIMITS: Mapping[str, int] = MappingProxyType({
    "seal_id": 64,
    "case_number": 128,
    "investigator": 128,
    "suspect_name": 128,
    "suspect_email": 256,
    "suspect_birth": 16,
    "suspect_phone": 32,
})
RESERVED_SEAL_PREFIX = "@"
AUTH_LEVELS = ("basic", "basic+password", "basic+otp", "basic+password+otp")
PASSWORDLESS_AUTH_LEVELS = tuple(
    level for level in AUTH_LEVELS if "password" not in level.split("+")
)
