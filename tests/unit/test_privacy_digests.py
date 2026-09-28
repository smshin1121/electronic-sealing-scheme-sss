"""Keyed identity digests (stage E, E3a).

The subject's name, birth date and phone number are matched by
HMAC-SHA256 digests under a server pepper. The message is length-framed
and names a domain, the field and the seal ID, so a digest is separated by
field and bound to its seal. Inputs are normalised first: name to Unicode
NFC with surrounding whitespace removed and inner runs collapsed to one
space (case is kept), birth date to its digits (``YYYYMMDD``), phone to its
digits. An input with nothing left after normalisation has no digest, and
an empty or malformed stored digest never matches. Synthetic values only;
peppers are generated per test.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import unicodedata

import pytest

from web.privacy.digests import (
    FIELD_BIRTH,
    FIELD_NAME,
    FIELD_PHONE,
    digest_matches,
    identity_digest,
    normalize_birth_date,
    normalize_name,
    normalize_phone,
)

SEAL = "S-20260928-DIG001"


@pytest.fixture()
def pepper() -> bytes:
    return os.urandom(32)


class TestNormalisation:
    def test_name_is_trimmed_and_inner_whitespace_collapsed(self) -> None:
        assert normalize_name("  홍  길동 ") == "홍 길동"
        assert normalize_name("홍\t길동\n") == "홍 길동"
        assert normalize_name("홍　길동") == "홍 길동"

    def test_name_is_nfc(self) -> None:
        decomposed = unicodedata.normalize("NFD", "홍길동")
        assert decomposed != "홍길동"
        assert normalize_name(decomposed) == "홍길동"

    def test_name_keeps_case(self) -> None:
        assert normalize_name("Hong Gil-dong") != normalize_name("hong gil-dong")

    def test_phone_keeps_digits_only(self) -> None:
        for raw in ("010-1234-5678", "01012345678", "010 1234 5678",
                    "(010) 1234.5678", "０１０-１２３４-５６７８"):
            assert normalize_phone(raw) == "01012345678", raw

    def test_birth_date_keeps_digits_only(self) -> None:
        for raw in ("1990-01-01", "19900101", " 1990.01.01 ", "１９９０-０１-０１"):
            assert normalize_birth_date(raw) == "19900101", raw

    def test_non_text_normalises_to_empty(self) -> None:
        for normalise in (normalize_name, normalize_phone, normalize_birth_date):
            assert normalise(None) == ""
            assert normalise(19900101) == ""


class TestDigest:
    def test_digest_is_lowercase_hex_sha256(self, pepper) -> None:
        digest = identity_digest(pepper, FIELD_NAME, SEAL, "홍길동")
        assert len(digest) == 64
        assert digest == digest.lower()
        int(digest, 16)

    def test_construction_is_framed_hmac_sha256(self, pepper) -> None:
        def frame(*parts: bytes) -> bytes:
            return b"".join(struct.pack(">I", len(p)) + p for p in parts)

        expected = hmac.new(
            pepper,
            frame(b"ESS-IDENTITY-DIGEST-v1", b"phone", SEAL.encode(), b"01012345678"),
            hashlib.sha256,
        ).hexdigest()
        assert identity_digest(pepper, FIELD_PHONE, SEAL, "010-1234-5678") == expected

    def test_formatting_variants_have_one_digest(self, pepper) -> None:
        assert (identity_digest(pepper, FIELD_BIRTH, SEAL, "1990-01-01")
                == identity_digest(pepper, FIELD_BIRTH, SEAL, "19900101"))
        assert (identity_digest(pepper, FIELD_PHONE, SEAL, "010-1234-5678")
                == identity_digest(pepper, FIELD_PHONE, SEAL, "01012345678"))
        assert (identity_digest(pepper, FIELD_NAME, SEAL, " 홍  길동")
                == identity_digest(pepper, FIELD_NAME, SEAL, "홍 길동"))

    def test_fields_are_domain_separated(self, pepper) -> None:
        same_value = "19900101"
        assert (identity_digest(pepper, FIELD_BIRTH, SEAL, same_value)
                != identity_digest(pepper, FIELD_PHONE, SEAL, same_value))

    def test_digest_is_bound_to_the_seal(self, pepper) -> None:
        assert (identity_digest(pepper, FIELD_PHONE, SEAL, "01012345678")
                != identity_digest(pepper, FIELD_PHONE, "S-20260928-DIG002", "01012345678"))

    def test_a_different_pepper_gives_a_different_digest(self, pepper) -> None:
        other = os.urandom(32)
        for field, value in ((FIELD_NAME, "홍길동"), (FIELD_BIRTH, "19900101"),
                             (FIELD_PHONE, "01012345678")):
            assert (identity_digest(pepper, field, SEAL, value)
                    != identity_digest(other, field, SEAL, value))

    def test_nothing_left_after_normalisation_has_no_digest(self, pepper) -> None:
        assert identity_digest(pepper, FIELD_PHONE, SEAL, "-") == ""
        assert identity_digest(pepper, FIELD_BIRTH, SEAL, "abc") == ""
        assert identity_digest(pepper, FIELD_NAME, SEAL, "   ") == ""

    def test_unknown_field_is_refused(self, pepper) -> None:
        with pytest.raises(ValueError):
            identity_digest(pepper, "email", SEAL, "x@example.org")

    def test_short_pepper_is_refused(self) -> None:
        with pytest.raises(ValueError):
            identity_digest(os.urandom(31), FIELD_NAME, SEAL, "홍길동")


class TestDigestMatches:
    def test_equal_digests_match(self, pepper) -> None:
        digest = identity_digest(pepper, FIELD_NAME, SEAL, "홍길동")
        assert digest_matches(digest, digest) is True

    def test_different_digests_do_not_match(self, pepper) -> None:
        assert digest_matches(identity_digest(pepper, FIELD_NAME, SEAL, "홍길동"),
                              identity_digest(pepper, FIELD_NAME, SEAL, "김철수")) is False

    def test_empty_digests_never_match(self) -> None:
        # hmac.compare_digest(b"", b"") is True; the matcher must refuse it.
        assert digest_matches("", "") is False

    def test_malformed_stored_values_never_match(self, pepper) -> None:
        digest = identity_digest(pepper, FIELD_NAME, SEAL, "홍길동")
        for stored in (digest.upper(), digest[:-1], "g" * 64, "홍" * 64, None, 7):
            assert digest_matches(stored, digest) is False, stored
            assert digest_matches(stored, stored) is False, stored
