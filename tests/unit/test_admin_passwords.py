"""Administrator password hashing (stage E, E4).

scrypt with a random 16-byte salt per hash. The algorithm and its cost
parameters are stored with the hash; verification reads them back within
fixed bounds and compares the derived key in constant time. A password
shorter than 12 characters is refused. Every password here is generated
per test (synthetic).
"""

from __future__ import annotations

import hashlib
import secrets

import pytest

from web.auth import passwords
from web.auth.passwords import (
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    verify_password,
)


def _password() -> str:
    return secrets.token_urlsafe(18)  # 24 characters


def _encode(password: str, *, n: int, r: int = 8, p: int = 1) -> str:
    """A hash built outside the module, with chosen parameters."""
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                         maxmem=4 * 128 * r * n, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${key.hex()}"


class TestHashing:
    def test_hash_records_algorithm_and_parameters(self) -> None:
        encoded = hash_password(_password())

        scheme, n, r, p, salt, key = encoded.split("$")

        assert scheme == "scrypt"
        assert (int(n), int(r), int(p)) == (2 ** 15, 8, 1)
        assert len(bytes.fromhex(salt)) == 16
        assert len(bytes.fromhex(key)) == 32

    def test_salt_differs_per_hash_of_the_same_password(self) -> None:
        password = _password()

        first, second = hash_password(password), hash_password(password)

        assert first.split("$")[4] != second.split("$")[4]
        assert first.split("$")[5] != second.split("$")[5]
        assert verify_password(password, first)
        assert verify_password(password, second)

    def test_wrong_password_fails(self) -> None:
        password = _password()
        encoded = hash_password(password)

        assert verify_password(password, encoded)
        assert not verify_password(password + "x", encoded)
        assert not verify_password(password[:-1], encoded)
        assert not verify_password(_password(), encoded)
        assert not verify_password("", encoded)

    def test_short_password_is_rejected(self) -> None:
        assert MIN_PASSWORD_LENGTH == 12
        twelve = secrets.token_hex(6)

        with pytest.raises(PasswordPolicyError):
            hash_password(twelve[:11])
        with pytest.raises(PasswordPolicyError):
            hash_password("")

        assert verify_password(twelve, hash_password(twelve))

    def test_overlong_password_is_rejected(self) -> None:
        with pytest.raises(PasswordPolicyError):
            hash_password(secrets.token_hex(513))  # 1026 characters


class TestVerification:
    def test_stored_parameters_are_read_back(self) -> None:
        password = _password()

        assert verify_password(password, _encode(password, n=2 ** 14))

    def test_parameters_below_the_floor_fail_closed(self) -> None:
        password = _password()

        assert not verify_password(password, _encode(password, n=2 ** 13))
        assert not verify_password(password, _encode(password, n=2 ** 14, r=4))

    @pytest.mark.parametrize("mangle", [
        lambda h: "",
        lambda h: "not-a-hash",
        lambda h: h.replace("scrypt$", "bcrypt$", 1),
        lambda h: h.rsplit("$", 1)[0],
        lambda h: h.upper(),
        lambda h: h + "00",
        lambda h: h.replace("$32768$", "$32767$", 1),
        lambda h: h.replace("$32768$", "$2147483648$", 1),
    ], ids=["empty", "garbage", "other-scheme", "no-key", "upper-hex",
            "long-key", "n-not-power-of-two", "n-above-ceiling"])
    def test_malformed_or_foreign_hashes_fail_closed(self, mangle) -> None:
        password = _password()
        encoded = hash_password(password)

        assert not verify_password(password, mangle(encoded))

    def test_derived_keys_are_compared_in_constant_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[int, int]] = []
        real = passwords.hmac.compare_digest

        def recording(a: bytes, b: bytes) -> bool:
            calls.append((len(a), len(b)))
            return real(a, b)

        monkeypatch.setattr(passwords.hmac, "compare_digest", recording)
        password = _password()
        encoded = hash_password(password)

        assert verify_password(password, encoded)
        assert not verify_password(_password(), encoded)
        assert calls == [(32, 32), (32, 32)]

    @pytest.mark.parametrize("n, r, p", [
        (2 ** 21, 8, 1),    # n above the ceiling
        (2 ** 14, 64, 1),   # r above the ceiling
        (2 ** 14, 8, 32),   # p above the ceiling
        (2 ** 18, 16, 1),   # each within its range, but 128*r*n = 512 MiB
    ], ids=["n", "r", "p", "memory"])
    def test_costs_above_the_ceiling_fail_before_any_derivation(
        self, monkeypatch: pytest.MonkeyPatch, n: int, r: int, p: int
    ) -> None:
        # Not computed: the bounds must refuse the row before scrypt runs.
        derivations: list[int] = []
        monkeypatch.setattr(passwords, "_derive",
                            lambda *args: derivations.append(1) or b"")
        encoded = (f"scrypt${n}${r}${p}${secrets.token_hex(16)}"
                   f"${secrets.token_hex(32)}")

        assert not verify_password(_password(), encoded)
        assert derivations == []

    def test_dummy_verification_costs_one_derivation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Used for unknown usernames so that they cost one scrypt, too.
        calls: list[tuple[int, int, int]] = []
        real = passwords._derive

        def counting(password: str, salt: bytes, params) -> bytes:
            calls.append((params.n, params.r, params.p))
            return real(password, salt, params)

        monkeypatch.setattr(passwords, "_derive", counting)

        assert passwords.burn_verification(_password()) is False
        assert calls == [(2 ** 15, 8, 1)]
