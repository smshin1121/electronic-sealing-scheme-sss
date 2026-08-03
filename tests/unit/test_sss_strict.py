"""Tests for strict-mode key splitting (outer 2-of-2 XOR wrap).

Strict mode adds an outer 2-of-2 XOR requirement:
K is split as K = R xor X where R is the owner share (s1) and X is
replicated to the three institutional channels (s2/s3/s4). Recovery
REQUIRES s1 plus at least one channel; channels alone reveal nothing.
"""

from __future__ import annotations

import os

import pytest

from desktop.crypto.exceptions import KeyRecoveryError, KeySplitError
from desktop.crypto.sss_recover import recover_key
from desktop.crypto.sss_split import split_key
from desktop.crypto.sss_strict import (
    SEAL_MODE_STANDARD,
    SEAL_MODE_STRICT,
    VALID_SEAL_MODES,
    recover_key_for_mode,
    recover_key_strict,
    split_key_strict,
)


@pytest.fixture()
def hex_key() -> str:
    return os.urandom(32).hex()


# ---------------------------------------------------------------------------
# split_key_strict
# ---------------------------------------------------------------------------


class TestSplitKeyStrict:
    def test_returns_four_index_prefixed_shares(self, hex_key: str) -> None:
        shares = split_key_strict(hex_key)
        assert len(shares) == 4
        for i, share in enumerate(shares, start=1):
            prefix, _, payload = share.partition("-")
            assert prefix == str(i)
            int(payload, 16)  # payload must be hex

    def test_channels_carry_identical_payload(self, hex_key: str) -> None:
        s1, s2, s3, s4 = split_key_strict(hex_key)
        payload = lambda s: s.partition("-")[2]  # noqa: E731
        assert payload(s2) == payload(s3) == payload(s4)
        assert payload(s1) != payload(s2)

    def test_xor_relation_holds(self, hex_key: str) -> None:
        s1, s2, _, _ = split_key_strict(hex_key)
        r = bytes.fromhex(s1.partition("-")[2])
        x = bytes.fromhex(s2.partition("-")[2])
        assert bytes(a ^ b for a, b in zip(r, x)).hex() == hex_key.zfill(64)

    def test_split_is_randomized(self, hex_key: str) -> None:
        first = split_key_strict(hex_key)
        second = split_key_strict(hex_key)
        assert first[0] != second[0]

    def test_rejects_invalid_hex(self) -> None:
        with pytest.raises(KeySplitError):
            split_key_strict("not-hex")

    def test_rejects_empty_key(self) -> None:
        with pytest.raises(KeySplitError):
            split_key_strict("")

    def test_rejects_oversized_key(self) -> None:
        with pytest.raises(KeySplitError):
            split_key_strict("ff" * 33)


# ---------------------------------------------------------------------------
# recover_key_strict
# ---------------------------------------------------------------------------


class TestRecoverKeyStrict:
    def test_s1_plus_each_channel_recovers(self, hex_key: str) -> None:
        s1, s2, s3, s4 = split_key_strict(hex_key)
        expected = hex_key.zfill(64)
        for channel in (s2, s3, s4):
            assert recover_key_strict([s1, channel]) == expected

    def test_order_does_not_matter(self, hex_key: str) -> None:
        s1, s2, _, _ = split_key_strict(hex_key)
        assert recover_key_strict([s2, s1]) == hex_key.zfill(64)

    def test_channels_alone_fail(self, hex_key: str) -> None:
        _, s2, s3, s4 = split_key_strict(hex_key)
        with pytest.raises(KeyRecoveryError, match="s1"):
            recover_key_strict([s2, s3])
        with pytest.raises(KeyRecoveryError, match="s1"):
            recover_key_strict([s2, s3, s4])

    def test_s1_alone_fails(self, hex_key: str) -> None:
        s1, _, _, _ = split_key_strict(hex_key)
        with pytest.raises(KeyRecoveryError):
            recover_key_strict([s1])

    def test_conflicting_channel_payloads_fail(self, hex_key: str) -> None:
        s1, s2, _, _ = split_key_strict(hex_key)
        forged_s3 = "3-" + os.urandom(32).hex()
        with pytest.raises(KeyRecoveryError, match="mismatch"):
            recover_key_strict([s1, s2, forged_s3])

    def test_leading_zero_key_round_trips(self) -> None:
        key = "00" * 4 + os.urandom(28).hex()
        s1, s2, _, _ = split_key_strict(key)
        assert recover_key_strict([s1, s2]) == key

    def test_malformed_share_fails(self, hex_key: str) -> None:
        s1, _, _, _ = split_key_strict(hex_key)
        with pytest.raises(KeyRecoveryError):
            recover_key_strict([s1, "2-zzzz"])
        with pytest.raises(KeyRecoveryError):
            recover_key_strict([s1, "no-dash-payload!"])

    def test_duplicate_s1_fails(self, hex_key: str) -> None:
        s1, _, _, _ = split_key_strict(hex_key)
        with pytest.raises(KeyRecoveryError):
            recover_key_strict([s1, s1])


# ---------------------------------------------------------------------------
# recover_key_for_mode (dispatch)
# ---------------------------------------------------------------------------


class TestRecoverKeyForMode:
    def test_standard_dispatches_to_sss(self, hex_key: str) -> None:
        shares = split_key(hex_key)
        recovered = recover_key_for_mode(
            SEAL_MODE_STANDARD, [shares[0], shares[1]]
        )
        assert recovered == recover_key([shares[0], shares[1]])

    def test_strict_dispatches_to_xor(self, hex_key: str) -> None:
        s1, s2, _, _ = split_key_strict(hex_key)
        assert recover_key_for_mode(SEAL_MODE_STRICT, [s1, s2]) == (
            hex_key.zfill(64)
        )

    def test_unknown_mode_fails_closed(self, hex_key: str) -> None:
        shares = split_key(hex_key)
        with pytest.raises(KeyRecoveryError, match="mode"):
            recover_key_for_mode("legacy", list(shares[:2]))

    def test_valid_modes_constant(self) -> None:
        assert VALID_SEAL_MODES == frozenset({"standard", "strict"})


# ---------------------------------------------------------------------------
# Record schema integration: mode covered by the signed record
# ---------------------------------------------------------------------------


class TestSealModeInRecord:
    @staticmethod
    def _minimal_record_kwargs() -> dict:
        return {
            "unlock_time_iso": "2026-12-31T00:00:00Z",
            "key_commitment": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # public-test-fixture; gitleaks:allow
            "case_info": {
                "case_number": "2026-001",
                "investigator": "Hong",
                "device_user": "Kim",
                "suspect": "Kim",
                "storage_type": "SSD",
                "storage_info": {
                    "manufacturer": "M", "model": "X", "serial": "1",
                },
                "seizure_time": "2026-08-02T00:00:00Z",
                "seizure_location": "Seoul",
            },
            "process_info": {
                "type": "Sealing",
                "start_time": "2026-08-02T00:00:00Z",
                "end_time": "2026-08-02T00:00:00Z",
                "file_count": 1,
                "investigator": "Hong",
                "reason": "",
                "participation": "",
            },
            "file_info": {
                "original_files": [{"filename": "a.img", "size": 1}],
                "result_files": [],
                "hash_match": True,
            },
            "signer_info": {
                "name": "Kim",
                "email": "kim@example.com",
                "birth_date": "900101",
                "phone": "010",
                "cert_fingerprint": "0" * 64,
                "signature_image_hash": "0" * 64,
            },
            "history": {
                "summary": "S1U0R0",
                "events": [{
                    "seal_type": "Sealing",
                    "start_time": "2026-08-02T00:00:00Z",
                    "end_time": "2026-08-02T00:00:00Z",
                    "investigator": "Hong",
                }],
            },
        }

    def test_default_mode_is_standard(self) -> None:
        from desktop.record import build_seal_record, validate_record

        record = build_seal_record(
            seal_id="S-20260802-ABC123", **self._minimal_record_kwargs()
        )
        assert record["seal_mode"] == SEAL_MODE_STANDARD
        assert validate_record(record) == []

    def test_explicit_strict_mode(self) -> None:
        from desktop.record import build_seal_record, validate_record

        record = build_seal_record(
            seal_id="S-20260802-ABC123",
            seal_mode=SEAL_MODE_STRICT,
            **self._minimal_record_kwargs(),
        )
        assert record["seal_mode"] == SEAL_MODE_STRICT
        assert validate_record(record) == []

    def test_invalid_mode_rejected_by_validator(self) -> None:
        from desktop.record import build_seal_record, validate_record

        record = build_seal_record(
            seal_id="S-20260802-ABC123", **self._minimal_record_kwargs()
        )
        tampered = {**record, "seal_mode": "none"}
        errors = validate_record(tampered)
        assert any("seal_mode" in e for e in errors)

    def test_missing_mode_rejected_by_validator(self) -> None:
        from desktop.record import build_seal_record, validate_record

        record = build_seal_record(
            seal_id="S-20260802-ABC123", **self._minimal_record_kwargs()
        )
        stripped = {k: v for k, v in record.items() if k != "seal_mode"}
        errors = validate_record(stripped)
        assert any("seal_mode" in e for e in errors)

    def test_unseal_record_carries_mode_forward(self) -> None:
        from desktop.record import build_seal_record, build_unseal_record

        seal = build_seal_record(
            seal_id="S-20260802-ABC123",
            seal_mode=SEAL_MODE_STRICT,
            **self._minimal_record_kwargs(),
        )
        unseal = build_unseal_record(
            prev_record=seal,
            process_info={**seal["process_info"], "type": "Unsealing"},
            file_info=seal["file_info"],
        )
        assert unseal["seal_mode"] == SEAL_MODE_STRICT

    def test_legacy_prev_record_defaults_to_standard(self) -> None:
        from desktop.record import build_seal_record, build_unseal_record

        seal = build_seal_record(
            seal_id="S-20260802-ABC123", **self._minimal_record_kwargs()
        )
        legacy_prev = {k: v for k, v in seal.items() if k != "seal_mode"}
        unseal = build_unseal_record(
            prev_record=legacy_prev,
            process_info={**seal["process_info"], "type": "Unsealing"},
            file_info=seal["file_info"],
        )
        assert unseal["seal_mode"] == SEAL_MODE_STANDARD
