"""Seal policy version 2: the policy generation (stage E, E2a).

A version-2 policy adds ``generation`` (a positive integer) to the stage D
fields. Verification accepts version 1 (implicit generation 0) and
version 2. Sealing signs generation 1; resealing signs the previous
generation + 1, where the previous generation is the higher of the loaded
record's policy and the record this desktop stored for the seal (a legacy
record or a version-1 policy counts as 0, so resealing either yields 1).

Synthetic material only (test CA from ``release_pki``).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from desktop.signature.seal_policy import (
    FIRST_POLICY_GENERATION,
    LEGACY_POLICY_VERSION,
    MAX_POLICY_GENERATION,
    SEAL_POLICY_VERSION,
    PolicyError,
    PolicyVerificationError,
    attach_policy,
    build_policy,
    canonicalize_policy,
    policy_from_record,
    policy_generation,
    verify_policy,
)
from tests.fixtures.release_pki import load_test_signer

SEAL_ID = "S-20260928-E2A001"
COMMIT = "cd" * 32
NEW_KEY_HEX = "ef" * 32


def _fields(**overrides: Any) -> dict:
    fields = {
        "seal_id": SEAL_ID,
        "case_no": "2026-형제-002",
        "seal_mode": "standard",
        "unlock_time_iso": "2026-10-06T00:00:00Z",
        "key_commitment": COMMIT,
    }
    fields.update(overrides)
    return fields


def _record(**overrides: Any) -> dict:
    record = {
        "seal_id": SEAL_ID,
        "seal_mode": "standard",
        "unlock_time_iso": "2026-10-06T00:00:00Z",
        "key_commitment": COMMIT,
        "case_info": {"case_number": "2026-형제-002"},
    }
    record.update(overrides)
    return record


# ===================================================================
# Schema
# ===================================================================

class TestVersionTwoSchema:
    def test_versions_and_bounds(self) -> None:
        assert (LEGACY_POLICY_VERSION, SEAL_POLICY_VERSION) == (1, 2)
        assert FIRST_POLICY_GENERATION == 1
        assert MAX_POLICY_GENERATION == 2 ** 31 - 1

    def test_exact_canonical_bytes_of_a_version_two_policy(self) -> None:
        policy = build_policy(**_fields(), generation=3)
        expected = json.dumps(
            {**_fields(), "v": 2, "generation": 3},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        assert canonicalize_policy(policy) == expected
        assert policy["v"] == 2 and policy["generation"] == 3

    def test_without_a_generation_the_policy_stays_version_one(self) -> None:
        policy = build_policy(**_fields())
        assert policy["v"] == 1
        assert "generation" not in policy
        assert policy_generation(policy) == 0

    def test_generation_of_a_version_two_policy(self) -> None:
        assert policy_generation(build_policy(**_fields(), generation=7)) == 7

    @pytest.mark.parametrize(
        "generation",
        [0, -1, True, 1.0, "1", None, MAX_POLICY_GENERATION + 1],
    )
    def test_invalid_generations_are_refused(self, generation: Any) -> None:
        policy = {**build_policy(**_fields(), generation=1),
                  "generation": generation}
        with pytest.raises(PolicyError):
            canonicalize_policy(policy)

    @pytest.mark.parametrize("generation", [1, 2, MAX_POLICY_GENERATION])
    def test_valid_generations_are_accepted(self, generation: int) -> None:
        policy = build_policy(**_fields(), generation=generation)
        assert policy_generation(policy) == generation

    def test_version_two_without_a_generation_is_refused(self) -> None:
        policy = {**build_policy(**_fields()), "v": 2}
        with pytest.raises(PolicyError):
            canonicalize_policy(policy)

    def test_version_one_with_a_generation_is_refused(self) -> None:
        policy = {**build_policy(**_fields()), "generation": 1}
        with pytest.raises(PolicyError):
            canonicalize_policy(policy)

    @pytest.mark.parametrize("version", [0, 3, True, 2.0, "2"])
    def test_unknown_versions_are_refused(self, version: Any) -> None:
        policy = {**build_policy(**_fields(), generation=1), "v": version}
        with pytest.raises(PolicyError):
            canonicalize_policy(policy)

    def test_policy_generation_refuses_a_malformed_policy(self) -> None:
        with pytest.raises(PolicyError):
            policy_generation({"v": 2, "generation": 1})

    def test_policy_from_record_carries_the_generation(self) -> None:
        assert policy_from_record(_record(), generation=4) == build_policy(
            **_fields(), generation=4
        )


# ===================================================================
# Verification accepts both versions
# ===================================================================

class TestVerifyBothVersions:
    def test_version_two_verifies_with_its_generation(self, release_pki) -> None:
        record, signed = attach_policy(
            _record(), load_test_signer(release_pki), generation=5
        )
        verified = verify_policy(
            record["policy"], record["policy_signature"],
            record["policy_cert"], ca_cert=release_pki.ca_cert,
            expected_seal_id=SEAL_ID,
        )
        assert verified.generation == 5
        assert verified.digest == signed.digest
        assert record["policy"]["v"] == 2

    def test_version_one_verifies_as_generation_zero(self, release_pki) -> None:
        record, _ = attach_policy(_record(), load_test_signer(release_pki))
        verified = verify_policy(
            record["policy"], record["policy_signature"],
            record["policy_cert"], ca_cert=release_pki.ca_cert,
            expected_seal_id=SEAL_ID,
        )
        assert record["policy"]["v"] == 1
        assert verified.generation == 0

    def test_a_raised_generation_breaks_the_signature(self, release_pki) -> None:
        record, _ = attach_policy(
            _record(), load_test_signer(release_pki), generation=1
        )
        forged = {**record["policy"], "generation": 9}
        with pytest.raises(PolicyVerificationError):
            verify_policy(
                forged, record["policy_signature"], record["policy_cert"],
                ca_cert=release_pki.ca_cert, expected_seal_id=SEAL_ID,
            )


# ===================================================================
# Desktop: sealing signs generation 1, resealing the previous + 1
# ===================================================================

def _seal_process(tmp_path: Path, signer: Any):
    import desktop.seal_process as sp

    enc = tmp_path / "evidence.bin.enc"
    enc.write_bytes(b"x" * 64)
    process = sp.SealProcess(db_path=str(tmp_path / "seal.db"),
                             policy_signer=signer)
    process.set_config(sp.SealConfig(
        source_file=str(tmp_path / "evidence.bin"), output_dir=str(tmp_path),
        chunk_size_bytes=1 << 30, case_number="2026-형제-002",
        investigator={"name": "Hong"},
        seizure={"date": "2026-08-02T00:00:00Z", "location": "Seoul",
                 "device_user": "Kim"},
        media={"type": "SSD", "manufacturer": "M", "model": "X", "serial": "1"},
        subject={"name": "Kim", "email": "k@example.com", "birth": "1990-01-01",
                 "phone": "010-0000-0000", "participation": "yes",
                 "password": "synthetic-subject-pw"},  # public-test-fixture
        signature_lines=[(0, 0, 1, 1)], unlock_days=7,
    ))
    process.state["s1"] = {
        "aes_key_hex": "ab" * 32, "enc_filepath": str(enc),
        "encryption_algo": "AES-256-GCM",
        "metadata": {"filename": "evidence.bin", "size": 4096,
                     "md5": "0" * 32, "sha256": "0" * 64,
                     "mtime": "2026-08-02T00:00:00Z",
                     "ctime": "2026-08-02T00:00:00Z",
                     "atime": "2026-08-02T00:00:00Z"},
        "enc_metadata": {"enc_ended_time": "2026-08-02T00:00:00Z",
                         "nonces": ["00"], "tags": ["11"],
                         "chunk_lengths": [4096]},
    }
    return process


def test_sealing_signs_generation_one(tmp_path: Path, release_pki) -> None:
    s4 = _seal_process(tmp_path, load_test_signer(release_pki)).run_s4()
    policy = s4["record_dict"]["policy"]
    assert policy["v"] == 2
    assert policy["generation"] == FIRST_POLICY_GENERATION


def _signed(record: dict, signer: Any, generation: Any) -> dict:
    return attach_policy(record, signer, generation=generation)[0]


def _reseal_process(tmp_path: Path, signer: Any, prev: dict,
                    monkeypatch: pytest.MonkeyPatch):
    import desktop.record as record_pkg
    import desktop.reseal_process as rp

    def _stub_render(record: dict, template_name: str, output_path: str) -> str:
        Path(output_path).write_bytes(b"%PDF-1.4 stub")
        return output_path

    monkeypatch.setattr(record_pkg, "render_record_pdf", _stub_render)
    process = rp.ResealProcess(db_path=str(tmp_path / "reseal.db"),
                               policy_signer=signer)
    process.state["r1"] = {"prev_record": prev, "seal_id": prev["seal_id"],
                           "record_path": ""}
    process.state["r2"] = {"known_files": [], "unknown_files": [],
                           "target_dir": str(tmp_path)}
    process.set_config(rp.ResealConfig(
        source_dir=str(tmp_path), output_dir=str(tmp_path),
        chunk_size_bytes=1 << 30, investigator="Hong", reason="analysis",
        subject_participated=True, unlock_days=5,
    ))
    process.state["r5"] = {
        "aes_key_hex": NEW_KEY_HEX,
        "enc_results": [{
            "enc_filepath": str(tmp_path / "e.enc"),
            "original_filepath": str(tmp_path / "e.bin"),
            "metadata": {"filename": "e.bin", "size": 1, "md5": "0" * 32,
                         "sha256": "0" * 64},
            "chunk_count": 1,
        }],
        "encryption_algo": "AES-256-GCM",
    }
    return process


def _prev_record(signer: Any, generation: Any) -> dict:
    record = _record(
        process_info={"type": "Sealing"},
        file_info={"original_files": []},
        signer_info={"name": "Kim"},
        history={"summary": "S1U0R0", "events": [
            {"id": 1, "seal_type": "Sealing", "start_time": "t",
             "end_time": "t", "investigator": "Hong"}]},
    )
    if signer is None:
        return record
    return _signed(record, signer, generation)


def _store(db_path: Path, record: dict) -> None:
    from desktop.db import init_db, save_seal_record

    init_db(str(db_path))
    save_seal_record(str(db_path), record["seal_id"],
                     json.dumps(record, ensure_ascii=False), "stored.pdf")


class TestResealGeneration:
    @pytest.mark.parametrize(
        "previous, expected",
        [(None, 1), ("v1", 1), (1, 2), (6, 7)],
        ids=["legacy", "version-one", "generation-1", "generation-6"],
    )
    def test_reseal_signs_the_previous_generation_plus_one(
        self, tmp_path: Path, release_pki, monkeypatch, previous, expected
    ) -> None:
        signer = load_test_signer(release_pki)
        if previous is None:
            prev = _prev_record(None, None)
        elif previous == "v1":
            prev = _prev_record(signer, None)
        else:
            prev = _prev_record(signer, previous)
        process = _reseal_process(tmp_path, signer, prev, monkeypatch)

        record = process.run_r6_record()["record_dict"]

        assert record["policy"]["v"] == 2
        assert record["policy"]["generation"] == expected
        assert record["policy"]["key_commitment"] == hashlib.sha256(
            bytes.fromhex(NEW_KEY_HEX)).hexdigest()

    def test_a_stale_file_does_not_lower_the_generation(
        self, tmp_path: Path, release_pki, monkeypatch
    ) -> None:
        # This desktop stored generation 3; the operator loads the older
        # generation-1 file. The reseal must still be above 3.
        signer = load_test_signer(release_pki)
        _store(tmp_path / "reseal.db", _prev_record(signer, 3))
        process = _reseal_process(tmp_path, signer, _prev_record(signer, 1),
                                  monkeypatch)

        record = process.run_r6_record()["record_dict"]

        assert record["policy"]["generation"] == 4

    def test_a_malformed_previous_policy_refuses_the_reseal(
        self, tmp_path: Path, release_pki, monkeypatch
    ) -> None:
        signer = load_test_signer(release_pki)
        prev = _prev_record(signer, 2)
        prev = {**prev, "policy": {**prev["policy"], "generation": "two"}}
        process = _reseal_process(tmp_path, signer, prev, monkeypatch)

        with pytest.raises(ValueError):
            process.run_r6_record()

    def test_an_exhausted_generation_refuses_the_reseal(
        self, tmp_path: Path, release_pki, monkeypatch
    ) -> None:
        signer = load_test_signer(release_pki)
        prev = _prev_record(signer, MAX_POLICY_GENERATION)
        process = _reseal_process(tmp_path, signer, prev, monkeypatch)

        with pytest.raises(ValueError):
            process.run_r6_record()

    def test_next_generation_helper_reads_both_sources(
        self, tmp_path: Path, release_pki
    ) -> None:
        from desktop.policy_generation import next_policy_generation

        signer = load_test_signer(release_pki)
        db = tmp_path / "desk.db"
        assert next_policy_generation(str(db), _prev_record(signer, 2)) == 3
        _store(db, _prev_record(signer, 9))
        assert next_policy_generation(str(db), _prev_record(signer, 2)) == 10
        assert next_policy_generation(str(db), _prev_record(None, None)) == 10


def test_without_a_key_a_malformed_previous_policy_still_refuses_the_reseal(
    tmp_path: Path, release_pki, monkeypatch
) -> None:
    # Code review (LOW): the generation is computed before the key is
    # known. Kept fail-closed on purpose, as E1's R1 refuses an
    # inconsistent mode whatever the key: the loaded file was altered.
    for name in ("ENC_ENVELOPE_POLICY_KEY_PATH",
                 "ENC_ENVELOPE_POLICY_CERT_PATH",
                 "ENC_ENVELOPE_POLICY_KEY_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    prev = _prev_record(load_test_signer(release_pki), 2)
    prev = {**prev, "policy": {**prev["policy"], "generation": "two"}}
    process = _reseal_process(tmp_path, None, prev, monkeypatch)

    with pytest.raises(ValueError):
        process.run_r6_record()
