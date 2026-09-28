"""Resealing keeps the seal mode; no silent downgrade from strict (stage E, E1).

ResealProcess takes the mode from the previous record: R1 reads it with
``seal_mode_of`` (an unknown mode, or one that differs from the signed
policy, is refused), cross-checks it with the record this desktop stored for
the seal (a file whose mode was stripped or edited is refused), R6 signs a
new policy with the same mode and R7 splits by the mode of the R6 record.
The reseal wizard shows the kept mode at R1, R6, R7 and R8.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest

from desktop.crypto import KeyRecoveryError, init_master_key, recover_key_for_mode
from desktop.record.record_builder import build_seal_record
from desktop.reseal_process import ResealConfig, ResealProcess
from desktop.signature.seal_policy import attach_policy, verify_policy
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.tk_root import destroy_test_root, new_test_root

OLD_KEY_HEX = "cd" * 32
NEW_KEY_HEX = "ef" * 32
SEAL_ID = "S-20260928-0C0FFE"


def _prior_record(mode: str, signer: Any = None) -> dict:
    record = build_seal_record(
        seal_id=SEAL_ID, seal_mode=mode,
        unlock_time_iso="2026-10-06T00:00:00Z",
        key_commitment=hashlib.sha256(bytes.fromhex(OLD_KEY_HEX)).hexdigest(),
        case_info={"case_number": "2026-E1-R", "investigator": "Hong",
                   "device_user": "Kim", "suspect": "Kim", "storage_type": "SSD",
                   "storage_info": {"manufacturer": "M", "model": "X", "serial": "1"},
                   "seizure_time": "2026-09-01T00:00:00Z", "seizure_location": "Seoul"},
        process_info={"type": "Sealing", "start_time": "2026-09-01T00:00:00Z",
                      "end_time": "2026-09-01T00:00:00Z", "file_count": 1,
                      "investigator": "Hong", "reason": "", "participation": "yes"},
        file_info={"original_files": [{"filename": "e.bin", "size": 1, "md5": "0" * 32,
                                       "sha256": "0" * 64, "mtime": "2026-09-01T00:00:00Z",
                                       "ctime": "2026-09-01T00:00:00Z",
                                       "atime": "2026-09-01T00:00:00Z"}],
                   "result_files": [], "hash_match": True},
        signer_info={"name": "Kim", "email": "k@example.com", "birth_date": "1990-01-01",
                     "phone": "010-0000-0000", "cert_fingerprint": "0" * 64,
                     "signature_image_hash": "0" * 64},
        history={"summary": "S1U0R0", "events": [
            {"event": "seal", "time": "2026-09-01T00:00:00Z", "actor": "Hong",
             "reason": ""}]},
    )
    if signer is None:
        return record
    return attach_policy(record, signer)[0]


def _write(tmp_path: Path, record: dict, name: str = "prev.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    return str(path)


@pytest.fixture()
def master_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    path = str(tmp_path / "master.key")
    init_master_key(path)
    monkeypatch.setenv("MASTER_KEY_PATH", path)
    return path


@pytest.fixture()
def stub_render(monkeypatch: pytest.MonkeyPatch) -> None:
    import desktop.record as record_pkg

    def _render(record: dict, template_name: str, output_path: str) -> str:
        Path(output_path).write_bytes(b"%PDF-1.4 stub")
        return output_path

    monkeypatch.setattr(record_pkg, "render_record_pdf", _render)


def _resealed(tmp_path: Path, prev: dict, signer: Any) -> ResealProcess:
    """R1 from a file, R2/R5 state injected (tiny synthetic file), config set."""
    process = ResealProcess(db_path=str(tmp_path / "reseal.db"), policy_signer=signer)
    process.run_r1_load(_write(tmp_path, prev))
    process.state["r2"] = {"known_files": [], "unknown_files": [],
                           "target_dir": str(tmp_path)}
    process.set_config(ResealConfig(
        source_dir=str(tmp_path), output_dir=str(tmp_path), chunk_size_bytes=1 << 30,
        investigator="Hong", reason="analysis complete", subject_participated=True,
        unlock_days=5,
    ))
    process.state["r5"] = {
        "aes_key_hex": NEW_KEY_HEX,
        "enc_results": [{"enc_filepath": str(tmp_path / "e.enc"),
                         "original_filepath": str(tmp_path / "e.bin"),
                         "metadata": {"filename": "e.bin", "size": 1, "md5": "0" * 32,
                                      "sha256": "0" * 64},
                         "chunk_count": 1}],
        "encryption_algo": "AES-256-GCM",
    }
    return process


# ===================================================================
# The process keeps strict (R1 -> R6 -> R7 -> R8)
# ===================================================================

class TestResealKeepsStrict:
    def test_strict_seal_stays_strict_through_r8(
        self, tmp_path, master_key, stub_render, release_pki
    ) -> None:
        from desktop.db import get_seal_record, init_db

        signer = load_test_signer(release_pki)
        prev = _prior_record("strict", signer)
        process = _resealed(tmp_path, prev, signer)
        assert process.state["r1"]["seal_mode"] == "strict"

        record = process.run_r6_record()["record_dict"]
        assert record["seal_mode"] == "strict"
        verified = verify_policy(record["policy"], record["policy_signature"],
                                 record["policy_cert"], ca_cert=release_pki.ca_cert,
                                 expected_seal_id=SEAL_ID)
        assert verified.seal_mode == "strict"
        assert record["policy"] != prev["policy"]  # a new policy for the new key

        s1, s2, s3, s4 = process.run_r7_split_key()["shares"]
        assert recover_key_for_mode("strict", [s1, s2]) == NEW_KEY_HEX
        assert recover_key_for_mode("strict", [s1, s4]) == NEW_KEY_HEX
        for institutional in ([s2, s3], [s2, s4], [s3, s4], [s2, s3, s4]):
            with pytest.raises(KeyRecoveryError):
                recover_key_for_mode("strict", institutional)

        init_db(process._db_path)
        process.run_r8_save()
        stored = get_seal_record(process._db_path, SEAL_ID)["record_json"]
        assert stored["seal_mode"] == "strict"
        assert stored["policy"]["seal_mode"] == "strict"

    def test_standard_seal_stays_standard(
        self, tmp_path, master_key, stub_render, monkeypatch
    ) -> None:
        for name in ("ENC_ENVELOPE_POLICY_KEY_PATH", "ENC_ENVELOPE_POLICY_CERT_PATH",
                     "ENC_ENVELOPE_POLICY_KEY_PASSWORD"):
            monkeypatch.delenv(name, raising=False)
        process = _resealed(tmp_path, _prior_record("standard"), None)
        process.run_r6_record()
        shares = process.run_r7_split_key()["shares"]

        assert process.state["r1"]["seal_mode"] == "standard"
        assert recover_key_for_mode("standard", [shares[1], shares[2]]) == NEW_KEY_HEX


# ===================================================================
# R1 refuses unknown / inconsistent modes and downgrades
# ===================================================================

class TestR1RefusesDowngrades:
    def test_unknown_mode(self, tmp_path) -> None:
        prev = _prior_record("strict")
        prev["seal_mode"] = "Strict"

        with pytest.raises(ValueError, match="seal_mode"):
            ResealProcess(db_path=":memory:").run_r1_load(_write(tmp_path, prev))

    def test_mode_stripped_from_a_signed_strict_record(self, tmp_path, release_pki) -> None:
        prev = _prior_record("strict", load_test_signer(release_pki))
        del prev["seal_mode"]

        with pytest.raises(ValueError, match="policy"):
            ResealProcess(db_path=":memory:").run_r1_load(_write(tmp_path, prev))

    def test_mode_edited_against_the_signed_policy(self, tmp_path, release_pki) -> None:
        prev = _prior_record("strict", load_test_signer(release_pki))
        prev["seal_mode"] = "standard"

        with pytest.raises(ValueError, match="policy"):
            ResealProcess(db_path=":memory:").run_r1_load(_write(tmp_path, prev))

    def _stored(self, tmp_path: Path, record: dict) -> str:
        from desktop.db import init_db, save_seal_record

        db = str(tmp_path / "desk.db")
        init_db(db)
        save_seal_record(db, SEAL_ID, json.dumps(record), "x.pdf")
        return db

    def test_downgrade_against_the_stored_record(self, tmp_path) -> None:
        """Policy and mode both stripped from the file: the desktop's own record still says strict."""
        db = self._stored(tmp_path, _prior_record("strict"))
        stripped = _prior_record("strict")
        del stripped["seal_mode"]

        with pytest.raises(ValueError, match="strict"):
            ResealProcess(db_path=db).run_r1_load(_write(tmp_path, stripped))

    def test_matching_stored_record_is_accepted(self, tmp_path) -> None:
        db = self._stored(tmp_path, _prior_record("strict"))

        result = ResealProcess(db_path=db).run_r1_load(
            _write(tmp_path, _prior_record("strict")))
        assert result["seal_mode"] == "strict"

    def test_registered_case_without_a_record_is_not_compared(self, tmp_path) -> None:
        from desktop.db import create_case, init_db

        db = str(tmp_path / "desk.db")
        init_db(db)
        case_id = create_case(db, "2026-E1-R", "Hong", "Kim")
        prev = _prior_record("standard")
        prev["seal_id"] = case_id

        result = ResealProcess(db_path=db).run_r1_load(_write(tmp_path, prev))
        assert result["seal_mode"] == "standard"

    def test_legacy_record_without_mode_is_standard(self, tmp_path) -> None:
        prev = _prior_record("standard")
        del prev["seal_mode"]

        result = ResealProcess(db_path=":memory:").run_r1_load(_write(tmp_path, prev))
        assert result["seal_mode"] == "standard"


class TestSealModeOf:
    def test_errors_are_readable(self) -> None:
        from desktop.record import RecordValidationError, seal_mode_of

        with pytest.raises(RecordValidationError) as info:
            seal_mode_of({"seal_mode": "Strict"})
        assert "seal_mode 'Strict' is not one of" in str(info.value)
        with pytest.raises(RecordValidationError) as info:
            seal_mode_of({"policy": {"seal_mode": "strict"}})
        assert "differs from the signed policy's 'strict'" in str(info.value)

    def test_build_seal_record_errors_are_readable(self) -> None:
        """RecordValidationError joins a list; a bare string was split per character."""
        from desktop.record import RecordValidationError

        record = _prior_record("standard")
        with pytest.raises(RecordValidationError) as info:
            build_seal_record(
                record["seal_id"], record["case_info"], record["process_info"],
                record["file_info"], record["signer_info"], record["history"],
                unlock_time_iso="", key_commitment=record["key_commitment"],
            )
        assert "unlock_time_iso is required" in str(info.value)

    @pytest.mark.parametrize("record, mode", [
        ({}, "standard"),
        ({"seal_mode": "strict"}, "strict"),
        ({"seal_mode": "strict", "policy": {"seal_mode": "strict"}}, "strict"),
    ])
    def test_valid_modes(self, record: dict, mode: str) -> None:
        from desktop.record import seal_mode_of

        assert seal_mode_of(record) == mode


class TestR7RefusesDowngrades:
    """R6 state edited after signing (R1 bypassed): R7 never falls back to standard.

    Strict resealing needs a signed policy (test_e1_review_fixes.py), so R6
    signs one with the test key before the R6 record is tampered with.
    """

    def test_r7_refuses_a_mode_it_cannot_read(
        self, tmp_path, master_key, stub_render, release_pki
    ) -> None:
        signer = load_test_signer(release_pki)
        process = _resealed(tmp_path, _prior_record("strict", signer), signer)
        process.run_r6_record()
        process.state["r6"]["record_dict"] = {
            **process.state["r6"]["record_dict"], "seal_mode": "Strict"}

        with pytest.raises(ValueError, match="seal_mode"):
            process.run_r7_split_key()
        assert "r7" not in process.state

    def test_r7_refuses_a_record_that_lost_strict(
        self, tmp_path, master_key, stub_render, release_pki
    ) -> None:
        signer = load_test_signer(release_pki)
        process = _resealed(tmp_path, _prior_record("strict", signer), signer)
        process.run_r6_record()
        process.state["r6"]["record_dict"] = {
            **process.state["r6"]["record_dict"], "seal_mode": "standard"}

        with pytest.raises(ValueError, match="strict"):
            process.run_r7_split_key()
        assert "r7" not in process.state


# ===================================================================
# The reseal wizard shows the kept mode
# ===================================================================

@pytest.fixture()
def root():
    r = new_test_root()  # see tests/fixtures/tk_root.py
    yield r
    destroy_test_root(r)


@pytest.fixture()
def wizard(root, monkeypatch):
    from desktop.gui import reseal_wizard

    monkeypatch.setattr(reseal_wizard.messagebox, "showerror", lambda *a, **_k: None)
    wiz = reseal_wizard.ResealWizard(root, SimpleNamespace(db_path=":memory:"))
    yield wiz
    wiz.destroy()


def _rendered_rows(summary: Any, refresh: Any) -> list[tuple]:
    captured: list[list[dict]] = []
    with mock.patch.object(summary, "render", side_effect=captured.append):
        refresh()
    return [row for section in captured[0] for row in section.get("rows", [])]


def test_wizard_r1_shows_the_kept_mode(wizard, tmp_path) -> None:
    from desktop.gui.i18n import t

    wizard._prev_record_selector.set(_write(tmp_path, _prior_record("strict")))
    wizard._target_dir_selector.set(str(tmp_path))
    wizard._output_dir_selector.set(str(tmp_path))

    assert wizard._validate_r1() is True
    info = wizard._r1_info.get("1.0", "end")
    assert t("mode.strict") in info
    assert t("mode.shares_strict") in info
    assert wizard._data["seal_mode"] == "strict"


def test_wizard_r6_r7_r8_show_strict(wizard, tmp_path) -> None:
    from desktop.gui.i18n import t

    record = _prior_record("strict")
    process = mock.create_autospec(ResealProcess, instance=True)
    process.state = {}
    process.config = None
    process.run_r7_split_key.return_value = {
        "shares": ["1-" + "a" * 64, "2-" + "b" * 64, "3-" + "b" * 64, "4-" + "b" * 64],
        "unlock_time_iso": "2026-10-23T00:00:00Z", "encrypted_shares": {},
    }
    wizard._data.update({"_process": process, "seal_mode": "strict",
                         "record_result": {"record_dict": copy.deepcopy(record)}})

    r6_rows = _rendered_rows(wizard._r6_summary, wizard._refresh_r6_preview)
    assert any(t("mode.strict") in str(row[1]) for row in r6_rows)

    assert wizard._validate_r7() is False  # E1b: split, shares 1/2 still to be saved
    assert t("keysplit.complete_strict") in wizard._r7_result.get("1.0", "end")

    r8_rows = _rendered_rows(wizard._r8_summary, wizard._refresh_r8_summary)
    assert any(t("mode.strict") in str(row[1]) for row in r8_rows)
