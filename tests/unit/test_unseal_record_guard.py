"""Unsealing cannot replace the record the downgrade guard trusts (Codex F2).

Resealing (R1) compares the loaded record's mode with the record this
desktop stored for the seal. Unsealing U7 replaces that stored row, so U3
now checks the loaded record as R1 does (mode readable and consistent with
its signed policy) and compares the fields an unsealing carries unchanged
(mode, time lock, key commitment, policy, its signature and certificate)
with the stored record; U7 checks the unseal record again before it
replaces the row. Regression: strict seal -> edited file unsealed -> reseal
stays strict.
"""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from desktop.db import get_seal_record, init_db, save_seal_bundle
from desktop.reseal_process import ResealProcess
from desktop.unseal_process import UnsealConfig, UnsealProcess
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.tk_root import destroy_test_root, new_test_root
from tests.unit.test_reseal_mode_carry import OLD_KEY_HEX, SEAL_ID, _prior_record

_POLICY_FIELDS = ("policy", "policy_signature", "policy_cert")


@pytest.fixture()
def stub_render(monkeypatch: pytest.MonkeyPatch) -> None:
    import desktop.record as record_pkg

    def _render(record: dict, template_name: str, output_path: str) -> str:
        Path(output_path).write_bytes(b"%PDF-1.4 stub")
        return output_path

    monkeypatch.setattr(record_pkg, "render_record_pdf", _render)


@pytest.fixture()
def strict_seal(release_pki) -> dict:
    return _prior_record("strict", load_test_signer(release_pki))


def _downgraded(record: dict) -> dict:
    """The file edit F2 describes: strict -> standard, the signed policy stripped."""
    edited = {k: v for k, v in copy.deepcopy(record).items() if k not in _POLICY_FIELDS}
    return {**edited, "seal_mode": "standard"}


def _db_with(tmp_path: Path, record: dict | None = None) -> str:
    db = str(tmp_path / "desk.db")
    init_db(db)
    if record is not None:
        save_seal_bundle(db, record["seal_id"], json.dumps(record, ensure_ascii=False),
                         "seal.pdf", shares={3: b"s3"})
    return db


def _unsealing(tmp_path: Path, db: str, record: dict, name: str = "loaded.json"
               ) -> UnsealProcess:
    path = tmp_path / name
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    enc = tmp_path / "e.bin.enc"
    enc.write_bytes(os.urandom(64))
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    process = UnsealProcess(db_path=db)
    process.set_config(UnsealConfig(
        enc_filepath=str(enc), seal_record_path=str(path), aes_key_hex=OLD_KEY_HEX,
        output_dir=str(out), reason="analysis", investigator="Hong",
        subject_participated=True))
    return process


def _through_u6(process: UnsealProcess, tmp_path: Path) -> dict:
    """U4/U5 state injected (no real ciphertext), then the real U6."""
    process.state["u4"] = {"all_matched": True, "items": []}
    process.state["u5"] = {"output_filepath": str(tmp_path / "out" / "e.bin"),
                           "hash_verified": True, "sha256_match": True,
                           "md5_match": True, "metadata": {}}
    return process.run_u6_record()


def _stored(db: str) -> dict:
    return get_seal_record(db, SEAL_ID)["record_json"]


# ===================================================================
# U3
# ===================================================================

class TestU3:
    def test_a_file_that_lost_strict_is_refused(self, tmp_path, strict_seal) -> None:
        db = _db_with(tmp_path, strict_seal)
        process = _unsealing(tmp_path, db, _downgraded(strict_seal))

        with pytest.raises(ValueError, match="strict"):
            process.run_u3_validate()
        assert "u3" not in process.state

    @pytest.mark.parametrize("field, value", [
        ("unlock_time_iso", "2026-09-29T00:00:00Z"),
        ("key_commitment", "0" * 64),
        ("policy_signature", "AAAA"),
    ])
    def test_an_edited_governing_field_is_refused(
        self, tmp_path, strict_seal, field: str, value: str
    ) -> None:
        db = _db_with(tmp_path, strict_seal)
        process = _unsealing(tmp_path, db, {**strict_seal, field: value})

        with pytest.raises(ValueError, match=field):
            process.run_u3_validate()

    def test_the_matching_file_is_accepted(self, tmp_path, strict_seal) -> None:
        db = _db_with(tmp_path, strict_seal)

        result = _unsealing(tmp_path, db, strict_seal).run_u3_validate()

        assert result["seal_id"] == SEAL_ID

    def test_with_nothing_stored_the_file_is_checked_on_its_own(
        self, tmp_path, strict_seal
    ) -> None:
        db = _db_with(tmp_path)
        assert _unsealing(tmp_path, db, strict_seal).run_u3_validate()["valid"]

        against_policy = {**strict_seal, "seal_mode": "standard"}
        with pytest.raises(ValueError, match="policy"):
            _unsealing(tmp_path, db, against_policy).run_u3_validate()
        with pytest.raises(ValueError, match="seal_mode"):
            _unsealing(tmp_path, db, {**strict_seal, "seal_mode": "Strict"}).run_u3_validate()

    def test_a_missing_database_file_is_not_created(self, tmp_path, strict_seal) -> None:
        db = str(tmp_path / "none.db")

        _unsealing(tmp_path, db, strict_seal).run_u3_validate()

        assert not Path(db).exists()


# ===================================================================
# U7
# ===================================================================

class TestU7:
    def test_the_unseal_record_of_the_matching_file_is_saved(
        self, tmp_path, strict_seal, stub_render
    ) -> None:
        db = _db_with(tmp_path, strict_seal)
        process = _unsealing(tmp_path, db, strict_seal)
        process.run_u3_validate()
        _through_u6(process, tmp_path)

        process.run_u7_save()

        stored = _stored(db)
        assert stored["process_info"]["type"] == "Unsealing"
        assert stored["seal_mode"] == "strict"
        assert all(stored[name] == strict_seal[name] for name in _POLICY_FIELDS)

    def test_an_unseal_record_that_changed_the_mode_is_not_saved(
        self, tmp_path, strict_seal, stub_render
    ) -> None:
        db = _db_with(tmp_path, strict_seal)
        process = _unsealing(tmp_path, db, strict_seal)
        process.run_u3_validate()
        record = _through_u6(process, tmp_path)["record_dict"]
        process.state["u6"] = {**process.state["u6"], "record_dict": _downgraded(record)}

        with pytest.raises(ValueError, match="seal_mode"):
            process.run_u7_save()
        assert _stored(db) == strict_seal
        assert "u7" not in process.state

    def test_a_stored_record_that_changed_since_u3_is_not_replaced(
        self, tmp_path, strict_seal, stub_render
    ) -> None:
        db = _db_with(tmp_path)
        process = _unsealing(tmp_path, db, strict_seal)
        process.run_u3_validate()  # nothing stored yet
        _through_u6(process, tmp_path)
        other = {**strict_seal, "key_commitment": "1" * 64}
        save_seal_bundle(db, SEAL_ID, json.dumps(other), "other.pdf", shares={3: b"o3"})

        with pytest.raises(ValueError, match="key_commitment"):
            process.run_u7_save()
        assert _stored(db) == other


# ===================================================================
# Regression: strict seal -> edited file unsealed -> reseal
# ===================================================================

def test_strict_seal_edited_unseal_then_reseal_stays_strict(
    tmp_path, strict_seal, stub_render
) -> None:
    db = _db_with(tmp_path, strict_seal)
    edited = _downgraded(strict_seal)

    # U3 refuses the edited file.
    with pytest.raises(ValueError, match="strict"):
        _unsealing(tmp_path, db, edited).run_u3_validate()

    # With U3 skipped (state injected), U7 still does not replace the row.
    process = _unsealing(tmp_path, db, edited)
    process.state["u3"] = {"seal_record": edited, "seal_id": SEAL_ID, "valid": True}
    unseal_json = _through_u6(process, tmp_path)["record_json_path"]
    with pytest.raises(ValueError, match="strict"):
        process.run_u7_save()
    assert _stored(db) == strict_seal

    # The edited unseal record cannot start a standard reseal either.
    with pytest.raises(ValueError, match="strict"):
        ResealProcess(db_path=db).run_r1_load(unseal_json)


def test_strict_seal_unseal_then_reseal_keeps_strict(
    tmp_path, strict_seal, stub_render
) -> None:
    db = _db_with(tmp_path, strict_seal)
    process = _unsealing(tmp_path, db, strict_seal)
    process.run_u3_validate()
    unseal_json = _through_u6(process, tmp_path)["record_json_path"]
    process.run_u7_save()

    r1 = ResealProcess(db_path=db).run_r1_load(unseal_json)

    assert r1["seal_mode"] == "strict"
    assert _stored(db)["process_info"]["type"] == "Unsealing"


# ===================================================================
# The unseal wizard reports a refused U7 save
# ===================================================================

def test_the_wizard_reports_a_refused_u7_save(monkeypatch) -> None:
    from desktop.gui import unseal_wizard
    from desktop.gui.i18n import t

    errors: list[tuple] = []
    monkeypatch.setattr(unseal_wizard.messagebox, "showerror",
                        lambda *a, **_k: errors.append(a))
    root = new_test_root()
    try:
        wiz = unseal_wizard.UnsealWizard(root, SimpleNamespace(db_path=":memory:"))

        def _refuse() -> Any:
            raise ValueError("seal_mode: stored 'strict', record 'standard'")

        wiz._data["_process"] = SimpleNamespace(run_u7_save=_refuse)
        wiz._run_u7_save()
        deadline = time.monotonic() + 5
        while not errors and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)

        assert len(errors) == 1
        title, message = errors[0][:2]
        assert title == t("unseal.u7_save_failed_title")
        assert "strict" in message
        assert "unseal_result" not in wiz._data
        wiz.destroy()
    finally:
        destroy_test_root(root)
