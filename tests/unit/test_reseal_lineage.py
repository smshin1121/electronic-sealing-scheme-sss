"""A reseal starts only from this desktop's latest record (stage E, E2f; Fable finding 2).

Before: R1 checked the loaded record's mode against the stored record but
not its lineage. After an unsealing on this desktop, the case manager's
reseal prefill proposed the sealing record (``<seal_id>_record.json``
beside the stored PDF), and R1 accepted it. R5 re-encrypted, R6 signed a
new policy, R7 split the key and the operator wrote share files 1 and 2;
only R8 refused, with ``StaleRecordError``.

Now:
- R1 applies U3's history rule: the stored history must be the start of
  the loaded record's, so an older record is refused before R2;
- the case manager's prefill, for unsealing and resealing alike, proposes
  the record file of the stored record's last event
  (``<seal_id>_record.json``, ``_unseal_record.json`` or
  ``_reseal_record.json`` beside the stored PDF).

The sequence is the one Fable named: seal, unseal, then R1. Synthetic data
only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.db import get_case_for_unseal, init_db
from desktop.reseal_process import ResealProcess
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_processes import (
    E2E_SEAL_ID,
    resealing_before_r8,
    seal_through_process,
    stub_record_render,
    unseal_from_file,
    write_record_file,
)


@pytest.fixture()
def env(tmp_path, monkeypatch) -> str:
    """A master key for S6/R7, no configured backend, a desktop DB path."""
    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)
    stub_record_render(monkeypatch)
    return str(tmp_path / "desktop.db")


@pytest.fixture()
def signer(release_pki):
    return load_test_signer(release_pki)


@pytest.fixture()
def sealed(tmp_path, env, signer):
    """Sealed on this desktop; the sealing record written to disk."""
    result = seal_through_process(tmp_path, signer, env)
    path = write_record_file(tmp_path, result.record_json,
                             f"{E2E_SEAL_ID}_record.json")
    return result, path


@pytest.fixture()
def unsealed(tmp_path, env, sealed):
    """Then unsealed on this desktop from the sealing record (real U3-U7)."""
    _result, sealing_file = sealed
    return unseal_from_file(tmp_path, env, sealing_file, "unseal_out")


# ===================================================================
# R1
# ===================================================================

class TestR1:
    def test_the_sealing_record_is_refused_after_an_unsealing(
        self, tmp_path, env, sealed, unsealed
    ) -> None:
        _result, sealing_file = sealed
        process = ResealProcess(db_path=env)

        with pytest.raises(ValueError, match="최신 기록보다 이전"):
            process.run_r1_load(str(sealing_file))

        assert "r1" not in process.state
        with pytest.raises(RuntimeError, match="R1"):
            process.run_r2_compare(str(tmp_path))

    def test_the_unsealing_record_is_accepted(self, env, unsealed) -> None:
        result = ResealProcess(db_path=env).run_r1_load(
            unsealed["record_json_path"])

        assert result["seal_id"] == E2E_SEAL_ID
        assert result["mode_source"] == "stored"

    def test_with_nothing_stored_the_file_is_checked_alone(
        self, tmp_path, sealed
    ) -> None:
        _result, sealing_file = sealed
        other_db = str(tmp_path / "other.db")
        init_db(other_db)

        result = ResealProcess(db_path=other_db).run_r1_load(str(sealing_file))

        assert result["seal_id"] == E2E_SEAL_ID


# ===================================================================
# The case manager's prefill (unseal and reseal share it)
# ===================================================================

class TestPrefill:
    def test_after_sealing_it_proposes_the_sealing_record(
        self, env, sealed
    ) -> None:
        result, _path = sealed

        proposed = get_case_for_unseal(env, E2E_SEAL_ID)["record_json_path"]

        assert proposed == str(Path(result.pdf_path).parent
                               / f"{E2E_SEAL_ID}_record.json")

    def test_after_unsealing_it_proposes_the_unsealing_record(
        self, env, unsealed
    ) -> None:
        proposed = get_case_for_unseal(env, E2E_SEAL_ID)["record_json_path"]

        assert proposed == unsealed["record_json_path"]
        assert Path(proposed).name == f"{E2E_SEAL_ID}_unseal_record.json"
        assert Path(proposed).is_file()

    def test_after_resealing_it_proposes_the_resealing_record(
        self, tmp_path, env, signer, unsealed, monkeypatch
    ) -> None:
        process = resealing_before_r8(tmp_path, signer, env,
                                      unsealed["record_dict"], monkeypatch)
        process.run_r8_save()

        proposed = get_case_for_unseal(env, E2E_SEAL_ID)["record_json_path"]

        assert proposed == process.state["r6"]["record_json_path"]
        assert Path(proposed).name == f"{E2E_SEAL_ID}_reseal_record.json"

    def test_the_proposed_record_passes_r1(self, env, unsealed) -> None:
        """The case manager's reseal: prefill, then R1 (the wizard's path)."""
        proposed = get_case_for_unseal(env, E2E_SEAL_ID)["record_json_path"]

        result = ResealProcess(db_path=env).run_r1_load(proposed)

        assert result["prev_record"] == json.loads(
            Path(proposed).read_text(encoding="utf-8"))

    def test_a_record_without_a_known_last_event_keeps_the_old_name(
        self, tmp_path
    ) -> None:
        from desktop.db import save_seal_record

        db = str(tmp_path / "legacy.db")
        init_db(db)
        legacy = {"seal_id": E2E_SEAL_ID,
                  "history": {"events": [{"event": "seal"}]}}
        save_seal_record(db, E2E_SEAL_ID, json.dumps(legacy),
                         str(tmp_path / "out" / "legacy.pdf"))

        proposed = get_case_for_unseal(db, E2E_SEAL_ID)["record_json_path"]

        assert proposed == str(tmp_path / "out" / f"{E2E_SEAL_ID}_record.json")
