"""The programmatic sealing path as driven by the GUI wizard (stage E, E1).

The seal wizard seals through ``SealProcess``: S1 encrypts through
``run_s1`` (resume-safe, the wizard's ``<name>.enc`` naming) and S4-S7 run
through ``run_seal_steps``, which maps the wizard data to ``SealConfig``
and names the failing step. A case registered in the case manager passes
its seal_id to S4; the id must have the record format.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import desktop.crypto as crypto_pkg
from desktop.seal_process import (
    SealConfig,
    SealProcess,
    SealResult,
    run_seal_in_background,
    seal_output_path,
)
from desktop.seal_steps import SealStepError, run_seal_steps, seal_config_from_wizard

KEY_HEX = "cd" * 32


def _wizard_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "source_file": "C:/evidence/disk.dd",
        "output_dir": "C:/out",
        "chunk_size_gb": 2,
        "case_number": "2026-E1-001",
        "investigator": {"name": "Hong", "rank": "Inspector"},
        "seizure": {"date": "2026-09-28T01:02:00Z", "location": "Seoul",
                    "device_user": "Kim"},
        "media": {"type": "SSD", "manufacturer": "M", "model": "X",
                  "serial": "1"},
        "subject": {"name": "Kim", "email": "k@example.com",
                    "birth": "1990-01-01", "phone": "010-0000-0000",
                    "password": "pw", "participation": "yes"},
        "signature_lines": [(0, 0, 1, 1)],
        "seal_mode": "strict",
        "unlock_days": 7,
        "seal_id": "S-20260928-0A1B2C",
    }
    data.update(overrides)
    return data


def _result() -> SealResult:
    return SealResult(
        seal_id="S-20260928-0A1B2C", enc_filepath="C:/out/disk.dd.enc",
        pdf_path="C:/out/x.pdf", key_shares=("1-a", "2-b", "3-c", "4-d"),
        unlock_time_iso="2026-10-05T00:00:00Z", record_json="{}",
    )


def _process() -> mock.MagicMock:
    process = mock.create_autospec(SealProcess, instance=True)
    process.state = {}
    process.config = None
    process.run_s7.return_value = _result()
    return process


# ===================================================================
# Wizard data -> SealConfig
# ===================================================================

class TestSealConfigFromWizard:
    def test_maps_every_field(self) -> None:
        config = seal_config_from_wizard(_wizard_data())

        assert config.seal_mode == "strict"
        assert config.unlock_days == 7
        assert config.seal_id == "S-20260928-0A1B2C"
        assert config.chunk_size_bytes == 2 * 1024 ** 3
        assert config.case_number == "2026-E1-001"
        assert config.seizure["date"] == "2026-09-28T01:02:00Z"
        assert config.media["type"] == "SSD"
        assert config.subject["password"] == "pw"

    def test_defaults_to_standard_and_a_generated_seal_id(self) -> None:
        data = _wizard_data()
        del data["seal_mode"], data["seal_id"]
        config = seal_config_from_wizard(data)

        assert config.seal_mode == "standard"
        assert config.seal_id is None

    def test_wizard_dicts_are_copied(self) -> None:
        data = _wizard_data()
        config = seal_config_from_wizard(data)
        data["subject"]["name"] = "changed later"

        assert config.subject["name"] == "Kim"


# ===================================================================
# run_seal_steps: S4 -> S7 in order, failing step named
# ===================================================================

class TestRunSealSteps:
    def test_runs_s4_to_s7_in_order(self) -> None:
        process = _process()
        steps: list[str] = []

        result = run_seal_steps(
            process, _wizard_data(), on_step=lambda step, _m: steps.append(step)
        )

        names = [c[0] for c in process.mock_calls]
        assert names == ["set_config", "run_s4", "run_s5", "run_s6", "run_s7"]
        assert result is process.run_s7.return_value
        assert steps == ["S4", "S5", "S6", "S7"]
        assert process.set_config.call_args.args[0].seal_mode == "strict"

    def test_s5_status_messages_reach_on_step(self) -> None:
        process = _process()

        def _s5(status_cb=None):
            status_cb("PDF signed successfully")
            return {}

        process.run_s5.side_effect = _s5
        messages: list[tuple[str, str]] = []
        run_seal_steps(process, _wizard_data(),
                       on_step=lambda s, m: messages.append((s, m)))

        assert ("S5", "PDF signed successfully") in messages

    def test_a_failure_names_the_step_and_stops(self) -> None:
        process = _process()
        boom = RuntimeError("TSA down")
        process.run_s5.side_effect = boom

        with pytest.raises(SealStepError) as info:
            run_seal_steps(process, _wizard_data())

        assert info.value.step == "S5"
        assert info.value.cause is boom
        process.run_s6.assert_not_called()
        process.run_s7.assert_not_called()

    def test_a_bad_config_fails_at_s4(self) -> None:
        process = _process()
        data = _wizard_data()
        del data["case_number"]

        with pytest.raises(SealStepError) as info:
            run_seal_steps(process, data)

        assert info.value.step == "S4"
        process.run_s4.assert_not_called()

    def test_background_wrapper_reports_the_failing_step(self) -> None:
        process = _process()
        boom = RuntimeError("disk full")
        process.run_s7.side_effect = boom
        errors: list[tuple[str, Exception]] = []

        thread = run_seal_in_background(
            process, _wizard_data(), db_path="unused",
            on_error=lambda step, exc: errors.append((step, exc)),
        )
        thread.join(timeout=10)

        assert errors == [("S7", boom)]


# ===================================================================
# S1: resume-safe key, the wizard's output naming
# ===================================================================

class TestRunS1:
    def test_output_is_named_after_the_full_source_name(self, tmp_path: Path) -> None:
        source = tmp_path / "disk.dd"
        source.write_bytes(os.urandom(4096))
        out = tmp_path / "out"
        out.mkdir()

        result = SealProcess(db_path=str(tmp_path / "s.db")).run_s1(
            str(source), str(out), 1
        )

        assert result["enc_filepath"] == seal_output_path(str(source), str(out))
        assert Path(result["enc_filepath"]).name == "disk.dd.enc"
        assert Path(result["enc_filepath"]).exists()

    def test_a_retry_reuses_the_session_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "disk.dd"
        source.write_bytes(os.urandom(4096))
        real_encrypt = crypto_pkg.encrypt_file
        keys: list[bytes] = []

        def _encrypt(**kwargs: Any) -> Any:
            keys.append(kwargs["aes_key"])
            if len(keys) == 1:
                raise RuntimeError("cancelled by the user")
            return real_encrypt(**kwargs)

        monkeypatch.setattr(crypto_pkg, "encrypt_file", _encrypt)
        process = SealProcess(db_path=str(tmp_path / "s.db"))
        with pytest.raises(RuntimeError):
            process.run_s1(str(source), str(tmp_path), 1)
        result = process.run_s1(str(source), str(tmp_path), 1)

        assert keys[0] == keys[1]
        assert result["aes_key_hex"] == keys[0].hex()


# ===================================================================
# S4: the case workflow's seal_id
# ===================================================================

def _process_after_s1(tmp_path: Path, seal_id: str | None) -> SealProcess:
    enc = tmp_path / "evidence.bin.enc"
    enc.write_bytes(b"x" * 64)
    process = SealProcess(db_path=str(tmp_path / "seal.db"))
    # Standard: strict needs a signed policy (test_e1_review_fixes.py), and
    # these tests are about the seal_id, with no policy key configured.
    process.set_config(seal_config_from_wizard(
        _wizard_data(source_file=str(tmp_path / "evidence.bin"),
                     output_dir=str(tmp_path), seal_id=seal_id,
                     seal_mode="standard")
    ))
    process.state["s1"] = {
        "aes_key_hex": KEY_HEX, "enc_filepath": str(enc),
        "encryption_algo": "AES-256-GCM",
        "metadata": {"filename": "evidence.bin", "size": 64, "md5": "0" * 32,
                     "sha256": "0" * 64, "mtime": "2026-09-28T00:00:00Z",
                     "ctime": "2026-09-28T00:00:00Z",
                     "atime": "2026-09-28T00:00:00Z"},
        "enc_metadata": {"enc_ended_time": "2026-09-28T00:00:00Z",
                         "nonces": ["00"], "tags": ["11"],
                         "chunk_lengths": [64]},
    }
    return process


class TestPreassignedSealId:
    @pytest.fixture(autouse=True)
    def _no_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("ENC_ENVELOPE_POLICY_KEY_PATH",
                     "ENC_ENVELOPE_POLICY_CERT_PATH",
                     "ENC_ENVELOPE_POLICY_KEY_PASSWORD"):
            monkeypatch.delenv(name, raising=False)

    def test_s4_uses_the_case_seal_id(self, tmp_path: Path) -> None:
        record = _process_after_s1(tmp_path, "S-20260928-0A1B2C").run_s4()[
            "record_dict"]

        assert record["seal_id"] == "S-20260928-0A1B2C"
        assert record["seal_mode"] == "standard"
        assert record["key_commitment"] == hashlib.sha256(
            bytes.fromhex(KEY_HEX)).hexdigest()

    def test_s4_generates_a_seal_id_without_one(self, tmp_path: Path) -> None:
        from desktop.record import is_valid_seal_id

        record = _process_after_s1(tmp_path, None).run_s4()["record_dict"]

        assert is_valid_seal_id(record["seal_id"])

    def test_s4_refuses_a_legacy_case_id(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="seal_id"):
            _process_after_s1(tmp_path, "SEAL-0123456789AB").run_s4()


class TestSealIdFormat:
    @pytest.mark.parametrize("value, expected", [
        ("S-20260928-0A1B2C", True),
        ("SEAL-0123456789AB", False),
        ("S-20260928-0a1b2c", False),
        ("S-20260928-0A1B2C\n", False),
        ("", False),
        (None, False),
    ])
    def test_is_valid_seal_id(self, value: Any, expected: bool) -> None:
        from desktop.record import is_valid_seal_id

        assert is_valid_seal_id(value) is expected

    def test_new_cases_get_record_format_ids(self, tmp_path: Path) -> None:
        from desktop.db import create_case, init_db
        from desktop.record import is_valid_seal_id

        db = str(tmp_path / "cases.db")
        init_db(db)
        seal_id = create_case(db, "2026-E1-001", "Hong", "Kim")

        assert is_valid_seal_id(seal_id)


def test_seal_config_keeps_its_old_positional_shape() -> None:
    """seal_id is keyword-only in practice: appended with a default."""
    config = SealConfig("s", "o", 1, "c", {}, {}, {}, {}, [])
    assert config.seal_id is None
    assert config.seal_mode == "standard"
