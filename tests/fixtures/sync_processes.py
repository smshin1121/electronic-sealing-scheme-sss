"""Run the real sealing, unsealing and resealing processes for the sync tests.

S4, S6, S7 of :class:`desktop.seal_process.SealProcess`, U7 of
:class:`desktop.unseal_process.UnsealProcess` and R6, R7, R8 of
:class:`desktop.reseal_process.ResealProcess` run as in production; the
steps that need a PAdES signature, a PDF renderer, decryption or large
files are stood in for (S1 and S5 state, U3 to U6 state, R1 to R5 state,
the reseal PDF renderer). The processes then queue and push each completed
record. ``unseal_from_file`` runs U3, U6 and U7 for real on a record file
(U4 and U5 stood in). Synthetic data only; the caller sets
``MASTER_KEY_PATH`` for S6/R7.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

E2E_SEAL_ID = "S-20260928-E2A0E2"
SEAL_KEY_HEX = "5a" * 32
RESEAL_KEY_HEX = "6b" * 32
_TIME = "2026-08-02T00:00:00Z"


def seal_through_process(
    tmp_path: Path, signer: Any, db_path: str, seal_id: str = E2E_SEAL_ID,
    *, registered: bool = True, seal_mode: str = "standard",
) -> Any:
    """S4, S6 and S7 of the real SealProcess; returns the SealResult."""
    return sealing_before_s7(tmp_path, signer, db_path, seal_id,
                             registered=registered, seal_mode=seal_mode).run_s7()


def sealing_before_s7(
    tmp_path: Path, signer: Any, db_path: str, seal_id: str = E2E_SEAL_ID,
    *, registered: bool = True, seal_mode: str = "standard",
) -> Any:
    """The real SealProcess after S4 and S6 (S7 not run yet).

    ``registered`` passes ``seal_id`` as the ID of a case registered in the
    case manager (``SealConfig.seal_id``); otherwise S4 draws one itself
    (``seal_id`` is then ignored). ``seal_mode`` is the recovery regime
    chosen at sealing (``"strict"`` needs the policy signer; stage F, F4).
    """
    import desktop.seal_process as sp
    from desktop.db import init_db

    enc = tmp_path / "evidence.bin.enc"
    enc.write_bytes(b"x" * 64)
    process = sp.SealProcess(db_path=db_path, policy_signer=signer)
    process.set_config(sp.SealConfig(
        source_file=str(tmp_path / "evidence.bin"), output_dir=str(tmp_path),
        chunk_size_bytes=1 << 30, case_number="2026-형제-E2A",
        investigator={"name": "Hong"},
        seizure={"date": _TIME, "location": "Seoul", "device_user": "Kim"},
        media={"type": "SSD", "manufacturer": "M", "model": "X", "serial": "1"},
        subject={"name": "Kim", "email": "k@example.com", "birth": "1990-01-01",
                 "phone": "010-0000-0000", "participation": "yes",
                 "password": "pw"},
        signature_lines=[(0, 0, 1, 1)], unlock_days=0,
        seal_id=seal_id if registered else None, seal_mode=seal_mode,
    ))
    process.state["s1"] = {
        "aes_key_hex": SEAL_KEY_HEX, "enc_filepath": str(enc),
        "encryption_algo": "AES-256-GCM",
        "metadata": {"filename": "evidence.bin", "size": 64, "md5": "0" * 32,
                     "sha256": "0" * 64, "mtime": _TIME, "ctime": _TIME,
                     "atime": _TIME},
        "enc_metadata": {"enc_ended_time": _TIME, "nonces": ["00"],
                         "tags": ["11"], "chunk_lengths": [64]},
    }
    process.run_s4()
    init_db(db_path)
    pdf = tmp_path / "seal_record_signed.pdf"
    pdf.write_bytes(b"%PDF-1.4 synthetic seal record")
    process.state["s5"] = {"pdf_path": str(pdf), "cert_pem": "", "key_pem": b""}
    process.run_s6()
    return process


def unseal_through_process(
    tmp_path: Path, db_path: str, sealed_record_json: str
) -> Any:
    """U7 of the real UnsealProcess on a sealing record; the UnsealResult."""
    return unsealing_before_u7(tmp_path, db_path, sealed_record_json).run_u7_save()


def unsealing_before_u7(
    tmp_path: Path, db_path: str, sealed_record_json: str
) -> Any:
    """The real UnsealProcess on a sealing record, U3 to U6 stood in.

    The unsealing record is built as U6 builds it: the Unsealing event is
    appended to the history and the record is made by
    ``build_unseal_record``. U7 is not run yet.
    """
    import json

    from desktop.record import append_event, build_unseal_record
    from desktop.unseal_process import UnsealConfig, UnsealProcess

    sealed = json.loads(sealed_record_json)
    when = "2026-10-06T01:00:00Z"
    history = append_event(sealed["history"], {
        "seal_type": "Unsealing", "start_time": when, "end_time": when,
        "investigator": "Hong"})
    record = build_unseal_record(
        prev_record={**sealed, "history": history},
        process_info={"type": "Unsealing", "reason": "analysis",
                      "investigator": "Hong", "subject_participated": True,
                      "start_time": when, "end_time": when},
        file_info={"original_files": sealed["file_info"]["original_files"]},
    )
    pdf = tmp_path / "unseal_record.pdf"
    pdf.write_bytes(b"%PDF-1.4 synthetic unseal record")
    process = UnsealProcess(db_path=db_path)
    process.set_config(UnsealConfig(
        enc_filepath="e.enc", seal_record_path="r.json",
        aes_key_hex="0" * 64, output_dir=str(tmp_path), reason="analysis",
        investigator="Hong", subject_participated=True))
    process.state.update({
        "u3": {"seal_record": sealed, "seal_id": sealed["seal_id"],
               "valid": True},
        "u4": {"items": [], "all_matched": True,
               "seal_id": sealed["seal_id"]},
        "u5": {"output_filepath": "out.bin", "hash_verified": True,
               "sha256_match": True, "md5_match": True, "metadata": {}},
        "u6": {"record_dict": record, "record_json_path": "u.json",
               "pdf_path": str(pdf)},
    })
    return process


def reseal_through_process(
    tmp_path: Path, signer: Any, db_path: str, prev: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """R6, R7 and R8 of the real ResealProcess; returns the ResealResult."""
    return resealing_before_r8(tmp_path, signer, db_path, prev,
                               monkeypatch).run_r8_save()


def resealing_before_r8(
    tmp_path: Path, signer: Any, db_path: str, prev: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """The real ResealProcess after R6 and R7 (R8 not run yet)."""
    import desktop.record as record_pkg
    import desktop.reseal_process as rp

    def _stub_render(record: dict, template_name: str, output_path: str) -> str:
        Path(output_path).write_bytes(b"%PDF-1.4 synthetic reseal record")
        return output_path

    monkeypatch.setattr(record_pkg, "render_record_pdf", _stub_render)
    process = rp.ResealProcess(db_path=db_path, policy_signer=signer)
    process.state["r1"] = {"prev_record": prev, "seal_id": prev["seal_id"],
                           "record_path": ""}
    process.state["r2"] = {"known_files": [], "unknown_files": [],
                           "target_dir": str(tmp_path)}
    process.set_config(rp.ResealConfig(
        source_dir=str(tmp_path), output_dir=str(tmp_path),
        chunk_size_bytes=1 << 30, investigator="Hong", reason="analysis",
        subject_participated=True, unlock_days=0,
    ))
    process.state["r5"] = {
        "aes_key_hex": RESEAL_KEY_HEX,
        "enc_results": [{"enc_filepath": str(tmp_path / "e.enc"),
                         "original_filepath": str(tmp_path / "e.bin"),
                         "metadata": {"filename": "e.bin", "size": 1,
                                      "md5": "0" * 32, "sha256": "0" * 64},
                         "chunk_count": 1}],
        "encryption_algo": "AES-256-GCM",
    }
    process.run_r6_record()
    process.run_r7_split_key()
    return process


# ---------------------------------------------------------------------------
# Unsealing from a record file (real U3, U6 and U7; stage E, E2e and E2f)
# ---------------------------------------------------------------------------

def stub_record_render(monkeypatch: pytest.MonkeyPatch) -> None:
    """U6 and R6 render a small synthetic PDF instead of the templates."""
    import desktop.record as record_pkg

    def _render(record: dict, template_name: str, output_path: str) -> str:
        Path(output_path).write_bytes(b"%PDF-1.4 synthetic record")
        return output_path

    monkeypatch.setattr(record_pkg, "render_record_pdf", _render)


def write_record_file(tmp_path: Path, record_json: str, name: str) -> Path:
    """A record JSON on disk, as the operator would load it."""
    path = tmp_path / name
    path.write_text(record_json, encoding="utf-8")
    return path


def unsealing_from_file(tmp_path: Path, db_path: str, record_path: Path,
                        out: str) -> Any:
    """An UnsealProcess from ``record_path`` into its own output folder."""
    from desktop.unseal_process import UnsealConfig, UnsealProcess

    enc = tmp_path / "evidence.bin.enc"
    if not enc.exists():
        enc.write_bytes(b"x" * 64)
    out_dir = tmp_path / out
    out_dir.mkdir()
    process = UnsealProcess(db_path=db_path)
    process.set_config(UnsealConfig(
        enc_filepath=str(enc), seal_record_path=str(record_path),
        aes_key_hex="0" * 64, output_dir=str(out_dir), reason="analysis",
        investigator="Hong", subject_participated=True))
    return process


def unsealing_u4_to_u6(process: Any, tmp_path: Path) -> dict:
    """U4/U5 state stood in (no real ciphertext), then the real U6."""
    process.state["u4"] = {"all_matched": True, "items": [],
                           "seal_id": process.state["u3"]["seal_id"]}
    process.state["u5"] = {"output_filepath": str(tmp_path / "plain.bin"),
                           "hash_verified": True, "sha256_match": True,
                           "md5_match": True, "metadata": {}}
    return process.run_u6_record()


def unseal_from_file(tmp_path: Path, db_path: str, record_path: Path,
                     out: str) -> dict:
    """U3 (real), U4/U5 stood in, U6 and U7 (real); returns U6's result."""
    process = unsealing_from_file(tmp_path, db_path, record_path, out)
    process.run_u3_validate()
    u6 = unsealing_u4_to_u6(process, tmp_path)
    process.run_u7_save()
    return u6
