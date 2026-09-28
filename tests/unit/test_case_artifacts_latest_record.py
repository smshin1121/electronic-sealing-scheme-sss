"""Case detail artifacts name the stored record's last event (stage F, F3).

Before v1.2 the case detail view (``get_case_artifacts``) listed
``<seal_id>_record.json`` beside the stored PDF as the case's record JSON,
so after an unsealing or a reseal it named the sealing record's file, or a
file that does not exist in the step's output directory. It also listed
the sealing key file (``<seal_id>_key.pem``, written only at sealing, S5)
beside whatever PDF the case stores now.
"""

from __future__ import annotations

import json
from pathlib import Path

SEAL_ID = "S-20260928-F3F3F3"


def _record(last_step: str) -> dict:
    steps = {"Sealing": ["Sealing"],
             "Unsealing": ["Sealing", "Unsealing"],
             "Resealing": ["Sealing", "Unsealing", "Resealing"]}[last_step]
    return {
        "seal_id": SEAL_ID,
        "process_info": {"type": last_step},
        "file_info": {"result_files": [{"filename": "evidence.bin.enc"}]},
        "history": {"events": [{"event_id": i + 1, "seal_type": step}
                               for i, step in enumerate(steps)]},
    }


def _artifacts(tmp_path: Path, record: dict, pdf_path: Path) -> dict[str, str]:
    from desktop.db.sqlite_store import (
        get_case_artifacts,
        init_db,
        save_seal_record,
    )

    db_path = str(tmp_path / "artifacts.db")
    init_db(db_path)
    save_seal_record(db_path, SEAL_ID, json.dumps(record, ensure_ascii=False),
                     str(pdf_path))
    return {a["file_type"]: a["file_path"]
            for a in get_case_artifacts(db_path, SEAL_ID)}


def test_sealing_lists_the_sealing_record_and_key(tmp_path: Path) -> None:
    out = tmp_path / "seal"
    out.mkdir()
    (out / f"{SEAL_ID}_key.pem").write_bytes(b"key")
    found = _artifacts(tmp_path, _record("Sealing"), out / f"{SEAL_ID}_record.pdf")
    assert found["JSON"] == str(out / f"{SEAL_ID}_record.json")
    assert found["key"] == str(out / f"{SEAL_ID}_key.pem")


def test_unsealing_lists_the_unseal_record(tmp_path: Path) -> None:
    out = tmp_path / "unseal"
    found = _artifacts(tmp_path, _record("Unsealing"),
                       out / f"{SEAL_ID}_unseal_record.pdf")
    assert found["JSON"] == str(out / f"{SEAL_ID}_unseal_record.json")


def test_resealing_lists_the_reseal_record(tmp_path: Path) -> None:
    out = tmp_path / "reseal"
    found = _artifacts(tmp_path, _record("Resealing"),
                       out / f"{SEAL_ID}_reseal_record.pdf")
    assert found["JSON"] == str(out / f"{SEAL_ID}_reseal_record.json")


def test_key_file_not_listed_where_a_later_step_wrote_no_key(tmp_path: Path) -> None:
    """After an unsealing into another folder there is no key file beside
    the stored PDF: the sealing key stays beside the sealing PDF."""
    out = tmp_path / "unseal"
    out.mkdir()
    found = _artifacts(tmp_path, _record("Unsealing"),
                       out / f"{SEAL_ID}_unseal_record.pdf")
    assert "key" not in found


def test_key_file_listed_when_a_later_step_used_the_sealing_folder(
    tmp_path: Path,
) -> None:
    out = tmp_path / "same"
    out.mkdir()
    (out / f"{SEAL_ID}_key.pem").write_bytes(b"key")
    found = _artifacts(tmp_path, _record("Resealing"),
                       out / f"{SEAL_ID}_reseal_record.pdf")
    assert found["key"] == str(out / f"{SEAL_ID}_key.pem")
