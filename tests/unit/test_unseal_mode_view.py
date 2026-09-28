"""Unsealing shows the record's seal mode and the shares a recovery needs (E1).

The desktop unseal wizard takes an AES key that was recovered elsewhere (the
release gate of the remote participation system, which dispatches strict
through ``recover_key_for_mode``); no desktop path combines shares to
unseal. The wizard therefore shows, once the record is loaded (U4) and on
U6/U7, which mode governs the seal and which shares its recovery needs:
standard any two of s1-s4; strict the subject's s1 plus one institutional
share.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional
from unittest import mock

import pytest

from desktop.gui.i18n import t
from desktop.gui.seal_mode_view import describe_seal_mode, seal_mode_rows
from tests.fixtures.tk_root import destroy_test_root, new_test_root


# ===================================================================
# describe_seal_mode / seal_mode_rows
# ===================================================================

@pytest.mark.parametrize("record, mode, label_key, shares_key", [
    ({"seal_mode": "standard"}, "standard", "mode.standard", "mode.shares_standard"),
    ({"seal_mode": "strict"}, "strict", "mode.strict", "mode.shares_strict"),
    ({}, "standard", "mode.legacy", "mode.shares_standard"),
    ({"seal_mode": "strict", "policy": {"seal_mode": "strict"}}, "strict",
     "mode.strict", "mode.shares_strict"),
])
def test_describe_valid_modes(record: dict, mode: str, label_key: str,
                              shares_key: str) -> None:
    view = describe_seal_mode(record)

    assert (view.mode, view.label, view.shares, view.problem) == (
        mode, t(label_key), t(shares_key), False)


@pytest.mark.parametrize("record", [
    {"seal_mode": "Strict"},
    {"seal_mode": "standard", "policy": {"seal_mode": "strict"}},
    {"policy": {"seal_mode": "strict"}},
    None,
])
def test_describe_flags_unusable_modes(record: Optional[dict]) -> None:
    view = describe_seal_mode(record)

    assert view.problem is True
    assert view.mode is None
    assert view.shares == ""


def test_rows_mark_strict_and_problems() -> None:
    strict = seal_mode_rows({"seal_mode": "strict"})
    assert strict[0] == (t("summary.seal_mode"), t("mode.strict"), "warning")
    assert strict[1] == (t("summary.recovery_shares"), t("mode.shares_strict"))
    assert seal_mode_rows({"seal_mode": "x"})[0][2] == "danger"
    kept = seal_mode_rows({"seal_mode": "strict"}, kept=True)
    assert kept[0][1] == t("mode.kept").format(v=t("mode.strict"))


# ===================================================================
# The unseal wizard shows them
# ===================================================================

def _strict_record() -> dict[str, Any]:
    return {
        "seal_id": "S-20260928-0D0D0D", "seal_mode": "strict",
        "unlock_time_iso": "2026-10-05T00:00:00Z", "key_commitment": "ab" * 32,
        "case_info": {"case_number": "2026-E1-U"},
        "file_info": {"original_files": [{"filename": "e.bin", "size": 1,
                                          "sha256": "0" * 64, "md5": "0" * 32}],
                      "result_files": [{"filename": "e.bin.enc"}]},
        "history": {"summary": "S1U0R0", "events": []},
    }


@pytest.fixture()
def wizard(monkeypatch):
    from desktop.gui import unseal_wizard

    root = new_test_root()
    monkeypatch.setattr(unseal_wizard.messagebox, "showerror", lambda *a, **_k: None)
    wiz = unseal_wizard.UnsealWizard(root, SimpleNamespace(db_path=":memory:"))
    yield wiz
    wiz.destroy()
    destroy_test_root(root)


def _rows(summary: Any, refresh: Any) -> list[tuple]:
    captured: list[list[dict]] = []
    with mock.patch.object(summary, "render", side_effect=captured.append):
        refresh()
    return [row for section in captured[0] for row in section.get("rows", [])]


def test_u4_shows_the_mode_of_the_loaded_record(wizard, tmp_path: Path) -> None:
    from desktop.gui.unseal_wizard import compute_preseal_validation

    record_path = tmp_path / "S-20260928-0D0D0D_record.json"
    record_path.write_text(json.dumps(_strict_record()), encoding="utf-8")
    enc = tmp_path / "e.bin.enc"
    enc.write_bytes(b"\x00" * 64)
    updates = compute_preseal_validation(":memory:", {
        "enc_filepath": str(enc), "seal_record_path": str(record_path),
        "aes_key_hex": "ab" * 32, "output_dir": str(tmp_path), "reason": "r",
        "investigator": "Hong", "subject_participated": True,
    })
    wizard._data.update(updates)

    rows = _rows(wizard._u4_summary, wizard._refresh_u4_results)
    assert (t("summary.seal_mode"), t("mode.strict"), "warning") in rows
    assert (t("summary.recovery_shares"), t("mode.shares_strict")) in rows


def test_u4_without_a_loaded_record_adds_no_mode_rows(wizard) -> None:
    wizard._data.update({"verification_items": [], "all_matched": False,
                         "verification_error": "bad record"})

    rows = _rows(wizard._u4_summary, wizard._refresh_u4_results)
    assert not any(row[0] == t("summary.seal_mode") for row in rows)


def test_u6_and_u7_show_the_mode(wizard) -> None:
    record = _strict_record()
    wizard._data.update({"seal_record": record,
                         "record_result": {"record_dict": record},
                         "decrypt_result": {"hash_verified": True}})

    u6 = _rows(wizard._u6_summary, wizard._refresh_u6_preview)
    u7 = _rows(wizard._u7_summary, wizard._refresh_u7_summary)
    for rows in (u6, u7):
        assert (t("summary.recovery_shares"), t("mode.shares_strict")) in rows


def test_u3_explains_where_the_key_comes_from(wizard) -> None:
    assert wizard._key_hint_label.cget("text") == t("unseal.key_hint")
    for lang in ("ko", "en"):
        from desktop.gui.i18n import _TRANSLATIONS

        assert _TRANSLATIONS["unseal.key_hint"][lang]


def test_no_desktop_unseal_path_combines_shares() -> None:
    """Unsealing takes the recovered key; share recombination is the release gate's."""
    import desktop.gui.unseal_wizard as uw
    import desktop.unseal_process as up

    for module in (uw, up):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "recover_key" not in source, module.__name__
