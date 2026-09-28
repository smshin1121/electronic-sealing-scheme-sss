"""Share files handed out at S6 / R7 (stage E, E1b).

Shares 1 (subject) and 2 (investigator) are saved to two separate files in
the portal contract's share-file format (portal sync interface contract, section 5): one
UTF-8 line ``N-<hex>`` plus a newline, extension ``.share``, at most 4 KB.
A file is written through a temporary file and a rename that never replaces
an existing file, then read back and compared. Only the index and the
fingerprint are logged; no message carries share text.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path

import pytest

from desktop.crypto import recover_key_for_mode, split_key, split_key_strict
from desktop.share_file import (
    SHARE_FILE_MAX_BYTES,
    ShareFileError,
    default_share_filename,
    fingerprint_of,
    write_share_file,
)

CONTRACT_SHARE_RE = re.compile(r"^[1-4]-[0-9a-fA-F]+$")  # contract §5


def _shares(mode: str) -> tuple[str, tuple[str, str, str, str]]:
    key_hex = os.urandom(32).hex()
    split = split_key_strict if mode == "strict" else split_key
    return key_hex, split(key_hex)


def _payload(share: str) -> str:
    return share.split("-", 1)[1]


# ===================================================================
# Format and recovery
# ===================================================================

@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_saved_files_contain_exactly_the_share_line(tmp_path: Path, mode: str) -> None:
    _key, shares = _shares(mode)
    for index in (1, 2):
        path = tmp_path / default_share_filename("S-20260928-0A1B2C", index)
        saved = write_share_file(path, shares[index - 1], index=index)

        data = path.read_bytes()
        assert data == f"{shares[index - 1]}\n".encode("utf-8")
        assert len(data) <= SHARE_FILE_MAX_BYTES == 4096
        assert data.decode("utf-8").count("\n") == 1
        assert path.suffix == ".share"
        assert saved.index == index
        assert saved.path == str(path)
        assert saved.fingerprint == fingerprint_of(shares[index - 1])


@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_shares_read_back_from_the_files_recover_the_key(tmp_path: Path, mode: str) -> None:
    key_hex, shares = _shares(mode)
    p1 = tmp_path / "s1.share"
    p2 = tmp_path / "s2.share"
    write_share_file(p1, shares[0], index=1)
    write_share_file(p2, shares[1], index=2, taken_paths=[str(p1)])

    s1 = p1.read_text(encoding="utf-8").strip()
    s2 = p2.read_text(encoding="utf-8").strip()
    assert recover_key_for_mode(mode, [s1, s2]) == key_hex


@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_file_content_passes_the_web_share_check(tmp_path: Path, mode: str) -> None:
    """The reference web's own checks, used read-only (src/web is not changed)."""
    import web.release_gate as gate

    _key, shares = _shares(mode)
    p1, p2 = tmp_path / "s1.share", tmp_path / "s2.share"
    write_share_file(p1, shares[0], index=1)
    write_share_file(p2, shares[1], index=2)
    text1 = p1.read_text(encoding="utf-8")
    text2 = p2.read_text(encoding="utf-8")

    # s2 as the investigator enters it at the release gate (form text).
    assert gate._presented_s2(text2) == (shares[1], "")
    # s1 as the subject route stores it (stripped) and the gate reads it.
    assert gate._slot_share({1: text1.strip()}, 1) == (shares[0], "")
    for text in (text1, text2):
        assert CONTRACT_SHARE_RE.fullmatch(text.strip())


def test_fingerprint_and_default_names() -> None:
    # desktop.gui needs Tk; a Python built without the Tk library raises
    # ImportError, not ModuleNotFoundError (pytest >= 8.2 needs exc_type).
    pytest.importorskip("tkinter", exc_type=ImportError)
    from desktop.gui import seal_mode_view

    share = "1-" + "0f" * 32
    assert fingerprint_of(share) == hashlib.sha256(share.encode()).hexdigest()[:16]
    assert seal_mode_view.fingerprint_of is fingerprint_of
    assert default_share_filename("S-20260928-0A1B2C", 1) == (
        "S-20260928-0A1B2C_share1_subject.share")
    assert default_share_filename("S-20260928-0A1B2C", 2) == (
        "S-20260928-0A1B2C_share2_investigator.share")
    with pytest.raises(ValueError):
        default_share_filename("S-20260928-0A1B2C", 3)


# ===================================================================
# Refusals: nothing is written, nothing is replaced
# ===================================================================

def _refused(path: Path, share: str, index: int, **kwargs) -> ShareFileError:
    with pytest.raises(ShareFileError) as info:
        write_share_file(path, share, index=index, **kwargs)
    assert _payload(share) not in str(info.value)
    return info.value


def test_an_existing_file_is_never_overwritten(tmp_path: Path) -> None:
    _key, shares = _shares("strict")
    target = tmp_path / "s1.share"
    target.write_bytes(b"do not touch\n")

    error = _refused(target, shares[0], 1)

    assert error.reason == "exists"
    assert target.read_bytes() == b"do not touch\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s1.share"]


@pytest.mark.parametrize("same", [
    lambda p: str(p),
    lambda p: os.path.join(str(p.parent), ".", p.name),
    lambda p: str(p).upper() if os.name == "nt" else str(p),
])
def test_the_same_path_for_both_shares_is_refused(tmp_path: Path, same) -> None:
    _key, shares = _shares("standard")
    first = tmp_path / "shares.share"
    write_share_file(first, shares[0], index=1)

    error = _refused(Path(same(first)), shares[1], 2, taken_paths=[str(first)])

    assert error.reason == "same_path"
    assert first.read_bytes() == f"{shares[0]}\n".encode()


def test_the_share_extension_is_required(tmp_path: Path) -> None:
    _key, shares = _shares("standard")

    error = _refused(tmp_path / "s1.txt", shares[0], 1)

    assert error.reason == "extension"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("share, index, reason", [
    ("2-" + "ab" * 32, 1, "index"),
    ("1-" + "ab" * 32, 2, "index"),
    ("1-xyz", 1, "format"),
    ("1-AB" + "ab" * 31, 1, "format"),
    ("1-", 1, "format"),
    ("", 1, "format"),
    ("1-" + "ab" * 32 + "\n", 1, "format"),
])
def test_malformed_shares_are_refused(tmp_path: Path, share: str, index: int,
                                      reason: str) -> None:
    with pytest.raises(ShareFileError) as info:
        write_share_file(tmp_path / "s.share", share, index=index)

    assert info.value.reason == reason
    if len(share) > 4:
        assert share.strip() not in str(info.value)
    assert list(tmp_path.iterdir()) == []


def test_an_unwritable_place_is_reported(tmp_path: Path) -> None:
    _key, shares = _shares("standard")

    error = _refused(tmp_path / "missing-dir" / "s1.share", shares[0], 1)

    assert error.reason == "io"


def test_a_failed_read_back_removes_the_file(tmp_path: Path, monkeypatch) -> None:
    import desktop.share_file as share_file

    _key, shares = _shares("strict")
    monkeypatch.setattr(share_file, "_read_back", lambda _path: b"1-00\n")
    target = tmp_path / "s1.share"

    error = _refused(target, shares[0], 1)

    assert error.reason == "verify"
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []


def test_no_temporary_file_is_left(tmp_path: Path) -> None:
    _key, shares = _shares("standard")
    write_share_file(tmp_path / "s1.share", shares[0], index=1)
    _refused(tmp_path / "s1.share", shares[0], 1)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["s1.share"]


# ===================================================================
# The no-overwrite publish (both branches run on this host)
# ===================================================================

def _no_links(*_a, **_k):
    raise OSError("hard links not supported")


def test_publish_by_link_never_replaces(tmp_path: Path) -> None:
    from desktop.share_file import _publish_by_link

    tmp = tmp_path / "t.tmp"
    tmp.write_bytes(b"new")
    target = tmp_path / "x.share"
    target.write_bytes(b"old")

    with pytest.raises(FileExistsError):
        _publish_by_link(str(tmp), str(target), b"new")
    assert target.read_bytes() == b"old"

    target.unlink()
    _publish_by_link(str(tmp), str(target), b"new")
    assert target.read_bytes() == b"new"  # the caller removes the temp file


def test_publish_without_hard_links_claims_the_name_exclusively(
    tmp_path: Path, monkeypatch
) -> None:
    """No hard links (FAT/exFAT): O_CREAT|O_EXCL claims the name, writes through it."""
    from desktop import share_file

    monkeypatch.setattr(share_file.os, "link", _no_links)
    tmp = tmp_path / "t.tmp"
    tmp.write_bytes(b"new")
    target = tmp_path / "x.share"
    target.write_bytes(b"old")

    with pytest.raises(FileExistsError):
        share_file._publish_by_link(str(tmp), str(target), b"new")
    assert target.read_bytes() == b"old"

    target.unlink()
    share_file._publish_by_link(str(tmp), str(target), b"new")
    assert target.read_bytes() == b"new"


# ===================================================================
# E1b review fixes: publish races, cleanup, seal_id in file names
# ===================================================================

def _one_share() -> str:
    return _shares("standard")[1][0]


@pytest.mark.skipif(
    os.name != "nt",
    reason="relies on Windows rename semantics; POSIX rename(2) replaces the "
           "target, and the POSIX branch claims the name with O_EXCL instead",
)
def test_windows_rename_collision_is_refused(tmp_path: Path, monkeypatch) -> None:
    """Race on the Windows branch: the name is free at the check, taken at the rename."""
    import desktop.share_file as share_file

    monkeypatch.setattr(share_file, "_RENAME_PUBLISH", True)
    monkeypatch.setattr(share_file, "_target_exists", lambda _path: False)
    target = tmp_path / "s1.share"
    target.write_bytes(b"theirs\n")

    error = _refused(target, _one_share(), 1)

    assert error.reason == "exists"
    assert target.read_bytes() == b"theirs\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s1.share"]


@pytest.mark.parametrize("links", [True, False], ids=["hard-link", "o-excl"])
def test_posix_publish_collision_is_refused(tmp_path: Path, monkeypatch, links: bool) -> None:
    """The same race on the POSIX paths: hard link, and O_EXCL without hard links."""
    import desktop.share_file as share_file

    monkeypatch.setattr(share_file, "_RENAME_PUBLISH", False)
    monkeypatch.setattr(share_file, "_target_exists", lambda _path: False)
    if not links:
        monkeypatch.setattr(share_file.os, "link", _no_links)
    target = tmp_path / "s1.share"
    target.write_bytes(b"theirs\n")

    error = _refused(target, _one_share(), 1)

    assert error.reason == "exists"
    assert target.read_bytes() == b"theirs\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s1.share"]


@pytest.mark.parametrize("links", [True, False], ids=["hard-link", "o-excl"])
def test_posix_publish_writes_the_share(tmp_path: Path, monkeypatch, links: bool) -> None:
    import desktop.share_file as share_file

    monkeypatch.setattr(share_file, "_RENAME_PUBLISH", False)
    if not links:
        monkeypatch.setattr(share_file.os, "link", _no_links)
    share = _one_share()
    target = tmp_path / "s1.share"

    saved = write_share_file(target, share, index=1)

    assert saved.path == str(target)
    assert target.read_bytes() == f"{share}\n".encode()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s1.share"]


def test_a_failed_temp_cleanup_does_not_fail_the_save(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """After the link the target is verified; the temporary name goes best-effort."""
    import desktop.share_file as share_file

    monkeypatch.setattr(share_file, "_RENAME_PUBLISH", False)
    real_unlink = Path.unlink

    def _stuck(self: Path, *args, **kwargs):
        if self.name.startswith(".share-"):
            raise PermissionError(13, "in use")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", _stuck)
    caplog.set_level(logging.DEBUG)
    share = _one_share()
    target = tmp_path / "s1.share"

    saved = write_share_file(target, share, index=1)

    assert saved.path == str(target)
    assert target.read_bytes() == f"{share}\n".encode()
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".share-")]
    assert len(leftovers) == 1  # disclosed: this temporary copy could not be removed
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(leftovers[0].name in message for message in warnings)
    assert _payload(share) not in caplog.text


@pytest.mark.parametrize("seal_id", ["../x", "S-1/2", "a b", "x" * 65, "C:\\x", "S-1\n"])
def test_file_names_refuse_unsafe_seal_ids(seal_id: str) -> None:
    with pytest.raises(ValueError):
        default_share_filename(seal_id, 1)


def test_file_names_for_legacy_and_missing_seal_ids() -> None:
    assert default_share_filename("SEAL-0123456789AB", 1) == (
        "SEAL-0123456789AB_share1_subject.share")
    assert default_share_filename("", 2) == "share2_investigator.share"


# ===================================================================
# Logging: one INFO line per saved share, index and fingerprint only
# ===================================================================

def test_logging_names_only_the_index_and_the_fingerprint(tmp_path: Path, caplog) -> None:
    _key, shares = _shares("strict")
    caplog.set_level(logging.DEBUG)

    write_share_file(tmp_path / "s1.share", shares[0], index=1)
    with pytest.raises(ShareFileError):
        write_share_file(tmp_path / "s1.share", shares[0], index=1)

    ours = [r for r in caplog.records if r.name == "desktop.share_file"]
    assert [r.levelno for r in ours] == [logging.INFO]
    assert fingerprint_of(shares[0]) in ours[0].getMessage()
    for share in shares:
        assert _payload(share) not in caplog.text
        assert all(_payload(share) not in r.getMessage() for r in caplog.records)
