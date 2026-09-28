"""Identity-protection keys for the web tests (stage E, E3a).

The identity pepper and the privacy master key are random bytes written to
temporary files at run time; no key is hard-coded. ``tests/conftest.py``
points every testing app at one pair per test session: since the Fable gate
fix for finding 5 an app does not start without them. A start-up test
clears both paths before the app is made (:func:`without_privacy_keys`); a
fail-closed request test clears them on a running app
(:func:`clear_privacy_keys`), as a key file lost after start-up would.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key

PEPPER_SIZE = 32
DIGEST_KEY_SETTING = "IDENTITY_PEPPER_PATH"
MASTER_SETTING = "PRIVACY_KMS_MASTER_KEY_PATH"


def write_pepper(path: Path, size: int = PEPPER_SIZE) -> str:
    """Write ``size`` random bytes to ``path``; returns the path."""
    path.write_bytes(os.urandom(size))
    return str(path)


def write_master_key(path: Path) -> str:
    """Create a new 32-byte privacy master key file; returns the path."""
    init_master_key(str(path))
    return str(path)


def make_privacy_key_files(directory: Path) -> tuple[str, str]:
    """A fresh (pepper path, master key path) pair in ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    return (write_pepper(directory / "identity_pepper.bin"),
            write_master_key(directory / "privacy_master.key"))


def set_privacy_keys(
    monkeypatch: pytest.MonkeyPatch, pepper_path: str, master_path: str
) -> None:
    """Point ``TestingConfig`` (read by ``create_app('testing')``) at the keys."""
    from web.config import TestingConfig

    monkeypatch.setattr(TestingConfig, DIGEST_KEY_SETTING, pepper_path)
    monkeypatch.setattr(TestingConfig, MASTER_SETTING, master_path)


def without_privacy_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear both key paths for the next app (it refuses to start)."""
    set_privacy_keys(monkeypatch, "", "")


def clear_privacy_keys(app: Any, unset: str = "both") -> None:
    """Clear the pepper, the master key or ``both`` on a running app."""
    assert unset in ("pepper", "master_key", "both")
    if unset in ("pepper", "both"):
        app.config[DIGEST_KEY_SETTING] = ""
    if unset in ("master_key", "both"):
        app.config[MASTER_SETTING] = ""


def read_pepper(app: Any) -> bytes:
    """The pepper bytes an app is configured with (for expected digests)."""
    return Path(app.config[DIGEST_KEY_SETTING]).read_bytes()
