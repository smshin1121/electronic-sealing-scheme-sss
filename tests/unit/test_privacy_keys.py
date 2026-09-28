"""Identity-protection keys: runtime loading and start-up validation (E3a).

Two files are configured by path: the identity pepper
(``IDENTITY_PEPPER_PATH``, 32 to 1024 random bytes) and the privacy master
key (``PRIVACY_KMS_MASTER_KEY_PATH``, a 32-byte local-KMS key, separate
from the release master key). Unset (since the Fable gate fix for finding
5), set but unusable, or the same key used twice: the app refuses to start.
At request time a key that is unset or unreadable is
:class:`PrivacyUnavailable` (HTTP 503 in the routes). Keys are generated
per test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from flask import Flask

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.privacy_keys import (
    make_privacy_key_files,
    set_privacy_keys,
    write_pepper,
)
from web.privacy.keys import (
    PrivacyConfigError,
    PrivacyUnavailable,
    load_privacy_keys,
    privacy_keys_configured,
)


def _create(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **config: Any) -> Any:
    from web.config import TestingConfig

    monkeypatch.setenv("USE_SQLITE", "true")
    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(tmp_path / "keys.db"))
    for name, value in config.items():
        monkeypatch.setattr(TestingConfig, name, value, raising=False)
    from web.app import create_app

    return create_app("testing")


def _config(pepper: str, master: str) -> dict[str, str]:
    return {"IDENTITY_PEPPER_PATH": pepper, "PRIVACY_KMS_MASTER_KEY_PATH": master}


class TestRuntimeLoading:
    def test_both_keys_are_loaded(self, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path)

        keys = load_privacy_keys(_config(pepper, master))

        assert keys.pepper == Path(pepper).read_bytes()
        assert keys.master_key == Path(master).read_bytes()
        assert keys.master_key_path == master
        assert privacy_keys_configured(_config(pepper, master)) is True

    def test_keys_are_not_in_repr(self, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path)
        keys = load_privacy_keys(_config(pepper, master))

        text = repr(keys)
        assert keys.pepper.hex() not in text and keys.master_key.hex() not in text
        assert repr(keys.pepper) not in text and repr(keys.master_key) not in text

    @pytest.mark.parametrize("which", ["neither", "pepper_only", "master_only"])
    def test_unset_keys_are_unavailable(self, tmp_path, which: str) -> None:
        pepper, master = make_privacy_key_files(tmp_path)
        config = {"neither": _config("", ""), "pepper_only": _config(pepper, ""),
                  "master_only": _config("", master)}[which]

        assert privacy_keys_configured(config) is False
        with pytest.raises(PrivacyUnavailable):
            load_privacy_keys(config)

    def test_a_key_file_gone_at_runtime_is_unavailable(self, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path)
        Path(pepper).unlink()

        with pytest.raises(PrivacyUnavailable):
            load_privacy_keys(_config(pepper, master))

    def test_keys_come_from_the_app_config(self, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path)
        app = Flask("privacy-keys-test")
        app.config.update(_config(pepper, master))

        with app.app_context():
            assert load_privacy_keys().pepper == Path(pepper).read_bytes()


class TestStartupValidation:
    def test_valid_keys_start(self, monkeypatch, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path / "keys")
        set_privacy_keys(monkeypatch, pepper, master)

        app = _create(monkeypatch, tmp_path)

        assert app.config["IDENTITY_PEPPER_PATH"] == pepper

    @pytest.mark.parametrize("unset", ["pepper", "master_key", "both"])
    def test_unset_keys_refuse_to_start(self, monkeypatch, tmp_path, unset) -> None:
        # Fable gate, finding 5: since E3b every release on a seal with
        # records needs them, so a missing key is a start-up error.
        pepper, master = make_privacy_key_files(tmp_path / "keys")
        set_privacy_keys(monkeypatch, "" if unset in ("pepper", "both") else pepper,
                         "" if unset in ("master_key", "both") else master)
        named = {"pepper": ["IDENTITY_PEPPER_PATH"],
                 "master_key": ["PRIVACY_KMS_MASTER_KEY_PATH"],
                 "both": ["IDENTITY_PEPPER_PATH", "PRIVACY_KMS_MASTER_KEY_PATH"]}[unset]

        with pytest.raises(PrivacyConfigError) as info:
            _create(monkeypatch, tmp_path)

        assert all(setting in str(info.value) for setting in named)
        assert "not set" in str(info.value)

    def test_a_set_key_is_checked_before_a_missing_one_is_reported(
        self, monkeypatch, tmp_path
    ) -> None:
        pepper = write_pepper(tmp_path / "short.bin", 16)
        set_privacy_keys(monkeypatch, pepper, "")

        with pytest.raises(PrivacyConfigError, match="IDENTITY_PEPPER_PATH is configured but unusable"):
            _create(monkeypatch, tmp_path)

    @pytest.mark.parametrize("size", [0, 31, 1025])
    def test_pepper_of_the_wrong_size_refuses_to_start(self, monkeypatch, tmp_path, size) -> None:
        _, master = make_privacy_key_files(tmp_path / "keys")
        pepper = write_pepper(tmp_path / "bad_pepper.bin", size)
        set_privacy_keys(monkeypatch, pepper, master)

        with pytest.raises(PrivacyConfigError, match="IDENTITY_PEPPER_PATH"):
            _create(monkeypatch, tmp_path)

    def test_missing_pepper_file_refuses_to_start(self, monkeypatch, tmp_path) -> None:
        _, master = make_privacy_key_files(tmp_path / "keys")
        set_privacy_keys(monkeypatch, str(tmp_path / "absent.bin"), master)

        with pytest.raises(PrivacyConfigError, match="IDENTITY_PEPPER_PATH"):
            _create(monkeypatch, tmp_path)

    @pytest.mark.parametrize("which", ["missing", "wrong_size"])
    def test_unusable_master_key_refuses_to_start(self, monkeypatch, tmp_path, which) -> None:
        pepper, _ = make_privacy_key_files(tmp_path / "keys")
        master = tmp_path / "bad_master.key"
        if which == "wrong_size":
            master.write_bytes(b"\x01" * 16)
        set_privacy_keys(monkeypatch, pepper, str(master))

        with pytest.raises(PrivacyConfigError, match="PRIVACY_KMS_MASTER_KEY_PATH"):
            _create(monkeypatch, tmp_path)

    def test_pepper_equal_to_the_master_key_refuses_to_start(self, monkeypatch, tmp_path) -> None:
        _, master = make_privacy_key_files(tmp_path / "keys")
        set_privacy_keys(monkeypatch, master, master)

        with pytest.raises(PrivacyConfigError, match="same key"):
            _create(monkeypatch, tmp_path)

    def test_release_master_key_cannot_be_reused(self, monkeypatch, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path / "keys")
        set_privacy_keys(monkeypatch, pepper, master)

        with pytest.raises(PrivacyConfigError, match="RELEASE_KMS_MASTER_KEY_PATH"):
            _create(monkeypatch, tmp_path, RELEASE_KMS_MASTER_KEY_PATH=master)

    def test_a_separate_release_master_key_is_accepted(self, monkeypatch, tmp_path) -> None:
        pepper, master = make_privacy_key_files(tmp_path / "keys")
        release = str(tmp_path / "release_master.key")
        init_master_key(release)
        set_privacy_keys(monkeypatch, pepper, master)

        app = _create(monkeypatch, tmp_path, RELEASE_KMS_MASTER_KEY_PATH=release)

        assert app.config["RELEASE_KMS_MASTER_KEY_PATH"] == release

    def test_error_names_the_setting_but_no_key_bytes(self, monkeypatch, tmp_path) -> None:
        _, master = make_privacy_key_files(tmp_path / "keys")
        pepper = write_pepper(tmp_path / "short.bin", 16)
        set_privacy_keys(monkeypatch, pepper, master)

        with pytest.raises(PrivacyConfigError) as info:
            _create(monkeypatch, tmp_path)

        assert Path(pepper).read_bytes().hex() not in str(info.value)
