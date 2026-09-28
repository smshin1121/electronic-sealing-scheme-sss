"""Release configuration is validated when the web app is created.

Stage D fix round (Fable finding 4, a release condition): a configured but
unreadable pinned CA, KMS master key or TSA certificate refuses to start
the app, instead of turning every policy-bearing seal into a runtime
denial. ``RELEASE_REQUIRE_POLICY`` needs a pinned CA. Unset values keep
the documented fail-closed runtime behaviour (the time-locked path denies).
"""

from __future__ import annotations

from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.signature.tsa_server import DEFAULT_TSA_POLICY_OID


def _create(monkeypatch: pytest.MonkeyPatch, tmp_path, **config: Any) -> Any:
    from web.config import TestingConfig

    monkeypatch.setenv("USE_SQLITE", "true")
    monkeypatch.setattr(TestingConfig, "SQLITE_PATH", str(tmp_path / "cfg.db"))
    for name, value in config.items():
        monkeypatch.setattr(TestingConfig, name, value, raising=False)
    from web.app import create_app

    return create_app("testing")


@pytest.fixture()
def master_key(tmp_path) -> str:
    path = str(tmp_path / "release_master.key")
    init_master_key(path)
    return path


def _config_error() -> type[Exception]:
    from web.release_config import ReleaseConfigError

    return ReleaseConfigError


class TestStartupValidation:
    def test_unset_release_configuration_starts(self, monkeypatch, tmp_path) -> None:
        app = _create(monkeypatch, tmp_path, POLICY_CA_CERT_PATH="",
                      RELEASE_KMS_MASTER_KEY_PATH="", RELEASE_TSA_CERT_PATH="",
                      RELEASE_REQUIRE_POLICY=False)
        assert app is not None

    def test_valid_release_configuration_starts(
        self, monkeypatch, tmp_path, release_pki, master_key
    ) -> None:
        app = _create(
            monkeypatch, tmp_path,
            POLICY_CA_CERT_PATH=str(release_pki.ca_cert_path),
            RELEASE_KMS_MASTER_KEY_PATH=master_key,
            RELEASE_TSA_CERT_PATH=str(release_pki.tsa_cert_path),
            RELEASE_TSA_CA_CERT_PATH=str(release_pki.ca_cert_path),
            RELEASE_TSA_POLICY_OID=DEFAULT_TSA_POLICY_OID,
            RELEASE_REQUIRE_POLICY=True,
        )
        assert app.config["RELEASE_REQUIRE_POLICY"] is True
        assert app.config["RELEASE_TSA_POLICY_OID"] == DEFAULT_TSA_POLICY_OID

    @pytest.mark.parametrize("which", ["missing", "not_a_ca"])
    def test_unusable_pinned_ca_refuses_to_start(
        self, monkeypatch, tmp_path, release_pki, which: str
    ) -> None:
        path = (tmp_path / "absent.pem" if which == "missing"
                else release_pki.policy_cert_path)
        with pytest.raises(_config_error(), match="POLICY_CA_CERT_PATH"):
            _create(monkeypatch, tmp_path, POLICY_CA_CERT_PATH=str(path))

    @pytest.mark.parametrize("which", ["missing", "wrong_size"])
    def test_unusable_master_key_refuses_to_start(
        self, monkeypatch, tmp_path, which: str
    ) -> None:
        path = tmp_path / "master.key"
        if which == "wrong_size":
            path.write_bytes(b"\x00" * 16)
        with pytest.raises(_config_error(), match="RELEASE_KMS_MASTER_KEY_PATH"):
            _create(monkeypatch, tmp_path,
                    RELEASE_KMS_MASTER_KEY_PATH=str(path))

    @pytest.mark.parametrize("which", ["missing", "not_a_certificate"])
    def test_unusable_tsa_certificate_refuses_to_start(
        self, monkeypatch, tmp_path, which: str
    ) -> None:
        path = tmp_path / "tsa.pem"
        if which == "not_a_certificate":
            path.write_text("not a certificate", encoding="ascii")
        with pytest.raises(_config_error(), match="RELEASE_TSA_CERT_PATH"):
            _create(monkeypatch, tmp_path, RELEASE_TSA_CERT_PATH=str(path))

    def test_require_policy_without_a_pinned_ca_refuses_to_start(
        self, monkeypatch, tmp_path
    ) -> None:
        with pytest.raises(_config_error(), match="RELEASE_REQUIRE_POLICY"):
            _create(monkeypatch, tmp_path, POLICY_CA_CERT_PATH="",
                    RELEASE_REQUIRE_POLICY=True)


class TestTsaTrustProfileStartup:
    """Stage E (E2b): the pinned TSA CA, policy OID and optional leaf pin."""

    @pytest.mark.parametrize("which", ["missing", "not_a_certificate",
                                       "not_a_ca"])
    def test_unusable_tsa_ca_refuses_to_start(
        self, monkeypatch, tmp_path, release_pki, which: str
    ) -> None:
        path = tmp_path / "tsa_ca.pem"
        if which == "not_a_certificate":
            path.write_text("not a certificate", encoding="ascii")
        elif which == "not_a_ca":
            path = release_pki.tsa_cert_path
        with pytest.raises(_config_error(), match="RELEASE_TSA_CA_CERT_PATH"):
            _create(monkeypatch, tmp_path, RELEASE_TSA_CA_CERT_PATH=str(path))

    @pytest.mark.parametrize("oid", ["1.2.x", "3.1", "1", "01.2", "1.40.2",
                                     "1..2", "1.2."])
    def test_malformed_policy_oid_refuses_to_start(
        self, monkeypatch, tmp_path, oid: str
    ) -> None:
        with pytest.raises(_config_error(), match="RELEASE_TSA_POLICY_OID"):
            _create(monkeypatch, tmp_path, RELEASE_TSA_POLICY_OID=oid)

    @pytest.mark.parametrize("which", ["other_ca", "wrong_eku"])
    def test_leaf_pin_the_profile_cannot_accept_refuses_to_start(
        self, monkeypatch, tmp_path, release_pki, which: str
    ) -> None:
        # A pin that no token could match would deny every time-locked
        # release at run time; it is refused at start-up instead.
        pin = (release_pki.other_policy_cert_path if which == "other_ca"
               else release_pki.policy_cert_path)
        with pytest.raises(_config_error(), match="RELEASE_TSA_CERT_PATH"):
            _create(monkeypatch, tmp_path,
                    RELEASE_TSA_CA_CERT_PATH=str(release_pki.ca_cert_path),
                    RELEASE_TSA_CERT_PATH=str(pin))

    @pytest.mark.parametrize("key_kind", ["ec_p256", "rsa_1024"])
    @pytest.mark.parametrize("with_ca", [True, False])
    def test_leaf_pin_with_an_unusable_key_refuses_to_start(
        self, monkeypatch, tmp_path, release_pki, key_kind: str, with_ca: bool
    ) -> None:
        # Codex round 1, F4: correctly issued and purpose-correct, but the
        # runtime verifier accepts RSA >= 2048 bits only, so every token
        # signed with this key would be rejected.
        from tests.fixtures.tsa_forge import make_tsa_cert, new_ec_key, new_key, pem

        key = new_ec_key() if key_kind == "ec_p256" else new_key(1024)
        _key, leaf = make_tsa_cert(release_pki.ca_key, release_pki.ca_cert,
                                   key=key)
        pin = tmp_path / f"{key_kind}_pin.pem"
        pin.write_bytes(pem(leaf))
        ca = str(release_pki.ca_cert_path) if with_ca else ""
        with pytest.raises(_config_error(), match="RELEASE_TSA_CERT_PATH"):
            _create(monkeypatch, tmp_path, RELEASE_TSA_CA_CERT_PATH=ca,
                    RELEASE_TSA_CERT_PATH=str(pin))

    def test_tsa_ca_with_a_short_key_refuses_to_start(
        self, monkeypatch, tmp_path
    ) -> None:
        from tests.fixtures.tsa_forge import make_ca, new_key, pem

        _key, short_ca = make_ca("E2b Short-key CA", key=new_key(1024))
        path = tmp_path / "short_ca.pem"
        path.write_bytes(pem(short_ca))
        with pytest.raises(_config_error(), match="RELEASE_TSA_CA_CERT_PATH"):
            _create(monkeypatch, tmp_path, RELEASE_TSA_CA_CERT_PATH=str(path))

    def test_expired_leaf_pin_starts_with_a_warning(
        self, monkeypatch, tmp_path, release_pki, caplog
    ) -> None:
        # Validity is time-dependent: the app starts (standard recovery must
        # stay available) and warns that the time-locked path will deny.
        from datetime import datetime, timedelta, timezone

        from tests.fixtures.tsa_forge import make_tsa_cert, pem

        now = datetime.now(timezone.utc)
        _key, expired = make_tsa_cert(
            release_pki.ca_key, release_pki.ca_cert,
            not_before=now - timedelta(days=10),
            not_after=now - timedelta(days=1),
        )
        pin = tmp_path / "expired_pin.pem"
        pin.write_bytes(pem(expired))
        with caplog.at_level("WARNING", logger="web.release_config"):
            app = _create(monkeypatch, tmp_path,
                          RELEASE_TSA_CA_CERT_PATH=str(release_pki.ca_cert_path),
                          RELEASE_TSA_CERT_PATH=str(pin))
        assert app is not None
        assert "RELEASE_TSA_CERT_PATH" in caplog.text
        assert "validity" in caplog.text

    def test_tsa_ca_without_a_leaf_pin_warns_about_its_reach(
        self, monkeypatch, tmp_path, release_pki, caplog
    ) -> None:
        # Without the pin, any timeStamping certificate the CA issues is
        # trusted; the CA must be dedicated to the TSA.
        with caplog.at_level("WARNING", logger="web.release_config"):
            _create(monkeypatch, tmp_path,
                    RELEASE_TSA_CA_CERT_PATH=str(release_pki.ca_cert_path),
                    RELEASE_TSA_POLICY_OID=DEFAULT_TSA_POLICY_OID,
                    RELEASE_TSA_CERT_PATH="")
        assert "dedicated" in caplog.text

    def test_tsa_url_without_the_profile_starts_with_a_warning(
        self, monkeypatch, tmp_path, caplog
    ) -> None:
        # Unset keys keep their runtime meaning (the time-locked path
        # denies as config_missing); the standard path must still start.
        with caplog.at_level("WARNING", logger="web.release_config"):
            app = _create(monkeypatch, tmp_path,
                          RELEASE_TSA_URL="http://127.0.0.1:9/tsa",
                          RELEASE_TSA_CA_CERT_PATH="",
                          RELEASE_TSA_POLICY_OID="")
        assert app is not None
        assert "RELEASE_TSA_CA_CERT_PATH" in caplog.text
        assert "RELEASE_TSA_POLICY_OID" in caplog.text
