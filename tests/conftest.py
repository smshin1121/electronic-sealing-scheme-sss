"""Shared pytest fixtures for the crypto test suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure src/ is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from tests.fixtures.generate_test_files import (
    SIZE_1MB,
    SIZE_10MB,
    create_random_file,
)

_TEST_TSA_KEY_PASSWORD = "test-only-tsa-key-password"  # public-test-fixture
_TEST_TSA_CA_KEY_PASSWORD = "test-only-tsa-ca-password"  # public-test-fixture


@pytest.fixture(autouse=True)
def tsa_test_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure non-production TSA credential passwords for every test."""
    monkeypatch.setenv(
        "ENC_ENVELOPE_TSA_KEY_PASSWORD",
        _TEST_TSA_KEY_PASSWORD,
    )
    monkeypatch.setenv(
        "ENC_ENVELOPE_TSA_CA_KEY_PASSWORD",
        _TEST_TSA_CA_KEY_PASSWORD,
    )


@pytest.fixture(scope="session")
def _home_default_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Stands in for ``~/.enc_envelope`` during the whole session."""
    return tmp_path_factory.mktemp("home_enc_envelope")


@pytest.fixture(autouse=True)
def _isolate_home_defaults(
    monkeypatch: pytest.MonkeyPatch, _home_default_dir: Path
) -> None:
    """Keep every test away from the operator's ``~/.enc_envelope``.

    The desktop program keeps its master key and TSA credentials there.
    Without this, a test that relies on those defaults reads the
    operator's master key, or creates TSA credentials in the operator's
    home. A test that needs a key or a TSA configures its own.
    """
    monkeypatch.setattr("desktop.crypto.local_kms._DEFAULT_MASTER_KEY_PATH",
                        _home_default_dir / "master.key")
    try:
        import desktop.signature.tsa_server  # noqa: F401
    except ImportError:  # signature stack not installed
        return
    monkeypatch.setattr("desktop.signature.tsa_server._DEFAULT_TSA_DIR",
                        _home_default_dir / "tsa")


@pytest.fixture
def tmp_work_dir(tmp_path: Path) -> Path:
    """Return a clean temporary working directory."""
    return tmp_path


@pytest.fixture
def aes_key() -> bytes:
    """Generate a fresh AES-256 key (32 bytes)."""
    return os.urandom(32)


@pytest.fixture
def file_1mb(tmp_path: Path) -> str:
    """Create a 1 MB random binary file."""
    return create_random_file(tmp_path / "test_1mb.bin", SIZE_1MB)


@pytest.fixture
def file_10mb(tmp_path: Path) -> str:
    """Create a 10 MB random binary file."""
    return create_random_file(tmp_path / "test_10mb.bin", SIZE_10MB)


@pytest.fixture(scope="session")
def release_pki(tmp_path_factory: pytest.TempPathFactory):
    """Synthetic CA, seal-policy cert, TSA cert and an untrusted CA."""
    from tests.fixtures.release_pki import build_release_pki

    return build_release_pki(tmp_path_factory.mktemp("release_pki"))


@pytest.fixture(scope="session")
def release_tsa(release_pki):
    """URL of a local RFC 3161 TSA signed by the synthetic CA."""
    from tests.fixtures.release_pki import start_release_tsa

    server, thread, url = start_release_tsa(release_pki)
    yield url
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def privacy_key_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """One synthetic (identity pepper, privacy master key) pair per session."""
    from tests.fixtures.privacy_keys import make_privacy_key_files

    return make_privacy_key_files(tmp_path_factory.mktemp("privacy_keys"))


@pytest.fixture(autouse=True)
def _privacy_test_keys(
    monkeypatch: pytest.MonkeyPatch, privacy_key_files: tuple[str, str]
) -> None:
    """Give every testing app the identity-protection keys (stage E, E3a).

    Since E3a, case registration and subject authentication refuse (503)
    without them. A fail-closed test clears both paths explicitly with
    ``tests.fixtures.privacy_keys.without_privacy_keys``.
    """
    from tests.fixtures.privacy_keys import set_privacy_keys

    set_privacy_keys(monkeypatch, *privacy_key_files)
