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
