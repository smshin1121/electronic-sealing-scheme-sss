"""Fail-closed contract for record signing and timestamp evidence.

Manuscript Sections 2 / 3.4 / Eq. (5) / Alg. S5 state that the sealed
document is a PAdES **B-T** object: a signature plus its embedded
RFC 3161 timestamp token. The implementation must therefore never emit a
timestamp-less (B-B) signature, or an unsigned record, while the record
presents itself as sealed. Every degradation path aborts instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from desktop.signature.exceptions import PDFSigningError
from desktop.signature.pdf_signer import sign_pdf


def _make_stub_files(tmp_path: Path) -> tuple[str, str, str, str]:
    """Create placeholder input paths that pass the pre-flight checks."""
    pdf = tmp_path / "record.pdf"
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    pdf.write_bytes(b"%PDF-1.7\n% stub\n")
    cert.write_text("-----BEGIN CERTIFICATE-----\nstub\n", encoding="utf-8")
    key.write_text(  # public-test-fixture
        "-----BEGIN PRIVATE KEY-----\nstub\n",  # public-test-fixture
        encoding="utf-8",
    )
    return str(pdf), str(cert), str(key), str(tmp_path / "signed.pdf")


class TestSignPdfFailClosed:
    """sign_pdf refuses to degrade B-T to B-B."""

    def test_missing_tsa_url_is_refused_by_default(self, tmp_path: Any) -> None:
        pdf, cert, key, out = _make_stub_files(tmp_path)
        with pytest.raises(PDFSigningError, match="B-T"):
            sign_pdf(pdf, cert, key, "pw", out)

    def test_missing_tsa_url_allowed_only_with_explicit_optin(
        self, tmp_path: Any
    ) -> None:
        """Without the TSA the call must get past the B-T pre-check.

        The stub credentials then fail at load time — that is a different
        error, which proves the B-T guard is what the default rejects.
        """
        pdf, cert, key, out = _make_stub_files(tmp_path)
        with pytest.raises(PDFSigningError) as exc:
            sign_pdf(pdf, cert, key, "pw", out, require_timestamp=False)
        assert "B-T" not in str(exc.value)

    def test_unreachable_tsa_aborts_instead_of_signing(
        self, tmp_path: Any
    ) -> None:
        """A TSA that cannot be used must never yield a B-B output file."""
        pdf, cert, key, out = _make_stub_files(tmp_path)
        with pytest.raises(PDFSigningError):
            sign_pdf(
                pdf, cert, key, "pw", out,
                tsa_url="http://127.0.0.1:1/nonexistent",
            )
        assert not Path(out).exists(), "no signed artifact on a failed run"

    def test_signature_exposes_require_timestamp(self) -> None:
        import inspect

        params = inspect.signature(sign_pdf).parameters
        assert "require_timestamp" in params
        assert params["require_timestamp"].default is True


class TestSealProcessRefusesDegradedRecords:
    """run_s5 aborts rather than emitting an unsigned/untimestamped record."""

    def test_error_types_are_exported(self) -> None:
        from desktop.seal_process import (
            SealRecordError,
            SealSigningError,
            SealTimestampError,
        )

        assert issubclass(SealSigningError, SealRecordError)
        assert issubclass(SealTimestampError, SealRecordError)
        assert issubclass(SealRecordError, RuntimeError)

    def test_signature_failure_aborts_the_seal(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """A failing signature pipeline must raise, not warn-and-continue."""
        import desktop.seal_process as sp

        process = sp.SealProcess(db_path=str(tmp_path / "seal.db"))
        process.config = sp.SealConfig(
            source_file=str(tmp_path / "src.bin"),
            output_dir=str(tmp_path),
            chunk_size_bytes=1 << 30,
            case_number="C-1",
            investigator={"name": "i"},
            seizure={"place": "p"},
            media={"type": "SSD"},
            subject={"name": "s", "email": "s@example.com",
                     "password": "pw"},
            signature_lines=[(0, 0, 1, 1)],
        )
        process.state["s4"] = {
            "seal_id": "S-20260802-TEST01",
            "record_dict": {"signer_info": {}},
        }

        import desktop.signature as sig_mod

        def _boom(*_args: Any, **_kwargs: Any) -> str:
            raise RuntimeError("TSA down")

        monkeypatch.setattr(sig_mod, "sign_pdf", _boom, raising=False)

        with pytest.raises(sp.SealRecordError):
            process.run_s5()

    def test_missing_subject_password_aborts_before_key_creation(
        self, tmp_path: Any
    ) -> None:
        """A signing key must never fall back to a built-in password."""
        import desktop.seal_process as sp

        process = sp.SealProcess(db_path=str(tmp_path / "seal.db"))
        process.config = sp.SealConfig(
            source_file=str(tmp_path / "src.bin"),
            output_dir=str(tmp_path),
            chunk_size_bytes=1 << 30,
            case_number="C-1",
            investigator={"name": "i"},
            seizure={"place": "p"},
            media={"type": "SSD"},
            subject={"name": "s", "email": "s@example.com"},
            signature_lines=[(0, 0, 1, 1)],
        )
        process.state["s4"] = {
            "seal_id": "S-20260803-NOPASS",
            "record_dict": {"signer_info": {}},
        }

        with pytest.raises(sp.SealSigningError, match="password"):
            process.run_s5()
