"""Fail-closed contract for record signing and timestamp evidence.

Manuscript Sections 2 / 3.4 / Eq. (5) / Alg. S5 state that the sealed
document is a PAdES **B-T** object: a signature plus its embedded
RFC 3161 timestamp token. The implementation must therefore never emit a
timestamp-less (B-B) signature, or an unsigned record, while the record
presents itself as sealed. Every degradation path aborts instead.

The TSA-failure tests sign a real PDF with real, freshly generated
credentials, so the TSA is the only part that fails (a working TSA signs
with the same inputs). The seal-process test uses the synthetic session
TSA; no test here starts the desktop TSA on its default port 3161
(stage E, E2e; Codex r3 M3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from desktop.signature.exceptions import PDFSigningError
from desktop.signature.pdf_signer import sign_pdf
from tests.fixtures.sync_web import StubHttpServer, unused_port

_KEY_PASSWORD = "synthetic-signing-key-password"  # public-test-fixture


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


def _real_inputs(tmp_path: Path) -> tuple[str, str, str, str]:
    """A real PDF and a real key and certificate (synthetic, generated here)."""
    from reportlab.pdfgen import canvas

    from desktop.signature import (
        create_self_signed_cert,
        generate_keypair,
        save_certificate,
        save_private_key,
    )

    pdf = tmp_path / "record.pdf"
    page = canvas.Canvas(str(pdf))
    page.drawString(72, 720, "synthetic record")
    page.save()
    private_key, _public_key = generate_keypair(2048)
    cert = create_self_signed_cert(
        private_key=private_key, subject_name="Synthetic Signer",
        email="signer@example.com", signature_image_hash="0" * 64,
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    save_certificate(cert, str(cert_path))
    save_private_key(private_key, str(key_path), _KEY_PASSWORD)
    return str(pdf), str(cert_path), str(key_path), str(tmp_path / "signed.pdf")


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

    def test_the_real_inputs_sign_with_a_working_tsa(
        self, tmp_path: Any, release_tsa: str
    ) -> None:
        """Control: the inputs of the TSA-failure tests below are valid."""
        pdf, cert, key, out = _real_inputs(tmp_path)

        assert sign_pdf(pdf, cert, key, _KEY_PASSWORD, out,
                        tsa_url=release_tsa) == ""
        assert Path(out).read_bytes().startswith(b"%PDF")

    def test_unreachable_tsa_aborts_instead_of_signing(
        self, tmp_path: Any
    ) -> None:
        """A TSA that cannot be reached must never yield an output file."""
        pdf, cert, key, out = _real_inputs(tmp_path)
        with pytest.raises(PDFSigningError, match="timestamp is required"):
            sign_pdf(
                pdf, cert, key, _KEY_PASSWORD, out,
                tsa_url=f"http://127.0.0.1:{unused_port()}/tsa",
            )
        assert not Path(out).exists(), "no signed artifact on a failed run"

    def test_a_failing_tsa_is_asked_and_nothing_is_written(
        self, tmp_path: Any
    ) -> None:
        """The TSA receives the timestamp query; its failure aborts signing."""
        pdf, cert, key, out = _real_inputs(tmp_path)
        with StubHttpServer([(500, b"")]) as tsa:
            with pytest.raises(PDFSigningError, match="timestamp is required"):
                sign_pdf(pdf, cert, key, _KEY_PASSWORD, out,
                         tsa_url=tsa.url + "/tsa")

        assert [(path, headers.get("content-type"))
                for path, headers, _body in tsa.requests] == [
            ("/tsa", "application/timestamp-query")]
        assert not Path(out).exists(), "no signed artifact on a failed run"

    def test_a_failed_run_leaves_an_earlier_output_untouched(
        self, tmp_path: Any
    ) -> None:
        pdf, cert, key, out = _real_inputs(tmp_path)
        Path(out).write_bytes(b"%PDF-1.4 earlier output")
        with StubHttpServer([(500, b"")]) as tsa:
            with pytest.raises(PDFSigningError):
                sign_pdf(pdf, cert, key, _KEY_PASSWORD, out,
                         tsa_url=tsa.url + "/tsa")

        assert Path(out).read_bytes() == b"%PDF-1.4 earlier output"

    def test_signature_exposes_require_timestamp(self) -> None:
        import inspect

        params = inspect.signature(sign_pdf).parameters
        assert "require_timestamp" in params
        assert params["require_timestamp"].default is True


def _process_before_s5(tmp_path: Path, seal_id: str,
                        subject: dict[str, str]) -> Any:
    """A SealProcess whose S4 state is stood in; S5 not run yet."""
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
        subject=subject,
        signature_lines=[(0, 0, 1, 1)],
    )
    process.state["s4"] = {
        "seal_id": seal_id,
        "record_dict": {"signer_info": {}},
    }
    return process


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
        self, tmp_path: Any, monkeypatch: Any, release_pki: Any,
        release_tsa: str,
    ) -> None:
        """A failing signature pipeline must raise, not warn-and-continue.

        S5 gets the synthetic session TSA, never the desktop's default
        (port 3161), and the refusal must come from the signing step.
        """
        import desktop.seal_process as sp
        import desktop.signature as sig_mod

        monkeypatch.setattr(
            sig_mod, "ensure_tsa_server_running",
            lambda *_a, **_k: (release_tsa, release_pki.tsa_cert_path),
        )
        calls: list[dict[str, Any]] = []

        class _SigningDown(RuntimeError):
            pass

        def _failing_sign(*args: Any, **kwargs: Any) -> str:
            calls.append(kwargs)
            raise _SigningDown("synthetic signing failure")

        monkeypatch.setattr(sig_mod, "sign_pdf", _failing_sign, raising=False)
        process = _process_before_s5(
            tmp_path, "S-20260802-TEST01",
            {"name": "s", "email": "s@example.com", "password": "pw"})

        with pytest.raises(sp.SealSigningError,
                           match="Signature pipeline failed") as info:
            process.run_s5()

        assert isinstance(info.value.__cause__, _SigningDown)
        assert [call["tsa_url"] for call in calls] == [release_tsa]
        assert "s5" not in process.state
        assert not (tmp_path / "S-20260802-TEST01_seal_record_signed.pdf").exists()

    def test_missing_subject_password_aborts_before_key_creation(
        self, tmp_path: Any
    ) -> None:
        """A signing key must never fall back to a built-in password."""
        import desktop.seal_process as sp

        process = _process_before_s5(tmp_path, "S-20260803-NOPASS",
                                     {"name": "s", "email": "s@example.com"})

        with pytest.raises(sp.SealSigningError, match="password"):
            process.run_s5()
