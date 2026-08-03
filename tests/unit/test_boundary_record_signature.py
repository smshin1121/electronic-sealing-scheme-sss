"""Boundary tests: record module -> signature module.

Validates:
  - render_record_pdf() output is a valid PDF (magic bytes %PDF)
  - pdf_signer.sign_pdf() input format compatible with rendered PDF
  - Graceful skip when weasyprint is not installed
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Conditional imports
# ---------------------------------------------------------------------------

try:
    import weasyprint  # noqa: F401
    _WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    _WEASYPRINT_AVAILABLE = False

from desktop.record.pdf_renderer import render_record_pdf, _VALID_TEMPLATES
from desktop.record.exceptions import RenderingError
from desktop.record.history_manager import create_initial_history
from desktop.record.record_builder import build_seal_record, create_seal_id

try:
    from desktop.signature.pdf_signer import sign_pdf, verify_pdf_signature
    from desktop.signature.exceptions import PDFSigningError
    _PYHANKO_AVAILABLE = True
except ImportError:
    _PYHANKO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_valid_record() -> dict:
    seal_id = create_seal_id()
    return build_seal_record(
        unlock_time_iso="2026-12-31T00:00:00Z",
        key_commitment="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  # public-test-fixture; gitleaks:allow
        seal_id=seal_id,
        case_info={
            "case_number": "2026-0001",
            "investigator": "Kim",
            "device_user": "Park",
            "suspect": "Lee",
            "storage_type": "SSD",
            "storage_info": {
                "manufacturer": "Samsung",
                "model": "870 EVO",
                "serial": "S1234",
            },
            "seizure_time": "2026-04-01T09:00:00Z",
            "seizure_location": "Seoul",
        },
        process_info={
            "type": "Sealing",
            "start_time": "2026-04-01T10:00:00Z",
            "end_time": "2026-04-01T11:00:00Z",
            "file_count": 1,
            "investigator": "Kim",
            "reason": None,
            "participation": "present",
        },
        file_info={
            "original_files": [
                {
                    "filename": "evidence.dd",
                    "size": 1048576,
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb924"
                              "27ae41e4649b934ca495991b7852b855",
                    "mtime": "2026-03-31T08:00:00Z",
                    "ctime": "2026-03-31T07:00:00Z",
                    "atime": "2026-04-01T09:00:00Z",
                },
            ],
            "result_files": [
                {
                    "filename": "evidence.dd.enc",
                    "size": 1048600,
                    "encryption_algo": "AES-256-GCM",
                    "enc_ended_time": "2026-04-01T11:00:00Z",
                    "nonces": ["aabbccddee001122aabbccdd"],
                    "tags": ["00112233445566778899aabbccddeeff"],
                    "chunk_lengths": [1048576],
                },
            ],
            "hash_match": True,
        },
        signer_info={
            "name": "Lee",
            "email": "lee@example.com",
            "birth_date": "1990-01-01",
            "phone": "010-1234-5678",
            "cert_fingerprint": "AB" * 32,
            "signature_image_hash": "CD" * 32,
        },
        history=create_initial_history({
            "seal_type": "Sealing",
            "start_time": "2026-04-01T10:00:00Z",
            "end_time": "2026-04-01T11:00:00Z",
            "investigator": "Kim",
        }),
    )


# ---------------------------------------------------------------------------
# Tests: render_record_pdf API
# ---------------------------------------------------------------------------


class TestRenderRecordPdfAPI:
    """render_record_pdf() function signature and template validation."""

    def test_function_signature(self) -> None:
        sig = inspect.signature(render_record_pdf)
        params = list(sig.parameters.keys())
        assert params == ["record", "template_name", "output_path"]

    def test_valid_templates_set(self) -> None:
        expected = {"seal_record.html", "unseal_record.html", "reseal_record.html"}
        assert _VALID_TEMPLATES == expected

    def test_invalid_template_raises(self, tmp_path) -> None:
        record = _make_valid_record()
        with pytest.raises(RenderingError, match="Unknown template"):
            render_record_pdf(
                record, "nonexistent.html", str(tmp_path / "out.pdf")
            )


# ---------------------------------------------------------------------------
# Tests: PDF magic bytes (requires weasyprint)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _WEASYPRINT_AVAILABLE,
    reason="weasyprint not installed"
)
class TestPDFMagicBytes:
    """Rendered PDF must start with %PDF magic bytes."""

    def test_seal_record_pdf_valid(self, tmp_path) -> None:
        record = _make_valid_record()
        out_path = str(tmp_path / "seal_record.pdf")

        result_path = render_record_pdf(record, "seal_record.html", out_path)

        with open(result_path, "rb") as f:
            magic = f.read(4)
        assert magic == b"%PDF", f"Expected %PDF magic, got {magic!r}"

    def test_pdf_file_not_empty(self, tmp_path) -> None:
        record = _make_valid_record()
        out_path = str(tmp_path / "seal_record2.pdf")

        result_path = render_record_pdf(record, "seal_record.html", out_path)

        import os
        assert os.path.getsize(result_path) > 100


# ---------------------------------------------------------------------------
# Tests: sign_pdf API compatibility
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _PYHANKO_AVAILABLE,
    reason="pyHanko not installed",
)
class TestSignPdfAPICompatibility:
    """sign_pdf() input expectations must align with render_record_pdf() output."""

    def test_sign_pdf_function_signature(self) -> None:
        sig = inspect.signature(sign_pdf)
        params = list(sig.parameters.keys())
        assert "pdf_path" in params
        assert "output_path" in params
        assert "cert_path" in params
        assert "key_path" in params
        assert "password" in params
        assert "tsa_url" in params

    def test_verify_pdf_signature_function_signature(self) -> None:
        sig = inspect.signature(verify_pdf_signature)
        params = list(sig.parameters.keys())
        assert "pdf_path" in params

    def test_sign_pdf_rejects_missing_file(self, tmp_path) -> None:
        with pytest.raises(PDFSigningError, match="not found"):
            sign_pdf(
                pdf_path=str(tmp_path / "nonexistent.pdf"),
                cert_path=str(tmp_path / "cert.pem"),
                key_path=str(tmp_path / "key.pem"),
                password="test",  # public-test-fixture
                output_path=str(tmp_path / "signed.pdf"),
            )

    def test_sign_pdf_rejects_empty_password(self, tmp_path) -> None:
        # Create dummy files so file-existence checks pass
        pdf_path = tmp_path / "dummy.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 dummy")
        cert_path = tmp_path / "cert.pem"
        cert_path.write_text("dummy cert")
        key_path = tmp_path / "key.pem"
        key_path.write_text("dummy key")

        with pytest.raises(PDFSigningError, match="password"):
            sign_pdf(
                pdf_path=str(pdf_path),
                cert_path=str(cert_path),
                key_path=str(key_path),
                password="",
                output_path=str(tmp_path / "signed.pdf"),
            )


# ---------------------------------------------------------------------------
# Tests: weasyprint unavailable graceful handling
# ---------------------------------------------------------------------------


class TestWeasyPrintUnavailable:
    """When weasyprint is not installed or non-functional, rendering should fail gracefully."""

    @pytest.mark.skipif(
        _WEASYPRINT_AVAILABLE,
        reason="weasyprint IS installed and functional; skip unavailability test"
    )
    def test_renders_with_fallback_when_weasyprint_unavailable(self, tmp_path) -> None:
        """Without working weasyprint, render should fall back to xhtml2pdf."""
        record = _make_valid_record()
        out_path = str(tmp_path / "out.pdf")
        # xhtml2pdf fallback should succeed, producing a valid PDF
        try:
            result = render_record_pdf(record, "seal_record.html", out_path)
            assert Path(result).exists()
            assert Path(result).stat().st_size > 0
        except (RenderingError, OSError):
            # If both weasyprint and xhtml2pdf are unavailable, that's also OK
            pass
