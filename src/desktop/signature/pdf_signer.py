"""PAdES PDF digital signature using pyHanko 0.34+.

Signs PDF files using IncrementalPdfFileWriter for non-destructive
modification, with TSA timestamp token embedding.

Fail-closed contract (manuscript Sections 2 / 3.4 / Eq. 5 / Alg. S5):
the sealing workflow claims PAdES **B-T**, i.e. a signature carrying an
embedded RFC 3161 timestamp token. A signing run that requests a
timestamp and cannot obtain one therefore must NOT silently emit a B-B
(timestamp-less) signature that the record then presents as B-T. When
``tsa_url`` is supplied, timestamp failure raises and the caller decides;
producing a timestamp-less signature requires the explicit opt-in of
``require_timestamp=False``, which returns a warning naming the level.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .exceptions import PDFSigningError
from .types import SignatureVerificationResult

logger = logging.getLogger(__name__)


def sign_pdf(
    pdf_path: str | Path,
    cert_path: str | Path,
    key_path: str | Path,
    password: str,
    output_path: str | Path,
    tsa_url: str | None = None,
    require_timestamp: bool = True,
) -> str:
    """Sign a PDF file with a PAdES signature.

    Args:
        pdf_path: Path to the input PDF file.
        cert_path: Path to the signer's certificate PEM file.
        key_path: Path to the signer's private key PEM file.
        password: Password to decrypt the private key.
        output_path: Path for the signed output PDF.
        tsa_url: TSA server URL for timestamp embedding. Required for a
            B-T signature; omitting it yields B-B and is only allowed
            together with ``require_timestamp=False``.
        require_timestamp: When True (default), the signature must carry
            an embedded RFC 3161 timestamp; any timestamp failure aborts
            signing instead of degrading to B-B.

    Returns:
        Empty string on a B-T signature, or a warning message naming the
        degraded level when ``require_timestamp`` is False.

    Raises:
        PDFSigningError: If signing fails, or if a timestamp was required
            and could not be embedded (fail-closed).
    """
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigSeedSubFilter

    pdf_file = Path(pdf_path)
    cert_file = Path(cert_path)
    key_file = Path(key_path)
    out_file = Path(output_path)

    if not pdf_file.exists():
        raise PDFSigningError(f"PDF file not found: {pdf_file}")
    if not cert_file.exists():
        raise PDFSigningError(f"Certificate file not found: {cert_file}")
    if not key_file.exists():
        raise PDFSigningError(f"Key file not found: {key_file}")
    if not password:
        raise PDFSigningError("Private key password is required")
    if require_timestamp and not tsa_url:
        raise PDFSigningError(
            "A PAdES B-T signature requires a TSA URL; pass "
            "require_timestamp=False to sign at B-B level explicitly"
        )

    out_file.parent.mkdir(parents=True, exist_ok=True)
    warning_msg = ""

    try:
        # Load signer credentials
        signer = signers.SimpleSigner.load(
            key_file=str(key_file),
            cert_file=str(cert_file),
            key_passphrase=password.encode("utf-8"),
        )

        # Configure timestamper. A configuration failure is fatal when a
        # timestamp is required — otherwise the run would emit B-B while
        # the record presents it as B-T.
        timestamper = None
        if tsa_url:
            try:
                from pyhanko.sign.timestamps import HTTPTimeStamper
                timestamper = HTTPTimeStamper(tsa_url)
            except Exception as exc:
                if require_timestamp:
                    raise PDFSigningError(
                        f"TSA timestamper unavailable, refusing to sign "
                        f"without a timestamp (fail-closed): {exc}"
                    ) from exc
                warning_msg = (
                    f"TSA 설정 실패 — B-B(타임스탬프 없음) 수준으로 서명: {exc}"
                )
                logger.warning(warning_msg)

        # PAdES signature metadata
        sig_metadata = signers.PdfSignatureMetadata(
            field_name="Signature1",
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        )

        # Sign
        pdf_signer = signers.PdfSigner(
            signature_meta=sig_metadata,
            signer=signer,
            timestamper=timestamper,
        )

        with open(pdf_file, "rb") as f_in:
            writer = IncrementalPdfFileWriter(f_in)
            with open(out_file, "wb") as f_out:
                pdf_signer.sign_pdf(writer, output=f_out)

        logger.info("PDF signed successfully: %s", out_file)
        return warning_msg

    except PDFSigningError:
        raise
    except Exception as exc:
        # A timestamped run that fails must not silently retry at B-B:
        # the sealing record would then claim B-T for a signature that
        # carries no timestamp. Retry without a timestamp only when the
        # caller explicitly accepted that level.
        if timestamper is not None:
            if require_timestamp:
                raise PDFSigningError(
                    f"Timestamped signing failed and a timestamp is "
                    f"required (fail-closed): {exc}"
                ) from exc
            logger.warning("Signing with TSA failed, retrying without: %s", exc)
            return _sign_without_tsa(
                pdf_file, cert_file, key_file, password, out_file, str(exc)
            )
        raise PDFSigningError(f"Failed to sign PDF: {exc}") from exc


def _sign_without_tsa(
    pdf_file: Path,
    cert_file: Path,
    key_file: Path,
    password: str,
    out_file: Path,
    original_error: str,
) -> str:
    """Fallback: sign PDF without TSA timestamp."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigSeedSubFilter

    try:
        signer = signers.SimpleSigner.load(
            key_file=str(key_file),
            cert_file=str(cert_file),
            key_passphrase=password.encode("utf-8"),
        )
        sig_metadata = signers.PdfSignatureMetadata(
            field_name="Signature1",
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        )
        pdf_signer = signers.PdfSigner(
            signature_meta=sig_metadata,
            signer=signer,
            timestamper=None,
        )
        with open(pdf_file, "rb") as f_in:
            writer = IncrementalPdfFileWriter(f_in)
            with open(out_file, "wb") as f_out:
                pdf_signer.sign_pdf(writer, output=f_out)

        warning = (
            f"PAdES B-B (타임스탬프 없음) 수준으로 서명됨 — B-T 아님. "
            f"원인: {original_error}"
        )
        logger.warning(warning)
        return warning
    except Exception as exc:
        raise PDFSigningError(f"Failed to sign PDF without TSA: {exc}") from exc


def verify_pdf_signature(pdf_path: str | Path) -> SignatureVerificationResult:
    """Verify digital signatures in a PDF file."""
    from pyhanko.pdf_utils.reader import PdfFileReader

    filepath = Path(pdf_path)
    if not filepath.exists():
        raise PDFSigningError(f"PDF file not found: {filepath}")

    try:
        with open(filepath, "rb") as f:
            reader = PdfFileReader(f)
            sigs = reader.embedded_signatures

            if not sigs:
                return SignatureVerificationResult(
                    valid=False,
                    signer_name="",
                    errors=("No signatures found in PDF",),
                )

            sig = sigs[0]
            from pyhanko.sign.validation import validate_pdf_signature
            status = validate_pdf_signature(sig)

            signer_name = ""
            try:
                cert = status.signing_cert
                if cert is not None:
                    signer_name = cert.subject.human_friendly
            except Exception:
                signer_name = "(unknown)"

            has_timestamp = False
            timestamp_time = None
            try:
                if status.timestamp_validity is not None:
                    has_timestamp = True
                    if hasattr(status.timestamp_validity, "timestamp"):
                        timestamp_time = str(status.timestamp_validity.timestamp)
            except Exception:
                pass

            errors: list[str] = []
            if not status.bottom_line:
                errors.append("Signature validation failed")

            return SignatureVerificationResult(
                valid=status.bottom_line,
                signer_name=signer_name,
                signing_time=None,
                has_timestamp=has_timestamp,
                timestamp_time=timestamp_time,
                errors=tuple(errors),
                warnings=(),
            )
    except PDFSigningError:
        raise
    except Exception as exc:
        raise PDFSigningError(f"Failed to verify PDF signature: {exc}") from exc
