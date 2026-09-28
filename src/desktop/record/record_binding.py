"""Binding between a sealing record's JSON and its signed PDF (stage E, E1).

The sealing PDF carries the SHA-256 of the record, in the canonical form
below, in its document information (``/Keywords``:
``enc-envelope-record-sha256=<hex>``) and on the page. The digest is taken
from the record S5 renders, which is the record S5 writes to
``<seal_id>_record.json`` and S7 stores; S5 then signs the PDF, so the PAdES
signature covers the digest. :func:`verify_record_binding` checks a record
JSON against a signed PDF.

Canonical form: the parsed record serialized with sorted keys, no
whitespace (``separators=(",", ":")``) and ``ensure_ascii=False``, encoded
as UTF-8. The indented record file and the stored JSON therefore give the
same digest.

What this does not show: that the signer certificate belongs to a known
person (the sealing certificate is self-signed per seal), or when the PDF
was signed (the RFC 3161 token is checked separately). Unsealing and
resealing records are not signed and carry no digest.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping, Union

RECORD_DIGEST_KEYWORD = "enc-envelope-record-sha256"

RecordSource = Union[Mapping[str, Any], str, bytes]
PathLike = Union[str, "os.PathLike[str]"]


@dataclass(frozen=True)
class RecordBindingCheck:
    """Result of :func:`verify_record_binding`.

    Attributes:
        ok: The PDF's signature is intact and valid, covers the whole file,
            and carries the record's digest.
        reason: ``ok``, ``unreadable_record``, ``unreadable_pdf``,
            ``no_signature``, ``signature_invalid``, ``not_entire_file``,
            ``no_digest`` or ``mismatch``.
        record_digest: Digest of the record checked ("" if unreadable).
        pdf_digest: Digest found in the PDF ("" if none was read).
    """

    ok: bool
    reason: str
    record_digest: str = ""
    pdf_digest: str = ""


def canonical_record_bytes(record: Mapping[str, Any]) -> bytes:
    """The record in the canonical form the digest is taken over."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_digest(record: Mapping[str, Any]) -> str:
    """SHA-256 (hex) of :func:`canonical_record_bytes`."""
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


def record_digest_keyword(digest: str) -> str:
    """The ``/Keywords`` entry that carries ``digest``."""
    return f"{RECORD_DIGEST_KEYWORD}={digest}"


def verify_record_binding(record: RecordSource, signed_pdf_path: PathLike) -> RecordBindingCheck:
    """Check a record against a signed sealing PDF.

    Args:
        record: The parsed record, or its JSON text (str or bytes).
        signed_pdf_path: The signed sealing PDF (``*_seal_record_signed.pdf``).

    Returns:
        The check; ``ok`` only when the PDF's signature is intact and valid
        over the whole file and the digest in it equals the record's.
    """
    try:
        parsed = record if isinstance(record, Mapping) else json.loads(record)
        if not isinstance(parsed, Mapping):
            raise ValueError("a record is a JSON object")
        digest = record_digest(parsed)
    except (TypeError, ValueError):
        return RecordBindingCheck(False, "unreadable_record")
    reason, pdf_digest = _signed_digest(signed_pdf_path)
    if reason != "ok":
        return RecordBindingCheck(False, reason, digest, pdf_digest)
    if pdf_digest != digest:
        return RecordBindingCheck(False, "mismatch", digest, pdf_digest)
    return RecordBindingCheck(True, "ok", digest, pdf_digest)


def verify_record_file(record_path: PathLike, signed_pdf_path: PathLike) -> RecordBindingCheck:
    """:func:`verify_record_binding` for a record JSON file."""
    try:
        with open(record_path, "rb") as fh:
            text = fh.read()
    except OSError:
        return RecordBindingCheck(False, "unreadable_record")
    return verify_record_binding(text, signed_pdf_path)


def _signed_digest(signed_pdf_path: PathLike) -> tuple[str, str]:
    """``(reason, digest)`` read from the signed PDF; reason ``ok`` or why not."""
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko.sign.validation.status import SignatureCoverageLevel

        with open(signed_pdf_path, "rb") as fh:
            reader = PdfFileReader(fh)
            signatures = reader.embedded_signatures
            if not signatures:
                return "no_signature", ""
            status = validate_pdf_signature(signatures[0])
            if not (status.intact and status.valid):
                return "signature_invalid", ""
            if status.coverage != SignatureCoverageLevel.ENTIRE_FILE:
                return "not_entire_file", ""
            keywords = reader.document_meta_view.keywords
    except Exception:  # noqa: BLE001 — any unreadable PDF fails the check
        return "unreadable_pdf", ""
    prefix = f"{RECORD_DIGEST_KEYWORD}="
    found = [k.strip()[len(prefix):] for k in keywords if k.strip().startswith(prefix)]
    if len(found) != 1:
        return "no_digest", ""
    return "ok", found[0]
