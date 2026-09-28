"""The signed sealing PDF binds the record JSON (Codex round 1, F3).

The sealing PDF shows the seal mode, the time lock, the key commitment and
the signer certificate fingerprint in both backends, and carries the
SHA-256 of the record in its canonical form (sorted keys, no whitespace,
UTF-8) in the document information (Keywords) and on the page, before S5
signs it. ``verify_record_binding`` checks a record JSON against a signed
PDF: an intact, valid signature over the whole file and the same digest.

The ReportLab path is read back from the PDF's content streams (values are
set in Courier, which keeps them as literal text) with pyHanko.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from desktop.record import pdf_renderer
from desktop.record.record_binding import (
    RECORD_DIGEST_KEYWORD,
    canonical_record_bytes,
    record_digest,
    verify_record_binding,
    verify_record_file,
)
from tests.unit.test_boundary_record_signature import _make_valid_record

# oscrypto (used by pyHanko's validator) still calls datetime.utcnow().
pytestmark = pytest.mark.filterwarnings(
    "ignore:datetime.datetime.utcnow:DeprecationWarning:oscrypto")

_PASSWORD = "test-only-binding-key-password"  # public-test-fixture
_FINGERPRINT = "ab" * 32
_COMMITMENT = "0123456789abcdef" * 4


def pdf_text(pdf_path: str | Path) -> bytes:
    """Decoded content streams of every page (pyHanko reader)."""
    from pyhanko.pdf_utils.reader import PdfFileReader

    chunks: list[bytes] = []
    with open(pdf_path, "rb") as fh:
        reader = PdfFileReader(fh)
        stack = [reader.root["/Pages"]]
        while stack:
            node = stack.pop().get_object()
            if node["/Type"] == "/Pages":
                stack.extend(reversed(list(node["/Kids"])))
                continue
            contents = node["/Contents"]
            parts = contents if isinstance(contents, list) else [contents]
            chunks.extend(part.get_object().data for part in parts)
    return b"\n".join(chunks)


@pytest.fixture()
def record() -> dict:
    base = _make_valid_record()
    return {
        **base,
        "seal_id": "S-20260928-0B1D00",
        "seal_mode": "strict",
        "key_commitment": _COMMITMENT,
        "signer_info": {**base["signer_info"], "cert_fingerprint": _FINGERPRINT},
    }


@pytest.fixture()
def reportlab_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf_renderer, "_get_weasyprint", lambda: None)


@pytest.fixture()
def signer(tmp_path: Path) -> tuple[str, str]:
    from desktop.signature import (
        create_self_signed_cert,
        generate_keypair,
        save_certificate,
        save_private_key,
    )

    private_key, _public = generate_keypair(2048)
    cert = create_self_signed_cert(private_key=private_key, subject_name="Lee",
                                   email="lee@example.com",
                                   signature_image_hash="cd" * 32)
    cert_path, key_path = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    save_certificate(cert, cert_path)
    save_private_key(private_key, key_path, _PASSWORD)
    return cert_path, key_path


def _sealed_pdf(tmp_path: Path, record: dict, signer: tuple[str, str]) -> str:
    """Rendered, then PAdES-signed (B-B; the TSA path runs in the GUI test)."""
    from desktop.signature.pdf_signer import sign_pdf

    rendered = str(tmp_path / "record.pdf")
    signed = str(tmp_path / "record_signed.pdf")
    pdf_renderer.render_record_pdf(record, "seal_record.html", rendered)
    sign_pdf(pdf_path=rendered, cert_path=signer[0], key_path=signer[1],
             password=_PASSWORD, output_path=signed, require_timestamp=False)
    return signed


# ===================================================================
# Canonical form
# ===================================================================

def test_the_digest_ignores_formatting_and_key_order(record) -> None:
    indented = json.loads(json.dumps(record, ensure_ascii=False, indent=2))
    reordered = dict(reversed(list(record.items())))

    assert record_digest(indented) == record_digest(record) == record_digest(reordered)
    assert canonical_record_bytes(record) == json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_the_digest_changes_with_any_field(record) -> None:
    edited = copy.deepcopy(record)
    edited["file_info"]["original_files"][0]["sha256"] = "0" * 64

    assert record_digest(edited) != record_digest(record)


# ===================================================================
# ReportLab sealing PDF
# ===================================================================

def test_the_reportlab_pdf_shows_the_fields_and_the_digest(
    tmp_path, record, signer, reportlab_only
) -> None:
    signed = _sealed_pdf(tmp_path, record, signer)

    text = pdf_text(signed)
    digest = record_digest(record)
    for value in ("strict", record["unlock_time_iso"], _COMMITMENT, _FINGERPRINT, digest):
        assert value.encode() in text, value


def test_a_legacy_record_renders_without_the_fields(tmp_path, record, reportlab_only) -> None:
    legacy = {k: v for k, v in record.items()
              if k not in ("seal_mode", "unlock_time_iso", "key_commitment")}
    out = str(tmp_path / "legacy.pdf")

    pdf_renderer.render_record_pdf(legacy, "seal_record.html", out)

    assert b"standard" in pdf_text(out)


# ===================================================================
# verify_record_binding
# ===================================================================

def test_the_saved_and_stored_json_verify(tmp_path, record, signer, reportlab_only) -> None:
    signed = _sealed_pdf(tmp_path, record, signer)
    json_path = tmp_path / "record.json"
    json_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

    for check in (verify_record_file(json_path, signed),
                  verify_record_binding(json_path.read_text(encoding="utf-8"), signed),
                  verify_record_binding(record, signed)):
        assert check.ok, check
        assert check.reason == "ok"
        assert check.record_digest == check.pdf_digest == record_digest(record)


@pytest.mark.parametrize("edit", [
    lambda r: r.update(seal_mode="standard"),
    lambda r: r.update(unlock_time_iso="2026-12-01T00:00:00Z"),
    lambda r: r["file_info"]["original_files"][0].update(sha256="0" * 64),
    lambda r: r.pop("key_commitment"),
])
def test_a_tampered_record_fails(tmp_path, record, signer, reportlab_only, edit) -> None:
    signed = _sealed_pdf(tmp_path, record, signer)
    tampered = copy.deepcopy(record)
    edit(tampered)

    check = verify_record_binding(json.dumps(tampered, ensure_ascii=False), signed)

    assert not check.ok
    assert check.reason == "mismatch"
    assert check.pdf_digest == record_digest(record) != check.record_digest


def test_an_unsigned_pdf_fails(tmp_path, record, reportlab_only) -> None:
    out = str(tmp_path / "unsigned.pdf")
    pdf_renderer.render_record_pdf(record, "seal_record.html", out)

    check = verify_record_binding(record, out)

    assert (check.ok, check.reason) == (False, "no_signature")


def test_a_digest_changed_after_signing_fails(tmp_path, record, signer, reportlab_only) -> None:
    """An incremental update that rewrites the Keywords is outside the signature."""
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    signed = _sealed_pdf(tmp_path, record, signer)
    tampered = {**record, "seal_mode": "standard"}
    with open(signed, "rb") as fh:
        writer = IncrementalPdfFileWriter(fh)
        info = writer.trailer["/Info"]
        info[generic.NameObject("/Keywords")] = generic.TextStringObject(
            f"{RECORD_DIGEST_KEYWORD}={record_digest(tampered)}")
        writer.update_container(info)
        updated = tmp_path / "updated.pdf"
        with open(updated, "wb") as out:
            writer.write(out)

    check = verify_record_binding(tampered, updated)

    assert not check.ok
    assert check.reason == "not_entire_file"


def test_unreadable_inputs_fail(tmp_path, record) -> None:
    missing = tmp_path / "none.pdf"
    assert verify_record_binding(record, missing).reason == "unreadable_pdf"
    assert verify_record_binding("{not json", missing).reason == "unreadable_record"
    assert verify_record_file(tmp_path / "none.json", missing).reason == "unreadable_record"


# ===================================================================
# HTML template (weasyprint backend) shows the same
# ===================================================================

def test_the_html_template_shows_the_fields_and_the_digest(record) -> None:
    html = pdf_renderer._render_html(record, "seal_record.html")
    digest = record_digest(record)

    for value in ("strict", record["unlock_time_iso"], _COMMITMENT, _FINGERPRINT, digest):
        assert value in html, value
    assert f'<meta name="keywords" content="{RECORD_DIGEST_KEYWORD}={digest}">' in html


def test_unseal_html_carries_no_record_digest(record) -> None:
    html = pdf_renderer._render_html(
        {**record, "process_info": {**record["process_info"], "type": "Unsealing"}},
        "unseal_record.html")

    assert RECORD_DIGEST_KEYWORD not in html
