"""JSON to HTML to PDF rendering pipeline.

Uses Jinja2 for HTML templating and weasyprint for PDF conversion.
Templates are loaded from the ``templates/`` subdirectory adjacent
to this module.

ReportLab Platypus generators live in:
- This file: seal (봉인지)
- pdf_unseal.py: unseal (봉인해제기록지)
- pdf_reseal.py: reseal (재봉인기록지)

Shared helpers (fonts, styles, tables) live in pdf_helpers.py.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from .exceptions import RenderingError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_VALID_TEMPLATES = frozenset({
    "seal_record.html",
    "unseal_record.html",
    "reseal_record.html",
})

# ---------------------------------------------------------------------------
# Cached backends (initialized once per process)
# ---------------------------------------------------------------------------

_JINJA_ENV: Environment | None = None
_WEASYPRINT_MODULE: object | None = None
_WEASYPRINT_CHECKED: bool = False


def _get_jinja_env() -> Environment:
    """Return the module-level Jinja2 environment (created once)."""
    global _JINJA_ENV
    if _JINJA_ENV is None:
        _JINJA_ENV = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=True,
        )
    return _JINJA_ENV


def _get_weasyprint() -> object | None:
    """Return the weasyprint module or None if unavailable (cached).

    The import (and its system-library probing) runs only once per
    process; later renders reuse the cached result.
    """
    global _WEASYPRINT_MODULE, _WEASYPRINT_CHECKED
    if not _WEASYPRINT_CHECKED:
        try:
            import weasyprint

            _WEASYPRINT_MODULE = weasyprint
        except (ImportError, OSError) as exc:
            logger.info("weasyprint unavailable (%s), using ReportLab", exc)
            _WEASYPRINT_MODULE = None
        _WEASYPRINT_CHECKED = True
    return _WEASYPRINT_MODULE

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_record_pdf(
    record: dict,
    template_name: str,
    output_path: str,
) -> str:
    """Render a seal record dict to a PDF file.

    Pipeline: record dict -> Jinja2 HTML -> weasyprint PDF.

    Args:
        record: The seal/unseal/reseal record dictionary.
        template_name: Name of the Jinja2 template file
            (e.g. ``"seal_record.html"``).
        output_path: Filesystem path where the PDF will be written.

    Returns:
        The absolute path of the generated PDF file.

    Raises:
        RenderingError: If template loading, HTML rendering, or PDF
            conversion fails.
    """
    if template_name not in _VALID_TEMPLATES:
        raise RenderingError(
            f"Unknown template '{template_name}'. "
            f"Valid templates: {sorted(_VALID_TEMPLATES)}"
        )

    # When weasyprint is known to be unavailable the ReportLab backend
    # is used directly and the intermediate HTML render is skipped.
    if _get_weasyprint() is None:
        html_content = None
    else:
        html_content = _render_html(record, template_name)

    pdf_path = _convert_html_to_pdf(
        html_content, output_path,
        record_dict=record, template_name=template_name,
    )
    logger.info("PDF rendered successfully: %s", pdf_path)
    return pdf_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _render_html(record: dict, template_name: str) -> str:
    """Render a record dict to an HTML string via Jinja2."""
    try:
        env = _get_jinja_env()
        template = env.get_template(template_name)
    except TemplateNotFound as exc:
        raise RenderingError(
            f"Template '{template_name}' not found in {_TEMPLATES_DIR}"
        ) from exc
    except Exception as exc:
        raise RenderingError(
            f"Failed to load template '{template_name}': {exc}"
        ) from exc

    try:
        html = template.render(record=record)
    except Exception as exc:
        raise RenderingError(
            f"Failed to render template '{template_name}': {exc}"
        ) from exc

    return html


def _resolve_generator(template_name: str):
    """Return the ReportLab generator function for the given template."""
    if template_name == "unseal_record.html":
        from .pdf_unseal import generate_unseal_pdf
        return generate_unseal_pdf
    if template_name == "reseal_record.html":
        from .pdf_reseal import generate_reseal_pdf
        return generate_reseal_pdf
    # Default: seal
    return _generate_pdf_reportlab


def _convert_html_to_pdf(
    html_content: str | None,
    output_path: str,
    record_dict: dict | None = None,
    template_name: str = "seal_record.html",
) -> str:
    """Convert an HTML string to a PDF file.

    Tries weasyprint first (best quality), falls back to the appropriate
    ReportLab Platypus generator based on template_name. When
    ``html_content`` is None the weasyprint path is skipped entirely.
    """
    abs_path = os.path.abspath(output_path)
    output_dir = os.path.dirname(abs_path)
    if output_dir and not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            raise RenderingError(
                f"Cannot create output directory '{output_dir}': {exc}"
            ) from exc

    # Try weasyprint first (best quality)
    weasyprint = _get_weasyprint()
    if weasyprint is not None and html_content is not None:
        try:
            html_doc = weasyprint.HTML(
                string=html_content,
                base_url=str(_TEMPLATES_DIR),
            )
            html_doc.write_pdf(abs_path)
            logger.info("PDF generated with weasyprint")
            return abs_path
        except OSError as exc:
            logger.info("weasyprint failed (%s), trying ReportLab", exc)

    # Fallback: ReportLab Platypus direct PDF generation
    if record_dict is None:
        raise RenderingError("record_dict required for ReportLab fallback")

    generator_fn = _resolve_generator(template_name)

    try:
        generator_fn(record_dict, abs_path)
        logger.info("PDF generated with ReportLab Platypus (%s)", template_name)
        return abs_path
    except ImportError as exc:
        raise RenderingError(
            "reportlab is not installed. Install: pip install reportlab"
        ) from exc
    except Exception as exc:
        raise RenderingError(f"PDF conversion failed: {exc}") from exc


# ---------------------------------------------------------------------------
# ReportLab Platypus generator — Seal record (봉인지)
# ---------------------------------------------------------------------------


def _generate_pdf_reportlab(record: dict, output_path: str) -> None:
    """Generate seal record (봉인지) PDF with ReportLab Platypus."""
    from .pdf_helpers import (
        Spacer,
        add_case_info_section,
        add_footer,
        add_history_section,
        add_signer_info_section,
        add_title,
        build_detail_table,
        create_document,
        create_styles,
        format_size,
        kv_table,
        p,
        section_row,
    )

    styles = create_styles()
    doc = create_document(output_path)
    story: list = []
    W = doc.width

    # Title
    add_title(story, "전자봉인지", styles)

    # 압수(제출) 정보
    add_case_info_section(story, record, W, styles)

    # 현재 절차 정보 (봉인)
    pi = record.get("process_info", {})
    orig_files = record.get("file_info", {}).get("original_files", [])
    file_list_str = "<br/>".join(
        f"&bull; {f.get('filename', '')}" for f in orig_files
    )
    story.append(p("현재 절차 정보 (봉인)", styles.h2))
    story.append(kv_table([
        ("봉인 ID", record.get("seal_id", "")),
        ("절차 유형", pi.get("type", "")),
        ("암호화 알고리즘", "AES-256-GCM"),
        ("암호화 시작", pi.get("start_time", "")),
        ("암호화 종료", pi.get("end_time", "")),
        ("파일 개수", str(pi.get("file_count", 0))),
        ("파일 목록", file_list_str),
    ], W, styles))

    # 파일 상세 정보
    result_files = record.get("file_info", {}).get("result_files", [])
    story.append(p("파일 상세 정보", styles.h2))

    for idx, ori in enumerate(orig_files):
        enc = result_files[idx] if idx < len(result_files) else {}
        story.append(p(f"파일 {idx + 1}", styles.h3))

        rows_data = [
            [p("암호화 완료 시각", styles.normal),
             p(enc.get("enc_ended_time", ""), styles.normal)],
            section_row("원본 파일 정보", styles),
            [p("파일명", styles.normal), p(ori.get("filename", ""), styles.normal)],
            [p("크기", styles.normal), p(format_size(ori.get("size", 0)), styles.normal)],
            [p("수정일시", styles.normal), p(ori.get("mtime", ""), styles.normal)],
            [p("생성일시", styles.normal), p(ori.get("ctime", ""), styles.normal)],
            [p("접근일시", styles.normal), p(ori.get("atime", ""), styles.normal)],
            [p("해시값(MD5)", styles.normal), p(ori.get("md5", ""), styles.small)],
            [p("해시값(SHA256)", styles.normal), p(ori.get("sha256", ""), styles.small)],
        ]
        if enc:
            rows_data += [
                section_row("암호화 파일 정보", styles),
                [p("파일명", styles.normal), p(enc.get("filename", ""), styles.normal)],
                [p("크기", styles.normal),
                 p(format_size(enc.get("size", 0)), styles.normal)],
                [p("암호화 알고리즘", styles.normal),
                 p(enc.get("encryption_algo", ""), styles.normal)],
                [p("구간 수", styles.normal),
                 p(str(len(enc.get("nonces", []))), styles.normal)],
            ]

        story.append(build_detail_table(rows_data, W))
        story.append(Spacer(1, 8))

    # 서명자 정보
    add_signer_info_section(story, record, W, styles)

    # 서명 이미지 삽입 (signature_data가 있을 때만)
    signature_data = record.get("signature_data")
    if signature_data:
        _add_signature_image_section(story, signature_data, W, styles)

    # 봉인 이력 정보
    add_history_section(story, record, W, styles)

    # Footer
    add_footer(story, styles)

    doc.build(story)


# ---------------------------------------------------------------------------
# Signature image section for seal record
# ---------------------------------------------------------------------------


def _add_signature_image_section(
    story: list,
    signature_data: dict,
    width: float,
    styles: object,
) -> None:
    """Append a signature image and hash to the PDF story.

    Inserts the signature PNG image and its SHA-256 hash value.
    Gracefully skips if the image file does not exist.

    Args:
        story: ReportLab story list to append to.
        signature_data: Dict with image_path, hash_sha256, sign_start, etc.
        width: Available document width.
        styles: PdfStyles instance from pdf_helpers.
    """
    from .pdf_helpers import Spacer, kv_table, p

    image_path = signature_data.get("image_path", "")
    hash_value = signature_data.get("hash_sha256", "")
    sign_start = signature_data.get("sign_start", "")
    sign_end = signature_data.get("sign_end", "")
    signer_name = signature_data.get("signer_name", "")

    story.append(p("서명 정보", styles.h2))

    # Insert signature image if available
    if image_path and os.path.isfile(image_path):
        try:
            from reportlab.lib.units import mm
            from reportlab.platypus import Image as RLImage

            sig_img = RLImage(image_path, width=80 * mm, height=32 * mm)
            story.append(sig_img)
            story.append(Spacer(1, 6))
        except Exception as exc:
            logger.warning("Failed to embed signature image: %s", exc)

    # Signature metadata
    kv_rows = []
    if signer_name:
        kv_rows.append(("서명자", signer_name))
    if sign_start:
        kv_rows.append(("서명 시작", sign_start))
    if sign_end:
        kv_rows.append(("서명 종료", sign_end))
    if hash_value:
        kv_rows.append(("서명 해시 (SHA-256)", hash_value))

    if kv_rows:
        story.append(kv_table(kv_rows, width, styles))
    story.append(Spacer(1, 8))
