"""Shared ReportLab PDF utilities for seal record generators.

Provides font registration, paragraph styles, and common table builders
used by all three record types (seal, unseal, reseal).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Font registration (idempotent)
# ---------------------------------------------------------------------------

_FONTS_REGISTERED = False

_FONT_PATH = Path("C:/Windows/Fonts/malgun.ttf")
_BOLD_PATH = Path("C:/Windows/Fonts/malgunbd.ttf")


def register_fonts() -> tuple[str, str]:
    """Register Korean fonts and return (normal_font, bold_font) names."""
    global _FONTS_REGISTERED
    if not _FONTS_REGISTERED:
        if _FONT_PATH.exists():
            try:
                pdfmetrics.registerFont(TTFont("Malgun", str(_FONT_PATH)))
            except Exception:
                pass
        if _BOLD_PATH.exists():
            try:
                pdfmetrics.registerFont(TTFont("MalgunBd", str(_BOLD_PATH)))
            except Exception:
                pass
        _FONTS_REGISTERED = True

    font = "Malgun" if _FONT_PATH.exists() else "Helvetica"
    font_bd = "MalgunBd" if _BOLD_PATH.exists() else "Helvetica-Bold"
    return font, font_bd


# ---------------------------------------------------------------------------
# Style collection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PdfStyles:
    """Immutable bundle of paragraph styles used across all generators."""

    title: ParagraphStyle
    h2: ParagraphStyle
    h3: ParagraphStyle
    normal: ParagraphStyle
    small: ParagraphStyle
    center: ParagraphStyle
    center_bd: ParagraphStyle
    footer: ParagraphStyle


def create_styles() -> PdfStyles:
    """Build the shared paragraph style collection."""
    font, font_bd = register_fonts()

    return PdfStyles(
        title=ParagraphStyle("Title_KR", fontName=font_bd, fontSize=20, leading=26),
        h2=ParagraphStyle("H2_KR", fontName=font_bd, fontSize=14, leading=20, spaceBefore=16, spaceAfter=8),
        h3=ParagraphStyle("H3_KR", fontName=font_bd, fontSize=12, leading=16, spaceBefore=12, spaceAfter=6),
        normal=ParagraphStyle("Normal_KR", fontName=font, fontSize=9, leading=13),
        small=ParagraphStyle("Small_KR", fontName=font, fontSize=8, leading=11),
        center=ParagraphStyle("Center_KR", fontName=font, fontSize=9, leading=13, alignment=1),
        center_bd=ParagraphStyle("CenterBd_KR", fontName=font_bd, fontSize=9, leading=13, alignment=1),
        footer=ParagraphStyle("Footer_KR", fontName=font, fontSize=7, leading=10, alignment=1, textColor=colors.grey),
    )


# ---------------------------------------------------------------------------
# Document factory
# ---------------------------------------------------------------------------


def create_document(output_path: str) -> SimpleDocTemplate:
    """Create a standard A4 document with consistent margins."""
    return SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=25 * mm,
        bottomMargin=25 * mm,
    )


# ---------------------------------------------------------------------------
# Paragraph helper
# ---------------------------------------------------------------------------


def p(text: str, style: ParagraphStyle) -> Paragraph:
    """Create a Paragraph from text, coercing to str."""
    return Paragraph(str(text), style)


# ---------------------------------------------------------------------------
# Common table builders
# ---------------------------------------------------------------------------

# Shared grid color
GRID_COLOR = colors.Color(0.8, 0.8, 0.8)
SECTION_BG = colors.Color(0.9, 0.9, 0.9)
HEADER_BG = colors.Color(0.73, 0.73, 0.73)
BLUE_LINE = colors.Color(0.16, 0.38, 1)
SUCCESS_GREEN = colors.Color(0.13, 0.55, 0.13)
FAIL_RED = colors.Color(0.8, 0.1, 0.1)


def kv_table(
    rows: list[tuple[str, str]],
    width: float,
    styles: PdfStyles,
) -> Table:
    """Key-value table with 30/70 column split."""
    data = [[p(k, styles.normal), p(v, styles.normal)] for k, v in rows]
    t = Table(data, colWidths=[width * 0.30, width * 0.70])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def section_row(text: str, styles: PdfStyles) -> list:
    """Gray centered section header row (for embedding in a larger table)."""
    return [p(text, styles.center_bd), ""]


def format_size(size: int) -> str:
    """Human-readable file size string."""
    if size <= 0:
        return "0 bytes"
    gb = size / (1024 ** 3)
    return f"{size:,} bytes ({gb:.3f} GB)"


# ---------------------------------------------------------------------------
# File detail table with section-row spanning
# ---------------------------------------------------------------------------


def build_detail_table(
    rows_data: list[list],
    width: float,
) -> Table:
    """Build a two-column detail table with auto-detected section rows."""
    t = Table(rows_data, colWidths=[width * 0.30, width * 0.70])
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]
    for r_idx, row in enumerate(rows_data):
        if isinstance(row, list) and len(row) == 2 and row[1] == "":
            style_cmds.append(("SPAN", (0, r_idx), (1, r_idx)))
            style_cmds.append(("BACKGROUND", (0, r_idx), (1, r_idx), SECTION_BG))
            style_cmds.append(("ALIGN", (0, r_idx), (1, r_idx), "CENTER"))
    t.setStyle(TableStyle(style_cmds))
    return t


# ---------------------------------------------------------------------------
# Title block
# ---------------------------------------------------------------------------


def add_title(story: list, title_text: str, styles: PdfStyles) -> None:
    """Append the standard title + blue line + spacer."""
    story.append(p(title_text, styles.title))
    story.append(HRFlowable(width="100%", thickness=3, color=BLUE_LINE))
    story.append(Spacer(1, 12))


# ---------------------------------------------------------------------------
# Case info section (shared by all three)
# ---------------------------------------------------------------------------


def add_case_info_section(
    story: list,
    record: dict,
    width: float,
    styles: PdfStyles,
) -> None:
    """Append the case info (압수/제출 정보) section."""
    ci = record.get("case_info", {})
    si = ci.get("storage_info", {})
    story.append(p("압수(제출) 정보", styles.h2))
    story.append(kv_table([
        ("사건 ID", ci.get("case_number", "")),
        ("피압수자", ci.get("suspect", "")),
        ("제조사 모델명 S/N", f"{si.get('manufacturer', '')} {si.get('model', '')} {si.get('serial', '')}"),
        ("사용자", ci.get("device_user", "")),
        ("수사관(압수자)", ci.get("investigator", "")),
        ("압수(제출)장소", ci.get("seizure_location", "")),
        ("압수(제출)일시", ci.get("seizure_time", "")),
    ], width, styles))


# ---------------------------------------------------------------------------
# Signer info section (shared by all three)
# ---------------------------------------------------------------------------


def add_signer_info_section(
    story: list,
    record: dict,
    width: float,
    styles: PdfStyles,
) -> None:
    """Append the signer info (서명자 정보) section."""
    sgn = record.get("signer_info", {})
    story.append(p("서명자 정보", styles.h2))
    story.append(kv_table([
        ("성명", sgn.get("name", "")),
        ("이메일", sgn.get("email", "")),
        ("생년월일", sgn.get("birth_date", "")),
        ("연락처", sgn.get("phone", "")),
    ], width, styles))


# ---------------------------------------------------------------------------
# History section (shared by all three)
# ---------------------------------------------------------------------------


def add_history_section(
    story: list,
    record: dict,
    width: float,
    styles: PdfStyles,
) -> None:
    """Append the history (봉인 이력 정보) section."""
    hist = record.get("history", {})
    events = hist.get("events", [])
    story.append(p("봉인 이력 정보", styles.h2))
    story.append(kv_table([("요약", hist.get("summary", ""))], width, styles))

    evt_header = [
        p("ID", styles.center_bd),
        p("절차 유형", styles.center_bd),
        p("시작 시각", styles.center_bd),
        p("종료 시각", styles.center_bd),
        p("담당 수사관", styles.center_bd),
    ]
    evt_data = [evt_header]
    for ev in events:
        evt_data.append([
            p(str(ev.get("id", "")), styles.center),
            p(ev.get("seal_type", ""), styles.center),
            p(ev.get("start_time", ""), styles.small),
            p(ev.get("end_time", ""), styles.small),
            p(ev.get("investigator", ""), styles.center),
        ])

    evt_table = Table(
        evt_data,
        colWidths=[width * 0.08, width * 0.14, width * 0.28, width * 0.28, width * 0.22],
    )
    evt_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(evt_table)


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------


def add_footer(story: list, styles: PdfStyles) -> None:
    """Append the standard document footer."""
    story.append(Spacer(1, 30))
    story.append(p(
        "본 문서는 디지털증거 전자봉인시스템에 의해 자동 생성되었습니다.",
        styles.footer,
    ))
