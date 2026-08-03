"""ReportLab Platypus PDF generator for reseal records (재봉인기록지).

Separated from pdf_renderer.py to keep file sizes under 800 lines.
"""

from __future__ import annotations

from .pdf_helpers import (
    GRID_COLOR,
    HEADER_BG,
    Spacer,
    Table,
    TableStyle,
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


# ---------------------------------------------------------------------------
# Public generator
# ---------------------------------------------------------------------------


def generate_reseal_pdf(record: dict, output_path: str) -> None:
    """Generate reseal record (재봉인기록지) PDF with ReportLab Platypus."""
    styles = create_styles()
    doc = create_document(output_path)
    story: list = []
    W = doc.width

    # Title
    add_title(story, "전자 재봉인 기록지", styles)

    # 봉인 ID
    story.append(p(f"봉인 ID: {record.get('seal_id', '')}", styles.h3))
    story.append(Spacer(1, 6))

    # 압수(제출) 정보
    add_case_info_section(story, record, W, styles)

    # 서명자 정보
    add_signer_info_section(story, record, W, styles)

    # 이전 절차 정보
    _add_previous_process_section(story, record, W, styles)

    # 현재 절차 정보 (재봉인)
    _add_reseal_process_section(story, record, W, styles)

    # 파일 상세 정보 (암호화)
    _add_file_details(story, record, W, styles)

    # Unknown 파일 분류 결과
    _add_unknown_files_section(story, record, W, styles)

    # 봉인 이력 정보
    add_history_section(story, record, W, styles)

    # Footer
    add_footer(story, styles)

    doc.build(story)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _add_previous_process_section(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append the previous process info section (이전 절차 정보)."""
    pi = record.get("process_info", {})
    prev = pi.get("previous_process", {})

    if not prev:
        prev = record.get("previous_process_info", {})

    if not prev:
        return

    prev_files = prev.get("file_list", [])
    if isinstance(prev_files, list):
        file_list_str = "<br/>".join(
            f"&bull; {f}" if isinstance(f, str)
            else f"&bull; {f.get('filename', '')}"
            for f in prev_files
        )
    else:
        file_list_str = str(prev_files)

    story.append(p("이전 절차 정보", styles.h2))
    story.append(kv_table([
        ("절차 유형", prev.get("seal_type", prev.get("type", ""))),
        ("암호화 알고리즘", prev.get("algorithm", "AES-256-GCM")),
        ("시작 시각", prev.get("start_time", "")),
        ("종료 시각", prev.get("end_time", "")),
        ("파일 개수", str(prev.get("file_count", 0))),
        ("파일 목록", file_list_str),
    ], width, styles))


def _add_reseal_process_section(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append the current process section for resealing."""
    pi = record.get("process_info", {})
    fi = record.get("file_info", {})
    orig_files = fi.get("original_files", [])
    file_list_str = "<br/>".join(
        f"&bull; {f.get('filename', '')}" for f in orig_files
    )

    story.append(p("현재 절차 정보 (재봉인)", styles.h2))
    story.append(kv_table([
        ("봉인 ID", record.get("seal_id", "")),
        ("절차 유형", pi.get("type", "Resealing")),
        ("암호화 알고리즘", "AES-256-GCM"),
        ("암호화 시작", pi.get("start_time", "")),
        ("암호화 종료", pi.get("end_time", "")),
        ("파일 개수", str(pi.get("file_count", len(orig_files)))),
        ("파일 목록", file_list_str),
    ], width, styles))


def _add_file_details(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append per-file detail tables for resealing (same layout as seal)."""
    fi = record.get("file_info", {})
    orig_files = fi.get("original_files", [])
    result_files = fi.get("result_files", [])

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
                [p("크기", styles.normal), p(format_size(enc.get("size", 0)), styles.normal)],
                [p("암호화 알고리즘", styles.normal),
                 p(enc.get("encryption_algo", ""), styles.normal)],
                [p("구간 수", styles.normal),
                 p(str(len(enc.get("nonces", []))), styles.normal)],
            ]

        story.append(build_detail_table(rows_data, width))
        story.append(Spacer(1, 8))


def _add_unknown_files_section(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append the unknown files classification section for resealing."""
    fi = record.get("file_info", {})
    unknown_files = fi.get("unknown_files", [])
    derived_files = fi.get("derived_files", [])

    story.append(p("Unknown 파일 분류 결과", styles.h2))

    # Summary
    story.append(kv_table([
        ("Unknown 파일 수", str(len(unknown_files))),
        ("파생 파일 수", str(len(derived_files))),
    ], width, styles))

    # Unknown files table
    if unknown_files:
        story.append(Spacer(1, 6))
        story.append(p("Unknown 파일 목록", styles.h3))

        header = [
            p("#", styles.center_bd),
            p("파일명", styles.center_bd),
            p("크기", styles.center_bd),
            p("분류 제안", styles.center_bd),
            p("SHA256", styles.center_bd),
        ]
        data = [header]
        for i, uf in enumerate(unknown_files):
            data.append([
                p(str(i + 1), styles.center),
                p(uf.get("filename", ""), styles.normal),
                p(str(uf.get("size", 0)), styles.center),
                p(uf.get("suggested_category", uf.get("category", "")), styles.center),
                p(uf.get("sha256", ""), styles.small),
            ])

        ut = Table(data, colWidths=[
            width * 0.06, width * 0.28, width * 0.12,
            width * 0.18, width * 0.36,
        ])
        ut.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ut)

    # Derived files table
    if derived_files:
        story.append(Spacer(1, 6))
        story.append(p("파생 파일 목록", styles.h3))

        header = [
            p("#", styles.center_bd),
            p("파일명", styles.center_bd),
            p("원본 파일", styles.center_bd),
            p("파생 사유", styles.center_bd),
            p("SHA256", styles.center_bd),
        ]
        data = [header]
        for i, df in enumerate(derived_files):
            data.append([
                p(str(i + 1), styles.center),
                p(df.get("filename", ""), styles.normal),
                p(df.get("source_filename", df.get("original_file", "")), styles.normal),
                p(df.get("reason", df.get("derivation_reason", "")), styles.normal),
                p(df.get("sha256", ""), styles.small),
            ])

        dt = Table(data, colWidths=[
            width * 0.06, width * 0.24, width * 0.20,
            width * 0.20, width * 0.30,
        ])
        dt.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(dt)
