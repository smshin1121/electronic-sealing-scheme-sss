"""ReportLab Platypus PDF generator for unseal records (봉인해제기록지).

Separated from pdf_renderer.py to keep file sizes under 800 lines.
"""

from __future__ import annotations

from reportlab.lib.styles import ParagraphStyle

from .pdf_helpers import (
    FAIL_RED,
    GRID_COLOR,
    HEADER_BG,
    SUCCESS_GREEN,
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


def generate_unseal_pdf(record: dict, output_path: str) -> None:
    """Generate unseal record (봉인해제기록지) PDF with ReportLab Platypus."""
    styles = create_styles()
    doc = create_document(output_path)
    story: list = []
    W = doc.width

    # Title
    add_title(story, "전자봉인 해제 기록지", styles)

    # 봉인 ID
    story.append(p(f"봉인 ID: {record.get('seal_id', '')}", styles.h3))
    story.append(Spacer(1, 6))

    # 압수(제출) 정보
    add_case_info_section(story, record, W, styles)

    # 서명자 정보
    add_signer_info_section(story, record, W, styles)

    # 이전 절차 정보
    _add_previous_process_section(story, record, W, styles)

    # 현재 절차 정보 (봉인해제)
    _add_unseal_process_section(story, record, W, styles)

    # 결과 요약
    _add_result_summary(story, record, W, styles)

    # 파일별 상세
    _add_file_details(story, record, W, styles)

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


def _add_unseal_process_section(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append the current process section for unsealing."""
    pi = record.get("process_info", {})
    fi = record.get("file_info", {})
    orig_files = fi.get("original_files", [])
    file_list_str = "<br/>".join(
        f"&bull; {f.get('filename', '')}" for f in orig_files
    )

    unseal = record.get("unseal_info", {})
    unsealer = pi.get("unsealer_name", unseal.get("unsealer_name", ""))
    unseal_time = pi.get("unseal_time", unseal.get("unseal_time", ""))
    unseal_place = pi.get("unseal_place", unseal.get("unseal_place", ""))
    unseal_reason = pi.get("unseal_reason", unseal.get("unseal_reason", ""))
    participation = pi.get("user_participation", unseal.get("user_participation", ""))

    story.append(p("현재 절차 정보 (봉인해제)", styles.h2))
    story.append(kv_table([
        ("절차 유형", pi.get("type", "Unsealing")),
        ("복호화 알고리즘", "AES-256-GCM"),
        ("복호화 시작", pi.get("start_time", "")),
        ("복호화 종료", pi.get("end_time", "")),
        ("파일 개수", str(pi.get("file_count", len(orig_files)))),
        ("파일 목록", file_list_str),
        ("해제 담당자", unsealer),
        ("해제 일시", unseal_time),
        ("해제 장소", unseal_place),
        ("해제 사유", unseal_reason),
        ("참여 여부", str(participation)),
    ], width, styles))


def _add_result_summary(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append the result summary section for unsealing."""
    fi = record.get("file_info", {})
    orig_files = fi.get("original_files", [])
    result_files = fi.get("result_files", fi.get("decrypted_files", []))
    missing = fi.get("missing_files", [])

    total = len(orig_files)
    missing_count = len(missing)
    success_count = 0
    mismatch_count = 0
    fail_count = 0

    for rf in result_files:
        status = rf.get("verification_status", "")
        dec_success = rf.get("decryption_success", True)
        if not dec_success:
            fail_count += 1
        elif status == "SUCCESS_MATCHED" or rf.get("hash_match") is True:
            success_count += 1
        elif status in ("MISMATCH", "FAIL_MISMATCH"):
            mismatch_count += 1
        else:
            hm = rf.get("hash_match", {})
            if isinstance(hm, dict):
                if hm.get("sha256_match") and hm.get("md5_match"):
                    success_count += 1
                else:
                    mismatch_count += 1
            elif hm is True:
                success_count += 1
            else:
                fail_count += 1

    story.append(p("결과 요약", styles.h2))
    story.append(kv_table([
        ("총 봉인 파일", str(total)),
        ("미발견 파일", str(missing_count)),
        ("성공 (일치)", str(success_count)),
        ("불일치", str(mismatch_count)),
        ("실패", str(fail_count)),
    ], width, styles))


def _add_file_details(
    story: list,
    record: dict,
    width: float,
    styles: "PdfStyles",
) -> None:
    """Append per-file detail tables for unsealing."""
    fi = record.get("file_info", {})
    orig_files = fi.get("original_files", [])
    result_files = fi.get("result_files", fi.get("decrypted_files", []))

    story.append(p("파일별 상세", styles.h2))

    for idx, rf in enumerate(result_files):
        ori = orig_files[idx] if idx < len(orig_files) else {}

        # Determine verification status
        status = rf.get("verification_status", "")
        dec_success = rf.get("decryption_success", True)
        if not status:
            hm = rf.get("hash_match", {})
            if isinstance(hm, dict):
                matched = hm.get("sha256_match", False) and hm.get("md5_match", False)
            else:
                matched = bool(hm)
            status = "SUCCESS_MATCHED" if (dec_success and matched) else "FAIL"

        is_success = status == "SUCCESS_MATCHED"
        badge_color = SUCCESS_GREEN if is_success else FAIL_RED

        ori_name = ori.get("filename", rf.get("ori_file", {}).get("ori_filename", ""))
        dec_file = rf.get("dec_file", {})

        # File header with badge
        badge_style = ParagraphStyle(
            f"Badge_{idx}",
            parent=styles.h3,
            textColor=badge_color,
        )
        story.append(p(f"파일 {idx + 1}: {ori_name}", styles.h3))
        story.append(p(f"[{status}]", badge_style))

        # Hash match info
        hm = rf.get("hash_match", {})
        if isinstance(hm, dict):
            sha_match = "일치" if hm.get("sha256_match") else "불일치"
            md5_match = "일치" if hm.get("md5_match") else "불일치"
            hash_match_str = f"SHA256: {sha_match}, MD5: {md5_match}"
        else:
            hash_match_str = "일치" if hm else "불일치"

        dec_sha = dec_file.get("dec_sha256", rf.get("sha256", ""))
        dec_md5 = dec_file.get("dec_md5", rf.get("md5", ""))

        rows_data = [
            [p("복호화 종료 시각", styles.normal),
             p(rf.get("dec_ended_time", rf.get("end_time", "")), styles.normal)],
            [p("복호화 성공 여부", styles.normal),
             p("성공" if dec_success else "실패", styles.normal)],
            [p("해시 일치 여부", styles.normal),
             p(hash_match_str, styles.normal)],
            [p("복호화 파일 해시(SHA256)", styles.normal),
             p(dec_sha, styles.small)],
            [p("복호화 파일 해시(MD5)", styles.normal),
             p(dec_md5, styles.small)],
        ]

        # Original file metadata
        ori_data = ori if ori else rf.get("ori_file", {})
        rows_data.append(section_row("원본 파일 메타데이터", styles))
        rows_data += _file_metadata_rows(ori_data, "ori_", styles)

        # Decrypted file metadata
        dec_data = dec_file if dec_file else rf
        rows_data.append(section_row("복호화 파일 메타데이터", styles))
        rows_data += _file_metadata_rows(dec_data, "dec_", styles)

        story.append(build_detail_table(rows_data, width))
        story.append(Spacer(1, 8))


# ---------------------------------------------------------------------------
# File metadata helper
# ---------------------------------------------------------------------------


def _file_metadata_rows(
    file_data: dict,
    prefix: str,
    styles: "PdfStyles",
) -> list[list]:
    """Build metadata rows, handling both prefixed and plain keys."""
    def _get(key: str) -> str:
        return str(file_data.get(f"{prefix}{key}", file_data.get(key, "")))

    size_raw = file_data.get(f"{prefix}size", file_data.get("size", 0))
    size_val = int(size_raw) if size_raw else 0

    return [
        [p("파일명", styles.normal), p(_get("filename"), styles.normal)],
        [p("크기", styles.normal), p(format_size(size_val), styles.normal)],
        [p("수정일시", styles.normal), p(_get("mtime"), styles.normal)],
        [p("생성일시", styles.normal), p(_get("ctime"), styles.normal)],
        [p("접근일시", styles.normal), p(_get("atime"), styles.normal)],
        [p("해시값(MD5)", styles.normal), p(_get("md5"), styles.small)],
        [p("해시값(SHA256)", styles.normal), p(_get("sha256"), styles.small)],
    ]
