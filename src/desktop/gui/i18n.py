"""Internationalization (i18n) module for Korean/English language switching."""

from __future__ import annotations
from typing import Callable

# Current language: "ko" or "en"
_current_lang: str = "ko"
_listeners: list[Callable[[], None]] = []


def get_lang() -> str:
    """Return the current language code."""
    return _current_lang


def set_lang(lang: str) -> None:
    """Set the current language and notify all listeners."""
    global _current_lang
    _current_lang = lang
    for listener in _listeners:
        listener()


def add_listener(callback: Callable[[], None]) -> None:
    """Register a callback to be invoked when language changes."""
    _listeners.append(callback)


def remove_listener(callback: Callable[[], None]) -> None:
    """Unregister a language-change callback."""
    if callback in _listeners:
        _listeners.remove(callback)


def t(key: str) -> str:
    """Translate key to current language."""
    translations = _TRANSLATIONS.get(key)
    if translations is None:
        return key
    return translations.get(_current_lang, translations.get("ko", key))


# ---- Translation dictionary ----
_TRANSLATIONS = {
    # App title
    "app.title": {
        "ko": "디지털증거 전자봉인시스템",
        "en": "Electronic Sealing Scheme (SSS)",
    },

    # Menu bar
    "menu.process": {"ko": "프로세스", "en": "Process"},
    "menu.seal": {"ko": "봉인 (Seal)", "en": "Seal"},
    "menu.unseal": {"ko": "봉인해제 (Unseal)", "en": "Unseal"},
    "menu.reseal": {"ko": "재봉인 (Reseal)", "en": "Reseal"},
    "menu.case_manager": {"ko": "케이스 관리", "en": "Case Manager"},
    "menu.exit": {"ko": "종료", "en": "Exit"},
    "menu.help": {"ko": "도움말", "en": "Help"},
    "menu.about": {"ko": "정보", "en": "About"},
    "menu.language": {"ko": "Language", "en": "Language"},
    "menu.lang_ko": {"ko": "한국어", "en": "한국어"},
    "menu.lang_en": {"ko": "English", "en": "English"},

    # Language toggle button
    "lang.toggle": {"ko": "EN", "en": "KO"},
    "lang.toggle_tip_ko": {
        "ko": "Switch to English",
        "en": "Switch to English",
    },
    "lang.toggle_tip_en": {
        "ko": "한국어로 전환",
        "en": "한국어로 전환",
    },
    "lang.changed": {
        "ko": "언어가 변경되었습니다",
        "en": "Language changed",
    },
    "lang.applied_next": {
        "ko": "진행 중인 화면에는 다음 화면부터 언어가 적용됩니다",
        "en": "Language will apply from the next screen",
    },

    # Dashboard
    "dashboard.title": {
        "ko": "디지털증거 전자봉인시스템",
        "en": "Electronic Sealing Scheme (SSS)",
    },
    "dashboard.refresh": {"ko": "새로고침", "en": "Refresh"},
    "dashboard.seal_count": {"ko": "봉인 건", "en": "Sealed"},
    "dashboard.unseal_count": {"ko": "봉인해제 건", "en": "Unsealed"},
    "dashboard.reseal_count": {"ko": "재봉인 건", "en": "Resealed"},
    "dashboard.quick_seal": {"ko": "봉인", "en": "Seal"},
    "dashboard.quick_seal_desc": {
        "ko": "새로운 디지털증거를 봉인합니다",
        "en": "Seal new digital evidence",
    },
    "dashboard.quick_unseal": {"ko": "봉인해제", "en": "Unseal"},
    "dashboard.quick_unseal_desc": {
        "ko": "봉인된 증거를 해제합니다",
        "en": "Unseal sealed evidence",
    },
    "dashboard.quick_reseal": {"ko": "재봉인", "en": "Reseal"},
    "dashboard.quick_reseal_desc": {
        "ko": "해제된 증거를 재봉인합니다",
        "en": "Reseal released evidence",
    },
    "dashboard.quick_cases": {"ko": "케이스 관리", "en": "Case Manager"},
    "dashboard.quick_cases_desc": {
        "ko": "케이스 목록을 관리합니다",
        "en": "Manage case records",
    },
    "dashboard.system_status": {"ko": "시스템 상태", "en": "System Status"},
    "dashboard.db_status": {"ko": "DB 연결", "en": "DB Connection"},
    "dashboard.db_ok": {"ko": "정상", "en": "OK"},
    "dashboard.db_fail": {"ko": "오류", "en": "Error"},
    "dashboard.master_key": {"ko": "마스터키", "en": "Master Key"},
    "dashboard.key_exists": {"ko": "존재", "en": "Present"},
    "dashboard.key_missing": {"ko": "미설정", "en": "Missing"},
    "dashboard.alerts": {"ko": "경고 알림", "en": "Alerts"},
    "dashboard.no_alerts": {"ko": "이상 없음", "en": "No issues"},
    "dashboard.expiring_seal": {"ko": "만료 임박", "en": "Expiring soon"},
    "dashboard.recent_activity": {"ko": "최근 작업 이력", "en": "Recent Activity"},
    "dashboard.no_activity": {
        "ko": "작업 이력이 없습니다",
        "en": "No activity records",
    },
    "dashboard.no_activity_hint": {
        "ko": "첫 봉인을 시작하면 이곳에 작업 이력이 표시됩니다.",
        "en": "Once you seal evidence, activity will appear here.",
    },
    "dashboard.empty_cta": {"ko": "첫 봉인 시작", "en": "Start First Seal"},
    "dashboard.loading": {"ko": "불러오는 중...", "en": "Loading..."},
    "dashboard.refresh_done": {
        "ko": "대시보드를 새로고침했습니다",
        "en": "Dashboard refreshed",
    },
    "dashboard.col_time": {"ko": "일시", "en": "Time"},
    "dashboard.col_type": {"ko": "유형", "en": "Type"},
    "dashboard.col_seal_id": {"ko": "Seal ID", "en": "Seal ID"},
    "dashboard.stat_na": {"ko": "N/A", "en": "N/A"},

    # Seal wizard
    "seal.title": {"ko": "봉인 프로세스", "en": "Sealing Process"},
    "seal.step1": {"ko": "파일선택", "en": "File"},
    "seal.step2": {"ko": "압수정보", "en": "Case Info"},
    "seal.step3": {"ko": "피압수자", "en": "Subject"},
    "seal.step4": {"ko": "미리보기", "en": "Preview"},
    "seal.step5": {"ko": "전자서명", "en": "Signature"},
    "seal.step6": {"ko": "키분할", "en": "Key Split"},
    "seal.step7": {"ko": "완료", "en": "Complete"},
    "seal.s1_title": {
        "ko": "S1. 파일 선택 및 암호화 설정",
        "en": "S1. File Selection & Encryption Settings",
    },
    "seal.target_file": {"ko": "대상 파일", "en": "Target File"},
    "seal.output_dir": {"ko": "출력 폴더", "en": "Output Directory"},
    "seal.chunk_size": {"ko": "GCM 구간 크기 (GB)", "en": "GCM Chunk Size (GB)"},
    "seal.chunk_range": {"ko": "GB (1~64)", "en": "GB (1~64)"},
    "seal.s2_title": {
        "ko": "S2. 압수·봉인 정보 입력",
        "en": "S2. Seizure & Sealing Information",
    },
    "seal.case_info": {"ko": "사건 정보", "en": "Case Information"},
    "seal.case_number": {"ko": "사건번호", "en": "Case Number"},
    "seal.seizure_date": {"ko": "압수일시", "en": "Seizure Date"},
    "seal.seizure_location": {"ko": "압수장소", "en": "Seizure Location"},
    "seal.media_info": {"ko": "매체정보", "en": "Media Info"},
    "seal.media_manufacturer": {"ko": "저장매체 제조사", "en": "Storage Manufacturer"},
    "seal.media_model": {"ko": "저장매체 모델명", "en": "Storage Model"},
    "seal.media_serial": {"ko": "저장매체 시리얼 번호", "en": "Storage Serial No."},
    "seal.investigator_info": {
        "ko": "수사관 정보",
        "en": "Investigator Information",
    },
    "seal.investigator_name": {"ko": "담당 수사관", "en": "Investigator Name"},
    "seal.investigator_rank": {"ko": "직급", "en": "Rank"},
    "seal.s3_title": {
        "ko": "S3. 피압수자 정보 입력",
        "en": "S3. Subject Information",
    },
    "seal.subject_info": {"ko": "피압수자 인적사항", "en": "Subject Identity"},
    "seal.subject_name": {"ko": "이름", "en": "Name"},
    "seal.subject_email": {"ko": "이메일", "en": "Email"},
    "seal.subject_dob": {"ko": "생년월일 (YYYYMMDD)", "en": "Date of Birth (YYYYMMDD)"},
    "seal.subject_phone": {"ko": "연락처", "en": "Phone"},
    "seal.security_info": {"ko": "보안 정보", "en": "Security Information"},
    "seal.password": {"ko": "비밀번호", "en": "Password"},
    "seal.password_confirm": {"ko": "비밀번호 확인", "en": "Confirm Password"},
    "seal.signature": {"ko": "서명", "en": "Signature"},
    "seal.s4_title": {
        "ko": "S4. 봉인지 미리보기 및 검토",
        "en": "S4. Seal Record Preview",
    },
    "seal.s5_title": {
        "ko": "S5. 전자서명 진행",
        "en": "S5. Digital Signature Processing",
    },
    "seal.s5_waiting": {"ko": "대기 중...", "en": "Waiting..."},
    "seal.s5_complete": {
        "ko": "전자서명 완료! → '다음'을 누르세요.",
        "en": "Signature complete! Press 'Next'.",
    },
    "seal.s6_title": {
        "ko": "S6. 키 분할 결과 및 접근제어 시간 설정",
        "en": "S6. Key Split Results & Access Control",
    },
    "seal.unlock_time": {"ko": "열람 제한 기간 (일)", "en": "Access Restriction Period (days)"},
    "seal.unlock_label": {"ko": "* unlock_time (일)", "en": "* unlock_time (days)"},
    "seal.unlock_range": {"ko": "일 (1~30)", "en": "days (1~30)"},
    "seal.s7_title": {"ko": "S7. 봉인 완료", "en": "S7. Sealing Complete"},

    # Unseal wizard
    "unseal.title": {"ko": "봉인해제 프로세스", "en": "Unsealing Process"},
    "unseal.step1": {"ko": "대상선택", "en": "Select"},
    "unseal.step2": {"ko": "파일대조", "en": "Verify"},
    "unseal.step3": {"ko": "복호화", "en": "Decrypt"},
    "unseal.step4": {"ko": "기록지", "en": "Record"},
    "unseal.step5": {"ko": "완료", "en": "Complete"},
    "unseal.u3_title": {
        "ko": "U3. 봉인해제 대상 선택 및 정보 입력",
        "en": "U3. Select Target & Input Information",
    },
    "unseal.enc_file": {"ko": "암호화 파일 (.enc)", "en": "Encrypted File (.enc)"},
    "unseal.record_json": {"ko": "봉인지 (JSON)", "en": "Seal Record (JSON)"},
    "unseal.output_dir": {"ko": "출력 폴더", "en": "Output Directory"},
    "unseal.aes_key_title": {"ko": "AES 키 입력", "en": "AES Key Input"},
    "unseal.aes_key": {"ko": "AES 키 (64자리 hex)", "en": "AES Key (64-char hex)"},
    "unseal.key_load": {"ko": ".key 파일 로드", "en": "Load key file"},
    "unseal.show_key": {"ko": "키 표시", "en": "Show key"},
    "unseal.unseal_info": {"ko": "봉인해제 정보", "en": "Unseal Information"},
    "unseal.reason": {"ko": "봉인해제 사유", "en": "Unseal Reason"},
    "unseal.investigator": {"ko": "담당 수사관", "en": "Investigator"},
    "unseal.participation": {"ko": "피압수자 참여 여부", "en": "Subject Participation"},
    "unseal.participate": {"ko": "참여함", "en": "Participated"},
    "unseal.u4_title": {
        "ko": "U4. 파일-봉인지 대조 검증 결과",
        "en": "U4. File-Seal Record Verification Results",
    },
    "unseal.u5_title": {"ko": "U5. 복호화 진행", "en": "U5. Decryption Progress"},
    "unseal.u5_waiting": {"ko": "대기 중...", "en": "Waiting..."},
    "unseal.u6_title": {
        "ko": "U6. 봉인해제기록지 미리보기",
        "en": "U6. Unseal Record Preview",
    },
    "unseal.u7_title": {"ko": "U7. 봉인해제 완료", "en": "U7. Unsealing Complete"},
    "unseal.cancel_confirm": {
        "ko": "봉인해제 프로세스를 취소하시겠습니까?",
        "en": "Cancel the unsealing process?",
    },

    # Reseal wizard
    "reseal.title": {"ko": "재봉인 프로세스", "en": "Resealing Process"},
    "reseal.step1": {"ko": "기록로드", "en": "Load"},
    "reseal.step2": {"ko": "파일비교", "en": "Compare"},
    "reseal.step3": {"ko": "분류", "en": "Classify"},
    "reseal.step4": {"ko": "재봉인정보", "en": "Info"},
    "reseal.step5": {"ko": "암호화", "en": "Encrypt"},
    "reseal.step6": {"ko": "기록지", "en": "Record"},
    "reseal.step7": {"ko": "키분할", "en": "Key Split"},
    "reseal.step8": {"ko": "완료", "en": "Complete"},
    "reseal.r1_title": {
        "ko": "R1. 이전 봉인해제기록지 로드",
        "en": "R1. Load Previous Unseal Record",
    },
    "reseal.prev_record": {
        "ko": "봉인해제기록지 (JSON)",
        "en": "Unseal Record (JSON)",
    },
    "reseal.target_dir": {"ko": "재봉인 대상 폴더", "en": "Reseal Target Directory"},
    "reseal.output_dir": {"ko": "출력 폴더", "en": "Output Directory"},
    "reseal.loaded_info": {"ko": "로드된 기록 정보:", "en": "Loaded Record Info:"},
    "reseal.r2_title": {"ko": "R2. 파일 비교 결과", "en": "R2. File Comparison Results"},
    "reseal.known_files": {
        "ko": "기존 파일 (해시 일치):",
        "en": "Known Files (Hash Match):",
    },
    "reseal.unknown_files": {
        "ko": "Unknown 파일 (분류 필요):",
        "en": "Unknown Files (Classification Required):",
    },
    "reseal.r3_title": {
        "ko": "R3. Unknown 파일 분류",
        "en": "R3. Unknown File Classification",
    },
    "reseal.r3_guide": {
        "ko": "각 Unknown 파일에 대해 '파생 파일' 또는 '제외'를 선택하세요.",
        "en": "Select 'Derived' or 'Excluded' for each unknown file.",
    },
    "reseal.r3_no_unknown": {
        "ko": "Unknown 파일이 없습니다. 다음 단계로 진행하세요.",
        "en": "No unknown files. Proceed to next step.",
    },
    "reseal.derived": {"ko": "파생 파일", "en": "Derived"},
    "reseal.excluded": {"ko": "제외", "en": "Excluded"},
    "reseal.parent_file": {"ko": "원본 파일:", "en": "Parent File:"},
    "reseal.derivation_reason": {"ko": "파생 사유:", "en": "Derivation Reason:"},
    "reseal.r4_title": {
        "ko": "R4. 재봉인 정보 입력",
        "en": "R4. Reseal Information Input",
    },
    "reseal.investigator": {"ko": "담당 수사관", "en": "Investigator"},
    "reseal.reason": {"ko": "재봉인 사유", "en": "Reseal Reason"},
    "reseal.participation": {"ko": "피압수자 참여 여부", "en": "Subject Participation"},
    "reseal.participate": {"ko": "참여함", "en": "Participated"},
    "reseal.chunk_size": {"ko": "GCM 구간 크기 (GB)", "en": "GCM Chunk Size (GB)"},
    "reseal.r5_title": {"ko": "R5. 암호화 진행", "en": "R5. Encryption Progress"},
    "reseal.r5_waiting": {"ko": "대기 중...", "en": "Waiting..."},
    "reseal.r6_title": {
        "ko": "R6. 재봉인기록지 미리보기",
        "en": "R6. Reseal Record Preview",
    },
    "reseal.r7_title": {
        "ko": "R7. 키 분할 결과 및 접근제어 시간 설정",
        "en": "R7. Key Split Results & Access Control",
    },
    "reseal.r8_title": {"ko": "R8. 재봉인 완료", "en": "R8. Resealing Complete"},
    "reseal.cancel_confirm": {
        "ko": "재봉인 프로세스를 취소하시겠습니까?",
        "en": "Cancel the resealing process?",
    },

    # Case manager
    "case.title": {"ko": "케이스 관리", "en": "Case Manager"},
    "case.search": {"ko": "검색", "en": "Search"},
    "case.search_label": {"ko": "검색:", "en": "Search:"},
    "case.search_placeholder": {"ko": "검색어 입력...", "en": "Search..."},
    "case.refresh": {"ko": "새로고침", "en": "Refresh"},
    "case.status_filter": {"ko": "상태:", "en": "Status:"},
    "case.status_all": {"ko": "전체", "en": "All"},
    "case.status_sealed": {"ko": "봉인", "en": "Sealed"},
    "case.status_unsealed": {"ko": "봉인해제", "en": "Unsealed"},
    "case.status_resealed": {"ko": "재봉인", "en": "Resealed"},
    "case.total_count": {"ko": "총 {count}건", "en": "{count} total"},
    "case.col_seal_id": {"ko": "Seal ID", "en": "Seal ID"},
    "case.col_case_number": {"ko": "사건번호", "en": "Case No."},
    "case.col_suspect": {"ko": "피압수자", "en": "Subject"},
    "case.col_investigator": {"ko": "수사관", "en": "Investigator"},
    "case.col_status": {"ko": "상태", "en": "Status"},
    "case.col_date": {"ko": "봉인일시", "en": "Sealed Date"},
    "case.detail": {"ko": "상세보기", "en": "Details"},
    "case.artifacts": {"ko": "산출물보기", "en": "Artifacts"},
    "case.history": {"ko": "이력보기", "en": "History"},
    "case.open_pdf": {"ko": "기록지PDF열기", "en": "Open PDF"},
    "case.delete": {"ko": "삭제", "en": "Delete"},
    "case.back_home": {"ko": "\u2190 홈으로", "en": "\u2190 Home"},
    "case.select_required": {"ko": "케이스를 선택하세요.", "en": "Please select a case."},
    "case.select_required_title": {"ko": "선택 필요", "en": "Selection Required"},
    "case.delete_confirm_title": {"ko": "삭제 확인", "en": "Confirm Delete"},
    "case.delete_confirm_msg": {
        "ko": "케이스 '{seal_id}'를 삭제하시겠습니까?\n(DB 레코드만 삭제되며 파일은 유지됩니다.)",
        "en": "Delete case '{seal_id}'?\n(Only DB record is deleted; files are preserved.)",
    },
    "case.delete_done": {"ko": "삭제 완료", "en": "Deleted"},
    "case.not_found": {"ko": "해당 케이스를 찾을 수 없습니다.", "en": "Case not found."},
    "case.not_found_title": {"ko": "없음", "en": "Not Found"},
    "case.loading": {"ko": "불러오는 중...", "en": "Loading..."},
    "case.empty_state": {
        "ko": "등록된 케이스가 없습니다",
        "en": "No cases yet",
    },
    "case.empty_state_hint": {
        "ko": "새 케이스를 생성하여 봉인 절차를 시작하세요.",
        "en": "Create a new case to start the sealing workflow.",
    },
    "case.delete_toast": {
        "ko": "케이스 '{seal_id}'가 삭제되었습니다",
        "en": "Case '{seal_id}' deleted",
    },

    # Case detail dialog
    "case_detail.title": {"ko": "케이스 상세", "en": "Case Detail"},
    "case_detail.tab_info": {"ko": "기본 정보", "en": "Basic Info"},
    "case_detail.tab_files": {"ko": "파일 정보", "en": "File Info"},
    "case_detail.tab_history": {"ko": "이력 타임라인", "en": "History Timeline"},
    "case_detail.tab_artifacts": {"ko": "산출물", "en": "Artifacts"},
    "case_detail.section_case": {"ko": "사건 정보", "en": "Case Information"},
    "case_detail.section_subject": {"ko": "피압수자 정보", "en": "Subject Information"},
    "case_detail.section_investigator": {"ko": "수사관 정보", "en": "Investigator Info"},
    "case_detail.seal_id": {"ko": "Seal ID", "en": "Seal ID"},
    "case_detail.case_number": {"ko": "사건번호", "en": "Case No."},
    "case_detail.seizure_time": {"ko": "압수일시", "en": "Seizure Date"},
    "case_detail.seizure_location": {"ko": "압수장소", "en": "Seizure Location"},
    "case_detail.storage_type": {"ko": "저장매체", "en": "Storage"},
    "case_detail.name": {"ko": "성명", "en": "Name"},
    "case_detail.email": {"ko": "이메일", "en": "Email"},
    "case_detail.dob": {"ko": "생년월일", "en": "Date of Birth"},
    "case_detail.phone": {"ko": "전화번호", "en": "Phone"},
    "case_detail.investigator": {"ko": "수사관", "en": "Investigator"},
    "case_detail.process_type": {"ko": "프로세스", "en": "Process"},
    "case_detail.start_time": {"ko": "시작 시간", "en": "Start Time"},
    "case_detail.end_time": {"ko": "종료 시간", "en": "End Time"},
    "case_detail.no_history": {"ko": "이력이 없습니다.", "en": "No history records."},
    "case_detail.reason_prefix": {"ko": "사유:", "en": "Reason:"},
    "case_detail.col_filename": {"ko": "파일명", "en": "File Name"},
    "case_detail.col_type": {"ko": "유형", "en": "Type"},
    "case_detail.col_size": {"ko": "크기", "en": "Size"},
    "case_detail.col_path": {"ko": "경로", "en": "Path"},
    "case_detail.status_unknown": {"ko": "상태 정보 없음", "en": "Status Unknown"},
    "case_detail.created_at": {"ko": "등록 일시", "en": "Registered At"},
    "case_detail.section_original_files": {"ko": "원본 파일", "en": "Original Files"},
    "case_detail.section_result_files": {
        "ko": "암호화 결과 파일",
        "en": "Encrypted Result Files",
    },
    "case_detail.section_unknown_files": {
        "ko": "미분류 파일 (Unknown)",
        "en": "Unknown Files",
    },
    "case_detail.section_derived_files": {"ko": "파생 파일", "en": "Derived Files"},
    "case_detail.file_size": {"ko": "크기", "en": "Size"},
    "case_detail.file_mtime": {"ko": "수정 시각", "en": "Modified"},
    "case_detail.enc_algo": {"ko": "암호화 알고리즘", "en": "Encryption Algorithm"},
    "case_detail.enc_ended": {"ko": "암호화 완료 시각", "en": "Encryption Finished"},
    "case_detail.hash_match": {"ko": "해시 일치", "en": "Hash Match"},
    "case_detail.hash_mismatch": {"ko": "해시 불일치", "en": "Hash Mismatch"},
    "case_detail.no_files": {"ko": "파일 정보가 없습니다.", "en": "No file information."},

    # Artifact context menu
    "artifact.open": {"ko": "열기", "en": "Open"},
    "artifact.open_folder": {"ko": "폴더 열기", "en": "Open Folder"},
    "artifact.copy_path": {"ko": "경로 복사", "en": "Copy Path"},
    "artifact.file_not_found": {
        "ko": "파일을 찾을 수 없습니다",
        "en": "File not found",
    },
    "artifact.folder_not_found": {
        "ko": "폴더를 찾을 수 없습니다",
        "en": "Folder not found",
    },

    # Common
    "common.cancel": {"ko": "취소", "en": "Cancel"},
    "common.prev": {"ko": "\u2190 이전", "en": "\u2190 Previous"},
    "common.next": {"ko": "다음 \u2192", "en": "Next \u2192"},
    "common.close": {"ko": "닫기", "en": "Close"},
    "common.confirm": {"ko": "확인", "en": "Confirm"},
    "common.required": {"ko": "필수 항목입니다", "en": "This field is required"},
    "common.browse": {"ko": "찾아보기...", "en": "Browse..."},
    "common.complete": {"ko": "완료", "en": "Complete"},
    "common.error": {"ko": "오류", "en": "Error"},
    "common.warning": {"ko": "경고", "en": "Warning"},
    "common.info": {"ko": "정보", "en": "Info"},
    "common.yes": {"ko": "예", "en": "Yes"},
    "common.no": {"ko": "아니오", "en": "No"},
    "common.step_of": {
        "ko": "단계 {current} / {total}",
        "en": "Step {current} / {total}",
    },
    "common.input_error": {"ko": "입력 오류", "en": "Input Error"},

    # Signature pad
    "sig.guide": {"ko": "여기에 서명하세요", "en": "Sign here"},
    "sig.clear": {"ko": "지우기", "en": "Clear"},
    "sig.complete": {"ko": "서명 완료", "en": "Complete Signing"},
    "sig.preview_title": {"ko": "서명 확인", "en": "Signature Confirmation"},
    "sig.preview_text": {"ko": "서명을 확인하세요", "en": "Confirm your signature"},
    "sig.accept": {"ko": "확인", "en": "Accept"},
    "sig.retry": {"ko": "다시 서명", "en": "Sign Again"},
    "sig.signer": {"ko": "서명자", "en": "Signer"},
    "sig.date": {"ko": "날짜", "en": "Date"},
    "sig.empty_warning": {"ko": "서명이 비어있습니다", "en": "Signature is empty"},
    "sig.confirmed": {"ko": "서명이 확정되었습니다", "en": "Signature confirmed"},
    "sig.signer_info": {
        "ko": "서명자: {name}  날짜: {date}",
        "en": "Signer: {name}  Date: {date}",
    },

    # Progress
    "progress.title": {"ko": "작업 진행 중", "en": "Processing"},
    "progress.status": {"ko": "진행 중...", "en": "Processing..."},
    "progress.preparing": {"ko": "준비 중...", "en": "Preparing..."},
    "progress.processing": {
        "ko": "처리 중... ({current}/{total})",
        "en": "Processing... ({current}/{total})",
    },
    "progress.chunk": {"ko": "구간", "en": "Chunk"},
    "progress.chunk_label": {
        "ko": "구간: {current} / {total}",
        "en": "Chunk: {current} / {total}",
    },
    "progress.elapsed": {"ko": "경과", "en": "Elapsed"},
    "progress.elapsed_label": {
        "ko": "경과: {time}",
        "en": "Elapsed: {time}",
    },
    "progress.remaining": {"ko": "잔여", "en": "Remaining"},
    "progress.remaining_label": {
        "ko": "잔여: {time}",
        "en": "Remaining: {time}",
    },
    "progress.remaining_calc": {"ko": "잔여: 계산 중...", "en": "Remaining: Calculating..."},
    "progress.speed": {"ko": "속도", "en": "Speed"},
    "progress.speed_label": {
        "ko": "속도: {rate:.2f} 구간/초",
        "en": "Speed: {rate:.2f} chunks/sec",
    },
    "progress.cancel": {"ko": "취소", "en": "Cancel"},
    "progress.cancelling": {"ko": "취소 중...", "en": "Cancelling..."},
    "progress.complete": {
        "ko": "완료! (소요: {time})",
        "en": "Complete! (Elapsed: {time})",
    },
    "progress.error": {
        "ko": "오류 발생 (소요: {time})",
        "en": "Error occurred (Elapsed: {time})",
    },
    "progress.remaining_zero": {"ko": "잔여: 0초", "en": "Remaining: 0s"},
    "progress.chunks_per_sec": {"ko": "구간/초", "en": "chunks/sec"},

    # Time formatting
    "time.hours": {"ko": "시간", "en": "h"},
    "time.minutes": {"ko": "분", "en": "m"},
    "time.seconds": {"ko": "초", "en": "s"},
    "time.fmt_hms": {"ko": "{h}시간 {m:02d}분 {s:02d}초", "en": "{h}h {m:02d}m {s:02d}s"},
    "time.fmt_ms": {"ko": "{m}분 {s:02d}초", "en": "{m}m {s:02d}s"},
    "time.fmt_s": {"ko": "{s}초", "en": "{s}s"},
    "time.zero": {"ko": "0초", "en": "0s"},

    # Event type labels (for case detail & case manager)
    "event.seal": {"ko": "봉인 (Sealing)", "en": "Sealing"},
    "event.unseal": {"ko": "봉인해제 (Unsealing)", "en": "Unsealing"},
    "event.reseal": {"ko": "재봉인 (Resealing)", "en": "Resealing"},

    # Progress dialog internal messages
    "progress.user_cancelled": {"ko": "사용자가 작업을 취소했습니다.", "en": "Operation cancelled by user."},
    "progress.task_cancelled": {"ko": "작업이 취소되었습니다.", "en": "Operation was cancelled."},
    "progress.encrypt_title": {"ko": "암호화 진행", "en": "Encryption Progress"},
    "progress.decrypt_complete": {"ko": "복호화 완료!", "en": "Decryption complete!"},
    "progress.encrypt_complete": {"ko": "암호화 완료!", "en": "Encryption complete!"},

    # Preview / completion labels
    "preview.seal_title": {"ko": "          전자봉인 기록지 미리보기", "en": "          Seal Record Preview"},
    "preview.case_info": {"ko": "[사건정보]", "en": "[Case Information]"},
    "preview.case_number": {"ko": "  사건번호: {v}", "en": "  Case No.: {v}"},
    "preview.investigator_name": {"ko": "  담당 수사관: {v}", "en": "  Investigator: {v}"},
    "preview.investigator_rank": {"ko": "  직급: {v}", "en": "  Rank: {v}"},
    "preview.seizure_info": {"ko": "[압수 정보]", "en": "[Seizure Information]"},
    "preview.seizure_datetime": {"ko": "  일시: {v}", "en": "  Date/Time: {v}"},
    "preview.seizure_location": {"ko": "  장소: {v}", "en": "  Location: {v}"},
    "preview.media_info": {"ko": "[저장매체]", "en": "[Storage Media]"},
    "preview.media_manufacturer": {"ko": "  제조사: {v}", "en": "  Manufacturer: {v}"},
    "preview.media_model": {"ko": "  모델명: {v}", "en": "  Model: {v}"},
    "preview.subject_info": {"ko": "[피압수자]", "en": "[Subject]"},
    "preview.subject_name": {"ko": "  이름: {v}", "en": "  Name: {v}"},
    "preview.subject_email": {"ko": "  이메일: {v}", "en": "  Email: {v}"},
    "preview.subject_dob": {"ko": "  생년월일: {v}", "en": "  Date of Birth: {v}"},
    "preview.subject_phone": {"ko": "  연락처: {v}", "en": "  Phone: {v}"},
    "preview.target_file_section": {"ko": "[대상 파일]", "en": "[Target File]"},
    "preview.file_path": {"ko": "  경로: {v}", "en": "  Path: {v}"},
    "preview.chunk_size": {"ko": "  구간 크기: {v} GB", "en": "  Chunk size: {v} GB"},
    "preview.confirm_next": {"ko": "위 내용을 확인한 후 '다음'을 클릭하세요.", "en": "Review the information above, then click 'Next'."},

    # Seal completion
    "complete.seal_title": {"ko": "        봉인이 완료되었습니다", "en": "        Sealing Complete"},
    "complete.seal_info_section": {"ko": "  [봉인 정보]", "en": "  [Seal Information]"},
    "complete.case_number": {"ko": "  사건번호      : {v}", "en": "  Case No.      : {v}"},
    "complete.subject": {"ko": "  피압수자      : {v}", "en": "  Subject       : {v}"},
    "complete.investigator": {"ko": "  수사관        : {v}", "en": "  Investigator  : {v}"},
    "complete.file_section": {"ko": "  [대상 파일]", "en": "  [Target File]"},
    "complete.filename": {"ko": "  파일명        : {v}", "en": "  Filename      : {v}"},
    "complete.filesize": {"ko": "  파일 크기     : {v}", "en": "  File size     : {v}"},
    "complete.enc_file": {"ko": "  암호화 파일   : {v}", "en": "  Encrypted     : {v}"},
    "complete.time_section": {"ko": "  [실행 시간]", "en": "  [Execution Time]"},
    "complete.enc_start": {"ko": "  암호화 시작   : {v}", "en": "  Start         : {v}"},
    "complete.enc_end": {"ko": "  암호화 종료   : {v}", "en": "  End           : {v}"},
    "complete.enc_elapsed": {"ko": "  암호화 소요   : {v}", "en": "  Elapsed       : {v}"},
    "complete.key_section": {"ko": "  [키 관리]", "en": "  [Key Management]"},
    "complete.key_shares": {"ko": "  키 조각       : 4개 (SSS 2-of-4)", "en": "  Key shares    : 4 (SSS 2-of-4)"},
    "complete.notice_section": {"ko": "  [안내]", "en": "  [Notice]"},
    "complete.seal_saved": {
        "ko": "  봉인지 PDF 및 키 조각이 저장되었습니다.",
        "en": "  Seal record PDF and key shares have been saved.",
    },
    "complete.key_instruction": {
        "ko": "  피압수자 키 조각(1)과 수사관 키 조각(2)은\n  각각의 저장매체에 안전하게 보관하세요.",
        "en": "  Subject key share (1) and investigator key share (2)\n  must be securely stored on separate media.",
    },

    # Key split messages
    "keysplit.complete_title": {"ko": "키 분할 완료 (SSS 2-of-4)", "en": "Key Split Complete (SSS 2-of-4)"},
    "keysplit.share_subject": {"ko": "  키 조각 1 (피압수자): {v}...", "en": "  Share 1 (Subject): {v}..."},
    "keysplit.share_investigator": {"ko": "  키 조각 2 (수사관):   {v}...", "en": "  Share 2 (Investigator): {v}..."},
    "keysplit.share_system": {"ko": "  키 조각 3 (시스템):   {v}...", "en": "  Share 3 (System):       {v}..."},
    "keysplit.share_admin": {"ko": "  키 조각 4 (관리자):   {v}...", "en": "  Share 4 (Admin):        {v}..."},
    "keysplit.subject_store": {
        "ko": "키 조각 1은 피압수자 저장매체에 저장됩니다.",
        "en": "Share 1 is stored on the subject's storage media.",
    },
    "keysplit.investigator_store": {
        "ko": "키 조각 2는 수사관 저장매체에 저장됩니다.",
        "en": "Share 2 is stored on the investigator's storage media.",
    },
    "keysplit.system_store": {
        "ko": "키 조각 3, 4는 시스템에 암호화 저장됩니다.",
        "en": "Shares 3, 4 are encrypted and stored in the system.",
    },
    "keysplit.run_prompt": {"ko": "키 분할을 실행하려면 '다음'을 클릭하세요.", "en": "Click 'Next' to execute key split."},
    "keysplit.failed": {"ko": "키 분할 실패 — 로그를 확인하세요.", "en": "Key split failed — check logs."},
    "keysplit.error": {"ko": "키 분할 오류", "en": "Key Split Error"},

    # Unseal preview/completion
    "preview.unseal_title": {"ko": "      봉인해제기록지 미리보기", "en": "      Unseal Record Preview"},
    "preview.unseal_info": {"ko": "[봉인해제 정보]", "en": "[Unseal Information]"},
    "preview.reason": {"ko": "  사유: {v}", "en": "  Reason: {v}"},
    "preview.investigator": {"ko": "  담당 수사관: {v}", "en": "  Investigator: {v}"},
    "preview.subject_participated": {"ko": "  피압수자 참여: {v}", "en": "  Subject participation: {v}"},
    "preview.yes": {"ko": "예", "en": "Yes"},
    "preview.no": {"ko": "아니오", "en": "No"},
    "preview.decrypt_result": {"ko": "[복호화 결과]", "en": "[Decryption Result]"},
    "preview.output_file": {"ko": "  출력 파일: {v}", "en": "  Output file: {v}"},
    "preview.hash_verified": {"ko": "  해시 검증: {v}", "en": "  Hash verified: {v}"},
    "preview.hash_pass": {"ko": "통과", "en": "Pass"},
    "preview.hash_fail": {"ko": "실패", "en": "Fail"},
    "preview.sha256_match": {"ko": "  SHA-256 일치: {v}", "en": "  SHA-256 match: {v}"},
    "preview.md5_match": {"ko": "  MD5 일치: {v}", "en": "  MD5 match: {v}"},
    "preview.procedure_history": {"ko": "[절차 이력]", "en": "[Procedure History]"},

    "complete.unseal_title": {"ko": "      봉인해제가 완료되었습니다", "en": "      Unsealing Complete"},
    "complete.dec_file": {"ko": "  복호화 파일: {v}", "en": "  Decrypted file: {v}"},
    "complete.hash_result_section": {"ko": "[해시 검증 결과]", "en": "[Hash Verification Result]"},
    "complete.overall_hash": {"ko": "  전체 검증: {v}", "en": "  Overall: {v}"},
    "complete.sha256": {"ko": "  SHA-256: {v}", "en": "  SHA-256: {v}"},
    "complete.md5": {"ko": "  MD5: {v}", "en": "  MD5: {v}"},
    "complete.match": {"ko": "일치", "en": "Match"},
    "complete.mismatch": {"ko": "불일치", "en": "Mismatch"},
    "complete.record_section": {"ko": "[기록 저장 상태]", "en": "[Record Save Status]"},
    "complete.record_json": {"ko": "  기록지 JSON: {v}", "en": "  Record JSON: {v}"},
    "complete.record_pdf": {"ko": "  기록지 PDF: {v}", "en": "  Record PDF: {v}"},
    "complete.hash_warn": {
        "ko": "  [경고] 해시 검증에 실패했습니다.\n  복호화된 파일의 무결성이 보장되지 않습니다.\n  에스컬레이션이 필요할 수 있습니다.",
        "en": "  [Warning] Hash verification failed.\n  The integrity of the decrypted file is not guaranteed.\n  Escalation may be required.",
    },
    "complete.mismatch_note": {
        "ko": "  [참고] 파일-봉인지 대조 불일치가 수사관에 의해 확인되었습니다.",
        "en": "  [Note] File-seal record mismatch was acknowledged by the investigator.",
    },
    "complete.unseal_saved": {
        "ko": "  봉인해제기록지가 저장되었습니다.",
        "en": "  Unseal record has been saved.",
    },

    # Reseal preview/completion
    "preview.reseal_title": {"ko": "      재봉인기록지 미리보기", "en": "      Reseal Record Preview"},
    "preview.reseal_info": {"ko": "[재봉인 정보]", "en": "[Reseal Information]"},
    "preview.file_status": {"ko": "[파일 현황]", "en": "[File Status]"},
    "preview.known_files": {"ko": "  기존 파일: {v}개", "en": "  Known files: {v}"},
    "preview.unknown_files": {"ko": "  Unknown 파일: {v}개", "en": "  Unknown files: {v}"},
    "preview.derived_files": {"ko": "  파생 파일: {v}개", "en": "  Derived files: {v}"},
    "preview.derived_item": {"ko": "    - {filename} (원본: {parent})", "en": "    - {filename} (parent: {parent})"},
    "preview.excluded_files": {"ko": "  제외 파일: {v}개", "en": "  Excluded files: {v}"},

    "complete.reseal_title": {"ko": "      재봉인이 완료되었습니다", "en": "      Resealing Complete"},
    "complete.enc_file_count": {"ko": "  암호화 파일 수: {v}", "en": "  Encrypted files: {v}"},
    "complete.reseal_saved": {
        "ko": "  재봉인기록지 PDF 및 키 조각이 저장되었습니다.",
        "en": "  Reseal record PDF and key shares have been saved.",
    },
    "complete.reseal_key_instruction": {
        "ko": "  피압수자 키 조각(1)과 수사관 키 조각(2)은\n  각각의 저장매체에 안전하게 보관해주세요.",
        "en": "  Subject key share (1) and investigator key share (2)\n  must be securely stored on separate media.",
    },

    # Reseal encryption status
    "reseal.enc_complete": {"ko": "암호화 완료: {v}개 파일", "en": "Encryption complete: {v} file(s)"},
    "reseal.record_generating": {"ko": "재봉인기록지 생성 중...", "en": "Generating reseal record..."},
    "reseal.record_generated": {"ko": "재봉인기록지 생성 완료", "en": "Reseal record generated"},
    "reseal.process_not_init": {"ko": "오류: 프로세스가 초기화되지 않았습니다.", "en": "Error: Process not initialized."},

    # Unseal decrypt status
    "unseal.dec_complete": {"ko": "복호화 완료: {v}", "en": "Decryption complete: {v}"},
    "unseal.hash_result": {"ko": "해시 검증: {v}", "en": "Hash verification: {v}"},
    "unseal.sha256_result": {"ko": "  SHA-256: {v}", "en": "  SHA-256: {v}"},
    "unseal.md5_result": {"ko": "  MD5: {v}", "en": "  MD5: {v}"},
    "unseal.record_generating": {"ko": "봉인해제기록지 생성 중...", "en": "Generating unseal record..."},
    "unseal.record_generated": {"ko": "봉인해제기록지 생성 완료", "en": "Unseal record generated"},
    "unseal.process_not_init": {"ko": "오류: 프로세스가 초기화되지 않았습니다.", "en": "Error: Process not initialized."},
    "unseal.error_occurred": {"ko": "오류 발생: {v}", "en": "Error: {v}"},

    # Unseal verification
    "verify.title": {"ko": "      파일-봉인지 대조 검증 결과", "en": "      File-Seal Record Verification Results"},
    "verify.target_file": {"ko": "  대상 파일: {v}", "en": "  Target file: {v}"},
    "verify.match": {"ko": "일치", "en": "Match"},
    "verify.mismatch": {"ko": "불일치", "en": "Mismatch"},
    "verify.expected_sha256": {"ko": "      기대 SHA-256: {v}...", "en": "      Expected SHA-256: {v}..."},
    "verify.actual_sha256": {"ko": "      실제 SHA-256: {v}", "en": "      Actual SHA-256: {v}"},
    "verify.result": {"ko": "      결과: {v}", "en": "      Result: {v}"},
    "verify.no_items": {"ko": "  검증 항목이 없습니다.", "en": "  No verification items."},
    "verify.all_match": {"ko": "  >>> 모든 항목 일치 <<<", "en": "  >>> All items match <<<"},
    "verify.has_mismatch": {"ko": "  >>> 불일치 항목이 있습니다! <<<", "en": "  >>> Mismatches detected! <<<"},
    "verify.mismatch_action": {"ko": "  수사관 판단으로 진행/중단을 선택해주세요.", "en": "  Investigator must decide to proceed or abort."},
    "verify.mismatch_warning": {"ko": "경고: 대조 불일치가 감지되었습니다.", "en": "Warning: Verification mismatch detected."},
    "verify.error_badge": {"ko": "검증 오류", "en": "Verification Error"},
    "verify.error_label": {"ko": "오류 원인", "en": "Error cause"},
    "verify.error_title": {"ko": "검증 오류", "en": "Verification Error"},
    "verify.error_block": {
        "ko": "사전 검증 중 오류가 발생하여 진행할 수 없습니다.\n입력한 봉인지/암호화 파일/키를 확인해주세요.\n\n원인: {v}",
        "en": "Pre-verification failed; cannot proceed.\nCheck the seal record, encrypted file, and key.\n\nCause: {v}",
    },
    "verify.error_action": {
        "ko": "  이전 단계로 돌아가 입력을 확인한 뒤 다시 시도해주세요.",
        "en": "  Go back to the previous step, check the inputs, and retry.",
    },
    "verify.error_warning": {
        "ko": "경고: 봉인지 검증 중 오류가 발생했습니다. 진행이 차단됩니다.",
        "en": "Warning: An error occurred during seal record verification. Progression is blocked.",
    },

    # Reseal file comparison
    "reseal.file_summary": {"ko": "기존 파일: {known}개  |  Unknown 파일: {unknown}개", "en": "Known files: {known}  |  Unknown files: {unknown}"},
    "reseal.file_size_cat": {"ko": "크기: {size} bytes  |  시스템 분류 제안: {cat}", "en": "Size: {size} bytes  |  System suggestion: {cat}"},
    "reseal.record_error": {"ko": "기록지 오류", "en": "Record Error"},
    "reseal.record_info_type": {"ko": "  유형: {v}", "en": "  Type: {v}"},
    "reseal.record_info_case": {"ko": "  사건번호: {v}", "en": "  Case No.: {v}"},
    "reseal.record_info_created": {"ko": "  생성일: {v}", "en": "  Created: {v}"},

    # Seal signature process messages
    "seal.sig_process_start": {"ko": "전자서명 프로세스 시작...", "en": "Digital signature process starting..."},
    "seal.sig_no_process": {"ko": "SealProcess 없음 — 간이 서명 수행", "en": "SealProcess unavailable — performing simple signature"},
    "seal.sig_process_done": {"ko": "전자서명 프로세스 완료!", "en": "Digital signature process complete!"},
    "seal.sig_error_continue": {"ko": "전자서명 오류 (계속 진행 가능): {v}", "en": "Signature error (can continue): {v}"},
    "seal.record_json_saved": {"ko": "봉인 기록 JSON 저장 완료", "en": "Seal record JSON saved"},
    "seal.pdf_rendered": {"ko": "PDF 렌더링 완료", "en": "PDF rendering complete"},
    "seal.pdf_fallback": {"ko": "PDF 렌더링 폴백: {v}", "en": "PDF rendering fallback: {v}"},
    "seal.rsa_keygen": {"ko": "RSA-2048 키쌍 생성 완료", "en": "RSA-2048 key pair generated"},
    "seal.x509_cert": {"ko": "X.509 인증서 생성 완료", "en": "X.509 certificate generated"},
    "seal.cert_saved": {"ko": "인증서/개인키 저장 완료", "en": "Certificate/private key saved"},
    "seal.cert_error": {"ko": "인증서 생성 오류 (계속 진행): {v}", "en": "Certificate error (continuing): {v}"},
    "seal.participation": {"ko": "참여", "en": "Participated"},

    # Reseal unlock_time
    "reseal.unlock_days": {"ko": "일 ({min}~{max})", "en": "days ({min}~{max})"},

    # About dialog
    "about.title": {"ko": "정보", "en": "About"},
    "about.version": {"ko": "v0.2.0", "en": "v0.2.0"},
    "about.desc": {
        "ko": "디지털증거 전자봉인시스템\nv0.2.0\n\n형사절차에서 디지털증거 봉인 모델\n(박희원, 성균관대 2025)",
        "en": "Electronic Sealing Scheme (SSS)\nv1.0.0\n\nResearch prototype for digital evidence",
    },

    # Exit dialog
    "exit.title": {"ko": "종료", "en": "Exit"},
    "exit.confirm": {
        "ko": "프로그램을 종료하시겠습니까?",
        "en": "Are you sure you want to exit?",
    },

    # Seal complete dialog
    "seal_complete.title": {"ko": "봉인 완료", "en": "Sealing Complete"},
    "seal_complete.msg": {
        "ko": "봉인이 성공적으로 완료되었습니다.",
        "en": "Sealing completed successfully.",
    },
    "unseal_complete.title": {"ko": "봉인해제 완료", "en": "Unsealing Complete"},
    "unseal_complete.msg": {
        "ko": "봉인해제가 완료되었습니다.",
        "en": "Unsealing completed.",
    },
    "reseal_complete.title": {"ko": "재봉인 완료", "en": "Resealing Complete"},
    "reseal_complete.msg": {
        "ko": "재봉인이 성공적으로 완료되었습니다.",
        "en": "Resealing completed successfully.",
    },
    "hash.verified": {"ko": "해시 검증 통과", "en": "Hash Verified"},
    "hash.failed": {
        "ko": "해시 검증 실패 (주의)",
        "en": "Hash Verification Failed (Warning)",
    },

    # Cancel confirmation
    "cancel.title": {"ko": "취소 확인", "en": "Confirm Cancel"},
    "cancel.msg": {
        "ko": "진행 중인 작업을 취소하시겠습니까?",
        "en": "Cancel the current operation?",
    },
    "seal.cancel_confirm": {
        "ko": "봉인 프로세스를 취소하시겠습니까?",
        "en": "Cancel the sealing process?",
    },

    # Dashboard status type display
    "status.seal": {"ko": "봉인", "en": "Seal"},
    "status.unseal": {"ko": "봉인해제", "en": "Unseal"},
    "status.reseal": {"ko": "재봉인", "en": "Reseal"},

    # Validation messages
    "validate.select_file": {
        "ko": "대상 파일을 선택해주세요.",
        "en": "Please select a target file.",
    },
    "validate.select_output": {
        "ko": "출력 폴더를 선택해주세요.",
        "en": "Please select an output directory.",
    },
    "validate.chunk_range": {
        "ko": "구간 크기는 {min}~{max}GB 범위여야 합니다.",
        "en": "Chunk size must be between {min}~{max} GB.",
    },
    "validate.chunk_invalid": {
        "ko": "구간 크기를 올바르게 입력해주세요.",
        "en": "Please enter a valid chunk size.",
    },
    "validate.field_required": {
        "ko": "{field} 을(를) 입력해주세요.",
        "en": "Please enter {field}.",
    },
    "validate.password_mismatch": {
        "ko": "비밀번호가 일치하지 않습니다.",
        "en": "Passwords do not match.",
    },
    "validate.signature_required": {
        "ko": "서명을 입력해주세요.",
        "en": "Please provide a signature.",
    },
    "validate.enc_file": {
        "ko": "암호화 파일(.enc)을 선택해주세요.",
        "en": "Please select an encrypted file (.enc).",
    },
    "validate.record_json": {
        "ko": "봉인지 JSON 파일을 선택해주세요.",
        "en": "Please select a seal record JSON file.",
    },
    "validate.aes_key_empty": {
        "ko": "AES 키를 입력해주세요.",
        "en": "Please enter the AES key.",
    },
    "validate.aes_key_invalid": {
        "ko": "AES 키는 64자리 16진수 문자열이어야 합니다.",
        "en": "AES key must be a 64-character hexadecimal string.",
    },
    "validate.reason_required": {
        "ko": "봉인해제 사유를 입력해주세요.",
        "en": "Please enter the unseal reason.",
    },
    "validate.investigator_required": {
        "ko": "담당 수사관을 입력해주세요.",
        "en": "Please enter the investigator name.",
    },
    "validate.unlock_range": {
        "ko": "unlock_time은 {min}~{max}일 범위여야 합니다.",
        "en": "unlock_time must be between {min}~{max} days.",
    },
    "validate.prev_record": {
        "ko": "봉인해제기록지 JSON 파일을 선택해주세요.",
        "en": "Please select the unseal record JSON file.",
    },
    "validate.target_dir": {
        "ko": "재봉인 대상 폴더를 선택해주세요.",
        "en": "Please select the reseal target directory.",
    },
    "validate.reseal_reason": {
        "ko": "재봉인 사유를 입력해주세요.",
        "en": "Please enter the reseal reason.",
    },
    "validate.classification_incomplete": {
        "ko": "미분류 파일이 {count}건 남아있습니다. 모두 분류해주세요.",
        "en": "{count} file(s) remain unclassified. Please classify all.",
    },
    "validate.classification_title": {
        "ko": "분류 미완료",
        "en": "Classification Incomplete",
    },

    # Mismatch warning
    "mismatch.title": {
        "ko": "경고: 대조 불일치",
        "en": "Warning: Verification Mismatch",
    },
    "mismatch.msg": {
        "ko": "파일-봉인지 대조에서 불일치가 감지되었습니다.\n\n수사관 판단으로 진행하시겠습니까?\n'아니오'를 선택하면 프로세스를 중단합니다.",
        "en": "Mismatch detected in file-seal record verification.\n\nProceed with investigator's judgment?\nSelect 'No' to abort the process.",
    },

    # Key file dialog
    "keyfile.title": {"ko": "키 파일 선택", "en": "Select Key File"},
    "keyfile.error": {"ko": "키 파일 읽기 실패", "en": "Failed to read key file"},

    # Encryption / decryption errors
    "encrypt.failed_title": {"ko": "암호화 실패", "en": "Encryption Failed"},
    "encrypt.failed_msg": {
        "ko": "암호화 중 오류가 발생했습니다",
        "en": "An error occurred during encryption",
    },

    # PDF open
    "pdf.not_found": {
        "ko": "PDF 파일을 찾을 수 없습니다.",
        "en": "PDF file not found.",
    },
    "pdf.open_failed": {
        "ko": "PDF 열기 실패",
        "en": "Failed to open PDF",
    },

    # File dialog titles
    "filedialog.select_folder": {"ko": "폴더 선택", "en": "Select Folder"},
    "filedialog.select_file": {"ko": "파일 선택", "en": "Select File"},
    "filedialog.all_files": {"ko": "모든 파일", "en": "All Files"},
    "filedialog.disk_images": {"ko": "디스크 이미지", "en": "Disk Images"},
    "filedialog.json_files": {"ko": "JSON 파일", "en": "JSON Files"},
    "filedialog.enc_files": {"ko": "암호화 파일", "en": "Encrypted Files"},
    "filedialog.key_files": {"ko": "키 파일", "en": "Key Files"},
    "filedialog.text_files": {"ko": "텍스트 파일", "en": "Text Files"},
    "filedialog.key_file_title": {"ko": "키 파일 선택", "en": "Select Key File"},

    # Miscellaneous process messages
    "process.encryption_progress_title": {
        "ko": "S1. AES-256-GCM 암호화 진행",
        "en": "S1. AES-256-GCM Encryption",
    },
    "process.decryption_progress_title": {
        "ko": "U5. AES-256-GCM 복호화 진행",
        "en": "U5. AES-256-GCM Decryption",
    },
    "process.reseal_encrypt_title": {
        "ko": "R5. AES-256-GCM 암호화 진행",
        "en": "R5. AES-256-GCM Encryption",
    },

    # Case workflow — new case dialog & action buttons
    "case.new_case": {"ko": "+ 새 케이스", "en": "+ New Case"},
    "case.create": {"ko": "생성", "en": "Create"},
    "case.case_number_input": {"ko": "사건번호 (필수)", "en": "Case Number (required)"},
    "case.investigator_input": {"ko": "수사관 (필수)", "en": "Investigator (required)"},
    "case.suspect_input": {"ko": "피압수자 이름 (선택)", "en": "Subject Name (optional)"},
    "case.start_seal": {"ko": "봉인 시작", "en": "Start Seal"},
    "case.start_unseal": {"ko": "봉인해제 시작", "en": "Start Unseal"},
    "case.start_reseal": {"ko": "재봉인 시작", "en": "Start Reseal"},
    "case.no_selection": {
        "ko": "케이스를 먼저 선택하세요.",
        "en": "Please select a case first.",
    },
    "case.seal_not_available": {
        "ko": "선택한 케이스는 봉인 가능 상태가 아닙니다.\n(봉인 전 케이스만 가능)",
        "en": "Selected case is not available for sealing.\n(Only pre-seal cases are eligible)",
    },
    "case.unseal_not_available": {
        "ko": "선택한 케이스는 봉인해제 가능 상태가 아닙니다.\n(봉인 완료 + 미해제 케이스만 가능)",
        "en": "Selected case is not available for unsealing.\n(Only sealed & not yet unsealed cases are eligible)",
    },
    "case.reseal_not_available": {
        "ko": "선택한 케이스는 재봉인 가능 상태가 아닙니다.\n(봉인해제 완료 케이스만 가능)",
        "en": "Selected case is not available for resealing.\n(Only unsealed cases are eligible)",
    },
    "case.create_success": {
        "ko": "케이스가 생성되었습니다.\nSeal ID: {seal_id}",
        "en": "Case created.\nSeal ID: {seal_id}",
    },
    "case.create_fail": {
        "ko": "케이스 생성 실패: {error}",
        "en": "Failed to create case: {error}",
    },
    "case.new_case_title": {"ko": "새 케이스 생성", "en": "Create New Case"},

    # Calendar
    "cal.title": {"ko": "날짜 선택", "en": "Select Date"},
    "cal.year": {"ko": "년", "en": "Year"},
    "cal.month": {"ko": "월", "en": "Month"},
    "cal.today": {"ko": "오늘", "en": "Today"},
    "cal.days_ko": {"ko": "일,월,화,수,목,금,토", "en": "Sun,Mon,Tue,Wed,Thu,Fri,Sat"},

    # Navigation
    "common.back_to_current": {"ko": "현재 단계로 →", "en": "Back to Current →"},

    # Wizard busy states (Wave 2)
    "unseal.verifying": {"ko": "파일 검증 중...", "en": "Verifying files..."},
    "reseal.comparing": {"ko": "파일 비교 중...", "en": "Comparing files..."},

    # Byte-level progress display (Wave 2)
    "progress.bytes_label": {
        "ko": "진행: {current} / {total}",
        "en": "Progress: {current} / {total}",
    },
    "progress.speed_mb": {
        "ko": "속도: {rate:.1f} MB/초",
        "en": "Speed: {rate:.1f} MB/s",
    },

    # Inline validation summary (Wave 2)
    "validate.fix_errors": {
        "ko": "입력 오류 {count}건을 확인해주세요.",
        "en": "Please fix {count} input error(s).",
    },

    # Summary card row labels (Wave 2)
    "summary.seal_id": {"ko": "Seal ID", "en": "Seal ID"},
    "summary.case_number": {"ko": "사건번호", "en": "Case No."},
    "summary.investigator": {"ko": "담당 수사관", "en": "Investigator"},
    "summary.rank": {"ko": "직급", "en": "Rank"},
    "summary.subject": {"ko": "피압수자", "en": "Subject"},
    "summary.email": {"ko": "이메일", "en": "Email"},
    "summary.dob": {"ko": "생년월일", "en": "Date of Birth"},
    "summary.phone": {"ko": "연락처", "en": "Phone"},
    "summary.seizure_datetime": {"ko": "압수일시", "en": "Seizure Date"},
    "summary.seizure_location": {"ko": "압수장소", "en": "Seizure Location"},
    "summary.manufacturer": {"ko": "제조사", "en": "Manufacturer"},
    "summary.model": {"ko": "모델명", "en": "Model"},
    "summary.serial": {"ko": "시리얼 번호", "en": "Serial No."},
    "summary.source_file": {"ko": "대상 파일", "en": "Target File"},
    "summary.file_size": {"ko": "파일 크기", "en": "File Size"},
    "summary.chunk_size": {"ko": "구간 크기", "en": "Chunk Size"},
    "summary.sha256": {"ko": "SHA-256", "en": "SHA-256"},
    "summary.md5": {"ko": "MD5", "en": "MD5"},
    "summary.enc_file": {"ko": "암호화 파일", "en": "Encrypted File"},
    "summary.enc_start": {"ko": "암호화 시작", "en": "Encryption Start"},
    "summary.enc_end": {"ko": "암호화 종료", "en": "Encryption End"},
    "summary.elapsed": {"ko": "소요 시간", "en": "Elapsed"},
    "summary.unlock_time": {"ko": "unlock_time", "en": "unlock_time"},
    "summary.key_shares": {"ko": "키 조각", "en": "Key Shares"},
    "summary.reason": {"ko": "사유", "en": "Reason"},
    "summary.participated": {"ko": "피압수자 참여", "en": "Subject Participation"},
    "summary.output_file": {"ko": "출력 파일", "en": "Output File"},
    "summary.hash_verified": {"ko": "해시 검증", "en": "Hash Verification"},
    "summary.record_json": {"ko": "기록지 JSON", "en": "Record JSON"},
    "summary.record_pdf": {"ko": "기록지 PDF", "en": "Record PDF"},
    "summary.dec_file": {"ko": "복호화 파일", "en": "Decrypted File"},
    "summary.known_files": {"ko": "기존 파일", "en": "Known Files"},
    "summary.unknown_files": {"ko": "Unknown 파일", "en": "Unknown Files"},
    "summary.derived_files": {"ko": "파생 파일", "en": "Derived Files"},
    "summary.excluded_files": {"ko": "제외 파일", "en": "Excluded Files"},
    "summary.enc_count": {"ko": "암호화 파일 수", "en": "Encrypted Files"},
    "summary.history": {"ko": "절차 이력", "en": "Procedure History"},
    "summary.summary_code": {"ko": "Summary", "en": "Summary"},
    "summary.expected_sha256": {"ko": "기대 SHA-256", "en": "Expected SHA-256"},
    "summary.actual_sha256": {"ko": "실제 SHA-256", "en": "Actual SHA-256"},
    "summary.result": {"ko": "결과", "en": "Result"},
    "summary.count_files": {"ko": "{v}개", "en": "{v} file(s)"},
    "summary.target_dir": {"ko": "대상 폴더", "en": "Target Directory"},
    "summary.verification": {"ko": "검증 항목", "en": "Verification Items"},
    "summary.notice": {"ko": "안내", "en": "Notice"},
}
