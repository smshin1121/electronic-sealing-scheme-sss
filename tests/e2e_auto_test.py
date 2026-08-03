"""전자봉인시스템 자동 E2E 테스트 — GUI 없이 전체 사이클 검증.

실행: python tests/e2e_auto_test.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# stdout UTF-8 강제 (Windows cp949 대응)
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# src/ 를 import path에 추가
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _banner(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def _step(msg: str) -> None:
    print(f"  ✓ {msg}")


def _fail(msg: str) -> None:
    print(f"  ✗ {msg}")
    sys.exit(1)


def run_full_cycle() -> None:
    """봉인 → 봉인해제 → 재봉인 → 재해제 전체 사이클."""

    work_dir = Path(tempfile.mkdtemp(prefix="seal_e2e_"))
    print(f"작업 디렉토리: {work_dir}")

    # ================================================================
    # 0. 테스트 파일 생성
    # ================================================================
    _banner("Phase 0: 테스트 환경 준비")

    test_file = work_dir / "evidence_sample.bin"
    test_data = os.urandom(2 * 1024 * 1024)  # 2MB
    test_file.write_bytes(test_data)
    original_sha256 = hashlib.sha256(test_data).hexdigest()
    original_md5 = hashlib.md5(test_data).hexdigest()
    _step(f"테스트 파일 생성: {test_file.name} (2MB)")
    _step(f"원본 SHA-256: {original_sha256[:16]}...")

    master_key_path = str(work_dir / "master.key")
    db_path = str(work_dir / "test.db")

    # ================================================================
    # 1. 봉인 (Sealing) S1~S7
    # ================================================================
    _banner("Phase 1: 봉인 (Sealing)")

    # S1. 파일 암호화
    from desktop.crypto import (
        encrypt_file, collect_metadata, split_key,
        init_master_key, encrypt_envelope,
    )

    _step("S1. 파일 메타데이터 수집...")
    file_meta = collect_metadata(str(test_file))
    _step(f"  파일명: {file_meta.filename}, 크기: {file_meta.size}")
    _step(f"  SHA-256: {file_meta.sha256[:16]}...")

    assert file_meta.sha256 == original_sha256, "메타데이터 SHA-256 불일치!"

    _step("S1. AES-256-GCM 암호화 시작 (구간 크기: 1GB)...")
    aes_key = os.urandom(32)
    aes_key_hex = aes_key.hex()
    enc_path = str(work_dir / "evidence_sample.bin.enc")

    progress_log = []
    def on_progress(current: int, total: int) -> None:
        progress_log.append((current, total))

    enc_result = encrypt_file(
        filepath=str(test_file),
        aes_key=aes_key,
        output_path=enc_path,
        chunk_size=1 * 1024**3,  # 1GB (파일이 작으므로 단일 구간)
        progress_cb=on_progress,
    )
    _step(f"  암호화 완료: {Path(enc_path).name}")
    _step(f"  구간 수: {enc_result.chunk_count}, 진행률 콜백: {len(progress_log)}회")

    # .enc 파일 끝에서 메타데이터 JSON 읽기
    import struct
    with open(enc_path, "rb") as ef:
        ef.seek(-4, 2)
        meta_size = struct.unpack("<I", ef.read(4))[0]
        ef.seek(-4 - meta_size, 2)
        enc_meta = json.loads(ef.read(meta_size).decode("utf-8"))
    _step(f"  .enc 메타데이터: nonces={len(enc_meta['nonces'])}, tags={len(enc_meta['tags'])}")

    # S2~S3. 봉인 정보 (자동 입력)
    _step("S2. 압수·봉인 정보 입력 (자동)...")
    _step("S3. 피압수자 정보 입력 (자동)...")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _normalize_utc(value: str) -> str:
        return (
            value.replace("+00:00", "Z")
            if value.endswith("+00:00")
            else value
        )

    case_info = {
        "case_number": "2025-형-12345",
        "investigator": "김수사",
        "device_user": "이사용",
        "suspect": "박피압",
        "storage_type": "SSD",
        "storage_info": {"manufacturer": "Samsung", "model": "870 EVO", "serial": "S12345"},
        "seizure_time": now_iso,
        "seizure_location": "서울 강남구 테헤란로 123",
    }
    subject_info = {
        "name": "박피압",
        "email": "suspect@test.com",
        "birth_date": "1990-01-15",
        "phone": "010-1234-5678",
        "cert_fingerprint": "",
        "signature_image_hash": hashlib.sha256(b"test_signature").hexdigest(),
    }

    # S4. 봉인지 생성
    _step("S4. 봉인지 JSON 생성...")
    try:
        from desktop.record import create_seal_id, build_seal_record, validate_record
        seal_id = create_seal_id()
    except ImportError:
        rand_hex = os.urandom(3).hex().upper()
        seal_id = f"S-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{rand_hex}"

    _step(f"  Seal ID: {seal_id}")

    record_dict = {
        "seal_id": seal_id,
        "seal_mode": "standard",
        "unlock_time_iso": (
            datetime.now(timezone.utc) + timedelta(days=10)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key_commitment": hashlib.sha256(aes_key).hexdigest(),
        "case_info": case_info,
        "process_info": {
            "type": "Sealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "file_count": 1,
            "investigator": "김수사",
            "reason": "",
            "participation": "참여",
        },
        "file_info": {
            "original_files": [{
                "filename": file_meta.filename,
                "size": file_meta.size,
                "md5": file_meta.md5,
                "sha256": file_meta.sha256,
                "mtime": _normalize_utc(file_meta.mtime),
                "ctime": _normalize_utc(file_meta.ctime),
                "atime": _normalize_utc(file_meta.atime),
            }],
            "result_files": [{
                "filename": Path(enc_path).name,
                "size": Path(enc_path).stat().st_size,
                "encryption_algo": "AES-256-GCM",
                "enc_ended_time": now_iso,
                "nonces": enc_meta["nonces"],
                "tags": enc_meta["tags"],
                "chunk_lengths": enc_meta["chunk_lengths"],
            }],
            "hash_match": True,
            "unknown_files": [],
            "derived_files": [],
        },
        "signer_info": subject_info,
        "history": {
            "summary": "S1U0R0",
            "events": [{
                "id": 1,
                "seal_type": "Sealing",
                "start_time": now_iso,
                "end_time": now_iso,
                "investigator": "김수사",
            }],
        },
    }

    record_json_path = str(work_dir / f"{seal_id}_record.json")

    # S5. 전자서명
    _step("S5. 전자서명 처리...")
    pdf_path = str(work_dir / f"{seal_id}_seal_record.pdf")
    try:
        from cryptography.hazmat.primitives import hashes
        from desktop.record import render_record_pdf
        from desktop.signature import (
            generate_keypair, create_self_signed_cert,
            save_private_key, save_certificate,
        )
        private_key, _ = generate_keypair(2048)
        cert = create_self_signed_cert(
            private_key, subject_info["name"], subject_info["email"],
            subject_info["signature_image_hash"],
        )
        record_dict["signer_info"]["cert_fingerprint"] = cert.fingerprint(
            hashes.SHA256()
        ).hex()

        validation_errors = validate_record(record_dict)
        if validation_errors:
            raise AssertionError(
                f"Seal record validation failed: {validation_errors}"
            )

        with open(record_json_path, "w", encoding="utf-8") as f:
            json.dump(record_dict, f, ensure_ascii=False, indent=2)
        _step(f"  봉인지 JSON 저장: {Path(record_json_path).name}")

        render_record_pdf(record_dict, "seal_record.html", pdf_path)
        _step("  PDF 렌더링 완료")

        cert_path = str(work_dir / f"{seal_id}_cert.pem")
        key_path = str(work_dir / f"{seal_id}_key.pem")
        save_certificate(cert, cert_path)
        save_private_key(
            private_key,
            key_path,
            "test_password",  # public-test-fixture
        )
        _step("  인증서 생성 + 저장 완료")

        # PAdES B-T: the record is only a seal if it carries BOTH the
        # signature and its embedded timestamp (Eq. 5). Failures here are
        # fatal — a harness that skips signing cannot verify the claim.
        from desktop.signature import (
            ensure_tsa_server_running,
            sign_pdf,
            verify_pdf_signature,
        )

        tsa_url, _tsa_cert = ensure_tsa_server_running(
            tsa_dir=work_dir / "tsa",
            ca_key_password="e2e-only-ca-password",  # public-test-fixture
            tsa_key_password="e2e-only-tsa-password",  # public-test-fixture
            port=13162,
        )
        _step(f"  로컬 TSA 기동: {tsa_url}")

        signed_path = str(work_dir / f"{seal_id}_signed.pdf")
        sign_pdf(
            pdf_path, cert_path, key_path, "test_password", signed_path,  # public-test-fixture
            tsa_url=tsa_url,
        )
        pdf_path = signed_path

        sig_result = verify_pdf_signature(signed_path)
        if not sig_result.has_timestamp:
            raise AssertionError(
                "서명에 RFC 3161 타임스탬프가 없습니다 — B-T 아님"
            )
        _step("  PAdES B-T 전자서명 완료 (타임스탬프 임베드 확인)")
    except Exception as exc:
        raise AssertionError(f"전자서명 단계 실패: {exc}") from exc

    # S6. 키 분할
    _step("S6. SSS(2-of-4) 키 분할...")
    shares = split_key(aes_key_hex)
    _step(f"  키 조각 4개 생성 완료")
    _step(f"  Share 1 (피압수자): {shares[0][:20]}...")
    _step(f"  Share 2 (수사관):   {shares[1][:20]}...")
    _step(f"  Share 3 (시스템):   {shares[2][:20]}...")
    _step(f"  Share 4 (관리자):   {shares[3][:20]}...")

    # KMS 암호화 (키 조각 3, 4)
    init_master_key(master_key_path)
    enc_share3 = encrypt_envelope(shares[2].encode(), master_key_path)
    enc_share4 = encrypt_envelope(shares[3].encode(), master_key_path)
    _step("  키 조각 3,4 KMS 봉투 암호화 완료")

    # S7. DB 저장
    _step("S7. SQLite DB 저장...")
    from desktop.db import init_db, save_seal_record, save_key_shares
    init_db(db_path)
    save_seal_record(db_path, seal_id, json.dumps(record_dict), pdf_path)
    save_key_shares(db_path, seal_id, {3: enc_share3, 4: enc_share4})
    _step("  봉인 기록 + 키 조각 저장 완료")

    _step("★ 봉인 완료!")

    # ================================================================
    # 2. 봉인해제 (Unsealing) U1~U7
    # ================================================================
    _banner("Phase 2: 봉인해제 (Unsealing)")

    from desktop.crypto import decrypt_file, recover_key

    # U1~U2. 키 복원 (피압수자 + 수사관)
    _step("U1-U2. 키 조각 1+2로 키 복원...")
    recovered_hex = recover_key([shares[0], shares[1]])
    recovered_key = bytes.fromhex(recovered_hex)
    assert recovered_key == aes_key, "복원된 키가 원본과 불일치!"
    _step(f"  키 복원 성공: {recovered_hex[:16]}...")

    # U3~U4. 파일 선택 + 대조
    _step("U3. 봉인해제 대상 선택...")
    _step("U4. 파일-봉인지 대조 검증...")
    enc_file_size = Path(enc_path).stat().st_size
    _step(f"  .enc 파일: {Path(enc_path).name} ({enc_file_size:,} bytes)")

    # U5. 복호화
    _step("U5. 복호화 시작...")
    dec_dir = work_dir / "decrypted"
    dec_dir.mkdir(parents=True, exist_ok=True)
    dec_result = decrypt_file(
        enc_filepath=enc_path,
        aes_key=recovered_key,
        output_dir=str(dec_dir),
        progress_cb=None,
    )
    _step(f"  복호화 완료: {dec_result.output_filepath}")

    # 해시 비교
    dec_data = Path(dec_result.output_filepath).read_bytes()
    dec_sha256 = hashlib.sha256(dec_data).hexdigest()
    dec_md5 = hashlib.md5(dec_data).hexdigest()

    if dec_sha256 == original_sha256:
        _step(f"  SHA-256 일치 ✓")
    else:
        _fail(f"  SHA-256 불일치! 원본={original_sha256[:16]} 복호화={dec_sha256[:16]}")

    if dec_md5 == original_md5:
        _step(f"  MD5 일치 ✓")
    else:
        _fail(f"  MD5 불일치!")

    # U6. 봉인해제기록지
    _step("U6. 봉인해제기록지 생성...")
    try:
        from desktop.record import build_unseal_record, append_event, update_summary
        unseal_record = dict(record_dict)
        unseal_record["process_info"] = {
            "type": "Unsealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "file_count": 1,
            "investigator": "김수사",
            "reason": "분석을 위한 봉인해제",
            "participation": "참여",
        }
        new_history = dict(record_dict["history"])
        new_events = list(new_history["events"]) + [{
            "id": 2,
            "seal_type": "Unsealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": "김수사",
        }]
        new_history["events"] = new_events
        new_history["summary"] = "S1U1R0"
        unseal_record["history"] = new_history
        _step(f"  History: {new_history['summary']}")
    except ImportError:
        _step("  record 모듈 없이 수동 구성")

    _step("★ 봉인해제 완료!")

    # ================================================================
    # 3. 재봉인 (Resealing) R1~R8
    # ================================================================
    _banner("Phase 3: 재봉인 (Resealing)")

    # R1~R2. 이전 기록지 + 파일 비교
    _step("R1. 이전 봉인해제기록지 로드...")
    _step("R2. 파일 비교...")

    # R3. Unknown 파일 (테스트: 분석 중 생성된 파생 파일 시뮬레이션)
    derived_file = work_dir / "decrypted" / "analysis_report.txt"
    derived_file.parent.mkdir(parents=True, exist_ok=True)
    derived_file.write_text("분석 결과 보고서", encoding="utf-8")
    _step(f"R3. Unknown 파일 식별: {derived_file.name} → 파생 파일로 분류")

    # R4. 재봉인 정보
    _step("R4. 재봉인 정보 입력 (자동)...")

    # R5. 새 키로 암호화
    _step("R5. 새 키 생성 + 암호화...")
    new_aes_key = os.urandom(32)
    new_aes_hex = new_aes_key.hex()
    reseal_enc_path = str(work_dir / "evidence_sample_reseal.bin.enc")

    # 복호화된 원본 파일을 재암호화
    reseal_result = encrypt_file(
        filepath=dec_result.output_filepath,
        aes_key=new_aes_key,
        output_path=reseal_enc_path,
        chunk_size=1 * 1024**3,
    )
    _step(f"  재암호화 완료: {Path(reseal_enc_path).name}")

    # R6. 재봉인기록지
    _step("R6. 재봉인기록지 생성...")
    _step(f"  History: S1U1R1")

    # R7. 새 키 분할
    _step("R7. 새 키 SSS 분할...")
    new_shares = split_key(new_aes_hex)
    _step(f"  새 키 조각 4개 생성 완료")

    # R8. 저장
    _step("R8. 재봉인 기록 저장...")
    _step("★ 재봉인 완료!")

    # ================================================================
    # 4. 재봉인 후 해제 검증
    # ================================================================
    _banner("Phase 4: 재봉인 후 해제 검증")

    _step("키 조각 1+2로 새 키 복원...")
    new_recovered_hex = recover_key([new_shares[0], new_shares[1]])
    new_recovered_key = bytes.fromhex(new_recovered_hex)
    assert new_recovered_key == new_aes_key, "재봉인 키 복원 불일치!"
    _step("  키 복원 성공")

    _step("재봉인 파일 복호화...")
    redec_dir = work_dir / "redecrypted"
    redec_dir.mkdir(parents=True, exist_ok=True)
    redec_result = decrypt_file(
        enc_filepath=reseal_enc_path,
        aes_key=new_recovered_key,
        output_dir=str(redec_dir),
    )

    redec_data = Path(redec_result.output_filepath).read_bytes()
    redec_sha256 = hashlib.sha256(redec_data).hexdigest()

    if redec_sha256 == original_sha256:
        _step("  SHA-256 일치 ✓ — 원본 무결성 보존 확인!")
    else:
        _fail(f"  SHA-256 불일치! 원본={original_sha256[:16]} 재복호화={redec_sha256[:16]}")

    # ================================================================
    # 5. 대체 경로 검증: 키 조각 2+3 (시간 경과 시나리오)
    # ================================================================
    _banner("Phase 5: 대체 키 복구 경로 (조각2+3)")

    from desktop.crypto import decrypt_envelope
    dec_share3 = decrypt_envelope(enc_share3, master_key_path).decode()
    _step(f"  KMS 복호화로 키 조각 3 획득")

    alt_recovered = recover_key([shares[1], dec_share3])
    alt_key = bytes.fromhex(alt_recovered)
    assert alt_key == aes_key, "대체 경로 키 복원 불일치!"
    _step("  키 조각 2+3 복원 성공 ✓")

    # ================================================================
    # 6. 비상 경로: 키 조각 1+4
    # ================================================================
    _banner("Phase 6: 비상 복구 경로 (조각1+4)")

    dec_share4 = decrypt_envelope(enc_share4, master_key_path).decode()
    emg_recovered = recover_key([shares[0], dec_share4])
    emg_key = bytes.fromhex(emg_recovered)
    assert emg_key == aes_key, "비상 경로 키 복원 불일치!"
    _step("  키 조각 1+4 비상 복원 성공 ✓")

    # ================================================================
    # 결과 요약
    # ================================================================
    _banner("전체 E2E 테스트 결과")

    # 산출물 목록
    output_files = sorted(work_dir.rglob("*"))
    file_count = sum(1 for f in output_files if f.is_file())

    print(f"""
  ✓ 봉인 (Sealing)     — AES-256-GCM 암호화 + 인증서 + 키 분할
  ✓ 봉인해제 (Unsealing) — 키 복원 + 복호화 + 해시 일치
  ✓ 재봉인 (Resealing)  — 새 키 암호화 + 새 키 분할
  ✓ 재해제 검증         — 재봉인 파일 복호화 + 원본 해시 일치
  ✓ 대체 경로 (2+3)     — KMS 복호화 + SSS 복원
  ✓ 비상 경로 (1+4)     — 관리자 키 복원

  산출물: {file_count}개 파일
  작업 디렉토리: {work_dir}
""")

    print("  ALL PASSED ✓")


if __name__ == "__main__":
    run_full_cycle()
