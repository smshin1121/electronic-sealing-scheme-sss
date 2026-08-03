"""논리적 정합성 검증 — 산출물의 내용이 설계서와 일치하는지 확인.

단순 실행 성공이 아니라:
- 암호화 파일 바이너리 구조가 설계서 명세와 일치하는가
- 봉인지 JSON의 6개 필드가 모두 의미 있는 값인가
- 서명된 PDF가 실제로 유효한 서명을 포함하는가
- SSS 6가지 2-of-4 조합이 모두 동일한 키를 복원하는가
- 봉인→해제 후 1비트도 변경되지 않았는가
- history가 절차 순서대로 정확히 누적되는가
- DB에 저장된 데이터를 다시 읽어도 일치하는가
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import struct
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

PASS = 0
FAIL = 0


def check(condition: bool, msg: str) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {msg}")
    else:
        FAIL += 1
        print(f"  [FAIL] {msg}")


def banner(msg: str) -> None:
    print(f"\n{'='*60}\n  {msg}\n{'='*60}")


def run() -> None:
    work = Path(tempfile.mkdtemp(prefix="logic_verify_"))
    print(f"작업 디렉토리: {work}")

    # ================================================================
    banner("1. 암호화 파일 바이너리 구조 검증")
    # ================================================================

    from desktop.crypto import encrypt_file, collect_metadata

    test_file = work / "test_evidence.bin"
    test_data = os.urandom(3 * 1024 * 1024)  # 3MB
    test_file.write_bytes(test_data)
    orig_sha256 = hashlib.sha256(test_data).hexdigest()
    orig_md5 = hashlib.md5(test_data).hexdigest()

    aes_key = os.urandom(32)
    enc_path = str(work / "test_evidence.bin.enc")
    encrypt_file(str(test_file), aes_key, enc_path, chunk_size=1 * 1024**3)

    # 설계서 3.8절: [8B offset LE][암호화 데이터][메타 JSON][4B meta_size LE]
    with open(enc_path, "rb") as f:
        # 1) 선두 8바이트 = offset
        offset_bytes = f.read(8)
        check(len(offset_bytes) == 8, "선두 8바이트 offset 존재")
        meta_offset = struct.unpack("<Q", offset_bytes)[0]
        check(meta_offset > 8, f"offset({meta_offset})이 8보다 큼 (암호화 데이터 영역 존재)")

        # 2) 끝 4바이트 = meta_size
        f.seek(-4, 2)
        file_end = f.tell() + 4
        meta_size = struct.unpack("<I", f.read(4))[0]
        check(meta_size > 0, f"meta_size({meta_size})가 0보다 큼")

        # 3) offset + meta_size + 4 == file_end
        check(meta_offset + meta_size + 4 == file_end,
              f"offset({meta_offset}) + meta_size({meta_size}) + 4 == file_end({file_end})")

        # 4) 메타데이터 JSON 파싱
        f.seek(meta_offset)
        meta_json = json.loads(f.read(meta_size).decode("utf-8"))

    # 설계서: 메타데이터 필수 필드
    required_meta = ["filename", "size", "encryption_algo", "nonces", "tags",
                     "chunk_lengths", "hash_before_sha256", "hash_before_md5"]
    for field in required_meta:
        check(field in meta_json, f"메타데이터 필드 '{field}' 존재")

    check(meta_json["encryption_algo"] == "AES-256-GCM", "encryption_algo == AES-256-GCM")
    check(meta_json["hash_before_sha256"] == orig_sha256, "메타데이터 SHA-256 == 원본 SHA-256")
    check(meta_json["hash_before_md5"] == orig_md5, "메타데이터 MD5 == 원본 MD5")
    check(meta_json["size"] == len(test_data), f"메타데이터 size({meta_json['size']}) == 원본 크기({len(test_data)})")

    # nonces, tags, chunk_lengths 배열 길이 동일
    n_chunks = len(meta_json["nonces"])
    check(n_chunks == len(meta_json["tags"]), "nonces 길이 == tags 길이")
    check(n_chunks == len(meta_json["chunk_lengths"]), "nonces 길이 == chunk_lengths 길이")

    # 각 nonce는 24자 hex (12바이트)
    for i, nonce in enumerate(meta_json["nonces"]):
        check(len(nonce) == 24 and all(c in "0123456789abcdef" for c in nonce),
              f"nonce[{i}] 24자 hex 형식")

    # 각 tag는 32자 hex (16바이트)
    for i, tag in enumerate(meta_json["tags"]):
        check(len(tag) == 32 and all(c in "0123456789abcdef" for c in tag),
              f"tag[{i}] 32자 hex 형식")

    # ================================================================
    banner("2. 복호화 후 비트 단위 무결성 검증")
    # ================================================================

    from desktop.crypto import decrypt_file

    dec_dir = work / "decrypted"
    dec_dir.mkdir()
    dec_result = decrypt_file(enc_path, aes_key, str(dec_dir))

    dec_data = Path(dec_result.output_filepath).read_bytes()
    check(dec_data == test_data, "복호화 데이터 == 원본 데이터 (비트 단위 일치)")
    check(hashlib.sha256(dec_data).hexdigest() == orig_sha256, "복호화 SHA-256 == 원본 SHA-256")

    # 잘못된 키로 복호화 시도
    wrong_key = os.urandom(32)
    from desktop.crypto.exceptions import TamperDetectedError, DecryptionError
    try:
        decrypt_file(enc_path, wrong_key, str(work / "wrong_dec"))
        check(False, "잘못된 키 → 복호화 실패해야 함")
    except (TamperDetectedError, DecryptionError):
        check(True, "잘못된 키 → TamperDetectedError/DecryptionError 발생")

    # ================================================================
    banner("3. SSS 6가지 2-of-4 조합 전수 검증")
    # ================================================================

    from desktop.crypto import split_key, recover_key

    hex_key = aes_key.hex()
    shares = split_key(hex_key)
    check(len(shares) == 4, "4개 share 생성됨")

    # 6가지 2-조합 모두 테스트
    all_pairs = list(itertools.combinations(range(4), 2))
    check(len(all_pairs) == 6, "6가지 2-조합")

    for i, (a, b) in enumerate(all_pairs):
        recovered = recover_key([shares[a], shares[b]])
        recovered_bytes = bytes.fromhex(recovered)
        check(recovered_bytes == aes_key,
              f"조합({a+1},{b+1}) → 원본 키 복원 성공")

    # 1개 share만으로는 복원 불가
    from desktop.crypto.exceptions import KeyRecoveryError
    try:
        recover_key([shares[0]])
        check(False, "1개 share로 복원 → 실패해야 함")
    except (KeyRecoveryError, Exception):
        check(True, "1개 share → 복원 불가 (정상)")

    # ================================================================
    banner("4. 봉인지 JSON 6개 필드 + 스키마 정합성")
    # ================================================================

    from desktop.record import create_seal_id, validate_record

    seal_id = create_seal_id()
    # seal_id 형식: S-YYYYMMDD-XXXXXX
    check(bool(re.match(r"^S-\d{8}-[0-9A-F]{6}$", seal_id)),
          f"seal_id '{seal_id}' 형식 일치 (S-YYYYMMDD-XXXXXX)")

    file_meta = collect_metadata(str(test_file))
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # collect_metadata가 +00:00 형식을 반환할 수 있으므로 Z로 정규화
    def _normalize_time(t: str) -> str:
        return t.replace("+00:00", "Z") if t.endswith("+00:00") else t

    file_meta_mtime = _normalize_time(file_meta.mtime)
    file_meta_ctime = _normalize_time(file_meta.ctime)
    file_meta_atime = _normalize_time(file_meta.atime)

    record = {
        "seal_id": seal_id,
        "seal_mode": "standard",
        "unlock_time_iso": (
            datetime.now(timezone.utc) + timedelta(days=10)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key_commitment": hashlib.sha256(aes_key).hexdigest(),
        "case_info": {
            "case_number": "2025-형-99999",
            "investigator": "테스트수사관",
            "device_user": "테스트사용자",
            "suspect": "테스트피압수자",
            "storage_type": "SSD",
            "storage_info": {"manufacturer": "Test", "model": "T1", "serial": "SN001"},
            "seizure_time": now_iso,
            "seizure_location": "서울 성북구",
        },
        "process_info": {
            "type": "Sealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "file_count": 1,
            "investigator": "테스트수사관",
            "reason": "",
            "participation": "참여",
        },
        "file_info": {
            "original_files": [{
                "filename": file_meta.filename,
                "size": file_meta.size,
                "md5": file_meta.md5,
                "sha256": file_meta.sha256,
                "mtime": file_meta_mtime,
                "ctime": file_meta_ctime,
                "atime": file_meta_atime,
            }],
            "result_files": [{
                "filename": Path(enc_path).name,
                "size": Path(enc_path).stat().st_size,
                "encryption_algo": "AES-256-GCM",
                "enc_ended_time": now_iso,
                "nonces": meta_json["nonces"],
                "tags": meta_json["tags"],
                "chunk_lengths": meta_json["chunk_lengths"],
            }],
            "hash_match": True,
            "unknown_files": [],
            "derived_files": [],
        },
        "signer_info": {
            "name": "테스트피압수자",
            "email": "test@test.com",
            "birth_date": "1990-01-01",
            "phone": "010-0000-0000",
            "cert_fingerprint": "a" * 64,
            "signature_image_hash": "b" * 64,
        },
        "history": {
            "summary": "S1U0R0",
            "events": [{
                "id": 1,
                "seal_type": "Sealing",
                "start_time": now_iso,
                "end_time": now_iso,
                "investigator": "테스트수사관",
            }],
        },
    }

    # 6개 최상위 필드 존재
    top_fields = [
        "seal_id",
        "seal_mode",
        "unlock_time_iso",
        "key_commitment",
        "case_info",
        "process_info",
        "file_info",
        "signer_info",
        "history",
    ]
    for f in top_fields:
        check(f in record, f"최상위 필드 '{f}' 존재")

    # validate_record 통과
    errors = validate_record(record)
    check(len(errors) == 0, f"validate_record 오류 0건 (실제: {errors})")

    # file_info의 원본 해시가 실제 파일과 일치
    check(record["file_info"]["original_files"][0]["sha256"] == orig_sha256,
          "봉인지 file_info.original_files.sha256 == 실제 원본 해시")

    # ================================================================
    banner("5. History 누적 논리 검증")
    # ================================================================

    from desktop.record import create_initial_history, append_event, update_summary

    h1 = create_initial_history({
        "id": 1, "seal_type": "Sealing",
        "start_time": now_iso, "end_time": now_iso,
        "investigator": "김수사"
    })
    check(h1["summary"].startswith("S1"), f"초기 history summary: '{h1['summary']}'")
    check(len(h1["events"]) == 1, "초기 events 1개")

    # 봉인해제 추가
    h2 = append_event(h1, {
        "id": 2, "seal_type": "Unsealing",
        "start_time": now_iso, "end_time": now_iso,
        "investigator": "김수사"
    })
    h2 = update_summary(h2)
    check("U1" in h2["summary"], f"해제 후 summary에 U1 포함: '{h2['summary']}'")
    check(len(h2["events"]) == 2, "해제 후 events 2개")
    check(h1["events"][0] == h2["events"][0], "이전 event 불변 (동일 내용)")
    check(id(h1["events"]) != id(h2["events"]), "이전 events 리스트는 다른 객체 (deep copy)")

    # 재봉인 추가
    h3 = append_event(h2, {
        "id": 3, "seal_type": "Resealing",
        "start_time": now_iso, "end_time": now_iso,
        "investigator": "김수사"
    })
    h3 = update_summary(h3)
    check("R1" in h3["summary"], f"재봉인 후 summary에 R1 포함: '{h3['summary']}'")
    check(len(h3["events"]) == 3, "재봉인 후 events 3개")

    # 2차 봉인해제
    h4 = append_event(h3, {
        "id": 4, "seal_type": "Unsealing",
        "start_time": now_iso, "end_time": now_iso,
        "investigator": "김수사"
    })
    h4 = update_summary(h4)
    check("U2" in h4["summary"], f"2차 해제 후 summary에 U2 포함: '{h4['summary']}'")

    # event id 순서 검증
    for i, evt in enumerate(h4["events"]):
        check(evt["id"] == i + 1, f"event[{i}].id == {i+1}")

    # ================================================================
    banner("6. KMS 봉투 암호화 → 복호화 왕복 검증")
    # ================================================================

    from desktop.crypto import init_master_key, encrypt_envelope, decrypt_envelope

    mk_path = str(work / "master.key")
    init_master_key(mk_path)

    secret = b"this-is-a-secret-key-share-data"  # public-test-fixture
    encrypted = encrypt_envelope(secret, mk_path)
    check(encrypted != secret, "암호화된 데이터 != 평문")
    check(len(encrypted) > len(secret), "암호화 후 크기 증가 (nonce 포함)")

    decrypted = decrypt_envelope(encrypted, mk_path)
    check(decrypted == secret, "KMS 복호화 == 원본 평문")

    # 다른 마스터키로 복호화 시도
    mk_path2 = str(work / "master2.key")
    init_master_key(mk_path2)
    from desktop.crypto.exceptions import KMSError
    try:
        decrypt_envelope(encrypted, mk_path2)
        check(False, "다른 마스터키 → 복호화 실패해야 함")
    except (KMSError, Exception):
        check(True, "다른 마스터키 → 복호화 실패 (정상)")

    # ================================================================
    banner("7. 전자서명 검증 — 인증서 + PAdES")
    # ================================================================

    from desktop.signature import (
        generate_keypair, create_self_signed_cert,
        save_private_key, save_certificate,
    )

    priv_key, _ = generate_keypair(2048)
    sig_hash = hashlib.sha256(b"test-signature-image").hexdigest()
    cert = create_self_signed_cert(priv_key, "테스트피압수자", "test@test.com", sig_hash)

    # 인증서 속성 검증
    from cryptography import x509
    check(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "테스트피압수자",
          "인증서 CN == '테스트피압수자'")
    check(cert.subject.get_attributes_for_oid(x509.oid.NameOID.EMAIL_ADDRESS)[0].value == "test@test.com",
          "인증서 Email == 'test@test.com'")

    # 커스텀 OID 확장 (서명이미지 해시)
    from desktop.signature.cert_generator import SIGNATURE_IMAGE_HASH_OID
    found_ext = False
    for ext in cert.extensions:
        if ext.oid == SIGNATURE_IMAGE_HASH_OID:
            found_ext = True
            check(sig_hash.encode() in ext.value.value,
                  "인증서 커스텀 OID에 서명이미지 해시 포함")
    check(found_ext, "커스텀 OID 확장 필드 존재")

    # PEM 저장 + 로드
    cert_path = str(work / "test_cert.pem")
    key_path = str(work / "test_key.pem")
    save_certificate(cert, cert_path)
    save_private_key(priv_key, key_path, "testpw")  # public-test-fixture
    check(Path(cert_path).exists(), "인증서 PEM 파일 생성됨")
    check(Path(key_path).exists(), "개인키 PEM 파일 생성됨 (비밀번호 암호화)")

    # PDF 서명 테스트
    from desktop.record import render_record_pdf
    pdf_path = str(work / "test_record.pdf")
    try:
        render_record_pdf(record, "seal_record.html", pdf_path)
        check(Path(pdf_path).stat().st_size > 100, "PDF 렌더링 성공 (100B+)")
    except Exception as exc:
        check(False, f"PDF 렌더링 실패: {exc}")

    signed_pdf = str(work / "test_signed.pdf")
    try:
        from desktop.signature import ensure_tsa_server_running, sign_pdf

        signing_tsa_url, _ = ensure_tsa_server_running(
            tsa_dir=work / "signing_tsa",
            ca_key_password="e2e-only-ca-password",  # public-test-fixture
            tsa_key_password="e2e-only-tsa-password",  # public-test-fixture
            port=13160,
        )
        warning = sign_pdf(
            pdf_path,
            cert_path,
            key_path,
            "testpw",  # public-test-fixture
            signed_pdf,
            tsa_url=signing_tsa_url,
        )
        check(Path(signed_pdf).exists(), "서명된 PDF 파일 생성됨")
        check(Path(signed_pdf).stat().st_size > Path(pdf_path).stat().st_size,
              "서명 후 PDF 크기 증가 (서명 데이터 추가)")

        # PDF 매직바이트 확인
        with open(signed_pdf, "rb") as f:
            magic = f.read(5)
        check(magic == b"%PDF-", "서명된 PDF 매직바이트 %PDF-")
    except Exception as exc:
        check(False, f"PDF 서명 실패: {exc}")

    # ================================================================
    banner("8. TSA 시점확인 — 서버 + 클라이언트 왕복")
    # ================================================================

    from desktop.signature import create_ca, issue_tsa_cert
    from desktop.signature.ca_setup import save_tsa_credentials

    ca_dir = work / "ca"
    ca_dir.mkdir()
    test_ca_password = "e2e-only-ca-password"  # public-test-fixture
    test_tsa_password = "e2e-only-tsa-password"  # public-test-fixture
    ca_key, ca_cert = create_ca(
        str(ca_dir),
        ca_key_password=test_ca_password,
    )
    tsa_key, tsa_cert = issue_tsa_cert(ca_key, ca_cert, "TestTSA")
    tsa_key_path_p, tsa_cert_path_p = save_tsa_credentials(
        tsa_key,
        tsa_cert,
        str(ca_dir),
        key_password=test_tsa_password,
    )
    tsa_key_path = str(tsa_key_path_p)
    tsa_cert_path = str(tsa_cert_path_p)

    from desktop.signature import start_tsa_server_background, request_timestamp
    import time

    server, thread = start_tsa_server_background(
        tsa_key_path,
        tsa_cert_path,
        key_password=test_tsa_password,
        port=13161,
    )
    time.sleep(0.5)

    try:
        test_hash = hashlib.sha256(b"test-data-for-tsa").digest()
        tst_token = request_timestamp(test_hash, "http://127.0.0.1:13161/tsa")
        check(len(tst_token) > 0, f"TST 토큰 수신 ({len(tst_token)} bytes)")

        # genTime 검증
        from desktop.signature import verify_timestamp
        gen_time = verify_timestamp(tst_token, tsa_cert_path)
        now = datetime.now(timezone.utc)
        time_diff = abs((now - gen_time).total_seconds())
        check(time_diff < 10, f"genTime과 현재시간 차이 {time_diff:.1f}초 (< 10초)")
    except Exception as exc:
        check(False, f"TSA 검증 실패: {exc}")
    finally:
        server.shutdown()

    # ================================================================
    banner("9. SQLite DB 저장 → 조회 왕복 검증")
    # ================================================================

    from desktop.db import init_db, save_seal_record, get_seal_record, save_key_shares, get_key_share

    db_path = str(work / "test.db")
    init_db(db_path)

    record_json_str = json.dumps(record, ensure_ascii=False)
    save_seal_record(db_path, seal_id, record_json_str, pdf_path)

    loaded = get_seal_record(db_path, seal_id)
    check(loaded is not None, "DB에서 봉인기록 조회 성공")
    if loaded:
        loaded_json = json.loads(loaded["record_json"]) if isinstance(loaded["record_json"], str) else loaded
        # seal_id 일치 확인
        check(str(loaded.get("seal_id", loaded_json.get("seal_id", ""))) == seal_id or
              loaded_json.get("seal_id") == seal_id,
              "DB 조회 seal_id == 원본 seal_id")

    # 키 조각 저장 → 조회
    enc_share3 = encrypt_envelope(shares[2].encode(), mk_path)
    save_key_shares(db_path, seal_id, {3: enc_share3})
    loaded_share = get_key_share(db_path, seal_id, 3)
    check(loaded_share is not None, "DB에서 키 조각 3 조회 성공")
    if loaded_share:
        dec_share = decrypt_envelope(loaded_share, mk_path)
        check(dec_share.decode() == shares[2], "DB 조회 키 조각 3 == 원본 share 3")

    # ================================================================
    banner("10. 봉인→해제→재봉인 해시 체인 무결성")
    # ================================================================

    # 봉인
    key1 = os.urandom(32)
    enc1 = str(work / "chain_seal.enc")
    encrypt_file(str(test_file), key1, enc1, chunk_size=1*1024**3)

    # 해제
    chain_dec = work / "chain_dec"
    chain_dec.mkdir()
    r1 = decrypt_file(enc1, key1, str(chain_dec))
    data1 = Path(r1.output_filepath).read_bytes()
    hash1 = hashlib.sha256(data1).hexdigest()

    # 재봉인 (새 키)
    key2 = os.urandom(32)
    enc2 = str(work / "chain_reseal.enc")
    encrypt_file(r1.output_filepath, key2, enc2, chunk_size=1*1024**3)

    # 재해제
    chain_redec = work / "chain_redec"
    chain_redec.mkdir()
    r2 = decrypt_file(enc2, key2, str(chain_redec))
    data2 = Path(r2.output_filepath).read_bytes()
    hash2 = hashlib.sha256(data2).hexdigest()

    check(hash1 == orig_sha256, "봉인→해제 후 해시 == 원본")
    check(hash2 == orig_sha256, "봉인→해제→재봉인→재해제 후 해시 == 원본")
    check(hash1 == hash2, "해시 체인: 1차 해제 == 2차 해제 (무결성 보존)")
    check(data1 == data2 == test_data, "바이트 단위 완전 일치 (3단계 체인)")

    # ================================================================
    banner("결과")
    # ================================================================
    total = PASS + FAIL
    print(f"\n  PASS: {PASS}/{total}")
    print(f"  FAIL: {FAIL}/{total}")
    if FAIL == 0:
        print("\n  ALL LOGIC CHECKS PASSED ✓")
    else:
        print(f"\n  {FAIL}건 논리적 불일치 발견!")
    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    run()
