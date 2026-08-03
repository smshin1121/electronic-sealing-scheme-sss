"""Unseal process orchestration (U3 through U7).

Coordinates the full unsealing workflow by calling into the crypto,
record, and db modules.  Each step produces results that feed into
the next.  On error the current state is preserved so the user
can retry from the failing step.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Immutable result containers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UnsealConfig:
    """Immutable configuration collected from wizard step U3."""

    enc_filepath: str
    seal_record_path: str
    aes_key_hex: str
    output_dir: str
    reason: str
    investigator: str
    subject_participated: bool


@dataclass(frozen=True)
class VerificationItem:
    """Single file verification result from U4."""

    filename: str
    expected_size: int
    expected_sha256: str
    actual_size: int
    actual_sha256: str
    matched: bool


@dataclass(frozen=True)
class UnsealResult:
    """Immutable result of the complete unseal process."""

    seal_id: str
    output_filepath: str
    hash_verified: bool
    sha256_match: bool
    md5_match: bool
    pdf_path: str
    record_json: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

AES_KEY_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_aes_key_hex(key_hex: str) -> bool:
    """Return True if the string is a valid 256-bit hex key."""
    return bool(AES_KEY_HEX_PATTERN.match(key_hex.strip()))


def _compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Unseal process orchestrator
# ---------------------------------------------------------------------------

class UnsealProcess:
    """Orchestrates the unsealing workflow steps U3 through U7.

    Driven by the UnsealWizard GUI.  Each ``run_uN`` method executes
    the corresponding step and returns a result dict.
    """

    def __init__(self, *, db_path: str) -> None:
        self._db_path = db_path
        self.config: Optional[UnsealConfig] = None
        self.state: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # U3: Input validation
    # ------------------------------------------------------------------

    def set_config(self, config: UnsealConfig) -> None:
        """Store configuration collected from U3."""
        self.config = config

    def run_u3_validate(self) -> dict[str, Any]:
        """Validate inputs from U3.

        Returns dict with keys: seal_record (parsed), valid.
        Raises ValueError on invalid input.
        """
        if self.config is None:
            raise RuntimeError("config가 설정되지 않았습니다.")

        # Validate file existence
        enc_path = Path(self.config.enc_filepath)
        if not enc_path.exists():
            raise ValueError(f"암호화 파일이 존재하지 않습니다: {enc_path}")

        record_path = Path(self.config.seal_record_path)
        if not record_path.exists():
            raise ValueError(f"봉인지 파일이 존재하지 않습니다: {record_path}")

        # Validate AES key format
        if not _validate_aes_key_hex(self.config.aes_key_hex):
            raise ValueError(
                "AES 키는 64자리 16진수 문자열이어야 합니다."
            )

        # Parse seal record JSON
        try:
            with open(record_path, "r", encoding="utf-8") as f:
                seal_record = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"봉인지 JSON 파싱 오류: {exc}") from exc

        # Basic seal_id check
        seal_id = seal_record.get("seal_id", "")
        if not seal_id:
            raise ValueError("봉인지에 seal_id가 없습니다.")

        step_result = {
            "seal_record": seal_record,
            "seal_id": seal_id,
            "valid": True,
        }
        self.state["u3"] = step_result
        logger.info("U3 검증 완료: seal_id=%s", seal_id)
        return step_result

    # ------------------------------------------------------------------
    # U4: File-seal record cross verification
    # ------------------------------------------------------------------

    def run_u4_verify(self) -> dict[str, Any]:
        """Cross-verify the .enc file against the seal record.

        Returns dict with keys: items (list[VerificationItem]),
        all_matched (bool).
        """
        if "u3" not in self.state:
            raise RuntimeError("U3가 완료되지 않았습니다.")

        seal_record = self.state["u3"]["seal_record"]
        enc_filepath = self.config.enc_filepath  # type: ignore[union-attr]

        items: list[VerificationItem] = []

        # Extract expected info from seal record. The canonical record
        # schema (build_seal_record) nests these under
        # file_info.original_files / file_info.result_files; fall back to
        # the legacy flat keys for older records.
        file_info = seal_record.get("file_info", {})
        original_files = file_info.get("original_files") or []
        original_file = (
            original_files[0]
            if original_files
            else seal_record.get("original_file", {})
        )
        encryption_info = seal_record.get("encryption", {})

        expected_filename = original_file.get("filename", "")
        expected_size = original_file.get("size", 0)
        expected_sha256 = original_file.get("sha256", "")

        # Get actual .enc file info. The seal record stores no hash for
        # the .enc container itself, so computing its SHA-256 here would
        # be a full read with nothing to compare against — skip it and
        # keep the filename-based cross check.
        enc_path = Path(enc_filepath)
        actual_size = enc_path.stat().st_size
        actual_sha256 = ""

        # Check enc filename recorded in seal record (canonical schema:
        # file_info.result_files[0].filename; legacy: encryption.enc_filepath)
        result_files = file_info.get("result_files") or []
        recorded_enc = (
            result_files[0].get("filename", "")
            if result_files
            else encryption_info.get("enc_filepath", "")
        )
        recorded_enc_name = Path(recorded_enc).name if recorded_enc else ""
        actual_enc_name = enc_path.name

        name_match = (
            recorded_enc_name == actual_enc_name
            if recorded_enc_name
            else True
        )

        items.append(
            VerificationItem(
                filename=actual_enc_name,
                expected_size=0,  # enc file size varies
                expected_sha256="",  # enc file hash differs from original
                actual_size=actual_size,
                actual_sha256=actual_sha256,
                matched=name_match,
            )
        )

        # Verify original file metadata is present in seal record
        has_metadata = bool(expected_filename and expected_sha256)
        items.append(
            VerificationItem(
                filename=f"원본: {expected_filename}",
                expected_size=expected_size,
                expected_sha256=expected_sha256,
                actual_size=0,
                actual_sha256="(복호화 후 검증)",
                matched=has_metadata,
            )
        )

        all_matched = all(item.matched for item in items)

        step_result = {
            "items": items,
            "all_matched": all_matched,
            "seal_id": self.state["u3"]["seal_id"],
        }
        self.state["u4"] = step_result
        logger.info("U4 대조 완료: all_matched=%s", all_matched)
        return step_result

    # ------------------------------------------------------------------
    # U5: Decryption
    # ------------------------------------------------------------------

    def run_u5_decrypt(
        self,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> dict[str, Any]:
        """Decrypt the .enc file and verify hashes.

        Returns dict with keys: output_filepath, hash_verified,
        sha256_match, md5_match, metadata.
        """
        if "u4" not in self.state or self.config is None:
            raise RuntimeError("U4가 완료되지 않았습니다.")

        from .crypto import decrypt_file

        aes_key = bytes.fromhex(self.config.aes_key_hex.strip())
        output_dir = self.config.output_dir

        # Compare against the selected sealing-record JSON rather than only
        # the container's self-declared hashes. This binds the plaintext to an
        # independently selected whole-file reference, but this path does not
        # authenticate the JSON against the signed PDF; reference authenticity
        # remains a caller and custody-procedure boundary.
        # Canonical schema nests these under file_info.original_files; fall
        # back to the legacy flat key for older records.
        seal_record = self.state["u3"]["seal_record"]
        file_info = seal_record.get("file_info", {})
        original_files = file_info.get("original_files") or []
        original_file = (
            original_files[0]
            if original_files
            else seal_record.get("original_file", {})
        )
        expected_sha256 = original_file.get("sha256") or None
        expected_md5 = original_file.get("md5") or None

        result = decrypt_file(
            enc_filepath=self.config.enc_filepath,
            aes_key=aes_key,
            output_dir=output_dir,
            progress_cb=progress_cb,
            expected_sha256=expected_sha256,
            expected_md5=expected_md5,
        )

        step_result = {
            "output_filepath": result.output_filepath,
            "original_filename": result.original_filename,
            "hash_verified": result.hash_verified,
            "sha256_match": result.sha256_match,
            "md5_match": result.md5_match,
            "metadata": result.metadata,
        }
        self.state["u5"] = step_result
        logger.info(
            "U5 복호화 완료: %s, hash_verified=%s",
            result.output_filepath,
            result.hash_verified,
        )
        return step_result

    # ------------------------------------------------------------------
    # U6: Unseal record generation
    # ------------------------------------------------------------------

    def run_u6_record(self) -> dict[str, Any]:
        """Generate the unseal record JSON and PDF.

        Returns dict with keys: record_dict, record_json_path, pdf_path.
        """
        if "u5" not in self.state or self.config is None:
            raise RuntimeError("U5가 완료되지 않았습니다.")

        seal_record = self.state["u3"]["seal_record"]
        seal_id = self.state["u3"]["seal_id"]
        now = datetime.now(tz=timezone.utc)
        output_dir = Path(self.config.output_dir)

        # Build unseal record
        record_dict: dict[str, Any] = {}
        try:
            from .record import append_event, build_unseal_record

            process_info = {
                "type": "Unsealing",
                "reason": self.config.reason,
                "investigator": self.config.investigator,
                "subject_participated": self.config.subject_participated,
                "start_time": now.isoformat(),
                "end_time": now.isoformat(),
            }
            file_info = {
                # Carry the original file metadata forward so the next
                # process (reseal R2 known-file matching, U4 verification)
                # can cross-check hashes against this record.
                "original_files": (
                    seal_record.get("file_info", {}).get("original_files", [])
                ),
                "output_filepath": self.state["u5"]["output_filepath"],
                "hash_verified": self.state["u5"]["hash_verified"],
                "sha256_match": self.state["u5"]["sha256_match"],
                "md5_match": self.state["u5"]["md5_match"],
                "metadata": self.state["u5"]["metadata"],
            }

            # build_unseal_record inherits history as-is — the caller must
            # append the unseal event first so summary becomes e.g. S1U1R0.
            prev_for_build = seal_record
            try:
                prev_history = seal_record.get("history") or {}
                new_history = append_event(prev_history, {
                    "seal_type": "Unsealing",
                    "start_time": now.isoformat(),
                    "end_time": now.isoformat(),
                    "investigator": self.config.investigator,
                })
                prev_for_build = {**seal_record, "history": new_history}
            except Exception as exc:
                logger.warning("history 이벤트 추가 실패 (이전 이력 유지): %s", exc)

            record_dict = build_unseal_record(
                prev_record=prev_for_build,
                process_info=process_info,
                file_info=file_info,
            )
        except ImportError:
            logger.warning("record 모듈 미구현 - 직접 기록 구성")
            # Fallback: build manually
            history = seal_record.get("history", [])
            new_event = {
                "event": "unseal",
                "timestamp": now.isoformat(),
                "actor": self.config.investigator,
                "reason": self.config.reason,
            }
            new_history = list(history) + [new_event]

            record_dict = {
                "seal_id": seal_id,
                "type": "unseal",
                "version": "1.0",
                "created_at": now.isoformat(),
                "case_number": seal_record.get("case_number", ""),
                "investigator": seal_record.get("investigator", {}),
                "unseal_info": {
                    "reason": self.config.reason,
                    "investigator": self.config.investigator,
                    "subject_participated": self.config.subject_participated,
                },
                "decryption": {
                    "output_filepath": self.state["u5"]["output_filepath"],
                    "hash_verified": self.state["u5"]["hash_verified"],
                    "sha256_match": self.state["u5"]["sha256_match"],
                    "md5_match": self.state["u5"]["md5_match"],
                },
                "original_file": seal_record.get("original_file", {}),
                "history": new_history,
                "summary": _compute_summary(new_history),
            }

        # Save JSON
        record_json_path = str(output_dir / f"{seal_id}_unseal_record.json")
        with open(record_json_path, "w", encoding="utf-8") as f:
            json.dump(record_dict, f, ensure_ascii=False, indent=2)

        # Render PDF
        pdf_path = str(output_dir / f"{seal_id}_unseal_record.pdf")
        try:
            from .record import render_record_pdf

            render_record_pdf(
                record=record_dict,
                template_name="unseal_record.html",
                output_path=pdf_path,
            )
        except ImportError:
            logger.warning("PDF 렌더링 모듈 미구현 - 경로만 기록")
            Path(pdf_path).write_text(
                f"[Placeholder] Unseal Record PDF for {seal_id}",
                encoding="utf-8",
            )

        step_result = {
            "record_dict": record_dict,
            "record_json_path": record_json_path,
            "pdf_path": pdf_path,
        }
        self.state["u6"] = step_result
        logger.info("U6 기록 생성 완료: %s", record_json_path)
        return step_result

    # ------------------------------------------------------------------
    # U7: Save records
    # ------------------------------------------------------------------

    def run_u7_save(self) -> UnsealResult:
        """Persist unseal record to DB and optionally upload.

        Returns an UnsealResult with the complete outcome.
        """
        required = ["u3", "u4", "u5", "u6"]
        for step in required:
            if step not in self.state:
                raise RuntimeError(f"{step.upper()}가 완료되지 않았습니다.")

        from .db import save_seal_record

        seal_id = self.state["u3"]["seal_id"]
        record_dict = self.state["u6"]["record_dict"]
        record_json = json.dumps(record_dict, ensure_ascii=False, indent=2)
        pdf_path = self.state["u6"]["pdf_path"]

        save_seal_record(self._db_path, seal_id, record_json, pdf_path)

        # Optional: remote upload
        try:
            self._upload_record(seal_id, record_json, pdf_path)
        except Exception as exc:
            logger.warning("원격 업로드 실패 (스킵): %s", exc)

        result = UnsealResult(
            seal_id=seal_id,
            output_filepath=self.state["u5"]["output_filepath"],
            hash_verified=self.state["u5"]["hash_verified"],
            sha256_match=self.state["u5"]["sha256_match"],
            md5_match=self.state["u5"]["md5_match"],
            pdf_path=pdf_path,
            record_json=record_json,
        )
        self.state["u7"] = {"unseal_result": result}
        logger.info("U7 완료: seal_id=%s, 모든 기록 저장", seal_id)
        return result

    def _upload_record(
        self, seal_id: str, record_json: str, pdf_path: str
    ) -> None:
        """Upload record to the remote participation system (optional)."""
        # Placeholder for future web integration
        logger.info("원격 업로드 미구현 (seal_id=%s)", seal_id)


def _compute_summary(history: list[dict[str, Any]]) -> str:
    """Compute S{n}U{n}R{n} summary from history events."""
    seal_count = sum(1 for e in history if e.get("event") == "seal")
    unseal_count = sum(1 for e in history if e.get("event") == "unseal")
    reseal_count = sum(1 for e in history if e.get("event") == "reseal")
    return f"S{seal_count}U{unseal_count}R{reseal_count}"


def run_unseal_in_background(
    process: UnsealProcess,
    wizard_data: dict[str, Any],
    *,
    db_path: str,
    on_step: Optional[Callable[[str, str], None]] = None,
    on_complete: Optional[Callable[[UnsealResult], None]] = None,
    on_error: Optional[Callable[[str, Exception], None]] = None,
) -> threading.Thread:
    """Run the full unseal process on a background thread.

    Args:
        process: The UnsealProcess instance.
        wizard_data: Data collected from the unseal wizard.
        db_path: SQLite database path.
        on_step: Callback ``(step_name, message)`` for progress updates.
        on_complete: Callback with the final UnsealResult.
        on_error: Callback ``(step_name, exception)`` on failure.

    Returns:
        The started daemon thread.
    """

    def _notify(step: str, msg: str) -> None:
        if on_step:
            on_step(step, msg)

    def _run() -> None:
        try:
            config = UnsealConfig(
                enc_filepath=wizard_data["enc_filepath"],
                seal_record_path=wizard_data["seal_record_path"],
                aes_key_hex=wizard_data["aes_key_hex"],
                output_dir=wizard_data["output_dir"],
                reason=wizard_data.get("reason", ""),
                investigator=wizard_data.get("investigator", ""),
                subject_participated=wizard_data.get(
                    "subject_participated", False
                ),
            )
            process.set_config(config)

            _notify("U3", "입력 검증 중...")
            process.run_u3_validate()

            _notify("U4", "파일-봉인지 대조 중...")
            process.run_u4_verify()

            _notify("U5", "복호화 진행 중...")
            process.run_u5_decrypt()

            _notify("U6", "봉인해제기록지 생성 중...")
            process.run_u6_record()

            _notify("U7", "기록 저장 중...")
            result = process.run_u7_save()

            if on_complete:
                on_complete(result)

        except Exception as exc:
            logger.exception("봉인해제 프로세스 오류")
            if on_error:
                on_error("unknown", exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
