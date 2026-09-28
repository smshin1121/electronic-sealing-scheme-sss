"""Reseal process orchestration (R1 through R8).

Coordinates the full resealing workflow by calling into the crypto,
record, and db modules.  Each step produces results that feed into
the next.  On error the current state is preserved so the user
can retry from the failing step.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .reseal_classify import _fallback_classify
from .seal_mode_guard import (
    require_policy_for_strict,
    require_safe_seal_id,
    check_reseal_lineage,
    resolve_reseal_mode,
    split_mode,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Immutable result containers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResealConfig:
    """Immutable configuration collected from wizard steps."""

    source_dir: str
    output_dir: str
    chunk_size_bytes: int
    investigator: str
    reason: str
    subject_participated: bool
    # Days until the new time-locked share may be released. Fixed before
    # R6 builds and signs the record so the policy is signature-covered.
    unlock_days: int = 10


@dataclass(frozen=True)
class UnknownFileInfo:
    """Classification result for a single unknown file."""

    filepath: str
    filename: str
    size: int
    sha256: str
    suggested_category: str
    classification: str  # "derived" | "excluded"
    parent_file: str  # original file for derived files
    derivation_reason: str  # reason for derivation


@dataclass(frozen=True)
class ResealResult:
    """Immutable result of the complete reseal process."""

    seal_id: str
    enc_filepath: str
    pdf_path: str
    key_shares: tuple[str, str, str, str]
    unlock_time_iso: str
    record_json: str
    # Base64 envelope ciphertext of the NEW s3 bound to the new signed
    # policy (sync field ``wrapped_s3``); None for a legacy record.
    wrapped_s3_b64: Optional[str] = None


# ---------------------------------------------------------------------------
# Reseal process orchestrator
# ---------------------------------------------------------------------------

class ResealProcess:
    """Orchestrates the resealing workflow steps R1 through R8.

    Driven by the ResealWizard GUI.  Each ``run_rN`` method executes
    the corresponding step and returns a result dict.
    """

    def __init__(
        self,
        *,
        db_path: str,
        policy_signer: Optional[Any] = None,
    ) -> None:
        """Create a resealing process.

        Args:
            db_path: Desktop SQLite database path.
            policy_signer: Institutional seal-policy signer; when ``None``
                it is resolved from the environment at R6 (legacy record
                with a warning if none is configured).
        """
        self._db_path = db_path
        self._policy_signer = policy_signer
        self.config: Optional[ResealConfig] = None
        self.state: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # R1: Load previous record
    # ------------------------------------------------------------------

    def run_r1_load(self, record_path: str) -> dict[str, Any]:
        """Load and validate the previous unseal record JSON.

        The seal mode the reseal must keep is read from the record and
        refused when unknown, when it differs from the record's signed
        policy, or when it differs from the record this desktop stored for
        the seal (a stripped or edited mode never downgrades strict). The
        record must also be that stored record or a later one: its history
        must start with the stored history (stage E, E2f), so a reseal from
        an older record stops here, before R2 to R7 run.

        Returns dict with keys: prev_record, seal_id, record_path, seal_mode.
        """
        path = Path(record_path)
        if not path.exists():
            raise ValueError(f"기록지 파일이 존재하지 않습니다: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                prev_record = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON 파싱 오류: {exc}") from exc

        seal_id = prev_record.get("seal_id", "")
        if not seal_id:
            raise ValueError("기록지에 seal_id가 없습니다.")
        # R6 builds output file names from it (no path in a seal_id).
        require_safe_seal_id(seal_id, "기록지")
        mode, mode_source = resolve_reseal_mode(self._db_path, prev_record)
        check_reseal_lineage(self._db_path, prev_record)

        step_result = {
            "prev_record": prev_record,
            "seal_id": seal_id,
            "record_path": record_path,
            "seal_mode": mode,
            # What confirmed the mode: "stored", "policy", or None (file only).
            "mode_source": mode_source,
        }
        self.state["r1"] = step_result
        logger.info("R1 기록지 로드 완료: seal_id=%s mode=%s", seal_id, mode)
        return step_result

    # ------------------------------------------------------------------
    # R2: File comparison / Unknown identification
    # ------------------------------------------------------------------

    def run_r2_compare(self, target_dir: str) -> dict[str, Any]:
        """Compare files in target_dir against the previous record.

        Returns dict with keys: known_files, unknown_files.
        """
        if "r1" not in self.state:
            raise RuntimeError("R1이 완료되지 않았습니다.")

        prev_record = self.state["r1"]["prev_record"]

        known_files: list[dict[str, Any]] = []
        unknown_files: list[dict[str, Any]] = []

        try:
            from .record import identify_unknown_files

            known_files, unknown_files = identify_unknown_files(
                prev_record=prev_record,
                current_dir=target_dir,
            )
        except ImportError:
            logger.warning("unknown_classifier 미구현 - 직접 비교")
            known_files, unknown_files = _fallback_classify(
                prev_record, target_dir
            )

        step_result = {
            "known_files": known_files,
            "unknown_files": unknown_files,
            "target_dir": target_dir,
        }
        self.state["r2"] = step_result
        logger.info(
            "R2 파일 비교 완료: known=%d, unknown=%d",
            len(known_files),
            len(unknown_files),
        )
        return step_result

    # ------------------------------------------------------------------
    # R3: Unknown file classification results
    # ------------------------------------------------------------------

    def set_r3_classifications(
        self, classifications: list[UnknownFileInfo]
    ) -> dict[str, Any]:
        """Store the user's classification of unknown files.

        Args:
            classifications: List of classified unknown files.

        Returns dict with keys: derived_files, excluded_files.
        """
        derived = [c for c in classifications if c.classification == "derived"]
        excluded = [
            c for c in classifications if c.classification == "excluded"
        ]

        step_result = {
            "classifications": classifications,
            "derived_files": [
                {
                    "filepath": c.filepath,
                    "filename": c.filename,
                    "sha256": c.sha256,
                    "parent_file": c.parent_file,
                    "derivation_reason": c.derivation_reason,
                }
                for c in derived
            ],
            "excluded_files": [
                {
                    "filepath": c.filepath,
                    "filename": c.filename,
                    "sha256": c.sha256,
                }
                for c in excluded
            ],
        }
        self.state["r3"] = step_result
        logger.info(
            "R3 분류 완료: derived=%d, excluded=%d",
            len(derived),
            len(excluded),
        )
        return step_result

    # ------------------------------------------------------------------
    # R4: Reseal info collection
    # ------------------------------------------------------------------

    def set_config(self, config: ResealConfig) -> None:
        """Store configuration collected from R4."""
        self.config = config

    # ------------------------------------------------------------------
    # R5: Encryption
    # ------------------------------------------------------------------

    def run_r5_encrypt(
        self,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> dict[str, Any]:
        """Encrypt files for resealing.

        Returns dict with keys: aes_key_hex, enc_filepath, metadata,
        chunk_count.
        """
        if self.config is None:
            raise RuntimeError("config가 설정되지 않았습니다 (R4).")
        if "r2" not in self.state:
            raise RuntimeError("R2가 완료되지 않았습니다.")

        from .crypto import MAX_CHUNK_SIZE, encrypt_file

        # Determine which files to encrypt
        # For simplicity, encrypt the source directory as a unit
        # In practice, files would be packed/archived first
        source_dir = self.state["r2"]["target_dir"]
        output_dir = self.config.output_dir

        # AES 키: 같은 세션 재시도(취소/오류 후 재실행) 시 기존 키를
        # 재사용한다. 새 키를 만들면 .enc.progress 기반 resume이 이전 키
        # 청크에 새 키 청크를 이어붙여 영구 복호화 불가가 되기 때문
        # (crypto 계층의 키 지문 가드와 2중 방어).
        aes_key_hex = self.state.get("r5_aes_key_hex")
        if aes_key_hex is None:
            aes_key_hex = os.urandom(32).hex()
            self.state["r5_aes_key_hex"] = aes_key_hex
        aes_key = bytes.fromhex(aes_key_hex)

        # Find the primary file to encrypt
        # Use the first known file or the directory itself
        known_files = self.state["r2"].get("known_files", [])
        derived_files = self.state.get("r3", {}).get("derived_files", [])

        # Collect all files to include
        files_to_encrypt: list[str] = []
        for kf in known_files:
            fp = kf.get("filepath", "")
            if fp and Path(fp).exists():
                files_to_encrypt.append(fp)
        for df in derived_files:
            fp = df.get("filepath", "")
            if fp and Path(fp).exists():
                files_to_encrypt.append(fp)

        enc_results: list[dict[str, Any]] = []
        total_files = len(files_to_encrypt)
        chunk_bytes = min(self.config.chunk_size_bytes, MAX_CHUNK_SIZE)

        # 취소/중단 후 위자드가 완료 없이 destroy될 때 부분 산출물을
        # 정리할 수 있도록 생성 예정 경로를 미리 기록한다.
        pending_paths: list[str] = []
        self.state["r5_pending_enc_paths"] = pending_paths

        for idx, filepath in enumerate(files_to_encrypt):
            src_name = Path(filepath).stem
            enc_filename = f"{src_name}.enc"
            enc_path = str(Path(output_dir) / enc_filename)
            pending_paths.append(enc_path)

            def _wrapped_cb(current: int, total: int) -> None:
                if progress_cb:
                    # Scale progress across all files
                    overall = idx * 100 + int((current / max(total, 1)) * 100)
                    overall_total = total_files * 100
                    progress_cb(overall, overall_total)

            # MD5/SHA-256 metadata is computed inline during the
            # encryption read (single pass over the source file).
            result = encrypt_file(
                filepath=filepath,
                aes_key=aes_key,
                output_path=enc_path,
                chunk_size=chunk_bytes,
                progress_cb=_wrapped_cb,
            )
            metadata = result.metadata

            enc_results.append(
                {
                    "enc_filepath": result.enc_filepath,
                    "original_filepath": filepath,
                    "metadata": {
                        "filename": metadata.filename,
                        "size": metadata.size,
                        "md5": metadata.md5,
                        "sha256": metadata.sha256,
                    },
                    "chunk_count": result.chunk_count,
                }
            )

        step_result = {
            "aes_key_hex": aes_key_hex,
            "enc_results": enc_results,
            "encryption_algo": "AES-256-GCM",
        }
        self.state["r5"] = step_result
        logger.info("R5 암호화 완료: %d 파일", len(enc_results))
        return step_result

    # ------------------------------------------------------------------
    # R6: Reseal record generation
    # ------------------------------------------------------------------

    def run_r6_record(self) -> dict[str, Any]:
        """Generate the reseal record JSON and PDF.

        Returns dict with keys: record_dict, record_json_path, pdf_path.
        """
        if "r5" not in self.state or self.config is None:
            raise RuntimeError("R5가 완료되지 않았습니다.")

        prev_record = self.state["r1"]["prev_record"]
        seal_id = self.state["r1"]["seal_id"]
        now = datetime.now(tz=timezone.utc)
        output_dir = Path(self.config.output_dir)

        record_dict: dict[str, Any] = {}

        try:
            from .record import append_event, build_reseal_record

            process_info = {
                "type": "Resealing",
                "reason": self.config.reason,
                "investigator": self.config.investigator,
                "subject_participated": self.config.subject_participated,
                "start_time": now.isoformat(),
                "end_time": now.isoformat(),
            }
            file_info = {
                # Files sealed by this reseal (known + derived) — the next
                # unseal/reseal cross-checks hashes against this list.
                "original_files": [
                    er.get("metadata", {})
                    for er in self.state["r5"]["enc_results"]
                ],
                "enc_results": self.state["r5"]["enc_results"],
                "encryption_algo": self.state["r5"]["encryption_algo"],
            }

            # build_reseal_record inherits history as-is — append the
            # reseal event first so summary becomes e.g. S1U1R1.
            prev_for_build = prev_record
            try:
                prev_history = prev_record.get("history") or {}
                new_history = append_event(prev_history, {
                    "seal_type": "Resealing",
                    "start_time": now.isoformat(),
                    "end_time": now.isoformat(),
                    "investigator": self.config.investigator,
                })
                prev_for_build = {**prev_record, "history": new_history}
            except Exception as exc:
                logger.warning("history 이벤트 추가 실패 (이전 이력 유지): %s", exc)
            unknown_files = self.state.get("r3", {}).get(
                "classifications", []
            )
            derived_files = self.state.get("r3", {}).get("derived_files", [])

            record_dict = build_reseal_record(
                prev_record=prev_for_build,
                process_info=process_info,
                file_info=file_info,
                unknown_files=[
                    {
                        "filename": u.filename,
                        "sha256": u.sha256,
                        "classification": u.classification,
                    }
                    for u in unknown_files
                    if isinstance(u, UnknownFileInfo)
                ],
                derived_files=derived_files,
                unlock_time_iso=(
                    now + timedelta(days=self.config.unlock_days)
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                # Resealing encrypts under a fresh key, so the commitment
                # must be recomputed — carrying the sealing-time one
                # forward would make every later verification fail.
                key_commitment=hashlib.sha256(
                    bytes.fromhex(self.state["r5"]["aes_key_hex"])
                ).hexdigest(),
            )
        except ImportError:
            logger.warning("record 모듈 미구현 - 직접 기록 구성")
            history = prev_record.get("history", [])
            new_event = {
                "event": "reseal",
                "timestamp": now.isoformat(),
                "actor": self.config.investigator,
                "reason": self.config.reason,
            }
            new_history = list(history) + [new_event]

            record_dict = {
                "seal_id": seal_id,
                "type": "reseal",
                "version": "1.0",
                "created_at": now.isoformat(),
                "case_number": prev_record.get("case_number", ""),
                "investigator": prev_record.get("investigator", {}),
                "reseal_info": {
                    "reason": self.config.reason,
                    "investigator": self.config.investigator,
                    "subject_participated": self.config.subject_participated,
                },
                "encryption": {
                    "algorithm": self.state["r5"]["encryption_algo"],
                    "enc_results": self.state["r5"]["enc_results"],
                },
                "known_files": self.state["r2"].get("known_files", []),
                "derived_files": self.state.get("r3", {}).get(
                    "derived_files", []
                ),
                "excluded_files": self.state.get("r3", {}).get(
                    "excluded_files", []
                ),
                "history": new_history,
                "summary": _compute_summary(new_history),
            }

        # Resealing fixes a new key, unlock time and commitment, so a NEW
        # policy is signed before the record is written and rendered. Its
        # generation is the previous one + 1 (stage E, E2a; see
        # desktop.policy_generation).
        from desktop.signature.seal_policy import attach_policy_if_configured

        from .policy_generation import next_policy_generation

        record_dict, policy_digest = attach_policy_if_configured(
            record_dict, self._policy_signer,
            generation=next_policy_generation(self._db_path, prev_record),
        )
        # As at sealing (S4): a strict record always carries a signed policy.
        require_policy_for_strict(record_dict, policy_digest)

        # Save JSON
        record_json_path = str(output_dir / f"{seal_id}_reseal_record.json")
        with open(record_json_path, "w", encoding="utf-8") as f:
            json.dump(record_dict, f, ensure_ascii=False, indent=2)

        # Render PDF
        pdf_path = str(output_dir / f"{seal_id}_reseal_record.pdf")
        try:
            from .record import render_record_pdf

            render_record_pdf(
                record=record_dict,
                template_name="reseal_record.html",
                output_path=pdf_path,
            )
        except ImportError:
            logger.warning("PDF 렌더링 모듈 미구현 - 경로만 기록")
            Path(pdf_path).write_text(
                f"[Placeholder] Reseal Record PDF for {seal_id}",
                encoding="utf-8",
            )

        step_result = {
            "record_dict": record_dict,
            "record_json_path": record_json_path,
            "pdf_path": pdf_path,
            "policy_digest": policy_digest,
        }
        self.state["r6"] = step_result
        logger.info("R6 기록 생성 완료: %s", record_json_path)
        return step_result

    # ------------------------------------------------------------------
    # R7: Key splitting
    # ------------------------------------------------------------------

    def run_r7_split_key(self) -> dict[str, Any]:
        """Split the new AES key via SSS 2-of-4 and encrypt shares.

        The unlock time is *read* from the record built and signed in R6,
        never recomputed here, so the shares are governed by exactly the
        policy that was signed.

        Returns dict with keys: shares, unlock_time_iso,
        encrypted_shares.
        """
        if "r5" not in self.state:
            raise RuntimeError("R5가 완료되지 않았습니다.")
        if "r6" not in self.state:
            raise RuntimeError("R6가 완료되지 않았습니다.")

        from .crypto import (
            SEAL_MODE_STRICT,
            get_master_key_path,
            recover_key_for_mode,
            split_key,
            split_key_strict,
        )
        from .s3_wrap import wrap_institutional_shares

        # Resealing honors the regime recorded at initial sealing: the key
        # is split by the mode of the R6 record (whose new policy was just
        # signed), and that mode must be the one carried from R1. Anything
        # unreadable or different is refused, never read as standard.
        mode = split_mode(
            self.state.get("r1", {}).get("prev_record", {}),
            self.state["r6"]["record_dict"],
        )

        aes_key_hex = self.state["r5"]["aes_key_hex"]
        if mode == SEAL_MODE_STRICT:
            shares = split_key_strict(aes_key_hex)
        else:
            shares = split_key(aes_key_hex)

        # Verify split
        recovered = recover_key_for_mode(mode, [shares[0], shares[1]])
        if recovered != aes_key_hex:
            raise RuntimeError("키 분할 검증 실패: 복원된 키가 원본과 불일치")

        # Encrypt shares 3 and 4 (s3 bound to the new policy when signed)
        encrypted_shares, wrapped_s3_b64 = wrap_institutional_shares(
            shares, get_master_key_path(),
            seal_id=self.state["r1"]["seal_id"],
            policy_digest=self.state["r6"].get("policy_digest"),
        )

        unlock_time_iso = self.state["r6"]["record_dict"].get("unlock_time_iso", "")

        step_result = {
            "shares": shares,
            "unlock_time_iso": unlock_time_iso,
            "encrypted_shares": encrypted_shares,
            "wrapped_s3_b64": wrapped_s3_b64,
        }
        self.state["r7"] = step_result
        logger.info("R7 키 분할 완료: unlock_time=%s", unlock_time_iso)
        return step_result

    # ------------------------------------------------------------------
    # R8: Save records
    # ------------------------------------------------------------------

    def run_r8_save(self) -> ResealResult:
        """Persist reseal record, key shares to the DB.

        Returns a ResealResult with the complete resealing outcome.
        """
        required = ["r1", "r5", "r6", "r7"]
        for step in required:
            if step not in self.state:
                raise RuntimeError(f"{step.upper()}가 완료되지 않았습니다.")

        from .db import save_seal_bundle

        seal_id = self.state["r1"]["seal_id"]
        # The R6 record already carries the signed unlock_time_iso, so it
        # is persisted verbatim — the stored JSON matches the signed one.
        record_dict = self.state["r6"]["record_dict"]
        record_json = json.dumps(
            record_dict, ensure_ascii=False, indent=2
        )
        pdf_path = self.state["r6"]["pdf_path"]

        # Persist record, key shares and the sync delivery intent
        # atomically in one transaction (stage E, E2d).
        intent = self._sync_intent(record_json, pdf_path)
        save_seal_bundle(
            self._db_path,
            seal_id,
            record_json,
            pdf_path,
            shares=self.state["r7"]["encrypted_shares"],
            extra_writes=intent.write,
        )

        shares = self.state["r7"]["shares"]
        enc_results = self.state["r5"].get("enc_results", [])
        enc_filepath = (
            enc_results[0]["enc_filepath"] if enc_results else ""
        )

        result = ResealResult(
            seal_id=seal_id,
            enc_filepath=enc_filepath,
            pdf_path=pdf_path,
            key_shares=(shares[0], shares[1], shares[2], shares[3]),
            unlock_time_iso=self.state["r7"]["unlock_time_iso"],
            record_json=record_json,
            wrapped_s3_b64=self.state["r7"].get("wrapped_s3_b64"),
        )
        self.state["r8"] = {"reseal_result": result}
        logger.info("R8 완료: seal_id=%s, 모든 기록 저장", seal_id)
        intent.deliver()
        return result

    def _sync_intent(self, record_json: str, pdf_path: str) -> Any:
        """Stage E (E2a, E2d): the delivery intent of the record R8 saves.

        Its outbox rows are written in the save's transaction; the push
        after it never fails the reseal.
        """
        from .sync import prepare_sync

        return prepare_sync(
            self._db_path, event_type="Resealing", record_json=record_json,
            pdf_path=pdf_path,
            wrapped_s3_b64=self.state["r7"].get("wrapped_s3_b64"),
            signer=self._policy_signer,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_summary(history: list[dict[str, Any]]) -> str:
    """Compute S{n}U{n}R{n} summary from history events."""
    seal_count = sum(1 for e in history if e.get("event") == "seal")
    unseal_count = sum(1 for e in history if e.get("event") == "unseal")
    reseal_count = sum(1 for e in history if e.get("event") == "reseal")
    return f"S{seal_count}U{unseal_count}R{reseal_count}"


def run_reseal_in_background(
    process: ResealProcess,
    wizard_data: dict[str, Any],
    *,
    db_path: str,
    on_step: Optional[Callable[[str, str], None]] = None,
    on_complete: Optional[Callable[[ResealResult], None]] = None,
    on_error: Optional[Callable[[str, Exception], None]] = None,
) -> threading.Thread:
    """Run the full reseal process on a background thread.

    Args:
        process: The ResealProcess instance.
        wizard_data: Data collected from the reseal wizard.
        db_path: SQLite database path.
        on_step: Callback ``(step_name, message)`` for progress updates.
        on_complete: Callback with the final ResealResult.
        on_error: Callback ``(step_name, exception)`` on failure.

    Returns:
        The started daemon thread.
    """

    def _notify(step: str, msg: str) -> None:
        if on_step:
            on_step(step, msg)

    def _run() -> None:
        try:
            _notify("R5", "암호화 진행 중...")
            process.run_r5_encrypt()

            _notify("R6", "재봉인기록지 생성 중...")
            process.run_r6_record()

            _notify("R7", "키 분할 중...")
            process.run_r7_split_key()

            _notify("R8", "기록 저장 중...")
            result = process.run_r8_save()

            if on_complete:
                on_complete(result)

        except Exception as exc:
            logger.exception("재봉인 프로세스 오류")
            if on_error:
                on_error("unknown", exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
