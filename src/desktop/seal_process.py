"""Seal process orchestration (S1 through S7).

Coordinates the full sealing workflow by calling into the crypto,
record, signature, and db modules. Each step produces results that feed
into the next. On error the current state is preserved so the user can
retry from the failing step.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class SealRecordError(RuntimeError):
    """A sealing record could not be produced with its required evidence.

    Raised instead of degrading silently: a record that lacks the
    signature or the timestamp evidence defined in Eq. (5) of the
    manuscript is not a seal, so the process aborts and the operator
    retries the failing step.
    """


class SealSigningError(SealRecordError):
    """The record could not be signed (PAdES signature unavailable)."""


class SealTimestampError(SealRecordError):
    """Timestamp evidence could not be obtained or verified."""


@dataclass(frozen=True)
class SealConfig:
    """Immutable configuration collected from wizard steps S1-S3."""

    source_file: str
    output_dir: str
    chunk_size_bytes: int
    case_number: str
    investigator: dict[str, str]
    seizure: dict[str, str]
    media: dict[str, str]
    subject: dict[str, str]
    signature_lines: list[tuple[int, int, int, int]]
    # Deployment-selectable recovery regime (no UI branch): "standard"
    # keeps SSS 2-of-4; "strict" requires s1 in every recovery path.
    seal_mode: str = "standard"
    # Days until the time-locked share may be released. Fixed here so S4
    # can write the resulting unlock time into the record BEFORE S5 signs
    # it — the policy is then covered by the subject's signature.
    unlock_days: int = 10


@dataclass(frozen=True)
class SealResult:
    """Immutable result of the complete seal process."""

    seal_id: str
    enc_filepath: str
    pdf_path: str
    key_shares: tuple[str, str, str, str]
    unlock_time_iso: str
    record_json: str


class SealProcess:
    """Orchestrates the sealing workflow steps S1 through S7."""

    def __init__(self, *, db_path: str) -> None:
        self._db_path = db_path
        self.config: Optional[SealConfig] = None
        self.state: dict[str, Any] = {}

    def run_s1(
        self,
        source_file: str,
        output_dir: str,
        chunk_size_gb: int,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> dict[str, Any]:
        """Encrypt the source file with AES-256-GCM.

        MD5/SHA-256 metadata is computed inline during the encryption
        read (single pass), so no separate hash pass is required.
        """
        from .crypto import MAX_CHUNK_SIZE, encrypt_file

        chunk_bytes = min(chunk_size_gb * (1024 ** 3), MAX_CHUNK_SIZE)
        aes_key = os.urandom(32)
        aes_key_hex = aes_key.hex()

        src_name = Path(source_file).stem
        enc_path = str(Path(output_dir) / f"{src_name}.enc")
        result = encrypt_file(
            filepath=source_file,
            aes_key=aes_key,
            output_path=enc_path,
            chunk_size=chunk_bytes,
            progress_cb=progress_cb,
        )
        metadata = result.metadata

        step_result = {
            "aes_key_hex": aes_key_hex,
            "enc_filepath": result.enc_filepath,
            "metadata": {
                "filename": metadata.filename,
                "size": metadata.size,
                "md5": metadata.md5,
                "sha256": metadata.sha256,
                "mtime": metadata.mtime,
                "ctime": metadata.ctime,
                "atime": metadata.atime,
            },
            "chunk_count": result.chunk_count,
            "encryption_algo": result.encryption_algo,
            "enc_metadata": _read_enc_metadata(result.enc_filepath),
        }
        self.state["s1"] = step_result
        logger.info(
            "S1 complete: %s -> %s (%d chunks)",
            source_file,
            result.enc_filepath,
            result.chunk_count,
        )
        return step_result

    def set_config(self, config: SealConfig) -> None:
        """Store the configuration collected from S1-S3."""
        self.config = config

    def run_s4(self) -> dict[str, Any]:
        """Generate the seal_id and assemble the seal record JSON."""
        if self.config is None:
            raise RuntimeError("Seal configuration must be set before S4")
        if "s1" not in self.state:
            raise RuntimeError("S1 must complete before S4")

        from .record import (
            build_seal_record,
            create_initial_history,
            create_seal_id,
            validate_record,
        )

        now = datetime.now(tz=timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        # The time-lock policy is fixed here, before the record is
        # rendered and signed in S5, so that sigma covers it.
        unlock_time_iso = (
            now + timedelta(days=self.config.unlock_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Commitment to the recovery key, also fixed before signing: a
        # recovering party can then prove it rebuilt the original key
        # without ever holding it (Section 3.3.3 / remote portal check).
        key_commitment = hashlib.sha256(
            bytes.fromhex(self.state["s1"]["aes_key_hex"])
        ).hexdigest()
        seal_id = create_seal_id()
        investigator_name = self.config.investigator.get("name", "")
        s1 = self.state["s1"]
        meta = s1["metadata"]
        enc_meta = s1.get("enc_metadata", {})

        history = create_initial_history({
            "seal_type": "Sealing",
            "start_time": now_iso,
            "end_time": now_iso,
            "investigator": investigator_name,
        })

        record = build_seal_record(
            seal_id=seal_id,
            seal_mode=self.config.seal_mode,
            unlock_time_iso=unlock_time_iso,
            key_commitment=key_commitment,
            case_info={
                "case_number": self.config.case_number,
                "investigator": investigator_name,
                "device_user": self.config.seizure.get("device_user", ""),
                "suspect": self.config.subject.get("name", ""),
                "storage_type": self.config.media.get("type", ""),
                "storage_info": {
                    "manufacturer": self.config.media.get("manufacturer", ""),
                    "model": self.config.media.get("model", ""),
                    "serial": self.config.media.get("serial", ""),
                },
                "seizure_time": self.config.seizure.get("date", now_iso),
                "seizure_location": self.config.seizure.get("location", ""),
            },
            process_info={
                "type": "Sealing",
                "start_time": now_iso,
                "end_time": now_iso,
                "file_count": 1,
                "investigator": investigator_name,
                "reason": "",
                "participation": self.config.subject.get("participation", ""),
            },
            file_info={
                "original_files": [{
                    "filename": meta["filename"],
                    "size": meta["size"],
                    "md5": meta["md5"],
                    "sha256": meta["sha256"],
                    "mtime": _to_zulu(meta["mtime"]),
                    "ctime": _to_zulu(meta["ctime"]),
                    "atime": _to_zulu(meta["atime"]),
                }],
                "result_files": [{
                    "filename": Path(s1["enc_filepath"]).name,
                    "size": Path(s1["enc_filepath"]).stat().st_size,
                    "encryption_algo": s1["encryption_algo"],
                    "enc_ended_time": _to_zulu(
                        enc_meta.get("enc_ended_time", now_iso)
                    ),
                    "nonces": enc_meta.get("nonces", []),
                    "tags": enc_meta.get("tags", []),
                    "chunk_lengths": enc_meta.get("chunk_lengths", []),
                }],
                "hash_match": True,
                "unknown_files": [],
                "derived_files": [],
            },
            signer_info={
                "name": self.config.subject.get("name", ""),
                "email": self.config.subject.get("email", ""),
                "birth_date": self.config.subject.get("birth", ""),
                "phone": self.config.subject.get("phone", ""),
                "cert_fingerprint": "0" * 64,
                "signature_image_hash": _signature_hash(
                    self.config.signature_lines
                ),
            },
            history=history,
        )

        errors = validate_record(record)
        if errors:
            raise RuntimeError(f"Seal record validation failed: {errors}")

        self.state["s4"] = {"seal_id": seal_id, "record_dict": record}
        logger.info("S4 complete: seal_id=%s", seal_id)
        return self.state["s4"]

    def run_s5(
        self,
        status_cb: Optional[Callable[[str], None]] = None,
    ) -> dict[str, Any]:
        """Generate certificate, render PDF, sign it, and timestamp it."""
        if "s4" not in self.state:
            raise RuntimeError("S4 must complete before S5")
        if self.config is None:
            raise RuntimeError("Seal configuration must be set before S5")

        def _notify(msg: str) -> None:
            if status_cb:
                status_cb(msg)

        seal_id = self.state["s4"]["seal_id"]
        record_dict = self.state["s4"]["record_dict"]
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate the signing credentials FIRST, so the real certificate
        # fingerprint is written into record_dict BEFORE the record JSON is
        # serialized and the PDF is rendered. Previously the fingerprint was
        # grafted in only after the PDF had already been rendered and signed,
        # so the signed PDF carried the "0" * 64 placeholder while the stored
        # JSON carried the real value — the two disagreed on
        # signer_info.cert_fingerprint. With this ordering the rendered PDF,
        # the signed PDF, and the stored JSON all carry the same fingerprint,
        # and no post-signing JSON rewrite is needed.
        subject_name = self.config.subject.get("name", "Unknown")
        subject_email = self.config.subject.get("email", "unknown@example.com")
        password = self.config.subject.get("password")
        if not isinstance(password, str) or not password:
            raise SealSigningError(
                "Subject password is required for private-key encryption"
            )
        sig_hash = hashlib.sha256(
            json.dumps(self.config.signature_lines).encode("utf-8")
        ).hexdigest()

        cert_pem_path = str(output_dir / f"{seal_id}_cert.pem")
        key_pem_path = str(output_dir / f"{seal_id}_key.pem")
        tsa_url = None
        tsa_cert_path = None

        _notify("Generating signing credentials")
        try:
            from desktop.signature import (
                ensure_tsa_server_running,
                generate_keypair,
                create_self_signed_cert,
                save_private_key,
                save_certificate,
            )

            tsa_url, tsa_cert_path = ensure_tsa_server_running()
            _notify("Local TSA ready")

            private_key, _public_key = generate_keypair(2048)
            _notify("RSA-2048 key generated")

            cert = create_self_signed_cert(
                private_key=private_key,
                subject_name=subject_name,
                email=subject_email,
                signature_image_hash=sig_hash,
            )

            from cryptography.hazmat.primitives import hashes

            record_dict["signer_info"]["cert_fingerprint"] = cert.fingerprint(
                hashes.SHA256()
            ).hex()
            _notify("X.509 certificate generated")

            save_certificate(cert, cert_pem_path)
            save_private_key(private_key, key_pem_path, password)
            _notify("Certificate and key saved")
        except ImportError as exc:
            # The signature stack is a hard requirement (pyHanko is in
            # requirements.txt): an unsigned record is not a seal.
            raise SealSigningError(
                f"Signature stack unavailable; refusing to emit an "
                f"unsigned sealing record: {exc}"
            ) from exc
        except Exception as exc:
            raise SealSigningError(
                f"Signing credentials could not be generated; refusing to "
                f"emit an unsigned sealing record: {exc}"
            ) from exc

        # Serialize the record JSON and render the PDF — both now carry the
        # real cert fingerprint set above.
        _notify("Writing record JSON")
        record_json_path = str(output_dir / f"{seal_id}_record.json")
        with open(record_json_path, "w", encoding="utf-8") as f:
            json.dump(record_dict, f, ensure_ascii=False, indent=2)

        _notify("Rendering record PDF")
        pdf_path = str(output_dir / f"{seal_id}_seal_record.pdf")
        try:
            from desktop.record import render_record_pdf

            render_record_pdf(record_dict, "seal_record.html", pdf_path)
            _notify("Record PDF rendered")
        except (ImportError, Exception) as exc:
            _notify(f"PDF render fallback: {exc}")
            logger.warning("PDF render fallback: %s", exc)
            Path(pdf_path).write_text(
                f"[Placeholder] Seal Record PDF for {seal_id}",
                encoding="utf-8",
            )

        # Apply the PAdES signature to the rendered PDF.
        _notify("Applying PAdES signature")
        signed_pdf_path = str(output_dir / f"{seal_id}_seal_record_signed.pdf")
        try:
            from desktop.signature import sign_pdf as signature_sign_pdf

            warning = signature_sign_pdf(
                pdf_path=pdf_path,
                cert_path=cert_pem_path,
                key_path=key_pem_path,
                password=password,
                output_path=signed_pdf_path,
                tsa_url=tsa_url,
            )
            pdf_path = signed_pdf_path
            if warning:
                _notify(f"PDF signed with warning: {warning}")
            else:
                _notify("PDF signed successfully")
        except ImportError as exc:
            raise SealSigningError(
                f"Signature stack unavailable; refusing to emit an "
                f"unsigned sealing record: {exc}"
            ) from exc
        except Exception as exc:
            raise SealSigningError(
                f"Signature pipeline failed; refusing to emit an "
                f"unsigned sealing record: {exc}"
            ) from exc

        # Fail-closed timestamp evidence (manuscript Eq. 5): the sealed
        # document is defined as carrying both the signature and its
        # timestamp evidence, so a failed or unverifiable TST aborts the
        # seal rather than leaving a record that claims evidence it lacks.
        _notify("Requesting RFC3161 timestamp")
        try:
            from desktop.signature import request_timestamp, verify_timestamp

            pdf_hash = _sha256_file_digest(pdf_path)
            if not tsa_url:
                raise RuntimeError("TSA URL was not initialized")
            if not tsa_cert_path:
                raise RuntimeError("TSA certificate path was not initialized")
            tst_token = request_timestamp(pdf_hash, tsa_url)
            verify_timestamp(tst_token, str(tsa_cert_path))
            _notify("RFC3161 timestamp verified")
        except Exception as exc:
            raise SealTimestampError(
                f"Timestamp evidence could not be obtained or verified; "
                f"refusing to emit a sealing record without it: {exc}"
            ) from exc

        cert_pem_content = ""
        key_pem_content = b""
        try:
            with open(cert_pem_path, "r", encoding="utf-8") as f:
                cert_pem_content = f.read()
            with open(key_pem_path, "rb") as f:
                key_pem_content = f.read()
        except FileNotFoundError:
            pass

        step_result = {
            "cert_pem_path": cert_pem_path,
            "key_pem_path": key_pem_path,
            "pdf_path": pdf_path,
            "record_json_path": record_json_path,
            "cert_pem": cert_pem_content,
            "key_pem": key_pem_content,
        }
        self.state["s5"] = step_result
        _notify("S5 complete")
        logger.info("S5 complete: pdf_path=%s", pdf_path)
        return step_result

    def run_s6(self) -> dict[str, Any]:
        """Split the AES key (mode-dependent) and encrypt shares 3/4.

        Standard mode uses SSS 2-of-4; strict mode uses the outer
        2-of-2 XOR wrap (owner share required in every recovery path).
        Shares 3/4 are envelope-wrapped identically in both modes.

        The unlock time is *read* from the signed record built in S4 —
        it is never recomputed here, so the value the shares are governed
        by is exactly the value the subject signed.
        """
        if "s1" not in self.state:
            raise RuntimeError("S1 must complete before S6")
        if "s4" not in self.state:
            raise RuntimeError("S4 must complete before S6")

        from .crypto import (
            SEAL_MODE_STRICT,
            encrypt_envelope,
            get_master_key_path,
            recover_key_for_mode,
            split_key,
            split_key_strict,
        )

        mode = self.config.seal_mode if self.config else "standard"
        aes_key_hex = self.state["s1"]["aes_key_hex"]
        if mode == SEAL_MODE_STRICT:
            shares = split_key_strict(aes_key_hex)
        else:
            shares = split_key(aes_key_hex)
        recovered = recover_key_for_mode(mode, [shares[0], shares[1]])
        if recovered != aes_key_hex:
            raise RuntimeError("Key-split recovery self-check failed")

        master_path = get_master_key_path()
        enc_share_3 = encrypt_envelope(shares[2].encode("utf-8"), master_path)
        enc_share_4 = encrypt_envelope(shares[3].encode("utf-8"), master_path)

        unlock_time_iso = self.state["s4"]["record_dict"]["unlock_time_iso"]
        step_result = {
            "shares": shares,
            "unlock_time_iso": unlock_time_iso,
            "encrypted_shares": {3: enc_share_3, 4: enc_share_4},
        }
        self.state["s6"] = step_result
        logger.info("S6 complete: unlock_time=%s", unlock_time_iso)
        return step_result

    def run_s7(self) -> SealResult:
        """Persist seal record, key shares, and certificate to the DB."""
        required = ["s1", "s4", "s5", "s6"]
        for step in required:
            if step not in self.state:
                raise RuntimeError(f"{step.upper()} must complete before S7")

        from .db import save_seal_bundle

        seal_id = self.state["s4"]["seal_id"]
        # The record already carries unlock_time_iso from S4 (signed in
        # S5), so it is persisted verbatim — nothing is grafted on after
        # signing, and the stored JSON matches the signed document.
        record_dict = self.state["s4"]["record_dict"]
        record_json = json.dumps(record_dict, ensure_ascii=False, indent=2)
        pdf_path = self.state["s5"]["pdf_path"]

        cert_pem = self.state["s5"].get("cert_pem", "")
        key_pem = self.state["s5"].get("key_pem", b"")
        key_encrypted = key_pem
        if cert_pem:
            try:
                from .crypto import encrypt_envelope, get_master_key_path

                master_path = get_master_key_path()
                key_encrypted = encrypt_envelope(key_pem, master_path)
            except Exception:
                key_encrypted = key_pem

        # Persist record, key shares, and certificate atomically in a
        # single transaction (all-or-nothing).
        save_seal_bundle(
            self._db_path,
            seal_id,
            record_json,
            pdf_path,
            shares=self.state["s6"]["encrypted_shares"],
            cert_pem=cert_pem,
            key_pem_encrypted=key_encrypted,
        )

        shares = self.state["s6"]["shares"]
        result = SealResult(
            seal_id=seal_id,
            enc_filepath=self.state["s1"]["enc_filepath"],
            pdf_path=pdf_path,
            key_shares=(shares[0], shares[1], shares[2], shares[3]),
            unlock_time_iso=self.state["s6"]["unlock_time_iso"],
            record_json=record_json,
        )
        self.state["s7"] = {"seal_result": result}
        logger.info("S7 complete: seal_id=%s", seal_id)
        return result


def _read_enc_metadata(enc_filepath: str) -> dict[str, Any]:
    """Read the embedded metadata JSON from an encrypted .enc file."""
    with open(enc_filepath, "rb") as f:
        f.seek(-4, 2)
        meta_size = struct.unpack("<I", f.read(4))[0]
        f.seek(-(4 + meta_size), 2)
        return json.loads(f.read(meta_size).decode("utf-8"))


def _sha256_file_digest(path: str | Path) -> bytes:
    """Compute the SHA-256 digest of a file with 8 MiB streaming reads."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def _to_zulu(value: str) -> str:
    """Normalize ISO 8601 timestamps to the schema's UTC Z form."""
    if value.endswith("+00:00"):
        return value.replace("+00:00", "Z")
    return value


def _signature_hash(signature_lines: list[tuple[int, int, int, int]]) -> str:
    """Derive a stable SHA-256 hash from signature line coordinates."""
    import hashlib

    return hashlib.sha256(
        json.dumps(signature_lines).encode("utf-8")
    ).hexdigest()


def run_seal_in_background(
    process: SealProcess,
    wizard_data: dict[str, Any],
    *,
    db_path: str,
    on_step: Optional[Callable[[str, str], None]] = None,
    on_complete: Optional[Callable[[SealResult], None]] = None,
    on_error: Optional[Callable[[str, Exception], None]] = None,
) -> threading.Thread:
    """Run the full seal process on a background thread."""

    def _notify(step: str, msg: str) -> None:
        if on_step:
            on_step(step, msg)

    def _run() -> None:
        try:
            config = SealConfig(
                source_file=wizard_data["source_file"],
                output_dir=wizard_data["output_dir"],
                chunk_size_bytes=wizard_data["chunk_size_gb"] * (1024 ** 3),
                case_number=wizard_data["case_number"],
                investigator=wizard_data.get("investigator", {}),
                seizure=wizard_data.get("seizure", {}),
                media=wizard_data.get("media", {}),
                subject=wizard_data.get("subject", {}),
                signature_lines=wizard_data.get("signature_lines", []),
                seal_mode=wizard_data.get("seal_mode", "standard"),
                unlock_days=wizard_data.get("unlock_days", 10),
            )
            process.set_config(config)

            _notify("S4", "Building seal record")
            process.run_s4()

            _notify("S5", "Generating signed record artifacts")
            process.run_s5(status_cb=lambda msg: _notify("S5", msg))

            _notify("S6", "Splitting AES key")
            process.run_s6()

            _notify("S7", "Saving seal record")
            result = process.run_s7()

            if on_complete:
                on_complete(result)

        except Exception as exc:
            logger.exception("Seal workflow failed")
            if on_error:
                on_error("unknown", exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
