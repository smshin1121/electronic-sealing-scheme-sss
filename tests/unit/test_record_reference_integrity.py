"""Regression tests for record consistency and plaintext reference checks.

The tests cover two integrity boundaries:

#1  ``seal_process.run_s5`` rendered and PAdES-signed the record PDF while
    ``signer_info.cert_fingerprint`` still held the ``"0" * 64`` placeholder,
    then grafted the real fingerprint into the stored JSON afterwards — so
    the signed document and the stored record disagreed. Credential
    generation now runs BEFORE the render/sign, so all artifacts agree.

#2  ``aes_gcm_decrypt.decrypt_file`` gated integrity on the container's own
    embedded plaintext hash, which travels inside the .enc and is rewritable
    by anyone who reorders segments (the per-segment GCM tags bind neither
    order nor whole-file digest). It now accepts independently supplied
    record-reference hashes; ``unseal_process`` passes them so inconsistent
    whole-file output is rejected. Authentication of the selected JSON record
    against its signed PDF is a separate boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from desktop.crypto.aes_gcm_decrypt import decrypt_file
from desktop.crypto.exceptions import TamperDetectedError


# ---------------------------------------------------------------------------
# #1 — seal record cert_fingerprint is set before render/sign
# ---------------------------------------------------------------------------

_REAL_FP = "ab" * 32  # 64 hex chars; distinct from the "0" * 64 placeholder


def _minimal_seal_record() -> dict[str, Any]:
    return {
        "seal_id": "S-20260101-ABCDEF",
        "seal_mode": "standard",
        "unlock_time_iso": "2026-01-11T00:00:00Z",
        "key_commitment": "cd" * 32,
        "case_info": {},
        "process_info": {"type": "Sealing"},
        "file_info": {"original_files": [{"filename": "e.bin"}]},
        "signer_info": {"name": "홍길동", "cert_fingerprint": "0" * 64},
        "history": {"summary": "S1U0R0", "events": [{}]},
    }


class _FakeCert:
    def fingerprint(self, _alg: Any) -> bytes:
        return bytes.fromhex(_REAL_FP)


def _patch_signature_stack(
    monkeypatch: pytest.MonkeyPatch, captured: dict
) -> None:
    """Replace the desktop.signature / desktop.record seams so run_s5 can be
    exercised without the real pyHanko + TSA stack, while capturing the
    cert_fingerprint present in record_dict AT RENDER TIME (the crux of #1)."""
    import desktop.record as rec
    import desktop.signature as sig

    def fake_render(record: dict, template_name: str, output_path: str) -> None:
        captured["render_fp"] = record["signer_info"]["cert_fingerprint"]
        Path(output_path).write_bytes(b"%PDF-1.4 fake\n")

    def fake_sign(
        *, pdf_path, cert_path, key_path, password, output_path, tsa_url
    ):
        Path(output_path).write_bytes(Path(pdf_path).read_bytes())
        return None

    monkeypatch.setattr(rec, "render_record_pdf", fake_render, raising=False)
    monkeypatch.setattr(
        sig, "ensure_tsa_server_running",
        lambda: ("http://localhost:0", "tsa.pem"), raising=False,
    )
    monkeypatch.setattr(
        sig, "generate_keypair",
        lambda bits=2048: (object(), object()), raising=False,
    )
    monkeypatch.setattr(
        sig, "create_self_signed_cert",
        lambda **kw: _FakeCert(), raising=False,
    )
    monkeypatch.setattr(
        sig, "save_certificate",
        lambda cert, path: Path(path).write_text("cert"), raising=False,
    )
    monkeypatch.setattr(
        sig, "save_private_key",
        lambda key, path, pw: Path(path).write_bytes(b"key"), raising=False,
    )
    monkeypatch.setattr(sig, "sign_pdf", fake_sign, raising=False)
    monkeypatch.setattr(
        sig, "request_timestamp", lambda digest, url: b"tst", raising=False,
    )
    monkeypatch.setattr(
        sig, "verify_timestamp", lambda token, cert: None, raising=False,
    )


class TestSealCertFingerprintOrdering:
    def test_render_and_stored_json_carry_real_fingerprint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from desktop.seal_process import SealConfig, SealProcess

        captured: dict = {}
        _patch_signature_stack(monkeypatch, captured)

        proc = SealProcess(db_path=str(tmp_path / "x.db"))
        proc.set_config(SealConfig(
            source_file="src", output_dir=str(tmp_path), chunk_size_bytes=0,
            case_number="c", investigator={}, seizure={}, media={},
            subject={"name": "홍길동", "email": "a@b.c", "password": "pw"},
            signature_lines=[[0, 0, 1, 1]],
        ))
        proc.state["s4"] = {
            "seal_id": "S-20260101-ABCDEF",
            "record_dict": _minimal_seal_record(),
        }

        proc.run_s5()

        # The PDF was rendered with the REAL fingerprint, not the placeholder.
        assert captured["render_fp"] == _REAL_FP
        assert captured["render_fp"] != "0" * 64

        # The stored JSON agrees with the signed document.
        stored = json.loads(
            (tmp_path / "S-20260101-ABCDEF_record.json").read_text(
                encoding="utf-8"
            )
        )
        assert stored["signer_info"]["cert_fingerprint"] == _REAL_FP

        # And the in-memory record used by S6/S7 (persisted to the DB) agrees.
        assert (
            proc.state["s4"]["record_dict"]["signer_info"]["cert_fingerprint"]
            == _REAL_FP
        )


# ---------------------------------------------------------------------------
# #2 — decryption can use record-reference hashes beyond container metadata
# ---------------------------------------------------------------------------

def _build_multichunk_enc(
    path: Path, aes_key: bytes, chunks: list[bytes]
) -> None:
    """Write a valid multi-segment container for the given plaintext chunks.

    Per-segment (nonce, tag) pairs are computed independently, exactly as the
    real encryptor lays them out, so every segment's GCM tag verifies. The
    container's own plaintext-hash metadata is set to the hash of the
    concatenation of *these* chunks in *this* order — i.e. a self-consistent
    container, whatever order the caller passes.
    """
    plaintext = b"".join(chunks)
    body = bytearray()
    nonces: list[str] = []
    tags: list[str] = []
    chunk_lengths: list[int] = []
    for chunk in chunks:
        nonce = os.urandom(12)
        ct_with_tag = AESGCM(aes_key).encrypt(nonce, chunk, None)
        body += ct_with_tag
        nonces.append(nonce.hex())
        tags.append(ct_with_tag[-16:].hex())
        chunk_lengths.append(len(chunk))

    meta = {
        "filename": "evidence.bin",
        "size": len(plaintext),
        "encryption_algo": "AES-256-GCM",
        "mtime": "2026-01-01T00:00:00+00:00",
        "ctime": "2026-01-01T00:00:00+00:00",
        "atime": "2026-01-01T00:00:00+00:00",
        "enc_ended_time": "2026-01-01T00:00:00+00:00",
        "seal_id": "",
        "nonces": nonces,
        "tags": tags,
        "chunk_lengths": chunk_lengths,
        "hash_before_sha256": hashlib.sha256(plaintext).hexdigest(),
        "hash_before_md5": hashlib.md5(plaintext).hexdigest(),
    }
    meta_json = json.dumps(meta).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", 8 + len(body)))
        f.write(bytes(body))
        f.write(meta_json)
        f.write(struct.pack("<I", len(meta_json)))


_CHUNK_A = b"A" * 4096
_CHUNK_B = b"B" * 4096
_ORIG = _CHUNK_A + _CHUNK_B
_ORIG_SHA = hashlib.sha256(_ORIG).hexdigest()
_ORIG_MD5 = hashlib.md5(_ORIG).hexdigest()


class TestContainerRecordHashBinding:
    def test_intact_container_verified_against_record(
        self, tmp_path: Path
    ) -> None:
        key = os.urandom(32)
        enc = tmp_path / "intact.enc"
        _build_multichunk_enc(enc, key, [_CHUNK_A, _CHUNK_B])
        out = tmp_path / "out"
        out.mkdir()

        result = decrypt_file(
            str(enc), key, str(out),
            expected_sha256=_ORIG_SHA, expected_md5=_ORIG_MD5,
        )
        assert result.hash_verified is True
        assert (out / "evidence.bin").read_bytes() == _ORIG

    def test_reordered_segments_caught_by_record(self, tmp_path: Path) -> None:
        """Swapped segments and matching container metadata remain
        inconsistent with the external record reference."""
        key = os.urandom(32)
        enc = tmp_path / "reordered.enc"
        # Alternate order with a self-consistent container hash for B || A.
        _build_multichunk_enc(enc, key, [_CHUNK_B, _CHUNK_A])

        # Legacy metadata-only path: the swapped container is internally
        # consistent, so the reorder is NOT caught (this is the gap #2 closes).
        legacy_out = tmp_path / "legacy"
        legacy_out.mkdir()
        legacy = decrypt_file(str(enc), key, str(legacy_out))
        assert legacy.hash_verified is True
        assert (legacy_out / "evidence.bin").read_bytes() == _CHUNK_B + _CHUNK_A

        # Record-anchored path: the reorder IS caught.
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(TamperDetectedError):
            decrypt_file(
                str(enc), key, str(out),
                expected_sha256=_ORIG_SHA, expected_md5=_ORIG_MD5,
            )
        assert not (out / "evidence.bin").exists()
        assert list(out.iterdir()) == []

    def test_metadata_only_tamper_caught_by_cross_check(
        self, tmp_path: Path
    ) -> None:
        """Plaintext intact but the container's embedded hash was swapped to a
        wrong value: the record cross-check flags the altered container."""
        key = os.urandom(32)
        enc = tmp_path / "meta.enc"
        _build_multichunk_enc(enc, key, [_CHUNK_A, _CHUNK_B])

        data = enc.read_bytes()
        wrong = hashlib.sha256(b"X" * 8192).hexdigest().encode("ascii")
        idx = data.rfind(_ORIG_SHA.encode("ascii"))
        assert idx != -1
        enc.write_bytes(data[:idx] + wrong + data[idx + len(wrong):])

        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(TamperDetectedError):
            decrypt_file(
                str(enc), key, str(out),
                expected_sha256=_ORIG_SHA, expected_md5=_ORIG_MD5,
            )
        assert not (out / "evidence.bin").exists()

    def test_no_record_falls_back_to_metadata(self, tmp_path: Path) -> None:
        """Utility callers with no record keep the legacy container-metadata
        behavior (backward compatible)."""
        key = os.urandom(32)
        enc = tmp_path / "nolegacy.enc"
        _build_multichunk_enc(enc, key, [_CHUNK_A, _CHUNK_B])
        out = tmp_path / "out"
        out.mkdir()

        result = decrypt_file(str(enc), key, str(out))
        assert result.hash_verified is True
        assert (out / "evidence.bin").read_bytes() == _ORIG


class TestUnsealForwardsRecordHashes:
    def test_run_u5_passes_record_originals_to_decrypt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """run_u5_decrypt forwards the selected record's original hashes to
        decrypt_file for a whole-file reference comparison."""
        from desktop import unseal_process as up

        captured: dict = {}

        def fake_decrypt(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                output_filepath=str(tmp_path / "e.bin"),
                original_filename="e.bin",
                hash_verified=True, sha256_match=True, md5_match=True,
                metadata={},
            )

        # run_u5 does `from .crypto import decrypt_file`; patch the source.
        monkeypatch.setattr("desktop.crypto.decrypt_file", fake_decrypt)

        proc = up.UnsealProcess(db_path=str(tmp_path / "x.db"))
        proc.set_config(up.UnsealConfig(
            enc_filepath=str(tmp_path / "e.enc"),
            seal_record_path=str(tmp_path / "r.json"),
            aes_key_hex="ab" * 32,
            output_dir=str(tmp_path),
            reason="", investigator="", subject_participated=False,
        ))
        proc.state["u3"] = {
            "seal_record": {
                "file_info": {"original_files": [
                    {"filename": "e.bin", "sha256": _ORIG_SHA, "md5": _ORIG_MD5},
                ]},
            },
            "seal_id": "S-20260101-ABCDEF",
        }
        proc.state["u4"] = {"all_matched": True}

        proc.run_u5_decrypt()

        assert captured["expected_sha256"] == _ORIG_SHA
        assert captured["expected_md5"] == _ORIG_MD5
