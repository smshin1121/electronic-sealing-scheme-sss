"""Unlock-time policy gate tests (manuscript Section 3.5(iv)).

The investigator recovery route must enforce a server-side comparison of
the current time against the unlock time anchored at sealing:

  - future unlock time  -> recovery denied (403), no TSA involvement
  - past unlock time    -> recovery proceeds
  - record without the field / no synced record (legacy) -> ungated
  - present but unparseable unlock time -> denied (fail-closed)
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from desktop.crypto.sss_split import split_key

TEST_KEY_HEX = "ab" * 32
CSRF_TOKEN = "test-csrf-token"  # public-test-fixture


@pytest.fixture()
def app(tmp_path: Any):
    """Create a fresh Flask app with a temporary SQLite DB."""
    db_path = str(tmp_path / "unlock_gate_test.db")
    os.environ["USE_SQLITE"] = "true"
    os.environ["SQLITE_PATH"] = db_path

    from web.config import TestingConfig
    original_path = TestingConfig.SQLITE_PATH
    TestingConfig.SQLITE_PATH = db_path

    from web.app import create_app

    app = create_app("testing")

    yield app

    TestingConfig.SQLITE_PATH = original_path


@pytest.fixture()
def client(app: Any):
    """Flask test client."""
    return app.test_client()


def _iso(delta_days: int) -> str:
    return (
        datetime.now(tz=timezone.utc) + timedelta(days=delta_days)
    ).isoformat()


def _post_recover(client: Any, seal_id: str) -> Any:
    """POST the recovery form with a valid CSRF token in the session."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = CSRF_TOKEN
    return client.post(
        "/investigator/recover-key",
        data={"seal_id": seal_id, "csrf_token": CSRF_TOKEN},
    )


def _seed(
    app: Any,
    seal_id: str,
    record: dict[str, Any] | None,
    record_json_override: str | None = None,
) -> None:
    """Insert a case, two valid standard shares, and (optionally) a record."""
    with app.app_context():
        from web.models.db_models import (
            insert_case,
            insert_key_share,
            insert_seal_record,
        )

        insert_case(
            seal_id=seal_id,
            case_number="C-GATE",
            investigator="수사관",
            suspect_name="홍길동",
        )
        s1, s2, _s3, _s4 = split_key(TEST_KEY_HEX)
        insert_key_share(seal_id, 1, s1, "suspect")
        insert_key_share(seal_id, 2, s2, "investigator")

        if record_json_override is not None:
            insert_seal_record(seal_id, 1, "Sealing", record_json_override)
        elif record is not None:
            insert_seal_record(
                seal_id, 1, "Sealing", json.dumps(record, ensure_ascii=False)
            )


# ===================================================================
# Route-level gate behavior
# ===================================================================

class TestUnlockGateRoute:
    """POST /investigator/recover-key with unlock-time variations."""

    def test_future_unlock_denies_403(self, app: Any, client: Any) -> None:
        seal_id = "S-GATE-FUTURE"
        _seed(app, seal_id, {
            "seal_mode": "standard",
            "unlock_time_iso": _iso(+1),
        })
        resp = _post_recover(client, seal_id)
        assert resp.status_code == 403
        # Distinguish the policy-gate denial from a CSRF 403.
        assert "열람 제한" in resp.get_data(as_text=True)

    def test_past_unlock_allows_recovery(self, app: Any, client: Any) -> None:
        seal_id = "S-GATE-PAST"
        _seed(app, seal_id, {
            "seal_mode": "standard",
            "unlock_time_iso": _iso(-1),
        })
        resp = _post_recover(client, seal_id)
        assert resp.status_code == 302
        assert f"/investigator/recovered/{seal_id}" in resp.headers["Location"]

    def test_record_without_field_is_ungated(
        self, app: Any, client: Any
    ) -> None:
        seal_id = "S-GATE-LEGACYFIELD"
        _seed(app, seal_id, {"seal_mode": "standard"})
        resp = _post_recover(client, seal_id)
        assert resp.status_code == 302

    def test_no_synced_record_is_ungated(self, app: Any, client: Any) -> None:
        seal_id = "S-GATE-NORECORD"
        _seed(app, seal_id, None)
        resp = _post_recover(client, seal_id)
        assert resp.status_code == 302

    def test_unparseable_unlock_time_denies_500(
        self, app: Any, client: Any
    ) -> None:
        seal_id = "S-GATE-BADTIME"
        _seed(app, seal_id, {
            "seal_mode": "standard",
            "unlock_time_iso": "not-a-timestamp",
        })
        resp = _post_recover(client, seal_id)
        assert resp.status_code == 500

    def test_legacy_unlock_time_key_is_honored(
        self, app: Any, client: Any
    ) -> None:
        seal_id = "S-GATE-LEGACYKEY"
        _seed(app, seal_id, {
            "seal_mode": "standard",
            "unlock_time": _iso(+1),
        })
        resp = _post_recover(client, seal_id)
        assert resp.status_code == 403


# ===================================================================
# Helper unit behavior
# ===================================================================

class TestCanonicalRecordCrossesTheBoundary:
    """A record built by the desktop builder must drive the portal gate.

    The gate reads ``unlock_time_iso`` from the synced sealing record. If
    the desktop builder ever renamed the field or changed its format, the
    gate would silently stop enforcing — so this test pins the contract
    against a record produced by the real builder, not a hand-written one.
    """

    @staticmethod
    def _canonical_record(unlock_iso: str) -> dict[str, Any]:
        from desktop.record.record_builder import build_seal_record

        return build_seal_record(
            seal_id="S-20260802-ABC123",
            unlock_time_iso=unlock_iso,
            key_commitment=hashlib.sha256(
                bytes.fromhex(TEST_KEY_HEX)
            ).hexdigest(),
            case_info={
                "case_number": "2026-001", "investigator": "Hong",
                "device_user": "Kim", "suspect": "Kim",
                "storage_type": "SSD",
                "storage_info": {"manufacturer": "M", "model": "X",
                                 "serial": "1"},
                "seizure_time": "2026-08-02T00:00:00Z",
                "seizure_location": "Seoul",
            },
            process_info={
                "type": "Sealing", "start_time": "2026-08-02T00:00:00Z",
                "end_time": "2026-08-02T00:00:00Z", "file_count": 1,
                "investigator": "Hong", "reason": "",
                "participation": "yes",
            },
            file_info={
                "original_files": [{
                    "filename": "e.bin", "size": 1, "md5": "0" * 32,
                    "sha256": "0" * 64,
                    "mtime": "2026-08-02T00:00:00Z",
                    "ctime": "2026-08-02T00:00:00Z",
                    "atime": "2026-08-02T00:00:00Z",
                }],
                "result_files": [{
                    "filename": "e.bin.enc", "size": 2,
                    "encryption_algo": "AES-256-GCM",
                    "enc_ended_time": "2026-08-02T00:00:00Z",
                    "nonces": ["00"], "tags": ["11"], "chunk_lengths": [1],
                }],
                "hash_match": True,
            },
            signer_info={
                "name": "Kim", "email": "k@example.com",
                "birth_date": "1990-01-01", "phone": "010-0000-0000",
                "cert_fingerprint": "0" * 64,
                "signature_image_hash": "0" * 64,
            },
            history={"summary": "S1U0R0", "events": [
                {"event": "seal", "time": "2026-08-02T00:00:00Z",
                 "actor": "Hong", "reason": ""},
            ]},
        )

    def test_future_policy_in_a_real_record_denies(
        self, app: Any, client: Any
    ) -> None:
        seal_id = "S-GATE-CANON-FUTURE"
        record = self._canonical_record(
            (datetime.now(tz=timezone.utc) + timedelta(days=5)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
        record["seal_id"] = seal_id
        _seed(app, seal_id, record)

        resp = _post_recover(client, seal_id)

        assert resp.status_code == 403
        assert "열람 제한" in resp.get_data(as_text=True)

    def test_elapsed_policy_in_a_real_record_allows(
        self, app: Any, client: Any
    ) -> None:
        seal_id = "S-GATE-CANON-PAST"
        record = self._canonical_record(
            (datetime.now(tz=timezone.utc) - timedelta(days=5)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
        record["seal_id"] = seal_id
        _seed(app, seal_id, record)

        resp = _post_recover(client, seal_id)

        assert resp.status_code == 302


class TestCommitmentVerification:
    """A reconstruction that disagrees with the signed commitment is refused."""

    def test_mismatched_commitment_is_refused(
        self, app: Any, client: Any
    ) -> None:
        seal_id = "S-GATE-BADCOMMIT"
        record = TestCanonicalRecordCrossesTheBoundary._canonical_record(
            (datetime.now(tz=timezone.utc) - timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
        record["seal_id"] = seal_id
        # Commitment of a DIFFERENT key: the shares still combine, but the
        # result is not the key this seal was made with.
        record["key_commitment"] = hashlib.sha256(b"another key").hexdigest()
        _seed(app, seal_id, record)

        resp = _post_recover(client, seal_id)

        assert resp.status_code == 400
        assert "확인값" in resp.get_data(as_text=True)

    def test_legacy_record_without_commitment_still_recovers(
        self, app: Any, client: Any
    ) -> None:
        """Pre-commitment seals must keep working (documented legacy path)."""
        seal_id = "S-GATE-NOCOMMIT"
        record = TestCanonicalRecordCrossesTheBoundary._canonical_record(
            (datetime.now(tz=timezone.utc) - timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
        record["seal_id"] = seal_id
        del record["key_commitment"]
        _seed(app, seal_id, record)

        resp = _post_recover(client, seal_id)

        assert resp.status_code == 302


class TestFindLatestUnlockTime:
    """db_models.find_latest_unlock_time."""

    def test_no_records_returns_none(self, app: Any) -> None:
        with app.app_context():
            from web.models.db_models import find_latest_unlock_time

            assert find_latest_unlock_time("S-GATE-NONE") is None

    def test_field_present_returns_value(self, app: Any) -> None:
        seal_id = "S-GATE-HELPER1"
        unlock = _iso(+3)
        _seed(app, seal_id, {"seal_mode": "standard",
                             "unlock_time_iso": unlock})
        with app.app_context():
            from web.models.db_models import find_latest_unlock_time

            assert find_latest_unlock_time(seal_id) == unlock

    def test_field_absent_returns_none(self, app: Any) -> None:
        seal_id = "S-GATE-HELPER2"
        _seed(app, seal_id, {"seal_mode": "standard"})
        with app.app_context():
            from web.models.db_models import find_latest_unlock_time

            assert find_latest_unlock_time(seal_id) is None

    def test_unreadable_json_raises(self, app: Any) -> None:
        seal_id = "S-GATE-HELPER3"
        _seed(app, seal_id, None, record_json_override="{not json")
        with app.app_context():
            from web.models.db_models import find_latest_unlock_time

            with pytest.raises(ValueError):
                find_latest_unlock_time(seal_id)

    def test_non_string_value_returns_none(self, app: Any) -> None:
        seal_id = "S-GATE-HELPER4"
        _seed(app, seal_id, {"seal_mode": "standard",
                             "unlock_time_iso": 12345})
        with app.app_context():
            from web.models.db_models import find_latest_unlock_time

            assert find_latest_unlock_time(seal_id) is None
