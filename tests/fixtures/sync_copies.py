"""Copies of a stored record under another event id (Fable gate, finding 1).

Scenario steps shared by the SQLite and MariaDB modules
(``test_sync_record_copies.py``, ``test_sync_record_copies_mariadb.py``).
A real record of a later event differs from every earlier one: the
desktop appends the event to ``history`` before it builds the record
(``unseal_process.py`` U7, ``reseal_process.py``) and ``process_info``
names the event. :func:`event_record` builds such records for the
synthetic seals; the policy fields are carried over unchanged.
Synthetic data only.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Optional

from tests.fixtures.release_web import ensure_case, sync_payload
from tests.fixtures.sync_web import signed_payload

URL = "/sync/upload-record"
COPY_REFUSAL = "같은 기록이 이미 다른 event_id에"
# Substrings of the generation refusals (routes/sync.py).
ROLLBACK_REFUSAL = "(롤백)"
SAME_GENERATION_REFUSAL = "같은 세대의 다른 봉인 정책"
POLICY_FIELDS = ("policy", "policy_signature", "policy_cert")
# Stands for an attacker's own bytes (not a valid envelope of any share).
FOREIGN_WRAPPED_S3 = "QUJD" * 16


def event_record(material: Any, events: tuple[str, ...]) -> dict:
    """The seal's record after ``events`` (``("Sealing", "Unsealing")``)."""
    summary = "S{}U{}R{}".format(*(events.count(kind) for kind in
                                   ("Sealing", "Unsealing", "Resealing")))
    history = {"summary": summary,
               "events": [{"seq": n, "type": kind} for n, kind in
                          enumerate(events, start=1)]}
    return {**copy.deepcopy(material.record),
            "process_info": {"type": events[-1]}, "history": history}


def replayed(material: Any, event_id: int) -> dict:
    """The seal's record replayed under ``event_id`` with a field outside
    the signed policy changed.

    Not an exact copy, so the rules after the copy check decide (the
    generation rules, a displacement): tests of those rules replay this
    instead of the record itself, which the copy check refuses first.
    """
    return {**copy.deepcopy(material.record),
            "process_info": {"type": "replay", "replayed_as": event_id}}


def stripped(record: dict) -> dict:
    """The record without its policy (an unauthenticated record)."""
    return {name: value for name, value in record.items()
            if name not in POLICY_FIELDS}


def post(app: Any, body: dict) -> Any:
    ensure_case(app, body["seal_id"])
    return app.test_client().post(URL, json=body)


def unsigned(material: Any, record: dict, event_id: int, event_type: str,
             wrapped_s3_b64: Optional[str] = None) -> dict:
    """An unsigned body; ``wrapped_s3`` only when given."""
    return sync_payload(material, event_id=event_id, event_type=event_type,
                        record=record, wrapped_s3_b64=wrapped_s3_b64,
                        include_wrapped=wrapped_s3_b64 is not None)


def signed(material: Any, signer: Any, record: dict, event_id: int,
           event_type: str) -> dict:
    """A body signed by the institutional key (no ``wrapped_s3``)."""
    return signed_payload(material, signer, event_id=event_id,
                          event_type=event_type, record=record,
                          include_wrapped=False)


def event_ids(app: Any, table: str, seal_id: str) -> list[int]:
    """The event ids stored for the seal in ``seal_records`` or
    ``wrapped_s3_shares`` (either backend)."""
    assert table in ("seal_records", "wrapped_s3_shares")
    with app.app_context():
        from web.models.db_models import execute_query

        rows = execute_query(
            f"SELECT event_id FROM {table} WHERE seal_id = ? ORDER BY event_id",
            (seal_id,), fetch_all=True) or []
    return [int(row["event_id"] if hasattr(row, "keys") else row[0])
            for row in rows]


def stored_record(app: Any, seal_id: str, event_id: int) -> Optional[dict]:
    """The decrypted record stored for the event, parsed."""
    with app.app_context():
        from web.models.release_models import find_record_at

        found = find_record_at(seal_id, event_id)
    return None if found is None else json.loads(found[1])


def refused_as_copy(response: Any) -> bool:
    body = response.get_json() or {}
    return response.status_code == 409 and COPY_REFUSAL in body.get("message", "")
