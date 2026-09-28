"""The portal payload follows the sync contract's documented fields (E2d; Codex r2 N7).

The desktop records name the process type ``process_info.type``; the
contract (the portal sync contract added to ``docs/`` from commit 2f1325a,
§2.3) names it ``process_info.seal_type``. The adapter now sets ``seal_type`` from the
record, keeps ``type`` as it is (an extra field, which the contract does not
forbid), and names each history event (``event_id``). Every push is checked
against the contract's required fields before it is sent.

The payloads checked here come from the real sealing, unsealing and
resealing processes (tests/fixtures/sync_processes.py). Synthetic data only.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from desktop.sync import portal_client, transport
from desktop.sync.backends import PORTAL_URL_ENV, WEB_URL_ENV
from tests.fixtures.release_pki import load_test_signer
from tests.fixtures.sync_processes import (
    reseal_through_process,
    seal_through_process,
    unseal_through_process,
)

SECRET = "3" * 32  # public-test-fixture


@pytest.fixture()
def records(tmp_path, monkeypatch, release_pki) -> dict[str, tuple[str, bytes]]:
    """Records of one seal saved by the real processes: seal, unseal, reseal."""
    master = str(tmp_path / "master.key")
    init_master_key(master)
    monkeypatch.setenv("MASTER_KEY_PATH", master)
    for name in (WEB_URL_ENV, PORTAL_URL_ENV, "SYNC_SHARED_SECRET"):
        monkeypatch.delenv(name, raising=False)
    signer = load_test_signer(release_pki)
    db = str(tmp_path / "desktop.db")
    sealed = seal_through_process(tmp_path, signer, db)
    unsealed = unseal_through_process(tmp_path, db, sealed.record_json)
    resealed = reseal_through_process(tmp_path, signer, db,
                                      json.loads(unsealed.record_json),
                                      monkeypatch)
    return {
        name: (result.record_json, Path(result.pdf_path).read_bytes())
        for name, result in (("Sealing", sealed), ("Unsealing", unsealed),
                             ("Resealing", resealed))
    }


def _payload(record_json: str, pdf: bytes) -> dict[str, Any]:
    return json.loads(portal_client._prepare_payload(record_json, record_pdf=pdf))


@pytest.mark.parametrize("event_type", ["Sealing", "Unsealing", "Resealing"])
def test_a_desktop_record_becomes_a_contract_payload(records, event_type) -> None:
    record_json, pdf = records[event_type]

    payload = _payload(record_json, pdf)

    assert portal_client.contract_problems(payload) == []
    assert payload["process_info"]["seal_type"] == event_type
    assert payload["process_info"]["type"] == event_type  # kept as an alias
    last = payload["history"]["events"][-1]
    assert last["seal_type"] == event_type
    assert last["event_id"] == f"EVT-{last['id']:04d}"
    assert base64.b64decode(payload["record_pdf"]) == pdf
    assert payload["process_info"]["unlock_time"] == json.loads(
        record_json)["unlock_time_iso"]


def test_the_adapter_keeps_a_documented_seal_type() -> None:
    record = {"seal_id": "S-20260928-E2D0B1",
              "process_info": {"seal_type": "Unsealing", "type": "Sealing"},
              "history": {"events": [{"id": 1, "seal_type": "Sealing"},
                                     {"id": 2, "seal_type": "Unsealing"}]}}

    payload = json.loads(portal_client._prepare_payload(json.dumps(record)))

    assert payload["process_info"]["seal_type"] == "Unsealing"


def test_without_a_process_type_the_last_event_names_it() -> None:
    record = {"process_info": {},
              "history": {"events": [{"id": 1, "seal_type": "Sealing"}]}}

    payload = json.loads(portal_client._prepare_payload(json.dumps(record)))

    assert payload["process_info"]["seal_type"] == "Sealing"


@pytest.mark.parametrize("change, problem", [
    (lambda p: p.pop("file_info"), "file_info"),
    (lambda p: p.update(seal_id="S-20260928-e2d0b1"), "seal_id"),
    (lambda p: p["signer_info"].update(phone=""), "signer_info.phone"),
    (lambda p: p["signer_info"].pop("birth_date"), "signer_info.birth_date"),
    (lambda p: p["process_info"].update(seal_type="Opening"),
     "process_info.seal_type"),
    (lambda p: p["history"]["events"][-1].pop("event_id"),
     "history.events[-1].event_id"),
    (lambda p: p["history"]["events"][-1].update(seal_type="Unsealing"),
     "history.events[-1].seal_type"),
    (lambda p: p["history"].update(events=[]), "history.events"),
    (lambda p: p.update(record_pdf=base64.b64encode(b"not a pdf").decode()),
     "record_pdf"),
], ids=["six-fields", "seal-id", "phone", "birth-date", "seal-type",
        "event-id", "current-event", "no-events", "pdf"])
def test_contract_problems_are_named(records, change, problem) -> None:
    payload = _payload(*records["Sealing"])
    change(payload)

    assert problem in portal_client.contract_problems(payload)


def test_a_record_outside_the_contract_is_not_sent(records, monkeypatch) -> None:
    opened: list[Any] = []
    monkeypatch.setattr(transport, "_open",
                        lambda request, timeout: opened.append(request))
    record = json.loads(records["Sealing"][0])
    record["signer_info"]["phone"] = ""

    with pytest.raises(portal_client.PortalSyncError) as info:
        portal_client.push_seal_record(json.dumps(record, ensure_ascii=False),
                                       base_url="https://portal.example.org",
                                       secret=SECRET)

    assert "signer_info.phone" in str(info.value)
    assert "010-" not in str(info.value)
    assert opened == []
