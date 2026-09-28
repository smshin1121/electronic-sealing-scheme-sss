"""The subject's view of synced seal records, audited (stage E, E3b).

A record's content leaves the server decrypted only through the subject's
record routes, after that route's session check:

  - ``GET /suspect/records/<seal>/detail/<event>`` (JSON, the record text);
  - ``GET /suspect/records/<seal>/pdf/<event>`` (the record PDF, download).

Each decryption appends an ``identity_access_audit`` row (seal, field
``record_json``/``record_pdf``, purpose, actor role ``subject``, client
address, outcome; never the content). If that row cannot be written the
content is withheld (503). A record that does not decrypt is audited as
``failed`` and answered 500. The list page decrypts nothing. Without a
session nothing is shown and nothing is decrypted. Synthetic data only.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from desktop.crypto.local_kms import init_master_key
from tests.fixtures.record_protection import (
    IDENTITY_VALUES,
    PDF_MARKER,
    access_rows,
    copy_column,
    identity_record,
    insert_plaintext_row,
    synthetic_pdf,
)
from tests.fixtures.release_pki import make_seal_material
from tests.fixtures.release_web import ensure_case, make_release_app, sync_payload

pytestmark = pytest.mark.integration

SEAL = "S-20260928-E3BA01"
OTHER = "S-20260928-E3BA02"
CLIENT = "198.51.100.23"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    master = str(tmp_path / "release_master.key")
    init_master_key(master)
    app = make_release_app(tmp_path, monkeypatch, master_key_path=master)
    app.config["TEST_RELEASE_MASTER"] = master
    return app


def _material(app: Any, seal_id: str) -> Any:
    return make_seal_material(seal_id=seal_id, signer=None,
                              master_key_path=app.config["TEST_RELEASE_MASTER"])


def _sync(app: Any, seal_id: str, event_id: int = 1, *, pdf: bytes | None = None,
          event_type: str = "Sealing") -> str:
    """Sync one record naming the signer; returns the record text sent."""
    material = _material(app, seal_id)
    ensure_case(app, seal_id)
    body = sync_payload(material, record=identity_record(material, note=f"e{event_id}"),
                        event_id=event_id, event_type=event_type, include_wrapped=False)
    if pdf is not None:
        body["record_pdf"] = base64.b64encode(pdf).decode("ascii")
    resp = app.test_client().post("/sync/upload-record", json=body)
    assert resp.status_code == 200, resp.get_json()
    return body["record_json"]


def _subject(app: Any, seal_id: str = SEAL) -> Any:
    client = app.test_client()
    with client.session_transaction() as sess:
        sess[f"auth_{seal_id}"] = True
    return client


def _detail(client: Any, seal_id: str = SEAL, event_id: int = 1) -> Any:
    return client.get(f"/suspect/records/{seal_id}/detail/{event_id}",
                      headers={"Accept": "application/json"},
                      environ_base={"REMOTE_ADDR": CLIENT})


def _pdf(client: Any, seal_id: str = SEAL, event_id: int = 1) -> Any:
    return client.get(f"/suspect/records/{seal_id}/pdf/{event_id}",
                      environ_base={"REMOTE_ADDR": CLIENT})


def _shows_no_content(resp: Any, record_text: str, pdf: bytes | None = None) -> None:
    body = resp.get_data()
    assert record_text.encode("utf-8") not in body
    for value in IDENTITY_VALUES:
        assert value.encode("utf-8") not in body, value
        assert json.dumps(value)[1:-1].encode("ascii") not in body, value
    assert PDF_MARKER not in body
    if pdf:
        assert pdf not in body


class TestAuditedViews:
    def test_the_record_view_decrypts_and_audits(self, app) -> None:
        text = _sync(app, SEAL)

        resp = _detail(_subject(app))

        assert resp.status_code == 200
        assert resp.get_json()["record_json"] == text
        assert "no-store" in resp.headers.get("Cache-Control", "")
        assert access_rows(app, SEAL) == [{
            "seal_id": SEAL, "field": "record_json", "purpose": "record_view",
            "actor_role": "subject", "actor": "", "client_address": CLIENT,
            "outcome": "revealed"}]

    def test_the_pdf_download_decrypts_and_audits(self, app) -> None:
        pdf = synthetic_pdf("download")
        _sync(app, SEAL, pdf=pdf)

        resp = _pdf(_subject(app))

        assert resp.status_code == 200
        assert resp.get_data() == pdf
        assert resp.mimetype == "application/pdf"
        disposition = resp.headers.get("Content-Disposition", "")
        assert disposition.startswith("attachment;") and ".pdf" in disposition
        assert "no-store" in resp.headers.get("Cache-Control", "")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert access_rows(app, SEAL) == [{
            "seal_id": SEAL, "field": "record_pdf", "purpose": "record_download",
            "actor_role": "subject", "actor": "", "client_address": CLIENT,
            "outcome": "revealed"}]

    def test_each_view_is_audited(self, app) -> None:
        _sync(app, SEAL, pdf=synthetic_pdf())
        client = _subject(app)

        for _ in range(2):
            assert _detail(client).status_code == 200
        assert _pdf(client).status_code == 200

        assert [(r["field"], r["outcome"]) for r in access_rows(app, SEAL)] == [
            ("record_json", "revealed"), ("record_json", "revealed"),
            ("record_pdf", "revealed")]

    @pytest.mark.parametrize("view", ["detail", "pdf"])
    def test_a_failed_audit_write_withholds_the_content(self, app, monkeypatch, view) -> None:
        pdf = synthetic_pdf("withheld")
        text = _sync(app, SEAL, pdf=pdf)

        def broken(*_args: Any, **_kwargs: Any) -> int:
            raise RuntimeError("synthetic audit store failure")

        monkeypatch.setattr("web.privacy.record_access.insert_identity_access", broken)
        client = _subject(app)
        resp = _detail(client) if view == "detail" else _pdf(client)

        assert resp.status_code == 503
        _shows_no_content(resp, text, pdf)
        assert access_rows(app, SEAL) == []

    def test_the_list_page_decrypts_nothing(self, app) -> None:
        text = _sync(app, SEAL, pdf=synthetic_pdf())
        _sync(app, SEAL, 2, event_type="Unsealing")

        resp = _subject(app).get(f"/suspect/records/{SEAL}")

        assert resp.status_code == 200
        _shows_no_content(resp, text)
        assert access_rows(app, SEAL) == []
        page = resp.get_data(as_text=True)
        assert f"/suspect/records/{SEAL}/pdf/1" in page
        assert f"/suspect/records/{SEAL}/pdf/2" not in page


class TestRefusals:
    def test_without_a_session_nothing_is_shown_or_decrypted(self, app) -> None:
        pdf = synthetic_pdf("anon")
        text = _sync(app, SEAL, pdf=pdf)
        client = app.test_client()

        detail, download = _detail(client), _pdf(client)
        listing = client.get(f"/suspect/records/{SEAL}")

        assert detail.status_code == 401
        assert download.status_code == 302 and listing.status_code == 302
        for resp in (detail, download, listing):
            _shows_no_content(resp, text, pdf)
        assert access_rows(app, SEAL) == []

    def test_a_session_for_another_seal_shows_nothing(self, app) -> None:
        pdf = synthetic_pdf("other")
        text = _sync(app, SEAL, pdf=pdf)
        _sync(app, OTHER)
        client = _subject(app, OTHER)

        for resp in (_detail(client), _pdf(client)):
            assert resp.status_code in (302, 401)
            _shows_no_content(resp, text, pdf)
        assert access_rows(app, SEAL) == []

    def test_a_record_that_does_not_decrypt_is_audited_as_failed(self, app) -> None:
        pdf = synthetic_pdf("moved")
        text = _sync(app, SEAL, pdf=pdf)
        _sync(app, OTHER, pdf=synthetic_pdf("other"))
        copy_column(app, (OTHER, 1, "record_json"), (SEAL, 1, "record_json"))
        copy_column(app, (OTHER, 1, "record_pdf"), (SEAL, 1, "record_pdf"))
        client = _subject(app)

        detail, download = _detail(client), _pdf(client)

        assert (detail.status_code, download.status_code) == (500, 500)
        for resp in (detail, download):
            _shows_no_content(resp, text, pdf)
        assert [(r["field"], r["outcome"]) for r in access_rows(app, SEAL)] == [
            ("record_json", "failed"), ("record_pdf", "failed")]

    @pytest.mark.parametrize("unset", ["IDENTITY_PEPPER_PATH", "PRIVACY_KMS_MASTER_KEY_PATH"])
    def test_without_the_keys_the_views_answer_503(self, app, unset) -> None:
        pdf = synthetic_pdf("keys")
        text = _sync(app, SEAL, pdf=pdf)
        app.config[unset] = ""
        client = _subject(app)

        for resp in (_detail(client), _pdf(client)):
            assert resp.status_code == 503
            _shows_no_content(resp, text, pdf)
        assert access_rows(app, SEAL) == []

    def test_an_unconverted_record_is_not_shown(self, app) -> None:
        ensure_case(app, SEAL)
        material = _material(app, SEAL)
        text = json.dumps(identity_record(material), ensure_ascii=False)
        pdf = synthetic_pdf("legacy")
        insert_plaintext_row(app, SEAL, 1, text, pdf)
        client = _subject(app)

        detail, download = _detail(client), _pdf(client)

        assert (detail.status_code, download.status_code) == (503, 503)
        assert "이관" in detail.get_json()["message"]
        for resp in (detail, download):
            _shows_no_content(resp, text, pdf)
        assert access_rows(app, SEAL) == []

    def test_a_missing_record_or_pdf_is_404_and_not_audited(self, app) -> None:
        _sync(app, SEAL)  # no PDF
        client = _subject(app)

        assert _detail(client, event_id=9).status_code == 404
        assert _pdf(client, event_id=9).status_code == 404
        assert _pdf(client, event_id=1).status_code == 404
        assert access_rows(app, SEAL) == []


class TestUnexpectedErrors:
    @pytest.mark.parametrize("view", ["detail", "pdf"])
    def test_a_database_error_is_a_controlled_refusal(self, app, monkeypatch, view) -> None:
        pdf = synthetic_pdf("dberror")
        text = _sync(app, SEAL, pdf=pdf)

        def broken(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("synthetic database failure")

        monkeypatch.setattr("web.privacy.record_access.find_stored_record", broken)
        client = _subject(app)
        resp = _detail(client) if view == "detail" else _pdf(client)

        assert resp.status_code == 500
        if view == "detail":
            assert resp.is_json and resp.get_json()["success"] is False
        _shows_no_content(resp, text, pdf)
        assert access_rows(app, SEAL) == []
