from __future__ import annotations

import base64
import json
import os

from fastapi.testclient import TestClient

from strongbox.auth.tokens import mint_dev_token
from tests.conftest import SECRET, auth

EXPT = "CUI//SP-EXPT//NOFORN"
NCR = {
    "name": "ncr",
    "marking": "cui//sp-expt",
    "indexed_fields": ["part_number"],
    "json_schema": {
        "type": "object",
        "properties": {"part_number": {"type": "string"}, "status": {"type": "string"}},
        "required": ["part_number"],
    },
}


def _upload(api: TestClient, data: bytes, subject: str = "engineer@rel.test", **headers: str) -> dict:
    h = {
        **auth(subject),
        "X-Strongbox-Marking": EXPT,
        "Content-Type": "text/plain",
        "X-Strongbox-Filename": "hot%20fire%20log.txt",
        "X-Strongbox-Metadata": base64.urlsafe_b64encode(json.dumps({"test": "HF-12"}).encode()).decode(),
        **headers,
    }
    r = api.post("/v1/blobs", content=data, headers=h)
    assert r.status_code in (200, 201), r.text
    return r.json()


def test_health_and_security_headers(api: TestClient) -> None:
    r = api.get("/healthz")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert len(r.headers["x-request-id"]) >= 8
    assert api.get("/readyz").json() == {"status": "ok"}


def test_request_id_propagates(api: TestClient) -> None:
    r = api.get("/v1/whoami", headers={**auth("engineer@rel.test"), "X-Request-ID": "trace-abc-123"})
    assert r.headers["x-request-id"] == "trace-abc-123"


def test_authentication_failures_are_problems_and_audited(api: TestClient, container) -> None:  # type: ignore[no-untyped-def]
    r = api.get("/v1/whoami")
    assert r.status_code == 401
    assert r.headers["content-type"] == "application/problem+json"
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.json()["code"] == "unauthenticated"
    wrong_aud = mint_dev_token(SECRET, "engineer@rel.test", audience="other")
    assert api.get("/v1/whoami", headers={"Authorization": f"Bearer {wrong_aud}"}).status_code == 401
    forged = mint_dev_token("y" * 40, "admin@rel.test")
    assert api.get("/v1/whoami", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    assert api.get("/v1/whoami", headers=auth("nobody@rel.test")).status_code == 401
    denies = [e for e in container.audit.list() if e["action"] == "auth.authenticate"]
    assert len(denies) == 4
    assert any(e["actor"] == "nobody@rel.test" for e in denies)


def test_whoami(api: TestClient) -> None:
    body = api.get("/v1/whoami", headers=auth("engineer@rel.test")).json()
    assert body["subject"] == "engineer@rel.test"
    assert body["us_person"] is True


def test_blob_roundtrip(api: TestClient) -> None:
    data = os.urandom(200_000)
    meta = _upload(api, data)
    assert meta["marking"] == EXPT
    assert meta["filename"] == "hot fire log.txt"
    assert meta["metadata"] == {"test": "HF-12"}
    r = api.get(f"/v1/blobs/{meta['id']}/content", headers=auth("engineer@rel.test"))
    assert r.status_code == 200
    assert r.content == data
    assert r.headers["x-strongbox-marking"] == EXPT
    assert "filename*=UTF-8''hot%20fire%20log.txt" in r.headers["content-disposition"]
    listing = api.get("/v1/blobs", headers=auth("engineer@rel.test")).json()
    assert [b["id"] for b in listing["items"]] == [meta["id"]]


def test_blob_idempotent_replay(api: TestClient) -> None:
    a = _upload(api, b"x", **{"Idempotency-Key": "upload-1"})
    r = api.post(
        "/v1/blobs",
        content=b"x",
        headers={**auth("engineer@rel.test"), "X-Strongbox-Marking": EXPT, "Idempotency-Key": "upload-1"},
    )
    assert r.status_code == 200
    assert r.json()["id"] == a["id"]


def test_blob_concealed_from_foreign_national(api: TestClient) -> None:
    meta = _upload(api, b"itar")
    r = api.get(f"/v1/blobs/{meta['id']}", headers=auth("foreign@rel.test"))
    assert r.status_code == 404
    assert r.json()["code"] == "not_found"


def test_blob_bad_marking_and_size(api: TestClient) -> None:
    r = api.post(
        "/v1/blobs", content=b"x", headers={**auth("engineer@rel.test"), "X-Strongbox-Marking": "SECRET"}
    )
    assert r.status_code == 422
    big = b"x" * (5 * 1024 * 1024 + 1)
    r = api.post("/v1/blobs", content=big, headers={**auth("engineer@rel.test"), "X-Strongbox-Marking": EXPT})
    assert r.status_code == 413


def test_blob_shred(api: TestClient) -> None:
    meta = _upload(api, b"gone")
    assert (
        api.delete(f"/v1/blobs/{meta['id']}?shred=true", headers=auth("engineer@rel.test")).status_code == 204
    )
    assert api.get(f"/v1/blobs/{meta['id']}", headers=auth("admin@rel.test")).status_code == 404


def test_records_flow(api: TestClient) -> None:
    assert api.post("/v1/collections", json=NCR, headers=auth("engineer@rel.test")).status_code == 403
    r = api.post("/v1/collections", json=NCR, headers=auth("svc-mes@rel.test"))
    assert r.status_code == 201, r.text
    assert r.json()["marking"] == "CUI//SP-EXPT"
    assert r.json()["encrypted"] is True

    h = {**auth("engineer@rel.test"), "Idempotency-Key": "ncr-1"}
    r = api.post(
        "/v1/collections/ncr/records", json={"data": {"part_number": "TR-1", "status": "open"}}, headers=h
    )
    assert r.status_code == 201
    rec = r.json()
    assert r.headers["etag"] == '"v1"'
    assert r.headers["x-strongbox-marking"] == "CUI//SP-EXPT"

    url = f"/v1/collections/ncr/records/{rec['id']}"
    body = {"data": {"part_number": "TR-1", "status": "closed"}}
    assert api.put(url, json=body, headers=auth("engineer@rel.test")).status_code == 428
    r = api.put(url, json=body, headers={**auth("engineer@rel.test"), "If-Match": '"v1"'})
    assert r.status_code == 200
    assert r.headers["etag"] == '"v2"'
    stale = api.put(url, json=body, headers={**auth("engineer@rel.test"), "If-Match": '"v1"'})
    assert stale.status_code == 412

    q = api.post(
        "/v1/collections/ncr/query",
        json={"filters": {"part_number": "TR-1"}},
        headers=auth("engineer@rel.test"),
    )
    assert q.status_code == 200
    assert q.json()["marking"] == "CUI//SP-EXPT"
    assert [i["data"]["status"] for i in q.json()["items"]] == ["closed"]

    bad = api.post(
        "/v1/collections/ncr/records", json={"data": {"status": "x"}}, headers=auth("engineer@rel.test")
    )
    assert bad.status_code == 422
    assert "part_number" in bad.json()["detail"]
    assert api.delete(url, headers={**auth("engineer@rel.test"), "If-Match": '"v2"'}).status_code == 204


def test_delegation_header(api: TestClient) -> None:
    api.post("/v1/collections", json=NCR, headers=auth("svc-mes@rel.test"))
    created = api.post(
        "/v1/collections/ncr/records",
        json={"data": {"part_number": "TR-9"}},
        headers=auth("engineer@rel.test"),
    ).json()
    url = f"/v1/collections/ncr/records/{created['id']}"

    # Agent acting for an engineer: metadata yes, CUI content withheld (agent not in an LLM boundary).
    r = api.get(url, headers=auth("agent:assistant", on_behalf_of="engineer@rel.test"))
    assert r.status_code == 200
    assert r.json()["content_withheld"] is True
    assert r.json()["data"] is None

    # Same agent acting for a foreign national: the record is invisible.
    assert api.get(url, headers=auth("agent:boundary", on_behalf_of="foreign@rel.test")).status_code == 404

    # Cleared agent for a cleared user: full content.
    r = api.get(url, headers=auth("agent:boundary", on_behalf_of="engineer@rel.test"))
    assert r.json()["data"] == {"part_number": "TR-9"}

    # A principal without the delegate scope cannot use the header.
    r = api.get(url, headers=auth("engineer@rel.test", on_behalf_of="admin@rel.test"))
    assert r.status_code == 403

    who = api.get("/v1/whoami", headers=auth("agent:boundary", on_behalf_of="engineer@rel.test")).json()
    assert who["subject"] == "engineer@rel.test"
    assert who["actor"] == "agent:boundary"
    assert "delegate" not in who["scopes"]


def test_admin_endpoints(api: TestClient) -> None:
    assert api.get("/v1/audit/verify", headers=auth("engineer@rel.test")).status_code == 403
    r = api.put(
        "/v1/principals/new.hire@rel.test",
        json={
            "kind": "user",
            "scopes": ["records:read"],
            "us_person": True,
            "cui_access": True,
            "cui_categories": ["PROPIN"],
        },
        headers=auth("admin@rel.test"),
    )
    assert r.status_code == 200
    assert api.get("/v1/whoami", headers=auth("new.hire@rel.test")).json()["cui_categories"] == ["PROPIN"]
    self_edit = api.put(
        "/v1/principals/admin@rel.test",
        json={"kind": "user", "scopes": ["*"]},
        headers=auth("admin@rel.test"),
    )
    assert self_edit.status_code == 403
    bad = api.put(
        "/v1/principals/x", json={"kind": "user", "scopes": ["root"]}, headers=auth("admin@rel.test")
    )
    assert bad.status_code == 422
    v = api.get("/v1/audit/verify", headers=auth("admin@rel.test")).json()
    assert v["ok"] is True
    events = api.get("/v1/audit/events?limit=5", headers=auth("admin@rel.test")).json()["items"]
    assert len(events) == 5


def test_openapi_document(api: TestClient) -> None:
    doc = api.get("/openapi.json").json()
    assert "/v1/blobs" in doc["paths"]
    assert "/v1/collections/{name}/query" in doc["paths"]
