"""MCP server end to end: MCP client -> MCP server -> HTTP client -> real API app -> services."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from mcp import Client

from strongbox.api.app import create_app
from strongbox.client import StrongboxClient
from strongbox.mcp_server import build_server
from strongbox.services.container import Container
from tests.conftest import token

SCHEMA = {
    "type": "object",
    "properties": {"part_number": {"type": "string"}, "status": {"type": "string"}},
    "required": ["part_number"],
}


async def _seed(api: StrongboxClient) -> None:
    await api.create_collection(
        "ncr", marking="CUI//SP-EXPT", json_schema=SCHEMA, indexed_fields=["part_number"]
    )
    await api.create_collection("tooling", marking="UNCONTROLLED", indexed_fields=["bay"])


@pytest.fixture
async def wired(container: Container) -> tuple[Container, httpx.ASGITransport]:
    transport = httpx.ASGITransport(app=create_app(container))
    async with StrongboxClient("http://strongbox", token("svc-mes@rel.test"), transport=transport) as svc:
        await _seed(svc)
        await svc.create_record("ncr", {"part_number": "TR-7", "status": "open"})
        await svc.put_blob(
            b"hot-fire notes: chamber pressure nominal",
            marking="CUI//SP-EXPT",
            content_type="text/plain",
            filename="hf.txt",
        )
        await svc.put_blob(b"cafeteria menu", marking="UNCONTROLLED", content_type="text/plain")
    return container, transport


def _client(transport: httpx.ASGITransport, agent: str, user: str | None) -> StrongboxClient:
    return StrongboxClient(
        "http://strongbox", token(agent), on_behalf_of=token(user) if user else None, transport=transport
    )


async def _call(server: Any, name: str, args: dict[str, Any] | None = None) -> Any:
    async with Client(server) as mcp:
        result = await mcp.call_tool(name, args or {})
    return result


def _data(result: Any) -> dict[str, Any]:
    assert not result.is_error, result.content
    return result.structured_content  # type: ignore[no-any-return]


async def test_tool_catalog_has_no_destructive_deletes(wired: Any) -> None:
    _, transport = wired
    server = build_server(_client(transport, "agent:assistant", "engineer@rel.test"))
    async with Client(server) as mcp:
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
    assert {"query_records", "get_record", "create_record", "read_blob_text", "put_blob_text"} <= tools.keys()
    assert not any("delete" in n or "shred" in n for n in tools)
    assert tools["query_records"].annotations.read_only_hint is True
    assert tools["update_record"].annotations.destructive_hint is True


async def test_agent_outside_boundary_sees_metadata_not_cui(wired: Any) -> None:
    _, transport = wired
    server = build_server(_client(transport, "agent:assistant", "engineer@rel.test"))
    page = _data(
        await _call(server, "query_records", {"collection": "ncr", "filters": {"part_number": "TR-7"}})
    )
    assert page["marking"] == "CUI//SP-EXPT"
    rec = page["records"][0]
    assert rec["content_withheld"] is True
    assert rec["data"] is None
    assert "handling" in rec

    blobs = _data(await _call(server, "list_blobs"))["blobs"]
    cui_blob = next(b for b in blobs if b["marking"] != "UNCONTROLLED")
    read = _data(await _call(server, "read_blob_text", {"blob_id": cui_blob["id"]}))
    assert read["content_withheld"] is True
    assert "text" not in read

    public = next(b for b in blobs if b["marking"] == "UNCONTROLLED")
    assert _data(await _call(server, "read_blob_text", {"blob_id": public["id"]}))["text"] == "cafeteria menu"


async def test_agent_inside_boundary_reads_cui(wired: Any) -> None:
    _, transport = wired
    server = build_server(_client(transport, "agent:boundary", "engineer@rel.test"))
    page = _data(
        await _call(server, "query_records", {"collection": "ncr", "filters": {"part_number": "TR-7"}})
    )
    assert page["records"][0]["data"] == {"part_number": "TR-7", "status": "open"}
    blobs = _data(await _call(server, "list_blobs"))["blobs"]
    cui = next(b for b in blobs if b["marking"] != "UNCONTROLLED")
    text = _data(await _call(server, "read_blob_text", {"blob_id": cui["id"]}))
    assert text["text"].startswith("hot-fire notes")
    assert text["marking"] == "CUI//SP-EXPT"


async def test_foreign_national_user_cannot_reach_itar_through_agent(wired: Any) -> None:
    _, transport = wired
    server = build_server(_client(transport, "agent:boundary", "foreign@rel.test"))
    result = await _call(server, "query_records", {"collection": "ncr"})
    assert result.is_error
    assert "not_found" in result.content[0].text
    blobs = _data(await _call(server, "list_blobs"))["blobs"]
    assert all(b["marking"] == "UNCONTROLLED" for b in blobs)


async def test_agent_writes_are_audited_with_both_identities(wired: Any) -> None:
    container, transport = wired
    server = build_server(_client(transport, "agent:assistant", "engineer@rel.test"))
    created = _data(
        await _call(
            server, "create_record", {"collection": "ncr", "data": {"part_number": "TR-8", "status": "open"}}
        )
    )
    assert created["marking"] == "CUI//SP-EXPT"
    assert created["created_by"] == "engineer@rel.test"
    note = _data(
        await _call(
            server, "put_blob_text", {"text": "summary", "marking": "CUI//SP-EXPT", "filename": "summary.md"}
        )
    )
    assert note["marking"] == "CUI//SP-EXPT"
    creates = [e for e in container.audit.list(limit=1000) if e["action"] in ("record.create", "blob.create")]
    last_two = creates[-2:]
    assert all(e["actor"] == "agent:assistant" and e["on_behalf_of"] == "engineer@rel.test" for e in last_two)


async def test_errors_surface_cleanly(wired: Any) -> None:
    _, transport = wired
    server = build_server(_client(transport, "agent:boundary", "engineer@rel.test"))
    bad = await _call(
        server, "create_record", {"collection": "ncr", "data": {"status": "missing part number"}}
    )
    assert bad.is_error
    assert "validation_failed" in bad.content[0].text
    stale = await _call(
        server,
        "query_records",
        {"collection": "ncr", "filters": {"status": "open"}},
    )
    assert stale.is_error
    assert "indexed fields" in stale.content[0].text


async def test_whoami_reflects_delegation(wired: Any) -> None:
    _, transport = wired
    server = build_server(_client(transport, "agent:assistant", "engineer@rel.test"))
    who = _data(await _call(server, "whoami"))
    assert who["subject"] == "engineer@rel.test"
    assert who["actor"] == "agent:assistant"
    assert who["kind"] == "agent"
