"""Runs against a live Strongbox server (the Go API in CI).

Requires STRONGBOX_TEST_API_URL and STRONGBOX_TEST_TOKEN for a principal with '*' scopes and CUI access.
"""

from __future__ import annotations

import os
import uuid

import pytest

from strongbox_client import StrongboxAPIError, StrongboxClient

URL = os.environ.get("STRONGBOX_TEST_API_URL")
TOKEN = os.environ.get("STRONGBOX_TEST_TOKEN")

pytestmark = pytest.mark.skipif(not (URL and TOKEN), reason="needs a live server")


@pytest.fixture
async def sb():
    async with StrongboxClient(URL, TOKEN) as client:
        yield client


async def test_blob_round_trip(sb: StrongboxClient) -> None:
    data = os.urandom(300_000)
    meta = await sb.put_blob(
        data, marking="cui//sp-expt", content_type="text/csv", filename="weld map.csv", metadata={"lot": 7}
    )
    assert meta["marking"] == "CUI//SP-EXPT"
    assert meta["filename"] == "weld map.csv"
    assert meta["metadata"] == {"lot": 7}
    got, banner = await sb.read_blob(meta["id"])
    assert got == data
    assert banner == "CUI//SP-EXPT"
    chunks = [c async for c in sb.iter_blob(meta["id"])]
    assert b"".join(chunks) == data
    await sb.delete_blob(meta["id"], shred=True)
    with pytest.raises(StrongboxAPIError) as exc:
        await sb.get_blob(meta["id"])
    assert exc.value.status == 404


async def test_records(sb: StrongboxClient) -> None:
    name = "py_" + uuid.uuid4().hex[:12]
    await sb.create_collection(
        name,
        marking="CUI//SP-EXPT",
        indexed_fields=["part_number"],
        json_schema={"type": "object", "required": ["part_number"], "properties": {"part_number": {"type": "string"}}},
    )
    rec = await sb.create_record(name, {"part_number": "TR-1", "status": "open"})
    upd = await sb.update_record(name, rec["id"], {"part_number": "TR-1", "status": "closed"}, expected_version=1)
    assert upd["version"] == 2
    with pytest.raises(StrongboxAPIError) as exc:
        await sb.update_record(name, rec["id"], {"part_number": "TR-1"}, expected_version=1)
    assert exc.value.code == "precondition_failed"
    page = await sb.query(name, {"part_number": "TR-1"})
    assert [i["data"]["status"] for i in page["items"]] == ["closed"]
    assert page["marking"] == "CUI//SP-EXPT"
    with pytest.raises(StrongboxAPIError) as exc:
        await sb.create_record(name, {"status": "missing part number"})
    assert exc.value.code == "validation_failed"
