from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import select, update

from strongbox.errors import AccessDenied, IntegrityViolation, NotFound, PayloadTooLarge, ValidationFailed
from strongbox.markings import Marking
from strongbox.services.blobs import BlobUpload
from strongbox.services.container import Container
from strongbox.services.guard import Ctx
from strongbox.storage import schema
from tests.conftest import ctx_for

EXPT = Marking.parse("CUI//SP-EXPT//NOFORN")


def _object_path(c: Container, blob_id: str) -> Path:
    return Path(c.settings.blob_local_path) / blob_id[-2:] / blob_id


def test_roundtrip_large_object(container: Container, engineer: Ctx) -> None:
    data = os.urandom(1_000_003)
    meta = container.blobs.put_bytes(
        engineer,
        data,
        marking=EXPT,
        content_type="application/octet-stream",
        filename="weld-map.bin",
        metadata={"part_number": "TR-1042", "lot": 7},
    )
    assert meta.size_bytes == len(data)
    got_meta, got = container.blobs.read_all(engineer, meta.id)
    assert got == data
    assert got_meta.filename == "weld-map.bin"
    assert got_meta.metadata == {"part_number": "TR-1042", "lot": 7}
    assert got_meta.marking == EXPT


def test_nothing_sensitive_at_rest(container: Container, engineer: Ctx) -> None:
    secret = b"INJECTOR-PINTLE-GEOMETRY " * 400
    meta = container.blobs.put_bytes(
        engineer, secret, marking=EXPT, filename="pintle-secret.txt", metadata={"note": "HOTFIRE-DATA"}
    )
    assert b"INJECTOR" not in _object_path(container, meta.id).read_bytes()
    with container.db.engine.connect() as conn:
        row = conn.execute(select(schema.blobs).where(schema.blobs.c.id == meta.id)).one()
    assert b"pintle-secret" not in bytes(row.sealed_meta)
    assert b"HOTFIRE" not in bytes(row.sealed_meta)
    assert len(bytes(row.wrapped_dek)) > 32  # wrapped, not raw


def test_tampered_object_detected_and_audited(container: Container, engineer: Ctx) -> None:
    meta = container.blobs.put_bytes(engineer, os.urandom(20_000), marking=EXPT)
    path = _object_path(container, meta.id)
    raw = bytearray(path.read_bytes())
    raw[-100] ^= 0xFF
    path.write_bytes(bytes(raw))
    with pytest.raises(IntegrityViolation):
        container.blobs.read_all(engineer, meta.id)
    events = container.audit.list()
    assert events[-1]["decision"] == "error"
    assert "integrity" in events[-1]["reason"]


def test_marking_downgrade_in_database_breaks_decryption(
    container: Container, engineer: Ctx, admin: Ctx
) -> None:
    meta = container.blobs.put_bytes(engineer, b"export controlled", marking=EXPT)
    with container.db.engine.begin() as conn:
        conn.execute(update(schema.blobs).where(schema.blobs.c.id == meta.id).values(marking="UNCONTROLLED"))
    with pytest.raises(IntegrityViolation):
        container.blobs.read_all(admin, meta.id)


def test_foreign_national_cannot_see_export_controlled(
    container: Container, engineer: Ctx, foreign: Ctx
) -> None:
    meta = container.blobs.put_bytes(engineer, b"itar", marking=EXPT)
    with pytest.raises(NotFound):  # concealed: no existence oracle
        container.blobs.get_meta(foreign, meta.id)
    with pytest.raises(NotFound):
        container.blobs.read_all(foreign, meta.id)
    items, _ = container.blobs.list(foreign)
    assert meta.id not in {m.id for m in items}
    denies = [e for e in container.audit.list() if e["decision"] == "deny"]
    assert any("U.S. person" in e["reason"] for e in denies)


def test_cannot_create_above_own_clearance(container: Container, foreign: Ctx) -> None:
    with pytest.raises(AccessDenied):
        container.blobs.put_bytes(foreign, b"x", marking=EXPT)


def test_shred_is_irreversible(container: Container, engineer: Ctx, admin: Ctx) -> None:
    meta = container.blobs.put_bytes(engineer, b"to be destroyed", marking=EXPT)
    container.blobs.delete(engineer, meta.id, shred=True)
    assert not _object_path(container, meta.id).exists()
    with container.db.engine.connect() as conn:
        row = conn.execute(select(schema.blobs).where(schema.blobs.c.id == meta.id)).one()
    assert row.state == "shredded"
    assert row.wrapped_dek is None
    with pytest.raises(NotFound):
        container.blobs.read_all(admin, meta.id)


def test_soft_delete_hides(container: Container, engineer: Ctx) -> None:
    meta = container.blobs.put_bytes(engineer, b"x", marking=Marking.uncontrolled())
    container.blobs.delete(engineer, meta.id)
    with pytest.raises(NotFound):
        container.blobs.get_meta(engineer, meta.id)


def test_size_limit_aborts_and_cleans_up(container: Container, engineer: Ctx) -> None:
    upload = container.blobs.begin_upload(engineer, marking=EXPT)
    assert isinstance(upload, BlobUpload)
    for _ in range(5):
        upload.write(os.urandom(1024 * 1024))
    with pytest.raises(PayloadTooLarge):
        upload.write(b"one byte too many")
    with container.db.engine.connect() as conn:
        assert conn.execute(select(schema.blobs)).all() == []
    assert not any(p.is_file() for p in Path(container.settings.blob_local_path).rglob("*"))


def test_idempotent_upload(container: Container, engineer: Ctx) -> None:
    a = container.blobs.put_bytes(engineer, b"once", marking=EXPT, idempotency_key="k-1")
    b = container.blobs.put_bytes(engineer, b"once", marking=EXPT, idempotency_key="k-1")
    assert a.id == b.id


def test_input_validation(container: Container, engineer: Ctx) -> None:
    with pytest.raises(ValidationFailed):
        container.blobs.put_bytes(engineer, b"x", marking=EXPT, content_type="not a type")
    with pytest.raises(ValidationFailed):
        container.blobs.put_bytes(engineer, b"x", marking=EXPT, filename="../../etc/passwd")


def test_list_pagination(container: Container, engineer: Ctx) -> None:
    ids = {container.blobs.put_bytes(engineer, b"x", marking=EXPT).id for _ in range(5)}
    page1, cursor = container.blobs.list(engineer, limit=2)
    page2, cursor2 = container.blobs.list(engineer, limit=2, cursor=cursor)
    page3, cursor3 = container.blobs.list(engineer, limit=2, cursor=cursor2)
    seen = [m.id for m in page1 + page2 + page3]
    assert set(seen) == ids
    assert len(seen) == 5
    assert cursor3 is None


def test_agent_sees_metadata_but_not_cui_content(container: Container, engineer: Ctx) -> None:
    from strongbox.errors import ContentWithheld

    meta = container.blobs.put_bytes(engineer, b"cui", marking=EXPT)
    agent = ctx_for(container, "agent:assistant")
    assert container.blobs.get_meta(agent, meta.id).id == meta.id
    with pytest.raises(ContentWithheld):
        container.blobs.read_all(agent, meta.id)
    cleared = ctx_for(container, "agent:boundary")
    assert container.blobs.read_all(cleared, meta.id)[1] == b"cui"
