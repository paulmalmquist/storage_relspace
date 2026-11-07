from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from strongbox.errors import Conflict, IntegrityViolation, NotFound, PreconditionFailed, ValidationFailed
from strongbox.markings import Marking
from strongbox.services.container import Container
from strongbox.services.guard import Ctx
from strongbox.storage import schema
from tests.conftest import ctx_for

EXPT = Marking.parse("CUI//SP-EXPT")
PART_SCHEMA = {
    "type": "object",
    "properties": {
        "part_number": {"type": "string"},
        "status": {"type": "string", "enum": ["open", "dispositioned", "closed"]},
        "defect": {"type": "string"},
        "qty": {"type": "integer", "minimum": 0},
    },
    "required": ["part_number", "status"],
    "additionalProperties": False,
}


@pytest.fixture
def ncrs(container: Container, admin: Ctx) -> str:
    container.records.create_collection(
        admin, name="ncr", marking=EXPT, json_schema=PART_SCHEMA, indexed_fields=["part_number", "status"]
    )
    return "ncr"


def test_cui_collections_must_be_encrypted(container: Container, admin: Ctx) -> None:
    with pytest.raises(ValidationFailed):
        container.records.create_collection(admin, name="bad", marking=EXPT, encrypted=False)


def test_collection_admin_scope_required(container: Container, engineer: Ctx) -> None:
    from strongbox.errors import AccessDenied

    with pytest.raises(AccessDenied):
        container.records.create_collection(engineer, name="nope", marking=EXPT)


def test_duplicate_collection(container: Container, admin: Ctx, ncrs: str) -> None:
    with pytest.raises(Conflict):
        container.records.create_collection(admin, name=ncrs, marking=EXPT)


def test_crud_with_versions(container: Container, engineer: Ctx, ncrs: str) -> None:
    r = container.records.create_record(
        engineer, ncrs, {"part_number": "TR-1042", "status": "open", "qty": 3}
    )
    assert r.version == 1
    assert r.data == {"part_number": "TR-1042", "status": "open", "qty": 3}
    r2 = container.records.update_record(
        engineer,
        ncrs,
        r.id,
        {"part_number": "TR-1042", "status": "dispositioned", "qty": 3},
        expected_version=1,
    )
    assert r2.version == 2
    with pytest.raises(PreconditionFailed):
        container.records.update_record(
            engineer, ncrs, r.id, {"part_number": "x", "status": "open"}, expected_version=1
        )
    assert container.records.get_record(engineer, ncrs, r.id).data["status"] == "dispositioned"  # type: ignore[index]
    container.records.delete_record(engineer, ncrs, r.id, expected_version=2)
    with pytest.raises(NotFound):
        container.records.get_record(engineer, ncrs, r.id)


def test_schema_enforced(container: Container, engineer: Ctx, ncrs: str) -> None:
    with pytest.raises(ValidationFailed, match="status"):
        container.records.create_record(engineer, ncrs, {"part_number": "TR-1", "status": "bogus"})
    with pytest.raises(ValidationFailed):
        container.records.create_record(engineer, ncrs, {"part_number": "TR-1", "status": "open", "extra": 1})


def test_plaintext_never_stored(container: Container, engineer: Ctx, ncrs: str) -> None:
    container.records.create_record(
        engineer, ncrs, {"part_number": "TR-SECRET-77", "status": "open", "defect": "porosity in manifold"}
    )
    with container.db.engine.connect() as conn:
        rec = conn.execute(select(schema.records)).one()
        idx = conn.execute(select(schema.record_index)).all()
    assert rec.data_plain is None
    assert b"porosity" not in bytes(rec.data_sealed)
    with container.db.engine.connect() as conn:  # SQL NULL, not a JSON 'null' document
        assert conn.exec_driver_sql("SELECT count(*) FROM records WHERE data_plain IS NULL").scalar() == 1
    assert all(row.token.startswith("b:") for row in idx)
    assert not any("TR-SECRET" in row.token for row in idx)


def test_blind_index_query(container: Container, engineer: Ctx, ncrs: str) -> None:
    for pn, status in [("TR-1", "open"), ("TR-1", "closed"), ("TR-2", "open")]:
        container.records.create_record(engineer, ncrs, {"part_number": pn, "status": status})
    items, _ = container.records.query(engineer, ncrs, filters={"part_number": "TR-1"})
    assert {i.data["status"] for i in items} == {"open", "closed"}  # type: ignore[index]
    items, _ = container.records.query(engineer, ncrs, filters={"part_number": "TR-1", "status": "open"})
    assert len(items) == 1
    with pytest.raises(ValidationFailed):
        container.records.query(engineer, ncrs, filters={"defect": "x"})


def test_row_swap_detected(container: Container, engineer: Ctx, ncrs: str) -> None:
    a = container.records.create_record(engineer, ncrs, {"part_number": "A", "status": "open"})
    b = container.records.create_record(engineer, ncrs, {"part_number": "B", "status": "open"})
    with container.db.engine.begin() as conn:
        sealed_b = conn.execute(
            select(schema.records.c.data_sealed).where(schema.records.c.id == b.id)
        ).scalar_one()
        conn.execute(update(schema.records).where(schema.records.c.id == a.id).values(data_sealed=sealed_b))
    with pytest.raises(IntegrityViolation):
        container.records.get_record(engineer, ncrs, a.id)


def test_record_marking_cannot_go_below_collection(container: Container, engineer: Ctx, ncrs: str) -> None:
    with pytest.raises(ValidationFailed):
        container.records.create_record(
            engineer, ncrs, {"part_number": "A", "status": "open"}, marking=Marking.parse("CUI//PROPIN")
        )
    r = container.records.create_record(
        engineer, ncrs, {"part_number": "A", "status": "open"}, marking=Marking.parse("CUI//SP-EXPT//NOFORN")
    )
    assert r.marking.banner == "CUI//SP-EXPT//NOFORN"
    with pytest.raises(ValidationFailed, match="decontrol"):
        container.records.update_record(
            engineer, ncrs, r.id, {"part_number": "A", "status": "open"}, expected_version=1, marking=EXPT
        )


def test_foreign_national_filtered_out(container: Container, engineer: Ctx, foreign: Ctx, ncrs: str) -> None:
    r = container.records.create_record(engineer, ncrs, {"part_number": "A", "status": "open"})
    with pytest.raises(NotFound):
        container.records.get_record(foreign, ncrs, r.id)
    with pytest.raises(NotFound):
        container.records.query(foreign, ncrs)


def test_agent_gets_metadata_only(container: Container, engineer: Ctx, ncrs: str) -> None:
    r = container.records.create_record(engineer, ncrs, {"part_number": "A", "status": "open"})
    view = container.records.get_record(ctx_for(container, "agent:assistant"), ncrs, r.id)
    assert view.content_withheld
    assert view.data is None
    assert view.marking == EXPT
    items, _ = container.records.query(
        ctx_for(container, "agent:assistant"), ncrs, filters={"part_number": "A"}
    )
    assert len(items) == 1
    assert items[0].data is None
    cleared = container.records.get_record(ctx_for(container, "agent:boundary"), ncrs, r.id)
    assert cleared.data == {"part_number": "A", "status": "open"}


def test_idempotent_create(container: Container, engineer: Ctx, ncrs: str) -> None:
    doc = {"part_number": "A", "status": "open"}
    a = container.records.create_record(engineer, ncrs, doc, idempotency_key="abc")
    b = container.records.create_record(engineer, ncrs, doc, idempotency_key="abc")
    assert a.id == b.id
    with pytest.raises(Conflict):
        container.records.create_record(engineer, ncrs, {**doc, "status": "closed"}, idempotency_key="abc")


def test_uncontrolled_collection_plain_storage(container: Container, admin: Ctx, engineer: Ctx) -> None:
    container.records.create_collection(
        admin, name="tooling", marking=Marking.uncontrolled(), indexed_fields=["bay"]
    )
    container.records.create_record(engineer, "tooling", {"bay": 4, "fixture": "F-12"})
    items, _ = container.records.query(engineer, "tooling", filters={"bay": 4})
    assert items[0].data == {"bay": 4, "fixture": "F-12"}
    with container.db.engine.connect() as conn:
        rec = conn.execute(select(schema.records)).one()
    assert (rec.data_plain if isinstance(rec.data_plain, dict) else json.loads(rec.data_plain))[
        "fixture"
    ] == "F-12"


def test_data_key_rotation(container: Container, engineer: Ctx, ncrs: str) -> None:
    r1 = container.records.create_record(engineer, ncrs, {"part_number": "A", "status": "open"})
    container.keys._rotation = timedelta(seconds=0)  # every key is now past its rotation window
    r2 = container.records.create_record(engineer, ncrs, {"part_number": "B", "status": "open"})
    with container.db.engine.connect() as conn:
        k1 = conn.execute(select(schema.records.c.key_id).where(schema.records.c.id == r1.id)).scalar_one()
        k2 = conn.execute(select(schema.records.c.key_id).where(schema.records.c.id == r2.id)).scalar_one()
    assert k1 != k2
    container.keys.clear_cache()
    assert container.records.get_record(engineer, ncrs, r1.id).data["part_number"] == "A"  # type: ignore[index]
