from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import delete, update

from strongbox.audit import AuditLog
from strongbox.errors import NotFound
from strongbox.markings import Marking
from strongbox.services.container import Container
from strongbox.services.guard import Ctx
from strongbox.storage import schema
from tests.conftest import PG_URL


def _activity(c: Container, engineer: Ctx, foreign: Ctx) -> str:
    meta = c.blobs.put_bytes(engineer, b"x", marking=Marking.parse("CUI//SP-EXPT"))
    c.blobs.read_all(engineer, meta.id)
    with contextlib.suppress(NotFound):
        c.blobs.get_meta(foreign, meta.id)
    return meta.id


def test_events_cover_allow_and_deny_without_content(
    container: Container, engineer: Ctx, foreign: Ctx
) -> None:
    blob_id = _activity(container, engineer, foreign)
    events = container.audit.list()
    actions = [(e["action"], e["decision"], e["actor"]) for e in events]
    assert ("blob.create", "allow", "engineer@rel.test") in actions
    assert ("blob.read_content", "allow", "engineer@rel.test") in actions
    assert ("blob.read_meta", "deny", "foreign@rel.test") in actions
    assert all(e["resource_id"] in (blob_id, None) for e in events)
    assert all(str(e["details"]) != "x" for e in events)


def test_chain_verifies(container: Container, engineer: Ctx, foreign: Ctx) -> None:
    _activity(container, engineer, foreign)
    result = container.audit.verify()
    assert result.ok
    assert result.checked == result.head_seq >= 3


def test_edit_detected(container: Container, engineer: Ctx, foreign: Ctx) -> None:
    _activity(container, engineer, foreign)
    with container.db.engine.begin() as conn:
        conn.execute(
            update(schema.audit_events).where(schema.audit_events.c.seq == 2).values(actor="someone-else")
        )
    result = container.audit.verify()
    assert not result.ok
    assert result.first_invalid_seq == 2


def test_deletion_detected(container: Container, engineer: Ctx, foreign: Ctx) -> None:
    _activity(container, engineer, foreign)
    with container.db.engine.begin() as conn:
        conn.execute(delete(schema.audit_events).where(schema.audit_events.c.seq == 1))
    assert not container.audit.verify().ok


def test_tail_truncation_detected(container: Container, engineer: Ctx, foreign: Ctx) -> None:
    _activity(container, engineer, foreign)
    head = container.audit.verify().head_seq
    with container.db.engine.begin() as conn:
        conn.execute(delete(schema.audit_events).where(schema.audit_events.c.seq == head))
    assert not container.audit.verify().ok


def test_delegated_actions_record_both_identities(container: Container) -> None:
    user = container.principals.get("engineer@rel.test")
    agent = container.principals.get("agent:assistant")
    assert user
    assert agent
    ctx = Ctx(user.delegated_to(agent), "r")
    container.blobs.list(ctx)
    last = container.audit.list()[-1]
    assert last["actor"] == "agent:assistant"
    assert last["on_behalf_of"] == "engineer@rel.test"
    assert last["actor_kind"] == "agent"


@pytest.mark.postgres
@pytest.mark.skipif(not PG_URL, reason="needs Postgres row locks to model multiple processes")
def test_concurrent_writers_keep_chain_valid(container: Container) -> None:
    # Separate AuditLog instances have separate in-process locks, like separate API replicas,
    # so ordering relies on SELECT ... FOR UPDATE on the chain head.
    logs = [AuditLog(container.db), AuditLog(container.db)]

    def worker(i: int) -> None:
        for j in range(10):
            logs[i % 2].record(
                principal=None,
                action="test.concurrency",
                resource_type="test",
                resource_id=f"{i}-{j}",
                decision="allow",
                reason="load",
            )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    result = container.audit.verify()
    assert result.ok
    assert result.checked == 80
