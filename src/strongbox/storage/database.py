"""Engine setup and small helpers shared by the services."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, create_engine, event, insert, select
from sqlalchemy.engine import Connection

from strongbox.storage import schema

SCHEMA_VERSION = "1"


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """SQLite drops tzinfo on round-trip; normalize so comparisons and cursors are stable."""
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class Database:
    def __init__(self, url: str, *, pool_size: int = 10, echo: bool = False) -> None:
        self.url = url
        self.is_sqlite = url.startswith("sqlite")
        kwargs: dict[str, Any] = {"echo": echo, "pool_pre_ping": True}
        if self.is_sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            kwargs["pool_size"] = pool_size
        self.engine: Engine = create_engine(url, **kwargs)
        if self.is_sqlite:
            event.listen(self.engine, "connect", _sqlite_pragmas)

    def create_all(self) -> None:
        schema.metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            if conn.execute(select(schema.audit_head).where(schema.audit_head.c.id == 1)).first() is None:
                conn.execute(insert(schema.audit_head).values(id=1, seq=0, hash="0" * 64))
            if (
                conn.execute(select(schema.schema_info).where(schema.schema_info.c.key == "version")).first()
                is None
            ):
                conn.execute(insert(schema.schema_info).values(key="version", value=SCHEMA_VERSION))

    def ping(self) -> bool:
        with self.engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True

    def dispose(self) -> None:
        self.engine.dispose()


def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.close()


def row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row._mapping)


__all__ = ["Connection", "Database", "as_utc", "new_id", "row_to_dict", "utcnow"]
