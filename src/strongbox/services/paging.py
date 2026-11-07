"""Opaque keyset-pagination cursors over (created_at, id), newest first."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_

from strongbox.errors import ValidationFailed
from strongbox.storage.database import as_utc

MAX_PAGE = 200


def clamp_limit(limit: int | None, default: int = 50) -> int:
    if limit is None:
        return default
    if limit < 1:
        raise ValidationFailed("limit must be >= 1")
    return min(limit, MAX_PAGE)


def encode_cursor(created_at: datetime, ident: str) -> str:
    raw = json.dumps({"t": as_utc(created_at).isoformat(), "i": ident}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
        return as_utc(datetime.fromisoformat(data["t"])), str(data["i"])
    except Exception as exc:
        raise ValidationFailed("invalid cursor") from exc


def before_cursor(created_col: Any, id_col: Any, cursor: str | None) -> Any:
    if not cursor:
        return None
    ts, ident = decode_cursor(cursor)
    return or_(created_col < ts, and_(created_col == ts, id_col < ident))
