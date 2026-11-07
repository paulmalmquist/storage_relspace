from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from strongbox.api.app import create_app
from strongbox.auth.principal import PrincipalKind, PrincipalSpec
from strongbox.auth.tokens import mint_dev_token
from strongbox.config import Settings
from strongbox.crypto.kms import LocalKeyProvider
from strongbox.services.container import Container
from strongbox.services.guard import Ctx
from strongbox.storage import schema
from strongbox.storage.database import Database

SECRET = "test-secret-" + "x" * 40
PG_URL = os.environ.get("STRONGBOX_TEST_DATABASE_URL")

RW = ["blobs:read", "blobs:write", "blobs:delete", "records:read", "records:write", "records:delete"]

PRINCIPALS = [
    PrincipalSpec("admin@rel.test", PrincipalKind.USER, ["*"], True, True, ["*"], ["*"]),
    PrincipalSpec("engineer@rel.test", PrincipalKind.USER, RW, True, True, ["SP-EXPT", "PROPIN"]),
    PrincipalSpec("foreign@rel.test", PrincipalKind.USER, RW, False, True, ["SP-EXPT", "PROPIN"]),
    PrincipalSpec("intern@rel.test", PrincipalKind.USER, RW, True, False),
    PrincipalSpec("svc-mes@rel.test", PrincipalKind.SERVICE, [*RW, "collections:admin"], True, True, ["*"]),
    PrincipalSpec(
        "agent:assistant",
        PrincipalKind.AGENT,
        ["records:read", "records:write", "blobs:read", "blobs:write", "delegate"],
        True,
        True,
        ["*"],
        ["*"],
    ),
    PrincipalSpec(
        "agent:boundary",
        PrincipalKind.AGENT,
        ["records:read", "records:write", "blobs:read", "blobs:write", "delegate"],
        True,
        True,
        ["*"],
        ["*"],
        llm_boundary_authorized=True,
    ),
]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    LocalKeyProvider.create(tmp_path / "keyring.json")
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        env="test",
        database_url=PG_URL or f"sqlite:///{tmp_path}/strongbox.db",
        local_keyring_path=tmp_path / "keyring.json",
        blob_local_path=tmp_path / "blobs",
        dev_jwt_secret=SECRET,
        chunk_size=4096,
        max_blob_bytes=5 * 1024 * 1024,
    )


@pytest.fixture
def container(settings: Settings) -> Iterator[Container]:
    if PG_URL:
        db = Database(PG_URL)
        schema.metadata.drop_all(db.engine)
        db.dispose()
    c = Container.build(settings, create_schema=True)
    for spec in PRINCIPALS:
        c.principals.put(spec)
    yield c
    c.db.dispose()


def ctx_for(c: Container, subject: str) -> Ctx:
    p = c.principals.get(subject)
    assert p is not None
    return Ctx(p, "test-request")


def token(subject: str, audience: str = "strongbox") -> str:
    return mint_dev_token(SECRET, subject, audience)


def auth(subject: str, on_behalf_of: str | None = None) -> dict[str, str]:
    h = {"Authorization": f"Bearer {token(subject)}"}
    if on_behalf_of:
        h["X-On-Behalf-Of"] = token(on_behalf_of)
    return h


@pytest.fixture
def api(container: Container) -> Iterator[TestClient]:
    with TestClient(create_app(container)) as tc:
        yield tc


@pytest.fixture
def admin(container: Container) -> Ctx:
    return ctx_for(container, "admin@rel.test")


@pytest.fixture
def engineer(container: Container) -> Ctx:
    return ctx_for(container, "engineer@rel.test")


@pytest.fixture
def foreign(container: Container) -> Ctx:
    return ctx_for(container, "foreign@rel.test")
