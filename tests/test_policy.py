from __future__ import annotations

import pytest

from strongbox.auth.policy import Action, PolicyEngine
from strongbox.auth.principal import Principal, PrincipalKind
from strongbox.markings import Marking

ENGINE = PolicyEngine(["SP-EXPT", "EXPT"])
EXPT = Marking.parse("CUI//SP-EXPT")
NOFORN = Marking.parse("CUI//PROPIN//NOFORN")
FEDCON = Marking.parse("CUI//PROPIN//FEDCON")


def p(**kw: object) -> Principal:
    base: dict[str, object] = {
        "subject": "u",
        "kind": PrincipalKind.USER,
        "scopes": frozenset({"records:read", "blobs:read"}),
        "us_person": True,
        "cui_access": True,
        "cui_categories": frozenset({"SP-EXPT", "PROPIN"}),
    }
    base.update(kw)
    return Principal(**base)  # type: ignore[arg-type]


def test_missing_scope_denied_not_concealed() -> None:
    d = ENGINE.evaluate(p(scopes=frozenset()), Action.RECORD_READ, EXPT)
    assert not d.allowed
    assert not d.conceal
    assert "scope" in d.reason


def test_uncontrolled_needs_only_scope() -> None:
    assert ENGINE.evaluate(p(cui_access=False), Action.RECORD_READ, Marking.uncontrolled()).allowed


def test_cui_requires_cui_access() -> None:
    d = ENGINE.evaluate(p(cui_access=False), Action.RECORD_READ, EXPT)
    assert not d.allowed
    assert d.conceal


def test_export_controlled_requires_us_person() -> None:
    d = ENGINE.evaluate(p(us_person=False), Action.RECORD_READ, EXPT)
    assert not d.allowed
    assert "U.S. person" in d.reason
    assert ENGINE.evaluate(p(), Action.RECORD_READ, EXPT).allowed


def test_category_must_be_authorized() -> None:
    d = ENGINE.evaluate(p(cui_categories=frozenset({"PROPIN"})), Action.RECORD_READ, EXPT)
    assert not d.allowed
    assert "SP-EXPT" in d.reason


def test_noforn_requires_us_person() -> None:
    assert not ENGINE.evaluate(p(us_person=False), Action.RECORD_READ, NOFORN).allowed
    assert ENGINE.evaluate(p(), Action.RECORD_READ, NOFORN).allowed


def test_other_ldcs_require_authorization() -> None:
    assert not ENGINE.evaluate(p(), Action.RECORD_READ, FEDCON).allowed
    assert ENGINE.evaluate(p(dissemination=frozenset({"FEDCON"})), Action.RECORD_READ, FEDCON).allowed


def test_wildcards() -> None:
    star = p(scopes=frozenset({"*"}), cui_categories=frozenset({"*"}), dissemination=frozenset({"*"}))
    assert ENGINE.evaluate(star, Action.BLOB_SHRED, Marking.parse("CUI//SP-CTI/PRVCY//FEDCON")).allowed


@pytest.mark.parametrize("action", [Action.RECORD_READ_CONTENT, Action.BLOB_READ_CONTENT])
def test_agent_content_withheld_outside_boundary(action: Action) -> None:
    agent = p(kind=PrincipalKind.AGENT)
    d = ENGINE.evaluate(agent, action, EXPT)
    assert not d.allowed
    assert d.withheld
    assert ENGINE.evaluate(agent, Action.RECORD_READ, EXPT).allowed  # metadata still visible
    assert ENGINE.evaluate(p(kind=PrincipalKind.AGENT, llm_boundary_authorized=True), action, EXPT).allowed
    assert ENGINE.evaluate(agent, action, Marking.uncontrolled()).allowed  # uncontrolled is fine


def test_delegation_is_intersection() -> None:
    user = p(subject="alice", us_person=False, scopes=frozenset({"*"}), cui_categories=frozenset({"PROPIN"}))
    agent = Principal(
        subject="agent:x",
        kind=PrincipalKind.AGENT,
        scopes=frozenset({"records:read", "delegate"}),
        us_person=True,
        cui_access=True,
        cui_categories=frozenset({"*"}),
        dissemination=frozenset({"*"}),
        llm_boundary_authorized=True,
    )
    eff = user.delegated_to(agent)
    assert eff.subject == "alice"
    assert eff.actor == "agent:x"
    assert eff.kind is PrincipalKind.AGENT
    assert eff.scopes == frozenset({"records:read"})  # delegate never propagates
    assert eff.us_person is False  # cannot borrow the agent's U.S.-person status
    assert eff.cui_categories == frozenset({"PROPIN"})
    assert not ENGINE.evaluate(eff, Action.RECORD_READ, EXPT).allowed
    assert not ENGINE.evaluate(eff, Action.RECORD_UPDATE, Marking.parse("CUI//PROPIN")).allowed
