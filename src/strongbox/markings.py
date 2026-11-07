"""CUI banner markings, following the NARA CUI Registry format.

    CUI//<category>[/<category>...]//<LDC>[/<LDC>...]

Specified categories carry an ``SP-`` prefix and are listed before basic ones; limited
dissemination controls (LDCs) come last. Examples: ``CUI``, ``CUI//SP-EXPT``,
``CUI//SP-EXPT/PROPIN//NOFORN``. Data that is not CUI is marked ``UNCONTROLLED``.

Markings are bound into every ciphertext as authenticated data, so changing a stored marking
without re-encrypting makes the object undecryptable rather than silently downgraded.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

UNCONTROLLED = "UNCONTROLLED"

_SIMPLE_LDCS = frozenset({"NOFORN", "FED ONLY", "FEDCON", "NOCON", "DL ONLY"})
_LIST_LDC_PREFIXES = ("REL TO ", "DISPLAY ONLY ")
_CATEGORY_RE = re.compile(r"^(SP-)?[A-Z][A-Z0-9]{1,15}(\([A-Z]\))?$")
_COUNTRY_RE = re.compile(r"^[A-Z]{3}$|^[A-Z]{4,8}$")


def _is_ldc(token: str) -> bool:
    return token in _SIMPLE_LDCS or token.startswith(_LIST_LDC_PREFIXES)


def _normalize_ldc(token: str) -> str:
    for prefix in _LIST_LDC_PREFIXES:
        if token.startswith(prefix):
            countries = [c.strip() for c in token[len(prefix) :].split(",") if c.strip()]
            if not countries or not all(_COUNTRY_RE.match(c) for c in countries):
                raise ValueError(f"invalid country list in {token!r}")
            if prefix == "REL TO " and countries[0] != "USA":
                countries = ["USA", *[c for c in countries if c != "USA"]]
            return prefix + ", ".join(dict.fromkeys(countries))
    return token


def _category_key(cat: str) -> tuple[int, str]:
    return (0 if cat.startswith("SP-") else 1, cat)


@dataclass(frozen=True, slots=True)
class Marking:
    controlled: bool
    categories: tuple[str, ...] = ()
    dissemination: tuple[str, ...] = ()

    # ---- construction -------------------------------------------------------------------
    @classmethod
    def uncontrolled(cls) -> Marking:
        return cls(controlled=False)

    @classmethod
    def cui(cls, categories: Iterable[str] = (), dissemination: Iterable[str] = ()) -> Marking:
        return cls._build(list(categories), list(dissemination))

    @classmethod
    def parse(cls, text: str) -> Marking:
        if not isinstance(text, str):
            raise ValueError("marking must be a string")
        norm = re.sub(r"\s+", " ", text.strip().upper())
        if not norm:
            raise ValueError("marking is required (use UNCONTROLLED for non-CUI data)")
        if norm == UNCONTROLLED:
            return cls.uncontrolled()
        segments = [s.strip() for s in norm.split("//")]
        head = segments[0]
        if head == "CONTROLLED":
            head = "CUI"
        if head != "CUI":
            raise ValueError(f"marking must start with CUI or be {UNCONTROLLED}: {text!r}")
        rest = segments[1:]
        if len(rest) > 2 or any(not s for s in rest):
            raise ValueError(f"malformed CUI banner: {text!r}")

        categories: list[str] = []
        ldcs: list[str] = []
        for idx, seg in enumerate(rest):
            tokens = [t.strip() for t in seg.split("/") if t.strip()]
            if all(_is_ldc(t) for t in tokens):
                ldcs.extend(tokens)
            elif idx == 0 and not any(_is_ldc(t) for t in tokens):
                categories.extend(tokens)
            else:
                raise ValueError(f"categories must precede dissemination controls: {text!r}")
        if len(rest) == 2 and not ldcs:
            raise ValueError(f"second banner segment must be dissemination controls: {text!r}")
        return cls._build(categories, ldcs)

    @classmethod
    def _build(cls, categories: list[str], ldcs: list[str]) -> Marking:
        cats = {c.strip().upper() for c in categories if c.strip()}
        for c in cats:
            if not _CATEGORY_RE.match(c):
                raise ValueError(f"invalid CUI category marking: {c!r}")
        controls = {_normalize_ldc(re.sub(r"\s+", " ", d.strip().upper())) for d in ldcs if d.strip()}
        for d in controls:
            if not _is_ldc(d):
                raise ValueError(f"unknown limited dissemination control: {d!r}")
        if "NOFORN" in controls and any(d.startswith("REL TO ") for d in controls):
            raise ValueError("NOFORN and REL TO are mutually exclusive")
        return cls(
            controlled=True,
            categories=tuple(sorted(cats, key=_category_key)),
            dissemination=tuple(sorted(controls)),
        )

    # ---- rendering ----------------------------------------------------------------------
    @property
    def banner(self) -> str:
        if not self.controlled:
            return UNCONTROLLED
        parts = ["CUI"]
        if self.categories:
            parts.append("/".join(self.categories))
        if self.dissemination:
            parts.append("/".join(self.dissemination))
        return "//".join(parts)

    def __str__(self) -> str:
        return self.banner

    @property
    def specified(self) -> bool:
        return any(c.startswith("SP-") for c in self.categories)

    # ---- comparisons --------------------------------------------------------------------
    def dominates(self, other: Marking) -> bool:
        """True if self is at least as restrictive as other (used to stop record-level downgrades)."""
        if not other.controlled:
            return True
        if not self.controlled:
            return False
        return set(self.categories) >= set(other.categories) and set(self.dissemination) >= set(
            other.dissemination
        )

    @classmethod
    def combine(cls, markings: Iterable[Marking]) -> Marking:
        """Roll up several markings into the banner for a response that aggregates them."""
        items = list(markings)
        if not any(m.controlled for m in items):
            return cls.uncontrolled()
        cats: list[str] = []
        ldcs: list[str] = []
        for m in items:
            cats.extend(m.categories)
            ldcs.extend(m.dissemination)
        rel = [d for d in ldcs if d.startswith("REL TO ")]
        if "NOFORN" in ldcs:
            ldcs = [d for d in ldcs if not d.startswith("REL TO ")]
        elif len(set(rel)) > 1:
            # Different release lists can only be released to the intersection; NOFORN is the safe roll-up.
            ldcs = [d for d in ldcs if not d.startswith("REL TO ")] + ["NOFORN"]
        return cls._build(cats, ldcs)

    def export_controlled(self, export_categories: Iterable[str]) -> bool:
        exp = {c.upper() for c in export_categories}
        return any(c in exp for c in self.categories)
