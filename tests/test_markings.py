import pytest

from strongbox.markings import Marking


@pytest.mark.parametrize(
    ("raw", "banner"),
    [
        ("CUI", "CUI"),
        ("cui//sp-expt", "CUI//SP-EXPT"),
        ("CONTROLLED//SP-EXPT", "CUI//SP-EXPT"),
        ("CUI//PROPIN/SP-EXPT//NOFORN", "CUI//SP-EXPT/PROPIN//NOFORN"),
        ("CUI//NOFORN", "CUI//NOFORN"),
        ("CUI//SP-CTI//REL TO GBR,  USA", "CUI//SP-CTI//REL TO USA, GBR"),
        ("  UNCONTROLLED ", "UNCONTROLLED"),
        ("CUI//SP-EXPT/NUC//FEDCON/NOFORN", "CUI//SP-EXPT/NUC//FEDCON/NOFORN"),
    ],
)
def test_parse_canonicalizes(raw: str, banner: str) -> None:
    assert Marking.parse(raw).banner == banner
    assert Marking.parse(banner).banner == banner  # idempotent


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "SECRET",
        "CUI//NOFORN//SP-EXPT",
        "CUI//SP-EXPT//NOFORN/REL TO USA, GBR",
        "CUI//SP EXPT",
        "CUI//SP-EXPT//NOFORN//EXTRA",
        "CUI////NOFORN",
        "CUI//SP-EXPT//REL TO 12",
    ],
)
def test_parse_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        Marking.parse(raw)


def test_dominance() -> None:
    base = Marking.parse("CUI//SP-EXPT")
    assert Marking.parse("CUI//SP-EXPT//NOFORN").dominates(base)
    assert Marking.parse("CUI//SP-EXPT/PROPIN").dominates(base)
    assert not Marking.parse("CUI//PROPIN").dominates(base)
    assert not Marking.uncontrolled().dominates(base)
    assert base.dominates(Marking.uncontrolled())


def test_combine_rolls_up() -> None:
    combined = Marking.combine(
        [Marking.parse("CUI//SP-EXPT"), Marking.parse("CUI//PROPIN//FEDCON"), Marking.uncontrolled()]
    )
    assert combined.banner == "CUI//SP-EXPT/PROPIN//FEDCON"
    assert Marking.combine([Marking.uncontrolled()]).banner == "UNCONTROLLED"
    assert Marking.combine([]).banner == "UNCONTROLLED"


def test_combine_conflicting_release_lists_becomes_noforn() -> None:
    combined = Marking.combine([Marking.parse("CUI//REL TO USA, GBR"), Marking.parse("CUI//REL TO USA, AUS")])
    assert combined.banner == "CUI//NOFORN"


def test_export_controlled() -> None:
    assert Marking.parse("CUI//SP-EXPT").export_controlled(["SP-EXPT"])
    assert not Marking.parse("CUI//PROPIN").export_controlled(["SP-EXPT"])
