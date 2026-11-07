package markings

import "testing"

func TestParseCanonicalizes(t *testing.T) {
	cases := map[string]string{
		"CUI":                             "CUI",
		"cui//sp-expt":                    "CUI//SP-EXPT",
		"CONTROLLED//SP-EXPT":             "CUI//SP-EXPT",
		"CUI//PROPIN/SP-EXPT//NOFORN":     "CUI//SP-EXPT/PROPIN//NOFORN",
		"CUI//NOFORN":                     "CUI//NOFORN",
		"CUI//SP-CTI//REL TO GBR,  USA":   "CUI//SP-CTI//REL TO USA, GBR",
		"  UNCONTROLLED ":                 "UNCONTROLLED",
		"CUI//SP-EXPT/NUC//FEDCON/NOFORN": "CUI//SP-EXPT/NUC//FEDCON/NOFORN",
	}
	for in, want := range cases {
		m, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if m.Banner() != want {
			t.Errorf("Parse(%q) = %q, want %q", in, m.Banner(), want)
		}
		again, err := Parse(want)
		if err != nil || again.Banner() != want {
			t.Errorf("canonical form %q did not round-trip", want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"SECRET",
		"CUI//NOFORN//SP-EXPT",
		"CUI//SP-EXPT//NOFORN/REL TO USA, GBR",
		"CUI//SP EXPT",
		"CUI//SP-EXPT//NOFORN//EXTRA",
		"CUI////NOFORN",
		"CUI//SP-EXPT//REL TO 12",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
}

func TestDominance(t *testing.T) {
	base := MustParse("CUI//SP-EXPT")
	if !MustParse("CUI//SP-EXPT//NOFORN").Dominates(base) || !MustParse("CUI//SP-EXPT/PROPIN").Dominates(base) {
		t.Error("more restrictive markings should dominate")
	}
	if MustParse("CUI//PROPIN").Dominates(base) || None().Dominates(base) {
		t.Error("less restrictive markings must not dominate")
	}
	if !base.Dominates(None()) {
		t.Error("everything dominates UNCONTROLLED")
	}
}

func TestCombine(t *testing.T) {
	got := Combine([]Marking{MustParse("CUI//SP-EXPT"), MustParse("CUI//PROPIN//FEDCON"), None()})
	if got.Banner() != "CUI//SP-EXPT/PROPIN//FEDCON" {
		t.Errorf("got %s", got.Banner())
	}
	if Combine(nil).Banner() != "UNCONTROLLED" || Combine([]Marking{None()}).Banner() != "UNCONTROLLED" {
		t.Error("empty or uncontrolled roll-up should be UNCONTROLLED")
	}
	rel := Combine([]Marking{MustParse("CUI//REL TO USA, GBR"), MustParse("CUI//REL TO USA, AUS")})
	if rel.Banner() != "CUI//NOFORN" {
		t.Errorf("conflicting release lists should roll up to NOFORN, got %s", rel.Banner())
	}
}

func TestExportControlled(t *testing.T) {
	if !MustParse("CUI//SP-EXPT").ExportControlled([]string{"SP-EXPT"}) {
		t.Error("SP-EXPT is export controlled")
	}
	if MustParse("CUI//PROPIN").ExportControlled([]string{"SP-EXPT"}) {
		t.Error("PROPIN is not export controlled")
	}
}
