// Package markings parses and renders CUI banner markings in the NARA CUI Registry format:
//
//	CUI//<category>[/<category>...]//<LDC>[/<LDC>...]
//
// Specified categories carry an "SP-" prefix and sort before basic ones; limited dissemination
// controls (LDCs) come last. Non-CUI data is marked UNCONTROLLED.
//
// Markings are bound into every ciphertext as authenticated data, so changing a stored marking
// without re-encrypting makes the object undecryptable rather than silently downgraded.
package markings

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const Uncontrolled = "UNCONTROLLED"

var (
	simpleLDCs     = map[string]bool{"NOFORN": true, "FED ONLY": true, "FEDCON": true, "NOCON": true, "DL ONLY": true}
	listLDCPrefix  = []string{"REL TO ", "DISPLAY ONLY "}
	categoryRe     = regexp.MustCompile(`^(SP-)?[A-Z][A-Z0-9]{1,15}(\([A-Z]\))?$`)
	countryRe      = regexp.MustCompile(`^[A-Z]{3,8}$`)
	spaceRe        = regexp.MustCompile(`\s+`)
	errEmpty       = errors.New("marking is required (use UNCONTROLLED for non-CUI data)")
	errCatsBefore  = "categories must precede dissemination controls: %q"
	errMalformed   = "malformed CUI banner: %q"
	errNotCUI      = "marking must start with CUI or be UNCONTROLLED: %q"
	errMutualLDC   = errors.New("NOFORN and REL TO are mutually exclusive")
	errSecondNoLDC = "second banner segment must be dissemination controls: %q"
)

// Marking is an immutable, canonicalized CUI marking.
type Marking struct {
	Controlled    bool
	Categories    []string
	Dissemination []string
}

func isLDC(t string) bool {
	if simpleLDCs[t] {
		return true
	}
	for _, p := range listLDCPrefix {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func normalizeLDC(t string) (string, error) {
	for _, p := range listLDCPrefix {
		if !strings.HasPrefix(t, p) {
			continue
		}
		var countries []string
		seen := map[string]bool{}
		for _, c := range strings.Split(t[len(p):], ",") {
			c = strings.TrimSpace(c)
			if c == "" || seen[c] {
				continue
			}
			if !countryRe.MatchString(c) {
				return "", fmt.Errorf("invalid country list in %q", t)
			}
			seen[c] = true
			countries = append(countries, c)
		}
		if len(countries) == 0 {
			return "", fmt.Errorf("invalid country list in %q", t)
		}
		if p == "REL TO " && countries[0] != "USA" {
			rest := []string{"USA"}
			for _, c := range countries {
				if c != "USA" {
					rest = append(rest, c)
				}
			}
			countries = rest
		}
		return p + strings.Join(countries, ", "), nil
	}
	return t, nil
}

// None returns the UNCONTROLLED marking.
func None() Marking { return Marking{} }

// Parse canonicalizes a banner. It returns an error for anything not in Registry format.
func Parse(text string) (Marking, error) {
	norm := spaceRe.ReplaceAllString(strings.ToUpper(strings.TrimSpace(text)), " ")
	if norm == "" {
		return Marking{}, errEmpty
	}
	if norm == Uncontrolled {
		return Marking{}, nil
	}
	segs := strings.Split(norm, "//")
	for i := range segs {
		segs[i] = strings.TrimSpace(segs[i])
	}
	head := segs[0]
	if head == "CONTROLLED" {
		head = "CUI"
	}
	if head != "CUI" {
		return Marking{}, fmt.Errorf(errNotCUI, text)
	}
	rest := segs[1:]
	if len(rest) > 2 {
		return Marking{}, fmt.Errorf(errMalformed, text)
	}
	for _, s := range rest {
		if s == "" {
			return Marking{}, fmt.Errorf(errMalformed, text)
		}
	}
	var cats, ldcs []string
	for i, seg := range rest {
		var tokens []string
		for _, t := range strings.Split(seg, "/") {
			if t = strings.TrimSpace(t); t != "" {
				tokens = append(tokens, t)
			}
		}
		allLDC, anyLDC := true, false
		for _, t := range tokens {
			if isLDC(t) {
				anyLDC = true
			} else {
				allLDC = false
			}
		}
		switch {
		case allLDC:
			ldcs = append(ldcs, tokens...)
		case i == 0 && !anyLDC:
			cats = append(cats, tokens...)
		default:
			return Marking{}, fmt.Errorf(errCatsBefore, text)
		}
	}
	if len(rest) == 2 && len(ldcs) == 0 {
		return Marking{}, fmt.Errorf(errSecondNoLDC, text)
	}
	return Build(cats, ldcs)
}

// MustParse is Parse for constants known to be valid.
func MustParse(text string) Marking {
	m, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return m
}

// Build validates and canonicalizes categories and dissemination controls into a CUI marking.
func Build(categories, ldcs []string) (Marking, error) {
	catSet := map[string]bool{}
	for _, c := range categories {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !categoryRe.MatchString(c) {
			return Marking{}, fmt.Errorf("invalid CUI category marking: %q", c)
		}
		catSet[c] = true
	}
	ldcSet := map[string]bool{}
	for _, d := range ldcs {
		d = spaceRe.ReplaceAllString(strings.ToUpper(strings.TrimSpace(d)), " ")
		if d == "" {
			continue
		}
		n, err := normalizeLDC(d)
		if err != nil {
			return Marking{}, err
		}
		if !isLDC(n) {
			return Marking{}, fmt.Errorf("unknown limited dissemination control: %q", n)
		}
		ldcSet[n] = true
	}
	if ldcSet["NOFORN"] {
		for d := range ldcSet {
			if strings.HasPrefix(d, "REL TO ") {
				return Marking{}, errMutualLDC
			}
		}
	}
	cats := keys(catSet)
	sort.Slice(cats, func(i, j int) bool {
		si, sj := strings.HasPrefix(cats[i], "SP-"), strings.HasPrefix(cats[j], "SP-")
		if si != sj {
			return si
		}
		return cats[i] < cats[j]
	})
	ld := keys(ldcSet)
	sort.Strings(ld)
	return Marking{Controlled: true, Categories: cats, Dissemination: ld}, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Banner renders the canonical banner string.
func (m Marking) Banner() string {
	if !m.Controlled {
		return Uncontrolled
	}
	parts := []string{"CUI"}
	if len(m.Categories) > 0 {
		parts = append(parts, strings.Join(m.Categories, "/"))
	}
	if len(m.Dissemination) > 0 {
		parts = append(parts, strings.Join(m.Dissemination, "/"))
	}
	return strings.Join(parts, "//")
}

func (m Marking) String() string { return m.Banner() }

// Equal compares canonical forms.
func (m Marking) Equal(o Marking) bool { return m.Banner() == o.Banner() }

// Dominates reports whether m is at least as restrictive as o (used to stop downgrades).
func (m Marking) Dominates(o Marking) bool {
	if !o.Controlled {
		return true
	}
	if !m.Controlled {
		return false
	}
	return superset(m.Categories, o.Categories) && superset(m.Dissemination, o.Dissemination)
}

func superset(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if !set[x] {
			return false
		}
	}
	return true
}

// Combine rolls several markings up into the banner for a response that aggregates them.
func Combine(ms []Marking) Marking {
	var cats, ldcs []string
	controlled := false
	for _, m := range ms {
		if m.Controlled {
			controlled = true
		}
		cats = append(cats, m.Categories...)
		ldcs = append(ldcs, m.Dissemination...)
	}
	if !controlled {
		return Marking{}
	}
	rel := map[string]bool{}
	noforn := false
	var other []string
	for _, d := range ldcs {
		switch {
		case d == "NOFORN":
			noforn = true
			other = append(other, d)
		case strings.HasPrefix(d, "REL TO "):
			rel[d] = true
		default:
			other = append(other, d)
		}
	}
	switch {
	case noforn:
		ldcs = other
	case len(rel) > 1:
		// Different release lists can only be released to their intersection; NOFORN is the safe roll-up.
		ldcs = append(other, "NOFORN")
	default:
		ldcs = append(other, keys(rel)...)
	}
	out, err := Build(cats, ldcs)
	if err != nil {
		return Marking{Controlled: true, Dissemination: []string{"NOFORN"}}
	}
	return out
}

// ExportControlled reports whether any category is in the export-controlled set (ITAR/EAR).
func (m Marking) ExportControlled(exportCategories []string) bool {
	set := map[string]bool{}
	for _, c := range exportCategories {
		set[strings.ToUpper(c)] = true
	}
	for _, c := range m.Categories {
		if set[c] {
			return true
		}
	}
	return false
}
