package service

import "testing"

// These are intentionally failing reproductions for findings not fixed by this review.
func TestReviewWideningProofRejectsTightening(t *testing.T) {
	cases := []struct {
		name, old, next string
		value           map[string]any
	}{
		{"const_null", `{"properties":{"tag":{}}}`, `{"properties":{"tag":{"const":null}}}`, map[string]any{"tag": "existing"}},
		{"pattern_properties", `{"type":"object","patternProperties":{".*":{}},"additionalProperties":false}`, `{"type":"object","patternProperties":{".*":{}},"additionalProperties":false,"properties":{"tag":{"type":"integer"}}}`, map[string]any{"tag": "existing"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			old, next := js(t, tt.old), js(t, tt.next)
			a, err := compileSchema("review", old)
			if err != nil {
				t.Fatal(err)
			}
			b, err := compileSchema("review", next)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Validate(tt.value); err != nil {
				t.Fatal(err)
			}
			if b.Validate(tt.value) == nil {
				t.Fatal("test document must fail the new schema")
			}
			if why := widens(old, next, "$"); why == "" {
				t.Fatal("checker proves compatibility for a schema that rejects an existing valid document")
			}
		})
	}
}
