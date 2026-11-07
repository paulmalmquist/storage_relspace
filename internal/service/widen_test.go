package service

import (
	"encoding/json"
	"testing"
)

func js(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWidens(t *testing.T) {
	cases := []struct {
		old, new string
		ok       bool
	}{
		{`{"type":"object"}`, `{"type":"object"}`, true},
		{`{"type":"object","required":["a"]}`, `{"type":"object"}`, true},
		{`{"type":"object"}`, `{"type":"object","required":["a"]}`, false},
		{`{"properties":{"a":{"type":"string","maxLength":5}}}`, `{"properties":{"a":{"type":"string","maxLength":9}}}`, true},
		{`{"properties":{"a":{"type":"string","maxLength":9}}}`, `{"properties":{"a":{"type":"string","maxLength":5}}}`, false},
		{`{"properties":{"a":{"type":"integer"}}}`, `{"properties":{"a":{"type":"number"}}}`, true},
		{`{"properties":{"a":{"type":"number"}}}`, `{"properties":{"a":{"type":"integer"}}}`, false},
		{`{"properties":{"a":{"enum":["x"]}}}`, `{"properties":{"a":{"enum":["x","y"]}}}`, true},
		{`{"properties":{"a":{"enum":["x","y"]}}}`, `{"properties":{"a":{"enum":["x"]}}}`, false},
		{`{"properties":{},"additionalProperties":false}`, `{"properties":{"b":{"type":"string"}},"additionalProperties":false}`, true},
		{`{"properties":{}}`, `{"properties":{"b":{"type":"string"}}}`, false},
		{`{"properties":{"a":{"type":"string"}}}`, `{"properties":{}}`, true},
		{`{"properties":{"a":{"type":"string"}}}`, `{"properties":{},"additionalProperties":false}`, false},
		{`{"properties":{"a":{"type":"string"}}}`, `{"properties":{"a":{"type":"string","pattern":"^x"}}}`, false},
		{`{"properties":{"a":{"minimum":0}}}`, `{"properties":{"a":{}}}`, true},
		{`{"items":{"type":"string"},"type":"array"}`, `{"type":"array"}`, true},
	}
	for _, c := range cases {
		why := widens(js(t, c.old), js(t, c.new), "$")
		if (why == "") != c.ok {
			t.Errorf("%s -> %s: got %q, want compatible=%v", c.old, c.new, why, c.ok)
		}
	}
}
