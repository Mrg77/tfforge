package main

import "testing"

func TestParseEnrichMapWholeObject(t *testing.T) {
	s := `{"0":{"fix":"Do X.","before":"a","after":"b"},"1":{"fix":"Do Y.","before":"c","after":"d"}}`
	m := parseEnrichMap(s)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m[0].Prose != "Do X." || m[0].Before != "a" || m[1].After != "d" {
		t.Errorf("fields not parsed: %+v", m)
	}
}

func TestParseEnrichMapTolueratesFences(t *testing.T) {
	s := "Here you go:\n```json\n{\"0\":{\"fix\":\"Do X.\",\"before\":\"\",\"after\":\"y\"}}\n```"
	m := parseEnrichMap(s)
	if len(m) != 1 || m[0].Prose != "Do X." {
		t.Errorf("should parse JSON inside prose/fences: %+v", m)
	}
}

// The regression that shipped a report with NO explanations: the reply hit the
// token cap and the tail JSON was cut off mid-entry. The salvage path must still
// recover every COMPLETE entry before the cut.
func TestParseEnrichMapSalvagesTruncated(t *testing.T) {
	// Two complete entries, then a third cut off mid-string (no closing }).
	s := `{"0":{"fix":"First.","before":"a","after":"b"},` +
		`"1":{"fix":"Second.","before":"c","after":"d"},` +
		`"2":{"fix":"Third but truncat`
	m := parseEnrichMap(s)
	if len(m) != 2 {
		t.Fatalf("salvage should recover the 2 complete entries, got %d: %+v", len(m), m)
	}
	if m[0].Prose != "First." || m[1].Prose != "Second." {
		t.Errorf("wrong entries salvaged: %+v", m)
	}
	if _, ok := m[2]; ok {
		t.Error("the truncated entry must NOT be included")
	}
}

func TestParseEnrichMapEmptyOnGarbage(t *testing.T) {
	for _, s := range []string{"", "no json here", "{", "}{"} {
		if m := parseEnrichMap(s); len(m) != 0 {
			t.Errorf("garbage %q should yield no entries, got %+v", s, m)
		}
	}
}

// balancedObject must respect quotes/escapes so a "}" inside a string doesn't
// close the object early.
func TestBalancedObjectRespectsStrings(t *testing.T) {
	s := `{"code":"a } b \" c"}`
	got := balancedObject(s, 0)
	if got != s {
		t.Errorf("brace inside string closed early: got %q", got)
	}
	if balancedObject(`{"x":1`, 0) != "" {
		t.Error("unterminated object should return \"\"")
	}
}
