package main

import "testing"

func TestSplitDirAndFlags(t *testing.T) {
	cases := []struct {
		args    []string
		wantDir string
		wantN   int // len(rest)
	}{
		{[]string{"mydir"}, "mydir", 0},
		{[]string{"mydir", "--json"}, "mydir", 1},
		{[]string{"--json", "mydir"}, "mydir", 1},
		{[]string{"mydir", "--fail-on", "high"}, "mydir", 2},
		{[]string{"--fail-on", "critical", "mydir", "--json"}, "mydir", 3},
		{[]string{}, "", 0},
	}
	for _, c := range cases {
		dir, rest := splitDirAndFlags(c.args)
		if dir != c.wantDir {
			t.Errorf("splitDirAndFlags(%v) dir = %q, want %q", c.args, dir, c.wantDir)
		}
		if len(rest) != c.wantN {
			t.Errorf("splitDirAndFlags(%v) rest = %v (len %d), want len %d", c.args, rest, len(rest), c.wantN)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high", "critical", "none"} {
		if _, ok := parseSeverity(s); !ok {
			t.Errorf("parseSeverity(%q) should be valid", s)
		}
	}
	if _, ok := parseSeverity("bogus"); ok {
		t.Error("parseSeverity(bogus) should be invalid")
	}
}
