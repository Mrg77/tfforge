package plan

import (
	"strings"
	"testing"
)

// a small but representative `terraform show -json` payload covering every
// action, including a replace (["delete","create"]) and a no-op.
const samplePlan = `{
  "resource_changes": [
    {"address":"aws_s3_bucket.data","type":"aws_s3_bucket","change":{"actions":["create"]}},
    {"address":"aws_iam_role.app","type":"aws_iam_role","change":{"actions":["update"]}},
    {"address":"aws_instance.old","type":"aws_instance","change":{"actions":["delete"]}},
    {"address":"aws_db_instance.db","type":"aws_db_instance","change":{"actions":["delete","create"]}},
    {"address":"aws_vpc.main","type":"aws_vpc","change":{"actions":["no-op"]}}
  ]
}`

func TestParseCounts(t *testing.T) {
	s, err := Parse([]byte(samplePlan))
	if err != nil {
		t.Fatal(err)
	}
	if s.Create != 1 || s.Update != 1 || s.Delete != 1 || s.Replace != 1 {
		t.Errorf("counts wrong: create=%d update=%d delete=%d replace=%d", s.Create, s.Update, s.Delete, s.Replace)
	}
	if s.Total() != 4 { // no-op excluded
		t.Errorf("Total should exclude no-ops; got %d", s.Total())
	}
	if !s.HasDestructive() {
		t.Error("HasDestructive should be true (a delete and a replace present)")
	}
}

func TestReplaceDetection(t *testing.T) {
	s, _ := Parse([]byte(samplePlan))
	var db *Change
	for i := range s.Changes {
		if s.Changes[i].Address == "aws_db_instance.db" {
			db = &s.Changes[i]
		}
	}
	if db == nil || db.Action != Replace {
		t.Fatalf(`["delete","create"] should normalize to Replace, got %v`, db)
	}
}

func TestReplaceOrderIndependent(t *testing.T) {
	// create_before_destroy emits ["create","delete"]; the default emits
	// ["delete","create"]. Both are a Replace, counted once.
	for _, p := range []string{
		`{"resource_changes":[{"address":"x.y","type":"x","change":{"actions":["create","delete"]}}]}`,
		`{"resource_changes":[{"address":"x.y","type":"x","change":{"actions":["delete","create"]}}]}`,
	} {
		s, _ := Parse([]byte(p))
		if s.Replace != 1 || s.Delete != 0 || s.Create != 0 {
			t.Errorf("both orders should be one Replace; got c=%d d=%d r=%d for %s", s.Create, s.Delete, s.Replace, p)
		}
	}
	// An unknown 2-action combo must NOT be miscounted as a replace.
	s, _ := Parse([]byte(`{"resource_changes":[{"address":"x.y","type":"x","change":{"actions":["create","update"]}}]}`))
	if s.Replace != 0 {
		t.Errorf("an unknown 2-action combo must not become a Replace; got r=%d", s.Replace)
	}
}

func TestDestructiveSortedFirst(t *testing.T) {
	s, _ := Parse([]byte(samplePlan))
	// The first change must be a destroy or replace (risk-first ordering), so a
	// reviewer sees the dangerous ones at the top of a big plan.
	first := s.Changes[0].Action
	if first != Delete && first != Replace {
		t.Errorf("expected a destructive change first, got %v", first)
	}
}

func TestDigestMentionsDestroyed(t *testing.T) {
	s, _ := Parse([]byte(samplePlan))
	d := s.Digest()
	if !strings.Contains(d, "aws_instance.old") {
		t.Errorf("digest should name the destroyed resource; got:\n%s", d)
	}
	if !strings.Contains(d, "1 to create") || !strings.Contains(d, "1 to destroy") {
		t.Errorf("digest counts wrong:\n%s", d)
	}
}

func TestTableNoColorForPipe(t *testing.T) {
	s, _ := Parse([]byte(samplePlan))
	out := s.Table(40, false)
	if strings.Contains(out, "\033[") {
		t.Error("Table(colorize=false) must not emit ANSI codes")
	}
	if !strings.Contains(out, "will be destroyed or replaced") {
		t.Error("Table should warn about destructive changes")
	}
}

func TestEmptyPlan(t *testing.T) {
	s, err := Parse([]byte(`{"resource_changes":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Total() != 0 || s.HasDestructive() {
		t.Error("empty plan should have no changes and nothing destructive")
	}
	if !strings.Contains(s.Table(40, false), "no changes") {
		t.Error("empty plan table should say 'no changes'")
	}
}

func TestBigPlanTruncates(t *testing.T) {
	// Build a plan with 100 creates; the table must cap the per-resource list
	// and fall back to a by-type summary.
	var b strings.Builder
	b.WriteString(`{"resource_changes":[`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"address":"aws_s3_bucket.b`)
		b.WriteString(strings.Repeat("x", 1)) // keep addresses distinct enough
		b.WriteString(itoa(i))
		b.WriteString(`","type":"aws_s3_bucket","change":{"actions":["create"]}}`)
	}
	b.WriteString(`]}`)
	s, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if s.Create != 100 {
		t.Fatalf("expected 100 creates, got %d", s.Create)
	}
	out := s.Table(40, false)
	if !strings.Contains(out, "more") {
		t.Error("a 100-resource plan should be truncated with a '… and N more' line")
	}
	if !strings.Contains(out, "aws_s3_bucket × 100") {
		t.Error("truncated plan should show a by-type rollup")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
