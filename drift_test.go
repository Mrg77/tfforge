package main

import (
	"strings"
	"testing"
)

// The real deal: parse the STRUCTURED plan JSON (tofu show -json). A hand-added
// tag in the cloud (before has it, after/code doesn't) must be phrased from the
// cloud's point of view ("added in the cloud"), not "removed".
func TestParsePlanJSONTagAddedByHand(t *testing.T) {
	// before = real cloud state (has env=dev), after = code (no env tag).
	planJSON := `{
	  "resource_changes": [
	    {
	      "address": "aws_vpc.practice",
	      "change": {
	        "actions": ["update"],
	        "before": {"id": "vpc-1", "tags": {"Name": "practice-vpc", "env": "dev"}},
	        "after":  {"id": "vpc-1", "tags": {"Name": "practice-vpc"}}
	      }
	    }
	  ]
	}`
	got := parsePlanJSON(planJSON)
	if len(got) != 1 || got[0].Address != "aws_vpc.practice" {
		t.Fatalf("expected 1 drifted vpc, got %+v", got)
	}
	joined := strings.Join(got[0].Changes, " | ")
	if !strings.Contains(joined, `"env"`) || !strings.Contains(joined, "added in the cloud") {
		t.Errorf("hand-added tag must read as added-in-cloud, got: %q", joined)
	}
	if strings.Contains(joined, "removed") {
		t.Errorf("must NOT say 'removed' when a tag was added by hand: %q", joined)
	}
}

func TestParsePlanJSONInstanceTypeChanged(t *testing.T) {
	planJSON := `{
	  "resource_changes": [
	    {
	      "address": "aws_instance.web",
	      "change": {
	        "actions": ["update"],
	        "before": {"instance_type": "t3.large"},
	        "after":  {"instance_type": "t3.micro"}
	      }
	    }
	  ]
	}`
	got := parsePlanJSON(planJSON)
	if len(got) != 1 {
		t.Fatalf("expected 1 change, got %+v", got)
	}
	joined := strings.Join(got[0].Changes, " | ")
	if !strings.Contains(joined, "instance_type") || !strings.Contains(joined, "t3.large") {
		t.Errorf("instance_type drift not captured: %q", joined)
	}
}

func TestParsePlanJSONNoChanges(t *testing.T) {
	if got := parsePlanJSON(`{"resource_changes":[]}`); len(got) != 0 {
		t.Errorf("empty plan should yield no drift, got %+v", got)
	}
}

func TestReAWSIDMatches(t *testing.T) {
	state := `{"resources":[{"instances":[{"attributes":{"id":"vpc-0fea779eb87300979","subnet":"subnet-0451196c0ab85ca0e"}}]}]}`
	ids := map[string]bool{}
	for _, m := range reAWSID.FindAllString(state, -1) {
		ids[m] = true
	}
	for _, want := range []string{"vpc-0fea779eb87300979", "subnet-0451196c0ab85ca0e"} {
		if !ids[want] {
			t.Errorf("reAWSID missed %q", want)
		}
	}
}

func TestDriftMarkdownNoDrift(t *testing.T) {
	r := &driftReport{Dir: "terraform", Drift: driftNone}
	md := r.markdown()
	if !strings.Contains(md, "No drift") {
		t.Error("clean report should say 'No drift'")
	}
	if !strings.Contains(md, "Nothing in the cloud outside Terraform") {
		t.Error("clean report should say no unmanaged resources")
	}
}

func TestDriftMarkdownWithFindings(t *testing.T) {
	r := &driftReport{
		Dir:   "terraform",
		Drift: driftFound,
		DriftedResources: []driftedRes{
			{Address: "aws_vpc.practice", Action: "updated", Changes: []string{"tags.Environment: added prod"}},
		},
		Unmanaged: []unmanagedRes{
			{Kind: "EC2 instance", ID: "i-0abc123", Name: "hand-made"},
		},
	}
	md := r.markdown()
	for _, want := range []string{"Drift detected", "aws_vpc.practice", "updated",
		"EC2 instance", "i-0abc123", "hand-made", "not** in the state"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}
