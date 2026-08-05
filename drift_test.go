package main

import (
	"strings"
	"testing"
)

func TestParseChangedResources(t *testing.T) {
	plan := `OpenTofu will perform the following actions:

  # aws_vpc.practice will be updated in-place
  ~ resource "aws_vpc" "practice" {}

  # aws_subnet.public will be destroyed
  - resource "aws_subnet" "public" {}

  # aws_instance.web will be replaced
Plan: 0 to add, 1 to change, 2 to destroy.`
	got := parseChangedResources(plan)
	want := map[string]bool{
		"aws_vpc.practice (updated)":    true,
		"aws_subnet.public (destroyed)": true,
		"aws_instance.web (replaced)":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d changed resources, got %d: %v", len(want), len(got), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected changed resource: %q", g)
		}
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
		Dir:              "terraform",
		Drift:            driftFound,
		DriftedResources: []string{"aws_vpc.practice (updated)"},
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
