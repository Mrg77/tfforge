package tools

import "testing"

func TestRepetitionFlagged(t *testing.T) {
	// 4 identical resource types, no loop → should suggest for_each.
	src := ""
	for i := 0; i < 4; i++ {
		src += `resource "datadog_monitor" "m` + string(rune('a'+i)) + `" {}` + "\n"
	}
	fs := findingsFor(t, src)
	if !hasCategory(fs, CatStructure, "for_each") {
		t.Error("4 repeated resources with no loop should be flagged as structure/DRY")
	}
}

func TestRepetitionQuietUnderThreshold(t *testing.T) {
	// 3 is below the >=4 threshold — don't nag.
	src := `resource "aws_instance" "a" {}
resource "aws_instance" "b" {}
resource "aws_instance" "c" {}`
	fs := findingsFor(t, src)
	if hasCategory(fs, CatStructure, "for_each") {
		t.Error("3 resources is under threshold; should NOT be flagged")
	}
}

func TestRepetitionQuietWhenForEachUsed(t *testing.T) {
	// Author already uses for_each → they know the idiom, stay silent even with
	// many resources.
	src := `resource "datadog_monitor" "loop" {
  for_each = var.monitors
}
resource "datadog_monitor" "a" {}
resource "datadog_monitor" "b" {}
resource "datadog_monitor" "c" {}
resource "datadog_monitor" "d" {}`
	fs := findingsFor(t, src)
	if hasCategory(fs, CatStructure, "for_each") {
		t.Error("a module already using for_each should not be nagged about repetition")
	}
}

func TestRepetitionPerTypeNotGlobalLoop(t *testing.T) {
	// A for_each on ONE resource type must NOT silence repetition of a DIFFERENT
	// type (the P2 hardening fix). 4 copy-pasted datadog_monitor + an unrelated
	// looped resource → the monitors must still be flagged.
	src := `resource "aws_instance" "looped" {
  for_each = var.nodes
}
resource "datadog_monitor" "a" {
  query = "x"
}
resource "datadog_monitor" "b" {
  query = "x"
}
resource "datadog_monitor" "c" {
  query = "x"
}
resource "datadog_monitor" "d" {
  query = "x"
}`
	fs := findingsFor(t, src)
	if !hasCategory(fs, CatStructure, `"datadog_monitor"`) {
		t.Error("a for_each on an unrelated type must not silence repetition of datadog_monitor")
	}
}

func TestRepetitionQuietWhenThisTypeLoops(t *testing.T) {
	// If THIS type already uses for_each in one of its blocks, stay quiet.
	src := `resource "datadog_monitor" "loop" {
  for_each = var.monitors
}
resource "datadog_monitor" "a" { query = "x" }
resource "datadog_monitor" "b" { query = "x" }
resource "datadog_monitor" "c" { query = "x" }`
	fs := findingsFor(t, src)
	if hasCategory(fs, CatStructure, `"datadog_monitor"`) {
		t.Error("a type already using for_each should not be nagged")
	}
}

func TestUntypedVariableFlagged(t *testing.T) {
	src := `variable "region" {
  default = "eu-west-par"
}`
	fs := findingsFor(t, src)
	if !hasCategory(fs, CatVariables, "no type") {
		t.Error("a variable without a type should be flagged")
	}
}

func TestUndescribedVariableFlagged(t *testing.T) {
	src := `variable "region" {
  type = string
}`
	fs := findingsFor(t, src)
	if !hasCategory(fs, CatVariables, "no description") {
		t.Error("a variable without a description should be flagged")
	}
}

func TestWellFormedVariableIsQuiet(t *testing.T) {
	// Typed AND described → no variable findings at all.
	src := `variable "region" {
  type        = string
  description = "OVH region for all resources"
  default     = "eu-west-par"
}`
	fs := findingsFor(t, src)
	for _, f := range fs {
		if f.Category == CatVariables {
			t.Errorf("a typed, described variable produced a finding: %s", f.Message)
		}
	}
}
