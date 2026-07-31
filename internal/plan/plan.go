// Package plan parses a Terraform plan into a structured, human-readable summary.
//
// On a large repo, raw `terraform plan` output is hundreds of lines — unreadable
// for a human and expensive (and hallucination-prone) to feed to an LLM. Instead
// tfforge asks terraform for the machine-readable plan (`terraform show -json`),
// parses it here, and produces:
//   - a deterministic create/update/delete/replace tally + a grouped table
//     (what the human reads), and
//   - a compact digest the agent can reason over without swallowing the whole plan.
//
// Deterministic parsing counts; the LLM only explains. That's what lets tfforge
// scale to a big repo.
package plan

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Action is the effect on one resource, normalized from terraform's action list.
type Action string

const (
	Create  Action = "create"
	Update  Action = "update" // in-place
	Delete  Action = "delete"
	Replace Action = "replace" // delete + create
	NoOp    Action = "no-op"
	Read    Action = "read"
)

// Change is one resource's planned change.
type Change struct {
	Address string // e.g. aws_s3_bucket.data
	Type    string // e.g. aws_s3_bucket
	Action  Action
}

// Summary is the parsed plan: per-action counts + the individual changes.
type Summary struct {
	Create, Update, Delete, Replace int
	Changes                         []Change // excludes no-ops, sorted for stable output
}

// tfPlan mirrors the subset of `terraform show -json` we need.
type tfPlan struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Type    string `json:"type"`
		Change  struct {
			Actions []string `json:"actions"`
		} `json:"change"`
	} `json:"resource_changes"`
}

// Parse reads `terraform show -json` output into a Summary.
func Parse(data []byte) (*Summary, error) {
	var p tfPlan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing plan JSON: %w", err)
	}
	s := &Summary{}
	for _, rc := range p.ResourceChanges {
		act := normalize(rc.Change.Actions)
		switch act {
		case Create:
			s.Create++
		case Update:
			s.Update++
		case Delete:
			s.Delete++
		case Replace:
			s.Replace++
		default:
			continue // no-op / read: not shown
		}
		s.Changes = append(s.Changes, Change{Address: rc.Address, Type: rc.Type, Action: act})
	}
	// Sort destroys/replaces first (the risky ones a reviewer looks at first),
	// then by address for stability.
	sort.SliceStable(s.Changes, func(i, j int) bool {
		if risk(s.Changes[i].Action) != risk(s.Changes[j].Action) {
			return risk(s.Changes[i].Action) > risk(s.Changes[j].Action)
		}
		return s.Changes[i].Address < s.Changes[j].Address
	})
	return s, nil
}

// normalize collapses terraform's action list into a single Action. A
// ["delete","create"] (or the reverse) is a replace.
func normalize(actions []string) Action {
	switch {
	case len(actions) == 2:
		// A replace is exactly a delete+create pair, in either order
		// (destroy-before-create or create_before_destroy). Only that pair is a
		// replace — guard against a future/unknown 2-action combo being miscounted.
		a, b := actions[0], actions[1]
		if (a == "delete" && b == "create") || (a == "create" && b == "delete") {
			return Replace
		}
		return NoOp
	case len(actions) == 1:
		switch actions[0] {
		case "create":
			return Create
		case "update":
			return Update
		case "delete":
			return Delete
		case "read":
			return Read
		default:
			return NoOp
		}
	default:
		return NoOp
	}
}

func risk(a Action) int {
	switch a {
	case Delete:
		return 3
	case Replace:
		return 2
	case Update:
		return 1
	default:
		return 0
	}
}

// HasDestructive reports whether the plan deletes or replaces anything — the
// signal a reviewer (or the guard) cares about most.
func (s *Summary) HasDestructive() bool { return s.Delete > 0 || s.Replace > 0 }

// Total is the number of changing resources (excludes no-ops).
func (s *Summary) Total() int { return len(s.Changes) }
