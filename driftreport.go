package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type driftState int

const (
	driftNone driftState = iota
	driftFound
	driftError
)

// unmanagedRes is a real cloud resource that isn't in the Terraform state.
type unmanagedRes struct {
	Kind string // "VPC", "Subnet", "EC2 instance", "Security group"
	ID   string // the cloud ID (vpc-…, i-…)
	Name string // Name tag if present
}

// driftReport is the result of `tfforge drift`.
type driftReport struct {
	Dir              string
	Drift            driftState
	DriftedResources []string // resource addresses that changed
	PlanOutput       string
	Unmanaged        []unmanagedRes
	Err              string
}

// reChanged matches a "  # aws_x.y will be updated/created/destroyed" line in a
// plan, to list which resources drifted.
var reChanged = regexp.MustCompile(`(?m)^\s*#\s+([a-z0-9_.\["\]-]+)\s+will be\s+(updated|created|destroyed|replaced)`)

func parseChangedResources(planOut string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reChanged.FindAllStringSubmatch(planOut, -1) {
		addr := m[1] + " (" + m[2] + ")"
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// findUnmanaged lists real AWS resources (via aws cli) and returns those NOT
// present in the Terraform state. It covers the core networking/compute types a
// practice repo uses; add services here as needed. Requires the aws cli + creds
// (in CI these come from the OIDC role). If the cli is absent or a call fails,
// that resource type is skipped silently (best-effort, never blocks drift).
//
// stateIDs is the set of cloud resource IDs Terraform manages (from the state
// JSON) — a resource whose ID is in this set is NOT unmanaged.
func findUnmanaged(ctx context.Context, stateIDs map[string]bool) []unmanagedRes {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil
	}
	var out []unmanagedRes
	out = append(out, sweepVPCs(ctx, stateIDs)...)
	out = append(out, sweepSubnets(ctx, stateIDs)...)
	out = append(out, sweepInstances(ctx, stateIDs)...)
	out = append(out, sweepSecurityGroups(ctx, stateIDs)...)
	return out
}

// managedCloudIDs returns every cloud resource ID Terraform manages, extracted
// from `tofu show -json` (the full state). Robust across resource types: an "id"
// like "vpc-…" / "subnet-…" / "i-…" appears in each resource's attributes, so a
// simple scan of all string values that look like AWS IDs is enough to avoid
// flagging a managed resource as unmanaged.
func managedCloudIDs(ctx context.Context, bin, dir string) map[string]bool {
	ids := map[string]bool{}
	out, err := runTF(ctx, bin, dir, "show", "-json")
	if err != nil {
		return ids
	}
	// Pull every AWS-looking ID out of the state JSON (vpc-…, subnet-…, i-…,
	// sg-…, etc.). We don't need to parse the tree — any occurrence means managed.
	for _, m := range reAWSID.FindAllString(out, -1) {
		ids[m] = true
	}
	return ids
}

// reAWSID matches common AWS resource IDs (type prefix + hex).
var reAWSID = regexp.MustCompile(`\b(?:vpc|subnet|sg|i|igw|rtb|acl|eni|vol|ami|nat)-[0-9a-f]{8,}\b`)

// awsJSON runs an aws cli query and unmarshals the JSON output into v.
func awsJSON(ctx context.Context, v any, args ...string) bool {
	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return json.Unmarshal(out, v) == nil
}

func nameTag(tags []struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}) string {
	for _, t := range tags {
		if t.Key == "Name" {
			return t.Value
		}
	}
	return ""
}

func sweepVPCs(ctx context.Context, stateIDs map[string]bool) []unmanagedRes {
	var resp struct {
		Vpcs []struct {
			VpcId     string `json:"VpcId"`
			IsDefault bool   `json:"IsDefault"`
			Tags      []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"Tags"`
		} `json:"Vpcs"`
	}
	if !awsJSON(ctx, &resp, "ec2", "describe-vpcs", "--output", "json") {
		return nil
	}
	var out []unmanagedRes
	for _, v := range resp.Vpcs {
		if v.IsDefault || stateIDs[v.VpcId] {
			continue // default VPC and state-managed ones aren't "unmanaged debt"
		}
		out = append(out, unmanagedRes{Kind: "VPC", ID: v.VpcId, Name: nameTag(v.Tags)})
	}
	return out
}

func sweepSubnets(ctx context.Context, stateIDs map[string]bool) []unmanagedRes {
	var resp struct {
		Subnets []struct {
			SubnetId string `json:"SubnetId"`
			Tags     []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"Tags"`
		} `json:"Subnets"`
	}
	if !awsJSON(ctx, &resp, "ec2", "describe-subnets", "--output", "json") {
		return nil
	}
	var out []unmanagedRes
	for _, s := range resp.Subnets {
		if stateIDs[s.SubnetId] {
			continue
		}
		out = append(out, unmanagedRes{Kind: "Subnet", ID: s.SubnetId, Name: nameTag(s.Tags)})
	}
	return out
}

func sweepInstances(ctx context.Context, stateIDs map[string]bool) []unmanagedRes {
	var resp struct {
		Reservations []struct {
			Instances []struct {
				InstanceId string `json:"InstanceId"`
				State      struct {
					Name string `json:"Name"`
				} `json:"State"`
				Tags []struct {
					Key   string `json:"Key"`
					Value string `json:"Value"`
				} `json:"Tags"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if !awsJSON(ctx, &resp, "ec2", "describe-instances", "--output", "json") {
		return nil
	}
	var out []unmanagedRes
	for _, r := range resp.Reservations {
		for _, i := range r.Instances {
			if i.State.Name == "terminated" || stateIDs[i.InstanceId] {
				continue
			}
			out = append(out, unmanagedRes{Kind: "EC2 instance", ID: i.InstanceId, Name: nameTag(i.Tags)})
		}
	}
	return out
}

func sweepSecurityGroups(ctx context.Context, stateIDs map[string]bool) []unmanagedRes {
	var resp struct {
		SecurityGroups []struct {
			GroupId   string `json:"GroupId"`
			GroupName string `json:"GroupName"`
		} `json:"SecurityGroups"`
	}
	if !awsJSON(ctx, &resp, "ec2", "describe-security-groups", "--output", "json") {
		return nil
	}
	var out []unmanagedRes
	for _, g := range resp.SecurityGroups {
		if g.GroupName == "default" || stateIDs[g.GroupId] {
			continue
		}
		out = append(out, unmanagedRes{Kind: "Security group", ID: g.GroupId, Name: g.GroupName})
	}
	return out
}

// --- rendering --------------------------------------------------------------

func (r *driftReport) text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Terraform drift — %s\n", r.Dir)
	switch r.Drift {
	case driftNone:
		b.WriteString("  ✓ no drift — real infrastructure matches the state.\n")
	case driftFound:
		fmt.Fprintf(&b, "  ⚠ DRIFT — %d managed resource(s) changed outside Terraform:\n", len(r.DriftedResources))
		for _, d := range r.DriftedResources {
			fmt.Fprintf(&b, "    • %s\n", d)
		}
	case driftError:
		fmt.Fprintf(&b, "  ✗ could not check drift: %s\n", r.Err)
	}
	if len(r.Unmanaged) > 0 {
		fmt.Fprintf(&b, "  ⚠ %d UNMANAGED resource(s) exist in the cloud but not in Terraform:\n", len(r.Unmanaged))
		for _, u := range r.Unmanaged {
			fmt.Fprintf(&b, "    • %s %s%s\n", u.Kind, u.ID, nameSuffix(u.Name))
		}
	} else if r.Drift != driftError {
		b.WriteString("  ✓ no unmanaged resources found in the swept services.\n")
	}
	return b.String()
}

func (r *driftReport) markdown() string {
	var b strings.Builder
	b.WriteString("# 🔎 tfforge — drift & unmanaged resources\n\n")

	switch r.Drift {
	case driftNone:
		b.WriteString("> 🟢 **No drift** — the real infrastructure matches the Terraform state.\n\n")
	case driftFound:
		fmt.Fprintf(&b, "> 🟡 **Drift detected** — %d managed resource(s) changed outside Terraform.\n\n", len(r.DriftedResources))
		b.WriteString("### Changed outside Terraform\n\n| Resource | Change |\n|:--|:--|\n")
		for _, d := range r.DriftedResources {
			addr, kind := d, ""
			if i := strings.LastIndex(d, " ("); i > 0 {
				addr, kind = d[:i], strings.Trim(d[i:], " ()")
			}
			fmt.Fprintf(&b, "| `%s` | %s |\n", addr, kind)
		}
		b.WriteString("\n")
	case driftError:
		fmt.Fprintf(&b, "> 🔴 **Could not check drift** — %s\n\n", r.Err)
	}

	b.WriteString("### Unmanaged resources\n\n")
	if len(r.Unmanaged) == 0 {
		b.WriteString("> ✅ Nothing in the cloud outside Terraform (for the swept services).\n\n")
	} else {
		fmt.Fprintf(&b, "> 🟡 **%d resource(s)** exist in AWS but are **not** in the state — created by hand and never imported.\n\n", len(r.Unmanaged))
		b.WriteString("| Kind | ID | Name |\n|:--|:--|:--|\n")
		for _, u := range r.Unmanaged {
			name := u.Name
			if name == "" {
				name = "—"
			}
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", u.Kind, u.ID, name)
		}
		b.WriteString("\n")
	}

	b.WriteString("<sub>tfforge · drift via `tofu plan`, unmanaged via AWS API · deterministic, no LLM</sub>\n")
	return b.String()
}

func nameSuffix(name string) string {
	if name == "" {
		return ""
	}
	return " (" + name + ")"
}
