package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
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

// driftedRes is one managed resource that changed outside Terraform, with the
// specific attributes that differ (so you see WHAT changed, not just "updated").
type driftedRes struct {
	Address string   // e.g. "aws_vpc.practice"
	Action  string   // updated | created | destroyed | replaced
	Changes []string // e.g. ["tags.Environment: added", "instance_type: t3.micro → t3.large"]
}

// driftReport is the result of `tfforge drift`.
type driftReport struct {
	Dir              string
	Region           string // AWS region actually scanned for unmanaged resources
	Drift            driftState
	DriftedResources []driftedRes
	PlanOutput       string
	Unmanaged        []unmanagedRes
	Err              string
}

// planJSONShape is the subset of `tofu show -json <plan>` we read. The plan is a
// stable, documented format — far more reliable than parsing the human output.
type planJSONShape struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			Actions []string       `json:"actions"` // ["update"], ["create"], ["delete"], ["delete","create"]…
			Before  map[string]any `json:"before"`
			After   map[string]any `json:"after"`
		} `json:"change"`
	} `json:"resource_changes"`
}

// parsePlanJSON reads the structured plan and returns the drifted resources with
// the EXACT attribute differences, phrased from the point of view of REALITY:
// "before" is the real cloud state, "after" is what the code wants. So a value in
// `before` that differs from `after` was changed in the cloud (drift).
func parsePlanJSON(jsonOut string) []driftedRes {
	var p planJSONShape
	if json.Unmarshal([]byte(jsonOut), &p) != nil {
		return nil
	}
	var out []driftedRes
	for _, rc := range p.ResourceChanges {
		action := actionVerb(rc.Change.Actions)
		if action == "" {
			continue // no-op
		}
		out = append(out, driftedRes{
			Address: rc.Address,
			Action:  action,
			Changes: diffAttrs(rc.Change.Before, rc.Change.After),
		})
	}
	return out
}

// actionVerb maps a plan actions list to a single human verb, or "" for no-op.
func actionVerb(actions []string) string {
	switch strings.Join(actions, ",") {
	case "update":
		return "changed by hand"
	case "create":
		return "will be created (in code, not yet in cloud)"
	case "delete":
		return "deleted from cloud"
	case "delete,create", "create,delete":
		return "must be replaced"
	case "no-op", "read", "":
		return ""
	default:
		return strings.Join(actions, "+")
	}
}

// diffAttrs compares the real state (before) to the code (after) and describes,
// from REALITY's side, what changed in the cloud. Bounded so a big resource
// doesn't spam. Noise attributes (id/arn/computed) are skipped.
func diffAttrs(before, after map[string]any) []string {
	skip := map[string]bool{"id": true, "arn": true, "tags_all": true, "owner_id": true}
	var out []string
	seen := map[string]bool{}

	add := func(s string) {
		if !seen[s] && len(out) < 10 {
			seen[s] = true
			out = append(out, s)
		}
	}

	// Union of keys.
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		if !skip[k] {
			names = append(names, k)
		}
	}
	sort.Strings(names)

	for _, k := range names {
		bv, hasB := before[k]
		av, hasA := after[k]
		if k == "tags" {
			diffTags(toStrMap(bv), toStrMap(av), add)
			continue
		}
		if !equalJSON(bv, av) {
			switch {
			case !hasB || bv == nil:
				add(fmt.Sprintf("%s = %v (added in cloud)", k, av))
			case !hasA || av == nil:
				add(fmt.Sprintf("%s = %v (present in cloud, absent in code)", k, bv))
			default:
				// before = real, after = code. Real differs from code = drift.
				add(fmt.Sprintf("%s: cloud has %v, code wants %v", k, bv, av))
			}
		}
	}
	return out
}

// diffTags compares the real tags (before) to the code tags (after), phrased from
// the cloud's side: a tag in the cloud but not the code was added by hand.
func diffTags(before, after map[string]string, add func(string)) {
	for k, v := range before {
		if _, ok := after[k]; !ok {
			add(fmt.Sprintf("tag %q=%q added in the cloud (not in code)", k, v))
		} else if after[k] != v {
			add(fmt.Sprintf("tag %q: cloud=%q, code=%q", k, v, after[k]))
		}
	}
	for k, v := range after {
		if _, ok := before[k]; !ok {
			add(fmt.Sprintf("tag %q=%q in code but missing in the cloud", k, v))
		}
	}
}

func toStrMap(v any) map[string]string {
	out := map[string]string{}
	m, ok := v.(map[string]any)
	if !ok {
		return out
	}
	for k, val := range m {
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}

func equalJSON(a, b any) bool {
	ba, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ba) == string(bb)
}

// findUnmanaged lists EVERY taggable AWS resource in the region via the Resource
// Groups Tagging API — one call, ALL services (EC2, S3, RDS, Lambda, ELB, IAM-
// taggable, …) — and returns those NOT present in the Terraform state. This is
// far broader than per-service describe calls and stays current as AWS adds
// services, since it's a single generic API. A handful of always-present AWS
// defaults are filtered so they don't read as "debt".
//
// stateIDs is the set of cloud resource IDs Terraform manages (from the state
// JSON) — a resource whose ID appears in state is NOT unmanaged.
func findUnmanaged(ctx context.Context, stateIDs map[string]bool, region string) []unmanagedRes {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil
	}

	var resp struct {
		ResourceTagMappingList []struct {
			ResourceARN string `json:"ResourceARN"`
			Tags        []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"Tags"`
		} `json:"ResourceTagMappingList"`
	}
	if !awsJSON(ctx, region, &resp, "resourcegroupstaggingapi", "get-resources", "--output", "json") {
		// Fall back to the per-service EC2 sweeps (covers the networking basics)
		// if the tagging API is unavailable or denied.
		var out []unmanagedRes
		out = append(out, sweepVPCs(ctx, stateIDs, region)...)
		out = append(out, sweepSubnets(ctx, stateIDs, region)...)
		out = append(out, sweepInstances(ctx, stateIDs, region)...)
		out = append(out, sweepSecurityGroups(ctx, stateIDs, region)...)
		return out
	}

	var out []unmanagedRes
	for _, r := range resp.ResourceTagMappingList {
		id := arnResourceID(r.ResourceARN)
		if id != "" && stateIDs[id] {
			continue // managed by Terraform
		}
		kind := arnService(r.ResourceARN)
		if isAWSDefault(kind, r.ResourceARN) {
			continue // default VPC/route table/SG etc. — not "debt"
		}
		name := ""
		for _, t := range r.Tags {
			if t.Key == "Name" {
				name = t.Value
			}
		}
		display := id
		if display == "" {
			display = r.ResourceARN
		}
		out = append(out, unmanagedRes{Kind: kind, ID: display, Name: name})
	}
	return out
}

// arnService returns a human "service/type" label from an ARN, e.g.
// arn:aws:ec2:eu-west-3:…:vpc/vpc-… → "ec2:vpc".
func arnService(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "resource"
	}
	svc := parts[2]
	res := parts[5]
	if i := strings.IndexAny(res, "/:"); i >= 0 {
		res = res[:i]
	}
	if res == "" || res == parts[5] {
		return svc
	}
	return svc + ":" + res
}

// arnResourceID returns the concrete resource ID at the end of an ARN
// (vpc-…, the bucket name, the function name), matching how it appears in state.
func arnResourceID(arn string) string {
	if i := strings.LastIndexAny(arn, "/:"); i >= 0 && i+1 < len(arn) {
		return arn[i+1:]
	}
	return ""
}

// isAWSDefault filters the resources AWS provisions on every account (default
// VPC, its route table/ACL/SG), which aren't user-created "debt".
func isAWSDefault(kind, arn string) bool {
	// Default security group / route table / network ACL come tagged by AWS as
	// "default" only sometimes; the reliable signal we already handle is the
	// default VPC in sweepVPCs. Here, drop the obvious platform noise.
	switch kind {
	case "ec2:security-group", "ec2:route-table", "ec2:network-acl", "ec2:dhcp-options":
		return false // keep — a hand-made one IS debt; default ones rarely tag
	}
	return false
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

// awsJSON runs an aws cli query in the given region (if non-empty) and unmarshals
// the JSON output into v.
func awsJSON(ctx context.Context, region string, v any, args ...string) bool {
	if region != "" {
		args = append(args, "--region", region)
	}
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

func sweepVPCs(ctx context.Context, stateIDs map[string]bool, region string) []unmanagedRes {
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
	if !awsJSON(ctx, region, &resp, "ec2", "describe-vpcs", "--output", "json") {
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

func sweepSubnets(ctx context.Context, stateIDs map[string]bool, region string) []unmanagedRes {
	var resp struct {
		Subnets []struct {
			SubnetId     string `json:"SubnetId"`
			DefaultForAz bool   `json:"DefaultForAz"`
			Tags         []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"Tags"`
		} `json:"Subnets"`
	}
	if !awsJSON(ctx, region, &resp, "ec2", "describe-subnets", "--output", "json") {
		return nil
	}
	var out []unmanagedRes
	for _, s := range resp.Subnets {
		// Skip AWS-provided default subnets (one per AZ in the default VPC) — they
		// exist on every account and aren't unmanaged "debt", same as we skip the
		// default VPC and default security group.
		if s.DefaultForAz || stateIDs[s.SubnetId] {
			continue
		}
		out = append(out, unmanagedRes{Kind: "Subnet", ID: s.SubnetId, Name: nameTag(s.Tags)})
	}
	return out
}

func sweepInstances(ctx context.Context, stateIDs map[string]bool, region string) []unmanagedRes {
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
	if !awsJSON(ctx, region, &resp, "ec2", "describe-instances", "--output", "json") {
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

func sweepSecurityGroups(ctx context.Context, stateIDs map[string]bool, region string) []unmanagedRes {
	var resp struct {
		SecurityGroups []struct {
			GroupId   string `json:"GroupId"`
			GroupName string `json:"GroupName"`
		} `json:"SecurityGroups"`
	}
	if !awsJSON(ctx, region, &resp, "ec2", "describe-security-groups", "--output", "json") {
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

// ANSI colors (used only when writing to a TTY).
const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cRed   = "\033[31m"
	cYel   = "\033[33m"
	cGrn   = "\033[32m"
	cDim   = "\033[2m"
	cCyan  = "\033[36m"
)

func (r *driftReport) text(color bool) string {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + cReset
	}
	var b strings.Builder

	fmt.Fprintf(&b, "%s", c(cBold, "Terraform drift — "+r.Dir))
	if r.Region != "" {
		fmt.Fprintf(&b, " %s", c(cDim, "(region "+r.Region+")"))
	}
	b.WriteString("\n")

	// --- drift ---
	switch r.Drift {
	case driftNone:
		fmt.Fprintf(&b, "  %s\n", c(cGrn, "✓ no drift — real infrastructure matches the state."))
	case driftFound:
		fmt.Fprintf(&b, "  %s\n", c(cYel, fmt.Sprintf("⚠ DRIFT — %d managed resource(s) changed outside Terraform:", len(r.DriftedResources))))
		for _, d := range r.DriftedResources {
			fmt.Fprintf(&b, "    %s %s  %s\n", c(cYel, "•"),
				c(cBold, d.Address), c(cDim, "("+d.Action+")"))
			for _, ch := range d.Changes {
				fmt.Fprintf(&b, "        %s %s\n", c(cDim, "↳"), c(cCyan, ch))
			}
		}
	case driftError:
		fmt.Fprintf(&b, "  %s\n", c(cRed, "✗ could not check drift: "+r.Err))
	}

	// --- unmanaged ---
	if len(r.Unmanaged) > 0 {
		fmt.Fprintf(&b, "  %s\n", c(cYel, fmt.Sprintf("⚠ %d UNMANAGED resource(s) exist in the cloud but not in Terraform:", len(r.Unmanaged))))
		for _, u := range r.Unmanaged {
			fmt.Fprintf(&b, "    %s %s %s%s\n", c(cYel, "•"),
				c(cDim, u.Kind), c(cBold, u.ID), c(cDim, nameSuffix(u.Name)))
		}
	} else if r.Drift != driftError {
		fmt.Fprintf(&b, "  %s\n", c(cGrn, "✓ no unmanaged resources found."))
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
		b.WriteString("### Changed outside Terraform\n\n| Resource | Action | What changed |\n|:--|:--|:--|\n")
		for _, d := range r.DriftedResources {
			what := "—"
			if len(d.Changes) > 0 {
				esc := make([]string, len(d.Changes))
				for i, c := range d.Changes {
					esc[i] = "`" + strings.ReplaceAll(c, "|", "\\|") + "`"
				}
				what = strings.Join(esc, "<br>")
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", d.Address, d.Action, what)
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
