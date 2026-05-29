package main

import (
	"testing"
)

// Offline parser tests for the Kubecost/OpenCost cost-model enumerator.
// Bodies are real captures from the FinOps cost-model survey (kc5-aws).
// No live host contact — pure parsing of the captured JSON.

// Captured /model/clusterInfo body (real, from the survey).
const captClusterInfo = `{"code":200,"status":"success","data":{"account":"","clusterProfile":"production","errorReporting":"true","id":"kc5-aws","logCollection":"true","name":"kc5-aws","productAnalytics":"false","provider":"AWS","provisioner":"EKS","region":"us-east-2","remoteReadEnabled":"false","thanosEnabled":"false","valuesReporting":"true","version":"1.33"}}`

// Representative /model/allocation body aggregated by namespace.
const captAllocation = `{"code":200,"data":[{"kube-system":{"properties":{"cluster":"kc5-aws","namespace":"kube-system"},"totalCost":1.23},"monitoring":{"properties":{"cluster":"kc5-aws"},"totalCost":4.56}}]}`

// ── parseClusterInfo ──────────────────────────────────────────────────────────

func TestParseClusterInfo_Canonical(t *testing.T) {
	ci := parseClusterInfo([]byte(captClusterInfo))
	if ci == nil {
		t.Fatalf("expected a parsed clusterInfo, got nil")
	}
	if ci.ID != "kc5-aws" {
		t.Errorf("id: want kc5-aws, got %q", ci.ID)
	}
	if ci.Provider != "AWS" {
		t.Errorf("provider: want AWS, got %q", ci.Provider)
	}
	if ci.Provisioner != "EKS" {
		t.Errorf("provisioner: want EKS, got %q", ci.Provisioner)
	}
	if ci.Region != "us-east-2" {
		t.Errorf("region: want us-east-2, got %q", ci.Region)
	}
	if ci.Profile != "production" {
		t.Errorf("profile: want production, got %q", ci.Profile)
	}
	if ci.Version != "1.33" {
		t.Errorf("version: want 1.33, got %q", ci.Version)
	}
}

func TestParseClusterInfo_RejectsBare200(t *testing.T) {
	// #52: a bare 200 with no cost-model shape must NOT parse as clusterInfo.
	cases := []string{
		`{"status":"ok"}`,                           // health endpoint, no code/data
		`{"code":200,"data":{}}`,                    // envelope but no cluster discriminators
		`{"code":404,"data":{"provisioner":"EKS"}}`, // wrong code
		`<html><body>200 OK</body></html>`,          // HTML, not JSON
		``,                                          // empty
	}
	for _, body := range cases {
		if ci := parseClusterInfo([]byte(body)); ci != nil {
			t.Errorf("body %q should not parse, got %+v", body, ci)
		}
	}
}

// ── parseAllocation ───────────────────────────────────────────────────────────

func TestParseAllocation_Canonical(t *testing.T) {
	a := parseAllocation([]byte(captAllocation))
	if a == nil {
		t.Fatalf("expected a parsed allocation, got nil")
	}
	// Namespaces are sorted for determinism: kube-system, monitoring.
	want := []string{"kube-system", "monitoring"}
	if a.Count != len(want) {
		t.Fatalf("namespace_count: want %d, got %d (%v)", len(want), a.Count, a.Namespaces)
	}
	for i, w := range want {
		if a.Namespaces[i] != w {
			t.Errorf("namespace[%d]: want %q, got %q", i, w, a.Namespaces[i])
		}
	}
	// Aggregate cost = 1.23 + 4.56 = 5.79 (float tolerance).
	if a.AggCost < 5.789 || a.AggCost > 5.791 {
		t.Errorf("agg_cost: want ~5.79, got %v", a.AggCost)
	}
	if a.Cluster != "kc5-aws" {
		t.Errorf("cluster: want kc5-aws, got %q", a.Cluster)
	}
}

func TestParseAllocation_RejectsBare200(t *testing.T) {
	// #52: shape gate. Bare/empty/non-cost responses must not parse.
	cases := []string{
		`{"code":200,"data":[]}`,         // empty data array → no namespaces
		`{"code":200,"data":[{}]}`,       // window present but no namespaces
		`{"status":"ok"}`,                // no code/data
		`{"code":500,"data":[{"x":{}}]}`, // wrong code
		`not json`,
		``,
	}
	for _, body := range cases {
		if a := parseAllocation([]byte(body)); a != nil {
			t.Errorf("body %q should not parse, got %+v", body, a)
		}
	}
}

func TestParseAllocation_MissingTotalCostStillCounts(t *testing.T) {
	// A namespace window with no totalCost must still be counted as a name; the
	// aggregate cost simply omits it (NAMES are the finding evidence, #41).
	body := `{"code":200,"data":[{"alpha":{"properties":{"cluster":"c1"}},"beta":{"totalCost":2.0}}]}`
	a := parseAllocation([]byte(body))
	if a == nil {
		t.Fatalf("expected parse, got nil")
	}
	if a.Count != 2 {
		t.Fatalf("want 2 namespaces, got %d (%v)", a.Count, a.Namespaces)
	}
	if a.AggCost < 1.999 || a.AggCost > 2.001 {
		t.Errorf("agg_cost: want ~2.0, got %v", a.AggCost)
	}
}

// ── costPostureFinding tiering (#37 severity wiring) ───────────────────────────

func TestCostPostureFinding_Tiering(t *testing.T) {
	cases := []struct {
		auth        string
		dataExposed bool
		wantSev     string
	}{
		{"OPEN_API", true, "high"},             // open API + data exposed
		{"OPEN_API", false, "medium"},          // open API, no data
		{"required (HTTP 403)", false, "info"}, // gated
		{"unknown", false, "info"},             // UI-only / not confirmed open
	}
	for _, tc := range cases {
		f := costPostureFinding(tc.auth, tc.dataExposed, "Kubecost")
		if f.Severity != tc.wantSev {
			t.Errorf("auth=%q data=%v: want severity %q, got %q",
				tc.auth, tc.dataExposed, tc.wantSev, f.Severity)
		}
	}
}
