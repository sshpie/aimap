package main

import (
	"testing"
)

// Iter 8d: systematic widening of DefaultPorts for user-facing AI services.
//
// Empirical motivation (Shodan, 2026-05-13):
//   Langfuse: 2,231 non-canonical-port hits
//   Flowise:  2,147
//   Airflow: 43,429
//   Superset: 9,945
//   n8n:     89,770
//   LiteLLM:  4,617
//   vLLM:       195
//   BentoML:     46
//
// All of these were filtered out by single-port DefaultPorts, so aimap
// silently missed huge fractions of each platform's deployment surface.

func TestSystematicPorts_UserFacingFPsIncludeHTTPAlts(t *testing.T) {
	cases := []struct {
		name      string
		needPorts []int
	}{
		// 80 + 443 are the common reverse-proxy fronting ports.
		// 8080 is the unprivileged-HTTP alt that many ops teams default to.
		{"Langfuse", []int{3000, 80, 443}},
		{"Flowise", []int{3000, 80, 443}},
		{"Apache Airflow", []int{8080, 80, 443}},
		{"Apache Superset", []int{8088, 80, 443, 8080}},
		{"n8n", []int{5678, 80, 443}},
		{"LiteLLM", []int{4000, 80, 443}},
		{"vLLM", []int{8000, 80, 443}},
		{"BentoML", []int{3000, 80, 443}},
	}
	for _, c := range cases {
		fp := fpByName(c.name)
		if fp == nil {
			t.Errorf("%s fingerprint not found", c.name)
			continue
		}
		for _, p := range c.needPorts {
			if !containsPort(fp.DefaultPorts, p) {
				t.Errorf("%s FP missing port %d in DefaultPorts (got %v)", c.name, p, fp.DefaultPorts)
			}
		}
	}
}
