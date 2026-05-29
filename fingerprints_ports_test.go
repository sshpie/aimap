package main

import (
	"testing"
)

// fpByName is a small test helper for the catalog-audit work.
func fpByName(name string) *Fingerprint {
	for i := range Fingerprints {
		if Fingerprints[i].Name == name {
			return &Fingerprints[i]
		}
	}
	return nil
}

// containsPort is the int-slice membership helper for DefaultPorts audits.
// Renamed from contains to avoid colliding with the string-slice contains in
// enumerators.go (added 2026-05-27 with enumArgoWorkflows), which had left the
// package test target failing to build.
func containsPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// Iter 8a: Grafana served at port 443 was filtered out because the FP
// listed only DefaultPorts:[3000]. Real-world deployments often front
// Grafana behind nginx on 80/443. Widen to include the standard HTTP
// alt ports.
func TestGrafana_DefaultPortsIncludesStandardHTTPS(t *testing.T) {
	fp := fpByName("Grafana")
	if fp == nil {
		t.Fatal("Grafana fingerprint not found")
	}
	for _, p := range []int{3000, 80, 443} {
		if !containsPort(fp.DefaultPorts, p) {
			t.Errorf("Grafana FP missing port %d in DefaultPorts (got %v)", p, fp.DefaultPorts)
		}
	}
}

// Iter 8a: Mem0 lived behind FastAPI/Swagger at port 8000 in our live
// audit, but the FP was scoped to 8888 only.
func TestMem0_DefaultPortsIncludesPort8000(t *testing.T) {
	fp := fpByName("Mem0")
	if fp == nil {
		t.Fatal("Mem0 fingerprint not found")
	}
	if !containsPort(fp.DefaultPorts, 8000) {
		t.Errorf("Mem0 FP missing port 8000 in DefaultPorts (got %v)", fp.DefaultPorts)
	}
	// Keep the original default too
	if !containsPort(fp.DefaultPorts, 8888) {
		t.Errorf("Mem0 FP must keep port 8888 in DefaultPorts (got %v)", fp.DefaultPorts)
	}
}
