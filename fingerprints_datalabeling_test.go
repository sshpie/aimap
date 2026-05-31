package main

import "testing"

// Data-labeling fingerprint fixes (2026-05-31), from the Stage -1 OSINT pass:
// CVAT anti-IAP-FP, Prodigy anti-name-collision, Argilla v2 path, doccano
// health anchor. Reuses meshProbe/meshJSON helpers (fingerprints_servicemesh_test.go).

func TestCVAT_AboutMatches(t *testing.T) {
	p := meshProbe(t, "CVAT", "/api/server/about")
	body := `{"name":"Computer Vision Annotation Tool","version":"2.20.0","description":""}`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("CVAT /api/server/about did not match the real about JSON")
	}
}

func TestCVAT_RejectsIAPCatchall(t *testing.T) {
	// GCP IAP catch-all: HTML 200 mentioning cvat, NOT the vnd.cvat+json object.
	p := meshProbe(t, "CVAT", "/api/server/about")
	html := `<!doctype html><html><head><title>Sign in - Google Accounts</title></head><body>cvat.example.com requires sign-in</body></html>`
	if matchProbe(p, meshJSON(html)) {
		t.Fatal("CVAT matched a GCP-IAP HTML catch-all (the reference_aimap_cvat_iap_fp bug)")
	}
}

func TestProdigy_HealthMatches(t *testing.T) {
	p := meshProbe(t, "Prodigy", "/health")
	if !matchProbe(p, meshJSON(`{"status":"alive"}`)) {
		t.Fatal("Prodigy /health did not match the alive status")
	}
}

func TestProdigy_RejectsBandTitle(t *testing.T) {
	// Name collision: a Prodigy band/music page must NOT match the root probe,
	// which now requires the prodigy.js bundle, not a bare <title>Prodigy</title>.
	p := meshProbe(t, "Prodigy", "/")
	html := `<!doctype html><html><head><title>Prodigy</title></head><body>The Prodigy official site</body></html>`
	if matchProbe(p, meshJSON(html)) {
		t.Fatal("Prodigy root probe over-matched a band page (name-collision FP)")
	}
}

func TestArgilla_V2VersionMatches(t *testing.T) {
	p := meshProbe(t, "Argilla", "/api/v1/version")
	if !matchProbe(p, meshJSON(`{"version":"2.4.0"}`)) {
		t.Fatal("Argilla /api/v1/version did not match")
	}
}

func TestDoccano_RootMatches(t *testing.T) {
	p := meshProbe(t, "Doccano", "/")
	html := `<!doctype html><html><head><title>doccano</title></head><body><div id="app">doccano</div></body></html>`
	if !matchProbe(p, meshJSON(html)) {
		t.Fatal("Doccano root probe did not match the doccano SPA")
	}
}

func TestDoccano_RejectsBareHealthStatus(t *testing.T) {
	// Regression: doccano must NOT be identified by a bare /v1/health {"status":...}
	// probe — that false-positived on Label Studio hosts in the 2026-05-31 survey.
	fp := fpByName("Doccano")
	if fp == nil {
		t.Fatal("Doccano fingerprint not found")
	}
	for _, pr := range fp.Probes {
		if pr.Path == "/v1/health" {
			t.Error("Doccano must not use /v1/health as an identity probe (FPs on Label Studio /v1/health)")
		}
	}
}

func TestLabelStudio_VersionMatches(t *testing.T) {
	p := meshProbe(t, "Label Studio", "/api/version")
	body := `{"release":"1.13.1","label-studio-os-package":{"version":"1.13.1"},"edition":"Community"}`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Label Studio /api/version did not match")
	}
}
