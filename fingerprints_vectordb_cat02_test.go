package main

import "testing"

// Cat-02 Vector DB virgin re-birth, 2026-06-04.
// New FPs (Marqo, Manticore) + tightened/strengthened (Typesense, Meilisearch, Vespa).
// Discipline: a real shape passes, the FP shape refutes. See methodology Stage 7 / CLAUDE.md
// "naked single-word body_contains is unsound at population scale".

func probeByPath(name, path string) (Probe, bool) {
	for _, fp := range Fingerprints {
		if fp.Name != name {
			continue
		}
		for _, p := range fp.Probes {
			if p.Path == path {
				return p, true
			}
		}
	}
	return Probe{}, false
}

// ── Marqo (new) ──────────────────────────────────────────────────────
func TestMarqo_MatchesWelcomeRoot(t *testing.T) {
	p, ok := probeByPath("Marqo", "/")
	if !ok {
		t.Fatal("Marqo / probe missing")
	}
	pr := PortResult{
		Host: "203.0.113.10", Port: 8882, Open: true, StatusCode: 200,
		Headers: map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"message":"Welcome to Marqo","version":"2.13.0"}`,
	}
	if !matchProbe(p, pr) {
		t.Fatal("Marqo FP did not match a real 'Welcome to Marqo' root response")
	}
}

func TestMarqo_RefutesGenericFastAPI(t *testing.T) {
	p, _ := probeByPath("Marqo", "/")
	// Generic FastAPI/uvicorn root that does NOT carry the Marqo brand string.
	pr := PortResult{
		Host: "203.0.113.11", Port: 8882, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json", "Server": "uvicorn"},
		BodySnippet: `{"message":"Welcome to FastAPI","docs":"/docs"}`,
	}
	if matchProbe(p, pr) {
		t.Fatal("Marqo FP false-matched a generic FastAPI welcome page")
	}
}

// ── Manticore (new) ──────────────────────────────────────────────────
func TestManticore_MatchesPoweredByHeader(t *testing.T) {
	p, ok := probeByPath("Manticore Search", "/")
	if !ok {
		t.Fatal("Manticore / probe missing")
	}
	pr := PortResult{
		Host: "203.0.113.20", Port: 9308, Open: true, StatusCode: 200,
		Headers:     map[string]string{"X-Powered-By": "Manticore Search 6.3.0", "Content-Type": "application/json"},
		BodySnippet: `{"total":0,"error":"","warning":""}`,
	}
	if !matchProbe(p, pr) {
		t.Fatal("Manticore FP did not match X-Powered-By: Manticore Search")
	}
}

func TestManticore_RefutesWhenHeaderAbsent(t *testing.T) {
	p, _ := probeByPath("Manticore Search", "/")
	// Same generic 3-key JSON body shape but NO X-Powered-By header — must not match
	// (the body shape alone is not unique enough; the header is the anchor).
	pr := PortResult{
		Host: "203.0.113.21", Port: 9308, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"total":0,"error":"","warning":""}`,
	}
	if matchProbe(p, pr) {
		t.Fatal("Manticore FP false-matched a header-less generic JSON shape")
	}
}

// ── Typesense (tightened) ────────────────────────────────────────────
func TestTypesense_MatchesWithServerHeader(t *testing.T) {
	p, ok := probeByPath("Typesense", "/health")
	if !ok {
		t.Fatal("Typesense /health probe missing")
	}
	pr := PortResult{
		Host: "203.0.113.30", Port: 8108, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Server": "Typesense/27.1", "Content-Type": "application/json"},
		BodySnippet: `{"ok":true}`,
	}
	if !matchProbe(p, pr) {
		t.Fatal("Typesense FP did not match {\"ok\":true} + Server: Typesense")
	}
}

func TestTypesense_RefutesGenericOkHealth(t *testing.T) {
	p, _ := probeByPath("Typesense", "/health")
	// The exact naked-body FP class: a generic service whose /health returns {"ok":true}
	// but is NOT Typesense (no Server: Typesense header). Pre-tighten this matched.
	pr := PortResult{
		Host: "203.0.113.31", Port: 8108, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Server": "nginx", "Content-Type": "application/json"},
		BodySnippet: `{"ok":true}`,
	}
	if matchProbe(p, pr) {
		t.Fatal("Typesense FP false-matched a generic {\"ok\":true} health endpoint (tighten regressed)")
	}
}

// ── Meilisearch (strengthened: header probe fires even when body gated) ──
func TestMeilisearch_MatchesVersionHeaderWhenLocked(t *testing.T) {
	p, ok := probeByPath("Meilisearch", "/version")
	if !ok {
		t.Fatal("Meilisearch /version probe missing")
	}
	// Master key set: body is a 401 auth error, but X-Meilisearch-Version still present.
	pr := PortResult{
		Host: "203.0.113.40", Port: 7700, Open: true, StatusCode: 401,
		Headers:     map[string]string{"X-Meilisearch-Version": "1.10.2", "Content-Type": "application/json"},
		BodySnippet: `{"message":"The Authorization header is missing","code":"missing_authorization_header"}`,
	}
	if !matchProbe(p, pr) {
		t.Fatal("Meilisearch FP did not match via X-Meilisearch-Version header on a locked instance")
	}
}

func TestMeilisearch_RefutesWhenNoVersionHeader(t *testing.T) {
	p, _ := probeByPath("Meilisearch", "/version")
	pr := PortResult{
		Host: "203.0.113.41", Port: 7700, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"some":"other service"}`,
	}
	if matchProbe(p, pr) {
		t.Fatal("Meilisearch /version probe false-matched without the X-Meilisearch-Version header")
	}
}

// ── Vespa (strengthened: com.yahoo.vespa namespace) ──────────────────
func TestVespa_MatchesYahooNamespace(t *testing.T) {
	p, ok := probeByPath("Vespa", "/ApplicationStatus")
	if !ok {
		t.Fatal("Vespa /ApplicationStatus probe missing")
	}
	pr := PortResult{
		Host: "203.0.113.50", Port: 19071, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"handlers":[{"id":"com.yahoo.vespa.config.server.http.v2.ApplicationHandler"}]}`,
	}
	if !matchProbe(p, pr) {
		t.Fatal("Vespa FP did not match the com.yahoo.vespa namespace on /ApplicationStatus")
	}
}
