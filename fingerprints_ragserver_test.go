package main

import "testing"

// Cat RAG-framework-server survey, 2026-06-17.
// 4 new/hardened fingerprints: LightRAG (hardened /health), llama_deploy apiserver,
// LlamaIndex Server, Hayhooks, Haystack REST API, Microsoft GraphRAG.
// Discipline: a real shape passes, the FP/catchall-200 shape refutes (Insight #6,
// CLAUDE.md "naked single-word body_contains is unsound at population scale").
// pr() and probeByPath() defined in the cat02 / gap test files.

// ── LightRAG (hardened) ──────────────────────────────────────────────
func TestLightRAG_HardenedHealth_Match(t *testing.T) {
	p, ok := probeByPath("LightRAG", "/health")
	if !ok {
		t.Fatal("LightRAG /health probe missing (hardening not applied)")
	}
	real := `{"status":"healthy","core_version":"1.2.6","api_version":"1.0","webui_title":"My RAG","auth_mode":"disabled"}`
	if !matchProbe(p, pr(9621, 200, "application/json", real)) {
		t.Fatal("LightRAG /health did not match a real health body")
	}
	// FP: a renamed WebUI / reverse-proxied health endpoint that lacks the
	// core_version+webui_title pair must NOT match.
	if matchProbe(p, pr(9621, 200, "application/json", `{"status":"healthy"}`)) {
		t.Fatal("LightRAG /health false-matched a bare healthy body")
	}
	// FP: brand reflection without the structured fields.
	if matchProbe(p, pr(9621, 200, "text/html", `<title>LightRAG</title>`)) {
		t.Fatal("LightRAG /health false-matched a brand-reflection HTML page")
	}
}

func TestLightRAG_DocsFallback_RejectsBrandReflection(t *testing.T) {
	p, ok := probeByPath("LightRAG", "/docs")
	if !ok {
		t.Fatal("LightRAG /docs fallback probe missing")
	}
	if !matchProbe(p, pr(9621, 200, "text/html", `<html><title>LightRAG</title><div id="swagger-ui"></div></html>`)) {
		t.Fatal("LightRAG /docs did not match a real Swagger page")
	}
	// Old naked shape: a page that just reflects "LightRAG" but is not Swagger.
	if matchProbe(p, pr(9621, 200, "text/html", `<html>welcome to the LightRAG project landing page</html>`)) {
		t.Fatal("LightRAG /docs false-matched a non-Swagger brand reflection")
	}
}

// ── llama_deploy apiserver ───────────────────────────────────────────
func TestLlamaDeployApiserver_Match(t *testing.T) {
	p, ok := probeByPath("llama_deploy apiserver", "/status")
	if !ok {
		t.Fatal("llama_deploy apiserver /status probe missing")
	}
	real := `{"status":"healthy","max_deployments":10,"deployments":["pipeline-a","pipeline-b"]}`
	if !matchProbe(p, pr(4501, 200, "application/json", real)) {
		t.Fatal("llama_deploy apiserver did not match a real /status body")
	}
	// FP: a generic healthy /status lacking max_deployments+deployments.
	if matchProbe(p, pr(4501, 200, "application/json", `{"status":"healthy"}`)) {
		t.Fatal("llama_deploy apiserver false-matched a bare healthy body")
	}
	// FP: has the keys but status is not healthy.
	if matchProbe(p, pr(4501, 200, "application/json", `{"status":"degraded","max_deployments":10,"deployments":[]}`)) {
		t.Fatal("llama_deploy apiserver false-matched a non-healthy status")
	}
}

// ── LlamaIndex Server (create-llama) ─────────────────────────────────
func TestLlamaIndexServer_ConfigMatch(t *testing.T) {
	p, ok := probeByPath("LlamaIndex Server", "/api/chat/config")
	if !ok {
		t.Fatal("LlamaIndex Server /api/chat/config probe missing")
	}
	real := `{"starterQuestions":["What is this doc about?"],"model":"gpt-4"}`
	if !matchProbe(p, pr(8000, 200, "application/json", real)) {
		t.Fatal("LlamaIndex Server /api/chat/config did not match real config")
	}
	// FP: generic chat config lacking starterQuestions.
	if matchProbe(p, pr(8000, 200, "application/json", `{"model":"gpt-4"}`)) {
		t.Fatal("LlamaIndex Server false-matched a generic chat config")
	}
	// FP: marketing-site reflection that mentions the brand domain.
	if matchProbe(p, pr(8000, 200, "application/json", `{"starterQuestions":[],"canonical":"https://www.llamaindex.ai/"}`)) {
		t.Fatal("LlamaIndex Server false-matched a llamaindex.ai marketing reflection")
	}
}

func TestLlamaIndexServer_DocsPairMatch(t *testing.T) {
	p, ok := probeByPath("LlamaIndex Server", "/docs")
	if !ok {
		t.Fatal("LlamaIndex Server /docs probe missing")
	}
	real := `<html>swagger spec with /api/chat and /api/files routers</html>`
	if !matchProbe(p, pr(8000, 200, "text/html", real)) {
		t.Fatal("LlamaIndex Server /docs did not match the router pair")
	}
	// FP: a generic FastAPI app exposing only /api/chat (the shared router).
	if matchProbe(p, pr(8000, 200, "text/html", `<html>swagger with only /api/chat</html>`)) {
		t.Fatal("LlamaIndex Server /docs false-matched a lone /api/chat app")
	}
}

// ── Hayhooks (Haystack) ──────────────────────────────────────────────
func TestHayhooks_Match(t *testing.T) {
	p, ok := probeByPath("Hayhooks", "/status")
	if !ok {
		t.Fatal("Hayhooks /status probe missing")
	}
	real := `{"status":"Up!","pipelines":["chat_with_website"]}`
	if !matchProbe(p, pr(1416, 200, "application/json", real)) {
		t.Fatal("Hayhooks did not match a real /status body")
	}
	// FP: a generic 'ok' health body without the Up! literal.
	if matchProbe(p, pr(1416, 200, "application/json", `{"status":"ok","pipelines":[]}`)) {
		t.Fatal("Hayhooks false-matched a generic ok/pipelines body")
	}
	// FP: has Up! token but lacks the pipelines key.
	if matchProbe(p, pr(1416, 200, "application/json", `{"status":"Up!"}`)) {
		t.Fatal("Hayhooks false-matched a body lacking pipelines")
	}
}

// ── Haystack REST API (legacy) ───────────────────────────────────────
func TestHaystackRESTAPI_Match(t *testing.T) {
	p, ok := probeByPath("Haystack REST API", "/openapi.json")
	if !ok {
		t.Fatal("Haystack REST API /openapi.json probe missing")
	}
	real := `{"openapi":"3.0.2","info":{"title":"Haystack REST API","version":"1.x"},"paths":{}}`
	if !matchProbe(p, pr(8000, 200, "application/json", real)) {
		t.Fatal("Haystack REST API did not match a real openapi.json")
	}
	// FP: a different service's openapi.json (generic title) — /initialized
	// alone must not carry the match.
	if matchProbe(p, pr(8000, 200, "application/json", `{"openapi":"3.0.2","info":{"title":"FastAPI"},"paths":{}}`)) {
		t.Fatal("Haystack REST API false-matched a generic FastAPI openapi.json")
	}
}

// ── Microsoft GraphRAG (accelerator) ─────────────────────────────────
func TestMicrosoftGraphRAG_Match(t *testing.T) {
	p, ok := probeByPath("Microsoft GraphRAG", "/manpage/openapi.json")
	if !ok {
		t.Fatal("Microsoft GraphRAG /manpage/openapi.json probe missing")
	}
	real := `{"openapi":"3.0.2","info":{"title":"GraphRAG"},"paths":{"/graph/graphml/{name}":{},"/source/report/{id}":{}}}`
	if !matchProbe(p, pr(443, 200, "application/json", real)) {
		t.Fatal("Microsoft GraphRAG did not match a real accelerator openapi.json")
	}
	// FP #1 (the big one): LightRAG self-brands as a GraphRAG server. Its
	// openapi must be EXCLUDED by the body_not_contains LightRAG/webui anti-matches.
	lightrag := `{"openapi":"3.0.2","info":{"title":"LightRAG Server API"},"paths":{"/webui":{},"/graph/graphml/{name}":{}}}`
	if matchProbe(p, pr(443, 200, "application/json", lightrag)) {
		t.Fatal("Microsoft GraphRAG false-matched a LightRAG openapi (exclusion failed)")
	}
	// FP: a generic openapi with title 'GraphRAG' but no accelerator routes.
	if matchProbe(p, pr(443, 200, "application/json", `{"info":{"title":"GraphRAG"},"paths":{}}`)) {
		t.Fatal("Microsoft GraphRAG false-matched a title-only doc lacking accelerator routes")
	}
}

func TestMicrosoftGraphRAG_SourceReportFallback(t *testing.T) {
	// The OR-fallback probe (second probe, same path) anchors on /source/report/.
	fp := fpByName("Microsoft GraphRAG")
	if fp == nil {
		t.Fatal("Microsoft GraphRAG fingerprint not registered")
	}
	real := `{"info":{"title":"GraphRAG"},"paths":{"/source/report/{id}":{}}}`
	matched := false
	for _, probe := range fp.Probes {
		if matchProbe(probe, pr(8000, 200, "application/json", real)) {
			matched = true
		}
	}
	if !matched {
		t.Fatal("Microsoft GraphRAG did not match via /source/report/ fallback route")
	}
}
