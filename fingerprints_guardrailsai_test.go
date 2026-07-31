package main

import (
	"testing"
)

// Cat-33 2026-06-23: Guardrails AI (guardrailsai.com) fingerprints.
//
// Two FPs, separated by concern:
//   1. "Guardrails AI API"                        — service-presence, sev low.
//      Anchored on the OpenAPI /api-docs description "Guardrails CRUD API".
//   2. "Guardrails AI Playground (unauth guards)" — the finding, sev high.
//      GET /guards/ returns a JSON array of every user's guard objects keyed
//      "playground-session-<provider>|<subject-id>" with NO auth, despite the
//      spec declaring security:[ApiKeyAuth,BearerAuth] on the op.
//
// Founding host: playground.api.guardrailsai.com. The prod tier
// (api.simlab.guardrailsai.com) is correctly 401 on the same paths; the
// playground shipped without the enforcement. The tests below prove the
// exposure FP fires on the open shape and stays silent on:
//   - SPA / deception catch-all 200s that echo HTML on every path (LBot lesson)
//   - marketing pages that merely mention guardrails
//   - the hardened prod 401

func matchByName(name string, pr PortResult) bool {
	for _, fp := range Fingerprints {
		if fp.Name != name {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				return true
			}
		}
	}
	return false
}

// The real unauth /guards/ array (synthesized to the verified shape: a JSON
// array of guard objects with the playground-session key scheme + validators).
func TestGuardrailsAI_MatchesUnauthPlayground(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.5", Port: 443, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{
			"Content-Type":                "application/json",
			"Access-Control-Allow-Origin": "*",
			"Server":                      "gunicorn",
		},
		BodySnippet: `[{"id":"playground-session-github|1457","name":"playground-session-github|1457",` +
			`"description":null,"validators":[{"id":"guardrails/detect_pii"}],"output_schema":{}},` +
			`{"id":"playground-session-google-oauth2|117","name":"playground-session-google-oauth2|117",` +
			`"validators":[{"id":"guardrails/detect_prompt_injection"}],"output_schema":{}}]`,
	}
	if !matchByName("Guardrails AI Playground (unauth guards)", pr) {
		t.Fatal("playground unauth FP did not match the real /guards/ array")
	}
}

// /api-docs OpenAPI spec — identification FP fires, exposure FP must not.
func TestGuardrailsAI_IdentifiesApiDocs(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.6", Port: 443, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `{"openapi":"3.1.0","info":{"title":"Guardrails API","version":"0.0.0","description":"Guardrails CRUD API"},"paths":{"/guards":{}}}`,
	}
	if !matchByName("Guardrails AI API", pr) {
		t.Fatal("identification FP did not match /api-docs spec")
	}
	if matchByName("Guardrails AI Playground (unauth guards)", pr) {
		t.Fatal("exposure FP wrongly matched the OpenAPI spec (not a /guards/ array)")
	}
}

// SPA / deception catch-all: 200 that echoes HTML on every path. The "<html"
// body_not_contains guard must keep the exposure FP silent even if a brand
// term leaks into the markup.
func TestGuardrailsAI_RejectsCatchAllHTML(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.7", Port: 443, Open: true,
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!doctype html><html lang="en"><head><title>app</title></head>` +
			`<body>playground-session validators</body></html>`,
	}
	if matchByName("Guardrails AI Playground (unauth guards)", pr) {
		t.Fatal("exposure FP matched an HTML catch-all page (guard failed)")
	}
}

// Marketing / comparison page that mentions guardrails — must not match either FP.
func TestGuardrailsAI_RejectsMarketing(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.8", Port: 443, Open: true,
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><head><title>Guardrails CRUD API vs the rest</title></head>` +
			`<body>a blog comparing Guardrails AI validators and playground-session flows</body></html>`,
	}
	if matchByName("Guardrails AI Playground (unauth guards)", pr) {
		t.Fatal("exposure FP matched a marketing page")
	}
	// Identification FP requires the openapi json_field, so an HTML blog
	// (no parseable openapi object) must not match it either.
	if matchByName("Guardrails AI API", pr) {
		t.Fatal("identification FP matched a marketing page (no openapi field)")
	}
}

// Hardened prod tier: /guards/ returns 401. Exposure FP must stay silent.
func TestGuardrailsAI_RejectsHardenedProd401(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.9", Port: 443, Open: true,
		StatusCode:  401,
		ContentType: "text/plain",
		Headers:     map[string]string{"Content-Type": "text/plain"},
		BodySnippet: `Incorrect authentication credentials.`,
	}
	if matchByName("Guardrails AI Playground (unauth guards)", pr) {
		t.Fatal("exposure FP matched a 401 (hardened prod)")
	}
}
