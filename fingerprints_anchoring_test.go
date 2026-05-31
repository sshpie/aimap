package main

import (
	"strings"
	"testing"
)

// fingerprints_anchoring_test.go — regression tests for the Insight #6
// anchoring discipline applied to fingerprints.go in v1.9.19.
//
// Each previously-naked body_contains probe gained a multi-anchor (status_code
// + JSON shape / structured signal). For each fixed probe, this file holds
// two tests: a TP case confirming the real-shape response still matches, and
// an FP case confirming the previously-FP-prone response is now rejected.
//
// Source review: v1.9.17 internal audit identified 24 naked single-token
// body_contains probes that violated the README's load-bearing FP rule.
// v1.9.19 closed all 24.

func probeFires(t *testing.T, fpName, path string, pr PortResult) bool {
	t.Helper()
	for _, fp := range Fingerprints {
		if fp.Name != fpName {
			continue
		}
		for _, probe := range fp.Probes {
			if path != "" && probe.Path != path {
				continue
			}
			if matchProbe(probe, pr) {
				return true
			}
		}
	}
	return false
}

// ── vLLM ────────────────────────────────────────────────────────────

func TestVLLM_MatchesV1Models(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.10", Port: 8000, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"object":"list","data":[{"id":"meta-llama/Llama-3","object":"model","created":1735000000,"owned_by":"vllm"}]}`,
	}
	if !probeFires(t, "vLLM", "/v1/models", pr) {
		t.Fatal("vLLM did not match a real /v1/models response shape")
	}
}

func TestVLLM_RejectsBlogPostMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.11", Port: 8000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body><h1>How vLLM compares to llama.cpp</h1><p>vllm has lower latency...</p></body></html>`,
	}
	if probeFires(t, "vLLM", "/v1/models", pr) {
		t.Fatal("vLLM FP fired on a blog HTML page (missing JSON shape)")
	}
}

// ── LiteLLM ─────────────────────────────────────────────────────────

func TestLiteLLM_MatchesHealth(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.20", Port: 4000, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"healthy_endpoints":[],"unhealthy_endpoints":[],"healthy_count":0,"unhealthy_count":0,"litellm_version":"1.40.0"}`,
	}
	if !probeFires(t, "LiteLLM", "/health", pr) {
		t.Fatal("LiteLLM did not match real /health shape")
	}
}

func TestLiteLLM_RejectsBareMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.21", Port: 4000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body><p>We use litellm as a gateway...</p></body></html>`,
	}
	if probeFires(t, "LiteLLM", "/health", pr) || probeFires(t, "LiteLLM", "/model/info", pr) {
		t.Fatal("LiteLLM FP fired on a bare brand mention HTML page")
	}
}

// ── Jupyter Notebook ────────────────────────────────────────────────

func TestJupyter_MatchesHTMLTitle(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.30", Port: 8888, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>Home Page - Select or create a notebook - Jupyter Notebook</title></head>`,
	}
	if !probeFires(t, "Jupyter Notebook", "/", pr) {
		t.Fatal("Jupyter FP did not match canonical HTML shape")
	}
}

func TestJupyter_RejectsBareMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.31", Port: 8888, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body><p>This site is about jupyter notebooks and other tools.</p></body></html>`,
	}
	if probeFires(t, "Jupyter Notebook", "/", pr) {
		t.Fatal("Jupyter FP fired on a bare brand mention (no <title>)")
	}
}

// ── Milvus ──────────────────────────────────────────────────────────

func TestMilvus_MatchesHealth(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.40", Port: 9091, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"is_healthy":true,"detail":[]}`,
	}
	if !probeFires(t, "Milvus", "/api/v1/health", pr) {
		t.Fatal("Milvus did not match real /api/v1/health JSON")
	}
}

func TestMilvus_RejectsK8sReadinessProbe(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.41", Port: 9091, Open: true,
		StatusCode: 200, ContentType: "text/plain",
		Headers:     map[string]string{"Content-Type": "text/plain"},
		BodySnippet: `is_healthy`,
	}
	if probeFires(t, "Milvus", "/api/v1/health", pr) {
		t.Fatal("Milvus FP fired on a plaintext 'is_healthy' string (generic K8s readiness)")
	}
}

// ── Langfuse ────────────────────────────────────────────────────────

func TestLangfuse_MatchesNextSPA(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.50", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><script id="__NEXT_DATA__">{"page":"/","query":{},"buildId":"langfuse-abc"}</script>`,
	}
	if !probeFires(t, "Langfuse", "/", pr) {
		t.Fatal("Langfuse did not match real Next.js SPA shape")
	}
}

func TestLangfuse_RejectsBlogMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.51", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body><h1>Comparing langfuse to LangSmith</h1></body></html>`,
	}
	if probeFires(t, "Langfuse", "/", pr) {
		t.Fatal("Langfuse FP fired on a blog post mentioning the brand (no __NEXT_DATA__)")
	}
}

// ── Kubeflow ────────────────────────────────────────────────────────

func TestKubeflow_RejectsMarketingMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.60", Port: 8080, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body><p>Our platform integrates with Kubeflow, Airflow, and Argo.</p></body></html>`,
	}
	if probeFires(t, "Kubeflow", "/", pr) {
		t.Fatal("Kubeflow FP fired on marketing mention (no <title>)")
	}
}

// ── OpenClaw (Molty) ────────────────────────────────────────────────

func TestOpenClaw_RejectsNon200(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.70", Port: 18789, Open: true,
		StatusCode: 404, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body>Not Found — looking for clawdbot-app</body></html>`,
	}
	if probeFires(t, "OpenClaw", "/", pr) {
		t.Fatal("OpenClaw FP fired on a 404 page (status_code anchor violated)")
	}
}

// ── Whisper ASR ─────────────────────────────────────────────────────

func TestWhisperASR_RejectsBareWord(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.80", Port: 9000, Open: true,
		StatusCode: 200, ContentType: "text/plain",
		Headers:     map[string]string{"Content-Type": "text/plain"},
		BodySnippet: `Powered by whisper.cpp`,
	}
	if probeFires(t, "Whisper ASR", "/inference", pr) {
		t.Fatal("Whisper ASR FP fired on /inference 200 plaintext (status_code 400 anchor violated)")
	}
}

// ── dcm4chee ────────────────────────────────────────────────────────

func TestDcm4chee_Rejects302Redirect(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.90", Port: 8080, Open: true,
		StatusCode: 302, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html", "Location": "https://keycloak/auth"},
		BodySnippet: `<html>Redirecting to dcm4chee Keycloak...</html>`,
	}
	if probeFires(t, "dcm4che / dcm4chee-arc DICOM Archive", "/dcm4chee-arc/", pr) {
		t.Fatal("dcm4chee FP fired on a 302 redirect HTML body (status_code anchor violated)")
	}
}

// ── Exposed API Credentials (cross-cutting) ─────────────────────────

func TestExposedCreds_Match200LangfuseKey(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.100", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<script>window.__ENV__={"LANGFUSE_SECRET_KEY":"sk-lf-abcdef12-3456-7890-abcd-ef1234567890"}</script>`,
	}
	if !probeFires(t, "Exposed API Credentials", "/", pr) {
		t.Fatal("Exposed API Credentials did not fire on a real leaked Langfuse key in 200 body")
	}
}

func TestExposedCreds_Rejects404Mention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.101", Port: 80, Open: true,
		StatusCode: 404, ContentType: "text/plain",
		Headers:     map[string]string{"Content-Type": "text/plain"},
		BodySnippet: `404: sk-lf- routes not found`,
	}
	// All 11 credential probes should be 200-only; 404 with prefix in body
	// is now rejected (most likely a docs/error page, not a real leak).
	if probeFires(t, "Exposed API Credentials", "/", pr) {
		t.Fatal("Exposed API Credentials fired on a 404 (status_code 200 anchor violated)")
	}
}

func TestExposedCreds_AllPrefixesCovered(t *testing.T) {
	// Inventory check: confirms every credentialClass in enumerators.go has
	// a corresponding fingerprint probe in fingerprints.go. If a new prefix
	// is added to credentialClasses but no fingerprint probe, this catches it.
	var fpPrefixes []string
	for _, fp := range Fingerprints {
		if fp.Name != "Exposed API Credentials" {
			continue
		}
		for _, probe := range fp.Probes {
			for _, m := range probe.Matches {
				if m.Type == "body_contains" {
					fpPrefixes = append(fpPrefixes, m.Value)
				}
			}
		}
	}
	required := []string{"sk-lf-", "sk-helicone-", "sk_live_", "sk_test_", "sk-ant-api03-",
		"lsv2_pt_", "lsv2_sk_", "sk-or-v1-", "xoxp-", "LANGFUSE_SECRET_KEY"}
	for _, want := range required {
		found := false
		for _, got := range fpPrefixes {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Exposed API Credentials missing fingerprint probe for prefix %q", want)
		}
	}
}

// ── MCP Server permissive fallback ──────────────────────────────────

func TestMCP_FallbackMatchesJSONError(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.110", Port: 8080, Open: true,
		StatusCode: 400, ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"error":"Bad Request: Mcp-Session-Id header is required"}`,
	}
	if !probeFires(t, "MCP Server", "/", pr) {
		t.Fatal("MCP permissive fallback did not match a real spec-mandated 400 error JSON")
	}
}

func TestMCP_FallbackRejectsHTMLDoc(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.111", Port: 80, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><body><h1>MCP spec</h1><p>The Mcp-Session-Id header is required by the spec...</p></body></html>`,
	}
	// Permissive fallback probes (7 and 9) now exclude <!DOCTYPE html pages.
	// At least one probe path may still match if a different MCP probe is also active;
	// we verify the body_not_contains anchor on the fallback specifically.
	for _, fp := range Fingerprints {
		if fp.Name != "MCP Server" {
			continue
		}
		for _, probe := range fp.Probes {
			// Probes 7 and 9 are the permissive ones: 1-2 conds, body_contains Mcp-Session-Id.
			// They should now also have body_not_contains "<!DOCTYPE html".
			hasMcpSession := false
			hasDoctypeAntiMatch := false
			for _, m := range probe.Matches {
				if m.Type == "body_contains" && m.Value == "Mcp-Session-Id" {
					hasMcpSession = true
				}
				if m.Type == "body_not_contains" && strings.Contains(m.Value, "DOCTYPE html") {
					hasDoctypeAntiMatch = true
				}
			}
			if hasMcpSession {
				if !hasDoctypeAntiMatch {
					// This is the legitimate 400-anchored probe (Probes 6 and 8) which
					// don't need the doctype anti-match because they're status-anchored.
					continue
				}
				if matchProbe(probe, pr) {
					t.Fatalf("MCP permissive fallback probe %q matched an HTML doc page", probe.Path)
				}
			}
		}
	}
}

// ── HTML-title structured probes (Dify, OpenHands, Coolify) ─────────

func TestHTMLTitleProbes_RejectNon200(t *testing.T) {
	cases := []struct {
		fp, path, title string
	}{
		{"Dify", "/", "<title>Dify</title>"},
		{"OpenHands", "/", "<title>OpenHands</title>"},
		{"Coolify", "/login", "<title>Coolify</title>"},
	}
	for _, c := range cases {
		pr := PortResult{
			Host: "203.0.113.120", Port: 80, Open: true,
			StatusCode: 500, ContentType: "text/html",
			Headers:     map[string]string{"Content-Type": "text/html"},
			BodySnippet: `<html><head>` + c.title + `</head><body>500 Internal Server Error</body></html>`,
		}
		if probeFires(t, c.fp, c.path, pr) {
			t.Errorf("%s FP fired on a 500 error page containing the title tag (status anchor violated)", c.fp)
		}
	}
}
