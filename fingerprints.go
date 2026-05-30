package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Fingerprint types ───────────────────────────────────────────────

type MatchCond struct {
	// Type: status_code, body_contains, body_not_contains, json_field,
	// json_array, header_contains, header_not_contains.
	//
	// body_not_contains is an anti-match: the probe FAILS if the substring
	// appears in the body. Used to exclude false-positive shapes (e.g.,
	// a marketing-site reflection that contains the brand name but isn't a
	// self-hosted instance).
	//
	// header_not_contains is a header-level anti-match: the probe FAILS if
	// the specified header field's value contains the substring. Used to
	// exclude services that identify themselves via Server/X-Powered-By headers
	// (e.g., Server: Milvus/ on a port that also serves {"status":"ok"}).
	// If the header is absent, the anti-match PASSES (absence != presence).
	Type  string
	Field string
	Value string
}

type Probe struct {
	Path    string
	Matches []MatchCond
}

type Fingerprint struct {
	Name         string
	DefaultPorts []int
	Probes       []Probe
	Severity     string
}

// ── Fingerprint database ────────────────────────────────────────────

var Fingerprints = []Fingerprint{
	// ── Vector databases ────────────────────────────────────────
	{
		Name:         "Weaviate",
		DefaultPorts: []int{8080, 8443},
		Probes: []Probe{
			{Path: "/v1/meta", Matches: []MatchCond{
				{Type: "json_field", Field: "version"},
				{Type: "json_field", Field: "modules"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "ChromaDB",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			// v2 API (ChromaDB >= 1.0.0) — path moved from /api/v1 to /api/v2
			{Path: "/api/v2/heartbeat", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "nanosecond heartbeat"},
			}},
			// v1 API fallback (ChromaDB < 1.0.0)
			{Path: "/api/v1/heartbeat", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "nanosecond heartbeat"},
			}},
			{Path: "/api/v1/collections", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Qdrant",
		DefaultPorts: []int{6333},
		Probes: []Probe{
			{Path: "/collections", Matches: []MatchCond{
				{Type: "json_field", Field: "result"},
			}},
		},
		Severity: "high",
	},

	// ── LLM runtimes ───────────────────────────────────────────
	{
		Name:         "Ollama",
		DefaultPorts: []int{11434},
		Probes: []Probe{
			{Path: "/api/tags", Matches: []MatchCond{
				{Type: "json_field", Field: "models"},
			}},
		},
		Severity: "high",
	},
	// llama.cpp HTTP server — frequently co-located on port 11434 (Ollama's
	// default) when operators deploy llama.cpp as an "Ollama-compatible"
	// service. Field-validated 2026-05-15 on 194.233.71.223. Two
	// conjunctive-within-probe paths: /v1/models (the OpenAI-compat surface)
	// and /props (the llama.cpp-native server-info endpoint). Either probe
	// hitting confirms llama.cpp.
	{
		Name:         "llama.cpp server",
		DefaultPorts: []int{8080, 8000, 11434},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"owned_by":"llamacpp"`},
			}},
			{Path: "/props", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "default_generation_settings"},
				{Type: "body_contains", Value: "chat_template"},
			}},
			// Server-header + body marker as a third alternative
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Server", Value: "llama.cpp"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "vLLM",
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			// /v1/models on real vLLM returns {"object":"list","data":[...,{"owned_by":"vllm",...}]}.
			// Anchored on JSON shape + body to reject blog pages / marketing copy mentioning vllm.
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "vllm"},
			}},
			// GGUF-serving vLLM tags models owned_by:"local", so the body never
			// contains "vllm" and the probe above misses it (field-observed
			// 2026-05-29 on 144.76.75.252 serving gpt-oss-20b-GGUF). vLLM's
			// /version returns {"model":"...","version":"0.x.x"} — the model+version
			// two-field shape on the /version path is the reliable fallback signal.
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "model"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "medium",
	},

	// ── LLM safety / guardrail ──────────────────────────────────
	// LLM Guard (Protect AI) scanner API. Field-validated 2026-05-29 on
	// 5.78.101.230:8000. GET / returns {"name":"LLM Guard API"} unauth.
	// AUTH_TOKEN is opt-in; when unset, /analyze/prompt + /analyze/output
	// run scanners with no auth (safety-layer bypass). Three-conjunct match
	// (status + json_field name + the exact product string) rejects generic
	// FastAPI roots that return a bare {"name":...}.
	{
		Name:         "LLM Guard API",
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "name"},
				{Type: "body_contains", Value: "LLM Guard API"},
			}},
		},
		Severity: "high",
	},

	// ── RAG / knowledge-base frameworks ─────────────────────────
	// AnythingLLM. Field-validated 2026-05-29 on 213.239.218.83:3001.
	// GET /api/setup-complete is UNAUTH and discloses auth posture:
	// {"results":{"RequiresAuth":bool,"MultiUserMode":bool,...}}. The
	// RequiresAuth + MultiUserMode field pair is AnythingLLM-unique; when
	// RequiresAuth=false the web UI is open to any browser visitor (the dev
	// REST API stays key-gated). Four conjuncts keep this off generic
	// {"results":...} APIs.
	{
		Name:         "AnythingLLM",
		DefaultPorts: []int{3001, 80, 443},
		Probes: []Probe{
			{Path: "/api/setup-complete", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "results"},
				{Type: "body_contains", Value: "RequiresAuth"},
				{Type: "body_contains", Value: "MultiUserMode"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "AnythingLLM | Your personal LLM"},
			}},
		},
		Severity: "medium",
	},

	// ── Auth / policy engines ───────────────────────────────────
	// Open Policy Agent. Field-validated 2026-05-29 (5/6 of an OPA sample
	// unauth). OPA performs no authentication by default. GET / returns the
	// ASCII-art diagnostic page with "Open Policy Agent" + "policy-enable";
	// GET /v1/policies returns {"result":[{"id":"...rego","raw":"..."}]} —
	// the full Rego policy list unauth (authz model + infra topology). Two
	// probe alternates so OPA matches via the root page or the policy API.
	{
		Name:         "Open Policy Agent",
		DefaultPorts: []int{8181, 8081},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Open Policy Agent"},
				{Type: "body_contains", Value: "policy-enable"},
			}},
			{Path: "/v1/policies", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "result"},
				{Type: "body_contains", Value: ".rego"},
			}},
		},
		Severity: "high",
	},

	// ── Image generation / diffusion ────────────────────────────
	// Field-validated 2026-05-16 across 50K-host ComfyUI Shodan corpus
	// (`product:"ComfyUI"`). Strict JSON-shape verification: shell-only
	// SPAs and reverse-proxy frontends that serve identical HTML for any
	// path do NOT match — only hosts returning real ComfyUI API JSON do.
	// Operator argv exposed via /system_stats system.argv field.
	{
		Name:         "ComfyUI",
		DefaultPorts: []int{8188, 7860, 3000, 8000, 8080},
		Probes: []Probe{
			{Path: "/system_stats", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "system"},
				{Type: "body_contains", Value: "comfyui_version"},
				{Type: "body_contains", Value: "python_version"},
			}},
		},
		Severity: "critical", // ComfyUI-Manager custom-node install = unauth RCE by design
	},
	// AUTOMATIC1111 / Forge / SD.Next — Gradio-on-7860 SPAs. Brand string lives
	// in JS bundle so Shodan title indexer misses; /sdapi/v1/options is the
	// stable JSON-shape anchor when API mode enabled.
	{
		Name:         "AUTOMATIC1111 / SD WebUI",
		DefaultPorts: []int{7860, 7861, 7862, 3000, 80, 443},
		Probes: []Probe{
			{Path: "/sdapi/v1/options", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sd_model_checkpoint"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "InvokeAI",
		DefaultPorts: []int{9090, 9091},
		Probes: []Probe{
			{Path: "/api/v1/app/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Fooocus",
		DefaultPorts: []int{7865, 7860},
		Probes: []Probe{
			// Fooocus exposes a Gradio config endpoint with its name marker.
			{Path: "/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Fooocus"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "SwarmUI",
		DefaultPorts: []int{7801},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "SwarmUI"},
			}},
		},
		Severity: "high",
	},

	// ── Agent-memory backends ───────────────────────────────────
	// Field-validated 2026-05-16 across the agent-memory survey corpus.
	// All Tier-C confirmed at population scale (auth-on-default holds);
	// fingerprints are for accurate platform-class identification, not
	// for unauth-detection — the data layer always requires the platform's
	// documented auth gate (X-API-Key, session cookie, etc.).
	{
		Name:         "Mem0",
		DefaultPorts: []int{8000, 8888, 8080, 3000},
		Probes: []Probe{
			// Mem0's /openapi.json contains "mem0" markers; /docs is the
			// Swagger UI; /memories requires X-API-Key (Tier-C).
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "mem0"},
				{Type: "json_field", Field: "paths"},
			}},
		},
		Severity: "medium", // Tier-C — informational unless API key leaked elsewhere
	},
	{
		Name:         "Argilla",
		DefaultPorts: []int{80, 443, 6900},
		Probes: []Probe{
			// /api/_info is Argilla's canonical public endpoint — version-only
			// disclosure. Data layer (/api/me) is auth-gated. Tier-C.
			{Path: "/api/_info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "medium",
	},
	// Zep + Letta fingerprints based on documented API shapes; field-validation
	// pending because the 2026-05-16 survey's Shodan candidate pool was almost
	// entirely false-positives (services with "zep"/"letta" string in HTML body
	// but no actual API). Future port-first masscan on 8000 (Zep) / 8283 (Letta)
	// on tier-2 cloud is the right way to surface the real population.
	{
		Name:         "Zep",
		DefaultPorts: []int{8000, 5557},
		Probes: []Probe{
			// Zep v2 API: /api/v2/health returns JSON with status field
			{Path: "/api/v2/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "zep"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Letta",
		DefaultPorts: []int{8283, 8084},
		Probes: []Probe{
			// Letta (formerly MemGPT): /v1/health returns {"status":"ok"} with letta/memgpt marker
			{Path: "/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "letta"},
			}},
			// Alternative: /v1/agents requires auth in newer Letta; check OpenAPI
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "letta"},
				{Type: "json_field", Field: "paths"},
			}},
		},
		Severity: "medium",
	},

	// ── Data-labeling platforms ────────────────────────────────
	// Field-validated 2026-05-16 in the data-labeling survey.
	{
		Name:         "Label Studio",
		DefaultPorts: []int{8080, 8081, 80, 443, 8000},
		Probes: []Probe{
			// Modern v1.x API path
			{Path: "/api/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "label-studio-os"},
			}},
			// Legacy v0.7.x path (still observed at population scale)
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "label-studio-backend"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "CVAT",
		DefaultPorts: []int{8080, 8081, 80, 443},
		Probes: []Probe{
			{Path: "/api/server/about", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "cvat"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Doccano",
		DefaultPorts: []int{8000, 3000, 80, 443},
		Probes: []Probe{
			// Doccano root page title
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "doccano"},
				{Type: "body_contains", Value: "<title>"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Prodigy",
		DefaultPorts: []int{8080, 8081, 8000},
		Probes: []Probe{
			// Prodigy's annotation UI is auth-free by design (Tier-A*)
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Prodigy</title>"},
			}},
		},
		Severity: "high", // unauth annotation UI exposed = workflow visibility
	},

	// ── Vector-DB stragglers (Solr / Meilisearch / Typesense / Vespa) ──
	// Field-validated 2026-05-16 in the vector-DB stragglers survey.
	// Solr 7.6.0 fleet (516 hosts unauth) is the headline finding —
	// CVE-2019-17558 Velocity RCE class.
	{
		Name:         "Apache Solr",
		DefaultPorts: []int{8983, 8984, 80, 443},
		Probes: []Probe{
			{Path: "/solr/admin/info/system", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "solr-spec-version"},
			}},
		},
		Severity: "critical", // 7.x-default unauth + Velocity RCE = unauth RCE
	},
	{
		Name:         "Meilisearch",
		DefaultPorts: []int{7700, 80, 443},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"status":"available"`},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Typesense",
		DefaultPorts: []int{8108, 80, 443},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"ok":true`},
			}},
		},
		Severity: "medium", // Tier-C confirmed (0/9837 unauth in field survey)
	},
	{
		Name:         "Vespa",
		DefaultPorts: []int{8080, 19071},
		Probes: []Probe{
			{Path: "/state/v1", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "config-server"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "SGLang",
		DefaultPorts: []int{30000, 8889},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "sglang is running"},
			}},
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "sglang"},
			}},
			{Path: "/get_model_info", Matches: []MatchCond{
				{Type: "json_field", Field: "model_path"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "LocalAI",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "localai"},
			}},
			{Path: "/models/available", Matches: []MatchCond{
				{Type: "json_field", Field: "object"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "AI TTS Server",
		DefaultPorts: []int{10087, 8080},
		Probes: []Probe{
			{Path: "/v1/audio/voices", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "voices"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "json_field", Field: "endpoints"},
				{Type: "body_contains", Value: "audio/speech"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "text-generation-webui",
		DefaultPorts: []int{7860},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "gradio"},
				{Type: "body_contains", Value: "text-generation"},
			}},
		},
		Severity: "medium",
	},

	// ── Model Context Protocol (MCP) servers ────────────────────────────
	// Designed against 88 unauth MCP servers observed in the wild (2026-05-15
	// MCP refresh — see verify/get_mcp_signal.jsonl in the recon artifact).
	// MCP servers run on heterogeneous ports and frameworks; this fingerprint
	// uses 5 disjunctive probes against GET /mcp to maximize coverage of the
	// empirically-observed response shapes.
	//
	// Threat class: MCP servers expose tools, resources, and prompts to LLM
	// clients. Per the April 2026 OX Security disclosure, every MCP SDK has
	// systemic RCE-class behavior by design (tool execution is the protocol).
	// Anthropic has declined to modify this; the protocol IS the bypass
	// when no auth wraps it. Severity: high.
	{
		Name:         "MCP Server",
		DefaultPorts: []int{443, 3000, 3001, 5000, 5001, 8000, 8001, 8080, 8081, 8088, 8443, 8888, 9000, 9090},
		Probes: []Probe{
			// Probe 1: FastMCP / Streamable HTTP shape — 406 Not Acceptable + JSON-RPC body.
			// Most common response when GET /mcp hits a server expecting POST with proper Accept.
			// Empirical coverage: 26/88 (30%) of observed unauth MCP servers.
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "status_code", Value: "406"},
				{Type: "body_contains", Value: "jsonrpc"},
			}},
			// Probe 2: 405 Method Not Allowed + body says POST. Less common but distinct.
			// Empirical coverage: ~6/88 (7%) — only servers that include Method-Not-Allowed in body AND mention POST.
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "body_contains", Value: "Method Not Allowed"},
				{Type: "body_contains", Value: "POST"},
			}},
			// Probe 3: Server header explicitly identifies as mcp-server*. High-confidence single signal.
			// Empirical coverage: 5/88 (6%) — servers built with mcp-framework that set Server: mcp-server/x.y.z.
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "header_contains", Field: "Server", Value: "mcp-server"},
			}},
			// Probe 4: JSON-RPC error code -32600 (Invalid Request) in body + jsonrpc literal.
			// FastMCP servers return this when GET hits a POST-only endpoint with proper JSON-RPC framing.
			// Empirical coverage: 18/88 (20%) — overlaps with Probe 1 but catches some non-406 cases.
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "body_contains", Value: "-32600"},
				{Type: "body_contains", Value: "jsonrpc"},
			}},
			// Probe 5: 405 + Allow header contains "post" (case-insensitive). The few servers
			// that send a proper Allow header on a 405 rejection.
			// Empirical coverage: 6/88 (7%).
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "header_contains", Field: "Allow", Value: "post"},
			}},
			// Probe 6: 400 Bad Request + body contains the literal "Mcp-Session-Id" header
			// name. The Streamable HTTP transport (2025-03-26 spec) requires this session
			// header; Kestrel/.NET-based MCP servers emit "Bad Request: Mcp-Session-Id
			// header is required" when the header is missing. Highly specific signal —
			// no non-MCP service emits this exact string. Added 2026-05-15 after a live
			// shakedown on 120.24.170.57:5001 (Vschool.GatewayApi) which exhibited this
			// shape and was missed by Probes 1-5.
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "status_code", Value: "400"},
				{Type: "body_contains", Value: "Mcp-Session-Id"},
			}},
			// Probe 7: body contains the literal "Mcp-Session-Id" anywhere — fallback for
			// servers that emit the spec header name on non-400 statuses. The Mcp-Session-Id
			// literal is unique to the MCP Streamable HTTP transport spec.
			// Anchored against HTML doc-page FPs: real MCP servers emit JSON or plaintext
			// errors, not HTML pages. <!DOCTYPE html marker rejects vendor docs / blog posts.
			{Path: "/mcp", Matches: []MatchCond{
				{Type: "body_contains", Value: "Mcp-Session-Id"},
				{Type: "body_not_contains", Value: "<!DOCTYPE html"},
			}},
			// Probe 8: root path /. Some MCP servers (notably Kestrel/.NET ones like
			// Vschool.GatewayApi) bind the MCP endpoint at the root, NOT at /mcp. They
			// emit "Bad Request: Mcp-Session-Id header is required" with status 400 on
			// GET /. Added 2026-05-15 after the live Vschool shakedown showed Probes 6+7
			// missing this case because they probed /mcp (which returns 404 on Kestrel
			// MCP) instead of / (which returns the spec error).
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "400"},
				{Type: "body_contains", Value: "Mcp-Session-Id"},
			}},
			// Probe 9: root path / + body contains "Mcp-Session-Id" literal anywhere.
			// Maximally permissive fallback for the root-bound MCP shape — catches
			// any server that emits the spec header literal on root, regardless of
			// status code. The literal is spec-unique.
			// Anchored against HTML doc-page FPs (MCP docs / vendor blogs would
			// otherwise match): real MCP servers emit JSON or plaintext errors.
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Mcp-Session-Id"},
				{Type: "body_not_contains", Value: "<!DOCTYPE html"},
			}},
		},
		Severity: "high",
	},

	// ── Container / orchestration tier ──────────────────────────────────
	// Added 2026-05-15 after the cross-class Critter validation showed
	// menlohunt was the only tool catching K8s/Docker/etcd/Vault/Consul/
	// Portainer/Kubelet on a 32-host container survey. aimap fingerprints
	// for these complete the chain's identification layer so the population
	// is visible regardless of which tool runs.
	//
	// Fixture sources: live GETs against the indicated targets in the
	// 2026-05-15 container survey. See:
	//   /home/cowboy/recon/2026-05-15-containers/verify/shapes.jsonl
	//
	// Kubelet Probe 1 note: body "ok" alone is a naked keyword per CLAUDE.md
	// discipline. This probe relies on DefaultPorts [10250, 10255] filtering
	// for soundness — under -scan-all-fingerprints it may false-positive on
	// generic health endpoints returning 200 "ok". Spec authority accepted;
	// documented here so the next hand knows the tradeoff.
	{
		// etcd: Kubernetes cluster state store. Unauth read = full cluster
		// compromise (secrets, kubeconfigs, service-account tokens).
		// Replaces the previous weak entry (naked json_field, no status_code
		// anchor). Ports: 2379 (client), 2380 (peer).
		// Fixture: 101.53.134.137:2379, 1.116.218.232:2379 → GET /version 200
		//   body: {"etcdserver":"3.5.12","etcdcluster":"3.5.0"}
		Name:         "etcd",
		DefaultPorts: []int{2379, 2380},
		Probes: []Probe{
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "etcdserver"},
				{Type: "body_contains", Value: "etcdcluster"},
			}},
		},
		Severity: "critical",
	},
	{
		// HashiCorp Vault: secrets manager. /v1/sys/health returns 200 with
		// initialized + sealed status fields. Auth-required Vault is still
		// sensitive intel (unsealed + initialized = prime target).
		// Fixture: 104.236.5.62:8200 → GET /v1/sys/health 200
		//   body: {"initialized":true,"sealed":false,"standby":false,...}
		Name:         "Vault",
		DefaultPorts: []int{8200},
		Probes: []Probe{
			{Path: "/v1/sys/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "initialized"},
				{Type: "body_contains", Value: "sealed"},
			}},
		},
		Severity: "high",
	},
	{
		// Docker daemon (unauthenticated TCP socket). Unauth = host RCE via
		// docker run --privileged -v /:/host. Two probes cover the two
		// observed body shapes: (a) Server header starts with Docker/,
		// (b) ApiVersion + GoVersion in body (some daemons omit the header).
		// Fixture A: 102.129.185.27:2375 → GET /version 200, Server: Docker/20.10.0
		//   body: {"Platform":{"Name":"Docker Engine - Community"},"Components":[...
		// Fixture B: 129.151.144.78:2375 → GET /version 200
		//   body: {"ApiVersion":"1.44","GitCommit":"v25.0.5","GoVersion":"go1.21.8",...
		Name:         "Docker daemon",
		DefaultPorts: []int{2375, 2376},
		Probes: []Probe{
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Server", Value: "Docker/"},
			}},
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ApiVersion"},
				{Type: "body_contains", Value: "GoVersion"},
				{Type: "body_not_contains", Value: "gitVersion"}, // anti-K8s API /version (2026-05-15)
			}},
		},
		Severity: "critical",
	},
	{
		// Kubernetes API server. Two probe shapes observed in the wild:
		// Probe 1: /version 200 → gitVersion + gitCommit (version disclosure even when auth enforced)
		// Probe 2: /api 403 → system:anonymous forbidden message (canonical K8s anon-rejection)
		// Fixture 1: 109.107.36.44:6443 → GET /version 200
		//   body: {"major":"1","minor":"32","gitVersion":"v1.32.1","gitCommit":"...
		// Fixture 2: 101.89.57.65:6443 → GET /api 403
		//   body: {"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden: User \"system:anonymous\"...
		Name:         "Kubernetes API",
		DefaultPorts: []int{6443, 8443},
		Probes: []Probe{
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gitVersion"},
				{Type: "body_contains", Value: "gitCommit"},
			}},
			{Path: "/api", Matches: []MatchCond{
				{Type: "status_code", Value: "403"},
				{Type: "body_contains", Value: "system:anonymous"},
				{Type: "body_contains", Value: "forbidden"},
			}},
		},
		Severity: "high",
	},
	{
		// HashiCorp Consul: service mesh + KV store. /v1/agent/self returns
		// full node config including Datacenter + NodeName (topology disclosure).
		// Fixture: 103.251.165.56:8500 → GET /v1/agent/self 200
		//   body: {"Config":{"Datacenter":"main","PrimaryDatacenter":"main","NodeName":"nl-lt-vpn01",...
		Name:         "Consul",
		DefaultPorts: []int{8500},
		Probes: []Probe{
			{Path: "/v1/agent/self", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Datacenter"},
				{Type: "body_contains", Value: "NodeName"},
			}},
			// Probe 2: /v1/catalog/services returns JSON object where "consul"
			// key is always present (Consul lists its own service). No positive
			// fixture captured in the 2026-05-15 survey — only 500s on that
			// path from isolated-agent nodes. Probe shipped on spec authority.
			{Path: "/v1/catalog/services", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "consul"},
			}},
		},
		Severity: "high",
	},
	{
		// Portainer: Docker/K8s management UI. /api/status returns Version +
		// InstanceID — enough to confirm Portainer and version-target it.
		// Default admin signup = cluster takeover.
		// Fixture: 103.219.226.52:9000 → GET /api/status 200
		//   body: {"Version":"2.19.5","InstanceID":"4d15c813-...","DemoEnvironment":{...
		Name:         "Portainer",
		DefaultPorts: []int{9000, 9443},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Version"},
				{Type: "body_contains", Value: "InstanceID"},
			}},
		},
		Severity: "high",
	},
	{
		// Kubelet: per-node K8s agent. Anonymous /exec or /run = cluster-wide
		// RCE. Even auth-protected Kubelet on :10250 is operator-intel disclosure.
		// Probe 1: /healthz 200 text/plain "ok" — anonymous Kubelet, no auth required.
		//   Fixture: 175.178.65.155:10250 → GET /healthz 200, Content-Type: text/plain; charset=utf-8, body: ok
		//   FP fix (2026-05-15): added Content-Type text/plain + body_not_contains "{"
		//   to exclude vector DBs (Qdrant/Milvus) and CrateDB returning {"status":"ok"}
		//   as JSON. Real Kubelet sends a 2-byte plaintext body — not a JSON object.
		// Probe 2: /healthz 401 text/plain "Unauthorized" — auth-protected Kubelet.
		//   Fixture: 172.236.15.129:10250 → GET /healthz 401, Content-Type: text/plain; charset=utf-8, body: Unauthorized
		//   FP fix (2026-05-15): added Content-Type text/plain to exclude nginx-fronted
		//   401 responses that return text/html (e.g. 43.155.71.160 nginx reverse proxy).
		// Probe 3: /pods 200 "PodList" — anonymous Kubelet pod listing.
		//   No positive fixture captured in the 2026-05-15 survey (all :10250
		//   /pods returns were 401). Probe shipped on spec authority.
		Name:         "Kubelet",
		DefaultPorts: []int{10250, 10255},
		Probes: []Probe{
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Content-Type", Value: "text/plain"},
				{Type: "body_contains", Value: "ok"},
				{Type: "body_not_contains", Value: "{"}, // exclude JSON bodies (Qdrant/Milvus/CrateDB)
			}},
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "401"},
				{Type: "header_contains", Field: "Content-Type", Value: "text/plain"},
				{Type: "body_contains", Value: "Unauthorized"},
			}},
			{Path: "/pods", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "PodList"},
			}},
		},
		Severity: "critical",
	},

	// ── ML platforms ────────────────────────────────────────────
	{
		// MLflow's tracking server. The /api/2.0/mlflow/experiments/list
		// endpoint that earlier versions exposed has been removed upstream;
		// /experiments/search (POST) replaced it. We fingerprint via the GET /
		// index, which serves a known HTML skeleton with <title>MLflow</title>
		// and a /static-files/manifest.json link. Two conjunctive conditions
		// keep this from matching arbitrary gunicorn apps.
		Name:         "MLflow",
		DefaultPorts: []int{5000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>mlflow</title>"},
				{Type: "body_contains", Value: "static-files/manifest.json"},
			}},
		},
		Severity: "high",
	},
	{
		// WandB self-hosted UI (Weights & Biases). The SPA returns a React
		// bundle with WandB-specific anti-flicker snippet and the canonical
		// title. Field-validated 2026-05-17 against 28-host Shodan corpus.
		Name:         "Weights & Biases",
		DefaultPorts: []int{8080, 8081, 80, 443, 28080, 8888},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "weights & biases"},
				{Type: "body_contains", Value: "<title"},
			}},
		},
		Severity: "high",
	},
	{
		// "WandB Service" — the FastAPI custom-proxy pattern. Field-validated
		// 2026-05-17 against vanijmcp.adya.ai:5005. The service description
		// string and FastAPI's /openapi.json title are the unambiguous anchors.
		// Operator's WandB API key is embedded in the service and proxied to
		// any unauth client. Different finding class from the SPA UI: this
		// exposes the operator's entire WandB workspace, not just the UI.
		Name:         "WandB Service (custom FastAPI proxy)",
		DefaultPorts: []int{5005, 5000, 8000, 5001},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},
				{Type: "body_contains", Value: "wandb service"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "service"},
				{Type: "body_contains", Value: "wandb"},
				{Type: "body_contains", Value: "endpoints"},
			}},
		},
		Severity: "critical",
	},
	{
		// ClearML — open-source MLOps platform. Self-hosted UI ships the
		// "Sign up/login to ClearML" title and product copy. Field-validated
		// 2026-05-17 against 95-host Shodan corpus.
		Name:         "ClearML",
		DefaultPorts: []int{8080, 8008, 8081, 8085, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "clearml"},
				{Type: "body_contains", Value: "<title"},
			}},
		},
		Severity: "high",
	},
	{
		// Aim — open-source experiment tracker. Less-populous category (2
		// confirmed Shodan hits 2026-05-17), but the html:aim-ui dork is
		// reliable. The SPA ships /static/* paths and an `aim-ui` body tag.
		Name:         "Aim",
		DefaultPorts: []int{43800, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "aim-ui"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "TensorFlow Serving",
		DefaultPorts: []int{8501},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "json_field", Field: "model_version_status"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Triton Inference Server",
		DefaultPorts: []int{8000, 8001},
		Probes: []Probe{
			{Path: "/v2", Matches: []MatchCond{
				{Type: "json_field", Field: "name"},
				{Type: "body_contains", Value: "triton"},
			}},
			{Path: "/v2/repository/index", Matches: []MatchCond{
				{Type: "json_array"},
				{Type: "body_contains", Value: "READY"},
			}},
		},
		Severity: "medium",
	},
	{
		Name: "Ray Serve",
		// Verified live 2026-05-13 against 16.52.175.212:80. Operators
		// often expose Ray Serve as a custom REST endpoint at / rather
		// than the upstream /api/serve/deployments/ admin path. The
		// distinctive body signal is "Ray Serve" in the root JSON, anchored
		// with json_field "message" to avoid matching random JSON with
		// the word "ray" or "serve".
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			{Path: "/api/serve/deployments/", Matches: []MatchCond{
				{Type: "json_field", Field: "deployments"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Content-Type", Value: "application/json"},
				{Type: "body_contains", Value: "Ray Serve"},
				{Type: "body_contains", Value: "message"},
			}},
		},
		Severity: "medium",
	},

	// ── Orchestration / UI ──────────────────────────────────────
	{
		Name: "LangServe",
		// Default upstream is :8000 (FastAPI), but production hosts often
		// front via nginx/Traefik on 80/443. Field-validated 2026-05-13:
		// 3.234.68.99:443 served the genai-langserve FastAPI/Swagger UI
		// and the FP was filtered out by over-narrow DefaultPorts.
		DefaultPorts: []int{8000, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "langserve"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "langserve"},
			}},
		},
		Severity: "medium",
	},
	{
		// Iter 22: tightened after the 1,203-host MLflow delta sweep
		// classified 13 honeypot sensors as Flowise. The single-word
		// body_contains "flowise" on / matched honeypot bait pages, and
		// the API probe hit /api/v1/flows — the DEPRECATED endpoint.
		// Modern Flowise uses /api/v1/chatflows; the real SPA ships
		// <title>Flowise - Build AI Agents, Visually</title>.
		Name:         "Flowise",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/v1/chatflows", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
				{Type: "body_contains", Value: "flowData"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>flowise - build ai agents"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Open WebUI",
		DefaultPorts: []int{3000, 8080},
		Probes: []Probe{
			// Conjunctive probe: title plus a unique-to-Open-WebUI asset path.
			// Single-word brand mentions ("open-webui" or "Open WebUI"
			// anywhere in the body) used to fire alone, which over-matched
			// blog posts, tutorials, and marketing reflections that referenced
			// the project. The /static/loader.js path is specific to the
			// Open WebUI deployment, not the brand.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>open webui</title>"},
				{Type: "body_contains", Value: "/static/loader.js"},
			}},
		},
		Severity: "medium",
	},
	{
		Name: "SillyTavern",
		// Pre-1.12 SillyTavern returned 401 with WWW-Authenticate:
		// SillyTavern. The modern build (verified 2026-05-13 against
		// 115.120.242.5:8000) serves an HTML login page directly. The
		// /css/st-tailwind.css path is the project-specific asset
		// signature; the title alone over-matches tutorial/blog content.
		DefaultPorts: []int{8000, 8001},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>sillytavern</title>"},
				{Type: "body_contains", Value: "css/st-tailwind.css"},
			}},
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>sillytavern</title>"},
				{Type: "body_contains", Value: "css/st-tailwind.css"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "LiteLLM",
		DefaultPorts: []int{4000, 80, 443},
		Probes: []Probe{
			// /health on real LiteLLM returns {"healthy_endpoints":[...],"unhealthy_endpoints":[...],"healthy_count":N}.
			// Anchored on status + JSON shape to reject pages that mention litellm in marketing text.
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "healthy_count"},
				{Type: "body_contains", Value: "litellm"},
			}},
			// /model/info on real LiteLLM returns {"data":[{"model_name":"...","litellm_params":{...}}]}.
			// The literal "litellm_params" is the LiteLLM-specific signal we anchor on.
			{Path: "/model/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "litellm_params"},
			}},
		},
		Severity: "medium",
	},
	{
		// sub2api (Wei-Shaw/sub2api) — Go-rewrite successor to claude-relay-
		// service. Pooled-account upstream proxy: holds N paid Anthropic /
		// OpenAI / Gemini accounts and serves downstream Tier-3 storefronts.
		// 7,720 hosts indexed on Shodan as of 2026-05-19 (Wei-Shaw README
		// claims 8,105 — within 1.8% of Shodan's count).
		//
		// The Go rewrite hardened the v1 (Node.js claude-relay-service)
		// pool-stats surface: account counters, token counters, and
		// thirdPartyMaxConcurrent are auth-gated. The v1 publicly-readable
		// pool stats that anchored the 2026-05-19 Anthropic disclosure do
		// NOT generalize to v2 (0 / 7,720 POOL_LEAK in the survey). Cross-ref
		// Insight #40 in AI-LLM-Infrastructure-OSINT/methodology/.
		//
		// SETUP_OPEN substate: /setup/status returning {"needs_setup":true}
		// is the install-wizard takeover-on-init vector. Anyone reaching
		// the host before the operator finishes setup can POST /setup/init
		// to claim the admin account and bind their own credentials. 101 of
		// 7,720 sub2api hosts had this in the survey (1.31%). VisorScuba
		// rule AI.H6 (High) fires on the SETUP-OPEN tag.
		Name:         "sub2api",
		DefaultPorts: []int{8080, 443, 8090, 3000},
		Probes: []Probe{
			// Anchor 1: /v1/models returns 401 with verbatim sub2api
			// API_KEY_REQUIRED envelope. Highest-precision single signature
			// — the exact "Bearer scheme" wording is unique to sub2api
			// (emitted from backend/internal/gateway/*).
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "401"},
				{Type: "body_contains", Value: "API_KEY_REQUIRED"},
				{Type: "body_contains", Value: "API key is required in Authorization header (Bearer scheme)"},
			}},
			// Anchor 2: /setup/status with the sub2api response envelope.
			// Catches both pre-setup (needs_setup=true) and post-setup
			// (needs_setup=false). The {"code":0, "data":{...}} envelope
			// shape is sub2api-specific.
			{Path: "/setup/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"needs_setup"`},
				{Type: "body_contains", Value: `"step"`},
				{Type: "body_contains", Value: `"code":0`},
			}},
			// Anchor 3: /api/v1/admin/users 401 with sub2api UNAUTHORIZED
			// envelope. Confirms admin-surface auth-on-default.
			{Path: "/api/v1/admin/users", Matches: []MatchCond{
				{Type: "status_code", Value: "401"},
				{Type: "body_contains", Value: `"code":"UNAUTHORIZED"`},
				{Type: "body_contains", Value: "Authorization required"},
			}},
		},
		Severity: "high",
	},
	{
		// One API (songquanpeng/one-api) — popular open-source LLM gateway.
		// Self-hosted in Chinese-region operator stacks for brokering OpenAI/
		// Anthropic/DeepSeek paid keys to downstream users. Default port 3000.
		// Discriminator: GET /api/status returns the deployment-config JSON
		// without authentication, including auth-provider flags (oidc, github,
		// lark, email_verification). Field-validated 2026-05-17 against
		// 139.224.251.102:3000 and 45.76.217.104:8200.
		//
		// Exposed One API admin = full LLM-billing-quota theft surface. The
		// dashboard stores every user's API keys, their downstream paid
		// quota, and prompt-relay logs. Default admin login is `root` /
		// `123456` on unconfigured deployments.
		Name:         "One API",
		DefaultPorts: []int{3000, 80, 443, 8200, 8080, 8000},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "email_verification"},
				{Type: "body_contains", Value: "display_in_currency"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>one api</title>"},
			}},
		},
		Severity: "critical",
	},
	{
		// NewAPI (Calcium-Ion/new-api) — fork of One API with a fancier UI,
		// extra brokering providers (Doubao, Tongyi, Moonshot, Kimi), and
		// gift-code / billing extras. Same /api/status discriminator pattern
		// as One API but the response carries NewAPI-specific fields:
		// HeaderNavModules, SidebarModulesAdmin, api_info[]. Field-validated
		// 2026-05-17 against 47.242.61.197:3000.
		//
		// Default port 3000, often co-located with One API behind a Vue/React
		// SPA. Same threat shape — exposed dashboard = LLM-billing theft +
		// prompt-history exfil.
		Name:         "NewAPI",
		DefaultPorts: []int{3000, 80, 443, 8090, 8080},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "HeaderNavModules"},
				{Type: "body_contains", Value: "api_info"},
			}},
		},
		Severity: "critical",
	},

	// ── Notebooks / dev ─────────────────────────────────────────
	{
		Name:         "Jupyter Notebook",
		DefaultPorts: []int{8888},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "json_field", Field: "started"},
			}},
			// / fallback for deployments where /api/status returns 403 unauth.
			// Anchored on the HTML title pattern to reject pages that merely mention "jupyter".
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>"},
				{Type: "body_contains", Value: "Jupyter"},
			}},
		},
		Severity: "high",
	},

	// ── Additions v1.1 ──────────────────────────────────────────
	{
		Name:         "Milvus",
		DefaultPorts: []int{9091, 19530},
		Probes: []Probe{
			// /api/v1/health on real Milvus returns {"is_healthy":true,"detail":[]}.
			// Anchored on status + JSON shape — is_healthy alone is a generic K8s readiness pattern
			// and would FP on hundreds of unrelated services if matched on body substring only.
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "is_healthy"},
			}},
			{Path: "/api/v1/collections", Matches: []MatchCond{
				{Type: "json_field", Field: "collection_names"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Langfuse",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/public/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "json_field", Field: "version"},
				{Type: "body_not_contains", Value: "cluster_name"}, // anti-CrateDB / anti-ES
				{Type: "body_not_contains", Value: "build_hash"},   // anti-CrateDB / anti-ES
				{Type: "body_not_contains", Value: "qdrant"},       // anti-Qdrant
			}},
			// / fallback for deployments where /api/public/health returns 401.
			// Real Langfuse SPA emits a Next.js page with __NEXT_DATA__ + "Langfuse" in title.
			// Anchored on Next.js bundle pattern to reject blog/doc pages that mention langfuse.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "__NEXT_DATA__"},
				{Type: "body_contains", Value: "langfuse"},
			}},
		},
		Severity: "high",
	},
	{
		// Opik — Comet ML open-source LLM evaluation + tracing platform.
		// Self-hosted default: nginx SPA on :5173, backend at /api/v1/private/*.
		// Auth: OPIK_AUTHENTICATION_ENABLED=false ships as default → fully unauth API.
		// Identity confirmed live 2026-05-22 on 80.79.202.18 (DTN Amsterdam, NL).
		Name:         "Opik",
		DefaultPorts: []int{5173, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/api/v1/private/projects", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "total"},
				{Type: "json_field", Field: "content"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Comet Opik"},
			}},
		},
		Severity: "high",
	},
	{
		// PromptLayer — LLM prompt versioning + evaluation platform (SaaS).
		// Identity anchored on the bundle route name "organizations-with-workspace-and-invites"
		// — a PromptLayer-specific internal route that appears in every SPA bundle.
		// The webhook-leak finding class (Make.com webhook URLs hardcoded in bundle)
		// is surfaced by the secret scanner, not this fingerprint.
		// Severity: high (unauth bundle disclosure + webhook secrets; Insight #10 class).
		Name:         "PromptLayer",
		DefaultPorts: []int{80, 443, 3000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "organizations-with-workspace-and-invites"},
				{Type: "body_contains", Value: "PromptLayer"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Dify",
		DefaultPorts: []int{80, 5001, 3000},
		Probes: []Probe{
			{Path: "/console/api/setup", Matches: []MatchCond{
				{Type: "json_field", Field: "step"},
			}},
			{Path: "/console/api/version", Matches: []MatchCond{
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "dify"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Dify</title>"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "BentoML",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/docs.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "openapi"},
				{Type: "body_contains", Value: "bentoml"},
			}},
			{Path: "/livez", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "BentoML"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Ray Dashboard",
		DefaultPorts: []int{8265},
		Probes: []Probe{
			{Path: "/api/version", Matches: []MatchCond{
				{Type: "json_field", Field: "ray_version"},
			}},
			{Path: "/api/cluster_status", Matches: []MatchCond{
				{Type: "json_field", Field: "cluster_status"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Kubeflow",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/pipeline/apis/v1beta1/healthz", Matches: []MatchCond{
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "kubeflow"},
			}},
			// / fallback for deployments where the pipelines endpoint is gated.
			// Anchored on HTML title to reject pages that merely reference Kubeflow.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>"},
				{Type: "body_contains", Value: "Kubeflow"},
			}},
		},
		Severity: "high",
	},

	// ── Compute orchestration / training tier ──────────────────
	// All fingerprints in this section follow the conjunctive-match
	// discipline (status_code + json_field + body_contains, all required)
	// so probes don't fire on naked single-word substring matches.
	{
		Name:         "Apache Spark UI",
		DefaultPorts: []int{4040, 8080, 18080},
		Probes: []Probe{
			{Path: "/api/v1/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "spark"},
			}},
			{Path: "/api/v1/applications", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Airflow",
		DefaultPorts: []int{8080, 80, 443},
		Probes: []Probe{
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "metadatabase"},
				{Type: "json_field", Field: "scheduler"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "metadatabase"},
				{Type: "json_field", Field: "scheduler"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Dask Dashboard",
		DefaultPorts: []int{8787},
		Probes: []Probe{
			{Path: "/json/identity.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "type"},
				{Type: "json_field", Field: "services"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Prefect",
		DefaultPorts: []int{4200},
		Probes: []Probe{
			{Path: "/api/admin/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
			}},
			{Path: "/api/admin/database", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "connection_url"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Temporal Web",
		// DefaultPorts: 8080/8233 = Temporal Web UI; 7243 = HTTP REST API gateway
		// (temporal server --headless mode or standalone temporal-http-api sidecar);
		// 7233 = gRPC frontend (not HTTP, listed so port-scanner includes it in sweep).
		DefaultPorts: []int{8080, 8233, 7233, 7243},
		Probes: []Probe{
			{Path: "/api/v1/cluster-info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "supportedClients"},
				{Type: "json_field", Field: "clusterName"},
			}},
			{Path: "/api/v1/namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "namespaces"},
			}},
			// HTTP REST API gateway (port 7243): unauth on default Temporal installs.
			// /api/v1/system-info returns serverVersion + capabilities; both fields
			// are Temporal-specific and conjunctive-match cleanly against other 7243
			// services.
			{Path: "/api/v1/system-info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "serverVersion"},
				{Type: "json_field", Field: "capabilities"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Cadence Web",
		DefaultPorts: []int{8088},
		Probes: []Probe{
			{Path: "/api/v1/domains", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "domains"},
			}},
			{Path: "/api/v1/clusters", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "clusters"},
			}},
		},
		Severity: "high",
	},

	// ── Workflow Orchestration (extended) ──────────────────────
	{
		Name: "Argo Workflows",
		// Port 2746 = default argo-server HTTP/HTTPS port (Argo-exclusive).
		// Three probe tiers:
		//   1. /api/v1/version — identity probe; gitTag+gitTreeState+compiler is
		//      Argo-unique and fires on ALL instances (auth or not) because GetVersion
		//      has no auth check in the source. Catches auth-enforced instances too.
		//   2. /api/v1/userinfo — auth classifier; serviceAccountName field only
		//      appears when --auth-mode=server is active (all requests run as the
		//      argo-server SA, no bearer token required). Tight unauth discriminator.
		//   3. /api/v1/info — fallback; managedNamespace + links fields are always
		//      present in the startup struct; no auth check in GetInfo handler.
		// Any probe matching fires the fingerprint. Severity=critical: unauth instances
		// expose POST /api/v1/workflows (arbitrary container exec) and pod exec.
		// Empirically confirmed: 111 of 136 Shodan-discovered instances run on
		// port 443 (Kubernetes ingress/LoadBalancer), not 2746 (bare server).
		// Also include 80, 8080, 8443 for proxy-fronted deployments.
		DefaultPorts: []int{2746, 443, 80, 8080, 8443},
		Probes: []Probe{
			{Path: "/api/v1/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "gitTag"},
				{Type: "body_contains", Value: "gitTreeState"},
				{Type: "body_contains", Value: "compiler"},
			}},
			{Path: "/api/v1/userinfo", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "serviceAccountName"},
			}},
			{Path: "/api/v1/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "managedNamespace"},
				{Type: "body_contains", Value: "links"},
			}},
		},
		Severity: "critical",
	},
	{
		// Identity-only fingerprint for auth-enforced Argo Workflows.
		// Fires when the API returns 401 (auth required) but the SPA root
		// reveals the X-Ratelimit-Limit header — a header injected exclusively
		// by Argo's gRPC-gateway rate-limit middleware. Survey (2026-05-27):
		// 67 of 156 Shodan hosts confirmed via this pattern; all auth-enforced
		// (401 on /api/v1/version and /api/v1/userinfo). Severity=info because
		// auth is working — version disclosure only.
		Name:         "Argo Workflows (auth-enforced)",
		DefaultPorts: []int{2746, 443, 80, 8080, 8443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				// X-Ratelimit-Limit header is injected exclusively by Argo's
				// gRPC-gateway rate-limit middleware; empty Value = "header exists".
				{Type: "header_contains", Field: "X-Ratelimit-Limit", Value: ""},
				{Type: "body_contains", Value: "noindex"},
				{Type: "body_contains", Value: "favicon-32x32.png"},
			}},
		},
		Severity: "info",
	},
	{
		Name: "Flyte Console",
		// Ports: 8088 (Flyte sandbox default) and 30080 (NodePort in k8s deploys).
		// Cadence Web also runs on 8088 — both fingerprints fire; the json_field
		// anchor discriminates: Flyte returns controlPlaneVersion, Cadence returns
		// domains/clusters.
		DefaultPorts: []int{8088, 30080},
		Probes: []Probe{
			{Path: "/api/v1/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "controlPlaneVersion"},
			}},
			{Path: "/api/v1/projects", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "projects"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Mage.ai",
		// Port 6789 = default Mage server port (docker run -p 6789:6789 mageai/mageai).
		// /api/kernels returns running Jupyter kernels; /api/pipelines returns the full
		// pipeline inventory. Both are unauth on default installs.
		// Kernel access = remote code execution via the kernel API — critical severity.
		DefaultPorts: []int{6789},
		Probes: []Probe{
			{Path: "/api/kernels", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "kernels"},
			}},
			{Path: "/api/pipelines", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "pipelines"},
			}},
		},
		Severity: "critical",
	},
	{
		Name: "ZenML",
		// Port 8237 = ZenML server default. Default install ships with an empty
		// password for the default user — auth is present but trivially bypassed.
		// /api/v1/info returns version info; the "version" field is the tight anchor
		// since body_contains "zen" is too broad (Zendesk, Zenoss, etc.).
		DefaultPorts: []int{8237},
		Probes: []Probe{
			{Path: "/api/v1/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "zenml"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "status"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Kestra",
		// Port 8080 — shared with Airflow, Spark, Conductor, Hatchet, etc.
		// Anchor on Kestra-specific paginated response shape: top-level "results"
		// array + "total" field on /api/v1/flows, and the unique "taskRunList"
		// string that appears in flow execution objects.
		// Pre-0.24 installs are fully open (no auth required).
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/api/v1/flows", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "results"},
				{Type: "body_contains", Value: "taskRunList"},
			}},
			{Path: "/api/v1/flows/distinct-namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "namespace"},
				{Type: "body_contains", Value: "Kestra"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Apache DolphinScheduler",
		// Port 12345 = DolphinScheduler API server default.
		// Default credentials admin/dolphinscheduler123 are widely unchanged in
		// production; CVE-2024-43202 enables unauth RCE via Python task submission.
		// Anchor: the SPA root path serves an HTML redirect to /ui/#/login containing
		// the literal string "/dolphinscheduler/ui/#/login".
		DefaultPorts: []int{12345},
		Probes: []Probe{
			{Path: "/dolphinscheduler/ui/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "dolphinscheduler"},
			}},
			{Path: "/dolphinscheduler/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "/dolphinscheduler/ui/#/login"},
			}},
		},
		Severity: "critical",
	},
	{
		Name: "Netflix Conductor",
		// Port 8080 — shared port; anchor tightly on Conductor-specific fields.
		// /api/metadata/workflow returns workflow definitions; each definition
		// contains the "ownerApp" field which is unique to Conductor's schema.
		// body_contains "ownerApp" + json_field "results" is the conjunctive
		// discriminator that rejects Kestra, Airflow, and other 8080 services.
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/api/metadata/workflow", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "results"},
				{Type: "body_contains", Value: "ownerApp"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "conductor"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Windmill",
		// Port 80 = primary (served via Caddy reverse proxy in default docker-compose).
		// /api/health returns {"db":"ok","worker_count":N} — the db + worker_count
		// combination is unique to Windmill's health response schema.
		// CVE-2026-29059 (CVSS 10.0) affects unpatched instances; default admin
		// credentials are set on first deploy and frequently left unchanged.
		DefaultPorts: []int{80, 443, 8000},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "db"},
				{Type: "json_field", Field: "worker_count"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "windmill"},
			}},
		},
		Severity: "critical",
	},
	{
		Name: "Restate",
		// Ports: 9070 = admin/management API (no auth by default); 8080 = ingress
		// (service invocation endpoint). /services on :9070 returns registered service
		// list; /deployments returns registered deployment configs.
		// Auth is completely absent on the admin port in default installs.
		DefaultPorts: []int{9070, 8080},
		Probes: []Probe{
			{Path: "/services", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "services"},
			}},
			{Path: "/deployments", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "deployments"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Hatchet",
		// Port 8080 = Hatchet API server (shared — anchor on Hatchet-specific fields).
		// Port 8733 = internal healthcheck port (maps to /healthz).
		// /api/v1/meta is the Hatchet-specific metadata endpoint; body_contains
		// "hatchet" discriminates from other 8080 services sharing the port.
		// Default install also exposes PostgreSQL on 5435 and RabbitMQ on 15673.
		DefaultPorts: []int{8080, 8733},
		Probes: []Probe{
			{Path: "/api/v1/meta", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "hatchet"},
			}},
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "hatchet"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Dagster",
		// Port 3000 = Dagster webserver (OSS default).
		// /server_info exposes dagster_webserver_version — field name unique to Dagster.
		// /graphql exposes the full GraphQL API including runConfigYaml (stores DB
		// credentials and API keys). Auth is off by default; GitHub issue #2219 open
		// since 2020, explicitly deferred by maintainers.
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/server_info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "dagster_webserver_version"},
			}},
			{Path: "/graphql", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "DagsterRunStatus"},
			}},
		},
		Severity: "high",
	},

	// ── BI / Dashboard / Visualization ──────────────────────────
	{
		Name:         "Metabase",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/session/properties", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "has-user-setup"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Superset",
		DefaultPorts: []int{8088, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/api/v1/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "message"},
				{Type: "body_contains", Value: "Superset"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Redash",
		DefaultPorts: []int{5000, 80, 443},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "workers"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "high",
	},

	// ── Observability / infra co-deployed with AI stacks ───────
	{
		Name: "Grafana",
		// Grafana's upstream default is :3000, but production deployments
		// almost always front it via nginx/Traefik on 80/443. Field-validated
		// 2026-05-13 against 141.147.71.47:443 which exposes the standard
		// /api/health JSON.
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "json_field", Field: "database"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Prometheus",
		DefaultPorts: []int{9090},
		Probes: []Probe{
			{Path: "/-/healthy", Matches: []MatchCond{
				{Type: "body_contains", Value: "Prometheus Server is Healthy"},
			}},
			{Path: "/api/v1/status/runtimeinfo", Matches: []MatchCond{
				{Type: "json_field", Field: "reloadConfigSuccess"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "MinIO",
		DefaultPorts: []int{9000},
		Probes: []Probe{
			// MinIO health returns empty 200 with x-amz-request-id header.
			// Require both the health path AND the S3-style root error body
			// to avoid matching Rails/Express catch-all routers.
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "AccessDenied"},
				{Type: "body_contains", Value: "xml"},
			}},
			{Path: "/minio/health/live", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "X-Amz-Request-Id", Value: ""},
			}},
		},
		Severity: "high",
	},
	{
		Name: "n8n",
		// Verified live 2026-05-13 against 217.77.5.226:5678 and
		// 89.207.169.68:10243. Single-word body_contains "n8n" over-matched
		// any page that mentioned the project; replaced with conjunctive
		// <title>n8n.io - Workflow Automation</title> + REST_ENDPOINT
		// JavaScript constant.
		DefaultPorts: []int{5678, 80, 443},
		Probes: []Probe{
			{Path: "/rest/active-workflows", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>n8n.io"},
				{Type: "body_contains", Value: "REST_ENDPOINT"},
			}},
		},
		Severity: "critical",
	},

	// ── AI agent platforms ──────────────────────────────────────
	{
		Name:         "OpenHands",
		DefaultPorts: []int{3000, 30000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>OpenHands</title>"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenHands Admin Console"},
			}},
		},
		Severity: "critical",
	},
	{
		// AutoGen Studio (Microsoft AutoGen agent IDE). Source-verified
		// against microsoft/autogen @ python/packages/autogen-studio: the
		// FastAPI app mounts its API under /api/ and serves the React SPA
		// at /. Two API endpoints carry unique-to-AutoGen-Studio messages:
		//   /api/version → message "Version retrieved successfully" + data.version
		//   /api/health  → message "Service is healthy"
		// Exposed AutoGen Studio is critical: an attacker inherits the
		// agent definitions, the tool configs (which frequently embed API
		// keys / credentials), and the agent's autonomy.
		Name:         "AutoGen Studio",
		DefaultPorts: []int{8081, 8001, 8000, 80, 443},
		Probes: []Probe{
			{Path: "/api/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "version retrieved successfully"},
				{Type: "json_field", Field: "data"},
			}},
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "service is healthy"},
				{Type: "json_field", Field: "status"},
			}},
		},
		Severity: "critical",
	},
	{
		// Anti-detect CDP browser-automation server. Field-discovered
		// 2026-05-14 in the browser-automation backend survey
		// (159.195.70.69, 23.19.231.93). A Python aiohttp server fronts
		// Chrome's DevTools Protocol on :9222. Two discriminators, either
		// of which confirms it on its own:
		//
		//   GET /              → an aiohttp control-plane JSON shape
		//                        {"status","active","processes":{...,
		//                        "seed","proxy","timezone","locale"}}.
		//                        The per-process seed/proxy fields are
		//                        anti-fingerprint controls — unique to
		//                        this class of automation tooling.
		//   GET /json/version  → a valid CDP version doc, but served by
		//                        aiohttp (Server header), not Chrome.
		//
		// Both probes REQUIRE the aiohttp Server header. That is what
		// keeps this fingerprint off (a) the CDP honeypot fleet, which
		// fakes /json/version with a bare-Chrome header and never serves
		// the control-plane root, and (b) raw Chrome CDP, whose HTTP
		// server is Chrome's own, not aiohttp.
		Name:         "Anti-detect CDP server",
		DefaultPorts: []int{9222, 9223, 3000, 5100},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Server", Value: "aiohttp"},
				{Type: "json_field", Field: "active"},
				{Type: "body_contains", Value: "processes"},
				{Type: "body_contains", Value: "seed"},
			}},
			{Path: "/json/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Server", Value: "aiohttp"},
				{Type: "body_contains", Value: "websocketdebuggerurl"},
			}},
		},
		Severity: "high",
	},

	// ── Code assistants (category 09) ───────────────────────────
	// All fingerprints below were source-verified against live
	// confirmed hosts during the 2026-05-14 code-assistant survey
	// (see AI-LLM-Infrastructure-OSINT/shodan/queries/09-code-assistants.md).
	{
		// OpenHands (All Hands AI) — autonomous coding-agent backend,
		// ex-OpenDevin. FastAPI under /api/, React SPA at /. Two
		// unauthenticated option endpoints confirmed on live hosts:
		//   GET /api/options/config → {"APP_MODE":"oss","GITHUB_CLIENT_ID":
		//                              "","POSTHOG_CLIENT_KEY":"phc_..."}
		//                              APP_MODE is OpenHands-specific.
		//   GET /api/options/models → a JSON array of model id strings.
		// The autonomous agent + Docker workspace puts an exposed
		// instance in the sandbox-escape / agent-hijack tier.
		Name:         "OpenHands",
		DefaultPorts: []int{3000, 3001, 80, 443},
		Probes: []Probe{
			{Path: "/api/options/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "APP_MODE"},
				{Type: "body_contains", Value: "POSTHOG_CLIENT_KEY"},
			}},
			{Path: "/api/options/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "critical",
	},
	{
		// Sourcegraph self-hosted — code-search + Cody backend.
		// /.api/graphql returns the unique string "Private mode
		// requires authentication." even when locked down; the
		// sign-in page title is also Sourcegraph-specific. Indexed
		// private repos are the exposure when auth is off.
		Name:         "Sourcegraph",
		DefaultPorts: []int{80, 81, 443, 7080, 3080},
		Probes: []Probe{
			{Path: "/.api/graphql", Matches: []MatchCond{
				{Type: "body_contains", Value: "Private mode requires authentication"},
			}},
			{Path: "/sign-in", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Sign in - Sourcegraph"},
			}},
		},
		Severity: "high",
	},
	{
		// Sourcebot self-hosted code-search. /api/version returns a
		// bare {"version":"v4.x.x"} (too generic alone), but /api/repos
		// returns the distinctive auth-error envelope
		// {"statusCode":401,"errorCode":"NOT_AUTHENTICATED",...} —
		// errorCode + the NOT_AUTHENTICATED token together are the
		// anchored signal.
		Name:         "Sourcebot",
		DefaultPorts: []int{8080, 3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/repos", Matches: []MatchCond{
				{Type: "json_field", Field: "errorCode"},
				{Type: "body_contains", Value: "NOT_AUTHENTICATED"},
			}},
		},
		Severity: "high",
	},
	{
		// Sweep AI — autonomous PR/issue-fixing agent. uvicorn.
		// GET /health → {"status":"UP","autocomplete":"N/A"}. The
		// autocomplete field is Sweep-specific (a generic health
		// endpoint does not carry it).
		Name:         "Sweep AI",
		DefaultPorts: []int{80, 443, 8080},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "autocomplete"},
				{Type: "body_contains", Value: "status"},
			}},
		},
		Severity: "high",
	},
	{
		// Tabnine self-hosted ("Tabnine Context Engine"). Indexes
		// private repos for completion. /api/version on a locked host
		// returns the Tabnine-specific auth-required message
		// {"error":"Unauthorized","message":"API key required. Use
		// Authorization: Bearer <key> or X-API-Key header."}.
		//
		// Anchored on the full product-unique message string (Insight #6
		// discipline, same shape as the v1.9.31 Evolution API "in the house"
		// fix): json_field:error + the complete "API key required. Use
		// Authorization: Bearer <key> or X-API-Key header." phrase. The
		// partial "X-API-Key header" substring alone is too generic.
		//
		// NOTE: v1.9.33 added a json_field:documentation conjunct to dodge an
		// FP at 48.209.17.55 (cite.videmak.net). That was wrong: real Tabnine
		// does not emit a "documentation" field on this endpoint (the observed
		// body above, the original v1.9.3 survey, and Tabnine's public API
		// docs all lack it), so the conjunct could never fire on a real host —
		// a false negative that defeated the fingerprint. Removed in v1.9.39.
		// The videmak body was byte-identical to real Tabnine, so it cannot be
		// excluded by body content alone; that collision is a known, accepted
		// limitation, not grounds for inventing a phantom field.
		Name:         "Tabnine Context Engine",
		DefaultPorts: []int{443, 80, 8080},
		Probes: []Probe{
			{Path: "/api/version", Matches: []MatchCond{
				{Type: "json_field", Field: "error"},
				{Type: "body_contains", Value: "API key required. Use Authorization: Bearer <key> or X-API-Key header."},
			}},
		},
		Severity: "high",
	},
	{
		// Dyad self-hosted app-builder agent. Static-exported app;
		// the generated app stamps <title>dyad-generated-app</title>
		// — a Dyad-specific title string not seen on other stacks.
		Name:         "Dyad",
		DefaultPorts: []int{80, 443, 3000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "dyad-generated-app"},
			}},
		},
		Severity: "medium",
	},
	{
		// bolt.diy self-hosted app-builder agent (OSS fork of
		// bolt.new). Remix app; the default HTML title is generic
		// ("Create Next App" on some builds) but the body carries
		// the "bolt.diy" string. Anchored to a 200 to avoid matching
		// error pages that reflect the term.
		Name:         "bolt.diy",
		DefaultPorts: []int{3000, 3001, 5173, 8081, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "bolt.diy"},
			}},
		},
		Severity: "medium",
	},
	{
		// Refact.ai self-hosted. The verified live population is small
		// and instances are typically auth-gated (the API returns
		// FastAPI 404s on unauthenticated paths), so the signature is
		// the login-page title string "Refact Server Login" — unique
		// to Refact's self-hosted server. NOTE: "Refact" alone is a
		// false-positive trap (matches "refactor" in JS bundles); the
		// full login-page string is required.
		Name:         "Refact",
		DefaultPorts: []int{80, 443, 8008, 8081},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Refact Server Login"},
			}},
		},
		Severity: "medium",
	},
	{
		// LangGraph Server — LangChain's stateful-agent execution runtime.
		// Survey-38 (2026-05-25): 16 hosts probed, 16/16 unauthenticated. Root key varies by operator:
		//   {"message":"LangGraph Conversational Stock Analyzer API is running"}
		//   {"message":"Docu Companion LangGraph API","version":"3.0.0"}
		//   {"status":"ok","bot":"modengy_v3","engine":"LangGraph"}
		//   {"ok":true,"service":"Sleep Doctor Service","chat_service":"wuji-langgraph"}
		//   {"service":"standalone-langgraph-server","version":"1.0.0"}
		// uvicorn Server header present on 15/16 hosts; primary anchor for FP reduction.
		// x-trace-id response header present on 2/16 (LangChain-managed infra only).
		// Partial-auth failure class confirmed: auth on list endpoints (/assistants, /threads),
		// none on individual resource endpoints (/threads/{id}, /runs/{id}) — Stock.ai / EMOR AI.
		// Default port 2024 is from `langgraph dev` CLI; 8123 is legacy Studio port; 8000 is prod default.
		Name:         "LangGraph Server",
		DefaultPorts: []int{2024, 8123, 8000, 80, 443},
		Probes: []Probe{
			// uvicorn + "LangGraph" body — covers 14/16 survey-38 hosts, highest precision
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Server", Value: "uvicorn"},
				{Type: "body_contains", Value: "LangGraph"},
			}},
			// json_field anchor for "service" key variant without uvicorn header
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "service"},
				{Type: "body_contains", Value: "LangGraph"},
			}},
			// /info endpoint on canonical LangGraph server
			{Path: "/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "langgraph"},
			}},
		},
		Severity: "high",
	},
	{
		// SuperAGI — self-hosted controllable autonomous agent framework.
		// Next.js frontend (port 3000) + FastAPI backend (port 8001).
		// HTML title "SuperAGI" is the primary identity anchor.
		// /api/v1/agents returns agent list with goals + tool assignments = agentic
		// workflow disclosure. 40% of population auth-gated (HTTP 401 on API);
		// 60% open in the 2026-05-16 survey sample.
		Name:         "SuperAGI",
		DefaultPorts: []int{3000, 8001, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "SuperAGI"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "superagi"},
			}},
		},
		Severity: "high",
	},
	{
		// AgentGPT (Reworkd) — browser-based autonomous agent SPA.
		// No JSON API identity endpoint; fingerprint is HTML-only.
		// "reworkd" is the maker name and appears in bundle paths (/_next/static/reworkd/).
		// Auth: none — all 12 confirmed Shodan hits return 200 with zero 401s.
		// Impact: agent run history + task graphs disclosed; /api/agent endpoints if exposed.
		Name:         "AgentGPT",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "AgentGPT"},
				{Type: "body_contains", Value: "reworkd"},
			}},
		},
		Severity: "high",
	},
	{
		// CrewAI Studio — open-source self-hosted multi-agent workflow builder.
		// React frontend (port 3000) + FastAPI backend. No auth in default install.
		// /api/crews returns crew configs with agent + task assignments unauth.
		// Distinct from crewai.com vendor SaaS — those sit behind Cloudflare.
		Name:         "CrewAI Studio",
		DefaultPorts: []int{3000, 8000, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "CrewAI Studio"},
			}},
			{Path: "/api/crews", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "critical",
	},
	{
		// Agno (formerly Phidata) — agent framework playground server.
		// /openapi.json carries the boilerplate description "Your multi-agent
		// operating system." on both confirmed deployments; this is Agno's
		// standard playground server description and survives operator title changes.
		// /agents returns a top-level JSON array (not an object); each element has
		// id, name, model, and tools.tools[].name revealing data-source access.
		// Port 7777 is the upstream playground default; 3000/8000 common in deploys.
		//
		// Shodan note: "Your multi-agent operating system." returns 0 Shodan results.
		// Shodan indexes port 7777 HTTP headers only (uvicorn banner) — the JSON body
		// never lands in the index. Discovery dork: http.html:"agno-agents" (port 3000
		// HTML; Shodan indexed it on an earlier crawl even though the string is absent
		// from current live responses). Probe and dork intentionally use different anchors.
		Name:         "Agno",
		DefaultPorts: []int{7777, 3000, 8000},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Your multi-agent operating system."},
			}},
			{Path: "/agents", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		// GPT Researcher — autonomous web research agent (FastAPI, port 8000).
		// The Python module name "gpt_researcher" (underscore) surfaces in
		// JS bundle import paths and static asset URLs — more distinctive than
		// the hyphenated URL slug and survives CDN caching.
		// /api/report is the primary generation endpoint; accessible unauth by default.
		Name:         "GPT Researcher",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gpt_researcher"},
			}},
			{Path: "/api/report", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "body_contains", Value: "method not allowed"},
			}},
		},
		Severity: "high",
	},
	{
		// Devika — open-source agentic AI software engineer (Flask, port 1337).
		// stitionai/devika: Vue.js frontend, Python Flask backend on same port.
		// /api/agents and /api/projects return full project state unauth.
		// "stitionai" is the org name embedded in static paths and bundle sources.
		Name:         "Devika",
		DefaultPorts: []int{1337, 3000, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Devika"},
				{Type: "body_contains", Value: "stitionai"},
			}},
			{Path: "/api/projects", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Mem0",
		// Default is 8888 in upstream docs, but field-validated 2026-05-13
		// against 45.77.183.19:8000 and other Shodan hits that run Mem0
		// behind uvicorn on the standard FastAPI port.
		DefaultPorts: []int{8888, 8000, 8080},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "body_contains", Value: "Mem0 REST APIs"},
			}},
			{Path: "/v1/memories", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Coolify",
		DefaultPorts: []int{8000, 443},
		Probes: []Probe{
			// Coolify returns JSON 401 when Accept: application/json is sent,
			// but always sets coolify_session cookie on any request.
			{Path: "/", Matches: []MatchCond{
				{Type: "header_contains", Field: "Set-Cookie", Value: "coolify_session"},
			}},
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Coolify</title>"},
			}},
		},
		Severity: "low",
	},
	{
		Name:         "Clawdbot",
		DefaultPorts: []int{18789, 443, 80},
		Probes: []Probe{
			// clawdbot-app is the React app's root element id — appears in the
			// real-deployment HTML and not in upstream docs / marketing pages.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "clawdbot-app"},
			}},
		},
		Severity: "medium",
	},

	// ── AI safety / eval / guardrails ───────────────────────────
	// All fingerprints in this section combine status_code + JSON shape +
	// distinctive keyword (conjunctive). Single-word body_contains is
	// disallowed — it produced FPs at population scale (Clipface ≠ Garak,
	// LiveChat ≠ DeepEval, EDocs ≠ DeepEval — see ai-safety-eval-cloud-survey
	// methodology correction 2026-05-05).
	{
		Name: "Promptfoo",
		// Verified live 2026-05-13 against 38.105.232.166:3000.
		// Some Promptfoo deployments ship only the SPA front-end without
		// a mounted /api/* — the canonical HTML has <title>promptfoo</title>
		// + a /promptfoo/favicon.png unique asset path.
		DefaultPorts: []int{15500, 5000, 3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "promptfoo"},
			}},
			{Path: "/api/eval", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>promptfoo</title>"},
				{Type: "body_contains", Value: "/promptfoo/favicon"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "NeMo Guardrails",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/v1/rails/configs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "/v1/rails/configs"},
				{Type: "body_contains", Value: "openapi"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "DeepEval Server",
		DefaultPorts: []int{5000, 8000, 8080},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "service"},
				{Type: "body_contains", Value: "deepeval"},
			}},
			{Path: "/api/v1/evaluations", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "LangSmith Self-Hosted",
		DefaultPorts: []int{1984, 8080},
		Probes: []Probe{
			{Path: "/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "instance_flags"},
			}},
			{Path: "/api/v1/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "langsmith"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Inspect AI",
		DefaultPorts: []int{7575, 7576, 8080},
		Probes: []Probe{
			{Path: "/api/logs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "<title>inspect"},
				{Type: "body_contains", Value: "log_dir"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Garak REST",
		DefaultPorts: []int{5000, 8000, 8080},
		Probes: []Probe{
			{Path: "/api/v1/garak/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "garak_version"},
			}},
			{Path: "/probes", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "probes"},
				{Type: "body_contains", Value: "garak"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Lakera Guard Self-Hosted",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/v1/guard", Matches: []MatchCond{
				{Type: "header_contains", Field: "Server", Value: "lakera"},
			}},
			{Path: "/api/v1/guards", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "guards"},
			}},
		},
		Severity: "high",
	},

	// ── Exposed file servers ────────────────────────────────────
	{
		Name:         "Open Directory",
		DefaultPorts: []int{9090, 8080, 8000, 4000},
		Probes: []Probe{
			// Python http.server / SimpleHTTPServer
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Directory listing for"},
			}},
			// nginx autoindex
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Index of /"},
			}},
		},
		Severity: "high",
	},

	// ── Specialty data layers — analytic / OLAP / NoSQL ─────────
	// Catalogued in case-studies/commercial/FUTURE-SURVEYS.md as
	// "Specialty data layers". All conjunctive: a server-issued header
	// or JSON field anchors the keyword match, no naked body_contains.
	{
		Name:         "ClickHouse",
		DefaultPorts: []int{8123, 8443, 9091},
		Probes: []Probe{
			// /ping returns "Ok.\n" with X-ClickHouse-* headers always present.
			// header_contains with empty Value matches "header exists at all".
			{Path: "/ping", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ok."},
				{Type: "header_contains", Field: "X-Clickhouse-Server-Display-Name", Value: ""},
			}},
			// /?query=SELECT+1 returns "1\n" with the same X-ClickHouse-* headers.
			{Path: "/?query=SELECT+1", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "X-Clickhouse-Format", Value: ""},
			}},
		},
		Severity: "high",
	},
	// Elasticsearch — Tier-A* (auth optional, off-by-default in the official
	// `elasticsearch:7.x`/`8.x` Docker image — xpack.security.enabled=false
	// is the deployment default). 5,037 unauth instances confirmed at
	// population scale 2026-05-16 (case-studies/commercial/
	// elasticsearch-ai-stack-population-survey-2026-05-16.md). Conjunctive:
	// version + cluster_name + cluster_uuid is the platform anchor — the
	// three-key tuple on / is unique to ES/OpenSearch and rules out generic
	// JSON 200s. enumElasticsearch pulls _mapping field types to distinguish
	// AI-stack (dense_vector / knn_vector field) from generic doc indices.
	{
		Name:         "Elasticsearch",
		DefaultPorts: []int{9200, 9201, 9202, 9203},
		Probes: []Probe{
			// GET / on a healthy ES cluster returns version object +
			// cluster_name + cluster_uuid. Drops the tagline conjunct so
			// OpenSearch (Amazon ES fork, version.distribution=opensearch)
			// also matches — both share the same API surface for our probe.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "json_field", Field: "cluster_name"},
				{Type: "json_field", Field: "cluster_uuid"},
				{Type: "body_contains", Value: "lucene_version"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Pinot Controller",
		DefaultPorts: []int{9000},
		Probes: []Probe{
			// /cluster/info returns canonical Pinot controller JSON.
			{Path: "/cluster/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "clusterName"},
				{Type: "json_field", Field: "controllerHost"},
			}},
			// /tables list — Pinot-specific structure {"tables":[...]}
			{Path: "/tables", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "tables"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "ScyllaDB REST",
		DefaultPorts: []int{10000},
		Probes: []Probe{
			// /api-doc/ returns Swagger 1.2 JSON listing storage_service / system / etc resources.
			// body_contains anchored by both json_field and the distinctive "storage_service" path.
			{Path: "/api-doc/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "apis"},
				{Type: "body_contains", Value: "storage_service"},
			}},
		},
		Severity: "high",
	},

	// ── Specialty data layers — DuckDB-backed APIs ──────────────
	// Discovered via Shodan `DuckDB-HTTP` facet 2026-05-05. The facet itself
	// is substring-noisy (38% of hits are a single SaaS operator's CSP
	// whitelist mentioning @duckdb/duckdb-wasm CDN URL — browser-side WASM,
	// not server-side DuckDB). Conjunctive matching anchors on structured
	// product banners, not the keyword.
	{
		Name:         "Amulet Scan DuckDB API",
		DefaultPorts: []int{3001, 3000, 8000},
		Probes: []Probe{
			// JSON banner at root: {"name":"Amulet Scan DuckDB API","version":"...","mode":"read-only",
			//                       "endpoints":["GET /health",...,"POST /refresh-views"],
			//                       "dataPath":"/var/lib/ledger_raw/raw"}
			// Canton Network (Daml DLT) ledger-explorer backend; surface includes
			// admin endpoints (POST /refresh-views, GET /health/config, /backfill/*).
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "name"},
				{Type: "json_field", Field: "endpoints"},
				{Type: "body_contains", Value: "amulet scan"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Definite.app DuckDB",
		DefaultPorts: []int{80, 443, 3000, 8000},
		Probes: []Probe{
			// Two operational headers together — x-backend-hostname leaks the K8s
			// pod name (duckdb-deployment-* in prod, duckdb-staging-deployment-* in
			// staging) + x-server-version is YYYY.MMDD.0 (git ...) date-versioned.
			// Conjunctive header_contains beats body matching since body is often
			// 2 bytes ("OK").
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "X-Backend-Hostname", Value: "duckdb-"},
				{Type: "header_contains", Field: "X-Server-Version", Value: "(git "},
			}},
		},
		Severity: "high",
	},

	// ── Adjacent (non-AI, noted for defender handoff) ───────────
	// Docker Registry is not an AI service, but often co-deployed with
	// AI stacks. Defender should hand off to nuclide-registry-recon.
	{
		Name:         "Docker Registry",
		DefaultPorts: []int{5000, 51000, 55000},
		Probes: []Probe{
			{Path: "/v2/", Matches: []MatchCond{
				{Type: "header_contains", Field: "Docker-Distribution-Api-Version", Value: "registry/2.0"},
			}},
			{Path: "/v2/_catalog", Matches: []MatchCond{
				{Type: "json_field", Field: "repositories"},
			}},
		},
		Severity: "low",
	},

	// ── Voice / Audio AI (survey 17) ───────────────────────────────────
	// These services are typically Tier-A "no auth concept" and skew toward
	// abuse classes that aren't in the typical CVE corpus: voice-cloning
	// fraud, transcription-compute theft, real-time-agent abuse.

	// Whisper ASR — broad family covering openai-whisper-asr-webservice,
	// faster-whisper, whisper.cpp HTTP server. The /v1/audio/transcriptions
	// endpoint is the OpenAI-compatible discriminator; some servers expose
	// /asr instead. Multiple probes for full family coverage.
	{
		Name: "Whisper ASR",
		// Verified live 2026-05-13 against 37.75.9.88:9000.
		// GET / returns 307 → /docs (FastAPI default). /docs HTML has the
		// title but not the /asr path (that's only in /openapi.json). Added
		// an explicit /openapi.json probe with the canonical title string
		// from the upstream webservice.
		DefaultPorts: []int{9000, 8080, 7860, 8000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "openai-whisper-asr-webservice"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "whisper asr webservice"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "whisper asr webservice"},
				{Type: "body_contains", Value: "/asr"},
			}},
			// /inference fallback for the whisper.cpp server variant. The server
			// returns a 400 error JSON when probed without a multipart audio body,
			// and the error response contains "whisper.cpp" — anchor on that 400.
			{Path: "/inference", Matches: []MatchCond{
				{Type: "status_code", Value: "400"},
				{Type: "body_contains", Value: "whisper.cpp"},
			}},
		},
		Severity: "medium",
	},

	// Coqui XTTS server — /api/tts is the inference endpoint;
	// /api/tts/speakers lists configured voices including any cloned ones.
	// Hardened by status_code + body_contains on the speaker-listing endpoint
	// to avoid colliding with random "tts" hits in marketing copy.
	{
		Name: "Coqui XTTS",
		// Coqui XTTS deployments split into two shapes:
		//   1. Upstream-style API exposing /api/tts/speakers (Flask)
		//   2. Custom HTML UI fork ("XTTS - Generate Speech from Text" /
		//      similar localized title + tts-form / tts-generator-card markup)
		// Verified live 2026-05-13 against 195.87.80.179:8040 (Turkish
		// custom UI). The "coqui" brand string is sometimes absent in
		// custom forks. The HTML probe anchors on the title pattern +
		// a tts-form class.
		DefaultPorts: []int{8020, 5002, 8000, 8040, 80, 443},
		Probes: []Probe{
			{Path: "/api/tts/speakers", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "speaker"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "XTTS"},
				{Type: "body_contains", Value: "coqui"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>xtts"},
				{Type: "body_contains", Value: "tts-form"},
			}},
		},
		Severity: "medium",
	},

	// Piper TTS HTTP wrapper — small, edge-deployed, often on Raspberry Pi.
	// Default port 5000 conflicts with Flask-many; require body_contains to
	// disambiguate.
	{
		Name:         "Piper TTS",
		DefaultPorts: []int{5000, 8080, 10200},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "piper"},
				{Type: "body_contains", Value: "tts"},
			}},
		},
		Severity: "low",
	},

	// RVC WebUI / GPT-SoVITS / Applio — the voice-cloning Gradio family.
	// Distinct fingerprint vs generic Gradio because the page advertises
	// the specific project name. Severity high because this is the
	// fraud-relevant class.
	{
		Name: "RVC Voice Cloning WebUI",
		// Verified live 2026-05-13 against 180.184.96.130:8055.
		// Modern Gradio builds of RVC don't ship the full upstream
		// "Retrieval-based-Voice-Conversion" string; the og:title
		// and gradio_config markdown header carry "RVC WebUI" instead.
		// Two conjuncts (og:title RVC WebUI + gradio_config) keep this
		// from matching arbitrary Gradio apps that mention RVC.
		DefaultPorts: []int{7865, 7860, 7897, 8055, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Retrieval-based-Voice-Conversion"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "GPT-SoVITS"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Applio"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `content="RVC WebUI"`},
				{Type: "body_contains", Value: "gradio_config"},
			}},
		},
		Severity: "high",
	},

	// OpenVoice (MyShell.ai) — multi-language voice cloning via speaker
	// embedding extraction. The se_extractor module name is project-specific.
	{
		Name:         "OpenVoice",
		DefaultPorts: []int{7860, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenVoice"},
				{Type: "body_contains", Value: "myshell"},
			}},
		},
		Severity: "high",
	},

	// ChatTTS (2noise) — conversational TTS, viral mid-2024.
	{
		Name:         "ChatTTS",
		DefaultPorts: []int{7860, 8000, 9966},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ChatTTS"},
				{Type: "body_contains", Value: "2noise"},
			}},
		},
		Severity: "medium",
	},

	// F5-TTS — flow-matching TTS (2024-25). Lab demo deployments.
	{
		Name:         "F5-TTS",
		DefaultPorts: []int{7860, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "F5-TTS"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "swivid/f5-tts"},
			}},
		},
		Severity: "medium",
	},

	// Pipecat (Daily.co) — real-time voice-agent framework. Severity high
	// because abuse is "outbound call automation" not just compute theft.
	{
		Name: "Pipecat Voice Agent",
		// Verified live 2026-05-13 against 18.142.164.147:80 (Pipecat UI).
		// Real deployments redirect / → /client/ and serve <title>Pipecat
		// UI</title>. Single-word body_contains "pipecat" was over-matching
		// risk; tighten to require the title plus the Vite client asset
		// path. Port 80 added to DefaultPorts.
		DefaultPorts: []int{7860, 8000, 8080, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>pipecat"},
				{Type: "body_contains", Value: "assets/index-"},
			}},
			{Path: "/client/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>pipecat"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "pipecat"},
			}},
		},
		Severity: "high",
	},

	// Vocode — voice-agent framework, often paired with twilio/daily.co.
	// Conjunctive match on banner term + framework signature to keep the
	// 4-hit Shodan FP-prone "vocode" string from over-matching.
	{
		Name:         "Vocode Voice Agent",
		DefaultPorts: []int{8000, 3000, 7860},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "vocode"},
				{Type: "body_contains", Value: "transcriber"},
			}},
		},
		Severity: "high",
	},

	// LiveKit — real-time AV pipeline framework + Meet demo app.
	{
		Name: "LiveKit Agents",
		// Three deployment shapes:
		//   1. Agent runner serving its own HTML (rare; "livekit-agents")
		//   2. LiveKit Server admin UI ("livekit-server")
		//   3. LiveKit Meet demo app (dominant — 992 Shodan hits 2026-05-13).
		// Verified live 2026-05-13 against 143.20.37.151:3002 (LiveKit Meet).
		// The Meet demo bundles /images/livekit-meet-home.svg as a unique
		// asset path; combined with the Next.js _next/static path this is
		// distinct enough to avoid bare-brand mentions.
		DefaultPorts: []int{7880, 8080, 3000, 3002, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-agents"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-server"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-meet-home"},
				{Type: "body_contains", Value: "_next/static"},
			}},
		},
		Severity: "medium",
	},

	// Kokoro-FastAPI (remsky) — OpenAI-compatible TTS server, port 8880.
	// No auth by default; api_key field accepts "not-needed" with no validation.
	// /debug/system is a project-unique path not present in any other TTS server.
	// Multiple competing Docker images in the wild (ghcr.io/remsky/kokoro-fastapi-*,
	// hwdsl2/kokoro-server). Verified via API schema 2026-05-28.
	{
		Name:         "Kokoro-FastAPI",
		DefaultPorts: []int{8880},
		Probes: []Probe{
			{Path: "/debug/system", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "cpu_percent"},
			}},
			{Path: "/v1/audio/voices", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"id"`},
				{Type: "body_contains", Value: `"name"`},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Kokoro"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "high",
	},

	// Chatterbox TTS Server (devnen variant) — zero-shot voice cloning, port 8000.
	// /api/model-info returns JSON with "engine" field (e.g. "chatterbox-turbo") —
	// distinctive differentiator from generic FastAPI TTS servers on port 8000.
	// /upload_reference is an unauthenticated voice-clone upload surface.
	// Severity high: voice-clone fraud, not just compute theft.
	{
		Name:         "Chatterbox TTS",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/api/model-info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "engine"},
			}},
			{Path: "/get_predefined_voices", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "voice"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "chatterbox"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "high",
	},

	// Chatterbox TTS API (travisvn variant) — same model, different server wrapper.
	// Port 4123 is near-unique to this project. /health + /config confirm identity.
	{
		Name:         "Chatterbox TTS API",
		DefaultPorts: []int{4123},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
			}},
			{Path: "/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "chatterbox"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Chatterbox"},
			}},
		},
		Severity: "high",
	},

	// Orpheus-FastAPI (canopyai) — 3B-param Llama TTS with emotion tags.
	// Port 8899 is near-unique to Orpheus deployments. No auth in default config.
	{
		Name:         "Orpheus-FastAPI",
		DefaultPorts: []int{8899},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Orpheus"},
				{Type: "body_contains", Value: "swagger"},
			}},
			{Path: "/v1/audio/speech", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
			}},
		},
		Severity: "medium",
	},

	// WhisperLive — real-time streaming ASR. Two surfaces:
	//   1. REST API (port 8000): FastAPI with /v1/audio/transcriptions
	//   2. WebSocket (port 9090): sends {"message":"SERVER_READY"} on connect.
	// PII severity: operators running this for meeting transcription expose
	// live audio streams to anyone who connects without auth.
	{
		Name:         "WhisperLive",
		DefaultPorts: []int{8000, 9090},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "WhisperLive"},
				{Type: "body_contains", Value: "swagger"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "nearly-live implementation"},
			}},
		},
		Severity: "high",
	},

	// Deepgram Self-Hosted (on-prem) — enterprise ASR. Runtime auth is OFF:
	// NGC API key gates image pull but /v1/status and /v1/listen require no
	// per-request auth once the container is running. /v1/status returns JSON
	// with "system_health" field — unique to this product.
	{
		Name:         "Deepgram Self-Hosted",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/v1/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "system_health"},
				{Type: "json_field", Field: "active_batch_requests"},
			}},
		},
		Severity: "critical",
	},

	// ── Embedding Services ──────────────────────────────────────────────

	// HuggingFace Text Embeddings Inference (TEI) — canonical standalone
	// embedding server from HuggingFace. Exposes /info with model_pipeline_tag
	// = "feature-extraction" (never present in LLM inference servers).
	// Ships auth-off; compute theft + embedding oracle against downstream RAG.
	{
		Name:         "HuggingFace TEI",
		DefaultPorts: []int{80, 8080, 3000},
		Probes: []Probe{
			{Path: "/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "model_pipeline_tag"},
				{Type: "body_contains", Value: "feature-extraction"},
			}},
		},
		Severity: "medium",
	},

	// infinity-embedding (michaelfeil/infinity) — OpenAI-compat embedding
	// server. Default port 7997. /openapi.json title is "Infinity Emb".
	{
		Name:         "infinity-embedding",
		DefaultPorts: []int{7997, 8080, 8000},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Infinity Emb"},
			}},
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "infinity_emb"},
			}},
		},
		Severity: "medium",
	},

	// Custom Embedding API — FastAPI/uvicorn embedding servers (the dominant
	// shape in the wild). Root GET / returns JSON with "embed" key referencing
	// a model name, or "embedding_dimension" (OpenVINO pattern). Covers
	// BAAI/bge, nomic-embed, multilingual-e5, and other model families
	// served via custom FastAPI wrappers. Auth-off by default on every
	// observed instance; leaks model name, embedding dimension, vector DB
	// collection names, and internal filesystem paths.
	{
		Name:         "Embedding API",
		DefaultPorts: []int{8000, 8001, 8080, 8002, 8100, 5000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "embedding_dimension"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "embed"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "embedding_dimension"},
			}},
		},
		Severity: "medium",
	},
	// === AI observability tier (Phase 3 of the 2026-05 sweep) ===
	//
	// Phoenix is the load-bearing one: 25% unauth rate at population scale
	// (94 of 377 hosts on 2026-05-10) driven by PHOENIX_ENABLE_AUTH=False
	// shipping default. The other four ship auth-on-by-default; we fingerprint
	// them to surface latent primitives (default secrets, weak ADMIN keys).
	{
		Name:         "Arize Phoenix",
		DefaultPorts: []int{6006, 80, 443, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Phoenix</title>"},
				{Type: "body_contains", Value: "Arize Phoenix"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "platformVersion"},
				{Type: "body_contains", Value: "Phoenix"},
			}},
		},
		Severity: "critical",
	},
	{
		Name:         "Helicone Self-Hosted",
		DefaultPorts: []int{3000, 80, 443, 8585},
		Probes: []Probe{
			// Direct /signin probe - returns 200 with BetterAuth login page.
			// The body_not_contains anti-match rejects the marketing-site
			// reflection observed live 2026-05-13 — helicone.ai's static
			// pages ship a hardcoded <link rel="canonical" href="https://
			// www.helicone.ai/">, while a real self-hosted instance does
			// not.
			{Path: "/signin", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "_next/static"},
				{Type: "body_contains", Value: "helicone"},
				{Type: "body_not_contains", Value: `canonical" href="https://www.helicone.ai/"`},
			}},
			// HTTP client follows the / -> /signin 307. After redirect we
			// land on signin and the body still contains helicone branding.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "_next/static"},
				{Type: "body_contains", Value: "helicone"},
				{Type: "body_not_contains", Value: `canonical" href="https://www.helicone.ai/"`},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Lunary",
		// Iter 21: catastrophic over-match against Elasticsearch fixed.
		// The old `/api/v1/health` + `json_field:status` probe matched any
		// JSON with a "status" field — including Elasticsearch's
		// /_cluster/health response (`status: green`). Observed 283 false
		// positives in the n8n corpus sweep against hosts reverse-proxying
		// Elasticsearch at /api/v1/health.
		//
		// Real Lunary returns the exact body `{"status":"OK"}`. We anchor
		// to that exact substring AND anti-match the ES shape via
		// body_not_contains on a unique-to-Elasticsearch field.
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"status":"ok"`},
				{Type: "body_not_contains", Value: "cluster_name"}, // anti-ES, anti-CrateDB
				{Type: "body_not_contains", Value: "active_shards"}, // anti-ES
				{Type: "body_not_contains", Value: "qdrant"},  // anti-Qdrant (2026-05-15 FP)
				{Type: "body_not_contains", Value: "milvus"},  // anti-Milvus body (2026-05-15 FP)
				{Type: "header_not_contains", Field: "Server", Value: "Milvus/"}, // anti-Milvus Server header
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Dashboard | Lunary</title>"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "OpenLIT",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			// The NextAuth middleware redirects /api/* to /login?callbackUrl=...
			// Our HTTP client follows redirects, so we'll see the login page
			// body. The login page contains the OpenLIT brand string.
			{Path: "/api/ping", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenLIT"},
				{Type: "body_contains", Value: "callbackUrl"},
			}},
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenLIT"},
				{Type: "body_contains", Value: "_next/static"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Pezzo",
		DefaultPorts: []int{4200, 3000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Pezzo</title>"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "pezzo"},
				{Type: "body_contains", Value: "<title>"},
			}},
		},
		Severity: "high",
	},
	// ── LLM observability stragglers (Sessions 30+, 2026-05-22) ─────
	{
		Name: "Evidently ML Monitoring",
		// Primary source: github.com/evidentlyai/evidently, evidently/ui/service/
		// Default deploy: `evidently ui --host 0.0.0.0 --port 8000`
		// /api/version always 200 with exact JSON body containing "Evidently UI"
		// as the `application` field — not present in any other platform.
		// /api/projects always 200 (no auth concept in default deploy) returning
		// a JSON array of project objects (may be empty on fresh instance).
		// Fingerprinted live against evidently/evidently-service:latest (v0.7.21)
		// on 2026-05-22 during the Evidently population survey.
		DefaultPorts: []int{8000, 3000, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/api/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Evidently UI"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "high",
	},
	// ── Medical & edge AI (Survey 28, 2026-05-15) ───────────────────
	{
		Name: "MONAI Label Server",
		// Primary source: github.com/Project-MONAI/MONAILabel
		// monailabel/main.py: -p/--port default=8000, -i/--host default=0.0.0.0
		// monailabel/interfaces/app.py info() returns meta with keys:
		//   name, description, version, labels, models, trainers, strategies,
		//   scoring, train_stats, datastore
		// RBAC opt-in via MONAI_LABEL_AUTH_ROLE_USER setting — default off.
		// Conjunctive marker: `trainers` + `strategies` + `scoring` together
		// are not co-emitted by any other fingerprinted platform.
		// Endpoint path is `/info/` (trailing slash); the router prefix is
		// "/info" and the handler binds "/" relative to that.
		// Tier-A* (auth optional, off-by-default).
		DefaultPorts: []int{8000, 8001, 80, 443},
		Probes: []Probe{
			{Path: "/info/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "trainers"},
				{Type: "json_field", Field: "strategies"},
				{Type: "json_field", Field: "scoring"},
				{Type: "json_field", Field: "datastore"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Orthanc DICOM Server",
		// Primary source: Orthanc REST book at orthanc.uclouvain.be
		// /system returns JSON with Name="Orthanc", DicomAet, DicomPort,
		// HttpPort, ApiVersion, Version, DatabaseVersion, PluginsEnabledInDb.
		// Default ports: 8042 (HTTP REST), 4242 (DICOM TCP).
		// RemoteAccessAllowed defaults false in modern config.json — when
		// enabled without AuthenticationEnabled or RegisteredUsers, instance
		// is fully unauthenticated. Default creds historically orthanc:orthanc
		// (when auth enabled but unchanged).
		// Tier-A* (config-gated remote access; once enabled, often unauth).
		DefaultPorts: []int{8042, 8043, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/system", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "DicomAet"},
				{Type: "json_field", Field: "ApiVersion"},
				{Type: "body_contains", Value: "Orthanc"},
			}},
		},
		Severity: "critical",
	},
	{
		Name: "dcm4che / dcm4chee-arc DICOM Archive",
		// Primary source: github.com/dcm4che/dcm4chee-arc-light
		// Web admin UI at /dcm4chee-arc/ui2/ (Keycloak-fronted in modern builds).
		// /dcm4chee-arc/aets returns JSON list of Application Entities when
		// security relaxed; otherwise 401/302 to Keycloak — both confirm
		// platform identity. Default deployment runs on Wildfly with port 8080.
		// Tier-C (auth-on-default via Keycloak) but Keycloak unconfigured /
		// auth-relaxed deployments expose AE list + study queries.
		DefaultPorts: []int{8080, 8443, 80, 443},
		Probes: []Probe{
			{Path: "/dcm4chee-arc/aets", Matches: []MatchCond{
				{Type: "json_array"},
			}},
			// /dcm4chee-arc/ fallback covers the Keycloak-fronted redirect case.
			// Anchored on status + path so an arbitrary page containing the literal
			// "dcm4chee" (e.g., a research paper or vendor doc page) does not match.
			{Path: "/dcm4chee-arc/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "dcm4chee"},
			}},
		},
		Severity: "critical",
	},
	{
		Name: "DICOMweb (QIDO-RS)",
		// Standard: DICOM PS3.18 (DICOMweb). QIDO-RS exposes /studies,
		// /studies/{study}/series, /studies/{study}/series/{series}/instances
		// returning Content-Type: application/dicom+json with DICOM tag keys
		// (8-hex-digit field names like "0020000D" StudyInstanceUID,
		// "00100010" PatientName, "00100020" PatientID).
		// Conjunctive: JSON array root + a canonical DICOM tag key. The tag
		// pattern is what disambiguates a DICOMweb response from any other
		// JSON-array endpoint — a naked /studies path is too generic.
		// Tier-A* (operator-configured; commonly exposed for cross-site
		// research access without auth).
		DefaultPorts: []int{8080, 8042, 443, 80, 8443},
		Probes: []Probe{
			{Path: "/studies", Matches: []MatchCond{
				{Type: "json_array"},
				{Type: "body_contains", Value: "0020000D"},
			}},
			{Path: "/dicomweb/studies", Matches: []MatchCond{
				{Type: "json_array"},
				{Type: "body_contains", Value: "0020000D"},
			}},
		},
		Severity: "critical",
	},
	{
		Name: "NVIDIA NIM",
		// Primary source: NVIDIA NIM container API reference.
		// NIM microservices expose OpenAI-compatible /v1/* plus a NIM-specific
		// /v1/metadata returning {"modelInfo":[...]} with `shortName` containing
		// the NIM model id (e.g. "meta/llama3-8b-instruct").
		// /v1/health/ready returns 200 when warm. Endpoint identity comes from
		// the /v1/metadata `modelInfo` array (OpenAI-compat servers don't ship
		// this surface) plus the `nvcr.io` or `nim-` substring in headers/body.
		// Tier-A* (default container exposes :8000 without auth; gating is the
		// operator's job via reverse proxy).
		DefaultPorts: []int{8000, 8080, 80, 443},
		Probes: []Probe{
			{Path: "/v1/metadata", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "modelInfo"},
			}},
		},
		Severity: "high",
	},
	// ── Exposed API Credentials (Insight #38, 2026-05-19) ──────────────
	// Cross-cutting fingerprint that fires when a high-signal vendor credential
	// prefix appears in the HTTP body of any service on any port. Detection is
	// independent of the service type — a Dokploy build log, a React SPA bundle,
	// a Coolify status page, or a rogue env-var dump all produce the same signal.
	//
	// Each probe is anchored on status_code = 200 (Insight #6 discipline applied
	// 2026-05-19): credential leaks in the wild come from 200-response surfaces
	// (env-var dumps, build logs, JS bundles, debug endpoints). The 4xx/5xx case
	// where a credential leaks into an error message is left to scanCredentials
	// at the enumerator stage (which runs against the response body separately).
	// The prefix itself is the structured signal — vendor-unique, ≥6 chars, with
	// a hyphen or underscore boundary character that makes substring collisions
	// vanishingly rare. Final hard-proof verification happens in scanCredentials
	// via regex extraction + format validation per credentialClass.
	//
	// Source: Insight #38 (exfil-credential hard-proof chain).
	{
		Name:         "Exposed API Credentials",
		DefaultPorts: []int{80, 443, 3000, 3001, 4000, 5000, 7860, 8000, 8080, 8443, 8888, 9000},
		Probes: []Probe{
			// Langfuse secret key in body
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sk-lf-"},
			}},
			// Helicone API key in body
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sk-helicone-"},
			}},
			// Stripe live secret (highest financial impact)
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sk_live_"},
			}},
			// Stripe test secret
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sk_test_"},
			}},
			// Anthropic API key (current key version prefix)
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sk-ant-api03-"},
			}},
			// LangSmith tokens
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "lsv2_pt_"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "lsv2_sk_"},
			}},
			// OpenRouter
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "sk-or-v1-"},
			}},
			// Slack user token (xoxp- is long enough to be low-FP on root)
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "xoxp-"},
			}},
			// Langfuse env-var on debug/env endpoints
			{Path: "/env", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LANGFUSE_SECRET_KEY"},
			}},
			{Path: "/debug/vars", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LANGFUSE_SECRET_KEY"},
			}},
		},
		Severity: "critical",
	},

	// ── Redis management GUI ─────────────────────────────────────────────

	// RedisInsight — Redis official GUI by Redis Ltd. Default port 8001 (older
	// v1 releases); v2 (RedisInsight 2.x) ships on port 5540 but also listens
	// on 8001 in many Docker deployments. The /api/databases endpoint returns
	// connection records including plaintext passwords in the `password` field —
	// no authentication required on a default install.
	// Insight #61 (2026-05-26): 7/27 responsive instances leaked Redis credentials.
	// Three-conjunct fingerprint (Insight #6 discipline):
	//   1. /api/info → json_field:"version" (product-unique key in RedisInsight API)
	//   2. /api/databases → status_code 200 + json_array (returns [] or [...] always)
	//   3. / → body_contains:"RedisInsight" (SPA title tag)
	{
		Name:         "RedisInsight",
		DefaultPorts: []int{5540, 8001, 8080, 80, 443},
		Probes: []Probe{
			// Primary: /api/info is RedisInsight-specific; returns {"version":"X.Y.Z",...}.
			// Requires body_contains "RedisInsight" to prevent FP against any FastAPI
			// service that exposes /api/info with a version field (2026-05-26: Collision
			// Analytics API at 5.78.111.11:8001 triggered this probe — false positive).
			{Path: "/api/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "RedisInsight"},
			}},
			// Secondary: /api/databases returns the connection list (array, possibly empty).
			// json_array match fires on [] and [...].
			{Path: "/api/databases", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			// Tertiary: SPA root contains "RedisInsight" in the title.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "RedisInsight"},
			}},
		},
		Severity: "critical",
	},

	// ── Chatbot frameworks ───────────────────────────────────────────────

	// Rasa Open Source — conversational AI framework. Default port 5005.
	// Rasa ships with NO authentication on the REST webhook channel by default;
	// operators must explicitly configure a token in credentials.yml.
	// Population survey 2026-05-22: 98/196 (50%) confirmed unauth, 0 auth-gated.
	// Three-conjunct marker (Insight #6 discipline):
	//   1. GET / → "Hello from Rasa: X.Y.Z" (product-unique banner)
	//   2. /status → JSON with model_file field
	//   3. /webhooks/rest/webhook GET → 405 Method Not Allowed
	//      (confirms endpoint exists without triggering a POST interaction)
	// Confirmed operator classes: government (ODPC Kenya), utilities (LECO Sri Lanka,
	// Uludağ Elektrik), insurance (HNBGI), payment validation, education.
	// Versions confirmed: 2.8.0, 3.5.10, 3.6.20, 3.9.6.
	{
		Name:         "Rasa",
		DefaultPorts: []int{5005, 80, 443, 8080},
		Probes: []Probe{
			// Primary: version banner on root. "Hello from Rasa: X.Y.Z" is
			// product-unique — no framework or middleware emits this string.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Hello from Rasa:"},
			}},
			// Secondary: /status returns model file path + training job count.
			// json_field "model_file" is Rasa-specific; absent on any other platform.
			{Path: "/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "model_file"},
			}},
			// Tertiary: /webhooks/rest/webhook existence probe (GET → 405 Allow: GET).
			// 405 with Allow:GET confirms the POST endpoint exists without triggering
			// a bot interaction. Rasa returns 405 on GET to the webhook path.
			{Path: "/webhooks/rest/webhook", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "header_contains", Field: "Allow", Value: "GET"},
			}},
		},
		Severity: "high",
	},

	// ── WhatsApp automation ──────────────────────────────────────────────
	{
		// Evolution API — open-source WhatsApp automation framework.
		// Default port 8080. Root endpoint returns JSON with status, version,
		// and clientName fields. "I'm in the house!" is the product-unique
		// banner string; no other service emits it.
		// Exposed Evolution API gives unauthenticated access to WhatsApp session
		// management: create/destroy sessions, send messages, read conversation
		// history, extract QR codes for session hijacking. Severity: high.
		// First confirmed live: 192.169.81.2:8080 (bmaconnect.com.br, Brazilian
		// WhatsApp SaaS) — 2026-05-26.
		Name:         "Evolution API (WhatsApp)",
		DefaultPorts: []int{8080, 3000},
		Probes: []Probe{
			// Root returns {"status":"online","version":"2.x.x",...,
			// "message":"I'm in the house!"} — the full phrase
			// "in the house" is the product-unique anchor. "house" alone
			// caused FP collisions against ClearML :8080 (2026-05-26).
			// Naked /manager probe removed — status_code:200 alone fires
			// on any service with a /manager route.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "in the house"},
			}},
		},
		Severity: "high",
	},
	{
		// Apollo GraphQL API — detects Apollo Server instances by the CSRF
		// rejection it issues on unauthenticated GET requests to /graphql.
		// Apollo Server 3+ blocks cross-origin GET requests with a 400 and
		// the message "This operation has been blocked as a potential
		// Cross-Site Request Forgery (CSRF) attack". This is a three-conjunct
		// anchor: status_code 400 + json_field errors + body_contains the
		// CSRF phrase. False-positive probability at population scale: very low
		// (the CSRF phrase is Apollo-specific; generic CSRF protections use
		// different language and usually return HTML, not JSON).
		//
		// Anchor: djaminn.app dev-api (35.187.172.141) and production
		// (34.36.106.50) — both confirmed 2026-05-26.
		Name:         "Apollo GraphQL API",
		DefaultPorts: []int{443, 80, 3000, 4000, 8080, 8000, 5000},
		Probes: []Probe{
			// Primary: Apollo CSRF rejection (GET /graphql → 400 with CSRF JSON).
			{Path: "/graphql", Matches: []MatchCond{
				{Type: "status_code", Value: "400"},
				{Type: "json_field", Field: "errors"},
				{Type: "body_contains", Value: "cross-site request forgery"},
			}},
			// Secondary: /api/graphql variant (same pattern).
			{Path: "/api/graphql", Matches: []MatchCond{
				{Type: "status_code", Value: "400"},
				{Type: "json_field", Field: "errors"},
				{Type: "body_contains", Value: "cross-site request forgery"},
			}},
		},
		Severity: "medium",
	},

	// ── Fine-tuning frameworks ─────────────────────────────────────────────
	// Added 2026-05-26. These hold training data, HuggingFace tokens, and
	// base-model checkpoints — severity: high across the category.
	{
		// LLaMA-Factory (hiyouga/LLaMA-Factory) — Gradio WebUI (port 7860)
		// + FastAPI inference server (port 8000). Two independent probe paths:
		//
		//   GET / (port 7860) — Gradio SPA; <title> carries the brand string
		//   "LLaMA Factory (<hostname>)". Anchored with body_contains "gradio"
		//   (present in every Gradio app's HTML bootstrap) + the brand substring.
		//   Confirmed against http.title:"LLaMA Factory" Shodan dork (~12 hits).
		//
		//   GET /v1/score/evaluation (port 8000) — LLaMA-Factory-specific POST
		//   endpoint exposed on the FastAPI server. An unauthenticated GET returns
		//   405 Method Not Allowed; the JSON body {"detail":"Method Not Allowed"}
		//   is FastAPI's default 405 shape. The path /v1/score/evaluation is not
		//   part of the OpenAI-compatible API spec and does not appear in any other
		//   known inference server — it is LLaMA-Factory-unique.
		//   Source: src/llamafactory/api/app.py, confirmed against docker-compose
		//   (ports: 7860:7860, 8000:8000).
		//
		// NOTE: Axolotl (OpenAccess-AI-Collective/axolotl) has NO built-in HTTP
		// server. It wraps vLLM for post-training inference, producing a standard
		// vLLM/OpenAI-compatible endpoint with no Axolotl-specific signal.
		// Fingerprint not added; would require single-word body match on
		// "axolotl" (FP risk from unrelated content).
		Name:         "LLaMA-Factory",
		DefaultPorts: []int{7860, 8000, 80, 443},
		Probes: []Probe{
			// Gradio WebUI probe — title contains brand string
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LLaMA Factory"},
				{Type: "body_contains", Value: "gradio"},
			}},
			// FastAPI inference server probe — LLaMA-Factory-unique path
			{Path: "/v1/score/evaluation", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "body_contains", Value: "Method Not Allowed"},
				{Type: "json_field", Field: "detail"},
			}},
		},
		Severity: "high",
	},
	{
		// Unsloth Studio — FastAPI backend for the Unsloth fine-tuning UI.
		// Repo: unslothai/unsloth, studio/backend/main.py.
		// Default port: 8888 (--port default=8888 in run.py).
		//
		// GET /api/health returns unauthenticated base object:
		//   {"status":"healthy","service":"Unsloth UI Backend","chat_only":...,
		//    "desktop_protocol_version":1,...}
		//
		// The "service":"Unsloth UI Backend" field is the anchor —
		// it is a hardcoded string in main.py and does not appear in any other
		// known service. "chat_only" is a second Unsloth-specific field
		// (controls whether training UI is shown). Both are emitted
		// unauthenticated to allow the Tauri watchdog and frontend bootstrap
		// to discover the backend before auth is available.
		// Source: studio/backend/main.py line ~550, health_check().
		//
		// Exposure: training data, HuggingFace tokens in the model download
		// flow, exported fine-tuned weights, and training configuration
		// (dataset paths, hyperparameters) are accessible once auth is bypassed
		// or on instances left with default credentials.
		Name:         "Unsloth Studio",
		DefaultPorts: []int{8888, 8000, 8080, 80, 443},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "chat_only"},
				{Type: "body_contains", Value: "Unsloth UI Backend"},
			}},
		},
		Severity: "high",
	},

	// ── ML Governance / Data Catalog ──────────────────────────────────────────
	//
	// OpenMetadata: CVE-2024-28255 (CVSS 9.8) — path parameter injection auth
	// bypass exploited in the wild against K8s clusters. Affects all versions
	// < 1.3.1. Chain: auth bypass → SpEL RCE → env var harvest of all connected
	// datasource credentials. Unauthenticated /api/v1/system/version exposes
	// version string enabling targeted exploit selection.
	{
		Name:         "OpenMetadata",
		DefaultPorts: []int{8585, 8080},
		Probes: []Probe{
			{Path: "/api/v1/system/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "json_field", Field: "revision"},
			}},
		},
		Severity: "critical",
	},

	// DataHub (LinkedIn): GMS backend (port 8080) is auth-off by default unless
	// METADATA_SERVICE_AUTH_ENABLED=true. Even when auth is "enabled", GMS does
	// not cryptographically verify JWT signatures — forge any user token.
	// Default frontend credentials: datahub/datahub. The /config endpoint is
	// unauthenticated and exposes platform version and capability flags.
	{
		Name:         "DataHub GMS",
		DefaultPorts: []int{8080, 9002},
		Probes: []Probe{
			{Path: "/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "noCode"},
				{Type: "body_contains", Value: "datahub"},
			}},
		},
		Severity: "high",
	},

	// Apache Atlas: ships admin/admin as default credentials baked into
	// users-credentials.properties. No forced rotation. Default config disables
	// TLS. Port 21000 is near-exclusive to Atlas in enterprise data stacks.
	// /api/atlas/admin/version is authenticated but admin/admin is the default.
	{
		Name:         "Apache Atlas",
		DefaultPorts: []int{21000, 21443},
		Probes: []Probe{
			{Path: "/api/atlas/admin/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "Description"},
				{Type: "body_contains", Value: "metadata"},
			}},
		},
		Severity: "high",
	},

	// Amundsen (Lyft): no auth by default across all three microservices
	// (frontend :5000, metadata API :5002, search API :5001). Auth requires
	// manual flaskoidc configuration. Full catalog read without credentials:
	// table schemas, ownership, PII tags, column statistics, lineage.
	{
		Name:         "Amundsen",
		DefaultPorts: []int{5000, 5001, 5002},
		Probes: []Probe{
			{Path: "/healthcheck", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "amundsen"},
			}},
		},
		Severity: "medium",
	},

	// Marquez (OpenLineage): no auth by default per documentation. Unauthenticated
	// POST to /api/v1/lineage enables arbitrary lineage event injection.
	// /api/v1/namespaces returns full namespace list; /api/v1/jobs exposes job
	// run history including SQL query text in OpenLineage facets.
	{
		Name:         "Marquez",
		DefaultPorts: []int{5000, 3000, 8080},
		Probes: []Probe{
			{Path: "/api/v1/namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "namespaces"},
			}},
		},
		Severity: "medium",
	},

	// CKAN: open data portal — read is unauthenticated by design; high value
	// when deployed on government/enterprise data infrastructure. Resource URLs
	// in dataset records often embed API keys or tokens from the creating user.
	// /api/3/action/status_show is unauthenticated and exposes ckan_version.
	{
		Name:         "CKAN",
		DefaultPorts: []int{5000, 80, 443},
		Probes: []Probe{
			{Path: "/api/3/action/status_show", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "ckan_version"},
				{Type: "body_contains", Value: "ckan"},
			}},
		},
		Severity: "low",
	},

	// Collibra: enterprise data governance — port 4402 console. Default
	// credentials Admin/Admin documented in quickstart; rarely rotated in
	// enterprise on-prem deployments. Exposure: full enterprise data inventory,
	// business glossary, lineage policies, PII classification rules.
	{
		Name:         "Collibra",
		DefaultPorts: []int{4402, 4421, 4401},
		Probes: []Probe{
			{Path: "/rest/2.0/ping", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "collibra"},
			}},
		},
		Severity: "high",
	},
	// Kubecost: K8s FinOps cost-allocation. No auth by default. /model/clusterInfo leaks
	// cluster name, cloud provider, account, region, and provisioner (EKS/GKE/AKS).
	// /model/allocation returns per-namespace cost topology. /model/helmValues (HIGH) leaks
	// full install-time Helm values including any cloud API keys or passwords passed via
	// values — presence confirmed by probe; secret bodies are NOT read (restraint ethic).
	// Survey-driven DefaultPorts: 80=75 hits, 9090=23, 443=18 (port 2746 pattern ≠ here).
	// Disambiguation: /model/ prefix = Kubecost; bare /allocation at :9003 = OpenCost.
	// Note: Shodan indexes title "Kubecost" on the nginx SPA; port 9090 bare body is not
	// independently indexed for this dork. Use http.title:"Kubecost" + favicon hash 611531125.
	{
		Name:         "Kubecost",
		DefaultPorts: []int{80, 443, 9090},
		Probes: []Probe{
			// Primary: /model/clusterInfo emits structured JSON with provider+provisioner+region.
			// All three conjuncts required: status + top-level "code" key + "provisioner" string.
			{Path: "/model/clusterInfo", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "code"},
				{Type: "body_contains", Value: "provisioner"},
			}},
			// Secondary: /model/allocation with cost data — cpuCost is present in every
			// confirmed instance regardless of whether allocation data is populated.
			{Path: "/model/allocation?window=1d&aggregate=namespace&accumulate=true", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "code"},
				{Type: "body_contains", Value: "cpuCost"},
			}},
		},
		Severity: "high",
	},
	// OpenCost: CNCF cost-allocation exporter. No built-in auth (no auth scheme in swagger.json).
	// API on :9003 (definitive); UI SPA on :9090 proxies to :9003 depending on BASE_URL.
	// /allocation returns per-namespace cpuCost/ramCost/totalCost topology.
	// /metrics carries kubecost_cluster_info (inherited from Kubecost codebase) + node_cpu_hourly_cost.
	// FP exclusion: opencost.de (Universität Regensburg, German construction-cost standard)
	// returns HTML with "Bauwerksdaten"/"Leistungsverzeichnis" — excluded by body_contains check.
	// ETag "1.96.0" is build-time-static in opencost-ui nginx template (low FP signal).
	{
		Name:         "OpenCost",
		DefaultPorts: []int{9003, 9090},
		Probes: []Probe{
			// Port 9003 API (definitive per Insight #52: bare 200 at path ≠ the API).
			{Path: "/allocation?window=1d&aggregate=namespace", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "code"},
				{Type: "body_contains", Value: "cpuCost"},
				// Exclude opencost.de (German construction-cost registry, "openCost" namesake).
				{Type: "body_not_contains", Value: "bauwerksdaten"},
			}},
			// /metrics: kubecost_cluster_info present in every OpenCost deployment.
			{Path: "/metrics", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "node_cpu_hourly_cost"},
				{Type: "body_not_contains", Value: "bauwerksdaten"},
			}},
		},
		Severity: "medium",
	},
}

// ── Matching engine ─────────────────────────────────────────────────

// scanAllFingerprints is set by the -scan-all-fingerprints CLI flag. When
// true, the DefaultPorts filter is bypassed and every fingerprint is
// probed against every open port. Trades ~30x more HTTP requests for the
// ability to catch services running on non-canonical ports.
var scanAllFingerprints = false

func matchFingerprints(openPorts []PortResult, timeout time.Duration, verbose bool, threads int) []ServiceMatch {
	client := newHTTPClient(timeout)
	var (
		mu      sync.Mutex
		matches []ServiceMatch
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, threads)

	for _, port := range openPorts {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Determine scheme(s) to try. Always include both so that a TLS port
			// that also speaks plaintext (e.g. OpenHands admin console) can match
			// on the richer HTTP body when the HTTPS SPA shell is too sparse.
			schemes := []string{"http", "https"}
			if port.TLS {
				schemes = []string{"https", "http"}
			}

			// Filter fingerprints to those that list this port in DefaultPorts,
			// or have no DefaultPorts restriction (empty = try on any port).
			// Avoids probing all 69 fingerprints against every open port.
			// -scan-all-fingerprints bypasses this filter — useful for hosts
			// running services on non-canonical ports.
			candidateFPs := Fingerprints[:0:0]
			if scanAllFingerprints {
				candidateFPs = append(candidateFPs, Fingerprints...)
			} else {
				for _, fp := range Fingerprints {
					if len(fp.DefaultPorts) == 0 {
						candidateFPs = append(candidateFPs, fp)
						continue
					}
					for _, dp := range fp.DefaultPorts {
						if dp == port.Port {
							candidateFPs = append(candidateFPs, fp)
							break
						}
					}
				}
				// Emit a one-line stderr warning if the open port has zero
				// FP candidates — a hint to the user that they may want to
				// re-run with -scan-all-fingerprints.
				if len(candidateFPs) == 0 && !verbose {
					fmt.Fprintf(os.Stderr,
						"\n[!] no FP candidates for %s:%d (port not in any DefaultPorts list); "+
							"re-run with -scan-all-fingerprints to probe exhaustively\n",
						port.Host, port.Port)
				}
			}

			// Parallelize FP candidates within this port. Iter 11.
			//
			// Without this, a port with 21 candidate FPs (e.g. port 80 after
			// the iter 8d/9 catalog-wide DefaultPorts widening) ran each FP
			// sequentially per port-goroutine. The -threads flag's worker
			// pool was idle while the matcher walked the candidate list
			// serially. Wall time per port grew from ~10s to ~80s.
			//
			// We spawn one inner goroutine per FP, gated by the same
			// outer semaphore so total concurrency stays bounded.
			var fpWG sync.WaitGroup
			for _, fp := range candidateFPs {
				fp := fp
				fpWG.Add(1)
				sem <- struct{}{}
				go func() {
					defer fpWG.Done()
					defer func() { <-sem }()
					matched := false
					for _, probe := range fp.Probes {
						if matched {
							break
						}
						for _, scheme := range schemes {
							url := fmt.Sprintf("%s://%s:%d%s", scheme, port.Host, port.Port, probe.Path)
							status, headers, body, err := httpGET(client, url)
							if err != nil {
								continue
							}

							allMatch := true
							for _, mc := range probe.Matches {
								if !evalMatch(mc, status, headers, body) {
									allMatch = false
									break
								}
							}

							if allMatch {
								baseURL := fmt.Sprintf("%s://%s:%d", scheme, port.Host, port.Port)
								sm := ServiceMatch{
									Host:      port.Host,
									Port:      port.Port,
									Service:   fp.Name,
									Severity:  fp.Severity,
									BaseURL:   baseURL,
									MatchPath: probe.Path,
								}
								if json.Valid(body) {
									sm.MatchBody = json.RawMessage(body)
								}
								if parsed, err := parseJSON(body); err == nil {
									if v := jStr(parsed, "version"); v != "" {
										sm.Version = v
									}
								}
								if verbose {
									fmt.Printf("    %s %s on %s:%d via %s\n",
										green("[match]"), fp.Name, port.Host, port.Port, probe.Path)
								}
								mu.Lock()
								matches = append(matches, sm)
								mu.Unlock()
								matched = true
								break
							}
						}
					}
				}()
			}
			fpWG.Wait()
		}()
	}
	wg.Wait()
	return matches
}

// matchProbe is a test-friendly helper that evaluates a Probe's match
// conditions against a captured PortResult, without making a network call.
// Used by fingerprint unit tests; in production the matcher fetches a fresh
// response per probe path.
//
// The probe's Path is NOT used by this helper — the caller is responsible
// for providing a PortResult whose BodySnippet/Headers represent what the
// path would return. This lets tests synthesize any probe shape (root,
// /api/v1/health, /docs, etc.) without network access.
func matchProbe(probe Probe, pr PortResult) bool {
	body := []byte(pr.BodySnippet)
	headers := pr.Headers
	if headers == nil {
		headers = map[string]string{}
		if pr.Server != "" {
			headers["Server"] = pr.Server
		}
		if pr.ContentType != "" {
			headers["Content-Type"] = pr.ContentType
		}
	}
	for _, mc := range probe.Matches {
		if !evalMatch(mc, pr.StatusCode, headers, body) {
			return false
		}
	}
	return len(probe.Matches) > 0
}

func evalMatch(mc MatchCond, status int, headers map[string]string, body []byte) bool {
	switch mc.Type {
	case "status_code":
		return fmt.Sprintf("%d", status) == mc.Value
	case "body_contains":
		return strings.Contains(strings.ToLower(string(body)), strings.ToLower(mc.Value))
	case "body_not_contains":
		return !strings.Contains(strings.ToLower(string(body)), strings.ToLower(mc.Value))
	case "json_field":
		if m, err := parseJSON(body); err == nil {
			return jHas(m, mc.Field)
		}
		return false
	case "json_array":
		_, err := parseJSONArray(body)
		return err == nil
	case "header_contains":
		if v, ok := headers[mc.Field]; ok {
			return strings.Contains(strings.ToLower(v), strings.ToLower(mc.Value))
		}
		return false
	case "header_not_contains":
		// Anti-match: PASSES if the header is absent OR its value doesn't contain the substring.
		if v, ok := headers[mc.Field]; ok {
			return !strings.Contains(strings.ToLower(v), strings.ToLower(mc.Value))
		}
		return true // header absent = not-contains = pass
	}
	return false
}
