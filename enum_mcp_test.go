package main

import (
	"strings"
	"testing"
)

// containsSubstr reports whether any element of haystack contains needle.
func containsSubstr(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// Offline parser tests for the MCP (Model Context Protocol) deep enumerator.
// Bodies are canonical JSON-RPC 2.0 shapes per the MCP spec revisions
// (2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25). serverInfo.name values are
// real reference-server identities (modelcontextprotocol/servers). No live host
// contact — pure parsing + classification of captured response bodies.
//
// Discipline (per aimap CLAUDE.md + schema-recon skill): enumMCP is a
// FINGERPRINTER, not a harvester. It enumerates tool NAMES + descriptions +
// input schemas (rung 1 of the validation ladder: metadata that names
// structure), and NEVER calls tools/call or resources/read. These tests pin the
// shape-gate (the honeypot discriminator, Insight #1 + #16) and the
// bag-of-fields tool-surface severity classifier.

// ── parseMCPInitialize: identity extraction + shape gate ──────────────────────

// Canonical Streamable HTTP initialize result (raw JSON body).
const mcpInitFilesystem = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true},"resources":{}},"serverInfo":{"name":"secure-filesystem-server","version":"0.6.2"}}}`

// SSE-framed initialize (Streamable HTTP servers often reply text/event-stream).
const mcpInitSSE = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"mcp-git\",\"version\":\"0.1.0\"}}}\n\n"

func TestParseMCPInitialize_Canonical(t *testing.T) {
	si := parseMCPInitialize([]byte(mcpInitFilesystem))
	if si == nil {
		t.Fatal("expected a parsed serverInfo, got nil")
	}
	if si.Name != "secure-filesystem-server" {
		t.Errorf("name: want secure-filesystem-server, got %q", si.Name)
	}
	if si.Version != "0.6.2" {
		t.Errorf("version: want 0.6.2, got %q", si.Version)
	}
	if si.ProtocolVersion != "2025-06-18" {
		t.Errorf("protocolVersion: want 2025-06-18, got %q", si.ProtocolVersion)
	}
	// Capability keys are captured (sorted) as the negotiated surface.
	if !contains(si.Capabilities, "tools") || !contains(si.Capabilities, "resources") {
		t.Errorf("capabilities: want tools+resources, got %v", si.Capabilities)
	}
}

func TestParseMCPInitialize_SSEFramed(t *testing.T) {
	si := parseMCPInitialize([]byte(mcpInitSSE))
	if si == nil {
		t.Fatal("SSE-framed initialize must parse (Streamable HTTP text/event-stream)")
	}
	if si.Name != "mcp-git" {
		t.Errorf("name: want mcp-git, got %q", si.Name)
	}
	if si.ProtocolVersion != "2025-03-26" {
		t.Errorf("protocolVersion: want 2025-03-26, got %q", si.ProtocolVersion)
	}
}

func TestParseMCPInitialize_ShapeGate(t *testing.T) {
	// The honeypot discriminator (Insight #1) + a-200-is-not-identity (Insight #16).
	// A permissive honeypot or a non-MCP 200 must NOT parse as an MCP server.
	cases := map[string]string{
		"bogus protocolVersion (outside closed spec-date set)": `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"9999-99-99","serverInfo":{"name":"x"}}}`,
		"missing serverInfo":                                   `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}`,
		"empty serverInfo.name":                                `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":""}}}`,
		"missing protocolVersion":                              `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"x"}}}`,
		"jsonrpc error response (no result)":                   `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`,
		"bare 200 health":                                      `{"status":"ok"}`,
		"HTML doc page":                                        `<!DOCTYPE html><html><body>MCP docs</body></html>`,
		"empty body":                                           ``,
	}
	for name, body := range cases {
		if si := parseMCPInitialize([]byte(body)); si != nil {
			t.Errorf("%s: must not parse, got %+v", name, si)
		}
	}
}

// ── parseMCPTools: surface enumeration (names + descriptions only) ────────────

func TestParseMCPTools_Canonical(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"read_file","description":"Read a file from disk","inputSchema":{"type":"object"}},` +
		`{"name":"execute_command","description":"Run a shell command"}]}}`
	tools := parseMCPTools([]byte(body))
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d (%v)", len(tools), tools)
	}
	if tools[0].Name != "read_file" || tools[1].Name != "execute_command" {
		t.Errorf("tool names: got %q, %q", tools[0].Name, tools[1].Name)
	}
	if tools[0].Description != "Read a file from disk" {
		t.Errorf("description: got %q", tools[0].Description)
	}
}

func TestParseMCPTools_SSEAndEmpty(t *testing.T) {
	sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"get_time\"}]}}\n\n"
	if tools := parseMCPTools([]byte(sse)); len(tools) != 1 || tools[0].Name != "get_time" {
		t.Errorf("SSE tools/list must parse: got %v", tools)
	}
	for _, b := range []string{`{"jsonrpc":"2.0","result":{"tools":[]}}`, `{"status":"ok"}`, ``, `not json`} {
		if tools := parseMCPTools([]byte(b)); len(tools) != 0 {
			t.Errorf("body %q must yield no tools, got %v", b, tools)
		}
	}
}

// ── classifyMCPToolSurface: bag-of-fields severity on the tool-name set ───────

func TestClassifyMCPToolSurface_Tiering(t *testing.T) {
	cases := []struct {
		name    string
		tools   []string
		wantSev string
	}{
		{"shell exec is critical", []string{"execute_command"}, "critical"},
		{"filesystem write is critical", []string{"read_file", "write_file"}, "critical"},
		{"infra admin (kubectl) is critical", []string{"kubectl_apply"}, "critical"},
		{"secret access is critical", []string{"get_secret", "list_aws_buckets"}, "critical"},
		{"filesystem read is high", []string{"read_file", "list_directory"}, "high"},
		{"database query is high", []string{"query_database"}, "high"},
		{"network fetch is medium", []string{"fetch_url"}, "medium"},
		{"benign read-only is low", []string{"get_weather", "calculate"}, "low"},
		{"no tools is info", []string{}, "info"},
	}
	for _, tc := range cases {
		tools := make([]mcpTool, len(tc.tools))
		for i, n := range tc.tools {
			tools[i] = mcpTool{Name: n}
		}
		sev, _ := classifyMCPToolSurface(tools)
		if sev != tc.wantSev {
			t.Errorf("%s: tools=%v want %q, got %q", tc.name, tc.tools, tc.wantSev, sev)
		}
	}
}

func TestClassifyMCPToolSurface_NamesAreTheFinding(t *testing.T) {
	// The dangerous-tool list IS the finding evidence — names carry the
	// intelligence before any payload is read (restraint ethic).
	tools := []mcpTool{{Name: "execute_command"}, {Name: "read_file"}, {Name: "get_weather"}}
	sev, dangerous := classifyMCPToolSurface(tools)
	if sev != "critical" {
		t.Errorf("want critical, got %q", sev)
	}
	// execute_command + read_file are dangerous; get_weather is not.
	if len(dangerous) != 2 {
		t.Fatalf("want 2 dangerous tools enumerated, got %d (%v)", len(dangerous), dangerous)
	}
	if !containsSubstr(dangerous, "execute_command") || !containsSubstr(dangerous, "read_file") {
		t.Errorf("dangerous list must name the risky tools, got %v", dangerous)
	}
}

// ── mcpAuthClassify: unauth finding vs auth-configured ────────────────────────

func TestMCPAuthClassify(t *testing.T) {
	// 401 + WWW-Authenticate (RFC 9728 / MCP authorization spec) = auth configured,
	// NOT a finding. A 200 with a valid result and a populated surface = unauth.
	if got := mcpAuthClassify(401, map[string]string{"Www-Authenticate": `Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"`}, false); got != "oauth" {
		t.Errorf("401+WWW-Authenticate: want oauth, got %q", got)
	}
	if got := mcpAuthClassify(401, map[string]string{}, false); got != "auth-required" {
		t.Errorf("bare 401: want auth-required, got %q", got)
	}
	if got := mcpAuthClassify(403, map[string]string{}, false); got != "auth-required" {
		t.Errorf("403: want auth-required, got %q", got)
	}
	if got := mcpAuthClassify(200, map[string]string{}, true); got != "none" {
		t.Errorf("200+valid result: want none, got %q", got)
	}
}

// ── parseMCPProxyStatus: sparfenyuk mcp-proxy /status marker ───────────────────

func TestParseMCPProxyStatus(t *testing.T) {
	// sparfenyuk/mcp-proxy /status returns a server_instances map — vendor-unique,
	// confirms the stdio-to-HTTP bridge (worst case: arbitrary stdio server exposed).
	body := `{"api_last_activity":"2026-05-31T00:00:00Z","server_instances":{"default":"configured"}}`
	if !parseMCPProxyStatus([]byte(body)) {
		t.Error("sparfenyuk /status body must be recognized")
	}
	for _, b := range []string{`{"status":"ok"}`, `{"server_instances":"notamap"}`, ``} {
		if parseMCPProxyStatus([]byte(b)) {
			t.Errorf("body %q must not be recognized as mcp-proxy /status", b)
		}
	}
}
