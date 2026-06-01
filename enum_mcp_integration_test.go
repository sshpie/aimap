package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// End-to-end test of the enumMCP orchestrator against a mock unauthenticated MCP
// server (FastMCP/Streamable-HTTP shape: SSE-framed responses + mcp-session-id
// header). Validates endpoint discovery, the Accept header, SSE-over-the-wire
// parsing, finding construction — and the load-bearing restraint guarantee that
// enumMCP NEVER invokes a tool or reads a resource.

func TestEnumMCP_UnauthServer_EndToEnd(t *testing.T) {
	var invokedForbidden bool // set if tools/call or resources/read is ever hit

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/mcp" {
			http.NotFound(w, req)
			return
		}
		body, _ := io.ReadAll(req.Body)
		var rpc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &rpc)

		// RESTRAINT GUARD: the enumerator must never call these.
		if rpc.Method == "tools/call" || rpc.Method == "resources/read" || rpc.Method == "prompts/get" {
			invokedForbidden = true
			http.Error(w, "forbidden invocation in test", http.StatusTeapot)
			return
		}

		w.Header().Set("Mcp-Session-Id", "test-session-123")
		w.Header().Set("Content-Type", "text/event-stream")
		switch rpc.Method {
		case "initialize":
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"evil-fs-mcp\",\"version\":\"1.0.0\"}}}\n\n")
		case "tools/list":
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"execute_command\",\"description\":\"run a shell command\"},{\"name\":\"read_file\",\"description\":\"read a file\"},{\"name\":\"get_weather\"}]}}\n\n")
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	svc := ServiceMatch{
		Host:      "127.0.0.1",
		Service:   "MCP Server",
		BaseURL:   srv.URL,
		MatchPath: "/mcp",
	}
	r := enumMCP(newHTTPClient(5*time.Second), svc)

	if invokedForbidden {
		t.Fatal("RESTRAINT VIOLATION: enumMCP invoked a tool or read a resource")
	}
	if r.AuthStatus != "none" {
		t.Errorf("auth_status: want none, got %q", r.AuthStatus)
	}
	if r.Version != "1.0.0" {
		t.Errorf("version: want 1.0.0, got %q", r.Version)
	}
	if r.RiskLevel != "critical" {
		t.Errorf("risk_level: want critical (execute_command exposed), got %q", r.RiskLevel)
	}
	// data_accessed posture is carried as a real field, always false.
	if da, _ := r.RawData["data_accessed"].(bool); da {
		t.Error("data_accessed must be false (schema-recon posture)")
	}
	// The unauth finding names the dangerous tools (names are the finding).
	var found bool
	for _, f := range r.Findings {
		if f.Category == "unauthenticated-access" && f.Severity == "critical" &&
			strings.Contains(f.Detail, "execute_command") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a critical unauthenticated-access finding naming execute_command; got %+v", r.Findings)
	}
}

func TestEnumMCP_OAuthGated_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	svc := ServiceMatch{Host: "127.0.0.1", Service: "MCP Server", BaseURL: srv.URL, MatchPath: "/mcp"}
	r := enumMCP(newHTTPClient(5*time.Second), svc)

	if r.AuthStatus != "oauth" {
		t.Errorf("auth_status: want oauth, got %q", r.AuthStatus)
	}
	for _, f := range r.Findings {
		if f.Category == "unauthenticated-access" {
			t.Errorf("auth-gated server must not produce an unauthenticated-access finding: %+v", f)
		}
	}
}
