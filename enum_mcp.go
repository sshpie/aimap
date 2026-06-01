package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// ── MCP (Model Context Protocol) deep enumerator ──────────────────────────────
//
// The "MCP Server" fingerprint (fingerprints.go) confirms a service speaks MCP.
// This enumerator does the next step: the active JSON-RPC `initialize` handshake,
// then `tools/list` / `resources/list` / `prompts/list` to enumerate the exposed
// surface, and classifies auth state.
//
// DISCIPLINE (schema-recon skill + aimap CLAUDE.md): this is a FINGERPRINTER, not
// a harvester. It stops at rung 1 of the validation ladder — tool NAMES,
// descriptions, and input SCHEMAS are metadata that name structure (the tool-name
// SET is the finding evidence, per the restraint ethic). It NEVER calls
// `tools/call` or `resources/read`; no tool is invoked, no resource content is
// read. `data_accessed` is false by construction.
//
// The closed set of spec-revision dates is the honeypot discriminator (Insight
// #1): a permissive deception fleet that answers any path with a generic 200
// cannot produce a protocolVersion inside this set with a non-empty serverInfo.

// mcpServerInfo is the identity extracted from a JSON-RPC initialize result.
type mcpServerInfo struct {
	Name            string
	Version         string
	ProtocolVersion string
	Capabilities    []string
}

// mcpTool is a single entry from a tools/list response — name + description
// only. Input schemas are surface metadata; tools are never invoked.
type mcpTool struct {
	Name        string
	Description string
}

// validMCPProtocolVersions is the closed set of published MCP spec revisions.
// A server whose initialize result reports a protocolVersion outside this set is
// not a spec-conformant MCP server. Update when the spec ships a new revision.
var validMCPProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

// mcpToolLexicon maps a substring token (matched against the lowercased tool
// name) to (category, tier). bag-of-fields: the worst tier present in the
// tool-name SET sets the severity floor; the matched names are the evidence.
// Ordered most-dangerous-first so the first match wins per token scan.
var mcpToolLexicon = []struct {
	tokens   []string
	category string
	tier     string
}{
	{[]string{"exec", "command", "shell", "bash", "run_code", "runcode", "eval", "subprocess", "terminal", "spawn", "system", "powershell", "script"}, "shell_exec", "critical"},
	{[]string{"write", "create_file", "delete", "edit_file", "move_file", "mkdir", "put_file", "append", "save_file", "unlink", "remove_file", "rmdir"}, "fs_write", "critical"},
	{[]string{"kubectl", "kube", "ssh", "docker", "terraform", "deploy", "k8s", "helm", "ansible", "provision"}, "infra_admin", "critical"},
	{[]string{"secret", "credential", "password", "api_key", "apikey", "vault", "private_key", "access_token"}, "secrets", "critical"},
	{[]string{"read_file", "read", "cat_", "list_dir", "list_directory", "get_file", "open_file", "glob", "search_files", "stat_file", "readfile"}, "fs_read", "high"},
	{[]string{"query", "sql", "database", "mongo", "redis", "postgres", "mysql", "db_query", "execute_query", "find_documents", "collection"}, "database", "high"},
	{[]string{"aws", "gcp", "azure", "s3_", "bucket", "cloud", "ec2", "lambda"}, "cloud", "high"},
	{[]string{"fetch", "http_", "request", "curl", "browse", "url", "web_", "scrape", "download", "get_url"}, "network", "medium"},
	{[]string{"send_email", "email", "send_message", "slack", "sms", "send_sms", "post_message", "notify", "webhook"}, "messaging", "medium"},
}

var mcpTierRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// parseMCPInitialize extracts identity from a JSON-RPC initialize response and
// gates on protocol-shape conformance. Returns nil unless the body carries a
// result with a protocolVersion in the closed spec set AND a non-empty
// serverInfo.name. Handles raw-JSON and SSE-framed (text/event-stream) bodies.
func parseMCPInitialize(body []byte) *mcpServerInfo {
	result := mcpResult(body)
	if result == nil {
		return nil
	}
	pv := jStr(result, "protocolVersion")
	if !validMCPProtocolVersions[pv] {
		return nil
	}
	srv := jMap(result, "serverInfo")
	if srv == nil {
		return nil
	}
	name := jStr(srv, "name")
	if strings.TrimSpace(name) == "" {
		return nil
	}
	si := &mcpServerInfo{
		Name:            name,
		Version:         jStr(srv, "version"),
		ProtocolVersion: pv,
	}
	if caps := jMap(result, "capabilities"); caps != nil {
		for k := range caps {
			si.Capabilities = append(si.Capabilities, k)
		}
		sort.Strings(si.Capabilities)
	}
	return si
}

// parseMCPTools extracts tool names + descriptions from a tools/list response.
// Names and descriptions only — input schemas are surface metadata, never
// invoked. Handles raw-JSON and SSE-framed bodies.
func parseMCPTools(body []byte) []mcpTool {
	result := mcpResult(body)
	if result == nil {
		return nil
	}
	arr := jArray(result, "tools")
	if len(arr) == 0 {
		return nil
	}
	var tools []mcpTool
	for _, t := range arr {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		name := jStr(tm, "name")
		if name == "" {
			continue
		}
		tools = append(tools, mcpTool{Name: name, Description: jStr(tm, "description")})
	}
	return tools
}

// classifyMCPToolSurface scores the tool-name SET (bag-of-fields). Returns the
// highest tier present and the list of dangerous (critical/high) tools as
// "name (category)" evidence strings. No tools → "info"; tools present but none
// matching the lexicon → "low".
func classifyMCPToolSurface(tools []mcpTool) (string, []string) {
	if len(tools) == 0 {
		return "info", nil
	}
	best := "low"
	var dangerous []string
	for _, t := range tools {
		ln := strings.ToLower(t.Name)
		cat, tier := mcpToolTier(ln)
		if tier == "" {
			continue
		}
		if mcpTierRank[tier] > mcpTierRank[best] {
			best = tier
		}
		if tier == "critical" || tier == "high" {
			dangerous = append(dangerous, fmt.Sprintf("%s (%s)", t.Name, cat))
		}
	}
	return best, dangerous
}

// mcpToolTier returns the (category, tier) for a lowercased tool name, or
// ("","") if no lexicon token matches.
func mcpToolTier(lowerName string) (string, string) {
	for _, e := range mcpToolLexicon {
		for _, tok := range e.tokens {
			if strings.Contains(lowerName, tok) {
				return e.category, e.tier
			}
		}
	}
	return "", ""
}

// mcpAuthClassify maps an initialize response to an auth posture.
//   - 401/403 with a WWW-Authenticate header → "oauth" (MCP authorization spec,
//     RFC 9728) — auth is configured, NOT a finding.
//   - bare 401/403 → "auth-required".
//   - 200 with a valid parsed result → "none" (unauthenticated).
func mcpAuthClassify(status int, headers map[string]string, hasResult bool) string {
	if status == 401 || status == 403 {
		for k, v := range headers {
			if strings.EqualFold(k, "WWW-Authenticate") && strings.TrimSpace(v) != "" {
				return "oauth"
			}
		}
		return "auth-required"
	}
	if status == 200 && hasResult {
		return "none"
	}
	return "unknown"
}

// parseMCPProxyStatus recognizes the sparfenyuk/mcp-proxy /status response, whose
// server_instances object is vendor-unique. A confirmed mcp-proxy is a
// stdio-to-HTTP bridge: it exposes whatever local stdio server it fronts
// (worst case, a shell/filesystem server → unauth OS command execution).
func parseMCPProxyStatus(body []byte) bool {
	m, err := parseJSON(body)
	if err != nil {
		return false
	}
	return jMap(m, "server_instances") != nil
}

// mcpResult unwraps optional SSE framing, parses JSON, and returns the JSON-RPC
// "result" object — or nil if the body is not a JSON-RPC result envelope.
func mcpResult(body []byte) map[string]interface{} {
	m, err := parseJSON(mcpUnwrapSSE(body))
	if err != nil {
		return nil
	}
	return jMap(m, "result")
}

// mcpUnwrapSSE extracts the JSON payload from an SSE (text/event-stream) frame.
// SSE carries the body across one or more `data:` lines; concatenate them. If no
// `data:` line is present the body is returned unchanged (raw JSON).
func mcpUnwrapSSE(body []byte) []byte {
	s := string(body)
	if !strings.Contains(s, "data:") {
		return body
	}
	var data strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if data.Len() == 0 {
		return body
	}
	return []byte(data.String())
}

// initRequest is the canonical unauthenticated JSON-RPC initialize request body.
// protocolVersion is sent as the newest published revision; spec backward-compat
// requires servers to negotiate down, and a -32602 is handled by the caller.
const mcpInitRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"aimap","version":"` + Version + `"}}}`

const mcpToolsListRequest = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`

// enumMCP performs the MCP initialize handshake against the candidate endpoints,
// enumerates the tool surface when reachable unauthenticated, and classifies
// auth state. Restraint: it lists tools/resources/prompts but never invokes them.
func enumMCP(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	r.AuthStatus = "unknown"
	r.RiskLevel = "info"
	r.RawData["data_accessed"] = false // schema-recon posture: surface, not content

	// Candidate initialize endpoints: Streamable HTTP at /mcp and at root
	// (Kestrel/.NET bind MCP at /), then the request path the fingerprint hit.
	endpoints := uniqueStrings([]string{
		svc.BaseURL + "/mcp",
		svc.BaseURL + "/",
		svc.BaseURL + strings.TrimRight(svc.MatchPath, "/"),
	})

	var si *mcpServerInfo
	var initStatus int
	var initHeaders map[string]string
	for _, ep := range endpoints {
		st, hdrs, body, err := mcpPostInit(c, ep)
		if err != nil {
			continue
		}
		if parsed := parseMCPInitialize(body); parsed != nil {
			si, initStatus, initHeaders = parsed, st, hdrs
			r.RawData["initialize_endpoint"] = ep
			break
		}
		// Record the first auth-gated response in case no endpoint answers unauth.
		if (st == 401 || st == 403) && initStatus == 0 {
			initStatus, initHeaders = st, hdrs
		}
	}

	// sparfenyuk/mcp-proxy bridge marker (vendor-unique /status).
	if st, _, body, err := httpGET(c, svc.BaseURL+"/status"); err == nil && st == 200 && parseMCPProxyStatus(body) {
		r.RawData["mcp_proxy"] = true
		r.Findings = append(r.Findings, Finding{
			Category: "exposure",
			Title:    "mcp-proxy stdio-to-HTTP bridge exposed",
			Detail:   "sparfenyuk/mcp-proxy /status is reachable; the bridge exposes whatever local stdio MCP server it fronts. If that server provides shell or filesystem tools, this is unauthenticated OS-level access. Tool surface enumerated below; no tool was invoked (restraint).",
			Severity: "high",
		})
	}

	if si == nil {
		// No endpoint produced a spec-conformant initialize result.
		r.AuthStatus = mcpAuthClassify(initStatus, initHeaders, false)
		if r.AuthStatus == "oauth" || r.AuthStatus == "auth-required" {
			r.Details = append(r.Details, "MCP server present; initialize is authentication-gated ("+r.AuthStatus+").")
		} else {
			r.Details = append(r.Details, "MCP fingerprint matched but no spec-conformant initialize result was returned (possible honeypot, non-standard transport, or version mismatch).")
		}
		return r
	}

	// Spec-conformant initialize result obtained unauthenticated.
	r.Version = si.Version
	r.AuthStatus = mcpAuthClassify(initStatus, initHeaders, true)
	r.RawData["server_name"] = si.Name
	r.RawData["protocol_version"] = si.ProtocolVersion
	r.RawData["capabilities"] = si.Capabilities
	r.Details = append(r.Details, fmt.Sprintf("Server %q (v%s), MCP %s, capabilities: %s",
		si.Name, emptyDash(si.Version), si.ProtocolVersion, strings.Join(si.Capabilities, ", ")))

	// Enumerate the tool surface (names/descriptions/schemas only).
	ep := svc.BaseURL + "/mcp"
	if v, ok := r.RawData["initialize_endpoint"].(string); ok {
		ep = v
	}
	var tools []mcpTool
	if _, _, body, err := mcpPost(c, ep, mcpToolsListRequest); err == nil {
		tools = parseMCPTools(body)
	}
	toolSev, dangerous := classifyMCPToolSurface(tools)
	if len(tools) > 0 {
		names := make([]string, 0, len(tools))
		for _, t := range tools {
			names = append(names, t.Name)
		}
		r.RawData["tools"] = names
		r.Details = append(r.Details, fmt.Sprintf("tools/list returned %d tools: %s", len(tools), strings.Join(names, ", ")))
	}

	// Severity wiring: an unauthenticated MCP server floors at medium (the
	// handshake itself leaks structure, Insight #3); a dangerous tool surface
	// promotes to the tool tier.
	sev := "info"
	if r.AuthStatus == "none" {
		sev = "medium"
		if mcpTierRank[toolSev] > mcpTierRank[sev] {
			sev = toolSev
		}
		detail := fmt.Sprintf("MCP server %q is reachable without authentication and exposes its protocol surface (%d tools).",
			si.Name, len(tools))
		if len(dangerous) > 0 {
			detail += " Dangerous tools enumerated: " + strings.Join(dangerous, "; ") + ". No tool was invoked (restraint: names and schemas only)."
		}
		r.Findings = append(r.Findings, Finding{
			Category: "unauthenticated-access",
			Title:    "Unauthenticated MCP server exposes tool surface",
			Detail:   detail,
			Severity: sev,
			Data: map[string]interface{}{
				"server_name":      si.Name,
				"protocol_version": si.ProtocolVersion,
				"tool_count":       len(tools),
				"dangerous_tools":  dangerous,
				"data_accessed":    false,
			},
		})
	}
	r.RiskLevel = sev
	return r
}

// mcpPostInit POSTs the initialize request with the MCP-correct Accept header.
func mcpPostInit(c *http.Client, url string) (int, map[string]string, []byte, error) {
	return mcpPost(c, url, mcpInitRequest)
}

// mcpPost issues a JSON-RPC POST with Accept: application/json, text/event-stream
// (required by Streamable HTTP servers; FastMCP returns 406 without it). It does
// not send MCP-Protocol-Version on the initialize POST (some servers 400 on it).
func mcpPost(c *http.Client, url, payload string) (int, map[string]string, []byte, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "github.com/nuclide-research/aimap/"+Version+" (security-research)")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	hdrs := make(map[string]string)
	for k, v := range resp.Header {
		hdrs[k] = strings.Join(v, ", ")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, hdrs, body, nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func emptyDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
