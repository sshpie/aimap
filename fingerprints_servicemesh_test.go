package main

import "testing"

// Service-mesh / cluster-introspection fingerprints (Cat: Network Perimeter /
// Service Mesh, 2026-05-31). Each plane's data-layer probe must (a) match the
// real unauth response shape and (b) reject brand-mention prose, gated (401/403)
// responses, and wrong-shape bodies. This enforces the conjunctive
// marker-anchored discipline (Insight #6) and Insight #16 (a 200 is identity,
// not auth-state — the data path is what earns the severity), with attention to
// the fact that body_contains is a case-insensitive substring match.

func meshProbe(t *testing.T, name, path string) Probe {
	t.Helper()
	fp := fpByName(name)
	if fp == nil {
		t.Fatalf("%s fingerprint not found", name)
	}
	for _, p := range fp.Probes {
		if p.Path == path {
			return p
		}
	}
	t.Fatalf("%s has no probe for path %q", name, path)
	return Probe{}
}

func meshJSON(body string) PortResult {
	return PortResult{
		Host: "203.0.113.10", Open: true, StatusCode: 200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: body,
	}
}

func meshJSONStatus(status int, body string) PortResult {
	pr := meshJSON(body)
	pr.StatusCode = status
	return pr
}

// ── Kiali ───────────────────────────────────────────────────────────

func TestKiali_AnonNamespacesMatches(t *testing.T) {
	p := meshProbe(t, "Kiali", "/api/namespaces")
	body := `[{"name":"istio-system","cluster":"Kubernetes","isAmbient":false},{"name":"default"}]`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Kiali /api/namespaces did not match a populated anon namespace array")
	}
}

func TestKiali_GatedNamespacesRejected(t *testing.T) {
	p := meshProbe(t, "Kiali", "/api/namespaces")
	if matchProbe(p, meshJSONStatus(401, `{"error":"Token is not valid"}`)) {
		t.Fatal("Kiali /api/namespaces matched a 401 (token-gated) response")
	}
}

func TestKiali_HTMLFallbackRejected(t *testing.T) {
	// A shared :443 ingress returning the SPA shell 200 for an unknown path
	// must not match — json_array is the guard.
	p := meshProbe(t, "Kiali", "/api/namespaces")
	html := `<!doctype html><html><head><title>Kiali</title></head><body><div id="root"></div></body></html>`
	if matchProbe(p, meshJSON(html)) {
		t.Fatal("Kiali /api/namespaces matched an HTML SPA fallback (not a JSON array)")
	}
}

func TestKiali_ConfigIdentity(t *testing.T) {
	p := meshProbe(t, "Kiali", "/api/config")
	if !matchProbe(p, meshJSON(`{"istioNamespace":"istio-system","istioIdentityDomain":"svc.cluster.local"}`)) {
		t.Fatal("Kiali /api/config identity probe did not match")
	}
}

// ── Hubble UI ───────────────────────────────────────────────────────

func TestHubbleUI_MatchesTitle(t *testing.T) {
	p := meshProbe(t, "Hubble UI", "/")
	html := `<!doctype html><html><head><title>Hubble UI</title></head><body><div id="app"></div></body></html>`
	if !matchProbe(p, meshJSON(html)) {
		t.Fatal("Hubble UI did not match its index title tag")
	}
}

func TestHubbleUI_RejectsProse(t *testing.T) {
	// case-insensitive body_contains must NOT fire on a bare brand mention
	p := meshProbe(t, "Hubble UI", "/")
	html := `<html><head><title>Our Platform</title></head><body>We run Hubble UI internally for flow visibility.</body></html>`
	if matchProbe(p, meshJSON(html)) {
		t.Fatal("Hubble UI over-matched a bare brand mention in prose")
	}
}

// ── Linkerd ─────────────────────────────────────────────────────────

func TestLinkerdViz_MatchesNamespaceAttr(t *testing.T) {
	p := meshProbe(t, "Linkerd Viz", "/")
	html := `<!doctype html><html><body data-controller-namespace="linkerd" data-go-version="1.21"><div id="main"></div></body></html>`
	if !matchProbe(p, meshJSON(html)) {
		t.Fatal("Linkerd Viz did not match the dashboard namespace data-attribute")
	}
}

func TestLinkerdViz_RejectsProse(t *testing.T) {
	p := meshProbe(t, "Linkerd Viz", "/")
	html := `<html><body>A comparison of Linkerd vs Istio for your service mesh</body></html>`
	if matchProbe(p, meshJSON(html)) {
		t.Fatal("Linkerd Viz over-matched a bare brand mention")
	}
}

func TestLinkerdProxyAdmin_EnvJson(t *testing.T) {
	p := meshProbe(t, "Linkerd Proxy Admin", "/env.json")
	body := `{"LINKERD2_PROXY_LOG":"warn","LINKERD2_PROXY_DESTINATION_SVC_ADDR":"linkerd-dst-headless.linkerd.svc.cluster.local:8086"}`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Linkerd proxy-admin /env.json did not match the proxy env shape")
	}
}

// ── Cilium ──────────────────────────────────────────────────────────

func TestCiliumMetrics_DropCount(t *testing.T) {
	p := meshProbe(t, "Cilium Metrics", "/metrics")
	body := "# HELP cilium_drop_count_total Total dropped packets\ncilium_drop_count_total{reason=\"Policy denied\"} 42\n"
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Cilium Metrics did not match the cilium_drop_count_total metric")
	}
}

func TestCiliumMetrics_RejectsGenericPrometheus(t *testing.T) {
	// The first /metrics probe (cilium_drop_count_total) must not fire on a
	// generic Go exporter scrape.
	p := meshProbe(t, "Cilium Metrics", "/metrics")
	body := "# HELP go_gc_duration_seconds A summary of GC pause durations\ngo_gc_duration_seconds{quantile=\"0\"} 0.0001\n"
	if matchProbe(p, meshJSON(body)) {
		t.Fatal("Cilium Metrics over-matched a generic Go-exporter /metrics")
	}
}

// ── Istio (Envoy admin + istiod debug) ──────────────────────────────

func TestEnvoyAdmin_ConfigDump(t *testing.T) {
	p := meshProbe(t, "Istio Envoy Admin", "/config_dump")
	body := `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.BootstrapConfigDump","bootstrap":{"node":{"cluster":"productpage.default.svc.cluster.local"}}}]}`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Envoy admin /config_dump did not match the envoy.admin.v3 + svc.cluster.local shape")
	}
}

func TestEnvoyAdmin_RejectsProse(t *testing.T) {
	p := meshProbe(t, "Istio Envoy Admin", "/config_dump")
	if matchProbe(p, meshJSON(`{"note":"envoy is great but this is not a config_dump"}`)) {
		t.Fatal("Envoy admin over-matched a body lacking the envoy.admin.v3 @type")
	}
}

func TestIstiod_Endpointz(t *testing.T) {
	p := meshProbe(t, "Istiod Debug", "/debug/endpointz")
	body := `[{"svc":"reviews.default.svc.cluster.local","endpoints":[{"service":{"serviceAccount":"spiffe://cluster.local/ns/default/sa/bookinfo-reviews"}}]}]`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("istiod /debug/endpointz did not match the registry shape")
	}
}

// ── Pomerium ────────────────────────────────────────────────────────

func TestPomerium_Jwks(t *testing.T) {
	p := meshProbe(t, "Pomerium", "/.well-known/pomerium/jwks.json")
	if !matchProbe(p, meshJSON(`{"keys":[{"use":"sig","kty":"EC","crv":"P-256","alg":"ES256","kid":"abc"}]}`)) {
		t.Fatal("Pomerium JWKS did not match the ES256 EC key shape")
	}
}

func TestPomerium_RejectsGenericRSAJwks(t *testing.T) {
	// A generic OIDC JWKS (RSA/RS256) must not match — ES256 is the anchor.
	p := meshProbe(t, "Pomerium", "/.well-known/pomerium/jwks.json")
	if matchProbe(p, meshJSON(`{"keys":[{"use":"sig","kty":"RSA","alg":"RS256","n":"0vx7","e":"AQAB"}]}`)) {
		t.Fatal("Pomerium over-matched a generic RSA JWKS (no ES256)")
	}
}

// ── Kubernetes API server (Cilium cluster-cert pivot) ───────────────

func TestK8sAPI_AnonNamespaceList(t *testing.T) {
	p := meshProbe(t, "Kubernetes API", "/api/v1/namespaces")
	body := `{"kind":"NamespaceList","apiVersion":"v1","items":[{"metadata":{"name":"kube-system"}}]}`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Kubernetes API /api/v1/namespaces did not match an anon NamespaceList")
	}
}

func TestK8sAPI_ForbiddenRejected(t *testing.T) {
	p := meshProbe(t, "Kubernetes API", "/api/v1/namespaces")
	body := `{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}`
	if matchProbe(p, meshJSONStatus(403, body)) {
		t.Fatal("Kubernetes API matched a 403 Forbidden (secured) response")
	}
}

func TestK8sAPI_VersionIdentity(t *testing.T) {
	p := meshProbe(t, "Kubernetes API", "/version")
	body := `{"major":"1","minor":"28","gitVersion":"v1.28.4","buildDate":"2023-11-15T16:48:23Z"}`
	if !matchProbe(p, meshJSON(body)) {
		t.Fatal("Kubernetes API /version identity probe did not match")
	}
}
