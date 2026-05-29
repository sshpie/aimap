package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Kubecost / OpenCost cost-model enumerator.
//
// WHY THIS EXISTS: aimap had fingerprints for Kubecost/OpenCost (the #66
// survey-driven DefaultPorts and #52 own-JSON-shape confirm signal) but no deep
// enumerator. With no enumerator the dispatcher fell back to mkResult, which
// sets AuthStatus="unknown" — and computeRisk then floored an open, unauth cost
// API at the fingerprint's flat severity instead of tiering on what was actually
// exposed. This closes that gap: it sets AuthStatus correctly (OPEN_API when the
// JSON API answers unauthenticated, gated on 401/403) and tiers severity on the
// data actually reachable. Ported from data/kubecost-opencost-probe.py.
//
// METHODOLOGY ANCHORS:
//   #52  HTTP 200 at an API path is not that API. We require the service's own
//        emitted JSON shape ({"code":200,"data":...}), never a bare 200.
//   #66  DefaultPorts are survey-driven (live on the fingerprints, mirrored in
//        the comments below).
//   #37  Asymmetric auth: the UI may be login-gated while the cost-model API is
//        open. We probe both surfaces and flag the asymmetry.
//   #41  Restraint: read NAMES not values. We pull aggregate=namespace (cluster +
//        namespace names + aggregate cost) and STOP. We never enumerate per-pod
//        records.
//   #38  /model/helmValues (Kubecost credential-leak class, macchaffee 2021):
//        record PRESENCE only (status + size) — never store or print the body.

// costClusterInfo is the structured cluster identity extracted from a Kubecost
// /model/clusterInfo response. Field NAMES only — no per-resource values (#41).
type costClusterInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Provisioner string `json:"provisioner"`
	Region      string `json:"region"`
	Profile     string `json:"cluster_profile"`
	Version     string `json:"version"`
	Account     string `json:"account,omitempty"`
}

// costAllocation is the namespace rollup extracted from /model/allocation (or
// the OpenCost :9003 /allocation). NAMES + an aggregate cost, never per-record
// values (#41).
type costAllocation struct {
	Namespaces []string `json:"namespaces"`
	Count      int      `json:"namespace_count"`
	AggCost    float64  `json:"agg_cost"`
	Cluster    string   `json:"cluster,omitempty"`
}

// parseClusterInfo extracts cluster identity from a /model/clusterInfo body.
// Pure (no network) so it can be unit-tested offline against captured bodies.
// Returns nil unless the body carries the service's own JSON shape (#52):
// top-level "code"==200 with a "data" object that has a provider/provisioner.
func parseClusterInfo(body []byte) *costClusterInfo {
	m, err := parseJSON(body)
	if err != nil {
		return nil
	}
	// #52: require the emitted shape, not a bare 200. "code" is a JSON number
	// (200) in the cost-model contract; parseJSON decodes it to float64.
	if jFloat(m, "code") != 200 {
		return nil
	}
	data := jMap(m, "data")
	if data == nil {
		return nil
	}
	// Must look like a cluster-info object, not some other {"code":200,"data":{}}
	// envelope. provisioner/provider are the discriminators.
	if jStr(data, "provisioner") == "" && jStr(data, "provider") == "" && jStr(data, "id") == "" {
		return nil
	}
	ci := &costClusterInfo{
		ID:          jStr(data, "id"),
		Name:        jStr(data, "name"),
		Provider:    jStr(data, "provider"),
		Provisioner: jStr(data, "provisioner"),
		Region:      jStr(data, "region"),
		Profile:     jStr(data, "clusterProfile"),
		Version:     jStr(data, "version"),
		Account:     jStr(data, "account"),
	}
	return ci
}

// parseAllocation extracts namespace NAMES and a summed aggregate cost from an
// /allocation response. Pure (no network) for offline testing. Returns nil
// unless the body carries the cost-model JSON shape (#52): "code"==200 with a
// "data" array of namespace->object windows.
//
// Restraint (#41): we collect the aggregate key NAMES (namespace names) and sum
// totalCost across them. We do NOT descend into per-pod / per-container records.
func parseAllocation(body []byte) *costAllocation {
	m, err := parseJSON(body)
	if err != nil {
		return nil
	}
	if jFloat(m, "code") != 200 {
		return nil
	}
	data := jArray(m, "data")
	if data == nil {
		return nil
	}
	a := &costAllocation{}
	for _, window := range data {
		wm, ok := window.(map[string]interface{})
		if !ok {
			continue
		}
		for name, val := range wm {
			a.Namespaces = append(a.Namespaces, name)
			if vm, ok := val.(map[string]interface{}); ok {
				a.AggCost += jFloat(vm, "totalCost")
				// Cluster id rides on properties.cluster (first one we see).
				if a.Cluster == "" {
					if props := jMap(vm, "properties"); props != nil {
						a.Cluster = jStr(props, "cluster")
					}
				}
			}
		}
	}
	// Deterministic ordering: map iteration is random; sort so output and the
	// agg cost are reproducible across runs.
	sort.Strings(a.Namespaces)
	a.Count = len(a.Namespaces)
	if len(a.Namespaces) == 0 {
		return nil
	}
	return a
}

// ── Kubecost ────────────────────────────────────────────────────────

// enumKubecost — read-only Kubecost cost-model enumeration. Sets AuthStatus to
// OPEN_API when the unauthenticated JSON API answers, or "required (HTTP NNN)"
// on a 401/403 gate. Tiers severity on what is actually reachable (#37/#41/#38):
//
//	OPEN_API + data (cluster identity or namespace topology) → high
//	OPEN_API, no data                                        → medium
//	UI-only (root reachable, API gated)                      → info
func enumKubecost(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	dataExposed := false

	// 1. /model/clusterInfo — cluster identity (id/provider/provisioner/region).
	st, _, body, err := httpGET(c, b+"/model/clusterInfo")
	switch {
	case err == nil && st == 200:
		if ci := parseClusterInfo(body); ci != nil {
			r.AuthStatus = "OPEN_API"
			dataExposed = true
			r.Version = ci.Version
			r.RawData["cluster_info"] = ci
			r.Details = append(r.Details,
				fmt.Sprintf("Cluster: %s (provider=%s provisioner=%s region=%s profile=%s)",
					nonEmpty(ci.ID, ci.Name), ci.Provider, ci.Provisioner, ci.Region, ci.Profile))
			r.Findings = append(r.Findings, Finding{
				Category: "CLUSTER_IDENTITY",
				Title:    fmt.Sprintf("Kubecost cluster identity exposed unauthenticated (%s / %s %s)", nonEmpty(ci.ID, ci.Name), ci.Provider, ci.Provisioner),
				Detail:   "GET /model/clusterInfo returned the cluster's cloud provider, provisioner (EKS/GKE/AKS), region, and profile without authentication. This pins the deployment to a specific cloud account and managed-Kubernetes service.",
				Severity: "high",
				Data:     ci,
			})
		}
	case err == nil && (st == 401 || st == 403):
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	// 2. /model/allocation?aggregate=namespace — namespace NAMES + aggregate cost
	//    (#41: NAMES not per-record values).
	if st, _, body, err := httpGET(c, b+"/model/allocation?window=1d&aggregate=namespace&accumulate=true"); err == nil {
		if st == 200 {
			if a := parseAllocation(body); a != nil {
				if r.AuthStatus != "OPEN_API" {
					r.AuthStatus = "OPEN_API"
				}
				dataExposed = true
				r.RawData["allocation"] = a
				r.Details = append(r.Details,
					fmt.Sprintf("Namespaces (%d): %s — aggregate cost ~%.4f", a.Count, strings.Join(a.Namespaces, ", "), a.AggCost))
				r.Findings = append(r.Findings, Finding{
					Category: "NAMESPACE_TOPOLOGY",
					Title:    fmt.Sprintf("Namespace cost topology exposed unauthenticated (%d namespaces)", a.Count),
					Detail:   fmt.Sprintf("GET /model/allocation aggregated by namespace returned the workload topology without authentication. Namespace names: %s. Aggregate 1d cost ~%.4f. Names map the internal application layout; per-pod records were not enumerated (restraint).", strings.Join(a.Namespaces, ", "), a.AggCost),
					Severity: "high",
					Data:     a,
				})
			}
		} else if (st == 401 || st == 403) && r.AuthStatus == "unknown" {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// 3. /model/helmValues — Kubecost credential-leak class (#38). PRESENCE ONLY:
	//    record status + body size, never the body. A populated helmValues blob
	//    can contain install-time cloud API keys / passwords passed via values.
	if st, _, body, err := httpGET(c, b+"/model/helmValues"); err == nil && st == 200 && len(body) > 200 {
		r.RawData["helmvalues_exposed"] = true
		r.RawData["helmvalues_bytes"] = len(body)
		r.Findings = append(r.Findings, Finding{
			Category: "HELM_VALUES_EXPOSED",
			Title:    fmt.Sprintf("/model/helmValues reachable (%d bytes) — credential-leak surface", len(body)),
			Detail:   "GET /model/helmValues returned a populated install-values blob without authentication. Helm values frequently carry cloud-provider API keys, datasource passwords, and tokens passed at install time. Presence recorded only; the body is NOT read or stored (restraint — reading a secret value needs explicit re-authorization).",
			Severity: "high",
		})
		dataExposed = true
	}

	// 4. #37 asymmetric: is the UI root gated while the API answered open?
	if st, _, _, err := httpGET(c, b+"/"); err == nil {
		r.RawData["ui_status"] = st
		uiGated := st == 301 || st == 302 || st == 401 || st == 403
		if uiGated && r.AuthStatus == "OPEN_API" {
			r.RawData["asymmetric_auth"] = true
			r.Findings = append(r.Findings, Finding{
				Category: "ASYMMETRIC_AUTH",
				Title:    fmt.Sprintf("UI gated (HTTP %d) but cost-model API open", st),
				Detail:   "The frontend root is login-gated or redirects, yet /model/* answered unauthenticated. The auth control is on the UI only; the data API behind it is reachable directly. Gating the UI does not protect the cost-model data.",
				Severity: "medium",
			})
		}
	}

	// Tier the floor severity on auth + data (#37). computeRisk takes the max of
	// the per-finding severities; this adds an explicit posture finding so a
	// UI-only / open-no-data instance is not silently dropped to info with no
	// record of why.
	r.Findings = append(r.Findings, costPostureFinding(r.AuthStatus, dataExposed, "Kubecost"))

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "on"
	}
	return r
}

// ── OpenCost ────────────────────────────────────────────────────────

// enumOpenCost — read-only OpenCost enumeration. The definitive API is on :9003
// (#52: :9090 is the UI SPA shell, not the API). We confirm via the cost-model
// JSON shape on /allocation and tier identically to Kubecost.
func enumOpenCost(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	dataExposed := false

	// 1. /allocation?aggregate=namespace — namespace NAMES + aggregate cost (#41).
	for _, path := range []string{
		"/allocation?window=1d&aggregate=namespace",
		"/allocation/compute?window=1d&aggregate=namespace",
	} {
		st, _, body, err := httpGET(c, b+path)
		if err != nil {
			continue
		}
		if st == 401 || st == 403 {
			if r.AuthStatus == "unknown" {
				r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
			}
			continue
		}
		if st != 200 {
			continue
		}
		if a := parseAllocation(body); a != nil {
			r.AuthStatus = "OPEN_API"
			dataExposed = true
			r.RawData["allocation"] = a
			r.RawData["api_path"] = strings.SplitN(path, "?", 2)[0]
			if a.Cluster != "" {
				r.Details = append(r.Details, "Cluster: "+a.Cluster)
			}
			r.Details = append(r.Details,
				fmt.Sprintf("Namespaces (%d): %s — aggregate cost ~%.4f", a.Count, strings.Join(a.Namespaces, ", "), a.AggCost))
			r.Findings = append(r.Findings, Finding{
				Category: "NAMESPACE_TOPOLOGY",
				Title:    fmt.Sprintf("OpenCost namespace cost topology exposed unauthenticated (%d namespaces)", a.Count),
				Detail:   fmt.Sprintf("GET %s returned the workload topology without authentication. Namespace names: %s. Aggregate cost ~%.4f. Names map the internal application layout; per-pod records were not enumerated (restraint).", strings.SplitN(path, "?", 2)[0], strings.Join(a.Namespaces, ", "), a.AggCost),
				Severity: "high",
				Data:     a,
			})
			break
		}
	}

	// 2. /metrics — kubecost_cluster_info carries provider/region/version (NAMES,
	//    not per-resource values; #41). We surface the single info line only.
	if st, _, body, err := httpGET(c, b+"/metrics"); err == nil && st == 200 {
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "kubecost_cluster_info{") {
				if len(line) > 400 {
					line = line[:400]
				}
				r.RawData["cluster_info_metric"] = line
				r.Details = append(r.Details, "kubecost_cluster_info metric exposed")
				if !dataExposed {
					r.Findings = append(r.Findings, Finding{
						Category: "CLUSTER_IDENTITY",
						Title:    "OpenCost /metrics exposes kubecost_cluster_info (provider/region/version)",
						Detail:   "The Prometheus exporter answered unauthenticated and carries the kubecost_cluster_info gauge, whose labels pin the cluster's cloud provider, region, and version.",
						Severity: "high",
					})
					dataExposed = true
				}
				if r.AuthStatus == "unknown" {
					r.AuthStatus = "OPEN_API"
				}
				break
			}
		}
	}

	r.Findings = append(r.Findings, costPostureFinding(r.AuthStatus, dataExposed, "OpenCost"))

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "on"
	}
	return r
}

// costPostureFinding emits the explicit auth+data posture finding so the floor
// severity is recorded even when no individual data finding fired (#37):
//
//	OPEN_API + data → high   (the cost-model data is reachable without auth)
//	OPEN_API, no data → medium (the API answers unauth but returned no topology)
//	otherwise (UI-only / gated) → info
func costPostureFinding(authStatus string, dataExposed bool, vendor string) Finding {
	switch {
	case authStatus == "OPEN_API" && dataExposed:
		return Finding{
			Category: "POSTURE",
			Title:    vendor + " cost-model API open and exposing data",
			Detail:   "The cost-model JSON API answered unauthenticated and returned cluster/namespace data. Anyone on the network can read the cluster's cloud account, region, and workload topology.",
			Severity: "high",
		}
	case authStatus == "OPEN_API":
		return Finding{
			Category: "POSTURE",
			Title:    vendor + " cost-model API open (no data returned)",
			Detail:   "The cost-model JSON API answered unauthenticated but returned no cluster identity or namespace topology (empty or not-yet-populated allocation). The API surface is open; treat as misconfiguration pending data.",
			Severity: "medium",
		}
	default:
		return Finding{
			Category: "POSTURE",
			Title:    vendor + " UI reachable; cost-model API not confirmed open",
			Detail:   "The UI/root was reachable but the cost-model JSON API did not answer unauthenticated (gated, redirected, or unreachable). No cost data exposure confirmed (#52).",
			Severity: "info",
		}
	}
}

// nonEmpty returns the first non-empty string, or "" if both are empty.
func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
