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
	// ── Document loaders / RAG ingest (Cat-Document-Loaders, 2026-06-19) ─────
	// The unguarded front door of every RAG pipeline. All auth-off-by-default.
	// Each anchors marker + status, with a catch-all-negative guard (LBot lesson,
	// Insight #107/#108): the deception fleet returns 200+canned-JSON on any path,
	// so a self-identifying marker alone is unsound at population scale.
	{
		// Apache Tika Server — GET /tika returns the exact greeting. No /version
		// endpoint; version only in startup log -> CVE-2025-66516 (XXE 10.0)
		// scoping needs a behavioral probe, recorded surface-open not exercised.
		Name:         "Apache Tika",
		DefaultPorts: []int{9998},
		Probes: []Probe{
			{Path: "/tika", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "This is Tika Server"},
				{Type: "body_contains", Value: "Please PUT"},
			}},
		},
		Severity: "high",
	},
	{
		// Gotenberg — Gotenberg-Trace correlation header on every API response is
		// the load-bearing isolator on noisy port 3000. CVE-2026-40281 (ExifTool
		// RCE 10.0) + SSRF->IMDS cluster (<8.32.0).
		Name:         "Gotenberg",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "header_contains", Field: "Gotenberg-Trace", Value: ""},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "header_contains", Field: "Gotenberg-Trace", Value: ""},
			}},
		},
		Severity: "critical",
	},
	{
		// GROBID — /api/isalive returns plain "true"; root console contains GROBID.
		// /api/version gives clean git-describe version for CVE scoping. No direct
		// CVE; unauth /api/modelTraining = compute-exhaustion DoS surface.
		Name:         "GROBID",
		DefaultPorts: []int{8070, 8071},
		Probes: []Probe{
			{Path: "/api/isalive", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "true"},
				{Type: "body_not_contains", Value: "<html"},
			}},
		},
		Severity: "medium",
	},
	{
		// docling-serve (IBM/LF AI) — /openapi.json carries the vendor-unique
		// convert/source path. Auth via DOCLING_SERVE_API_KEY (off default).
		// CVE-2026-24009 (PyYAML RCE 8.1) via embedded docling-core 2.21.0-2.48.3.
		Name:         "docling-serve",
		DefaultPorts: []int{5001},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "/v1/convert/source"},
			}},
		},
		Severity: "high",
	},
	{
		// Unstructured API — /general/openapi.json title is unambiguous. Swagger at
		// /general/docs (NOT /docs). Port 8000 extreme-noise -> anchor on title,
		// not port. CVE-2025-64712 (path-trav->RCE 9.8) in the unstructured lib.
		Name:         "Unstructured API",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/general/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Unstructured Pipeline API"},
			}},
		},
		Severity: "high",
	},
	// ── LLM-app / RAG builders (Cat-34) ─────────────────────────
	{
		Name:         "Vanna",
		DefaultPorts: []int{8000, 8001, 8010, 8080, 8084, 5000, 3000},
		Probes: []Probe{
			// Cross-variant: both classic vanna-flask (vanna-flask.svg) and the
			// newer "Vanna Agents Chat" UI embed the vendor-unique img.vanna.ai
			// CDN. Anchored to status_code per the naked-keyword lesson.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "img.vanna.ai"},
			}},
		},
		Severity: "high",
	},
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
	// Marqo — added Cat-02 virgin re-birth 2026-06-04 (no nuclei template existed).
	// Root returns {"message":"Welcome to Marqo",...} — exact hardcoded string, VERY LOW FP.
	// /indexes is the unauth enumeration surface (index names). Doc-grounded; field-UNVALIDATED
	// (0 Shodan hits via http.html on the Freelancer web UI — route via Censys/active to confirm).
	{
		Name:         "Marqo",
		DefaultPorts: []int{8882, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Welcome to Marqo"},
			}},
			{Path: "/indexes", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "results"},
			}},
		},
		Severity: "high",
	},
	// Manticore Search — added Cat-02 virgin re-birth 2026-06-04 (no nuclei template existed).
	// No auth layer exists in the product (Manticore ships zero authentication). Recent versions
	// emit `X-Powered-By: Manticore Search` on the HTTP JSON API (9308) — header-anchored, unique.
	// Doc-grounded; field-UNVALIDATED (0 Shodan hits — confirm via active 9308/9306 sweep).
	{
		Name:         "Manticore Search",
		DefaultPorts: []int{9308, 9306},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "header_contains", Field: "X-Powered-By", Value: "Manticore"},
			}},
		},
		Severity: "high", // no-auth-by-design + full SQL over HTTP
	},

	// ── Cat-02 wave-2 gap fingerprints (2026-06-05; scaffolded from `tome probe`) ──
	// MongoDB (27017) and Cassandra (9042) intentionally NOT here — binary wire protocols
	// (Mongo hello/buildInfo, CQL SUPPORTED) that the HTTP matcher cannot speak; need a Go enumerator.
	{
		Name:         "SurrealDB",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "surrealdb-"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Infinity", // InfiniFlow vector DB (NOT michaelfeil infinity-embedding)
		DefaultPorts: []int{23820},
		Probes: []Probe{
			{Path: "/databases", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "error_code"},
				{Type: "json_field", Field: "databases"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Databend",
		DefaultPorts: []int{8000, 8124},
		Probes: []Probe{
			{Path: "/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "databend"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "GreptimeDB",
		DefaultPorts: []int{4000},
		Probes: []Probe{
			{Path: "/v1/sql?sql=SELECT+1", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "records"},
				{Type: "body_contains", Value: "schema"},
			}},
		},
		Severity: "high",
	},
	// Epsilla — body quirk: lowercase "statusCode":200. Path may require POST; FIELD-UNVALIDATED.
	{
		Name:         "Epsilla",
		DefaultPorts: []int{8888},
		Probes: []Probe{
			{Path: "/api/default/load", Matches: []MatchCond{
				{Type: "body_contains", Value: `"statusCode":200`},
				{Type: "body_contains", Value: `"message"`},
				{Type: "body_contains", Value: `"result"`},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Solr",
		DefaultPorts: []int{8983, 8984},
		Probes: []Probe{
			{Path: "/solr/admin/info/system", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "solr-spec-version"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Couchbase",
		DefaultPorts: []int{8091},
		Probes: []Probe{
			{Path: "/pools", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "implementationVersion"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Neo4j", // :7474/ discovery JSON, readable unauth even when Bolt is gated
		DefaultPorts: []int{7474},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "neo4j_version"},
			}},
		},
		Severity: "medium",
	},
	// OceanBase — obshell HTTP on 2886; 2881 is MySQL-wire (won't HTTP-match). CANDIDATE / FIELD-UNVALIDATED.
	{
		Name:         "OceanBase",
		DefaultPorts: []int{2886, 2881},
		Probes: []Probe{
			{Path: "/api/v1/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OceanBase"},
			}},
		},
		Severity: "medium",
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

	// ── OpenAI-compat inference servers (Cat-03, 2026-06-05) ────
	// KoboldCpp — local LLM inference server, port 5001 (KoboldCpp-exclusive).
	// GET /api/extra/version returns the capabilities dict with a literal
	// "KoboldCpp" string in the result field — zero FP, unique across all
	// AI/ML servers. Optional --password flag only gates generation endpoints;
	// /api/extra/version is always unauthenticated. Auth tier A*.
	{
		Name:         "KoboldCpp",
		DefaultPorts: []int{5001, 5000, 8000},
		Probes: []Probe{
			{Path: "/api/extra/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"result":"KoboldCpp"`},
			}},
			// FN fix (2026-06-05, Cat-03): every KoboldCpp response carries
			// `Server: KoboldCppServer` and the landing page is `<title>KoboldAI
			// Lite</title>`. 108.210.175.159:5001 was a live KoboldCpp that this
			// fingerprint MISSED (h2oGPT claimed it instead) because the
			// /api/extra/version probe was unreachable on that crawl while `/`
			// served the Lite UI. The Server header is zero-FP across the corpus.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Server", Value: "KoboldCppServer"},
			}},
		},
		Severity: "medium",
	},

	// LM Studio — desktop LLM app exposing OpenAI-compat server on port 1234
	// (LM Studio-exclusive default). Native REST API at /api/v1/ prefix is
	// LM Studio-exclusive; /api/v1/models/load and /api/v1/models/download
	// allow unauth model management including HuggingFace downloads when no
	// API token is configured. Auth tier A*.
	{
		Name:         "LM Studio",
		DefaultPorts: []int{1234, 8080, 80},
		Probes: []Probe{
			{Path: "/api/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
			}},
		},
		Severity: "medium",
	},

	// Aphrodite Engine — vLLM fork for creative/RP workloads (PygmalionAI).
	// Default port 2242 (Aphrodite-exclusive). owned_by:"pygmalionai" in
	// /v1/models is hardcoded in protocol.py 0.6.4+ — unique across all
	// OpenAI-compat servers. Do NOT use body_contains:"aphrodite" alone —
	// bare "aphrodite" matches 362 Shodan Greek-mythology noise results.
	{
		Name:         "Aphrodite Engine",
		DefaultPorts: []int{2242, 8000, 7860},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "pygmalionai"},
			}},
		},
		Severity: "medium",
	},

	// LMDeploy — InternLM/Shanghai AI Lab serving engine. Port 23333 is
	// LMDeploy-exclusive (api_server.py:1432, server_port default 23333).
	// auth_default=none: api_keys parameter Default to None (api_server.py:1486)
	// — Swagger UI mounted at docs_url='/' (api_server.py:1543), /openapi.json
	// publicly enumerates every route. owned_by:"lmdeploy" in /v1/models;
	// /update_weights, /terminate, /sleep, /wakeup, /distserve/* exposed.
	//
	// Hardening (2026-06-09, Lane 5): the bare body_contains:"lmdeploy" probe
	// was an Insight #6-class single-keyword match. Anchored on the unique
	// route family /distserve/engine_info + /v1/encode + /is_sleeping +
	// /v1/chat/interactive — none of which appear in vLLM, SGLang, TGI, or
	// AIBrix openapi.json. The /openapi.json probe requires status_code:200
	// AND all three distinctive route strings to fire — IAP HTML walls (CVAT-FP
	// class, reference_aimap_cvat_iap_fp) cannot satisfy three substring
	// conditions on a single response body. Tome source: ~/tome/platforms/lmdeploy.json.
	//
	// Cat-LMDeploy Lane B hardening (2026-06-10): added /v1/encode as a third
	// conjunctive anchor on /openapi.json, taking the matcher to the tome's
	// recommended "at least 2 of N" floor + 1. Three independent LMDeploy-
	// unique route names co-occurring in a single openapi.json document is a
	// near-zero-FP signal. DefaultPorts kept at {23333,8000,80} pending Lane A
	// cross-corpus port distribution check (tome canonical = [23333] only;
	// 8000/80 carry the FastAPI default convention and may be drift).
	{
		Name:         "LMDeploy",
		DefaultPorts: []int{23333, 8000, 80},
		Probes: []Probe{
			// Primary: /openapi.json route-name anchor — LMDeploy-unique distserve
			// + chat-interactive + encode route family. Conjunctive match across
			// three unique strings inside a single JSON document rejects substrate
			// noise (Insight #6 + Cat-Tabby Tabby FP hardening pattern 2026-06-09).
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "/distserve/engine_info"},
				{Type: "body_contains", Value: "/v1/chat/interactive"},
				{Type: "body_contains", Value: "/v1/encode"},
			}},
			// Fallback: /v1/models — kept for non-Swagger deploys but anchored
			// on data field shape AND owned_by:"lmdeploy". owned_by:"lmdeploy"
			// is hardcoded in api_server.py model_card construction, so the
			// keyword is structurally bound to the JSON model object, not the
			// page HTML.
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "lmdeploy"},
			}},
		},
		Severity: "medium",
	},

	// AIBrix — ByteDance K8s-native vLLM control plane on Envoy Gateway.
	// auth_default=none (quickstart literally curls http://${ENDPOINT}/v1/completions
	// with no auth). Default LoadBalancer on port 80; aibrix-runtime sidecar
	// on 8080; vLLM backend on 8000 reachable directly when Service is
	// LoadBalancer instead of ClusterIP. Tome source: ~/tome/platforms/aibrix.json
	// (sha 0d0ff153b2fd82dbdcafc23721fef50656fb6d24).
	//
	// FP-discipline: the gateway is just Envoy, so a bare "envoy" header would
	// match every Envoy in the world. The k8s label namespace model.aibrix.ai
	// is the AIBrix-unique tell — it is a string that only appears in
	// aibrix-system-controlled responses (HTTPRoute resource references, label
	// echoes, gateway plugin error bodies). Anchored on body_contains of the
	// label namespace AND a structured signal (Envoy server header or vLLM-shape
	// /v1/models response) to reject blog/docs pages.
	{
		Name:         "AIBrix",
		DefaultPorts: []int{80, 8000, 8080},
		Probes: []Probe{
			// Primary: /v1/models gateway aggregator response — vLLM-shape JSON
			// (data array) PLUS the model.aibrix.ai label string appearing in
			// the gateway-aggregated payload PLUS Envoy server header. Triple
			// anchor rejects (1) standalone vLLM (no aibrix label), (2) generic
			// Envoy proxies (no /v1/models), and (3) marketing pages mentioning
			// aibrix (no Envoy header on a /v1/models JSON response).
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "model.aibrix.ai"},
				{Type: "header_contains", Field: "Server", Value: "envoy"},
			}},
			// Fallback: /healthz on aibrix-runtime sidecar (port 8080) — the
			// runtime sidecar response embeds aibrix-system namespace strings
			// in error/info paths. Anchored on body_contains of the namespace
			// AND status_code:200 AND aibrix-runtime header tell.
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "aibrix"},
				{Type: "header_contains", Field: "Server", Value: "envoy"},
			}},
		},
		Severity: "high",
	},

	// RTP-LLM — Alibaba havenask LLM serving engine. Default START_PORT=8088
	// (py_config_modules.py:36, DEFAULT_START_PORT). auth_default=none:
	// FastAPI app receives only CORSMiddleware, no AuthenticationMiddleware
	// (frontend_app.py:166-175). /worker_status discloses dp_size, tp_size,
	// role, running task list, cache utilization; /set_log_level,
	// /update_scheduler_info, /start_profile are anonymous-mutate surfaces.
	// Tome source: ~/tome/platforms/rtp-llm.json (sha b0c09a3440f7df0dce8d682ae4383d741809bb56).
	//
	// FP-discipline: port 8088 is also http-alt and admin-panel territory,
	// so port presence alone is high-FP. The havenask service-mesh route
	// aliasing (/GraphService/cm2_status, /SearchService/cm2_status) is the
	// single most distinctive tell — these route names are reused from
	// Alibaba's open-source havenask search engine, and no other LLM serving
	// stack carries them. The frontend_concurrency_limit + dp_size key
	// co-occurrence on /worker_status is structurally bound to RTP-LLM's
	// frontend+backend split (frontend adds frontend_*, backend gRPC adds
	// dp_size/tp_size) — neither key alone is unique, the combination is.
	{
		Name:         "RTP-LLM",
		DefaultPorts: []int{8088, 8089, 8090, 8092},
		Probes: []Probe{
			// Primary: /worker_status — two co-occurring JSON keys whose
			// combination is RTP-LLM unique per source review. dp_size alone
			// would FP on Ray/Dask telemetry; frontend_concurrency_limit alone
			// could FP on generic FastAPI middleware boilerplate. Together
			// they require both the frontend layer AND the rtp-llm backend.
			{Path: "/worker_status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "frontend_available_concurrency"},
				{Type: "body_contains", Value: "dp_size"},
			}},
			// Fallback: /cache_status — same frontend_* key plus
			// available_kv_cache (KV-cache telemetry is LLM-serving specific;
			// the frontend prefix is RTP-LLM specific). Conjunctive match.
			{Path: "/cache_status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "available_kv_cache"},
				{Type: "body_contains", Value: "frontend_available_concurrency"},
			}},
			// Tertiary: havenask service-mesh path returning "ok" — confirms
			// Alibaba search-stack lineage even when LLM-specific endpoints
			// are filtered. Anchored on status_code:200 AND the unique path
			// itself; the body "ok" is short but the path name is the load
			// bearer here.
			{Path: "/GraphService/cm2_status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ok"},
			}},
		},
		Severity: "high",
	},

	// GPT4All — local LLM desktop app (Nomic AI), port 4891 (exclusive).
	// owned_by:"humanity" is hardcoded in server.cpp — unique across all
	// OpenAI-compat servers. Server is off by default (serverChat=false);
	// only fires on unauth-enabled instances. Auth tier A*.
	{
		Name:         "GPT4All",
		DefaultPorts: []int{4891},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "humanity"},
			}},
		},
		Severity: "medium",
	},

	// HuggingFace TGI (Text Generation Inference) — LLM inference server,
	// maintenance mode as of 2026. Docker -p 8080:80 is the canonical mapping.
	// GET /info returns tokenization_workers + model_sha — absent from all
	// other serving platforms. model_id reveals private/gated HF models.
	// Auth tier A (no auth mechanism; Shodan-dark via JSON-body dorks).
	{
		Name:         "HuggingFace TGI",
		DefaultPorts: []int{8080, 80, 3000},
		Probes: []Probe{
			{Path: "/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "model_id"},
				{Type: "body_contains", Value: "tokenization_workers"},
			}},
		},
		Severity: "medium",
	},

	// faster-whisper server (speaches / faster-whisper-server) — OpenAI-compat
	// ASR API. GET /v1/models returns model IDs with "Systran/" prefix
	// (e.g. Systran/faster-distil-whisper-large-v3), distinguishing from
	// openai-whisper-asr-webservice (openai/whisper-*) and whisper.cpp.
	// linuxserver/faster-whisper uses port 10300. Auth tier A.
	{
		Name:         "faster-whisper server",
		DefaultPorts: []int{8000, 10300, 8080},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "Systran"},
			}},
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "faster-whisper"},
			}},
		},
		Severity: "low",
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

	// ── RAG Framework Servers (Cat-07, 2026-05-31) ──────────────
	// Built from data/platform-intel/rag-frameworks-osint-2026-05-27.md.
	// Each probe re-implements a Shodan dork already validated in
	// shodan/queries/rag-frameworks-queries.md as an active probe.
	// Distinctive product names (LightRAG, goldenverba, Perplexica,
	// kotaemon, ragapp) act as marker anchors; common-word names
	// (R2R, txtai, Onyx) require a second conjunct (Insight #6).
	{
		// LightRAG — GraphRAG server, port 9621 (LightRAG-exclusive).
		// Auth off by default; /health is always unauthenticated and the
		// Ollama-compat endpoints stay open even with API-key auth on.
		//
		// HARDENED 2026-06-17 (Cat RAG-framework-server survey). The old
		// fingerprint was status_code:200 + a single body_contains:"LightRAG"
		// on /docs and /. That naked title-keyword shape is the catchall-200
		// FP class (cf. the aimap CVAT fingerprint firing on transient GCP IAP
		// 200s, and the dcm4chee ASP.NET catchall echo): a reverse-proxy that
		// reflects the brand string, or a renamed WebUI whose /docs title is
		// preserved, satisfies it. Re-anchored on the /health JSON contract.
		//
		// /health on a real LightRAG server returns a JSON object carrying the
		// pair core_version + webui_title (LightRAG-specific build/UI keys) plus
		// status:"healthy". The core_version + webui_title CONJUNCTION is the
		// marker anchor — no generic health endpoint emits BOTH keys (Insight #6).
		Name:         "LightRAG",
		DefaultPorts: []int{9621, 80, 443, 8000},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "core_version"},        // LightRAG build-version key
				{Type: "json_field", Field: "webui_title"},         // LightRAG WebUI key — pair defeats renamed-UI FP
				{Type: "body_contains", Value: `"status":"healthy"`}, // value-gate (json_field is presence-only)
			}},
			// NOTE: auth_mode is a VALUE the engine cannot decode at the
			// fingerprint layer — MatchCond has no value-equality type, only
			// json_field (presence) + body_contains (substring). This probe
			// does NOT branch on auth_mode; open-vs-auth determination
			// (auth_mode=="disabled" => open, "enabled" => auth-on) MUST be
			// made downstream by a LightRAG deep enumerator reading the same
			// /health body into EnumResult.AuthStatus. Wiring that enumerator
			// (enumeratorRegistry["LightRAG"]) is the follow-on; it is NOT
			// required for detection. Fingerprint stops at identity.
			//
			// Fallback for older builds whose /health predates webui_title:
			// /docs Swagger title gated on the real swagger-ui marker so the
			// lone brand keyword is never the only condition (anti catchall-200).
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LightRAG"},
				{Type: "body_contains", Value: "swagger-ui"}, // anchor: real Swagger doc page, not a brand reflection
			}},
		},
		Severity: "high",
	},
	{
		// llama_deploy apiserver — LlamaIndex agent control plane / rag-framework
		// server, port 4501 (llama_deploy-exclusive). Added 2026-06-17
		// (Cat RAG-framework-server survey).
		//
		// /status on a real apiserver returns a JSON object with the triple
		// max_deployments (numeric quota) + deployments (an object/array of
		// live deployments) + status:"healthy". That conjunction is unique to
		// llama_deploy — no generic /status emits max_deployments. Identity is
		// the structured-field set, not a brand keyword (Insight #6).
		//
		// NOTE: the spec asks for `deployments` as a JSON ARRAY, but json_array
		// tests the WHOLE BODY (parseJSONArray on body), not a field — and the
		// body here is a top-level OBJECT, so json_array would FAIL. There is no
		// "field-is-array" MatchCond in the vocabulary. Closest expressible
		// equivalent: json_field "deployments" (presence) + body_contains
		// `"deployments"` is redundant with presence, so the array-shape
		// constraint is dropped to "deployments key present". max_deployments
		// being numeric likewise cannot be type-checked (json_field is
		// presence-only); its mere presence already discriminates.
		Name:         "llama_deploy apiserver",
		DefaultPorts: []int{4501, 80, 443},
		Probes: []Probe{
			{Path: "/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "max_deployments"},      // llama_deploy quota key — unique to apiserver
				{Type: "json_field", Field: "deployments"},          // deployments map/array (presence only)
				{Type: "body_contains", Value: `"status":"healthy"`}, // value-gate; nested-value equality unavailable
			}},
		},
		Severity: "high",
	},
	{
		// LlamaIndex Server (create-llama) — rag-framework server, port 8000.
		// Added 2026-06-17 (Cat RAG-framework-server survey).
		//
		// The generic "/api/chat" router is shared by many FastAPI chat apps,
		// so a lone /api/chat match is the catchall-200 FP class. The
		// create-llama server ALWAYS ships the PAIR /api/chat + /api/files
		// (chat router + file-management router); the pair conjunction on the
		// OpenAPI/Swagger surface is server-specific. Prefer the openapi.json
		// path (structured) with /docs (Swagger HTML) as the OR fallback.
		Name:         "LlamaIndex Server",
		DefaultPorts: []int{8000, 80, 443, 3000},
		Probes: []Probe{
			// Structured surface: openapi.json carries the router path literals.
			{Path: "/api/chat/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "starterQuestions"}, // create-llama chat-config key
				{Type: "body_not_contains", Value: "llamaindex.ai"}, // anti marketing-site reflection
			}},
			// Swagger HTML fallback: the create-llama router PAIR is the anchor.
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "/api/chat"},  // chat router
				{Type: "body_contains", Value: "/api/files"}, // file router — pair defeats generic /api/chat FP
				{Type: "body_not_contains", Value: "llamaindex.ai"}, // anti marketing-site reflection
			}},
		},
		Severity: "high",
	},
	{
		// Hayhooks (Haystack) — rag-framework pipeline server, ports 1416/1417
		// (Hayhooks defaults) + 8000 (SHARED). Added 2026-06-17
		// (Cat RAG-framework-server survey).
		//
		// /status on a real Hayhooks server returns {"status":"Up!","pipelines":[...]}.
		// The literal "Up!" is hayhooks-unique (no other health endpoint emits
		// that exact token); the pipelines array key is the second conjunct.
		// "pipelines" alone is generic and is anchored ONLY WITH "Up!".
		Name:         "Hayhooks",
		DefaultPorts: []int{1416, 1417, 8000, 80, 443},
		Probes: []Probe{
			{Path: "/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"status":"up!"`}, // hayhooks-unique literal (case-insensitive match)
				{Type: "json_field", Field: "pipelines"},          // pipelines key — second conjunct, gated by Up!
			}},
		},
		Severity: "high",
	},
	{
		// Haystack REST API (legacy deepset server) — rag-framework server,
		// port 8000 (SHARED). Added 2026-06-17 (Cat RAG-framework-server survey).
		//
		// /openapi.json info.title is exactly "Haystack REST API" — that title
		// is the anchor. /initialized==true is generic and MUST be title-gated.
		//
		// NOTE: json_field does NOT descend into info.title (jHas is a flat
		// top-level lookup). Closest expressible equivalent: json_field "info"
		// (the parent key present) + body_contains `"Haystack REST API"` (the
		// serialized title literal). The exact-equality semantics the spec asks
		// for ("title EXACTLY") are not expressible — body_contains is a
		// substring test — but the full title string is distinctive enough that
		// substring containment is effectively the title match here.
		Name:         "Haystack REST API",
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},                    // OpenAPI info object present
				{Type: "body_contains", Value: `"Haystack REST API"`},  // title literal — the anchor (nested-key gap)
			}},
		},
		Severity: "high",
	},
	{
		// Microsoft GraphRAG (accelerator / solution-accelerator server form
		// only — the core library is CLI-only and gets NO fingerprint).
		// Ports 443/80/8000/8080. Added 2026-06-17 (Cat RAG-framework-server survey).
		//
		// /manpage/openapi.json info.title is exactly "GraphRAG" (NOT the
		// substring "graphrag", which would also catch LightRAG, which
		// self-brands as a GraphRAG server and is the #1 false-positive). The
		// accelerator-unique parameterized routes /graph/graphml/ and
		// /source/report/ are the second anchor. LightRAG and its /webui are
		// excluded at the matcher with body_not_contains.
		//
		// NOTE: two unexpressible constraints, both handled by the closest
		// conjunctive marker-anchored equivalent:
		//   1. info.title EXACTLY "GraphRAG" — json_field has no nested descent
		//      and no value-equality. Expressed as json_field "info" (parent
		//      present) + body_contains `"title":"GraphRAG"` (serialized exact
		//      title pair, quote-bounded so it will NOT substring-match
		//      "LightRAG" or "title":"GraphRAG Accelerator"-style variants as a
		//      bare "graphrag"). The quote-bounded literal is the tightest the
		//      substring engine allows.
		//   2. route A OR route B — there is no within-probe disjunction. Two
		//      probes express the OR: probe 1 anchors on /graph/graphml/,
		//      probe 2 on /source/report/. Both carry the title + LightRAG/
		//      webui exclusions so neither probe is a weaker gate.
		Name:         "Microsoft GraphRAG",
		DefaultPorts: []int{443, 80, 8000, 8080},
		Probes: []Probe{
			{Path: "/manpage/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},                       // OpenAPI info object present
				{Type: "body_contains", Value: `"title":"GraphRAG"`},      // exact title pair (nested-key + equality gap)
				{Type: "body_contains", Value: "/graph/graphml/"},         // accelerator-unique route (anchor route A)
				{Type: "body_not_contains", Value: "LightRAG"},            // #1 FP: LightRAG self-brands as GraphRAG server
				{Type: "body_not_contains", Value: "/webui"},              // anti-LightRAG WebUI route
			}},
			// OR fallback: same identity, anchored on the /source/report/ route.
			{Path: "/manpage/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},
				{Type: "body_contains", Value: `"title":"GraphRAG"`},
				{Type: "body_contains", Value: "/source/report/"},         // accelerator-unique route (anchor route B)
				{Type: "body_not_contains", Value: "LightRAG"},
				{Type: "body_not_contains", Value: "/webui"},
			}},
		},
		Severity: "high",
	},
	{
		// PrivateGPT — offline RAG, port 8001. Auth off by default
		// (auth.enabled:false). /v1/ingest/* paths do not exist in stock
		// OpenAI-compatible servers — clean identity signal.
		Name:         "PrivateGPT",
		DefaultPorts: []int{8001},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "PrivateGPT"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "PrivateGPT"},
			}},
		},
		Severity: "high",
	},
	{
		// txtai — semantic search/RAG, port 8080 (SHARED). Auth fully open
		// by default. Require the openapi spec carry both the name and the
		// txtai-specific /workflow path — two conjuncts on a shared port.
		Name:         "txtai",
		DefaultPorts: []int{8080, 8000},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "txtai"},
				{Type: "body_contains", Value: "/workflow"},
			}},
		},
		Severity: "high",
	},
	{
		// Cognita (TrueFoundry) — RAG pipeline, port 8000 (SHARED).
		// Auth off in default local compose. Require both the app name and
		// the truefoundry operator string.
		Name:         "Cognita",
		DefaultPorts: []int{8000, 5001},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "cognita"},
				{Type: "body_contains", Value: "truefoundry"},
			}},
		},
		Severity: "high",
	},
	{
		// R2R (SciPhi) — RAG framework, port 7272 (R2R-exclusive). Auth off
		// by default. /v3/ path prefix + health response shape; "R2R" is a
		// common token so anchor on the v3 health JSON shape.
		Name:         "R2R",
		DefaultPorts: []int{7272},
		Probes: []Probe{
			{Path: "/v3/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "results"},
				{Type: "body_contains", Value: "response"},
			}},
		},
		Severity: "high",
	},
	{
		// Kotaemon — document-QA Gradio UI, port 7860 (SHARED with SD/Whisper
		// Gradio apps). Default creds admin/admin. "kotaemon" is a unique
		// product token, safe as a single anchor on the shared port.
		Name:         "Kotaemon",
		DefaultPorts: []int{7860},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "kotaemon"},
			}},
		},
		Severity: "high",
	},
	{
		// Quivr — second-brain RAG, port 5050 (Quivr backend default).
		// Auth on by default (Supabase JWT); fingerprint is identity-only.
		Name:         "Quivr",
		DefaultPorts: []int{5050},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Quivr"},
			}},
		},
		Severity: "medium",
	},
	{
		// Danswer / Onyx — enterprise AI search, port 3000 (SHARED). Danswer
		// is a distinctive legacy token; Onyx is a common word so requires
		// the "connector" conjunct.
		Name:         "Danswer/Onyx",
		DefaultPorts: []int{3000, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Danswer"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Onyx"},
				{Type: "body_contains", Value: "connector"},
			}},
		},
		Severity: "high",
	},
	{
		// Verba (Weaviate) — RAG app, port 8000 (SHARED). Auth off by design.
		// The PyPI package token "goldenverba" appears in the bundle and is
		// highly distinctive — safe single anchor.
		Name:         "Verba",
		DefaultPorts: []int{8000, 8080, 8888},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "goldenverba"},
			}},
		},
		Severity: "high",
	},
	{
		// DocsGPT — documentation QA, port 5001. Auth off by default;
		// pre-auth RCE CVE-2025-0868 on v0.8.1-v0.12.0. Identity on the
		// distinctive product name.
		Name:         "DocsGPT",
		DefaultPorts: []int{5001},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "DocsGPT"},
			}},
		},
		Severity: "high",
	},
	{
		// Ragapp — agentic RAG (LlamaIndex), port 8000 (SHARED). No auth by
		// design; /admin is an unauthenticated admin UI. Require app name +
		// the /admin path conjunct.
		Name:         "Ragapp",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/admin/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ragapp"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ragapp"},
				{Type: "body_contains", Value: "llamaindex"},
			}},
		},
		Severity: "high",
	},
	{
		// Perplexica — private Perplexity, port 3000 (SHARED). No auth by
		// default; devs advise against public exposure. Distinctive product
		// token.
		Name:         "Perplexica",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Perplexica"},
			}},
		},
		Severity: "high",
	},
	{
		// RAGFlow — deep-document RAG, port 80 (nginx front, SHARED) and 9380
		// (internal API). Default creds admin@ragflow.io/admin. Port 80 is
		// very shared; require both the SPA token and a second app string.
		Name:         "RAGFlow",
		DefaultPorts: []int{80, 9380, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ragflow"},
				{Type: "body_contains", Value: "RAGFlow"},
			}},
		},
		Severity: "high",
	},

	// ── Service mesh / cluster introspection planes ─────────────
	// Cat: Network Perimeter / Service Mesh, 2026-05-31. Built from
	// data/platform-intel/service-mesh-perimeter-osint-2026-05-31.md.
	//
	// Category thesis: these planes describe the cluster's internal traffic
	// by design (service graph, pod IPs, mesh identities, mTLS certs, L7
	// metadata) and ship no-auth-by-default, substituting network placement
	// (loopback / ClusterIP / NetworkPolicy) for authentication. Exposure
	// therefore means the placement control ALREADY failed — so a reachable
	// plane is almost always a fully-unauth cluster-recon API.
	//
	// Design (Insight #16 — a 200 is identity, not auth-state): the FIRST
	// probe in each fingerprint is the data-layer endpoint whose 200+marker
	// proves identity AND unauth at once (auth would 401, the probe fails).
	// matchFingerprints records MatchPath on first hit, so the report
	// disambiguates auth-state per host: a hit on the data path = unauth
	// confirmed; a hit on the identity-only fallback = present-but-gated,
	// downgrade at ledger time. Restraint (schema-recon): probes read only
	// enough to classify — namespace/metric/config names — never workloads.
	{
		// Kiali — Istio mesh console (20001). `anonymous` auth strategy = full
		// cluster-wide read via the Kiali ServiceAccount. /api/namespaces
		// returning a populated JSON array unauth IS that leak; /api/config is
		// reachable pre-auth (SPA bootstrap) so it still IDs token-gated installs.
		Name:         "Kiali",
		DefaultPorts: []int{20001, 443, 80},
		Probes: []Probe{
			{Path: "/api/namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
				{Type: "body_contains", Value: "name"},
			}},
			{Path: "/kiali/api/namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
				{Type: "body_contains", Value: "name"},
			}},
			{Path: "/api/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "istioNamespace"},
			}},
		},
		Severity: "high",
	},
	{
		// Hubble UI — Cilium flow-visibility console. No auth, no login by
		// design (assumes port-forward only). SPA title is the zero-FP anchor;
		// the cluster-wide flow DATA lives behind the gRPC relay (4245),
		// covered by a separate grpcurl lane (aimap is HTTP-only).
		Name:         "Hubble UI",
		DefaultPorts: []int{12000, 30120, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Hubble UI</title>"},
			}},
		},
		Severity: "medium",
	},
	{
		// Linkerd viz dashboard (8084) — no auth layer by design; the only
		// built-in guard is a Host-header regexp (DNS-rebind fix) that
		// enforcedHostRegexp:.* disables. The namespace data-attribute is the
		// verified-nuclei conjunct.
		Name:         "Linkerd Viz",
		DefaultPorts: []int{8084, 8085, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "data-controller-namespace=\"linkerd"},
			}},
		},
		Severity: "high",
	},
	{
		// Linkerd proxy admin (4191) — binds 0.0.0.0, no auth, no TLS.
		// /env.json leaks proxy env vars (creds if env-injected); /metrics
		// leaks the workload graph via dst_* labels. Both unauth by
		// construction. env.json first (credential-exposure severity).
		Name:         "Linkerd Proxy Admin",
		DefaultPorts: []int{4191},
		Probes: []Probe{
			{Path: "/env.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LINKERD2_PROXY_"},
			}},
			{Path: "/metrics", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "proxy_build_info"},
				{Type: "body_contains", Value: "inbound_http_authz"},
			}},
		},
		Severity: "high",
	},
	{
		// Cilium metrics (9962 agent / 9963 operator / 9965 hubble) — no auth,
		// default-on all-interface. cilium_drop_count_total and
		// hubble_flows_processed_total are Cilium-exclusive metric namespaces;
		// they leak the workload/flow-graph topology.
		Name:         "Cilium Metrics",
		DefaultPorts: []int{9962, 9963, 9965, 9090},
		Probes: []Probe{
			{Path: "/metrics", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "cilium_drop_count_total"},
			}},
			{Path: "/metrics", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "hubble_flows_processed_total"},
			}},
		},
		Severity: "medium",
	},
	{
		// Istio sidecar Envoy admin (15000) — no auth, loopback-bound in-pod
		// but reachable via exposed nodePort / co-tenant container.
		// /config_dump = full mesh topology + ALL mTLS cert material this proxy
		// holds + routing + filter chains. envoy.admin.v3 @type +
		// .svc.cluster.local service name = Istio-managed Envoy, unauth.
		Name:         "Istio Envoy Admin",
		DefaultPorts: []int{15000},
		Probes: []Probe{
			{Path: "/config_dump", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "envoy.admin.v3"},
				{Type: "body_contains", Value: ".svc.cluster.local"},
			}},
			{Path: "/server_info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "state"},
			}},
		},
		Severity: "high",
	},
	{
		// istiod debug (15014, also 8080) — structurally unauth pre-1.30
		// (ENABLE_DEBUG_ENDPOINT_AUTH default-true only from 1.30.0).
		// /debug/endpointz + /debug/registryz = the full service registry:
		// every pod IP, ServiceAccount, namespace istiod's ClusterRole sees.
		Name:         "Istiod Debug",
		DefaultPorts: []int{15014, 8080},
		Probes: []Probe{
			{Path: "/debug/endpointz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "svc.cluster.local"},
				{Type: "body_contains", Value: "serviceAccount"},
			}},
			{Path: "/debug/registryz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "svc.cluster.local"},
				{Type: "body_contains", Value: "hostname"},
			}},
		},
		Severity: "high",
	},
	{
		// Pomerium — identity-aware proxy (IS the auth layer). Presence is
		// trivial + deterministic via the NAMESPACED jwks path; the real
		// finding (a route with public_access:true fronting internal tooling)
		// is behavioral and needs per-route probing aimap can't do generically.
		// So this fingerprint is identity/attribution only — its value is the
		// operator's real domain SANs for the VisorGraph cert-pivot. The
		// /.well-known/pomerium/ prefix distinguishes it from generic OIDC.
		Name:         "Pomerium",
		DefaultPorts: []int{443, 80},
		Probes: []Probe{
			{Path: "/.well-known/pomerium/jwks.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "keys"},
				{Type: "body_contains", Value: "ES256"},
			}},
		},
		Severity: "low",
	},
	{
		// Kubernetes API server (6443/8443) — surfaced here via the Cilium
		// cluster-cert pivot (*.<cluster>.hubble-grpc.cilium.io leaf). /version
		// is anonymous-allowed by default and IDs the control plane; the
		// FINDING is anonymous-auth: /api/v1/namespaces returning a populated
		// item list unauth = system:anonymous bound to cluster read.
		Name:         "Kubernetes API",
		DefaultPorts: []int{6443, 8443},
		Probes: []Probe{
			{Path: "/api/v1/namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "\"kind\":\"NamespaceList\""},
				{Type: "json_field", Field: "items"},
			}},
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gitVersion"},
				{Type: "body_contains", Value: "buildDate"},
			}},
		},
		Severity: "high",
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
			// Argilla v2 (current, HF-managed) public version endpoint.
			{Path: "/api/v1/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "version"},
			}},
			// Argilla v1 (legacy) public info endpoint. Data layer (/api/v1/me)
			// is auth-gated; default key argilla.apikey is the misconfig class
			// (intel only, not exercised).
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
		// DefaultPorts widened 2026-07-04 (cat-label-studio): the port-agnostic
		// survey pipeline confirmed 49 live LS hosts on non-canonical ports the
		// original {8080,8081,80,443,8000} set missed. Observed winning-port tail:
		// 8085(10) 8090(9) 8888(5) 9090(5) 18080(4) 9001(3) 9000(2) 8443(1).
		DefaultPorts: []int{8080, 8081, 80, 443, 8000, 8085, 8090, 8888, 9090, 18080, 9001, 9000, 8443},
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
			// Modern v1.x /version — the -os- infix (label-studio-os-package)
			// replaced the legacy label-studio-backend slug. Field-validated
			// 2026-07-04 (cat-label-studio): /version is UNAUTHENTICATED and
			// leaks exact release, git commit, and outdated flag on v1.22/1.23.
			// Anchored: path + 200 + json_field release + unique v1.x marker.
			{Path: "/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "release"},
				{Type: "body_contains", Value: "label-studio-os-package"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "CVAT",
		DefaultPorts: []int{8080, 8081, 80, 443},
		Probes: []Probe{
			// Anti-IAP-FP (reference_aimap_cvat_iap_fp): a GCP IAP catch-all
			// returns HTML 200, not the application/vnd.cvat+json object. Require
			// the JSON version field AND the full product name so a bare 200 with
			// "cvat" anywhere in HTML cannot match.
			// KNOWN GAP (2026-05-31): CVAT uses DRF AcceptHeaderVersioning, so
			// /api/server/about needs an Accept: application/vnd.cvat+json request
			// header to return this JSON; aimap's Probe has no request-header field,
			// so this fingerprint will NOT fire live until that support is added.
			// The survey verification probe (data/datalabel-probe.py) covers CVAT.
			{Path: "/api/server/about", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "Computer Vision Annotation Tool"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Doccano",
		DefaultPorts: []int{8000, 3000, 80, 443},
		Probes: []Probe{
			// Identity anchor: doccano SPA root carries the "doccano" marker.
			// NOTE: /v1/health ({"status":"green"}) is deliberately NOT an identity
			// probe — it has no doccano marker and false-positived on Label Studio
			// hosts (the LS reverse proxy also serves a /v1/health with a "status"
			// field). The /v1/health liveness + /v1/projects auth-state checks live
			// in the survey verification probe (data/datalabel-probe.py), not here.
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
			// Anti-name-collision (Prodigy band/music/games share the title):
			// anchor on the auth-free /health JSON (status:alive) and the
			// prodigy.js bundle, never a bare "Prodigy" title.
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "alive"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "prodigy.js"},
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
			// X-Meilisearch-Version header is emitted on every response and is exclusive to
			// Meilisearch — fires even when a master key is set and /health body is gated.
			// Strengthened Cat-02 virgin 2026-06-04.
			{Path: "/version", Matches: []MatchCond{
				{Type: "header_contains", Field: "X-Meilisearch-Version", Value: ""},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Typesense",
		DefaultPorts: []int{8108, 80, 443},
		Probes: []Probe{
			// TIGHTENED Cat-02 virgin 2026-06-04: `{"ok":true}` alone is a generic health-shape
			// (the exact naked-body FP class the methodology warns against). Anchor to the
			// Server: Typesense/x header, which Typesense emits on every response.
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"ok":true`},
				{Type: "header_contains", Field: "Server", Value: "Typesense"},
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
			// /ApplicationStatus on the config server (19071) leaks the com.yahoo.vespa Java
			// namespace — exclusive to Vespa, matched 38 hosts on Shodan (bare-string dork).
			// Strengthened Cat-02 virgin 2026-06-04.
			{Path: "/ApplicationStatus", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "com.yahoo.vespa"},
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
			// Swagger UI at root — catches AUTH-PROTECTED LiteLLM deployments
			// where /health and /model/info correctly require keys (401/403)
			// but the OpenAPI docs leak at /. Observed 2026-06-07 on 3 hosts
			// in the 06-01 litellm-title corpus (18.236.39.160, 80.241.215.47:4000,
			// 89.167.90.181:4000). The title string "LiteLLM API - Swagger UI"
			// is LiteLLM-emitted (proxy_server.py) and product-unique enough.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LiteLLM API - Swagger UI"},
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
		DefaultPorts: []int{3000, 80, 443, 8080},
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
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "BentoML"},
			}},
		},
		Severity: "high",
	},
	{
		// Yatai: BentoML's K8s operator + admin dashboard (github.com/bentoml/Yatai).
		// Admin panel on :8080; /setup?token= is a first-admin-claim surface
		// (YATAI_INITIALIZATION_TOKEN, 16-char alphanum, exposed if Ingress unprotected).
		// /api/v1/api_tokens returns token list; /api/v1/deployments lists bento deployments.
		Name:         "Yatai (BentoML K8s Admin)",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/api/v1/api_tokens", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			{Path: "/api/v1/deployments", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "total"},
			}},
		},
		Severity: "critical",
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

	// ── Time-series databases (Cat-TSDB, 2026-07-28) ────────────────────
	// TimescaleDB deliberately excluded: it's a Postgres extension with no
	// bundled HTTP surface — no pre-auth fingerprint exists, confirmed via
	// Step 0 Shodan harvest (product:PostgreSQL 0% precision, hostname/port
	// dorks both null). Structural population-invisibility, not a gap.
	{
		Name: "InfluxDB",
		// X-Influxdb-Version response header on /ping is the single canonical
		// fingerprint — no other TSDB emits it. Version distribution field-
		// validated 2026-07-28 (n=50): 48/50 on the v1.x line (auth-enabled=
		// false factory default), only 2/50 on v2.x (mandatory onboarding
		// wizard closes off the unauth tail). 27/50 clustered on exactly
		// v1.6.4, 16/50 on v1.6.7~rc0 — template-propagation signature.
		DefaultPorts: []int{8086},
		Probes: []Probe{
			{Path: "/ping", Matches: []MatchCond{
				{Type: "status_code", Value: "204"},
				{Type: "header_contains", Field: "X-Influxdb-Version", Value: ""},
			}},
		},
		Severity: "high",
	},
	{
		Name: "VictoriaMetrics",
		// Root path serves the vmui web console with a distinctive title and
		// brand string. Two-condition conjunctive match (status + two body
		// substrings) per the naked-single-word lesson — "vmui" alone could
		// theoretically collide, "VictoriaMetrics" alone could appear in an
		// unrelated ops blog reflection; requiring both together is sound.
		DefaultPorts: []int{8428},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "vmui"},
				{Type: "body_contains", Value: "VictoriaMetrics"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "QuestDB",
		// /exec is the primary attack-surface endpoint (arbitrary SQL exec)
		// and doubles as the most reliable fingerprint: QuestDB's JSON
		// response envelope (query/columns/dataset/count) is distinctive
		// and doesn't collide with InfluxDB/TimescaleDB response shapes.
		// Secondary probe on web-console root for hosts that block /exec.
		DefaultPorts: []int{9000},
		Probes: []Probe{
			{Path: "/exec?query=SELECT+1", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "dataset"},
				{Type: "json_field", Field: "columns"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>QuestDB</title>"},
			}},
		},
		Severity: "high",
	},
	{
		Name: "M3DB Coordinator",
		// M3 Coordinator ships with zero auth subsystem in the config struct
		// (not merely off-by-default — no toggle exists at all). Namespace
		// enumeration doubles as fingerprint and finding: the registry.
		// namespaces JSON envelope is unique to M3, and a 200 here already
		// confirms unauth read access to cluster topology.
		DefaultPorts: []int{7201},
		Probes: []Probe{
			{Path: "/api/v1/services/m3db/namespace", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "registry"},
				{Type: "body_contains", Value: "namespaces"},
			}},
		},
		Severity: "high",
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

	// Galileo agent-control — runtime guardrails / policy engine for AI agents.
	// Port 8000, Next.js SPA. The /health endpoint returns {"status":"healthy","version":"0.1.0"}
	// which is shared with ZenML and Chatterbox TTS — anchor on root-path body text instead.
	// Zero auth on all endpoints by design (documented warning in README).
	// DefaultPorts NOTE: ZenML probes /health at 8000 with body_contains "status" — that loose
	// probe FP-fires here; the conjunctive root-path match below provides the discriminating signal.
	{
		Name:         "Galileo agent-control",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Runtime Guardrails for AI Agents"},
			}},
		},
		Severity: "high",
	},

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
		// Tabby (TabbyML) self-hosted AI code-completion server.
		// Two-probe identity:
		//   /v1/health returns HealthState JSON shape unauthenticated
		//   on every version: {"model","chat_model","device","webserver",...}.
		//   The "chat_model" + "webserver" field pair is Tabby-unique
		//   (no other AI service emits the two together at /v1/health).
		//   Anchored on json_field per Insight #6 marker discipline.
		//   /auth/signin (v0.11.0+) returns the login HTML with the
		//   "<title>Tabby" prefix; conjoined with status_code 200 to
		//   suppress 404-on-pre-v0.11.0 hosts (those have NO webserver
		//   so /v1/health is the only identity probe). Population port
		//   set derived from 2026-06-09 cohort (97 Shodan title hits):
		//   :9090 dominates (40/94), then :8000 (11), :443 (8), :80 (7),
		//   :9000 (6), :8080 (5), :9999 + :8010 + :12399 long tail.
		//   Squad-1 brief mistakenly fixated on :8080 — the real
		//   default is :9090 once webserver is enabled.
		Name:         "Tabby (TabbyML)",
		DefaultPorts: []int{9090, 8080, 8000, 443, 80, 9000, 9999, 8443},
		Probes: []Probe{
			{Path: "/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "chat_model"},
				{Type: "json_field", Field: "webserver"},
			}},
			{Path: "/auth/signin", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Tabby"},
				// FP-hardening 2026-06-09 (Lane-B): VPN-exit response-
				// rewriting layer was injecting "<title>Tabby" into
				// unrelated hosts' /auth/signin (22-byte stub bodies),
				// producing 66 FPs in the Cat-Tabby cohort. Real Tabby
				// is a Next.js SPA emitting webpack chunks; the mimicry
				// did not. Anchor on the Next.js webpack chunk path
				// (unique to real Tabby v0.11.0+ builds) and the Tabby-
				// application-route signin page chunk (even stricter).
				// Per Insight #6: never naked single-token body_contains.
				{Type: "body_contains", Value: "/_next/static/chunks/webpack-"},
				{Type: "body_contains", Value: "app/auth/signin/page-"},
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
		//
		// FP fix (2026-06-05, Cat-03): removed the /api/report 405 +
		// "method not allowed" probe. Gradio mounts a FastAPI catch-all that
		// returns 405 "Method Not Allowed" on any unmatched route, so that
		// probe matched every Gradio app — four "Whisper Playground" hosts
		// (15.235.9.143, 88.198.67.137, 34.47.31.176, 91.99.202.219:8000)
		// were mislabelled GPT Researcher. A bare 405 carries no
		// GPT-Researcher-specific signal, so it cannot be made sound; the
		// body-anchored "/" probe below is the only reliable identifier.
		Name:         "GPT Researcher",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gpt_researcher"},
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
		Name:         "OpenClaw",
		DefaultPorts: []int{18789, 443, 80},
		Probes: []Probe{
			// clawdbot-app is the React root element id embedded in the product HTML
			// (internal name; marketing name is "Openclaw" by vendor Molty).
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
		// Guardrails AI (guardrailsai.com) — the Guardrails CRUD API behind the
		// Hub playground. Identification only: the OpenAPI spec self-describes as
		// "Guardrails CRUD API" with the /guards CRUD surface. Anchors the exact
		// vendor description (not the generic "Guardrails API" title, which is too
		// weak) + the openapi json_field. Fires on any tier including the hardened
		// prod API (api.simlab.*) where the data paths are 401. Severity low: this
		// is service-presence, not exposure — the exposure FP below carries the risk.
		// Founding host: playground.api.guardrailsai.com, Cat-33 2026-06-23.
		Name:         "Guardrails AI API",
		DefaultPorts: []int{443, 8000, 8080},
		Probes: []Probe{
			{Path: "/api-docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "openapi"},
				{Type: "body_contains", Value: "Guardrails CRUD API"},
			}},
		},
		Severity: "low",
	},
	{
		// Guardrails AI playground — UNAUTH multi-tenant guard exposure. The
		// playground tier serves GET /guards/ without auth, returning every user's
		// guard objects keyed "playground-session-<provider>|<subject-id>"
		// (google-oauth2 / github / auth0). The OpenAPI spec declares
		// security:[ApiKeyAuth,BearerAuth] on this op — enforcement is just absent
		// (missing middleware), so the open shape IS the finding, not the service.
		// Conjunctive anchor: 200 + json_array + the vendor-unique session-key
		// scheme + the guard-object "validators" field, with a catch-all-negative
		// "<html" guard (LBot lesson, Insight #107/#108) so SPA/deception 200s that
		// echo HTML on any path can't trip it. "playground-session-" alone is
		// effectively un-FP-able but the guard keeps it sound at population scale.
		// Founding host: playground.api.guardrailsai.com/guards/ (1335 objects /
		// 992+ distinct subject IDs), Cat-33 2026-06-23.
		Name:         "Guardrails AI Playground (unauth guards)",
		DefaultPorts: []int{443, 8000, 8080},
		Probes: []Probe{
			{Path: "/guards/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
				{Type: "body_contains", Value: "playground-session-"},
				{Type: "body_contains", Value: "validators"},
				{Type: "body_not_contains", Value: "<html"},
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
	// AI stacks. Defender should hand off to -registry-recon.
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
			// anti-ZenTao (2026-06-05 Cat-03 FP): ZenTao's PHP router echoes the
			// requested path in its error page ("'api/tts/speakers' illegal ...
			// router.class.php") with status 200, so the bare "speaker" substring
			// matched 61.171.112.92:8000 (a ZenTao PM app). The real endpoint
			// returns a JSON speaker list, not an HTML error page.
			{Path: "/api/tts/speakers", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "speaker"},
				{Type: "body_not_contains", Value: "router.class.php"},
				{Type: "body_not_contains", Value: "<!doctype"},
				{Type: "header_not_contains", Field: "Set-Cookie", Value: "zentaosid"},
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
			// anti-ZenTao (2026-06-05 Cat-03 FP): same path-echo FP class as the
			// Coqui XTTS /api/tts/speakers probe — ZenTao reflects "/get_predefined_voices"
			// in a 200 error body, matching the bare "voice" substring. Real
			// endpoint returns JSON, not the PHP-router HTML error page.
			{Path: "/get_predefined_voices", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "voice"},
				{Type: "body_not_contains", Value: "router.class.php"},
				{Type: "body_not_contains", Value: "<!doctype"},
				{Type: "header_not_contains", Field: "Set-Cookie", Value: "zentaosid"},
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

	// ── Voice / Audio AI gap-fill (Cat voice-tts-conversational, tome
	//    reconciliation 2026-08-06) ──────────────────────────────────────
	// 33 fingerprints scaffolded from the tome voice-tts-conversational
	// corpus for platforms that had no aimap FP. All ship auth-off by
	// default (tome auth=None on every one). Discipline: no naked single-word
	// body_contains — every probe pins a structural build artifact (Gradio's
	// embedded gradio_config blob, a Swagger /docs shell, a distinctive
	// API operationId / model-id / SPA marker) plus the brand.
	//
	// The Gradio family (7860) is the dominant shape: the SPA embeds
	// window.gradio_config (a build artifact witness). Brand + gradio_config
	// is the same two-conjunct pattern the existing seed-vc/so-vits/RVC FPs
	// use and that fingerprints_voice_test.go blesses.

	// Applio — RVC fork, voice-cloning Gradio UI on the near-unique port 6969.
	// The existing RVC WebUI FP body-matches "Applio" but its DefaultPorts
	// omit 6969, so Applio deployments were being missed. Fraud class → high.
	{
		Name:         "Applio",
		DefaultPorts: []int{6969, 7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "Applio"},
			}},
		},
		Severity: "high",
	},

	// Bark (suno-ai / bark-gui) — Gradio TTS. "bark" alone is a common word;
	// anchor on gradio_config + the distinctive en_speaker_N history-prompt id.
	{
		Name:         "Bark TTS",
		DefaultPorts: []int{7860, 5000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "en_speaker_"},
			}},
		},
		Severity: "medium",
	},

	// Bert-VITS2 — Gradio TTS. Brand string is distinctive; gradio_config
	// kills the article/README brand-mention FP shape.
	{
		Name:         "Bert-VITS2",
		DefaultPorts: []int{7860, 5000, 6006, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "Bert-VITS2"},
			}},
		},
		Severity: "medium",
	},

	// Dia (Nari Labs) — Gradio TTS. "Dia" is far too generic alone; anchor on
	// gradio_config + the unique app title "Nari Text-to-Speech".
	{
		Name:         "Dia TTS",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "Nari Text-to-Speech"},
			}},
		},
		Severity: "medium",
	},

	// EmotiVoice (netease-youdao) — FastAPI OpenAI-compat TTS (:8000) + a
	// Streamlit demo (:8501). The openapi.json names the EmotiVoice-specific
	// SpeechRequest model; the Streamlit page pins the streamlit build assets.
	{
		Name:         "EmotiVoice",
		DefaultPorts: []int{8000, 8501, 80, 443},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "SpeechRequest"},
				{Type: "body_contains", Value: "/v1/audio/speech"},
				{Type: "body_contains", Value: "response_format"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "EmotiVoice"},
				{Type: "body_contains", Value: "streamlit"},
			}},
		},
		Severity: "medium",
	},

	// FunASR (Alibaba/ModelScope) — streaming ASR. Primary surface is
	// WSS :10095/:10096 (JSON handshake mode=offline|online|2pass, streams
	// PCM). aimap is HTTP-oriented and CANNOT confirm the WSS wire protocol —
	// those ports route to Censys / TLS-banner / active-handshake discovery.
	// The newer funasr-server exposes an HTTP FastAPI on :8000 (Swagger +
	// OpenAI-compat /v1/audio/transcriptions); we fingerprint that surface.
	{
		Name:         "FunASR",
		DefaultPorts: []int{8000, 10095, 10096, 80, 443},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "FunASR"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "high",
	},

	// GPT-SoVITS — few-shot voice cloning. Fraud class → high. The FastAPI
	// runtime (987x/9880) exposes /docs whose Swagger names the project-unique
	// set_gpt_weights / set_sovits_weights operations; the Gradio training UI
	// carries the brand + gradio_config. The existing RVC FP body-matches
	// "GPT-SoVITS" but its DefaultPorts omit the 987x range.
	{
		Name:         "GPT-SoVITS",
		DefaultPorts: []int{9880, 9872, 9873, 9874, 9871, 80, 443},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "set_gpt_weights"},
				{Type: "body_contains", Value: "set_sovits_weights"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "GPT-SoVITS"},
			}},
		},
		Severity: "high",
	},

	// Higgs Audio (bosonai) — OpenAI-compat TTS. /v1/models returns the
	// higgs-audio model id owned_by bosonai — two co-occurring anchors that
	// generic OpenAI-compat servers never both emit.
	{
		Name:         "Higgs Audio",
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "higgs-audio"},
				{Type: "body_contains", Value: "bosonai"},
			}},
		},
		Severity: "medium",
	},

	// IndexTTS (bilibili) — Gradio TTS.
	{
		Name:         "IndexTTS",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "IndexTTS"},
			}},
		},
		Severity: "medium",
	},

	// MaryTTS — legacy Java TTS server on :59125 (SHARED with mimic3, which
	// the conjunctive brand markers disambiguate). Plain public TTS, no
	// cloning / PII → low. Anchors on the unique MARY Web Client + the
	// maryWebClient DOM id.
	{
		Name:         "MaryTTS",
		DefaultPorts: []int{59125, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "MARY Web Client"},
				{Type: "body_contains", Value: "maryWebClient"},
			}},
		},
		Severity: "low",
	},

	// MegaTTS3 (ByteDance) — Gradio TTS.
	{
		Name:         "MegaTTS3",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "MegaTTS3"},
			}},
		},
		Severity: "medium",
	},

	// MeloTTS (MyShell) — FastAPI. /docs Swagger pins the MeloTTS-Docker-API
	// /convert/tts route which is distinctive to this server wrapper.
	{
		Name:         "MeloTTS",
		DefaultPorts: []int{8888, 8000, 80, 443},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "MeloTTS"},
				{Type: "body_contains", Value: "convert/tts"},
			}},
		},
		Severity: "medium",
	},

	// MetaVoice (metavoice-src) — voice cloning, FastAPI on the near-unique
	// port 58003. Fraud class → high. tome markers are weak (generic FastAPI
	// title); the anchor is port 58003 + brand string in the openapi schema.
	{
		Name:         "MetaVoice",
		DefaultPorts: []int{58003, 7861, 80, 443},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "MetaVoice"},
				{Type: "body_contains", Value: "/tts"},
			}},
		},
		Severity: "high",
	},

	// Mimic 3 (Mycroft) — Hypercorn TTS on :59125 (SHARED with MaryTTS).
	// Plain public TTS → low. Anchors on the exact server tagline + Mycroft.
	{
		Name:         "Mimic 3",
		DefaultPorts: []int{59125, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Mimic 3 text to speech server"},
				{Type: "body_contains", Value: "Mycroft"},
			}},
		},
		Severity: "low",
	},

	// NVIDIA Riva — enterprise ASR/TTS/NMT. Primary surface is gRPC :50051
	// (nvidia.riva.* services, content-type application/grpc) which aimap
	// CANNOT confirm over HTTP — that port routes to Censys / gRPC-reflection
	// / active-handshake discovery. Best-effort HTTP probe: the optional
	// metrics port (9000/9001, Triton backend) exposes Prometheus nv_inference_*
	// counters. When present, that's a structural Riva/Triton witness.
	{
		Name:         "NVIDIA Riva",
		DefaultPorts: []int{9000, 9001, 50051, 80, 443},
		Probes: []Probe{
			{Path: "/metrics", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "nv_inference_request"},
			}},
		},
		Severity: "high",
	},

	// OpenTTS (synesthesiam) — Hypercorn TTS aggregator on :5500. Plain
	// public TTS → low. Anchors on the exact project tagline.
	{
		Name:         "OpenTTS",
		DefaultPorts: []int{5500, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenTTS"},
				{Type: "body_contains", Value: "Unifies access to multiple open source"},
			}},
		},
		Severity: "low",
	},

	// OpenVoiceOS (OVOS) — open assistant stack. The messagebus on :8181 is a
	// WebSocket; a plain HTTP GET /core returns 426 Upgrade Required from
	// TornadoServer. /core is the OVOS-distinctive path; status 426 + the
	// TornadoServer header + the /core path together form the anchor. The
	// bus itself is a wire protocol and is not otherwise HTTP-probeable.
	{
		Name:         "OpenVoiceOS",
		DefaultPorts: []int{8181, 18181, 80, 443},
		Probes: []Probe{
			{Path: "/core", Matches: []MatchCond{
				{Type: "status_code", Value: "426"},
				{Type: "body_contains", Value: "426 Upgrade Required"},
				{Type: "header_contains", Field: "Server", Value: "TornadoServer"},
			}},
		},
		Severity: "medium",
	},

	// Parler-TTS (HuggingFace) — Gradio TTS. Anchor on gradio_config + the
	// parler_tts module / model id.
	{
		Name:         "Parler-TTS",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "parler-tts-mini"},
			}},
		},
		Severity: "medium",
	},

	// Rhasspy — offline voice assistant (Hypercorn). Exposes profile/config +
	// STT/TTS/intent surfaces. Anchors on the distinctive UI section labels.
	{
		Name:         "Rhasspy",
		DefaultPorts: []int{12101, 12183, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Rhasspy"},
				{Type: "body_contains", Value: "Wake Word"},
				{Type: "body_contains", Value: "Intent Recognition"},
			}},
		},
		Severity: "medium",
	},

	// Seed-VC — zero-shot voice conversion, Gradio. Fraud class → high.
	{
		Name:         "Seed-VC",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "Seed-VC"},
			}},
		},
		Severity: "high",
	},

	// sherpa-onnx (k2-fsa) — ASR/TTS. Primary streaming surface is a raw
	// WebSocket (sherpa-onnx-*-websocket-server) which aimap cannot confirm;
	// the Python demo server DOES serve an HTTP web UI (streaming_record.html)
	// whose page carries the "Next-gen Kaldi demo" title + repo slug. We
	// fingerprint that HTTP surface.
	{
		Name:         "sherpa-onnx",
		DefaultPorts: []int{6006, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Next-gen Kaldi demo"},
				{Type: "body_contains", Value: "sherpa-onnx"},
			}},
		},
		Severity: "high",
	},

	// so-vits-svc — singing/voice conversion, Gradio. Fraud class → high.
	{
		Name:         "so-vits-svc",
		DefaultPorts: []int{7860, 5000, 6842, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "so-vits"},
			}},
		},
		Severity: "high",
	},

	// Spark-TTS (SparkAudio) — Gradio TTS with voice creation.
	{
		Name:         "Spark-TTS",
		DefaultPorts: []int{7860, 8000, 8001, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "Spark-TTS"},
			}},
		},
		Severity: "medium",
	},

	// Tortoise TTS (ai-voice-cloning fork) — Gradio voice cloning. "tortoise"
	// alone is a common word; anchor on gradio_config + the fork's unique
	// "ai-voice-cloning" app title. Fraud class → high.
	{
		Name:         "Tortoise TTS",
		DefaultPorts: []int{7860, 5000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "ai-voice-cloning"},
			}},
		},
		Severity: "high",
	},

	// Ultravox (fixie-ai) — real-time voice-agent platform. /api/calls exposes
	// call objects (joinUrl, callId, transcripts, recordings) = PII surface
	// when unauth. Gated instances (X-API-Key) will not 200 — surface open,
	// access not exercised. Fallback: the OpenAI-compat /v1/models names the
	// ultravox model. High.
	{
		Name:         "Ultravox",
		DefaultPorts: []int{8000, 8080, 80, 443},
		Probes: []Probe{
			{Path: "/api/calls", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "joinUrl"},
				{Type: "body_contains", Value: "callId"},
			}},
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ultravox"},
				{Type: "body_contains", Value: "object"},
			}},
		},
		Severity: "high",
	},

	// VALL-E-X (Plachtaa) — zero-shot voice cloning, Gradio. Fraud → high.
	{
		Name:         "VALL-E-X",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "VALL-E"},
			}},
		},
		Severity: "high",
	},

	// Vosk — offline STT. PURE WIRE: a raw WebSocket on :2700 with NO path
	// routing and NO HTTP surface. aimap is HTTP-oriented and cannot confirm
	// the ws protocol; discovery routes to Censys / TLS-banner / active-ws
	// handshake. The probe below is a best-effort placeholder that will NOT
	// fire on a bare HTTP GET (correct — there is no HTTP body) and cannot
	// false-positive; the Fingerprint exists for DefaultPorts + port-class
	// registration and honest documentation of the wire-only limitation.
	{
		Name:         "Vosk",
		DefaultPorts: []int{2700},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "\"partial\""},
				{Type: "body_contains", Value: "\"result\""},
			}},
		},
		Severity: "high",
	},

	// WeNet — E2E ASR. Port :10086 multiplexes WebSocket (websocket_server_main),
	// gRPC (grpc_server_main) and HTTP (http_server_main). aimap can only
	// confirm the http_server_main mode, which serves the bundled web client
	// (runtime/.../web/templates/index.html). The ws/gRPC modes are invisible
	// to an HTTP sweep and route to Censys / banner / active-handshake.
	{
		Name:         "WeNet",
		DefaultPorts: []int{10086, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "wenet"},
				{Type: "body_contains", Value: "websocket"},
			}},
		},
		Severity: "high",
	},

	// whisper_streaming (ufal) — real-time ASR. PURE WIRE: a raw TCP line
	// protocol on :43007/:43001 (client streams 16kHz PCM, server emits
	// "beg_ts end_ts text" lines). NOT HTTP — aimap cannot confirm it; the
	// port routes to Censys / banner / active-socket handshake. Best-effort
	// placeholder probe (will not fire over HTTP, cannot false-positive).
	{
		Name:         "whisper_streaming",
		DefaultPorts: []int{43007, 43001},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "beg_ts"},
				{Type: "body_contains", Value: "end_ts"},
			}},
		},
		Severity: "high",
	},

	// WhisperFusion (Collabora) — real-time ASR+LLM+TTS. Serves an HTTP Web
	// GUI on :8000 whose page names WhisperFusion + WhisperSpeech. The STT
	// backend (WhisperLive ws) and TensorRT-LLM bridge are separate wire
	// surfaces. Live-audio PII → high.
	{
		Name:         "WhisperFusion",
		DefaultPorts: []int{8000, 6006, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "WhisperFusion"},
				{Type: "body_contains", Value: "WhisperSpeech"},
			}},
		},
		Severity: "high",
	},

	// Willow Inference Server — self-hosted ASR/TTS for the Willow ESP32
	// assistant, HTTPS on :19000. /api/docs is the Swagger UI; the page title
	// carries the product name. Live-audio + assistant control → high.
	{
		Name:         "Willow Inference Server",
		DefaultPorts: []int{19000, 80, 443},
		Probes: []Probe{
			{Path: "/api/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Willow Inference Server"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "high",
	},

	// Wyoming protocol — Home Assistant voice satellite/service transport.
	// PURE WIRE: newline-delimited JSON events over raw TCP across the
	// :10200-10700 range (10200 tts, 10300 asr, 10400 wake, 10500 intent,
	// 10700 satellite). NOT HTTP — aimap cannot confirm it; ports route to
	// Censys / banner / active-JSONL handshake. Best-effort placeholder probe
	// (will not fire over HTTP, cannot false-positive).
	{
		Name:         "Wyoming Protocol",
		DefaultPorts: []int{10200, 10300, 10400, 10500, 10700},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "\"synthesize\""},
				{Type: "body_contains", Value: "\"transcribe\""},
			}},
		},
		Severity: "medium",
	},

	// Zonos (Zyphra) — Gradio TTS.
	{
		Name:         "Zonos",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "gradio_config"},
				{Type: "body_contains", Value: "Zonos"},
			}},
		},
		Severity: "medium",
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
				// anti-CheckRef (2026-06-05 Cat-03 FP): the scholarly-reference
				// app CheckRef returns {"status":"ok","services":{...},"apis":
				// {"crossref":...,"openalex":...}} on /api/v1/health and matched
				// the bare "status:ok" anchor. crossref/openalex never appear in Lunary.
				{Type: "body_not_contains", Value: "crossref"},
				{Type: "body_not_contains", Value: "openalex"},
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
		// Training-UI ports added 2026-06-05 (field-observed LlamaBoard on
		// 10000/10004/10007/6006 in the Cat-04 survey).
		DefaultPorts: []int{7860, 8000, 80, 443, 10000, 10004, 10007, 6006},
		Probes: []Probe{
			// PRIMARY (2026-06-05): LlamaBoard webui. The Gradio 5.x API-info
			// endpoint lists named_endpoints including /get_model_info — a
			// LLaMA-Factory-unique webui callback. This is title- and
			// version-stable: it fires on "LLaMA Board"-branded hosts (which
			// carry zero "LLaMA Factory" string) and it survives aimap's 1 MB
			// body cap, where the / probe below TRUNCATES — on 1.5 MB board
			// pages the brand string is buried >1 MB deep in window.gradio_config.
			// Field-verified on 121.46.230.100:10004, 139.224.134.227:6006.
			{Path: "/gradio_api/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "get_model_info"},
			}},
			// Gradio WebUI probe — title contains brand string (lighter builds
			// where the marker lands inside the 1 MB window).
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LLaMA Factory"},
				{Type: "body_contains", Value: "gradio"},
			}},
			// FastAPI inference server probe — api.py (separate process from
			// the webui; /v1/* 404s on a webui-only deployment).
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

	// ── Cat-04 training / fine-tuning (2026-06-05) ────────────────────────────
	// OpenLLM (bentoml/OpenLLM) — `openllm serve` shells `bentoml serve`, so the
	// runtime IS a BentoML HTTP server (port 3000) serving an OpenAI-compat /v1
	// surface. aimap already IDs the BentoML control plane separately; this FP
	// flags the LLM-serving variant. Discriminator: the BentoML schema doc
	// (/docs.json, BentoML-specific path — vLLM serves /openapi.json instead)
	// that ALSO lists the OpenAI chat route. Auth NONE by default. Inherits
	// BentoML CVE-2025-27520 (CVSS 9.8 unauth RCE) / CVE-2025-32375 (runner
	// pickle RCE) — open inference escalates to host RCE on unpatched versions.
	{
		Name:         "OpenLLM",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/docs.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "openapi"},
				{Type: "body_contains", Value: "/v1/chat/completions"},
			}},
		},
		Severity: "high",
	},

	// Determined AI (determined-ai/determined; HPE MLDE) — distributed training
	// platform master on 8080 (plaintext) / 8443 (TLS). Exactly 3 unauth RPCs:
	// Login, GetMaster, GetTelemetry (source master/internal/grpcutil/auth.go).
	// GET /api/v1/master returns camelCase JSON with required clusterId +
	// masterId + version — unauth metadata leak by design. Everything sensitive
	// (experiments, checkpoints, training data, command/shell submission =
	// arbitrary container exec on cluster GPUs) sits behind the Bearer gate, so
	// auth tier A*. Real takeover path is a credential-default chain: OSS ships
	// a built-in `determined` admin with an EMPTY password — active login, NOT
	// probed here. 0 CVEs as of 2026-06.
	{
		Name:         "Determined AI",
		DefaultPorts: []int{8080, 8443, 80, 443},
		Probes: []Probe{
			{Path: "/api/v1/master", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "clusterId"},
				{Type: "json_field", Field: "masterId"},
			}},
		},
		Severity: "medium",
	},

	// Feast (feast-dev/feast) — feature store. Feature server on 6566 (REST +
	// gRPC), UI/registry on 8888. Auth NONE by default (auth fires only when
	// auth_config.type is set). The high-signal route (/get-online-features) is
	// POST-only = Shodan-dark; aimap confirms via GET signals. The route name
	// "get-online-features" is Feast-unique: it appears in the FastAPI
	// /openapi.json route list, and a GET to the path returns 405 (route exists,
	// POST-only) where a non-Feast server 404s. CVE-2026-23536 (CVSS 7.5) —
	// unauth path traversal / arbitrary file read on the feature server; chains
	// feature-value read -> feature_store.yaml cloud-cred theft.
	{
		Name:         "Feast",
		DefaultPorts: []int{6566, 8888, 8000},
		Probes: []Probe{
			// FastAPI schema lists the Feast-unique route.
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "get-online-features"},
			}},
			// Fallback when docs are disabled: the POST-only route exists (405),
			// not 404. Allow header confirms it is a real method mismatch.
			{Path: "/get-online-features", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "header_contains", Field: "Allow", Value: "POST"},
			}},
		},
		Severity: "high",
	},

	// Lightning App (Lightning-AI; legacy `lightning run app` framework) —
	// FastAPI/uvicorn on 7501 (APP_SERVER_PORT). DEPRECATED and removed from
	// current pytorch-lightning main — shrinking legacy population (~3 Shodan
	// hits). NOTE: the pytorch-lightning library itself has NO server; only the
	// app framework does. /healthz returns a generic {"status":"ok"}, so anchor
	// on the unforgeable session-header error literal (source app/core/api.go)
	// or the Lightning-unique OpenAPI tag. Session headers are a coordination
	// check, not authentication.
	{
		Name:         "Lightning App",
		DefaultPorts: []int{7501},
		Probes: []Probe{
			{Path: "/api/v1/spec", Matches: []MatchCond{
				{Type: "status_code", Value: "500"},
				{Type: "body_contains", Value: "Missing X-Lightning-Session-UUID header"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "app_client_command"},
			}},
		},
		Severity: "low",
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

	// ── AI Gateways (Cat-32, added v1.9.46) ─────────────────────
	{
		// Kong Admin API (:8001) — unauth by default in docker-compose
		// deployments (CVE-2020-11710, CVSS 9.8). The Admin API is the RCE
		// surface: unauthenticated POST /services + POST /plugins with the
		// pre-function plugin executes arbitrary Lua code server-side.
		//
		// Fingerprint derived from primary-source Shodan host dossiers
		// (2026-06-01, 5-host sample): Server header is "kong/<version>"
		// on every instance; X-Kong-Admin-Latency is present on every
		// Admin API response and is unique to Kong.
		// Body probe: GET / returns full JSON config including
		// {"tagline":"Welcome to Kong","version":"x.y.z"}.
		Name:         "Kong Admin API",
		DefaultPorts: []int{8001, 8444},
		Probes: []Probe{
			// Primary: JSON root with tagline + version (definitive)
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"tagline":"Welcome to Kong"`},
				{Type: "json_field", Field: "version"},
			}},
			// Fallback: header-level detection when body is not indexed
			// X-Kong-Admin-Latency is emitted exclusively by the Admin API.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "server", Value: "kong/"},
				{Type: "header_contains", Field: "x-kong-admin-latency", Value: ""},
			}},
			// Services endpoint — confirms Admin API access (auth-state probe)
			{Path: "/services", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "json_field", Field: "next"},
			}},
		},
		Severity: "critical",
	},
	{
		// Bifrost AI Gateway (maximhq/bifrost) — Go LLM gateway.
		// Auth bypass on root path (GitHub Issue #937): GET / returns 200
		// even when basic auth is configured — the auth middleware only
		// protects paths other than "/".
		//
		// Fingerprint from dossier (2026-06-01): Server = "fasthttp" on
		// all 5 instances; title "Bifrost" on auth-bypassed instances;
		// Content-Length 5690 or 2078 consistent across installs; security
		// headers (X-Frame-Options: DENY, Content-Security-Policy:
		// frame-ancestors 'none') present uniformly.
		// Body contains "getbifrost.ai" (footer link — confirmed via
		// 82-hit Shodan dork).
		Name:         "Bifrost AI Gateway",
		DefaultPorts: []int{8080, 443, 80},
		Probes: []Probe{
			// Primary: footer domain link present in body
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "getbifrost.ai"},
				{Type: "header_contains", Field: "server", Value: "fasthttp"},
			}},
			// Fallback: title when body is rendered / cached
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Bifrost</title>"},
				{Type: "header_contains", Field: "server", Value: "fasthttp"},
			}},
		},
		Severity: "medium",
	},
	{
		// Portkey OSS Gateway (portkey-ai/gateway) — TypeScript LLM proxy.
		// Auth-on-default via x-portkey-api-key header, but the health
		// endpoint at / is unauthenticated and returns a plain-text string.
		// CVE-2025-66405: SSRF via x-portkey-custom-host header (< v1.14.0,
		// CVSS 6.9) allows server-side request forgery to internal services.
		//
		// 0 public instances found in Shodan (2026-06-01) — Portkey is
		// primarily a hosted SaaS; self-hosted instances appear to be behind
		// reverse proxies or VPNs. Fingerprint kept for lab/internal use.
		Name:         "Portkey Gateway",
		DefaultPorts: []int{8787, 443, 80},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "AI Gateway says hey"},
			}},
		},
		Severity: "medium",
	},
	{
		// Envoy Admin Interface (:9901) — Envoy proxy (and Envoy AI Gateway)
		// admin endpoint. Exposes full configuration including upstream
		// cluster credentials via /config_dump. Unauthenticated by default;
		// must be firewalled to loopback.
		//
		// Fingerprint from dossier (2026-06-01, 5-host sample): Server
		// header is "envoy" (lowercase) on all instances; title "Envoy Admin"
		// consistent; lowercase HTTP headers (h2-style) even on HTTP/1.1.
		// /config_dump is the finding endpoint — returns full JSON config
		// including plaintext API keys, JWTs, and auth tokens for all
		// configured upstream clusters.
		Name:         "Envoy Admin",
		DefaultPorts: []int{9901, 15000},
		Probes: []Probe{
			// Primary: admin root with title and server header
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Envoy Admin"},
				{Type: "header_contains", Field: "server", Value: "envoy"},
			}},
			// config_dump: the finding — accessible = all upstream credentials exposed
			{Path: "/config_dump", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "configs"},
				{Type: "header_contains", Field: "server", Value: "envoy"},
			}},
		},
		Severity: "critical",
	},

	// ── LLM Orchestration platforms (added v1.9.47) ───────────────────────
	// 11 platforms that were previously undetected. All probes conjunctive
	// (status_code + platform-specific body/json marker minimum). Anti-FP
	// discipline applied throughout; see inline comments for FP rationale.

	{
		// Langflow — LangChain visual agent builder. Default port 7860 (Gradio/
		// uvicorn).
		//
		// FALSE-POSITIVE HARDENING (Cat-Langflow survey 2026-06-18/19):
		// http.title:"Langflow" returns ~54k Shodan hits that are ~100% a
		// coordinated SCANNER-POISONING DECEPTION FLEET ("LBot"), NOT Langflow:
		//   - Catch-all 200 on EVERY path, including nonsense /api/v1 paths, with
		//     a ~135KB canned HTML page titled "LBot". That HTML contains the
		//     substrings "chat", "db", and "status", so the old health_check
		//     triple OVER-MATCHED the fleet on a non-JSON catch-all page.
		//   - /api/v1/version returns a Gitea-shaped bait JSON:
		//     {"version":"10.0.1+gitea-1.22.0",...} with NO "package" key and
		//     NO "langflow" substring anywhere (it stuffs Gitea/TP-Link/JWT bait
		//     for many scanners at once, but never fakes Langflow's own marker).
		// Discriminator: REAL Langflow's GET /api/v1/version returns a JSON body
		// that contains the vendor-unique pair "package":"Langflow". The fleet
		// never fakes this pair. This is the only robust live signal.
		//
		// GUARD: any host that returns 200 on a nonsense /api/v1 path is a
		// catch-all responder and MUST be excluded — the primary probe below is
		// anchored so a catch-all 200 alone cannot satisfy it (it requires a
		// parseable JSON body with a "package" key AND the "langflow" substring
		// AND the absence of the fleet's "gitea" version string).
		//
		// DO NOT match on http.title:"Langflow" — see the FP ratio above.
		Name:         "Langflow",
		DefaultPorts: []int{7860, 80, 443},
		Probes: []Probe{
			// PRIMARY — vendor-unique. GET /api/v1/version must parse as JSON,
			// carry the "package" key, contain the "langflow" substring, and NOT
			// carry the LBot fleet's "gitea" version string. All four conditions
			// are conjunctive, so the fleet's Gitea-shaped bait JSON (no package
			// key, no "langflow", "...gitea-1.22.0" version) cannot fire this.
			{Path: "/api/v1/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "package"},
				{Type: "body_contains", Value: "langflow"},
				{Type: "body_not_contains", Value: "gitea"},
			}},
			// SECONDARY (confirm-only, never sole). The {status, chat, db} triple
			// is Langflow's health_check shape, but those three words also appear
			// as plain substrings inside the LBot fleet's 135KB canned HTML, so
			// this probe is hardened to require a parseable JSON object (real
			// health_check is a small JSON body, the fleet page is HTML) and to
			// reject the fleet's "gitea"/"LBot" tells. Use only to corroborate a
			// PRIMARY hit, not to label a host on its own.
			{Path: "/api/v1/health_check", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "chat"},
				{Type: "body_contains", Value: "db"},
				{Type: "body_not_contains", Value: "gitea"},
				{Type: "body_not_contains", Value: "lbot"},
			}},
			// SECONDARY (confirm-only). /api/v1/config carries langflow_version on
			// real instances; the fleet's catch-all returns its Gitea/JWT bait, so
			// guard against the "gitea" tell here too.
			{Path: "/api/v1/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "langflow_version"},
				{Type: "body_not_contains", Value: "gitea"},
			}},
		},
		Severity: "high",
	},
	{
		// LibreChat — open-source multi-LLM chat platform. Default port 3080.
		// GET /api/config returns registration/social-login config unauth.
		// The {registration, socialLogins} pair is LibreChat-specific — not
		// present in any other chat-platform /api/config shape.
		Name:         "LibreChat",
		DefaultPorts: []int{3080, 3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "registration"},
				{Type: "body_contains", Value: "socialLogins"},
			}},
		},
		Severity: "high",
	},
	{
		// LobeChat — modern LLM chat UI. Default port 3210. Two probe
		// alternates covering the global-config API and the HTML root.
		Name:         "LobeChat",
		DefaultPorts: []int{3210, 3000, 80, 443},
		Probes: []Probe{
			// /api/config/global returns oAuthSSOProviders in the config blob // VERIFY
			{Path: "/api/config/global", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "oAuthSSOProviders"},
			}},
			// HTML root — dual brand markers (title + asset path) // VERIFY second marker
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "LobeChat"},
				{Type: "body_contains", Value: "lobe"},
			}},
		},
		Severity: "medium",
	},
	{
		// big-AGI — open-source GPT-4 UI. Default port 3000.
		// tRPC backend.listCapabilities endpoint exposes model/capability list.
		// The {capabilities, llms} pair is big-AGI-specific. // VERIFY
		Name:         "big-AGI",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/trpc/backend.listCapabilities?batch=1&input={}", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "capabilities"},
				{Type: "body_contains", Value: "llms"},
			}},
		},
		Severity: "high", // VERIFY against live instance
	},
	{
		// FastGPT — RAG+knowledge-base LLM platform (Sealos/labring). Default
		// port 3000. Two probes: (A) presence-gated data-layer 401 with the
		// FastGPT-specific "unAuthorization" token; (B) login page identity anchor.
		Name:         "FastGPT",
		DefaultPorts: []int{3000, 443},
		Probes: []Probe{
			// Auth-gated data-layer probe — present-gated (401 confirms identity)
			{Path: "/api/v1/core/dataset/list", Matches: []MatchCond{
				{Type: "status_code", Value: "401"},
				{Type: "body_contains", Value: "unAuthorization"},
			}},
			// Login page dual-brand anchor
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "fastgpt"},
				{Type: "body_contains", Value: "FastGPT"},
			}},
		},
		Severity: "high",
	},
	{
		// Coze Studio — ByteDance open-source agent builder. Default port 8888.
		// Root page carries both the display name ("Coze Studio") and the
		// internal JS bundle slug ("coze-studio") — the pair is distinctive.
		Name:         "Coze Studio",
		DefaultPorts: []int{8888, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Coze Studio"},
				{Type: "body_contains", Value: "coze-studio"},
			}},
		},
		Severity: "high",
	},
	{
		// BISHENG — DataElem enterprise document-intelligence platform.
		// Default ports: 3001 (frontend), 7860 (backend Gradio/FastAPI).
		// Two probes: root HTML (brand + vendor slug) and /docs openapi.
		Name:         "BISHENG",
		DefaultPorts: []int{3001, 7860, 443},
		Probes: []Probe{
			// Root SPA — brand name + DataElem vendor slug // VERIFY title-case
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "bisheng"},
				{Type: "body_contains", Value: "dataelement"},
			}},
			// /docs OpenAPI spec on the backend port
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "openapi"},
				{Type: "body_contains", Value: "bisheng"},
			}},
		},
		Severity: "high",
	},
	{
		// Chainlit — Python LLM app framework (FRAMEWORK: title is dev-set,
		// NEVER match on <title>). Two structural probes: /auth/config
		// (always served, contains requireLogin/passwordAuth) and the S3 CDN
		// asset path that is hardcoded in every Chainlit deployment.
		Name:         "Chainlit",
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			// Auth-config endpoint — always present, contains auth-state flags
			{Path: "/auth/config", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "requireLogin"},
				{Type: "body_contains", Value: "passwordAuth"},
			}},
			// Hardcoded CDN asset path in every Chainlit bundle
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "chainlit-cloud.s3.eu-west-3.amazonaws.com"},
			}},
		},
		Severity: "high",
	},
	{
		// Cheshire Cat — Italian OSS LLM framework. Default port 1865
		// (the "cat port" — near-unique). CRITICAL: unauth /plugins/upload
		// accepts arbitrary plugin ZIPs = unauthenticated code execution on
		// the server. Two probes: OpenAPI spec title and Swagger docs body.
		Name:         "Cheshire Cat",
		DefaultPorts: []int{1865, 80, 443},
		Probes: []Probe{
			// OpenAPI title confirms identity // VERIFY exact OpenAPI title
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Cheshire Cat"},
			}},
			// /docs Swagger page carries the slug
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "cheshire-cat"},
			}},
		},
		Severity: "critical",
	},
	{
		// Khoj — open-source personal AI assistant. Default port 42110
		// (Khoj-exclusive). Anonymous mode is the default. Two probes:
		// Django admin panel with khoj marker; root page brand.
		Name:         "Khoj",
		DefaultPorts: []int{42110, 80, 443},
		Probes: []Probe{
			// Django admin page — Django administration + khoj marker // VERIFY khoj marker on admin page
			{Path: "/server/admin/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Django administration"},
				{Type: "body_contains", Value: "khoj"},
			}},
			// Root page carries brand string
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "khoj"},
			}},
		},
		Severity: "high",
	},
	{
		// h2oGPT — H2O.ai open-source LLM chat + RAG. Default ports 7860
		// (Gradio), 5000/5001 (OpenAI-compat API). Two probes: Gradio OpenAPI
		// spec with h2oGPT-unique function name; OpenAI-compat /models endpoint.
		Name:         "h2oGPT",
		DefaultPorts: []int{7860, 5000, 5001},
		Probes: []Probe{
			// Gradio OpenAPI spec contains h2oGPT-specific function name
			{Path: "/gradio_api/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "submit_nochat_plain_api"},
			}},
			// OpenAI-compat /models endpoint
			// anti-KoboldCpp (2026-06-05 Cat-03 FP): KoboldCpp serves the same
			// /openai_api/v1/models path with a "data" array, so 108.210.175.159:5001
			// (a real KoboldCpp) was mislabelled h2oGPT. KoboldCpp tags every model
			// with owned_by:"koboldcpp" and an id prefixed "koboldcpp/".
			{Path: "/openai_api/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_not_contains", Value: "koboldcpp"},
			}},
		},
		Severity: "medium",
	},
	{
		// Sluice — AI-generated email guardrails SaaS. Sits between AI agents
		// and recipients, scans outbound LLM-drafted email for PII / tone /
		// prompt-injection-echo / hallucination / policy violations / etc.
		// before delivery. Single-VM Docker Compose (Haraka MTA + Next.js +
		// nginx) on Hetzner Helsinki. Opens a new  subcategory:
		// AI-Email-Guardrails (siblings: AegisAI, Prompt Security email
		// connectors, BeeSafe AI, Salus). Hardened auth-on-default posture.
		// Operator: sluice.email, registered 2026-03-11 via Ascio DK.
		// Probe anchors: brand <title>Sluice AND meta description
		// "AI email safety layer" (brand alone is too generic — sluice gate,
		// sluice box). The combined string identifies the SaaS instance.
		Name:         "Sluice",
		DefaultPorts: []int{443, 80, 587, 465},
		Probes: []Probe{
			// /login is the canonical landing for the Next.js app (root 307s
			// here for unauthed users). It renders the brand title + meta tag.
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Sluice"},
				{Type: "body_contains", Value: "AI email safety layer"},
			}},
		},
		Severity: "info",
	},
	// ── Cat-X ROS / Robotics (added 2026-06-09, Lane B scaffolding) ─────
	// Six fingerprints for the ROS ecosystem. Master brief:
	// AI-LLM-Infrastructure-OSINT/data/platform-intel/cat-x-ros-osint-2026-06-09.md
	// Academic anchor: Brown et al. 2018 (arxiv:1808.03322) — 100+ rosmasters
	// in a single IPv4 scan, 70%+ on .edu.  2026 survey is the 8-year
	// follow-up. Auth-on-default tier: ALL Tier-A (structural, no auth shipped).
	{
		// Foxglove bridge — self-hosted WebSocket bridge serving ROS/ROS2 topic
		// graphs to the Foxglove Studio visualization client. Default 8765.
		// Master brief §"aimap fingerprint debt" #5.
		//
		// Detection vector: WebSocket upgrade with subprotocol
		// `Sec-WebSocket-Protocol: foxglove.websocket.v1`. The aimap matcher
		// is GET-only over TCP — we cannot do a WS handshake here, so the
		// fingerprint observes the bare GET / response which most foxglove_bridge
		// builds answer with HTTP 426 Upgrade Required + a `Sec-WebSocket-Protocol`
		// hint header on advertised builds (this is the build-artifact-class
		// anchor per Insight #93 — the subprotocol identifier IS the build
		// artifact baked into the WebSocket handshake server). Conjunctive
		// per Insight #6: status_code + header_contains.
		//
		// Active confirmation (Lane C scope): WS upgrade and read serverInfo
		// frame from /listChannels — out of aimap's TCP-GET engine.
		Name:         "Foxglove bridge",
		DefaultPorts: []int{8765, 8766},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "426"},
				{Type: "header_contains", Field: "Sec-WebSocket-Protocol", Value: "foxglove.websocket.v1"},
			}},
		},
		Severity: "critical",
	},
	{
		// Jupyter-on-Jetson — Jupyter Notebook / Lab on NVIDIA Jetson boards
		// (JetBot, classroom kits, Isaac ROS Dev images). Master brief
		// §"aimap fingerprint debt" #6.
		//
		// Insight #40 watchpoint: JetPack 6 (2024) flipped Jupyter token-on-by-
		// default at first boot. Exposed cohort skews JetPack 4/5 + classroom
		// images that ship with token disabled. Conjunctive marker pairs Jupyter's
		// generic `Jupyter` body marker with a Jetson-identity marker (`JetBot` /
		// `L4T` / `jetson`) per Insight #6 — neither alone is sound at population
		// scale (Jupyter is common; `jetson` is a generic word).
		//
		// Three probes — one per Jetson-identity marker — to express the OR
		// disjunction within the matcher's conjunctive-Match[] engine. Each
		// fires independently; the first match wins.
		//
		// Operator attribution: reuse the existing aimap Docker-registry
		// classifier `classifyJetsonRepos` (enumerators.go:1373). When this
		// fingerprint fires on :8888 and :5000 also resolves to a Docker
		// registry on the same host, the classifier surfaces the Jetson stack
		// from /v2/_catalog without rebuilding here.
		Name:         "Jupyter-on-Jetson",
		DefaultPorts: []int{8888, 8889},
		Probes: []Probe{
			{Path: "/tree?", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Jupyter"},
				{Type: "body_contains", Value: "JetBot"},
			}},
			{Path: "/tree?", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Jupyter"},
				{Type: "body_contains", Value: "L4T"},
			}},
			{Path: "/tree?", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Jupyter"},
				{Type: "body_contains", Value: "jetson"},
			}},
		},
		Severity: "critical",
	},
	{
		// ROS2 DDS — Data Distribution Service (RTPS protocol). Master brief
		// §"aimap fingerprint debt" #3.
		//
		// DETECTION GAP: RTPS is binary-over-UDP. The aimap matcher engine is
		// HTTP/GET-over-TCP only. This fingerprint is REGISTERED as a placeholder
		// with no satisfiable HTTP probe so the platform appears in catalog
		// listings (-show-fingerprints output, future tome reconciliation), but
		// detection during a live scan must come from the UDP scanner side or
		// from the Lane C aztarna reuse path.
		//
		// Real-world detection requires:
		//   - UDP probe to 7400-7415 sending an RTPS PARTICIPANT_ANNOUNCE shape
		//   - Match on RTPS magic header `RTPS\x02\x01\x01\x01` at byte 0 of
		//     the response (build-artifact anchor per Insight #93 — protocol
		//     magic bytes are the build artifact baked into the wire format)
		//
		// Lane C reuse: Alias Robotics `aztarna` already implements DDS
		// PARTICIPANT_ANNOUNCE + DCPS enumeration. Do not rebuild — call out
		// to aztarna from the verify stage.
		//
		// Severity: high (LAN-only typical deployment; SROS2 opt-in rarely on).
		// Probes intentionally empty: the matcher will not fire this FP on
		// HTTP/HTTPS traffic, preventing FPs against arbitrary 7400-7415 web
		// servers. The fingerprint exists to keep the platform registered.
		Name:         "ROS2 DDS",
		DefaultPorts: []int{7400, 7401, 7410, 7411, 7412, 7413, 7414, 7415},
		Probes:       []Probe{},
		Severity:     "high",
	},
	{
		// rosbridge_server — ROS1 WebSocket bridge (Tornado-based) serving
		// /rosapi/topics, /rosapi/services, /rosapi/nodes over WS. Master
		// brief §"aimap fingerprint debt" #2. Tier-A for 16 years.
		//
		// Detection vector: rosbridge_server runs on Python Tornado. GET / over
		// the same port returns either 404 Not Found or 405 Method Not Allowed
		// with `Server: TornadoServer/X.Y.Z` header. The Tornado server header
		// alone is generic (many Python services use Tornado) — conjunctive per
		// Insight #6: anchor to the default-port set (9090 is rosbridge-canonical;
		// not a common Tornado default) AND the Server header AND the 404/405
		// status. Two probes cover both status shapes.
		//
		// Build-artifact anchor (Insight #93): the canonical rosbridge_suite
		// rosbridge_server binary embeds Tornado as its only HTTP responder.
		// Server: TornadoServer + port 9090 + 404/405 with no body content is
		// the tuple. The full discriminator is the WebSocket handshake to /
		// expecting `{"op":"service_response","service":"/rosapi/topics",...}`
		// after sending `{"op":"call_service","service":"/rosapi/topics","args":{}}`
		// — that path is Lane C verify scope (out of aimap GET engine).
		Name:         "rosbridge_server",
		DefaultPorts: []int{9090, 9091},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "404"},
				{Type: "header_contains", Field: "Server", Value: "TornadoServer"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "405"},
				{Type: "header_contains", Field: "Server", Value: "TornadoServer"},
			}},
		},
		Severity: "critical",
	},
	{
		// rosmaster — ROS1 master node (XML-RPC on port 11311). Master brief
		// §"aimap fingerprint debt" #1. Tier-A — "trusts all nodes."
		//
		// Detection vector: rosmaster speaks XML-RPC over POST only. The aimap
		// matcher is GET-only. Python's SimpleXMLRPCServer (the rosmaster HTTP
		// layer) responds to GET / with HTTP 501 "Unsupported method ('GET')"
		// and a `Server: BaseHTTP/X.Y Python/X.Y.Z` header + a recognizable
		// XML body fragment. The conjunctive marker pair is:
		//   - status_code 501
		//   - Server header containing BaseHTTP (Python stdlib HTTP server)
		//   - body containing "Unsupported method ('GET')" (Python SimpleXMLRPCServer
		//     literal error string — the build-artifact-class anchor per
		//     Insight #93)
		//
		// Full discriminator (Lane C verify scope, requires POST):
		//   POST / with XML-RPC <methodCall><methodName>getUri</methodName>...
		//   → expect <methodResponse><value>1</value>... success code
		// Brown 2018 used getSystemState — same access pattern, returns the full
		// topic/service graph. POST is out of aimap's GET-only matcher engine.
		//
		// FP risk: the conjunctive triple is unique enough at port 11311 that
		// generic Python services would not collide (they would not be on 11311).
		// Adding `body_contains "Unsupported method"` keeps this anchored should
		// rosmaster ever be re-bound to a non-default port via -scan-all-fingerprints.
		Name:         "rosmaster",
		DefaultPorts: []int{11311, 11315, 11316},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "501"},
				{Type: "header_contains", Field: "Server", Value: "BaseHTTP"},
				{Type: "body_contains", Value: "Unsupported method"},
			}},
		},
		Severity: "critical",
	},
	{
		// web_video_server — ROS package serving robot camera topics as
		// MJPEG/H264 streams over HTTP. Master brief §"aimap fingerprint
		// debt" #4. Auth knob has never shipped.
		//
		// Detection vector: GET / returns a hard-coded HTML page listing
		// streamable topics. The HTML literal "ROS Streamable Topic List"
		// (in <title> and <h1>) plus the link prefix "/stream?topic=" are
		// the build-artifact-class anchors per Insight #93 — both are
		// hard-coded in web_video_server/src/web_video_server.cpp and have
		// not shifted across releases. Conjunctive per Insight #6:
		// status_code + both HTML literals.
		//
		// Restraint posture (Lane D Squad-3 Option A): topic NAMES are the
		// finding. Do NOT GET /stream?topic=... — that pulls live frames
		// and creates chain-of-evidence problems. The fingerprint matches
		// on the topic-list page only; deep enumeration parses topic names
		// from the same HTML, never the stream.
		Name:         "web_video_server",
		DefaultPorts: []int{8080, 8181, 8000, 8888},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ROS Streamable Topic List"},
				{Type: "body_contains", Value: "/stream?topic="},
			}},
		},
		Severity: "high",
	},

	// ── cat-voice-tts-agents (2026-08-04) ──────────────────────────────
	// 10 new fingerprints for voice/conversational AI platforms.
	// All probes conjunctive per Insight #6 / CLAUDE.md: status_code +
	// json_field or multiple distinctive body_contains. Never naked keyword.

	// AllTalk TTS — multi-engine TTS aggregator (Kokoro+XTTS+Piper). Port 7851.
	// /api/ready returns {"status":"ready","message":"AllTalk TTS is Ready"}.
	// CORS wildcard + allow_credentials:true = full CSRF surface unauth.
	// /audiocache/{filename} path traversal candidate (directory listing).
	{
		Name:         "AllTalk TTS",
		DefaultPorts: []int{7851, 7852},
		Probes: []Probe{
			{Path: "/api/ready", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "AllTalk"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "AllTalk"},
				{Type: "body_contains", Value: "tts-generate"},
			}},
			{Path: "/api/voices", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "voices"},
				{Type: "body_contains", Value: "alltalk"},
			}},
		},
		Severity: "high",
	},

	// openedai-speech — OpenAI-compat TTS proxy (/v1/audio/speech). Port 8000/8080.
	// Archived 2026-01-04: dependency freeze, XTTS v2 CVEs never patched.
	// /v1/models returns JSON with owned_by:"openedai" — project-unique discriminator.
	{
		Name:         "openedai-speech",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "openedai"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "openedai"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "high",
	},

	// Fish Speech — zero-shot voice cloning TTS (fishaudio). Port 8080/8000.
	// /docs Swagger UI contains "fish-speech" project slug.
	// /v1/tts accepts msgpack — content-type: application/msgpack is project-unique.
	// /v1/asr adds STT pivot on same unauth surface.
	{
		Name:         "Fish Speech",
		DefaultPorts: []int{8080, 8000, 7860},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "fish-speech"},
				{Type: "body_contains", Value: "swagger"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},
				{Type: "body_contains", Value: "fish"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "fishaudio"},
			}},
		},
		Severity: "high",
	},

	// CosyVoice 2 — Alibaba 3-5s zero-shot voice clone. Port 50000 (canonical).
	// Port 50000 is near-unique for this platform. /docs has "CosyVoice" in title.
	// gRPC port 50051 also unauth with published protobuf defs (not HTTP — scanner skip).
	{
		Name:         "CosyVoice 2",
		DefaultPorts: []int{50000, 9880},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "CosyVoice"},
				{Type: "body_contains", Value: "swagger"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},
				{Type: "body_contains", Value: "cosyvoice"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "inference_zero_shot"},
			}},
		},
		Severity: "high",
	},

	// StyleTTS2 — expressive TTS. Gradio UI (:7860) or FastAPI (:8000).
	// Gradio root contains "StyleTTS 2" in title and page body.
	// Gradio --share tunnel bypasses operator firewall rules (non-obvious risk).
	{
		Name:         "StyleTTS2",
		DefaultPorts: []int{7860, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "StyleTTS 2"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "styletts"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "medium",
	},

	// Botpress — self-hosted conversational AI platform. Port 3000.
	// /api/v1/admin/bots returns bot list; botId is often a predictable slug.
	// CVE-2026-4984: POST /api/v1/messaging/webhooks/{token} — unauthenticated
	// Twilio credential theft via forged webhook, zero operator interaction required.
	// Workflow definitions contain embedded OpenAI/Anthropic API keys.
	{
		Name:         "Botpress",
		DefaultPorts: []int{3000, 3001},
		Probes: []Probe{
			{Path: "/api/v1/admin/bots", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "bots"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Botpress"},
				{Type: "body_contains", Value: "bp-web-widget"},
			}},
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "botpress"},
			}},
		},
		Severity: "critical",
	},

	// pyAnnote diarization — GDPR Art.9 biometric exposure (speaker embeddings).
	// HF_TOKEN harvest from container env → lateral movement into operator HuggingFace.
	// Probe: /docs Swagger with "pyannote" + "diarize" — project-unique conjunction.
	{
		Name:         "pyAnnote diarization",
		DefaultPorts: []int{8000, 5000},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "pyannote"},
				{Type: "body_contains", Value: "swagger"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "paths"},
				{Type: "body_contains", Value: "diarize"},
			}},
		},
		Severity: "critical",
	},

	// WhisperX — Whisper + speaker diarization. Port 8000.
	// Distinguishable from base Whisper by "word_segments" field in docs/schema.
	// PYANNOTE_AUTH_TOKEN harvest from container env (same class as pyAnnote).
	// fedirz/faster-whisper-server: API_KEY unset by default = auth disabled.
	{
		Name:         "WhisperX",
		DefaultPorts: []int{8000, 9000},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "whisperx"},
				{Type: "body_contains", Value: "swagger"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "paths"},
				{Type: "body_contains", Value: "word_segments"},
			}},
		},
		Severity: "high",
	},

	// Silero VAD/STT — edge-deployed voice activity detection + transcription.
	// Wyoming TCP :10400 injection into Home Assistant pipelines is the novel surface.
	// HTTP wrapper distinguishable by "silero" in /openapi.json schema body.
	{
		Name:         "Silero VAD",
		DefaultPorts: []int{8000, 10400},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "info"},
				{Type: "body_contains", Value: "silero"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "silero"},
				{Type: "body_contains", Value: "swagger"},
			}},
		},
		Severity: "medium",
	},

	// Moshi — Kyutai real-time full-duplex voice LLM. Port 8998.
	// WebSocket server: plain HTTP GET returns 400/426; WS upgrade to /api/chat succeeds.
	// authorized_ids enforcement only triggers when list non-empty — empty config bypasses.
	// Gradio :7860 tunnel variant: share without token = ephemeral public endpoint.
	{
		Name:         "Moshi voice LLM",
		DefaultPorts: []int{8998, 8088, 7860},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "kyutai"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "moshi"},
				{Type: "body_contains", Value: "swagger"},
			}},
			// 400 on plain HTTP GET to WS endpoint = liveness signal
			{Path: "/api/chat", Matches: []MatchCond{
				{Type: "status_code", Value: "400"},
				{Type: "body_contains", Value: "kyutai"},
			}},
		},
		Severity: "high",
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
