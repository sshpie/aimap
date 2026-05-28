package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// langfuseNextDataRe extracts the Next.js __NEXT_DATA__ JSON blob from a
// server-rendered Langfuse page. The blob embeds `props.pageProps` which on
// /auth/sign-in includes `signUpDisabled`, `authProviders`, and
// `runningOnHuggingFaceSpaces` — the fastest way to audit a Langfuse
// deployment's posture without logging in.
var langfuseNextDataRe = regexp.MustCompile(`<script id="__NEXT_DATA__" type="application/json">(.+?)</script>`)

// ── PII detection ───────────────────────────────────────────────────

var piiPatterns = []string{
	"student", "email", "mail", "phone", "tel", "mobile",
	"counseling", "counselor", "grade", "personal", "private",
	"name", "first_name", "last_name", "firstname", "lastname", "fullname",
	"ssn", "social_security", "national_id", "passport", "identity",
	"address", "street", "city", "zip", "postal",
	"dob", "date_of_birth", "birthday", "birth_date",
	"password", "passwd", "secret", "token", "api_key", "credential",
	"credit_card", "card_number", "cvv", "bank", "account",
	"salary", "income", "gender", "sex", "race", "ethnicity",
	"medical", "health", "diagnosis", "disability",
	"parent", "guardian", "emergency_contact", "family",
	"gpa", "score", "evaluation", "discipline",
	"customer", "employee", "user",
}

func isPII(field string) bool {
	lower := strings.ToLower(field)
	for _, p := range piiPatterns {
		if lower == p || strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ── Dispatcher ──────────────────────────────────────────────────────
//
// 2026-05-15: parallelized PHASE 3 via a worker pool. Prior implementation
// iterated `services` sequentially with a single HTTP client; on a corpus
// of ~10,000 confirmed Ollama hosts that meant 50+ minutes of wall-clock
// where threads=100 was set by the user. The flag now flows from main and
// caps concurrent enumerators at `threads` goroutines.
//
// 2026-05-19 (v1.9.19): converted from a 50-arm switch statement to a
// registry-pattern dispatch. enumeratorRegistry maps service name to its
// enumerator function. Adding a new enumerator is one-line registration
// next to its enumXxx definition (or in this table); "did you wire it up?"
// becomes a compile error rather than a silent "no enumerator ran" miss.

// enumeratorFn is the dispatch signature every service enumerator satisfies.
type enumeratorFn func(c *http.Client, svc ServiceMatch) EnumResult

// enumeratorRegistry maps a fingerprint's Service name to its deep enumerator.
// If a service has no entry here, runEnumerators falls back to mkResult (a
// minimal EnumResult with no findings beyond the generic header sweep).
var enumeratorRegistry = map[string]enumeratorFn{
	// Vector databases
	"Weaviate": enumWeaviate,
	"ChromaDB": enumChromaDB,
	"Qdrant":   enumQdrant,
	"Milvus":   enumMilvus,

	// LLM runtimes
	"Ollama":           enumOllama,
	"llama.cpp server": enumLlamaCpp,
	"SGLang":           enumSGLang,
	"vLLM":             enumVLLM,

	// Image generation
	"ComfyUI":                  enumComfyUI,
	"AUTOMATIC1111 / SD WebUI": enumA1111,
	"InvokeAI":                 enumInvokeAI,

	// Embedding servers
	"HuggingFace TEI":    enumTEI,
	"infinity-embedding": enumInfinity,
	"Embedding API":      enumEmbeddingAPI,

	// ML platforms / experiment tracking
	"MLflow": enumMLflow,

	// LLM proxy / gateway
	"LiteLLM": enumLiteLLM,

	// Orchestration / UI
	"Flowise":     enumFlowise,
	"Dify":        enumDify,
	"Open WebUI":  enumOpenWebUI,
	"SillyTavern": enumSillyTavern,

	// AI agent platforms
	"Agno":                    enumAgno,
	"LangGraph Server":        enumLangGraph,
	"OpenHands":              enumOpenHands,
	"AutoGen Studio":         enumAutoGenStudio,
	"Anti-detect CDP server": enumAntiDetectCDP,
	"Mem0":                   enumMem0,
	"Coolify":                enumCoolify,
	"Clawdbot":               enumClawdbot,

	// Compute orchestration / workflow
	"n8n":             enumN8n,
	"Temporal Web":    enumTemporal,
	"Cadence Web":     enumCadence,
	"Argo Workflows":  enumArgoWorkflows,

	// BI / Dashboard
	"Metabase":        enumMetabase,
	"Apache Superset": enumSuperset,
	"Redash":          enumRedash,
	"Grafana":         enumGrafana,

	// Observability / tracing
	"Langfuse":             enumLangfuse,
	"Arize Phoenix":        enumPhoenix,
	"Helicone Self-Hosted": enumHelicone,
	"Lunary":               enumLunary,
	"OpenLIT":              enumOpenLIT,
	"Pezzo":                enumPezzo,
	"Prometheus":           enumPrometheus,

	// Container / Kubernetes / infra
	"etcd": enumEtcd,

	// Object storage
	"MinIO": enumMinIO,

	// Analytical datastores
	"ClickHouse":    enumClickHouse,
	"Elasticsearch": enumElasticsearch,

	// ML Governance / Data Catalog
	"OpenMetadata": enumOpenMetadata,
	"DataHub GMS":  enumDataHub,
	"Apache Atlas": enumApacheAtlas,
	"Marquez":      enumMarquez,

	// AI safety / eval / guardrails
	"Promptfoo":             enumPromptfoo,
	"NeMo Guardrails":       enumNeMoGuardrails,
	"DeepEval Server":       enumDeepEval,
	"LangSmith Self-Hosted": enumLangSmith,

	// Redis management GUI
	"RedisInsight": enumRedisInsight,

	// GraphQL API
	"Apollo GraphQL API": enumGraphQL,

	// Chatbot frameworks
	"Rasa": enumRasa,

	// Voice / Audio AI
	"AI TTS Server": enumTTS,

	// Notebooks / dev / adjacent
	"Jupyter Notebook": enumJupyter,
	"Open Directory":   enumOpenDirectory,
	"Docker Registry":  enumDockerRegistry,

	// Cross-cutting
	"Exposed API Credentials": enumExposedCredentials,
}

func runEnumerators(services []ServiceMatch, timeout time.Duration, verbose bool, threads int) []EnumResult {
	client := newHTTPClient(timeout)
	if threads < 1 {
		threads = 20
	}

	results := make([]EnumResult, len(services))
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for i := range services {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			svc := services[idx]
			if verbose {
				fmt.Printf("    enumerating %s @ %s\n", svc.Service, svc.BaseURL)
			}
			var result EnumResult
			if fn, ok := enumeratorRegistry[svc.Service]; ok {
				result = fn(client, svc)
			} else {
				result = mkResult(svc)
			}
			result.Findings = append(result.Findings, checkGeneric(client, svc)...)
			result.RiskLevel = computeRisk(result)
			results[idx] = result
		}(i)
	}
	wg.Wait()
	return results
}

func mkResult(svc ServiceMatch) EnumResult {
	return EnumResult{
		Service:    svc.Service,
		Host:       svc.Host,
		Port:       svc.Port,
		BaseURL:    svc.BaseURL,
		Version:    svc.Version,
		AuthStatus: "unknown",
		RawData:    make(map[string]interface{}),
	}
}

// ── Weaviate ────────────────────────────────────────────────────────

func enumWeaviate(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	if st, _, body, err := httpGET(c, b+"/v1/meta"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["meta"] = m
			if mods := jMap(m, "modules"); mods != nil {
				names := make([]string, 0, len(mods))
				for k := range mods {
					names = append(names, k)
				}
				r.RawData["modules"] = names
			}
		}
	}

	r.AuthStatus = "none"
	if st, _, _, err := httpGET(c, b+"/.well-known/openid-configuration"); err == nil && st == 200 {
		r.AuthStatus = "OIDC"
	}

	if st, _, body, err := httpGET(c, b+"/v1/schema"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			classes := jArray(m, "classes")
			type colInfo struct {
				Name       string   `json:"name"`
				Vectorizer string   `json:"vectorizer"`
				Props      int      `json:"properties"`
				Objects    int      `json:"objects"`
				PII        []string `json:"pii_fields,omitempty"`
			}
			var cols []colInfo
			var allPII []string
			totalObjects := 0

			r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(classes)))
			for _, cls := range classes {
				cm, ok := cls.(map[string]interface{})
				if !ok {
					continue
				}
				ci := colInfo{
					Name:       jStr(cm, "class"),
					Vectorizer: jStr(cm, "vectorizer"),
				}
				props := jArray(cm, "properties")
				ci.Props = len(props)
				for _, p := range props {
					pm, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					if pName := jStr(pm, "name"); isPII(pName) {
						ci.PII = append(ci.PII, pName)
						allPII = append(allPII, pName)
					}
				}
				url := fmt.Sprintf("%s/v1/objects?class=%s&limit=1", b, ci.Name)
				if s, _, ob, e := httpGET(c, url); e == nil && s == 200 {
					if om, e := parseJSON(ob); e == nil {
						ci.Objects = int(jFloat(om, "totalResults"))
					}
				}
				totalObjects += ci.Objects
				r.Details = append(r.Details, fmt.Sprintf("  %-30s (%s objects)", ci.Name, fmtNum(ci.Objects)))
				cols = append(cols, ci)
			}
			r.RawData["collections"] = cols

			if len(allPII) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII fields: " + strings.Join(allPII, ", "),
					Severity: "critical", Data: allPII,
				})
			}
			if totalObjects > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%s total objects — full read access", fmtNum(totalObjects)),
					Severity: "high",
				})
			} else {
				r.Findings = append(r.Findings, Finding{
					Category: "schema", Title: "Full schema readable (collections empty)",
					Severity: "high",
				})
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/v1/nodes"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			nodes := jArray(m, "nodes")
			r.RawData["node_count"] = len(nodes)
		}
	}

	return r
}

// ── Ollama ──────────────────────────────────────────────────────────

func enumOllama(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/tags"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "models")
			type modelInfo struct {
				Name string `json:"name"`
				Size string `json:"size"`
			}
			var mlist []modelInfo
			var parts []string
			for _, mdl := range models {
				mm, ok := mdl.(map[string]interface{})
				if !ok {
					continue
				}
				mi := modelInfo{Name: jStr(mm, "name")}
				if sz := jFloat(mm, "size"); sz > 0 {
					mi.Size = fmt.Sprintf("%.1fGB", sz/1e9)
				}
				mlist = append(mlist, mi)
				parts = append(parts, fmt.Sprintf("%s (%s)", mi.Name, mi.Size))
			}
			r.RawData["models"] = mlist
			if len(parts) > 0 {
				r.Details = append(r.Details, "Models: "+strings.Join(parts, ", "))
			}
			r.Findings = append(r.Findings, Finding{
				Category: "models", Title: fmt.Sprintf("%d models loaded", len(mlist)),
				Severity: "high",
			})
		}
	}

	if st, _, _, err := httpGET(c, b+"/api/generate"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "/api/generate open — anyone can run inference",
			Detail:   fmt.Sprintf("HTTP %d", st),
			Severity: "critical",
		})
	}

	if st, _, _, err := httpGET(c, b+"/api/pull"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "/api/pull open — anyone can download new models",
			Detail:   fmt.Sprintf("HTTP %d", st),
			Severity: "critical",
		})
	}

	return r
}

// ── llama.cpp server ────────────────────────────────────────────────
//
// llama.cpp ships its own HTTP server (`./llama-server`) exposing
// /v1/models (OpenAI compat), /v1/chat/completions, /completion, /props
// (server-info), /health, /props for chat-template + n_ctx + total_slots.
// When deployed on port 11434 it overlaps Ollama; the fingerprint
// distinguishes them via /v1/models response shape and Server header.
// Field instance: 194.233.71.223 (2026-05-15) — Contabo SG host serving
// Microsoft BitNet-b1.58-2B-4T unauth with chat-template + completion
// endpoints exposed.

func enumLlamaCpp(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// /v1/models — OpenAI-compatible model list
	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			data := jArray(m, "data")
			var ids []string
			for _, e := range data {
				if mm, ok := e.(map[string]interface{}); ok {
					if id := jStr(mm, "id"); id != "" {
						ids = append(ids, id)
					}
				}
			}
			if len(ids) > 0 {
				r.RawData["models"] = ids
				r.Details = append(r.Details, "Models: "+strings.Join(ids, ", "))
				r.Findings = append(r.Findings, Finding{
					Category: "models", Title: fmt.Sprintf("%d model(s) loaded", len(ids)),
					Severity: "high",
				})
			}
		}
	}

	// /props — server-side config (n_ctx, total_slots, chat_template)
	if st, _, body, err := httpGET(c, b+"/props"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["props"] = m
			if dg := jMap(m, "default_generation_settings"); dg != nil {
				if nctx := jFloat(dg, "n_ctx"); nctx > 0 {
					r.Details = append(r.Details, fmt.Sprintf("n_ctx=%d", int(nctx)))
				}
			}
			if ts := jFloat(m, "total_slots"); ts > 0 {
				r.Details = append(r.Details, fmt.Sprintf("total_slots=%d", int(ts)))
			}
			if ct := jStr(m, "chat_template"); ct != "" {
				excerpt := ct
				if len(excerpt) > 120 {
					excerpt = excerpt[:120] + "..."
				}
				r.RawData["chat_template_excerpt"] = excerpt
				r.Findings = append(r.Findings, Finding{
					Category: "config", Title: "chat_template exposed via /props",
					Detail: "Custom system-prompt / persona configuration disclosed",
					Severity: "medium",
				})
			}
		}
	}

	// /health — liveness
	if st, _, _, err := httpGET(c, b+"/health"); err == nil && st == 200 {
		r.Details = append(r.Details, "health: ok")
	}

	// /completion — flag the unauth inference endpoint without invoking it
	if st, _, _, err := httpGET(c, b+"/completion"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "/completion open — anyone can run unauth inference",
			Detail:   fmt.Sprintf("HTTP %d (POST is the invocation method; GET probe confirms reachability)", st),
			Severity: "critical",
		})
	}

	return r
}

// ── ChromaDB ────────────────────────────────────────────────────────

func enumChromaDB(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/version"); err == nil && st == 200 {
		r.Version = strings.Trim(string(body), "\" \n\r")
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/collections"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			type colInfo struct {
				Name  string `json:"name"`
				ID    string `json:"id"`
				Count int    `json:"count"`
			}
			var cols []colInfo
			totalObjects := 0
			var piiNames []string

			r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(arr)))
			for _, item := range arr {
				if cm, ok := item.(map[string]interface{}); ok {
					ci := colInfo{Name: jStr(cm, "name"), ID: jStr(cm, "id")}
					if ci.ID != "" {
						cURL := fmt.Sprintf("%s/api/v1/collections/%s/count", b, ci.ID)
						if s, _, cb, e := httpGET(c, cURL); e == nil && s == 200 {
							var cnt int
							if json.Unmarshal(cb, &cnt) == nil {
								ci.Count = cnt
							}
						}
					}
					totalObjects += ci.Count
					if isPII(ci.Name) {
						piiNames = append(piiNames, ci.Name)
					}
					r.Details = append(r.Details, fmt.Sprintf("  %-30s (%s objects)", ci.Name, fmtNum(ci.Count)))
					cols = append(cols, ci)
				}
			}
			r.RawData["collections"] = cols

			if len(piiNames) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII-indicating collection names: " + strings.Join(piiNames, ", "),
					Severity: "high",
				})
			}
			if totalObjects > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%s total objects — full read access", fmtNum(totalObjects)),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── Qdrant ──────────────────────────────────────────────────────────

func enumQdrant(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/collections"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			result := jMap(m, "result")
			if result != nil {
				cols := jArray(result, "collections")
				type colDetail struct {
					Name   string `json:"name"`
					Points int    `json:"points"`
					Status string `json:"status"`
				}
				var details []colDetail
				r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(cols)))
				for _, col := range cols {
					cm, ok := col.(map[string]interface{})
					if !ok {
						continue
					}
					cd := colDetail{Name: jStr(cm, "name")}
					cURL := fmt.Sprintf("%s/collections/%s", b, cd.Name)
					if s, _, cb, e := httpGET(c, cURL); e == nil && s == 200 {
						if dm, err := parseJSON(cb); err == nil {
							if res := jMap(dm, "result"); res != nil {
								cd.Points = int(jFloat(res, "points_count"))
								cd.Status = jStr(res, "status")
							}
						}
					}
					r.Details = append(r.Details, fmt.Sprintf("  %-30s (%s points)", cd.Name, fmtNum(cd.Points)))
					details = append(details, cd)
				}
				r.RawData["collections"] = details
				r.Findings = append(r.Findings, Finding{
					Category: "schema", Title: "Collections enumerated",
					Detail:   fmt.Sprintf("%d collections accessible", len(details)),
					Severity: "high",
				})
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/cluster"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["cluster"] = m
		}
	}

	return r
}

// ── Flowise ─────────────────────────────────────────────────────────

func enumFlowise(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/flows"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Flows: %d", len(arr)))
			r.Findings = append(r.Findings, Finding{
				Category: "flows", Title: fmt.Sprintf("%d flows readable", len(arr)),
				Severity: "high",
			})
		}
		r.Findings = append(r.Findings, Finding{
			Category: "cve",
			Title:    "CVE-2024-36420 — Auth bypass via path traversal (< 1.8.2)",
			Detail:   "Path traversal grants unauth access to chatflow config and embedded API keys. Verify version.",
			Severity: "high",
		})
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/chatflows"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Chatflows: %d", len(arr)))
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/credentials"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Findings = append(r.Findings, Finding{
				Category: "credentials", Title: fmt.Sprintf("Credentials endpoint accessible — %d entries", len(arr)),
				Severity: "critical",
			})
		}
	}

	return r
}

// ── Jupyter ─────────────────────────────────────────────────────────

func enumJupyter(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Kernels
	if st, _, body, err := httpGET(c, b+"/api/kernels"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["kernels"] = len(arr)
			r.Findings = append(r.Findings, Finding{
				Category: "rce", Title: "Unauthenticated code execution",
				Detail:   fmt.Sprintf("Anyone on the network gets a full shell. No token required. %d active kernel(s).", len(arr)),
				Severity: "critical",
			})
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = "token/password required"
	}

	// Sessions
	if st, _, body, err := httpGET(c, b+"/api/sessions"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["sessions"] = len(arr)
		}
	}

	// File listing + secret scanning
	if st, _, body, err := httpGET(c, b+"/api/contents"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			contents := jArray(m, "content")
			r.RawData["files"] = len(contents)

			// Look for sensitive files
			sensitiveFiles := []string{".env", ".env.local", ".env.production", "config.py", "settings.py", "credentials.json"}
			for _, item := range contents {
				im, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				fname := jStr(im, "name")
				for _, sf := range sensitiveFiles {
					if strings.EqualFold(fname, sf) || strings.HasSuffix(strings.ToLower(fname), ".env") {
						// Try to read the file
						fURL := fmt.Sprintf("%s/api/contents/%s", b, fname)
						if fs, _, fb, fe := httpGET(c, fURL); fe == nil && fs == 200 {
							if fm, fe := parseJSON(fb); fe == nil {
								content := jStr(fm, "content")
								if content != "" {
									scanSecrets(content, &r)
								}
							}
						}
						break
					}
				}
			}

			if len(contents) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "files", Title: fmt.Sprintf("File listing accessible — %d files/dirs in root", len(contents)),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── MLflow ──────────────────────────────────────────────────────────

func enumMLflow(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/2.0/mlflow/experiments/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			exps := jArray(m, "experiments")
			r.Details = append(r.Details, fmt.Sprintf("Experiments: %d", len(exps)))
			r.Findings = append(r.Findings, Finding{
				Category: "experiments", Title: fmt.Sprintf("%d experiments accessible", len(exps)),
				Severity: "high",
			})
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/2.0/mlflow/registered-models/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "registered_models")
			r.Details = append(r.Details, fmt.Sprintf("Registered models: %d", len(models)))
			r.Findings = append(r.Findings, Finding{
				Category: "models", Title: fmt.Sprintf("%d registered models accessible", len(models)),
				Severity: "high",
			})
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "cve",
		Title:    "CVE-2024-37052…37060 — RCE via model deserialization",
		Detail:   "Any exposed MLflow with write access to the model registry is RCE. Chain: upload malicious pickle model → trigger load → code execution.",
		Severity: "critical",
	})

	return r
}

// ── Milvus ──────────────────────────────────────────────────────────

func enumMilvus(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Version / build info
	if st, _, body, err := httpGET(c, b+"/api/v1/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["version_info"] = m
		}
	}

	// Health
	if st, _, body, err := httpGET(c, b+"/api/v1/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
		}
	}

	// Prometheus metrics (often exposes internal cluster info)
	if st, _, body, err := httpGET(c, b+"/metrics"); err == nil && st == 200 {
		if strings.Contains(string(body), "milvus_") {
			r.Findings = append(r.Findings, Finding{
				Category: "metrics", Title: "Prometheus metrics endpoint accessible",
				Detail:   "/metrics exposes internal cluster telemetry and deployment topology",
				Severity: "medium",
			})
		}
	}

	// Collection enumeration via REST gateway
	if st, _, body, err := httpGET(c, b+"/api/v1/collections"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			cols := jArray(m, "collection_names")
			if cols == nil {
				// Alternative response shape
				if data := jMap(m, "data"); data != nil {
					cols = jArray(data, "collection_names")
				}
			}
			var piiNames []string
			r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(cols)))
			for _, c := range cols {
				if name, ok := c.(string); ok {
					r.Details = append(r.Details, fmt.Sprintf("  %s", name))
					if isPII(name) {
						piiNames = append(piiNames, name)
					}
				}
			}
			r.RawData["collections"] = cols

			if len(cols) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%d collections enumerable without auth", len(cols)),
					Severity: "high",
				})
			}
			if len(piiNames) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII-indicating collection names: " + strings.Join(piiNames, ", "),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── Langfuse ────────────────────────────────────────────────────────

func enumLangfuse(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Health / status
	if st, _, body, err := httpGET(c, b+"/api/public/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["health"] = m
		}
	}

	// Langfuse is the LLM observability platform. If it's exposed, the real
	// concern is NOT the UI but the trace/span data which contains full
	// prompt+response history. Even signup-open without auth is a finding
	// because anyone can create an account and read existing org data in
	// misconfigured deployments.

	// Deep posture audit via /auth/sign-in — Langfuse SSR-embeds the auth
	// config in a __NEXT_DATA__ JSON blob. This is the fastest way to see
	// whether signup is open and which SSO providers (if any) are configured,
	// without having to create an account.
	if st, _, body, err := httpGET(c, b+"/auth/sign-in"); err == nil && st == 200 {
		if m := langfuseNextDataRe.FindSubmatch(body); len(m) == 2 {
			var wrap struct {
				Props struct {
					PageProps map[string]interface{} `json:"pageProps"`
				} `json:"props"`
			}
			if err := json.Unmarshal(m[1], &wrap); err == nil {
				pp := wrap.Props.PageProps
				r.RawData["sign_in_config"] = pp

				// signUpDisabled: false → anyone on the internet can register.
				// For a self-hosted Langfuse on corporate infra, this is almost
				// always unintended.
				if v, ok := pp["signUpDisabled"].(bool); ok && !v {
					r.Findings = append(r.Findings, Finding{
						Category: "access", Title: "Langfuse signup is open to the public",
						Detail:   "signUpDisabled=false. Any internet visitor can register an account, persisting a user record in the operator's Postgres and enabling authenticated API probing. Set LANGFUSE_AUTH_DISABLE_SIGNUP=true or restrict via LANGFUSE_AUTH_DOMAINS_*.",
						Severity: "medium",
					})
				}

				// authProviders: inventory configured SSO and flag the common
				// misconfig of password-only auth on a production deployment.
				if ap, ok := pp["authProviders"].(map[string]interface{}); ok {
					var enabled []string
					credsOnly := false
					for name, val := range ap {
						if b, ok := val.(bool); ok && b {
							enabled = append(enabled, name)
						}
					}
					if len(enabled) == 1 && enabled[0] == "credentials" {
						credsOnly = true
					}
					if len(enabled) > 0 {
						r.Details = append(r.Details, "Auth providers: "+strings.Join(enabled, ", "))
					}
					if credsOnly {
						r.Findings = append(r.Findings, Finding{
							Category: "access", Title: "Credentials-only auth (no SSO configured)",
							Detail:   "Only password-based authentication is enabled. No OIDC/SAML provider configured, which removes the identity-provider brute-force ceiling and centralized MFA. Configure LANGFUSE_AUTH_*_CLIENT_* for Google/GitHub/Okta/Azure AD.",
							Severity: "low",
						})
					}
				}

				// runningOnHuggingFaceSpaces flag — informational. This alters
				// default auth semantics and sometimes exposes SPACE_HOST.
				if v, ok := pp["runningOnHuggingFaceSpaces"].(bool); ok && v {
					r.Findings = append(r.Findings, Finding{
						Category: "info", Title: "Running as HuggingFace Space",
						Detail:   "runningOnHuggingFaceSpaces=true — HF Spaces deployments use different default auth semantics.",
						Severity: "info",
					})
				}
			}
		}
	}

	// Langfuse exposes /api/public/projects etc. Without auth these return
	// 401 when properly configured.
	if st, _, body, err := httpGET(c, b+"/api/public/projects"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			r.Findings = append(r.Findings, Finding{
				Category: "data", Title: "LLM trace data accessible without authentication",
				Detail:   "Langfuse stores full prompt/response history, system prompts, user inputs, and tool-call outputs. Unauthenticated access likely exposes production conversation data.",
				Severity: "critical",
			})
			if arr, err := parseJSONArray(body); err == nil {
				r.RawData["project_count"] = len(arr)
				r.Details = append(r.Details, fmt.Sprintf("Projects: %d", len(arr)))
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
			r.Findings = append(r.Findings, Finding{
				Category: "info", Title: "Authentication enforced on trace API",
				Severity: "info",
			})
		}
	}

	// Always flag the severity of what Langfuse contains, even when auth is on
	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Langfuse stores LLM conversation data",
		Detail:   "This service contains full prompt/response history. Misconfigurations here leak production conversation data and potentially PII, credentials in tool-call outputs, or system prompts.",
		Severity: "info",
	})

	return r
}

// ── Dify ────────────────────────────────────────────────────────────

func enumDify(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Dify exposes /console/api/setup — returns a JSON response indicating
	// whether initial admin setup has been completed. A fresh Dify instance
	// where setup has NOT been completed is a critical finding: anyone can
	// claim the admin account.
	if st, _, body, err := httpGET(c, b+"/console/api/setup"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			setupDone := false
			if v, ok := m["step"]; ok {
				if s, ok := v.(string); ok && s == "finished" {
					setupDone = true
				}
			}
			r.RawData["setup"] = m
			if !setupDone {
				r.Findings = append(r.Findings, Finding{
					Category: "access", Title: "Dify initial setup NOT completed — admin claimable",
					Detail:   "Anyone reaching /install can register the first admin account. Claim immediately or firewall.",
					Severity: "critical",
				})
				r.AuthStatus = "none (admin claimable)"
			} else {
				r.AuthStatus = "setup completed"
			}
		}
	}

	// Version / info endpoints
	if st, _, body, err := httpGET(c, b+"/console/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	// App enumeration (usually requires auth, but some older Dify versions
	// exposed these endpoints without)
	if st, _, body, err := httpGET(c, b+"/console/api/apps"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jArray(m, "data"); data != nil {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%d Dify apps enumerable", len(data)),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── SillyTavern ─────────────────────────────────────────────────────

func enumSillyTavern(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	r.AuthStatus = "basic"
	if strings.HasPrefix(svc.BaseURL, "http://") {
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "SillyTavern protected by HTTP Basic Auth (cleartext credentials)",
			Detail:   "Basic Auth over plain HTTP transmits base64-encoded credentials without encryption. Upgrade to HTTPS or place behind a TLS reverse proxy.",
			Severity: "medium",
		})
	}
	return r
}

// ── Open WebUI ──────────────────────────────────────────────────────

func enumOpenWebUI(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	if st, _, body, err := httpGET(c, b+"/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	authEnabled := true
	signupEnabled := false
	if st, _, body, err := httpGET(c, b+"/api/config"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if feats, ok := m["features"].(map[string]interface{}); ok {
				if v, ok := feats["auth"].(bool); ok {
					authEnabled = v
				}
				if v, ok := feats["enable_signup"].(bool); ok {
					signupEnabled = v
				}
			}
			r.RawData["config"] = m
		}
	}

	if !authEnabled {
		r.AuthStatus = "none"
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Open WebUI running without authentication",
			Detail:   "AUTH_ENABLED=false — all API endpoints and chat history accessible without credentials.",
			Severity: "critical",
		})
	} else if signupEnabled {
		r.AuthStatus = "open registration"
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Open WebUI allows public self-registration",
			Detail:   "enable_signup=true — anyone can create an account and access connected LLM backends.",
			Severity: "high",
		})
	} else {
		r.AuthStatus = "auth required"
	}

	// Even with auth enabled, check if the OpenAI-compatible API is exposed
	if st, _, body, err := httpGET(c, b+"/api/models"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jArray(m, "data"); data != nil {
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    fmt.Sprintf("Open WebUI /api/models unauthenticated — %d model(s) listed", len(data)),
					Severity: "critical",
				})
				r.AuthStatus = "none"
			}
		}
	}

	return r
}

// ── Docker Registry ─────────────────────────────────────────────────

// AI/ML image substrings used to flag a registry as AI-relevant. Each entry
// must be path/word-anchored, not bare substring — single short tokens like
// `ray` FP'd on `krayzdrav` (Russian "regional health"). Insight #6 applies.
var aiRegistryImages = []string{
	"ollama", "vllm", "localai", "llama", "mistral", "deepseek",
	"ragflow", "langflow", "flowise", "dify", "openwebui", "open-webui",
	"sglang", "lmdeploy", "triton", "mlflow",
	"/ray/", "ray-", "/ray-", "rayproject/", "anyscale/ray", // `ray` was bare-substring; now anchored
	"pytorch", "tensorflow", "transformers", "huggingface",
	"chromadb", "qdrant", "weaviate", "milvus",
	"n8n", "langchain", "autogen", "comfyui", "stable-diffusion",
}

// Jetson-attribution signals. A registry catalog leak (/v2/_catalog) that
// surfaces ANY high-confidence signal fingerprints the operator as a Jetson
// builder / deployer. Source: Jetson-tensorrt edge survey 2026-05-18, F1
// mfgbot (Hetzner FI), F4 RAG-on-Jetson (APNIC JP) — both single-signal high
// confidence (`mfgbot/l4t-base` / `mfgbot-os/jetson/*` for F1; `dustynv/ollama`
// for F4). F5 Auriga (Aliyun CN) is medium+arch -> promoted to high.
//
// High-confidence signals (single match -> Jetson):
//   - dustynv/         : Dustin Franklin's Jetson AI Lab containers (github.com/dusty-nv/jetson-containers)
//   - l4t              : NVIDIA Linux for Tegra (Jetson-exclusive base OS)
//   - jetson           : explicit string in repo path
//   - tegra            : Jetson SoC family name
//   - jetpack          : Jetson SDK
//
// Medium-confidence signals (Jetson when paired with an arch hint):
//   - isaac-lab / isaac_ros / isaac-sim : NVIDIA Isaac stack (runs on x86 too;
//                                          the arch hint disambiguates)
//
// Architecture hints (Jetson is aarch64; combined with medium signal -> high):
//   - aarch64 / -arm- / _arm / /arm/
var jetsonHighConfidenceSignals = []string{
	"dustynv/",
	"/l4t-", "/l4t/", "l4t-base",
	"/jetson", "jetson/",
	// `tegra` must be path/word-anchored, not bare substring. Bare `tegra`
	// FP'd on `mcintegration` (substring inside `integration`) at population
	// scale (160.85.252.184 in the 2026-05-19 registry pop survey). Insight
	// #6 (conjunctive marker-anchored matchers) — applies inside this
	// classifier as much as it applies to body-text matchers.
	"/tegra", "tegra/", "tegra-", "-tegra", "tegra_", "_tegra",
	"jetpack",
}

var jetsonMediumConfidenceSignals = []string{
	"isaac-lab", "isaac_lab",
	"isaac-ros", "isaac_ros",
	"isaac-sim", "isaac_sim",
}

var jetsonArchHints = []string{
	"aarch64",
	"-arm-", "_arm", "/arm/",
}

// Healthcare-imaging operator signals. Sources: dcm4chee-arc-light (the
// reference open-source DICOM archive), Orthanc (the other dominant PACS),
// OHIF Viewer + Weasis (DICOM web clients), DICOMweb route prefixes (`/dicom`,
// `/wadors`, `/qido`). Healthcare imaging registries are operator-curated
// (rad teams pull and pin specific images) so single-signal matches are
// reliable.
//
// Internationalization (per Insight #35): the v1.9.13 signal set was
// western-DICOM-PACS-centric. Population-pass burn-in on the registry
// survey 2026-05-19 found a Russian regional-healthcare operator
// (88.99.214.110:5000, repos `external/krayzdrav/fss-*`) that the original
// classifier missed. v1.9.15 adds language-specific healthcare-system terms:
// Russian (zdrav, krayzdrav, krayzdravotdel), German (klinik, krankenhaus,
// praxis), Spanish (salud, clinica, hospital), French (sante, clinique),
// Italian (sanita, ospedale), Mandarin (yiyuan), Japanese (byouin).
//
// High-confidence (single match suffices):
//   - dcm4chee, orthanc, ohif, weasis : DICOM platform images
//   - pacs, dicom, dicomweb            : explicit medical imaging strings
//   - wadors, qido                      : DICOMweb route fragments
//   - International healthcare-system terms (path/word-anchored)
//
// Medium-confidence (paired with adjacent signal -> high):
//   - radiology, radiology-, radiant   : clinical workflow tools
//   - imagej                            : medical image processing toolkit
//
// Anchoring: all multi-letter tokens that have common-English collisions
// (e.g., `pacs` would FP on `vmwarepacs` — but no such case yet) are
// path-anchored. Each signal must contain `/`, `-`, or `_` boundary unless
// it's a long enough token that bare-substring collision is unlikely
// (`dcm4chee`, `dicomweb`, `krayzdrav`).
var healthcareImagingHighSignals = []string{
	// English / international product names
	"dcm4chee",
	"orthancteam/", "osimis/orthanc", "/orthanc",
	"ohif/", "/ohif-viewer",
	"weasis",
	// `pacs/` and `dicom/` (without preceding slash) FP'd at population scale:
	// `adicom/admin-mongo` contains `dicom/` as substring. Require a slash
	// boundary before, OR a hyphen/underscore suffix. `dicomweb` (8 chars)
	// is safe as bare.
	"/pacs", "pacs-", "/pacs/", "pacs_",
	"/dicom", "dicom-", "/dicom/", "dicom_", "dicomweb",
	"/wadors", "/qido",
	// Russian / Ukrainian: zdrav = health
	"zdrav-", "/zdrav", "zdrav/", "krayzdrav", "minzdrav",
	// German: klinik = clinic, krankenhaus = hospital, praxis = practice
	// `klinik/` and `salud/` etc. mirror the dicom/ FP class — anchor with
	// a preceding slash OR a hyphen/underscore suffix.
	"/klinik", "klinik-", "/klinik/", "klinik_", "krankenhaus", "/praxis", "praxis-",
	// Spanish: salud = health, clinica = clinic
	"/salud", "salud-", "/salud/", "salud_", "/clinica", "clinica-", "/clinica/",
	// French: sante = health, clinique = clinic
	"/sante", "sante-", "/sante/", "sante_", "/clinique", "clinique-",
	// Italian: sanita = health, ospedale = hospital
	"/sanita", "sanita-", "/ospedale", "ospedale-",
	// Mandarin transliteration: yiyuan = hospital
	"yiyuan", "/yiyuan", "yiyuan-",
	// Japanese transliteration: byouin = hospital
	"byouin", "/byouin",
	// Generic medical-system fragments (path-anchored)
	"/medical-", "medical/", "/hospital-", "hospital/",
}

var healthcareImagingMediumSignals = []string{
	"radiology", "radiant-",
	"imagej-",
}

func classifyHealthcareRepos(repos []string) (matched []string, confidence string) {
	return classifyRepos(repos, healthcareImagingHighSignals, healthcareImagingMediumSignals, nil)
}

// Finance / algotrading operator signals. The retail-and-prop algo trading
// stack standardizes on a few open-source brokers and quant libraries.
// Each one is a strong indicator the operator is running a live or
// backtesting trading bot (and exposing it).
//
// High-confidence (single match suffices):
//   - freqtrade, freqtradeorg/      : the dominant open-source crypto trading bot
//   - quantlib                       : the dominant quant finance library
//   - vector-bt, vectorbt            : vectorized backtesting library
//   - alpaca, alpaca-py              : Alpaca broker API
//   - ibapi, ib-gateway, ibkr        : Interactive Brokers gateway / API
//   - oanda, oandapy                 : OANDA fx broker
//   - mt4, mt5, metatrader           : MetaTrader 4 / 5 (Windows fx)
//   - nautilus_trader                : nautilus algo trading platform
//
// Medium-confidence (paired with adjacent signal -> high):
//   - backtrader, zipline, lean-engine : backtesting frameworks (also used in
//                                         analysis pipelines that aren't trading)
//   - binance-, kraken-, coinbase-     : exchange-API wrappers
var financeTradingHighSignals = []string{
	"freqtrade",
	"quantlib",
	"vector-bt", "vectorbt",
	"alpaca/", "alpaca-",
	"ibapi", "ib-gateway", "/ibkr",
	"oanda",
	"/mt4", "/mt5", "metatrader",
	"nautilus_trader", "nautilus-trader",
}

var financeTradingMediumSignals = []string{
	"backtrader", "zipline", "lean-engine",
	"binance-", "kraken-", "coinbase-",
}

func classifyFinanceRepos(repos []string) (matched []string, confidence string) {
	return classifyRepos(repos, financeTradingHighSignals, financeTradingMediumSignals, nil)
}

// classifyRepos is the shared engine for all per-operator-class registry
// classifiers. Each class supplies its own high / medium / arch signal lists.
// arch may be nil for classes where architecture is not a discriminator.
//
// Tiering rule (same across all classes):
//   - any high-confidence match -> high
//   - medium match + any arch hint -> promoted to high
//   - medium match alone -> medium
//   - arch hint alone -> low (if class has any arch signal list)
func classifyRepos(repos []string, highSignals, mediumSignals, archSignals []string) (matched []string, confidence string) {
	seen := map[string]bool{}
	var highHits, medHits, archHits []string
	for _, name := range repos {
		lower := strings.ToLower(name)
		hit := false
		for _, sig := range highSignals {
			if strings.Contains(lower, sig) && !seen[name] {
				highHits = append(highHits, name)
				seen[name] = true
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		for _, sig := range mediumSignals {
			if strings.Contains(lower, sig) && !seen[name] {
				medHits = append(medHits, name)
				seen[name] = true
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		for _, sig := range archSignals {
			if strings.Contains(lower, sig) && !seen[name] {
				archHits = append(archHits, name)
				seen[name] = true
				break
			}
		}
	}
	matched = append(append(highHits, medHits...), archHits...)
	switch {
	case len(highHits) > 0:
		confidence = "high"
	case len(medHits) > 0 && len(archHits) > 0:
		confidence = "high"
	case len(medHits) > 0:
		confidence = "medium"
	case len(archHits) > 0:
		confidence = "low"
	default:
		confidence = ""
	}
	return matched, confidence
}

// classifyJetsonRepos inspects a /v2/_catalog repository list and returns the
// matching repos plus a confidence tier. Designed to be pure (no I/O) so it
// can be unit-tested directly against fixture inputs.
func classifyJetsonRepos(repos []string) (matched []string, confidence string) {
	return classifyRepos(repos, jetsonHighConfidenceSignals, jetsonMediumConfidenceSignals, jetsonArchHints)
}

func enumDockerRegistry(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, hdrs, _, err := httpGET(c, b+"/v2/"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
		} else if st == 401 {
			if wa, ok := hdrs["Www-Authenticate"]; ok {
				r.AuthStatus = "required: " + wa
			} else {
				r.AuthStatus = "required (HTTP 401)"
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/v2/_catalog"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			repos := jArray(m, "repositories")
			r.RawData["repo_count"] = len(repos)
			r.Details = append(r.Details, fmt.Sprintf("Repositories: %d", len(repos)))

			// Score AI-relevant images
			var aiRepos []string
			for _, repo := range repos {
				name, ok := repo.(string)
				if !ok {
					continue
				}
				lower := strings.ToLower(name)
				for _, tag := range aiRegistryImages {
					if strings.Contains(lower, tag) {
						aiRepos = append(aiRepos, name)
						break
					}
				}
			}

			if len(aiRepos) > 0 {
				r.Details = append(r.Details, fmt.Sprintf("AI images: %s", strings.Join(aiRepos, ", ")))
				r.Findings = append(r.Findings, Finding{
					Category: "ai-images",
					Title:    fmt.Sprintf("%d AI/ML images in anonymous registry — pull without auth", len(aiRepos)),
					Detail:   strings.Join(aiRepos, ", "),
					Severity: "high",
				})
			}

			// Jetson-attribution pass. A registry catalog can ship clean of
			// commodity-AI images yet still surface the operator as a Jetson
			// builder (F1 mfgbot — only `pytorch` matches aiRegistryImages,
			// but `l4t-base` + `mfgbot-os/jetson/*` are unambiguous Jetson).
			repoNames := make([]string, 0, len(repos))
			for _, repo := range repos {
				if name, ok := repo.(string); ok {
					repoNames = append(repoNames, name)
				}
			}
			// Operator-class attribution via catalog content. Each classifier
			// is a pure function over the repo name list. Multiple classifiers
			// can fire on the same registry (an operator with a mixed stack).
			operatorClasses := []struct {
				name      string
				classify  func([]string) ([]string, string)
				rawConf   string
				rawRepos  string
				titlePrefix string
			}{
				{"Jetson / NVIDIA edge", classifyJetsonRepos, "jetson_confidence", "jetson_repos", "Jetson / NVIDIA edge"},
				{"Healthcare imaging (PACS / DICOM)", classifyHealthcareRepos, "healthcare_confidence", "healthcare_repos", "Healthcare imaging (PACS / DICOM)"},
				{"Finance / algotrading", classifyFinanceRepos, "finance_confidence", "finance_repos", "Finance / algotrading"},
			}
			for _, oc := range operatorClasses {
				hits, conf := oc.classify(repoNames)
				if conf == "" {
					continue
				}
				r.RawData[oc.rawConf] = conf
				r.RawData[oc.rawRepos] = hits
				r.Details = append(r.Details, fmt.Sprintf("%s attribution (%s): %s", oc.name, conf, strings.Join(hits, ", ")))
				severity := "info"
				switch conf {
				case "high":
					severity = "high"
				case "medium":
					severity = "medium"
				case "low":
					severity = "low"
				}
				r.Findings = append(r.Findings, Finding{
					Category: "operator-attribution",
					Title:    fmt.Sprintf("%s operator attributed via /v2/_catalog (%s confidence)", oc.titlePrefix, conf),
					Detail:   strings.Join(hits, ", "),
					Severity: severity,
				})
			}

			if len(repos) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    fmt.Sprintf("%d repos anonymously enumerable via /v2/_catalog", len(repos)),
					Severity: "medium",
				})
			}
		}
	} else {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "Docker Registry detected — catalog access denied",
			Severity: "low",
		})
	}

	return r
}

// ── Metabase ─────────────────────────────────────────────────────────
func enumMetabase(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// /api/session/properties — always public, reveals setup state + version
	if st, _, body, err := httpGET(c, b+"/api/session/properties"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["session_properties"] = m

			if v, ok := m["version"].(map[string]any); ok {
				if tag, ok := v["tag"].(string); ok {
					r.Version = tag
				}
			}

			// CVE-2023-38646: setup wizard active = pre-auth RCE via JDBC injection
			if setup, ok := m["has-user-setup"].(bool); ok && !setup {
				r.AuthStatus = "none (setup wizard active)"
				r.Findings = append(r.Findings, Finding{
					Category: "rce",
					Title:    "Metabase setup wizard active — CVE-2023-38646 pre-auth RCE via JDBC injection",
					Severity: "critical",
				})
			}

			if token, ok := m["setup-token"].(string); ok && token != "" {
				r.RawData["setup_token"] = token
				r.Findings = append(r.Findings, Finding{
					Category: "credentials",
					Title:    fmt.Sprintf("Setup token exposed: %s", token),
					Severity: "critical",
				})
			}
		}
	}

	// /api/health — version cross-check
	if st, _, body, err := httpGET(c, b+"/api/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
			if r.AuthStatus == "unknown" {
				r.AuthStatus = "login required"
			}
		}
	}

	// /api/database — lists DB connections with engine + details (requires auth, but misconfigured instances leak it)
	if st, _, body, err := httpGET(c, b+"/api/database"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			data, _ := m["data"].([]any)
			r.Details = append(r.Details, fmt.Sprintf("Databases: %d", len(data)))
			r.Findings = append(r.Findings, Finding{
				Category: "credentials",
				Title:    fmt.Sprintf("%d database connections exposed — connection strings and credentials readable", len(data)),
				Severity: "critical",
			})
			r.RawData["databases"] = data
		}
	} else if st == 401 || st == 403 {
		if r.AuthStatus == "unknown" {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// /api/user — user enumeration (auth required normally)
	if st, _, body, err := httpGET(c, b+"/api/user"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Users: %d", len(arr)))
			r.Findings = append(r.Findings, Finding{
				Category: "info",
				Title:    fmt.Sprintf("%d users enumerated without authentication", len(arr)),
				Severity: "high",
			})
		}
	}

	return r
}

// ── Apache Superset ───────────────────────────────────────────────────
func enumSuperset(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "login required"

	// /api/v1/me/ — unauth access would be anomalous
	if st, _, body, err := httpGET(c, b+"/api/v1/me/"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				r.RawData["me"] = m
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    "Superset /api/v1/me/ accessible without auth — session/role data exposed",
					Severity: "high",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
		_ = body
	}

	// Default credentials: admin/general (Superset quickstart default)
	type loginPayload struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Provider string `json:"provider"`
		Refresh  bool   `json:"refresh"`
	}
	for _, creds := range []loginPayload{
		{Username: "admin", Password: "general", Provider: "db", Refresh: true},
		{Username: "admin", Password: "admin", Provider: "db", Refresh: true},
	} {
		payload, _ := json.Marshal(creds)
		if st, _, loginBody, err := httpPOST(c, b+"/api/v1/security/login", "application/json", payload); err == nil && st == 200 {
			if m, err := parseJSON(loginBody); err == nil {
				if token, ok := m["access_token"].(string); ok && token != "" {
					r.AuthStatus = "none (default credentials)"
					r.RawData["access_token"] = token[:min(20, len(token))] + "..."
					r.Findings = append(r.Findings, Finding{
						Category: "credentials",
						Title:    fmt.Sprintf("Default credentials valid: %s/%s — full admin access", creds.Username, creds.Password),
						Severity: "critical",
					})
					break
				}
			}
		}
	}

	// /api/v1/database/ — DB connection strings (requires auth)
	if st, _, body, err := httpGET(c, b+"/api/v1/database/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			count, _ := m["count"].(float64)
			r.Details = append(r.Details, fmt.Sprintf("Databases: %d", int(count)))
			r.Findings = append(r.Findings, Finding{
				Category: "credentials",
				Title:    fmt.Sprintf("%d database connections exposed", int(count)),
				Severity: "critical",
			})
			r.RawData["databases"] = m
		}
	} else {
		_ = body
	}

	// Version from /api/v1/
	if st, _, body, err := httpGET(c, b+"/api/v1/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["api_root"] = m
		}
	} else {
		_ = body
	}

	return r
}

// ── Redash ───────────────────────────────────────────────────────────
func enumRedash(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// /api/status — always public, exposes version + worker state
	if st, _, body, err := httpGET(c, b+"/api/status"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["status"] = m
			if v, ok := m["version"].(string); ok {
				r.Version = v
			}
			if workers, ok := m["workers"].([]any); ok {
				r.Details = append(r.Details, fmt.Sprintf("Workers: %d", len(workers)))
			}
			r.AuthStatus = "login required"
		}
	}

	// /api/data_sources — connection strings (critical if unauth)
	if st, _, body, err := httpGET(c, b+"/api/data_sources"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Data sources: %d", len(arr)))
			r.Findings = append(r.Findings, Finding{
				Category: "credentials",
				Title:    fmt.Sprintf("%d data source connections exposed without authentication — connection strings readable", len(arr)),
				Severity: "critical",
			})
			r.RawData["data_sources"] = arr
		}
	} else if st == 401 || st == 403 {
		if r.AuthStatus == "unknown" {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// /api/queries — stored queries (data disclosure)
	if st, _, body, err := httpGET(c, b+"/api/queries"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if results, ok := m["results"].([]any); ok {
				r.Details = append(r.Details, fmt.Sprintf("Queries: %d", len(results)))
				r.Findings = append(r.Findings, Finding{
					Category: "info",
					Title:    fmt.Sprintf("%d stored queries exposed — query logic and table structure visible", len(results)),
					Severity: "medium",
				})
			}
		}
	} else {
		_ = body
	}

	// /api/users — user enumeration
	if st, _, body, err := httpGET(c, b+"/api/users"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Users: %d", len(arr)))
			r.Findings = append(r.Findings, Finding{
				Category: "info",
				Title:    fmt.Sprintf("%d users enumerated without authentication", len(arr)),
				Severity: "medium",
			})
		}
	} else {
		_ = body
	}

	return r
}

// ── Grafana ─────────────────────────────────────────────────────────

func enumGrafana(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/api/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["health"] = m
		}
	}

	// Datasources — unauthenticated access = credential exposure (DB URLs, API keys)
	if st, _, body, err := httpGET(c, b+"/api/datasources"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if arr, err := parseJSONArray(body); err == nil {
				r.Details = append(r.Details, fmt.Sprintf("Datasources: %d", len(arr)))
				r.Findings = append(r.Findings, Finding{
					Category: "credentials",
					Title:    fmt.Sprintf("%d datasources exposed — connection strings and keys readable", len(arr)),
					Severity: "critical",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// Anonymous access check — Grafana has a grafana.ini anon.enabled option
	if st, _, body, err := httpGET(c, b+"/api/org"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.AuthStatus = "none (anonymous access enabled)"
			r.RawData["org"] = m
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "Grafana anonymous access enabled — dashboards readable without login",
				Severity: "medium",
			})
		}
	}

	// Alert rules may contain sensitive metric names and infra topology
	if st, _, body, err := httpGET(c, b+"/api/ruler/grafana/api/v1/rules"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["alert_rules"] = m
			r.Findings = append(r.Findings, Finding{
				Category: "info",
				Title:    "Alert rules readable — internal service topology disclosed",
				Severity: "low",
			})
		}
	}

	return r
}

// ── Prometheus ──────────────────────────────────────────────────────

func enumPrometheus(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/status/runtimeinfo"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				r.Version = jStr(data, "version")
				r.RawData["runtimeinfo"] = data
			}
		}
	}

	// Config dump — may contain scrape targets with credentials in URLs
	if st, _, body, err := httpGET(c, b+"/api/v1/status/config"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				cfg := jStr(data, "yaml")
				scanSecrets(cfg, &r)
				r.Findings = append(r.Findings, Finding{
					Category: "config",
					Title:    "Full Prometheus config readable — scrape targets and credentials exposed",
					Detail:   "Check for basic_auth, bearer_token, and tls_config entries in the YAML dump.",
					Severity: "high",
				})
			}
		}
	}

	// Targets — full internal service map
	if st, _, body, err := httpGET(c, b+"/api/v1/targets"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				active := jArray(data, "activeTargets")
				r.Details = append(r.Details, fmt.Sprintf("Active scrape targets: %d", len(active)))
				r.RawData["target_count"] = len(active)
				if len(active) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "topology",
						Title:    fmt.Sprintf("%d active scrape targets — full internal service map readable", len(active)),
						Severity: "medium",
					})
				}
			}
		}
	}

	// Alert rules
	if st, _, body, err := httpGET(c, b+"/api/v1/rules"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["rules"] = m
		}
	}

	return r
}

// ── etcd ─────────────────────────────────────────────────────────────

func enumEtcd(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "etcdserver")
			r.RawData["version"] = m
		}
	}

	if st, _, body, err := httpGET(c, b+"/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
			r.AuthStatus = "none"
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "etcd unauthenticated — full cluster secret disclosure",
				Detail:   "All Kubernetes secrets, service account tokens, kubeconfig data, and TLS certs readable via /v3/kv/range. Effectively cluster takeover.",
				Severity: "critical",
			})
		}
	}

	// Key dump via gRPC-gateway (etcd v3 HTTP API)
	// POST /v3/kv/range with empty key range returns all keys
	if st, _, body, err := httpGET(c, b+"/v3/kv/range"); err == nil && st != 404 {
		r.RawData["v3_api_accessible"] = true
		r.Details = append(r.Details, fmt.Sprintf("v3 KV API: HTTP %d", st))
		if st == 200 {
			if m, err := parseJSON(body); err == nil {
				if kvs := jArray(m, "kvs"); kvs != nil {
					r.Details = append(r.Details, fmt.Sprintf("Keys returned: %d", len(kvs)))
					scanSecrets(string(body), &r)
				}
			}
		}
	}

	// Members — cluster topology
	if st, _, body, err := httpGET(c, b+"/v3/cluster/member/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			members := jArray(m, "members")
			r.Details = append(r.Details, fmt.Sprintf("Cluster members: %d", len(members)))
			r.RawData["members"] = members
		}
	}

	return r
}

// ── MinIO ────────────────────────────────────────────────────────────

func enumMinIO(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, _, err := httpGET(c, b+"/minio/health/live"); err == nil && st == 200 {
		r.AuthStatus = "S3 API (check bucket policies)"
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "MinIO S3 API reachable",
			Detail:   "Check anonymous bucket policies. Anonymous GET/LIST on buckets exposes stored model artifacts, training data, and MLflow experiment artifacts.",
			Severity: "medium",
		})
	}

	// S3 list-buckets (root /) — requires auth on MinIO by default,
	// but anonymous access is configurable per-bucket
	if st, _, body, err := httpGET(c, b+"/"); err == nil {
		if st == 200 && strings.Contains(strings.ToLower(string(body)), "<listallmybucketsresult") {
			r.AuthStatus = "none — anonymous bucket listing"
			r.Findings = append(r.Findings, Finding{
				Category: "data",
				Title:    "Anonymous bucket listing enabled — all buckets enumerable",
				Severity: "critical",
			})
		} else if strings.Contains(strings.ToLower(string(body)), "accessdenied") {
			r.AuthStatus = "required"
		}
	}

	return r
}

// ── LangGraph Server ─────────────────────────────────────────────────
//
// ── Agno ─────────────────────────────────────────────────────────────
// Agno (formerly Phidata) playground server. Ships with no auth. /agents
// returns a top-level JSON array of agent objects. Each agent carries its
// name, optional description, and a tools.tools[] array whose member names
// reveal the data sources the agent can reach (e.g. query_postgres_agent_tool,
// get_fireflies_transcripts). Insight #64: the manifest IS the finding.

func enumAgno(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	st, _, body, err := httpGET(c, b+"/agents")
	if err != nil || st != 200 {
		r.Findings = append(r.Findings, Finding{
			Category: "auth", Title: "Agno playground API open — /agents unreachable",
			Severity: "high",
		})
		return r
	}

	var agents []map[string]interface{}
	if jsonErr := json.Unmarshal(body, &agents); jsonErr != nil {
		return r
	}

	r.Details = append(r.Details, fmt.Sprintf("Agents: %d", len(agents)))

	type kwClass struct {
		keywords []string
		category string
		label    string
		severity string
	}
	classes := []kwClass{
		{[]string{"postgres", "mysql", "mongodb", "elasticsearch", "redis", "sqlite", "database", "sql"}, "database", "database", "critical"},
		{[]string{"email", "gmail", "outlook", "slack", "fireflies", "transcript"}, "communications", "email/communications", "critical"},
		{[]string{"contract", "sow", "brd"}, "documents", "contract/document", "critical"},
		{[]string{"asana", "smartsheet", "salesforce", "jira", "hubspot"}, "project_mgmt", "project management", "high"},
	}
	seen := map[string]bool{}

	for _, agent := range agents {
		name := jStr(agent, "name")
		blob := strings.ToLower(name) + " " + strings.ToLower(jStr(agent, "description"))

		var toolNames []string
		if toolsObj, ok := agent["tools"].(map[string]interface{}); ok {
			if toolArr, ok := toolsObj["tools"].([]interface{}); ok {
				for _, t := range toolArr {
					if tm, ok := t.(map[string]interface{}); ok {
						tn := jStr(tm, "name")
						toolNames = append(toolNames, tn)
						blob += " " + strings.ToLower(tn)
					}
				}
			}
		}

		if len(toolNames) > 0 {
			r.Details = append(r.Details, fmt.Sprintf("  %s [%s]", name, strings.Join(toolNames, ", ")))
		} else {
			r.Details = append(r.Details, fmt.Sprintf("  %s", name))
		}

		for _, cls := range classes {
			if seen[cls.category] {
				continue
			}
			for _, kw := range cls.keywords {
				if strings.Contains(blob, kw) {
					seen[cls.category] = true
					r.Findings = append(r.Findings, Finding{
						Category: cls.category,
						Title:    fmt.Sprintf("Agent manifest names %s access: %s", cls.label, name),
						Detail:   fmt.Sprintf("keyword match: %q", kw),
						Severity: cls.severity,
					})
					if cls.severity == "critical" {
						r.RiskLevel = "critical"
					}
					break
				}
			}
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "auth",
		Title:    fmt.Sprintf("%d agents enumerable without credentials", len(agents)),
		Severity: "high",
	})

	return r
}

// LangGraph Server is LangChain's stateful agent execution runtime.
// Survey-38 (2026-05-25): 16/16 hosts unauthenticated. Partial-auth failure
// class confirmed: list endpoints (/assistants, /threads) auth-gated on some
// operators (Stock.ai / EMOR AI) while individual resource endpoints
// (/threads/{id}, /runs/{id}) remain open. Full-open installs expose the
// complete agent execution context: thread state, assistant configs (which
// embed system prompts + tool definitions), and run I/O history.

func enumLangGraph(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// /info — canonical identity + version endpoint on LangGraph Server.
	// Returns {"version": "...", "license_plan": "...", ...}.
	if st, _, body, err := httpGET(c, b+"/info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if v := jStr(m, "version"); v != "" {
				r.Version = v
			}
			if plan := jStr(m, "license_plan"); plan != "" {
				r.Details = append(r.Details, fmt.Sprintf("License plan: %s", plan))
			}
		}
	}

	// /assistants — list configured assistants (agent definitions).
	// Each assistant record embeds graph_id, config, and metadata — operator's
	// agent topology and system-prompt configuration are exposed here.
	if st, _, body, err := httpGET(c, b+"/assistants"); err == nil {
		switch st {
		case 200:
			r.AuthStatus = "none"
			var items []interface{}
			if json.Unmarshal(body, &items) == nil {
				r.Details = append(r.Details, fmt.Sprintf("Assistants exposed: %d", len(items)))
				r.RawData["assistants_count"] = len(items)
			}
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "LangGraph Server /assistants readable without authentication",
				Detail:   "Assistant configurations are world-readable. Each record embeds graph_id, system prompt config, and tool definitions. Reveals the operator's full agent topology.",
				Severity: "high",
			})
		case 401, 403:
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// /threads — list agent threads (conversation/execution state).
	// Thread records carry checkpoint state, which includes message history
	// and intermediate tool call outputs.
	if st, _, body, err := httpGET(c, b+"/threads"); err == nil {
		switch st {
		case 200:
			r.AuthStatus = "none"
			var items []interface{}
			if json.Unmarshal(body, &items) == nil {
				r.Details = append(r.Details, fmt.Sprintf("Threads exposed: %d", len(items)))
				r.RawData["threads_count"] = len(items)
			}
			r.Findings = append(r.Findings, Finding{
				Category: "data",
				Title:    "LangGraph Server /threads readable without authentication",
				Detail:   "Agent thread list is world-readable. Thread state includes full message history and tool call I/O from every agent execution — user prompts and model outputs exposed.",
				Severity: "high",
			})
		case 401, 403:
			if r.AuthStatus == "unknown" {
				r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
			}
		}
	}

	// /runs — list recent agent runs across all threads.
	// Present on some deployments; reveals execution volume and timing.
	if st, _, body, err := httpGET(c, b+"/runs"); err == nil && st == 200 {
		r.AuthStatus = "none"
		var items []interface{}
		if json.Unmarshal(body, &items) == nil {
			r.Details = append(r.Details, fmt.Sprintf("Runs exposed: %d", len(items)))
			r.RawData["runs_count"] = len(items)
		}
		r.Findings = append(r.Findings, Finding{
			Category: "data",
			Title:    "LangGraph Server /runs readable without authentication",
			Detail:   "Agent run list is world-readable. Reveals execution cadence, run status, and cross-thread activity.",
			Severity: "medium",
		})
	}

	// Partial-auth detection: if /assistants or /threads returned 401/403 but
	// /info or /runs was open, flag the partial-auth pattern explicitly.
	if r.AuthStatus != "none" && r.AuthStatus != "unknown" {
		// At least one list endpoint is auth-gated; confirm whether the root
		// is still open (partial-auth failure class from survey-38).
		if st, _, _, err := httpGET(c, b+"/"); err == nil && st == 200 {
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "LangGraph Server partial-auth: root open, list endpoints gated",
				Detail:   "Root endpoint returns 200 unauthenticated while /assistants or /threads require auth. Survey-38 confirmed individual resource endpoints (/threads/{id}, /runs/{id}) may still be accessible without auth when list endpoints are gated — partial-auth failure class.",
				Severity: "medium",
			})
		}
	}

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "auth required"
	}

	return r
}

// ── n8n ──────────────────────────────────────────────────────────────

func enumN8n(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Unauthenticated workflow enumeration
	if st, _, body, err := httpGET(c, b+"/rest/active-workflows"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				workflows := jArray(m, "data")
				r.Details = append(r.Details, fmt.Sprintf("Active workflows: %d", len(workflows)))
				r.Findings = append(r.Findings, Finding{
					Category: "rce",
					Title:    fmt.Sprintf("n8n unauthenticated — %d active workflows — RCE by design", len(workflows)),
					Detail:   "n8n workflow nodes execute arbitrary JavaScript and shell commands. Write access = unrestricted code execution. No CVE; this is intended behavior.",
					Severity: "critical",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// Credentials endpoint — provider API keys stored in n8n
	if st, _, body, err := httpGET(c, b+"/rest/credentials"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			creds := jArray(m, "data")
			if len(creds) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "credentials",
					Title:    fmt.Sprintf("%d stored credentials accessible — provider API keys exposed", len(creds)),
					Severity: "critical",
				})
			}
		}
	}

	return r
}

// ── Temporal Web ─────────────────────────────────────────────────────

// sensitiveTaskQueuePatterns covers task queue name substrings that indicate
// high-sensitivity workflow workloads (payments, PII, medical, identity).
var sensitiveTaskQueuePatterns = []string{
	"payment", "finance", "trade", "kyc", "medical", "health",
	"pii", "user", "customer",
}

func hasSensitiveQueue(queue string) bool {
	lower := strings.ToLower(queue)
	for _, p := range sensitiveTaskQueuePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func enumTemporal(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Step 1: cluster-info — identity + version
	if st, _, body, err := httpGET(c, b+"/api/v1/cluster-info"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			if name := jStr(m, "clusterName"); name != "" {
				r.Details = append(r.Details, "Cluster: "+name)
				r.RawData["clusterName"] = name
			}
			if ver := jStr(m, "serverVersion"); ver != "" {
				r.Version = ver
				r.Details = append(r.Details, "Server version: "+ver)
			}
			if clients := jMap(m, "supportedClients"); clients != nil {
				var clist []string
				for k := range clients {
					clist = append(clist, k)
				}
				r.Details = append(r.Details, "Supported clients: "+strings.Join(clist, ", "))
			}
		}
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Temporal cluster-info readable without authentication",
			Detail:   "/api/v1/cluster-info exposes cluster name, server version, and supported SDK client list without auth.",
			Severity: "medium",
		})
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	// Step 2: namespaces — list + count
	var namespaceNames []string
	if st, _, body, err := httpGET(c, b+"/api/v1/namespaces"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			nsList := jArray(m, "namespaces")
			r.Details = append(r.Details, fmt.Sprintf("Namespaces: %d", len(nsList)))
			r.RawData["namespace_count"] = len(nsList)
			for _, ns := range nsList {
				if nsMap, ok := ns.(map[string]interface{}); ok {
					// Namespace records nest name under namespaceInfo.name
					if info := jMap(nsMap, "namespaceInfo"); info != nil {
						if name := jStr(info, "name"); name != "" {
							namespaceNames = append(namespaceNames, name)
						}
					}
					// Some versions expose name at top level
					if name := jStr(nsMap, "name"); name != "" && !contains(namespaceNames, name) {
						namespaceNames = append(namespaceNames, name)
					}
				}
			}
			if len(namespaceNames) > 0 {
				r.Details = append(r.Details, "Namespace names: "+strings.Join(namespaceNames, ", "))
				r.RawData["namespace_names"] = namespaceNames
			}
		}
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    fmt.Sprintf("Temporal namespace list exposed — %d namespace(s)", len(namespaceNames)),
			Detail:   "Namespace enumeration reveals the operator's workflow domains. Each namespace isolates workflow executions; their names often reflect business functions (payments, user-onboarding, etc.).",
			Severity: "high",
		})
	}

	// Step 3: per-namespace workflow sampling (up to 3 namespaces)
	var allWorkflowTypes []string
	var allTaskQueues []string
	runningWithSensitiveQueue := false

	cap := 3
	if len(namespaceNames) < cap {
		cap = len(namespaceNames)
	}
	for _, ns := range namespaceNames[:cap] {
		wfURL := fmt.Sprintf("%s/api/v1/namespaces/%s/workflows?pageSize=5", b, ns)
		if st, _, body, err := httpGET(c, wfURL); err == nil && st == 200 {
			if m, err := parseJSON(body); err == nil {
				executions := jArray(m, "executions")
				for _, ex := range executions {
					exMap, ok := ex.(map[string]interface{})
					if !ok {
						continue
					}
					// execution.execution.workflowId
					if exec := jMap(exMap, "execution"); exec != nil {
						if wfID := jStr(exec, "workflowId"); wfID != "" {
							r.Details = append(r.Details, fmt.Sprintf("[%s] workflow: %s", ns, wfID))
						}
					}
					// execution.type.name
					if wfType := jMap(exMap, "type"); wfType != nil {
						if typeName := jStr(wfType, "name"); typeName != "" && !contains(allWorkflowTypes, typeName) {
							allWorkflowTypes = append(allWorkflowTypes, typeName)
						}
					}
					// execution.taskQueue (present on some API versions)
					if tq := jStr(exMap, "taskQueue"); tq != "" && !contains(allTaskQueues, tq) {
						allTaskQueues = append(allTaskQueues, tq)
					}
					// status
					status := jStr(exMap, "status")
					if status == "Running" || status == "WORKFLOW_EXECUTION_STATUS_RUNNING" {
						// Check task queue for sensitive patterns
						if tq := jStr(exMap, "taskQueue"); tq != "" && hasSensitiveQueue(tq) {
							runningWithSensitiveQueue = true
						}
					}
				}
				if len(executions) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "data",
						Title:    fmt.Sprintf("Temporal workflows readable in namespace %q — %d execution(s) sampled", ns, len(executions)),
						Detail:   "Workflow execution history is world-readable. Records include workflow IDs, types, run status, and task queue names — reveals business process topology and active workload identity.",
						Severity: "high",
					})
				}
			}
		}
	}

	if len(allWorkflowTypes) > 0 {
		r.Details = append(r.Details, "Workflow types seen: "+strings.Join(allWorkflowTypes, ", "))
		r.RawData["workflow_types"] = allWorkflowTypes
	}
	if len(allTaskQueues) > 0 {
		r.Details = append(r.Details, "Task queues seen: "+strings.Join(allTaskQueues, ", "))
		r.RawData["task_queues"] = allTaskQueues
	}

	// Auto-CRITICAL: running workflows on sensitive-named task queues
	if runningWithSensitiveQueue {
		r.Findings = append(r.Findings, Finding{
			Category: "data",
			Title:    "CRITICAL: running workflows on sensitive task queue (payment/finance/kyc/medical/pii/user/customer)",
			Detail:   "At least one RUNNING workflow is assigned to a task queue whose name matches a high-sensitivity pattern. These task queues handle business-critical or regulated workloads. Unauthenticated read access to running workflow state likely exposes PII, financial data, or regulated health information.",
			Severity: "critical",
		})
	}

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "auth required"
	}

	return r
}

// ── Cadence Web ──────────────────────────────────────────────────────

func enumCadence(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Health
	if st, _, body, err := httpGET(c, b+"/api/v1/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
		}
	}

	// Domains list
	if st, _, body, err := httpGET(c, b+"/api/v1/domains"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			domains := jArray(m, "domains")
			var domainNames []string
			for _, d := range domains {
				if dm, ok := d.(map[string]interface{}); ok {
					if info := jMap(dm, "domainInfo"); info != nil {
						if name := jStr(info, "name"); name != "" {
							domainNames = append(domainNames, name)
						}
					}
				}
			}
			r.Details = append(r.Details, fmt.Sprintf("Domains: %d", len(domains)))
			if len(domainNames) > 0 {
				r.Details = append(r.Details, "Domain names: "+strings.Join(domainNames, ", "))
				r.RawData["domain_names"] = domainNames
			}
		}
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Cadence domain list readable without authentication",
			Detail:   "/api/v1/domains exposes workflow domain names. Cadence is Uber's durable execution platform; exposed domains reveal workflow topology and operator business functions.",
			Severity: "high",
		})
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	// Cluster info
	if st, _, body, err := httpGET(c, b+"/api/v1/clusters"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			clusters := jArray(m, "clusters")
			r.Details = append(r.Details, fmt.Sprintf("Clusters: %d", len(clusters)))
			r.RawData["cluster_count"] = len(clusters)
		}
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Cadence cluster topology readable without authentication",
			Detail:   "/api/v1/clusters exposes cluster membership and replication topology.",
			Severity: "medium",
		})
	}

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "auth required"
	}

	return r
}

// contains is a small helper to check membership in a string slice.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func enumTTS(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Service info from root
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if name := jStr(m, "name"); name != "" {
				r.Details = append(r.Details, "Server: "+name)
			}
			if model := jStr(m, "model"); model != "" {
				r.Version = model
				r.Details = append(r.Details, "Model: "+model)
			}
		}
	}

	// Voice list
	if st, _, body, err := httpGET(c, b+"/v1/audio/voices"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Voices available: %d", len(arr)))
		} else if m, err := parseJSON(body); err == nil {
			voices := jArray(m, "voices")
			r.Details = append(r.Details, fmt.Sprintf("Voices available: %d", len(voices)))
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "exposure",
		Title:    "AI TTS server unauthenticated — /v1/audio/speech open",
		Detail:   "OpenAI-compatible TTS endpoint accessible without credentials. Attacker can generate arbitrary speech, consume compute, potentially abuse voice cloning if enabled.",
		Severity: "medium",
	})
	return r
}

func enumSGLang(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Model info — SGLang-specific endpoint
	if st, _, body, err := httpGET(c, b+"/get_model_info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if v := jStr(m, "model_path"); v != "" {
				r.Details = append(r.Details, "Model: "+v)
				r.Version = v
			}
			if v := jStr(m, "is_generation"); v != "" {
				r.Details = append(r.Details, "Generation mode: "+v)
			}
		}
	}

	// OpenAI-compat model list
	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "data")
			r.Details = append(r.Details, fmt.Sprintf("Models served: %d", len(models)))
			for _, mdl := range models {
				if mm, ok := mdl.(map[string]interface{}); ok {
					if id, ok := mm["id"].(string); ok {
						r.Details = append(r.Details, "  - "+id)
					}
				}
			}
		}
	}

	// Server info
	if st, _, body, err := httpGET(c, b+"/get_server_info"); err == nil && st == 200 {
		r.RawData["server_info"] = json.RawMessage(body)
	}

	if r.AuthStatus == "none" {
		r.Findings = append(r.Findings, Finding{
			Category: "exposure",
			Title:    "SGLang inference server unauthenticated",
			Detail:   "Full model inference available without credentials. Attacker can enumerate loaded models, run arbitrary prompts, and consume compute.",
			Severity: "high",
		})
	}
	return r
}

func enumVLLM(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				models := jArray(m, "data")
				r.Details = append(r.Details, fmt.Sprintf("Models served: %d", len(models)))
				for _, mdl := range models {
					if mm, ok := mdl.(map[string]interface{}); ok {
						if id, ok := mm["id"].(string); ok {
							r.Details = append(r.Details, "  - "+id)
						}
					}
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "exposure",
				Title:    "vLLM OpenAI-compatible API unauthenticated",
				Detail:   "Full inference access without credentials. /v1/completions and /v1/chat/completions accessible.",
				Severity: "high",
			})
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// Check completions endpoint directly
	if st, _, _, err := httpGET(c, b+"/v1/completions"); err == nil && st != 404 {
		r.Details = append(r.Details, fmt.Sprintf("/v1/completions → HTTP %d", st))
	}
	return r
}

// ── Open Directory ──────────────────────────────────────────────────

func enumOpenDirectory(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		bodyStr := string(body)

		// Count entries in directory listing
		entries := strings.Count(bodyStr, "<li>") + strings.Count(bodyStr, `href="`)
		if entries > 2 {
			r.Details = append(r.Details, fmt.Sprintf("~%d entries visible", entries/2))
		}

		// Scan for high-value filenames/paths
		highValue := []struct {
			needle   string
			severity string
			title    string
		}{
			{".env", "critical", ".env file exposed — may contain credentials"},
			{"docker-compose", "high", "docker-compose file exposed — reveals service topology"},
			{".ssh/", "critical", "SSH directory exposed"},
			{"id_rsa", "critical", "SSH private key exposed"},
			{"credentials", "critical", "Credentials file exposed"},
			{".claude/", "high", "Claude AI config directory exposed (.claude/)"},
			{".openhands/", "high", "OpenHands AI agent config exposed (.openhands/)"},
			{"CLAUDE.md", "high", "CLAUDE.md instructions file exposed — may contain sensitive directives"},
			{"api_key", "critical", "API key file exposed"},
			{"secret", "high", "Secret file exposed"},
			{"backup", "medium", "Backup file/directory exposed"},
			{".git/", "high", ".git directory exposed — full source history accessible"},
			{"Dockerfile", "medium", "Dockerfile exposed — reveals build environment"},
			{"requirements.txt", "low", "Python requirements file exposed"},
			{"package.json", "low", "Node.js package manifest exposed"},
		}

		for _, hv := range highValue {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(hv.needle)) {
				r.Findings = append(r.Findings, Finding{
					Category: "exposure",
					Title:    hv.title,
					Detail:   fmt.Sprintf("Filename/path '%s' found in directory listing", hv.needle),
					Severity: hv.severity,
				})
			}
		}

		scanSecrets(bodyStr, &r)
	}

	r.Findings = append(r.Findings, Finding{
		Category: "access",
		Title:    "Unauthenticated directory listing — full filesystem tree browsable",
		Detail:   "Server serving files with no authentication; all listed contents are downloadable.",
		Severity: "high",
	})

	return r
}

// ── OpenHands ───────────────────────────────────────────────────────

func enumOpenHands(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Detect admin console vs. regular UI
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if strings.Contains(strings.ToLower(string(body)), "admin console") {
			r.Details = append(r.Details, "Variant: Admin Console")
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "OpenHands Admin Console — unclaimed setup wizard accessible",
				Detail:   "First visitor can configure the admin account with no prior credentials.",
				Severity: "critical",
			})
			r.AuthStatus = "none"
		}
	}

	// Try settings/config API — unauthenticated on default installs
	if st, _, body, err := httpGET(c, b+"/api/v1/settings"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			r.RawData["settings"] = m
		}
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "OpenHands /api/v1/settings accessible without authentication",
			Severity: "critical",
		})
	} else if r.AuthStatus == "unknown" {
		if st == 401 || st == 403 {
			r.AuthStatus = "auth required"
		}
	}

	// Pull agent list
	if st, _, body, err := httpGET(c, b+"/api/v1/agents"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if agents := jArray(m, "agents"); agents != nil {
				r.Details = append(r.Details, fmt.Sprintf("Agents available: %d", len(agents)))
			}
		}
	}

	return r
}

// ── AutoGen Studio ──────────────────────────────────────────────────

func enumAutoGenStudio(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Version from /api/version
	if st, _, body, err := httpGET(c, b+"/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				r.Version = jStr(data, "version")
			}
		}
	}

	// AutoGen Studio's data routes require a user_id query param. With the
	// optional AuthMiddleware disabled (the default), user_id is just an
	// arbitrary string anyone can supply — there is no per-user secret.
	// A 200 with a data array == fully unauthenticated.
	probeUID := "?user_id=guest@guest.com"

	// /api/teams — agent team definitions. This is the crown-jewel route:
	// team configs embed the tool definitions, and AutoGen tool configs
	// frequently carry API keys / credentials inline.
	if st, _, body, err := httpGET(c, b+"/api/teams/"+probeUID); err == nil {
		switch st {
		case 200:
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				if teams := jArray(m, "data"); teams != nil {
					r.Details = append(r.Details, fmt.Sprintf("Agent teams readable: %d", len(teams)))
					r.RawData["teams_count"] = len(teams)
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "AutoGen Studio /api/teams readable without authentication",
				Detail:   "Agent team definitions are world-readable. AutoGen team configs embed tool definitions that frequently carry inline API keys and credentials.",
				Severity: "critical",
			})
		case 401, 403:
			r.AuthStatus = "auth required"
		}
	}

	// /api/settings — per-user settings blob, can include model client
	// configuration (which carries provider API keys on some setups).
	if st, _, body, err := httpGET(c, b+"/api/settings/"+probeUID); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			r.RawData["settings"] = m
		}
		r.Findings = append(r.Findings, Finding{
			Category: "data",
			Title:    "AutoGen Studio /api/settings readable without authentication",
			Detail:   "Model-client configuration is world-readable; may expose provider API keys depending on operator setup.",
			Severity: "high",
		})
	}

	// /api/sessions — conversation/run history. Leaks prompts + outputs.
	if st, _, body, err := httpGET(c, b+"/api/sessions/"+probeUID); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			if sessions := jArray(m, "data"); sessions != nil {
				r.Details = append(r.Details, fmt.Sprintf("Sessions readable: %d", len(sessions)))
			}
		}
		r.Findings = append(r.Findings, Finding{
			Category: "data",
			Title:    "AutoGen Studio /api/sessions readable without authentication",
			Detail:   "Agent conversation history is world-readable — prompts, intermediate reasoning, and outputs.",
			Severity: "high",
		})
	}

	// /api/gallery — component gallery (custom tools/agents shared on the
	// instance). Lower severity but confirms the data tier is open.
	if st, _, _, err := httpGET(c, b+"/api/gallery/"+probeUID); err == nil && st == 200 {
		r.Details = append(r.Details, "Gallery endpoint readable")
	}

	if r.AuthStatus == "unknown" {
		// /api/version returned 200 (FP matched) but no data route was
		// readable — likely AuthMiddleware is enabled.
		r.AuthStatus = "auth required"
	}

	if r.AuthStatus == "none" {
		r.Findings = append(r.Findings, Finding{
			Category: "context",
			Title:    "AutoGen Studio stores agent definitions, tool configs, and run history",
			Detail:   "An exposed AutoGen Studio gives an attacker the agent definitions, the tool configs (which may embed credentials), and the conversation history. If the instance can execute agents, the attacker also inherits the agent's autonomy.",
			Severity: "info",
		})
	}

	return r
}

// ── Mem0 ────────────────────────────────────────────────────────────

func enumMem0(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Pull OpenAPI spec for version
	if st, _, body, err := httpGET(c, b+"/openapi.json"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if info := jMap(m, "info"); info != nil {
				r.Version = jStr(info, "version")
			}
			r.RawData["openapi"] = m
		}
	}

	// Probe memory endpoint — Mem0 default requires Authorization: Token <key>
	if st, _, body, err := httpGET(c, b+"/v1/memories?user_id=test"); err == nil {
		switch st {
		case 200:
			r.AuthStatus = "none"
			count := 0
			if m, err := parseJSON(body); err == nil {
				if arr := jArray(m, "memories"); arr != nil {
					count = len(arr)
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    fmt.Sprintf("Mem0 /v1/memories unauthenticated — %d entries accessible", count),
				Detail:   "AI agent memory store readable without API key; may contain conversation history, user PII, or agent state.",
				Severity: "critical",
			})
		case 401, 403:
			r.AuthStatus = "auth required"
		default:
			r.AuthStatus = "unknown"
		}
	}

	// Check /v1/users for user enumeration
	if st, _, body, err := httpGET(c, b+"/v1/users"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if users := jArray(m, "users"); users != nil {
				r.Details = append(r.Details, fmt.Sprintf("Users in memory store: %d", len(users)))
			}
		}
		_ = body
	}

	return r
}

// ── Coolify ─────────────────────────────────────────────────────────

func enumCoolify(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Coolify returns JSON 401 {"message":"Unauthenticated."} for API clients.
	// A 200 at /api/v1/settings would mean auth is disabled (extremely unusual).
	if st, _, body, err := httpGET(c, b+"/api/v1/settings"); err == nil {
		switch st {
		case 200:
			if m, err := parseJSON(body); err == nil {
				r.RawData["settings"] = m
				if jStr(m, "registration_enabled") == "true" {
					r.AuthStatus = "open registration"
					r.Findings = append(r.Findings, Finding{
						Category: "access",
						Title:    "Coolify open registration — anyone can create an admin account",
						Severity: "high",
					})
				} else {
					r.AuthStatus = "auth required"
				}
			}
		case 401, 403:
			r.AuthStatus = "auth required"
		}
	}

	// Check if registration is open on the login page (HTML mode, no JSON Accept)
	if st, _, body, err := httpGET(c, b+"/login"); err == nil && st == 200 {
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "register") && !strings.Contains(bodyStr, "disabled") {
			r.AuthStatus = "open registration"
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "Coolify self-registration enabled — public account creation allowed",
				Severity: "high",
			})
		} else if r.AuthStatus == "unknown" {
			r.AuthStatus = "auth required"
		}
	}

	return r
}

// ── Clawdbot ─────────────────────────────────────────────────────────

func enumClawdbot(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Extract assistant name and avatar from the SPA index HTML
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		bodyStr := string(body)
		if idx := strings.Index(bodyStr, `__CLAWDBOT_ASSISTANT_NAME__="`); idx >= 0 {
			rest := bodyStr[idx+len(`__CLAWDBOT_ASSISTANT_NAME__="`):]
			if end := strings.IndexByte(rest, '"'); end > 0 {
				r.Details = append(r.Details, "Assistant name: "+rest[:end])
			}
		}
		if idx := strings.Index(bodyStr, `__CLAWDBOT_ASSISTANT_AVATAR__="`); idx >= 0 {
			rest := bodyStr[idx+len(`__CLAWDBOT_ASSISTANT_AVATAR__="`):]
			if end := strings.IndexByte(rest, '"'); end > 0 {
				r.Details = append(r.Details, "Avatar: "+rest[:end])
			}
		}
	}

	// Probe the WebSocket gateway — the SPA is a catch-all so HTTP paths are
	// useless for auth detection; the real backend is a WS gateway.
	useTLS := strings.HasPrefix(svc.BaseURL, "https://")
	authStatus, wsDetail := clawdbotWSProbe(svc.Host, svc.Port, useTLS, 6*time.Second)
	r.AuthStatus = authStatus
	if wsDetail != "" {
		r.Details = append(r.Details, wsDetail)
	}

	switch authStatus {
	case "none":
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Clawdbot gateway accessible without authentication",
			Detail:   "WebSocket gateway accepts connections without a valid token.",
			Severity: "critical",
		})
	case "token required":
		// Expected secure state — gateway requires pre-issued token
	}

	r.Findings = append(r.Findings, Finding{
		Category: "exposure",
		Title:    "Clawdbot Control UI exposed to internet",
		Detail:   "OpenClaw management interface accessible publicly; intended for Tailscale/VPN-only access.",
		Severity: "medium",
	})
	r.Findings = append(r.Findings, checkGeneric(c, svc)...)
	return r
}

// clawdbotWSProbe performs a minimal WebSocket handshake and connect probe
// to determine the Clawdbot gateway auth posture without external dependencies.
func clawdbotWSProbe(host string, port int, useTLS bool, timeout time.Duration) (authStatus, detail string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return "unknown", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Valid 16-byte base64 key for the WS upgrade handshake.
	rawKey := base64.StdEncoding.EncodeToString([]byte("clawdbotprobe123"))

	handshake := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		addr, rawKey,
	)
	if _, err := conn.Write([]byte(handshake)); err != nil {
		return "unknown", ""
	}

	// The 101 response and the first WS frame (challenge) often arrive in the
	// same TCP segment. Read everything available, split on \r\n\r\n.
	initial := make([]byte, 4096)
	n, _ := conn.Read(initial)
	initial = initial[:n]

	sep := []byte("\r\n\r\n")
	idx := strings.Index(string(initial), "\r\n\r\n")
	if idx < 0 || !strings.Contains(string(initial[:idx+4]), "101") {
		return "unknown", ""
	}
	_ = sep

	// Bytes after the HTTP headers are the first WS frame(s).
	buf := newWSBuffer(conn, initial[idx+4:])

	challengeFrame, err := buf.readFrame()
	if err != nil || !strings.Contains(string(challengeFrame), "connect.challenge") {
		return "unknown", ""
	}
	var challengeMsg struct {
		Payload struct {
			Nonce string `json:"nonce"`
			Ts    int64  `json:"ts"`
		} `json:"payload"`
	}
	json.Unmarshal(challengeFrame, &challengeMsg)
	nonce := challengeMsg.Payload.Nonce

	// Generate an ephemeral Ed25519 keypair and sign the challenge.
	// The client-side JS uses Ed25519 (SHA-512 key expansion) matching stdlib.
	// A fresh unregistered keypair lets us reach the token check, not just schema validation.
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubBytes := []byte(pubKey)
	devIDBytes := sha256.Sum256(pubBytes)
	deviceID := fmt.Sprintf("%x", devIDBytes)
	pubB64 := base64.RawURLEncoding.EncodeToString(pubBytes)
	signedAt := challengeMsg.Payload.Ts + 1
	scopes := "operator.admin,operator.approvals,operator.pairing"
	msgToSign := fmt.Sprintf("v2|%s|clawdbot-control-ui|webchat|operator|%s|%d||%s",
		deviceID, scopes, signedAt, nonce)
	sig := ed25519.Sign(privKey, []byte(msgToSign))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	connectPayload := fmt.Sprintf(
		`{"type":"req","id":"00000000-0000-0000-0000-000000000001","method":"connect","params":{`+
			`"minProtocol":3,"maxProtocol":3,`+
			`"client":{"id":"clawdbot-control-ui","version":"dev","platform":"web","mode":"webchat","instanceId":"probe"},`+
			`"role":"operator","scopes":["operator.admin","operator.approvals","operator.pairing"],`+
			`"device":{"id":%q,"publicKey":%q,"signature":%q,"signedAt":%d,"nonce":%q},`+
			`"caps":[],"auth":{},"userAgent":"aimap/1.0","locale":"en-US"}}`,
		deviceID, pubB64, sigB64, signedAt, nonce,
	)
	if err := wsSendTextFrame(conn, []byte(connectPayload)); err != nil {
		return "unknown", ""
	}

	resp, err := buf.readFrame()
	if err != nil {
		return "unknown", ""
	}

	var reply struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp, &reply); err != nil {
		return "unknown", ""
	}

	if reply.OK {
		return "none", "WS gateway: open (no token required)"
	}
	msg := reply.Error.Message
	if strings.Contains(msg, "token missing") || strings.Contains(msg, "unauthorized") {
		return "token required", "WS gateway: " + truncStr(msg, 60)
	}
	return "restricted", "WS gateway: " + truncStr(msg, 60)
}

// wsBuffer wraps a net.Conn with a pre-read buffer for parsing WS frames.
type wsBuffer struct {
	conn net.Conn
	buf  []byte
}

func newWSBuffer(conn net.Conn, initial []byte) *wsBuffer {
	return &wsBuffer{conn: conn, buf: append([]byte(nil), initial...)}
}

func (w *wsBuffer) read(p []byte) (int, error) {
	if len(w.buf) >= len(p) {
		copy(p, w.buf[:len(p)])
		w.buf = w.buf[len(p):]
		return len(p), nil
	}
	// Drain buffer first, then read from conn
	n := copy(p, w.buf)
	w.buf = w.buf[:0]
	if n < len(p) {
		m, err := w.conn.Read(p[n:])
		return n + m, err
	}
	return n, nil
}

func (w *wsBuffer) readN(n int) ([]byte, error) {
	buf := make([]byte, n)
	total := 0
	for total < n {
		got, err := w.read(buf[total:])
		total += got
		if err != nil {
			return buf[:total], err
		}
	}
	return buf, nil
}

func (w *wsBuffer) readFrame() ([]byte, error) {
	hdr, err := w.readN(2)
	if err != nil {
		return nil, err
	}
	plen := int(hdr[1] & 0x7f)
	if plen == 126 {
		ext, err := w.readN(2)
		if err != nil {
			return nil, err
		}
		plen = int(binary.BigEndian.Uint16(ext))
	} else if plen == 127 {
		ext, err := w.readN(8)
		if err != nil {
			return nil, err
		}
		plen = int(binary.BigEndian.Uint64(ext))
	}
	if plen > 64*1024 {
		plen = 64 * 1024
	}
	return w.readN(plen)
}

// wsSendTextFrame sends a masked WebSocket text frame (client→server must be masked).
func wsSendTextFrame(conn net.Conn, payload []byte) error {
	plen := len(payload)
	var header []byte
	header = append(header, 0x81) // FIN + text opcode
	if plen < 126 {
		header = append(header, byte(0x80|plen))
	} else {
		header = append(header, 0x80|126, byte(plen>>8), byte(plen))
	}
	// masking key (all zeros for simplicity — valid per RFC 6455)
	mask := [4]byte{}
	header = append(header, mask[:]...)
	frame := append(header, payload...) // mask of 0x00 is a no-op XOR
	_, err := conn.Write(frame)
	return err
}

// ── Promptfoo ───────────────────────────────────────────────────────

func enumPromptfoo(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/api/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["health"] = m
		}
	}

	// Promptfoo is a red-team / eval framework. The eval-history is the
	// operator's curated jailbreak/probe corpus — disclosure is direct
	// competitor intelligence + ammunition for the same probes against
	// other operators.
	if st, _, body, err := httpGET(c, b+"/api/eval"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if arr, err := parseJSONArray(body); err == nil {
				r.RawData["eval_count"] = len(arr)
				r.Details = append(r.Details, fmt.Sprintf("Eval runs: %d", len(arr)))
				if len(arr) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "data", Title: "Promptfoo eval history readable without auth",
						Detail:   "Operator's red-team / eval-run history is enumerable. Contains the prompts being tested, target models, and pass/fail per probe. Direct competitor intelligence for adversarial-AI work.",
						Severity: "high",
					})
				}
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/results"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil && len(arr) > 0 {
			r.RawData["results_count"] = len(arr)
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Promptfoo stores red-team / eval history",
		Detail:   "This service contains adversarial-prompt corpora and per-model robustness scores. Misconfigurations leak the operator's attack-research corpus.",
		Severity: "info",
	})

	return r
}

// ── NeMo Guardrails ─────────────────────────────────────────────────

func enumNeMoGuardrails(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/v1/rails/configs"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if arr, err := parseJSONArray(body); err == nil {
				r.RawData["configs"] = arr
				r.Details = append(r.Details, fmt.Sprintf("Rails configs: %d", len(arr)))
				if len(arr) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "data", Title: "NeMo Guardrails configs enumerable",
						Detail:   "Operator's safety policy is readable. An attacker can fingerprint exactly which rails are enabled (jailbreak / topical / fact-check / hallucination / output-mod) and craft inputs that route around them.",
						Severity: "high",
					})
				}
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// /v1/chat/completions → if 405 Method Not Allowed, the inference path
	// is unauth (POST would succeed). If 401/403, auth is enforced.
	if st, _, _, err := httpGET(c, b+"/v1/chat/completions"); err == nil {
		if st == 405 {
			r.Findings = append(r.Findings, Finding{
				Category: "compute", Title: "Inference endpoint reachable without auth",
				Detail:   "GET returned 405 Method Not Allowed (POST would be functional). Anyone can drive the guardrail-wrapped LLM and burn operator quota.",
				Severity: "high",
			})
		}
	}

	return r
}

// ── DeepEval Server ─────────────────────────────────────────────────

func enumDeepEval(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/api/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["health"] = m
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/evaluations"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if arr, err := parseJSONArray(body); err == nil {
				r.RawData["evaluations_count"] = len(arr)
				r.Details = append(r.Details, fmt.Sprintf("Evaluations: %d", len(arr)))
				if len(arr) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "data", Title: "DeepEval evaluation results readable without auth",
						Detail:   "Operator's LLM-app eval corpus is enumerable. Contains test cases, target prompts, model IDs, and pass/fail metrics — proprietary QA data.",
						Severity: "high",
					})
				}
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	return r
}

// ── LangSmith Self-Hosted ───────────────────────────────────────────

func enumLangSmith(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["info"] = m
			if flags, ok := m["instance_flags"].(map[string]interface{}); ok {
				if v, ok := flags["organization_creation_disabled"].(bool); ok && !v {
					r.Findings = append(r.Findings, Finding{
						Category: "access", Title: "LangSmith organization-creation is open",
						Detail:   "instance_flags.organization_creation_disabled=false. New orgs can be self-registered, which on a self-hosted deployment is usually unintended (defaults to disabled in production configs).",
						Severity: "medium",
					})
				}
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/projects"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if arr, err := parseJSONArray(body); err == nil {
				r.RawData["project_count"] = len(arr)
				r.Details = append(r.Details, fmt.Sprintf("Projects: %d", len(arr)))
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: "LangSmith projects + traces accessible without auth",
					Detail:   "Project list and trace history are enumerable. Traces contain full prompt/response pairs, system prompts, tool-call inputs, and sometimes embedded credentials in tool outputs.",
					Severity: "critical",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "LangSmith stores LLM trace data",
		Detail:   "This service contains full prompt/response history. Misconfigurations leak production conversation data.",
		Severity: "info",
	})

	return r
}

// ── AI observability tier (Phase 3 of the 2026-05 sweep) ────────────

// enumPhoenix probes Arize Phoenix for unauthenticated GraphQL access.
// The product ships with PHOENIX_ENABLE_AUTH=False as the documented default,
// which drives a 25% unauth rate at population scale (94 of 377 hosts on
// 2026-05-10). The GraphQL endpoint at /graphql accepts unauth POST and
// returns project + span data including prompt/response history.
var phoenixVersionRe = regexp.MustCompile(`platformVersion\s*:\s*"([^"]+)"`)

func enumPhoenix(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Version extraction. Prefer the X-Phoenix-Server-Version response
	// header (clean, no parsing) and fall back to the SPA bootstrap regex.
	if _, hdrs, body, err := httpGET(c, b+"/"); err == nil {
		if v, ok := hdrs["X-Phoenix-Server-Version"]; ok && v != "" {
			r.Version = v
		} else if m := phoenixVersionRe.FindSubmatch(body); len(m) == 2 {
			r.Version = string(m[1])
		}
		if r.Version != "" {
			r.Details = append(r.Details, "Phoenix version: "+r.Version)
		}
	}

	// GraphQL introspection probe. Phoenix's /graphql accepts POST without
	// auth when PHOENIX_ENABLE_AUTH is False. We probe with a minimal
	// __typename query that fires for any GraphQL endpoint, then escalate
	// to project enumeration if the type query succeeds.
	typeProbe := []byte(`{"query":"{ __typename }"}`)
	if st, _, body, err := httpPOST(c, b+"/graphql", "application/json", typeProbe); err == nil && st == 200 {
		if bytes.Contains(body, []byte(`"__typename"`)) && bytes.Contains(body, []byte(`"Query"`)) {
			// GraphQL is reachable. Probe projects to confirm unauth read.
			projProbe := []byte(`{"query":"{ projects { edges { node { id name } } } }"}`)
			if st2, _, body2, err2 := httpPOST(c, b+"/graphql", "application/json", projProbe); err2 == nil && st2 == 200 {
				if bytes.Contains(body2, []byte(`"projects"`)) && bytes.Contains(body2, []byte(`"edges"`)) {
					r.AuthStatus = "none"
					// Count projects from the response
					projCount := bytes.Count(body2, []byte(`"node":`))
					if projCount > 0 {
						r.RawData["project_count"] = projCount
						r.Details = append(r.Details, fmt.Sprintf("Projects (unauth read): %d", projCount))
					}
					r.Findings = append(r.Findings, Finding{
						Category: "data", Title: "Phoenix GraphQL accessible without authentication",
						Detail:   "POST /graphql accepts unauthenticated queries. The full project list, span data, and prompt/response history are readable. Phoenix ships with PHOENIX_ENABLE_AUTH=False as the documented default; operators who deploy without explicitly setting PHOENIX_ENABLE_AUTH=True inherit this exposure. See https://docs.arize.com/phoenix/self-hosting/authentication for the env-var spec.",
						Severity: "critical",
					})
				}
			}

			// On Phoenix 15.x+, the Secret type is exposed in the GraphQL
			// schema with a readable .value field. Earlier majors (4-14)
			// have CreateUserApiKeyMutation as the closest write primitive.
			// We probe schema for Secret type to detect the worse case.
			schemaProbe := []byte(`{"query":"{ __schema { types { name } } }"}`)
			if st3, _, body3, err3 := httpPOST(c, b+"/graphql", "application/json", schemaProbe); err3 == nil && st3 == 200 {
				if bytes.Contains(body3, []byte(`"Secret"`)) {
					r.Findings = append(r.Findings, Finding{
						Category: "secrets", Title: "Phoenix Secret type present in unauth GraphQL schema",
						Detail:   "Phoenix 15.x+ ships a Secret type with a readable .value field via the secrets query. On instances with PHOENIX_ENABLE_AUTH=False this means stored LLM provider API keys (OpenAI, Anthropic, etc.) and arbitrary secrets are extractable. Probe: { secrets { edges { node { name value } } } }",
						Severity: "critical",
					})
				}
			}
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Phoenix stores LLM trace + prompt data",
		Detail:   "Phoenix is an LLM observability platform: it captures and replays full prompt/response history per project. Trace data on an unauthenticated instance includes system prompts, user inputs, model outputs, and tool-call payloads.",
		Severity: "info",
	})

	return r
}

// enumHelicone probes Helicone self-hosted instances. Helicone ships
// auth-on-by-default (BetterAuth or Supabase) so we don't expect unauth
// finds. The latent primitive is the literal BETTER_AUTH_SECRET value
// committed to multiple .env.example files in the upstream repo - if an
// operator copied the example verbatim without rotating, session-cookie
// forgery is possible. We can't detect that remotely, but we surface the
// platform identification so operators can audit their own deployments.
func enumHelicone(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Probe /signin for the BetterAuth dashboard. 200 means the dashboard
	// exists. 307 from / to /signin means the auth middleware is active.
	if st, _, body, err := httpGET(c, b+"/signin"); err == nil && st == 200 {
		if bytes.Contains(body, []byte("helicone")) {
			r.AuthStatus = "required (BetterAuth or Supabase)"
			r.Details = append(r.Details, "Auth middleware active at /signin")
		}
	}

	// Probe the API health endpoint for version banner if available.
	if st, _, body, err := httpGET(c, b+"/api/v1/heartbeat"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["heartbeat"] = m
			if v := jStr(m, "version"); v != "" {
				r.Version = v
			}
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "config", Title: "Helicone self-hosted ships literal BETTER_AUTH_SECRET in .env.example",
		Detail:   "Upstream repo's web/.env.example, valhalla/jawn/.env.example, and docker/.env.example all contain `BETTER_AUTH_SECRET=\"MKUcaeqyMD7UBkGeFYY5hwxKS1aB6Vsi\"` literally. Operators who copy an example file verbatim and don't rotate inherit a known session-cookie signing key, enabling session-token forgery for anyone with the literal value. Confirm rotation via: cat /path/to/.env | grep BETTER_AUTH_SECRET",
		Severity: "high",
	})
	r.Findings = append(r.Findings, Finding{
		Category: "config", Title: "Helicone bundled MinIO defaults to minioadmin:minioadmin",
		Detail:   "helicone-all-in-one Docker image bundles MinIO at port 9080 with S3_ACCESS_KEY=minioadmin and S3_SECRET_KEY=minioadmin documented defaults. If port 9080 is reachable from outside, full read/write to the `request-response-storage` bucket (raw LLM request bodies + response bodies) is exposed. Audit: nmap port 9080 + `curl -H 'Authorization: AWS4...' http://target:9080/minio/health/live`.",
		Severity: "high",
	})
	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Helicone stores LLM request + response bodies",
		Detail:   "Helicone is an LLM observability + AI gateway product. It captures full prompt and response bodies (not just metadata) for every routed request. The bundled MinIO bucket request-response-storage is the storage backend.",
		Severity: "info",
	})

	return r
}

// enumLunary probes Lunary self-hosted instances. Lunary ships auth-on
// by default via JWT (NextAuth.js). /api/v1/health returns {status:OK}
// unauth; protected routes return 401 with a clean JSON envelope. We
// fingerprint the install + flag the JWT_SECRET=changeme placeholder
// for operator audit (similar threat model to Langfuse's ADMIN_API_KEY).
func enumLunary(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/api/v1/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
			if s := jStr(m, "status"); s == "OK" || s == "ok" {
				r.Details = append(r.Details, "Lunary health: "+s)
			}
		}
	}

	// Probe a protected route. 401 = auth working. 200 = auth bypassed.
	if st, _, body, err := httpGET(c, b+"/v1/projects"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			r.Findings = append(r.Findings, Finding{
				Category: "data", Title: "Lunary projects accessible without authentication",
				Detail:   "GET /v1/projects returned 200 without auth. Lunary stores LLM observability + prompt-management data per project. This indicates JWT auth was bypassed or disabled.",
				Severity: "critical",
			})
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
			if bytes.Contains(body, []byte("Invalid access token")) {
				r.Details = append(r.Details, "Lunary JWT auth enforced (standard 401 envelope)")
			}
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "config", Title: "Lunary self-hosted ships JWT_SECRET=changeme placeholder",
		Detail:   "Upstream lunary-ai/lunary repo's .env.example contains JWT_SECRET=changeme as a placeholder (not a literal default like Helicone's BetterAuth secret). Operators who run with the literal `changeme` value can have JWT tokens forged. Confirm rotation via: grep JWT_SECRET in operator's .env. Better than Helicone's pattern but still worth auditing.",
		Severity: "medium",
	})
	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Lunary stores LLM trace + prompt data",
		Detail:   "Lunary is an open-source LLM observability + prompt management platform. Captures full conversation history, prompts, and run metadata per project.",
		Severity: "info",
	})

	return r
}

// enumOpenLIT probes OpenLIT self-hosted instances. OpenLIT ships auth
// via NextAuth.js with every API route wrapped in middleware that
// redirects unauth requests to /login. Zero unauth at population scale
// on 2026-05-10 (23 of 23 hosts auth-fronted). We surface the install
// and check for the most common operator-side IP-shadow co-location:
// node_exporter on 9100 (seen on 1 of 23 hosts).
func enumOpenLIT(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// The aimap HTTP client follows redirects, so a NextAuth-protected /api/ping
	// lands on /login after the 307. We detect auth posture by content: a
	// followed body containing "callbackUrl" indicates the redirect chain
	// hit the login page (auth is enforced). A 200 with actual JSON payload
	// would indicate auth bypass.
	if st, _, body, err := httpGET(c, b+"/api/ping"); err == nil && st == 200 {
		if bytes.Contains(body, []byte("callbackUrl")) || bytes.Contains(body, []byte("login")) {
			r.AuthStatus = "required (NextAuth middleware redirects to /login)"
			r.Details = append(r.Details, "NextAuth.js middleware active")
		} else if bytes.Contains(body, []byte(`"pong"`)) || bytes.Contains(body, []byte(`"ok"`)) {
			r.AuthStatus = "none"
			r.Findings = append(r.Findings, Finding{
				Category: "data", Title: "OpenLIT /api/ping accessible without authentication",
				Detail:   "GET /api/ping returned a JSON response payload without being redirected through the login flow. NextAuth.js middleware appears bypassed or disabled. Probe protected routes (/api/db/checkConnection, /api/prompt-hub) to confirm scope.",
				Severity: "high",
			})
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "OpenLIT stores LLM observability + evaluation data",
		Detail:   "OpenLIT is an open-source LLM/GenAI observability platform with built-in eval, playground, and prompt-management. Captures trace data, prompts, and evaluation runs.",
		Severity: "info",
	})

	return r
}

// enumPezzo probes Pezzo self-hosted instances. Pezzo is a Nest.js
// backend + Next.js frontend split (4200 frontend, 3000 backend).
// Auth via JWT on the GraphQL backend; SPA-shadow on the frontend.
// Population at 2026-05-10: 1 confirmed instance, 0 unauth.
func enumPezzo(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if bytes.Contains(body, []byte("<title>Pezzo</title>")) {
			r.Details = append(r.Details, "Pezzo SPA frontend identified")
		}
	}

	// Probe the GraphQL backend (typically port 3000 if frontend is 4200).
	// On a single-port deploy, /graphql is co-located.
	gqlProbe := []byte(`{"query":"{ __typename }"}`)
	if st, _, _, err := httpPOST(c, b+"/graphql", "application/json", gqlProbe); err == nil {
		if st == 200 {
			r.AuthStatus = "graphql reachable (auth posture unknown without write probe)"
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		} else if st == 405 {
			r.AuthStatus = "graphql endpoint requires POST (auth posture unknown)"
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Pezzo stores LLM prompts + observability + dataset versions",
		Detail:   "Pezzo is an open-source LLMOps platform (prompt management, observability, dataset versioning). Captures prompt versions, run history, and evaluation datasets.",
		Severity: "info",
	})

	return r
}

// ── Generic checks ──────────────────────────────────────────────────

func checkGeneric(c *http.Client, svc ServiceMatch) []Finding {
	var findings []Finding
	b := svc.BaseURL

	if _, hdrs, _, err := httpGET(c, b+"/"); err == nil {
		if cors, ok := hdrs["Access-Control-Allow-Origin"]; ok && cors == "*" {
			findings = append(findings, Finding{
				Category: "cors", Title: "CORS: Access-Control-Allow-Origin: *",
				Severity: "medium",
			})
		}
		for _, h := range []string{"X-Powered-By", "X-AspNet-Version"} {
			if v, ok := hdrs[h]; ok && v != "" {
				findings = append(findings, Finding{
					Category: "headers", Title: fmt.Sprintf("%s header disclosed", h),
					Detail: v, Severity: "low",
				})
			}
		}
	}

	if svc.MatchBody != nil {
		bodyStr := string(svc.MatchBody)
		for _, sp := range secretPatterns {
			if strings.Contains(bodyStr, sp.Pattern) {
				findings = append(findings, Finding{
					Category: "secrets", Title: fmt.Sprintf("Possible %s in response", sp.Name),
					Detail:   fmt.Sprintf("Pattern '%s' found in probe response", sp.Pattern),
					Severity: "critical",
				})
			}
		}
	}

	return findings
}

// ── Embedding Services ───────────────────────────────────────────────

func enumTEI(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["info"] = m
			if v := jStr(m, "model_id"); v != "" {
				r.Details = append(r.Details, "Model: "+v)
			}
			if v := jStr(m, "version"); v != "" {
				r.Version = v
			}
			if v := jStr(m, "max_input_length"); v != "" {
				r.Details = append(r.Details, "Max input length: "+v)
			}
			if v := jStr(m, "max_batch_total_tokens"); v != "" {
				r.Details = append(r.Details, "Max batch tokens: "+v)
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/metrics"); err == nil && st == 200 {
		bodyStr := string(body)
		r.RawData["metrics_sample"] = bodyStr[:min(len(bodyStr), 512)]
		if strings.Contains(bodyStr, "te_request_count") {
			r.Details = append(r.Details, "Prometheus metrics exposed (te_request_count visible)")
		}
		if strings.Contains(bodyStr, "te_embed_count") {
			r.Details = append(r.Details, "Embed call counter exposed")
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "access",
		Title:    "Unauthenticated TEI embedding server",
		Detail:   "HuggingFace Text Embeddings Inference ships with no authentication. Any caller can submit text for embedding at the operator's GPU cost, and use this server as an embedding oracle to pre-compute query vectors against the downstream vector database.",
		Severity: "medium",
	})

	return r
}

func enumInfinity(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["models"] = m
		}
	}

	if st, _, body, err := httpGET(c, b+"/openapi.json"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if info, ok := m["info"].(map[string]interface{}); ok {
				if v, ok := info["version"].(string); ok {
					r.Version = v
				}
				if t, ok := info["title"].(string); ok {
					r.Details = append(r.Details, "API title: "+t)
				}
			}
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "access",
		Title:    "Unauthenticated infinity-embedding server",
		Detail:   "infinity-embedding (michaelfeil/infinity) exposes an OpenAI-compatible /v1/embeddings endpoint with no authentication. Compute theft and embedding oracle attack against downstream vector stores.",
		Severity: "medium",
	})

	return r
}

func enumEmbeddingAPI(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["root"] = m
			if v := jStr(m, "embed"); v != "" {
				r.Details = append(r.Details, "Embed model: "+v)
			}
			if v := jStr(m, "embedding_dimension"); v != "" {
				r.Details = append(r.Details, "Embedding dimension: "+v)
			}
			if v := jStr(m, "model_name"); v != "" {
				r.Details = append(r.Details, "Model: "+v)
			}
			if v := jStr(m, "reranker"); v != "" {
				r.Details = append(r.Details, "Reranker: "+v)
			}
			if v := jStr(m, "llm"); v != "" {
				r.Details = append(r.Details, "LLM: "+v)
			}
			if v := jStr(m, "index_dir"); v != "" {
				r.Details = append(r.Details, "Index dir (path leak): "+v)
			}
			if v := jStr(m, "docs_dir"); v != "" {
				r.Details = append(r.Details, "Docs dir (path leak): "+v)
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
			if v := jStr(m, "model_name"); v != "" && len(r.Details) == 0 {
				r.Details = append(r.Details, "Model: "+v)
			}
			if v := jStr(m, "embedding_dimension"); v != "" {
				r.Details = append(r.Details, "Embedding dimension: "+v)
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/openapi.json"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if info, ok := m["info"].(map[string]interface{}); ok {
				if t, ok := info["title"].(string); ok {
					r.Details = append(r.Details, "API: "+t)
				}
				if v, ok := info["version"].(string); ok {
					r.Version = v
				}
			}
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "access",
		Title:    "Unauthenticated embedding API",
		Detail:   "Custom FastAPI embedding server with no authentication. Root endpoint leaks embedding model, vector dimension, reranker, LLM backend, and internal filesystem paths. Compute theft + embedding oracle.",
		Severity: "medium",
	})

	return r
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── GraphQL API ─────────────────────────────────────────────────────
//
// Probes any Apollo/generic GraphQL endpoint for:
//   1. Unauthenticated introspection (confirms full schema exposure)
//   2. Admin-grade data export operations (getCsvUrl, getCustomUsersCsv, etc.)
//   3. Admin flag fields on User types (isSuper, isAdmin, isDeveloper, etc.)
//   4. Unauth execution of data export queries (if present)
//
// Anchor cases: djaminn.app dev-api (getCustomUsersCsv executed unauth → GCS URL),
// djaminn.app production (introspection open, per-resolver auth mixed).

// graphqlDataExportOps lists operation names that expose admin-grade data exports.
var graphqlDataExportOps = []string{
	"getCsvUrl", "getCustomUsersCsv", "exportUsers", "downloadUsers",
	"getUsersExport", "getUsersCsv", "exportData", "downloadData",
	"getExportUrl", "exportAll", "bulkExport", "getCsvDownload",
}

// graphqlAdminFlagFields lists boolean fields on User types that expose role hierarchy.
var graphqlAdminFlagFields = []string{
	"isSuper", "isSuperUser", "isAdmin", "isStaff", "isDeveloper",
	"isModerator", "isOperator", "isOwner", "isRoot",
}

func enumGraphQL(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// GraphQL endpoints to probe in order.
	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/api/v1/graphql"}

	// Phase 1: confirm introspection is accessible.
	typeProbe := []byte(`{"query":"{ __typename }"}`)
	var gqlBase string
	for _, ep := range endpoints {
		if st, _, body, err := httpPOST(c, b+ep, "application/json", typeProbe); err == nil && st == 200 {
			if strings.Contains(string(body), "__typename") || strings.Contains(string(body), `"Query"`) {
				gqlBase = b + ep
				r.AuthStatus = "none"
				break
			}
		}
	}
	if gqlBase == "" {
		return r
	}

	r.Details = append(r.Details, "GraphQL introspection: accessible without auth")
	r.Findings = append(r.Findings, Finding{
		Category: "access",
		Title:    "GraphQL introspection accessible without authentication",
		Detail:   fmt.Sprintf("POST %s with {__typename} returns schema data. Full introspection is enabled and requires no credential.", gqlBase),
		Severity: "medium",
	})

	// Phase 2: enumerate root query operation names.
	schemaProbe := []byte(`{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}`)
	if st, _, body, err := httpPOST(c, gqlBase, "application/json", schemaProbe); err == nil && st == 200 {
		if m, parseErr := parseJSON(body); parseErr == nil {
			queryFields := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
			mutationFields := gqlFieldNames(m, "data", "__schema", "mutationType", "fields")
			allOps := append(queryFields, mutationFields...)

			// Check for data export operations.
			var exportOps []string
			for _, op := range allOps {
				for _, target := range graphqlDataExportOps {
					if strings.EqualFold(op, target) {
						exportOps = append(exportOps, op)
						break
					}
				}
			}
			if len(exportOps) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data",
					Title:    fmt.Sprintf("Admin-grade data export operations in unauth GraphQL schema: %s", strings.Join(exportOps, ", ")),
					Detail: "These operations export user data or generate bulk download URLs. " +
						"Their presence in the unauth introspection schema does not confirm they execute without auth, " +
						"but unauthenticated introspection means the attack surface is fully mapped.",
					Severity: "high",
					Data:     map[string]interface{}{"export_ops": exportOps},
				})

				// Phase 3: attempt to execute each export op without auth.
				for _, op := range exportOps {
					execProbe := []byte(fmt.Sprintf(`{"query":"{ %s }"}`, op))
					if st2, _, body2, err2 := httpPOST(c, gqlBase, "application/json", execProbe); err2 == nil && st2 == 200 {
						m2, parseErr2 := parseJSON(body2)
						if parseErr2 == nil {
							// Success: data returned without an errors block containing "unauthorized"
							if dataVal, hasData := m2["data"]; hasData && dataVal != nil {
								errField, hasErr := m2["errors"]
								if !hasErr || errField == nil {
									r.Findings = append(r.Findings, Finding{
										Category: "data",
										Title:    fmt.Sprintf("Data export query %q executed without authentication", op),
										Detail: fmt.Sprintf(
											"POST %s with {%s} returned data with no auth error. "+
												"The resolver executed without a token or session cookie.",
											gqlBase, op,
										),
										Severity: "critical",
										Data:     map[string]interface{}{"operation": op},
									})
								}
							}
						}
					}
				}
			}

			if len(allOps) > 0 {
				r.Details = append(r.Details, fmt.Sprintf("Schema operations: %d query, %d mutation", len(queryFields), len(mutationFields)))
				r.RawData["operations_count"] = map[string]int{"query": len(queryFields), "mutation": len(mutationFields)}
			}
		}
	}

	// Phase 4: check common User type names for admin flag fields.
	userTypeNames := []string{"User", "UserConfidential", "UserProfile", "Account", "Member"}
	for _, typeName := range userTypeNames {
		typeQuery := []byte(fmt.Sprintf(`{"query":"{ __type(name: \"%s\") { fields { name } } }"}`, typeName))
		if st, _, body, err := httpPOST(c, gqlBase, "application/json", typeQuery); err == nil && st == 200 {
			if m, parseErr := parseJSON(body); parseErr == nil {
				fields := gqlFieldNamesFlat(m, "data", "__type", "fields")
				var adminFlags []string
				for _, f := range fields {
					for _, target := range graphqlAdminFlagFields {
						if strings.EqualFold(f, target) {
							adminFlags = append(adminFlags, f)
							break
						}
					}
				}
				if len(adminFlags) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "data",
						Title:    fmt.Sprintf("Admin role flags in GraphQL %s type: %s", typeName, strings.Join(adminFlags, ", ")),
						Detail: fmt.Sprintf(
							"The %s type exposes boolean admin-role fields via introspection: %s. "+
								"If allUsers or getUserByEmail resolvers are accessible without auth, "+
								"these fields enumerate admin accounts directly.",
							typeName, strings.Join(adminFlags, ", "),
						),
						Severity: "medium",
						Data:     map[string]interface{}{"type": typeName, "admin_flags": adminFlags},
					})
				}
			}
		}
	}

	return r
}

// gqlFieldNames extracts the "name" string from each element of a nested
// GraphQL __schema fields array. Path: m[key0][key1]...[keyN] = []{"name":...}
func gqlFieldNames(m map[string]interface{}, keys ...string) []string {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	arr, ok := cur.([]interface{})
	if !ok {
		return nil
	}
	var names []string
	for _, item := range arr {
		if obj, ok := item.(map[string]interface{}); ok {
			if name, ok := obj["name"].(string); ok && name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// gqlFieldNamesFlat handles the __type(name:...) { fields { name } } response shape.
func gqlFieldNamesFlat(m map[string]interface{}, keys ...string) []string {
	return gqlFieldNames(m, keys...)
}

// ── Anti-detect CDP server ──────────────────────────────────────────

// enumAntiDetectCDP deep-reads an aiohttp-fronted anti-detect Chrome
// DevTools Protocol server. CDP has no authentication concept, so any
// reachable instance is unauthenticated by definition. The enumerator
// reads only the discovery endpoints — /json/version, /json, and the
// aiohttp control-plane root. It never opens the WebSocket; the mere
// presence of a webSocketDebuggerUrl is the proof of control.
func enumAntiDetectCDP(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none" // CDP is auth-never; reachable == unauthenticated

	// /json/version — browser build + the browser-level ws control URL.
	if st, _, body, err := httpGET(c, b+"/json/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "Browser")
			if ws := jStr(m, "webSocketDebuggerUrl"); ws != "" {
				r.RawData["browser_ws"] = ws
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    "Browser-level CDP WebSocket exposed without authentication",
					Detail: "The browser-level webSocketDebuggerUrl is reachable. " +
						"Speaking CDP over it gives full remote control of the browser: " +
						"Network.getAllCookies (incl. HttpOnly session tokens), " +
						"Runtime.evaluate (arbitrary JS in any origin), Page.navigate, " +
						"and Target.createTarget. Equivalent to a remote-desktop session " +
						"into a browser that is already logged into things.",
					Severity: "critical",
				})
			}
		}
	}

	// /json — open targets (tabs/workers), each with its own ws URL. A
	// live page target means a live, hijackable session.
	if st, _, body, err := httpGET(c, b+"/json"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			pages := 0
			var urls []string
			for _, t := range arr {
				tm, ok := t.(map[string]interface{})
				if !ok {
					continue
				}
				if jStr(tm, "type") == "page" {
					pages++
					if u := jStr(tm, "url"); u != "" {
						urls = append(urls, u)
					}
				}
			}
			r.RawData["open_targets"] = len(arr)
			r.RawData["open_pages"] = pages
			if len(urls) > 0 {
				r.RawData["page_urls"] = urls
				r.Details = append(r.Details, fmt.Sprintf("%d open page target(s)", pages))
				r.Findings = append(r.Findings, Finding{
					Category: "data",
					Title:    "Live browser session(s) reachable via CDP",
					Detail: "Open page targets are listed with controllable WebSocket URLs. " +
						"If any session is authenticated, Network.getCookies yields its " +
						"session token — account takeover with no password and no MFA prompt.",
					Severity: "critical",
				})
			}
		}
	}

	// / — the aiohttp anti-detect control plane. Exposes the managed
	// browser-process pool: pid, internal port, anti-fingerprint seed,
	// and any pinned proxy / timezone / locale.
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if procs := jMap(m, "processes"); procs != nil {
				r.RawData["managed_processes"] = len(procs)
				r.Details = append(r.Details, fmt.Sprintf("%d managed browser process(es)", len(procs)))
				for _, pv := range procs {
					pm, ok := pv.(map[string]interface{})
					if !ok {
						continue
					}
					if proxy := jStr(pm, "proxy"); proxy != "" {
						r.RawData["upstream_proxy"] = proxy
					}
				}
				r.Findings = append(r.Findings, Finding{
					Category: "config",
					Title:    "Anti-detect browser-farm control plane exposed",
					Detail: "The aiohttp control-plane root lists the managed browser-process " +
						"pool with per-process anti-fingerprint seeds and any pinned upstream " +
						"proxy/timezone/locale. Discloses the scraping operation's structure " +
						"and lets an attacker drive the farm.",
					Severity: "high",
				})
			}
		}
	}

	r.RiskLevel = computeRisk(r)
	return r
}

func computeRisk(r EnumResult) string {
	ranks := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	best := "info"
	for _, f := range r.Findings {
		if ranks[f.Severity] > ranks[best] {
			best = f.Severity
		}
	}
	if r.AuthStatus == "none" && best == "high" {
		return "critical"
	}
	return best
}

// enumComfyUI — read-only ComfyUI API enumeration.
// Reads /system_stats (version + GPU + operator argv), /object_info (node
// catalog size), /queue (running/pending workflows), /history (recent runs).
// Probes /customnode/getlist as a tell for ComfyUI-Manager — its presence
// means the operator can RCE themselves by design (custom-node install is
// arbitrary Python). Restraint: never POST /prompt, never trigger /interrupt,
// never call /upload/image, never install custom nodes.
// Field-validated 2026-05-16 on 103.192.253.238:8575 (NVIDIA L40S, 1TB RAM).
func enumComfyUI(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// /system_stats — version, GPU, operator argv
	if st, _, body, err := httpGET(c, b+"/system_stats"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["system_stats"] = m
			if sys, ok := m["system"].(map[string]interface{}); ok {
				if v := jStr(sys, "comfyui_version"); v != "" {
					r.Version = v
					r.Details = append(r.Details, "ComfyUI "+v)
				}
				if py := jStr(sys, "python_version"); py != "" {
					if i := strings.Index(py, "|"); i > 0 {
						py = strings.TrimSpace(py[:i])
					}
					r.Details = append(r.Details, "Python "+py)
				}
				if pt := jStr(sys, "pytorch_version"); pt != "" {
					r.Details = append(r.Details, "PyTorch "+pt)
				}
				// Operator argv — frequently exposes config secrets, custom flags
				if argv, ok := sys["argv"].([]interface{}); ok && len(argv) > 0 {
					var parts []string
					for _, a := range argv {
						parts = append(parts, fmt.Sprintf("%v", a))
					}
					argvStr := strings.Join(parts, " ")
					r.RawData["argv"] = argvStr
					if len(argvStr) < 300 {
						r.Details = append(r.Details, "argv: "+argvStr)
					}
				}
			}
			// devices — GPU info
			if devs, ok := m["devices"].([]interface{}); ok && len(devs) > 0 {
				if d0, ok := devs[0].(map[string]interface{}); ok {
					if name := jStr(d0, "name"); name != "" {
						r.Details = append(r.Details, "GPU: "+name)
					}
					if vram := jFloat(d0, "vram_total"); vram > 0 {
						r.Details = append(r.Details, fmt.Sprintf("VRAM: %.1f GB", vram/1024/1024/1024))
					}
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "unauth_api", Title: "ComfyUI API unauthenticated",
				Severity: "critical",
				Detail:   "GET /system_stats returns operator config + GPU info. Anyone can POST /prompt to run workflows on the operator's GPU. Compute-theft + (with ComfyUI-Manager) unauth RCE by design.",
			})
		}
	}

	// /queue — running + pending workflows (size only, no payload read)
	if st, _, body, err := httpGET(c, b+"/queue"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			running := 0
			pending := 0
			if rArr, ok := m["queue_running"].([]interface{}); ok {
				running = len(rArr)
			}
			if pArr, ok := m["queue_pending"].([]interface{}); ok {
				pending = len(pArr)
			}
			r.RawData["queue"] = map[string]int{"running": running, "pending": pending}
			if running+pending > 0 {
				r.Details = append(r.Details, fmt.Sprintf("queue: %d running, %d pending", running, pending))
			}
		}
	}

	// /history — recent workflow runs (count only)
	if st, _, body, err := httpGET(c, b+"/history"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["history_count"] = len(m)
			if len(m) > 0 {
				r.Details = append(r.Details, fmt.Sprintf("history: %d completed runs", len(m)))
			}
		}
	}

	// /customnode/getlist — ComfyUI-Manager presence (RCE-by-design surface).
	// The endpoint exists only when ComfyUI-Manager is installed. Without
	// Manager, ComfyUI returns 404. With Manager installed, the endpoint
	// returns 200 (body has ComfyUI-Manager/custom_nodes markers) OR 500
	// (Manager loaded but errored on the catalog fetch — common when the
	// host has no outbound internet) OR 502/503 (Manager loaded but slow).
	// Status != 404 + status != 0 (network error) is the right signal.
	if st, _, body, err := httpGET(c, b+"/customnode/getlist"); err == nil && st != 404 && st != 0 {
		r.RawData["has_manager"] = true
		r.RawData["manager_probe_status"] = st
		detail := "POST /customnode/install on an unauth ComfyUI installs arbitrary Python custom nodes. ComfyUI-Manager's design is that this is intended; auth is meant to gate it. No auth = anyone gets shell."
		if st == 200 && (strings.Contains(string(body), "ComfyUI-Manager") || strings.Contains(string(body), "custom_nodes")) {
			detail = "Confirmed: /customnode/getlist returns 200 with Manager catalog. " + detail
		} else if st == 500 || st == 502 || st == 503 {
			detail = fmt.Sprintf("Manager loaded (HTTP %d on /customnode/getlist suggests Manager endpoint exists but catalog fetch errored — Manager is present). %s", st, detail)
		}
		r.Findings = append(r.Findings, Finding{
			Category: "rce_by_design", Title: "ComfyUI-Manager present — unauth custom-node install = RCE",
			Severity: "critical",
			Detail:   detail,
		})
	}

	return r
}

// enumA1111 — read-only AUTOMATIC1111 / Forge / SD.Next API enumeration.
// Reads /sdapi/v1/options (operator config + model paths), /sdapi/v1/samplers,
// /sdapi/v1/sd-models (model count only). Restraint: never POST /sdapi/v1/txt2img
// or /sdapi/v1/img2img — those trigger generation.
func enumA1111(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/sdapi/v1/options"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["options_keys"] = len(m)
			if ckpt := jStr(m, "sd_model_checkpoint"); ckpt != "" {
				r.Details = append(r.Details, "loaded checkpoint: "+ckpt)
			}
			if loraDir := jStr(m, "lora_dir"); loraDir != "" {
				r.Details = append(r.Details, "lora_dir: "+loraDir)
			}
			r.Findings = append(r.Findings, Finding{
				Category: "unauth_api", Title: "A1111 API unauthenticated",
				Severity: "high",
				Detail:   "GET /sdapi/v1/options exposes operator config including loaded checkpoint and model paths. POST /sdapi/v1/txt2img triggers generation on operator's GPU.",
			})
		}
	}
	if st, _, body, err := httpGET(c, b+"/sdapi/v1/sd-models"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["model_count"] = len(arr)
			if len(arr) > 0 {
				r.Details = append(r.Details, fmt.Sprintf("%d SD models available", len(arr)))
			}
		}
	}
	return r
}

// enumInvokeAI — read-only InvokeAI API enumeration.
// Reads /api/v1/app/version, /api/v1/models/get (size only — full enumeration
// would scrape model paths which is operator-attribution-rich but high-touch).
func enumInvokeAI(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/app/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if v := jStr(m, "version"); v != "" {
				r.Version = v
				r.Details = append(r.Details, "InvokeAI "+v)
			}
			r.Findings = append(r.Findings, Finding{
				Category: "unauth_api", Title: "InvokeAI API unauthenticated",
				Severity: "high",
				Detail:   "GET /api/v1/app/version exposes version. POST /api/v1/queue/default/enqueue_batch triggers generation on operator's GPU.",
			})
		}
	}
	return r
}

// ── Elasticsearch (v1.9.8) ──────────────────────────────────────────
//
// Tier-A* — Docker image ships with xpack.security.enabled=false. 5,037
// unauth instances confirmed at population scale 2026-05-16.
//
// Deep probe extends yesterday's fast_enum_es.py (which captured cluster_name +
// top-20 index names) with the missing `_mapping` field-type pass: the
// canonical AI-stack signal is a `dense_vector` field type in any index. That
// promotes a host from "unauth Elasticsearch" to "unauth Elasticsearch backing
// a RAG/vector workload" regardless of whether the index name contains an
// AI-stack token. The case study's 5,025 "generic name, likely AI-stack"
// hosts are exactly what this enumerator surfaces.
//
// Restraint: GET-only. Pulls cluster identity (/), cluster health
// (/_cluster/health), index list (/_cat/indices), and per-index `_mapping`
// for up to esMappingProbeCap indices. **No _search, no document reads, no
// /_bulk, no /_delete_by_query.** Field-type metadata is the finding;
// document contents are out of scope per the restraint ethic.
//
// **Exception (v1.9.10):** the extortion-marker index is the *attacker's*
// document, not the operator's data. When the marker is present we read one
// document from it to extract actor identifiers (wallet, email, paste URL).
// This characterizes the attacker, not the victim, and is consistent with
// the restraint ethic. Capped at 64 KB and one document.
const (
	esMappingProbeCap     = 30 // cap _mapping probes per host to avoid abuse
	esVectorFieldNameHint = "embedding,vector,vec_,embed_"
)

// Actor-attribution patterns (v1.9.10). Drawn from the 2026-05-17 150-host
// campaign-scope probe (case study: meow-multi-actor-campaign-scope-2026-05-17.md).
// Three actors share the read_me marker but use distinct contact/wallet schemas:
//   Actor A (Meow / wendy.etabw) — bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r +
//     wendy.etabw@gmx.com, paste URL tli.sh/73x1k (decrypts to follow-up note)
//   Actor B (sharebot)            — db-recovery@sharebot.net
//   Actor C (onionmail)           — scandal@onionmail.org
var (
	extortionBtcRe   = regexp.MustCompile(`bc1[0-9a-z]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}`)
	extortionEmailRe = regexp.MustCompile(`[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	extortionPasteRe = regexp.MustCompile(`(?:tli\.sh|paste\.sh|pastebin\.com|privatebin\.[a-z.]+)/[A-Za-z0-9_/\-#?=]+`)
	extortionOnionRe = regexp.MustCompile(`[a-z2-7]{56}\.onion|[a-z2-7]{16}\.onion`)
	extortionXmrRe   = regexp.MustCompile(`4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}`)
)

// extractExtortionAttribution reads ONE document from the marker index and
// pulls out actor identifiers. Returns nil on any error or 0-hit response.
// Single GET, 64 KB cap.
func extractExtortionAttribution(c *http.Client, baseURL, marker string) map[string]interface{} {
	st, _, body, err := httpGET(c, baseURL+"/"+marker+"/_search?size=1")
	if err != nil || st != 200 {
		return nil
	}
	if len(body) > 64*1024 {
		body = body[:64*1024]
	}
	text := strings.ReplaceAll(string(body), "\n", " ")

	attrs := map[string]interface{}{}
	if m := extortionBtcRe.FindString(text); m != "" {
		attrs["btc_wallet"] = m
	}
	if m := extortionXmrRe.FindString(text); m != "" {
		attrs["xmr_wallet"] = m
	}
	emails := extortionEmailRe.FindAllString(text, -1)
	if len(emails) > 0 {
		seen := map[string]bool{}
		uniq := make([]string, 0, len(emails))
		for _, e := range emails {
			el := strings.ToLower(e)
			if !seen[el] {
				seen[el] = true
				uniq = append(uniq, e)
			}
		}
		attrs["contact_emails"] = uniq
	}
	if m := extortionPasteRe.FindString(text); m != "" {
		attrs["paste_url"] = m
	}
	if m := extortionOnionRe.FindString(text); m != "" {
		attrs["onion_url"] = m
	}

	// Actor classification — drawn from the 150-host campaign-scope analysis.
	actor := "unknown"
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "wendy.etabw") ||
		strings.Contains(lower, "bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r") ||
		strings.Contains(lower, "tli.sh/73x1k"):
		actor = "Meow-Actor-A (wendy.etabw / tli.sh)"
	case strings.Contains(lower, "db-recovery@sharebot.net"):
		actor = "Meow-Actor-B (db-recovery@sharebot)"
	case strings.Contains(lower, "scandal@onionmail.org"):
		actor = "Meow-Actor-C (scandal@onionmail)"
	}
	attrs["actor_class"] = actor
	return attrs
}

func enumElasticsearch(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// GET / — cluster identity + version anchor
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if ver, ok := m["version"].(map[string]interface{}); ok {
				r.Version = jStr(ver, "number")
				r.RawData["lucene_version"] = jStr(ver, "lucene_version")
			}
			r.RawData["cluster_name"] = jStr(m, "cluster_name")
			r.RawData["tagline"] = jStr(m, "tagline")
			r.Details = append(r.Details, fmt.Sprintf(
				"Elasticsearch %s · cluster=%s",
				r.Version, jStr(m, "cluster_name"),
			))
		}
	}

	// GET /_cluster/health — Insight #16 "data layer over status code".
	// Health is sometimes still open when /_cat/indices is auth-gated; that
	// asymmetry itself is the finding (effective-unauth via cluster_health).
	if st, _, body, err := httpGET(c, b+"/_cluster/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["cluster_health"] = m
			r.Details = append(r.Details, fmt.Sprintf(
				"health=%s · nodes=%v · indices=%v",
				jStr(m, "status"),
				m["number_of_nodes"], m["active_primary_shards"],
			))
		}
	}

	// GET /_cat/indices — index list. Auth-state classification anchored here.
	st, _, body, err := httpGET(c, b+"/_cat/indices?format=json&s=index")
	if err != nil {
		return r
	}
	if st == 401 || st == 403 {
		r.AuthStatus = "auth-gated"
		return r
	}
	if st != 200 {
		r.AuthStatus = "partial-open" // / was 200 but /_cat/indices wasn't
		return r
	}

	indices, err := parseJSONArray(body)
	if err != nil {
		return r
	}
	r.AuthStatus = "none"

	// Collect index names (skip system .* indices). Also track per-index doc
	// counts so the wiped/marked classifier can look at actual data, not
	// just index cardinality.
	indexNames := make([]string, 0, len(indices))
	indexDocCounts := make(map[string]int64, len(indices))
	for _, raw := range indices {
		idx, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := jStr(idx, "index")
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		indexNames = append(indexNames, name)
		// docs.count can come back as either string or number depending on
		// format=json convention; cover both.
		switch v := idx["docs.count"].(type) {
		case string:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				indexDocCounts[name] = n
			}
		case float64:
			indexDocCounts[name] = int64(v)
		}
	}
	r.RawData["index_count"] = len(indexNames)
	if len(indexNames) > 20 {
		r.RawData["indices_sample"] = indexNames[:20]
	} else {
		r.RawData["indices_sample"] = indexNames
	}

	r.Findings = append(r.Findings, Finding{
		Category: "unauth_data",
		Title:    "Elasticsearch index list reachable without authentication",
		Severity: "high",
		Detail:   fmt.Sprintf("GET /_cat/indices returned %d indices unauth (X-Pack security disabled or default Docker image).", len(indexNames)),
	})

	// Extortion-classifier (v1.9.9) — detect Meow / Indexrm-class compromise.
	// The signature is a small index with the literal name "read_me" (or close
	// variants like read_me_first, recover_data). When present, the host has
	// been hit by automated extortion tooling and the attacker has established
	// control. Findings emitted here drive downstream pipeline filtering —
	// don't send "your host is exposed" disclosures to hosts that are already
	// compromised; that's a different conversation.
	//
	// Three states:
	//   1. compromised-wiped       — read_me present + index_count <= 2 (data deleted)
	//   2. compromised-marked      — read_me present + other indices alive (control established,
	//                                 not yet wiped — these are the saveable cases)
	//   3. (no extortion marker)   — proceed with AI-stack probe normally
	//
	// 4,411 of 4,776 (92.4%) of 2026-05-16's surveyed-unauth Elasticsearch hosts
	// matched state 1 or 2 in the 2026-05-17 re-probe (case study:
	// es-clickhouse-cross-stack-2026-05-17.md). The classifier short-circuits
	// the _mapping probe on state 1 (no data to characterize) but preserves
	// it on state 2 (operator's data still alive and worth characterizing).
	extortionMarkers := []string{"read_me", "read_me_first", "recover_data", "readme", "how_to_recover"}
	var extortionIndex string
	for _, name := range indexNames {
		lower := strings.ToLower(name)
		for _, marker := range extortionMarkers {
			if lower == marker || strings.HasPrefix(lower, marker+"_") {
				extortionIndex = name
				break
			}
		}
		if extortionIndex != "" {
			break
		}
	}
	if extortionIndex != "" {
		// Wiped state: marker present AND every non-marker non-system index
		// has zero docs. Cardinality alone is misleading — the Russian host
		// 81.94.155.178 has only [read_me, russian_news] yet russian_news
		// carries 286,385 alive docs. Look at the data, not the index count.
		nonMarkerAliveDocs := int64(0)
		for name, n := range indexDocCounts {
			if name == extortionIndex {
				continue
			}
			nonMarkerAliveDocs += n
		}
		wiped := nonMarkerAliveDocs == 0
		r.RawData["extortion_marker"] = extortionIndex
		r.RawData["extortion_state"] = map[string]bool{"wiped": wiped, "marked": !wiped}
		r.RawData["non_marker_alive_docs"] = nonMarkerAliveDocs
		state := "compromised-marked"
		if wiped {
			state = "compromised-wiped"
		}
		// Tag for downstream pipeline filtering: --exclude-compromised drops
		// these hosts from disclosure batches that frame "your host is exposed."
		r.RawData["pipeline_tag"] = state

		// v1.9.10 — actor attribution. Read one document from the marker index
		// (the attacker's ransom note) and parse it for wallet/email/paste URL.
		// This is the attacker's planted content, not operator data.
		attrs := extractExtortionAttribution(c, b, extortionIndex)
		actorClass := "unknown"
		if attrs != nil {
			r.RawData["extortion_attribution"] = attrs
			if v, ok := attrs["actor_class"].(string); ok {
				actorClass = v
			}
		}

		var detail string
		if wiped {
			detail = fmt.Sprintf(
				"Host has the extortion marker index '%s' and only %d indices total — Meow / Indexrm-class wipe complete. Operator's data has been deleted. Disclosure framing should NOT say 'your host is exposed' (host is already compromised); say 'you've been hit by automated extortion, here's actor attribution + recovery posture.' Attributed actor: %s.",
				extortionIndex, len(indexNames), actorClass,
			)
		} else {
			detail = fmt.Sprintf(
				"Host has the extortion marker index '%s' alongside %d other indices — Meow / Indexrm-class attacker has established control marker but data is still alive. Saveable case; disclosure-urgent. Don't pay (Meow does not exfiltrate, only deletes). Attributed actor: %s.",
				extortionIndex, len(indexNames)-1, actorClass,
			)
		}
		findingData := map[string]interface{}{
			"marker_index": extortionIndex,
			"state":        state,
			"index_count":  len(indexNames),
			"actor_class":  actorClass,
			"references": []string{
				"https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/meow-multi-actor-campaign-scope-2026-05-17.md",
				"https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/evidence/2026-05-17-meow-attribution/ransom-note-and-paste.md",
				"https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/methodology/insight-29-overwhelming-prior-state-look-at-deltas-not-snapshots.md",
			},
		}
		if attrs != nil {
			if w, ok := attrs["btc_wallet"].(string); ok {
				findingData["btc_wallet"] = w
			}
			if w, ok := attrs["xmr_wallet"].(string); ok {
				findingData["xmr_wallet"] = w
			}
			if e, ok := attrs["contact_emails"].([]string); ok && len(e) > 0 {
				findingData["contact_emails"] = e
			}
			if p, ok := attrs["paste_url"].(string); ok {
				findingData["paste_url"] = p
			}
			if o, ok := attrs["onion_url"].(string); ok {
				findingData["onion_url"] = o
			}
		}
		r.Findings = append(r.Findings, Finding{
			Category: "compromised_by_extortion",
			Title:    "Elasticsearch compromised by automated extortion (Meow / Indexrm family)",
			Severity: "critical",
			Detail:   detail,
			Data:     findingData,
		})
	}

	// _mapping deep probe — cap at esMappingProbeCap indices to bound probe
	// cost. Probe order: indices with names matching vector-field hints
	// first (most likely AI-stack), then a sample of the rest.
	hintIdx := make([]string, 0)
	otherIdx := make([]string, 0)
	hints := strings.Split(esVectorFieldNameHint, ",")
	for _, name := range indexNames {
		lower := strings.ToLower(name)
		matched := false
		for _, h := range hints {
			if h != "" && strings.Contains(lower, h) {
				matched = true
				break
			}
		}
		if matched {
			hintIdx = append(hintIdx, name)
		} else {
			otherIdx = append(otherIdx, name)
		}
	}
	probeOrder := append(hintIdx, otherIdx...)
	if len(probeOrder) > esMappingProbeCap {
		probeOrder = probeOrder[:esMappingProbeCap]
	}

	aiStackIndices := make([]map[string]interface{}, 0)
	for _, idx := range probeOrder {
		st2, _, body2, err2 := httpGET(c, b+"/"+idx+"/_mapping")
		if err2 != nil || st2 != 200 {
			continue
		}
		m2, err2 := parseJSON(body2)
		if err2 != nil {
			continue
		}
		// Mapping shape: { "<index>": { "mappings": { "properties": { "<field>": {"type":"dense_vector","dims":N}, ... } } } }
		idxMap, ok := m2[idx].(map[string]interface{})
		if !ok {
			// ES 7.x older-style: properties one level deeper
			for _, v := range m2 {
				if im, ok := v.(map[string]interface{}); ok {
					idxMap = im
					break
				}
			}
		}
		mappings, _ := idxMap["mappings"].(map[string]interface{})
		props, _ := mappings["properties"].(map[string]interface{})
		if props == nil {
			continue
		}
		vectorFields := make([]map[string]interface{}, 0)
		// Walk top-level properties AND one level of nested objects — chunk
		// schemas (Spring AI, LangChain Java) commonly use `chunks_<dim>:
		// {type: nested, properties: {vector_embedding_<dim>: {knn_vector}}}`.
		// Without this, a host like 84.247.189.64 (OpenSearch with chunks
		// pattern) reports zero vector fields despite being clearly RAG.
		walkProps := func(propMap map[string]interface{}, pathPrefix string) {
			for fname, fdef := range propMap {
				fmap, ok := fdef.(map[string]interface{})
				if !ok {
					continue
				}
				ftype := jStr(fmap, "type")
				if ftype == "dense_vector" || ftype == "knn_vector" || ftype == "sparse_vector" {
					// ES uses "dims", OpenSearch uses "dimension". Capture either.
					dims := fmap["dims"]
					if dims == nil {
						dims = fmap["dimension"]
					}
					vectorFields = append(vectorFields, map[string]interface{}{
						"field":      pathPrefix + fname,
						"type":       ftype,
						"dims":       dims,
						"similarity": fmap["similarity"],
					})
				}
			}
		}
		walkProps(props, "")
		for fname, fdef := range props {
			fmap, ok := fdef.(map[string]interface{})
			if !ok {
				continue
			}
			ftype := jStr(fmap, "type")
			if ftype != "nested" && ftype != "object" {
				continue
			}
			inner, _ := fmap["properties"].(map[string]interface{})
			if inner != nil {
				walkProps(inner, fname+".")
			}
		}
		if len(vectorFields) > 0 {
			aiStackIndices = append(aiStackIndices, map[string]interface{}{
				"index":          idx,
				"vector_fields":  vectorFields,
			})
		}
	}
	if len(aiStackIndices) > 0 {
		r.RawData["ai_stack_indices"] = aiStackIndices
		r.Details = append(r.Details, fmt.Sprintf(
			"AI-stack signal: %d index(es) with dense_vector/knn_vector field types",
			len(aiStackIndices),
		))
		r.Findings = append(r.Findings, Finding{
			Category: "rag_vector_store",
			Title:    "Elasticsearch backs RAG / vector workload (dense_vector field detected)",
			Severity: "high",
			Detail: fmt.Sprintf(
				"%d index(es) declare vector field types — operator is running a RAG or vector-search pipeline on this cluster.",
				len(aiStackIndices),
			),
			Data: aiStackIndices,
		})
	}

	// Ancient-RCE flag — ES <= 2.x has multiple unauth groovy/MVEL RCEs
	// (CVE-2014-3120, CVE-2015-1427, CVE-2015-5531). Insight #21:
	// "ES 2.9.0 hosts are exposed to multiple unauthenticated RCEs."
	if strings.HasPrefix(r.Version, "1.") || strings.HasPrefix(r.Version, "2.") {
		r.Findings = append(r.Findings, Finding{
			Category: "rce_candidate",
			Title:    "Elasticsearch " + r.Version + " — ancient (pre-X-Pack) with public unauth RCEs",
			Severity: "critical",
			Detail:   "ES 1.x/2.x have multiple unauthenticated RCEs in default config (CVE-2014-3120 Groovy, CVE-2015-1427 sandbox-escape, CVE-2015-5531 path-traversal). Confirm exploitability per host before disclosure framing.",
		})
	}

	return r
}

// ── ClickHouse (v1.9.8) ─────────────────────────────────────────────
//
// Tier-A* — Docker image's default `default` user has no password. 1,832
// unauth instances confirmed at population scale 2026-05-16.
//
// Deep probe pulls SHOW DATABASES + SHOW TABLES via the HTTP GET query
// interface (ClickHouse supports query in URL ?query=... for SELECT and
// SHOW commands — no POST body needed). The DB + table names disclose the
// operator's app schema; `system.*` tables provide cluster topology.
//
// Restraint: SHOW commands + `system.*` queries are pure metadata. No
// SELECT * on user tables, no INSERT, no ALTER, no system.processes
// (which can leak query text including secrets), no system.users (creds).
const (
	chMaxDatabases = 60
	chMaxTables    = 200
)

func enumClickHouse(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// /ping is the platform-identity anchor. The X-ClickHouse-* headers
	// from the fingerprint already proved this is ClickHouse; we use this
	// to capture the Server-Display-Name banner.
	if _, hdr, _, err := httpGET(c, b+"/ping"); err == nil {
		if name := hdr["X-Clickhouse-Server-Display-Name"]; name != "" {
			r.RawData["server_display_name"] = name
		}
	}

	// version() — single-row scalar
	if st, _, body, err := httpGET(c, b+"/?query="+urlQuery("SELECT version()")); err == nil && st == 200 {
		r.Version = strings.TrimSpace(string(body))
		r.Details = append(r.Details, "ClickHouse "+r.Version)
	}

	// SHOW DATABASES — JSONEachRow gives newline-separated {"name":"..."} rows
	st, _, body, err := httpGET(c, b+"/?query="+urlQuery("SHOW DATABASES FORMAT JSONEachRow"))
	if err != nil || st != 200 {
		if st == 401 || st == 403 {
			r.AuthStatus = "auth-gated"
		}
		return r
	}
	r.AuthStatus = "none"

	dbNames := parseJSONEachRowNames(body, "name")
	r.RawData["database_count"] = len(dbNames)
	if len(dbNames) > 20 {
		r.RawData["databases_sample"] = dbNames[:20]
	} else {
		r.RawData["databases_sample"] = dbNames
	}

	if len(dbNames) > 0 {
		r.Findings = append(r.Findings, Finding{
			Category: "unauth_data",
			Title:    "ClickHouse database list reachable without authentication",
			Severity: "high",
			Detail: fmt.Sprintf(
				"GET /?query=SHOW DATABASES returned %d databases unauth (default `default` user has no password in the standard Docker image).",
				len(dbNames),
			),
		})
	}

	// Skip system DBs; sample user DBs for SHOW TABLES
	sysDBs := map[string]bool{
		"system": true, "INFORMATION_SCHEMA": true,
		"information_schema": true, "default": false, // include default — operator usually uses it
	}
	type dbTable struct {
		Database string   `json:"database"`
		Tables   []string `json:"tables"`
	}
	dbTables := make([]dbTable, 0)
	tablesSeen := 0
	for _, db := range dbNames {
		if sysDBs[db] && db != "default" {
			continue
		}
		if tablesSeen >= chMaxTables || len(dbTables) >= chMaxDatabases {
			break
		}
		q := fmt.Sprintf("SHOW TABLES FROM `%s` FORMAT JSONEachRow", strings.ReplaceAll(db, "`", ""))
		st2, _, body2, err2 := httpGET(c, b+"/?query="+urlQuery(q))
		if err2 != nil || st2 != 200 {
			continue
		}
		tbls := parseJSONEachRowNames(body2, "name")
		// trim long table lists
		shown := tbls
		if len(shown) > 25 {
			shown = shown[:25]
		}
		dbTables = append(dbTables, dbTable{Database: db, Tables: shown})
		tablesSeen += len(shown)
	}
	if len(dbTables) > 0 {
		r.RawData["db_tables"] = dbTables
		r.Details = append(r.Details, fmt.Sprintf(
			"%d database(s) enumerated; %d table(s) total in sample",
			len(dbTables), tablesSeen,
		))
	}

	// AI-stack signal: DB / table names suggesting AI workloads.
	aiMarkers := []string{
		"langfuse", "phoenix", "helicone", "signoz", "posthog",
		"vector", "embedding", "rag_", "rag-", "llm",
		"vllm", "ollama", "openai", "anthropic",
		"prompt", "chat_", "completion",
	}
	aiHits := make([]string, 0)
	for _, dt := range dbTables {
		lower := strings.ToLower(dt.Database)
		for _, m := range aiMarkers {
			if strings.Contains(lower, m) {
				aiHits = append(aiHits, "db:"+dt.Database)
				break
			}
		}
		for _, t := range dt.Tables {
			tlower := strings.ToLower(t)
			for _, m := range aiMarkers {
				if strings.Contains(tlower, m) {
					aiHits = append(aiHits, dt.Database+"."+t)
					break
				}
			}
		}
	}
	if len(aiHits) > 0 {
		r.RawData["ai_stack_hits"] = aiHits
		r.Findings = append(r.Findings, Finding{
			Category: "ai_stack_disclosure",
			Title:    "ClickHouse stores AI-stack workload (LLM observability / RAG / vector)",
			Severity: "high",
			Detail: fmt.Sprintf(
				"DB / table names disclose AI workload: %s",
				strings.Join(aiHits, ", "),
			),
			Data: aiHits,
		})
	}

	return r
}

// ── ClickHouse helpers ──────────────────────────────────────────────

// parseJSONEachRowNames pulls the named string field from a JSONEachRow
// response body (one JSON object per line). ClickHouse's JSONEachRow is
// always one row per line; tolerates blank lines + trailing whitespace.
func parseJSONEachRowNames(body []byte, key string) []string {
	out := make([]string, 0)
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if s, ok := m[key].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// urlQuery is a minimal URL-encoder for the `?query=` SHOW-statement use
// case. It encodes spaces and the few characters that break URL parsing;
// ClickHouse accepts unencoded backticks in the query string.
func urlQuery(q string) string {
	repl := strings.NewReplacer(
		" ", "+",
		"\n", "+",
		"\t", "+",
		"#", "%23",
		"&", "%26",
		"?", "%3F",
		"=", "%3D",
	)
	return repl.Replace(q)
}

// ── Rasa (v1.9.23) ──────────────────────────────────────────────────
// Rasa Open Source conversational AI framework. Default port 5005.
// Ships with NO authentication on the REST webhook channel by default.
// Population survey 2026-05-22: 98/196 (50%) unauth, 0 auth-gated.
// Operator classes confirmed: government (ODPC Kenya), utilities, insurance, payment.

func enumRasa(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Version — GET / returns "Hello from Rasa: X.Y.Z"
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		bodyStr := string(body)
		if idx := strings.Index(bodyStr, "Hello from Rasa:"); idx >= 0 {
			version := strings.TrimSpace(bodyStr[idx+len("Hello from Rasa:"):])
			// Trim HTML and excess content
			if end := strings.IndexAny(version, "\n<"); end > 0 {
				version = strings.TrimSpace(version[:end])
			}
			r.Details = append(r.Details, "Version: "+version)
		}
	}

	// Model metadata — GET /status returns {"model_file":"...","num_active_training_jobs":N}
	if st, _, body, err := httpGET(c, b+"/status"); err == nil && st == 200 {
		if m, parseErr := parseJSON(body); parseErr == nil {
			if modelFile, ok := m["model_file"].(string); ok && modelFile != "" {
				r.Details = append(r.Details, "Model: "+modelFile)
				r.Findings = append(r.Findings, Finding{
					Category: "info-leak",
					Title:    "Model file path exposed via /status",
					Detail:   fmt.Sprintf("Model: %s — internal naming conventions disclosed without auth.", modelFile),
					Severity: "low",
				})
			}
		}
	}

	// Auth check — POST /webhooks/rest/webhook with a minimal probe message.
	// 200 + JSON array with recipient_id = unauthenticated.
	// 401/403 = auth configured.
	probeBody := []byte(`{"sender":"aimap-probe","message":"hello"}`)
	if st, _, body, err := httpPOST(c, b+"/webhooks/rest/webhook", "application/json", probeBody); err == nil {
		switch st {
		case 200:
			r.AuthStatus = "none"
			bodyStr := string(body)
			// Confirm it's a real Rasa response (recipient_id field)
			if strings.Contains(bodyStr, "recipient_id") {
				r.Findings = append(r.Findings, Finding{
					Category: "unauth-access",
					Title:    "Unauthenticated Rasa webhook — direct bot invocation",
					Detail:   "POST /webhooks/rest/webhook returns bot responses without authentication. Any caller can inject messages and read responses. Set a token in credentials.yml to require auth.",
					Severity: "high",
				})
			}
		case 401, 403:
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		default:
			r.AuthStatus = fmt.Sprintf("unknown (HTTP %d)", st)
		}
	}

	return r
}

// ── RedisInsight (v1.9.27) ───────────────────────────────────────────
// RedisInsight — Redis official GUI. Default ports: 5540 (v2), 8001 (v1/Docker).
// Ships with no authentication on a default install.
// Insight #61 (2026-05-26): /api/databases returns plaintext Redis passwords.
// 7/27 responsive instances in corpus leaked credentials.

func enumRedisInsight(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Version — GET /api/info returns {"version":"X.Y.Z","appType":"ELECTRON"|"WEB",...}
	if st, _, body, err := httpGET(c, b+"/api/info"); err == nil && st == 200 {
		if m, parseErr := parseJSON(body); parseErr == nil {
			if v := jStr(m, "version"); v != "" {
				r.Version = v
				r.Details = append(r.Details, "Version: "+v)
			}
			if appType := jStr(m, "appType"); appType != "" {
				r.Details = append(r.Details, "AppType: "+appType)
			}
			r.AuthStatus = "none"
		}
	}

	// Database credential extraction — GET /api/databases
	// Returns a JSON array of connection records. Each record may contain:
	//   id, name, host, port, username, password, connectionType, modules[]
	// password is plaintext on default install — no masking, no auth required.
	if st, _, body, err := httpGET(c, b+"/api/databases"); err == nil && st == 200 {
		r.AuthStatus = "none"
		arr, parseErr := parseJSONArray(body)
		if parseErr != nil {
			r.Details = append(r.Details, fmt.Sprintf("/api/databases: HTTP %d (parse error)", st))
		} else {
			r.Details = append(r.Details, fmt.Sprintf("Redis connections configured: %d", len(arr)))
			r.RawData["databases_count"] = len(arr)

			var leakedCreds []map[string]interface{}
			var connections []map[string]interface{}

			for _, item := range arr {
				row, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				name, _ := row["name"].(string)
				host, _ := row["host"].(string)
				connType, _ := row["connectionType"].(string)
				username, _ := row["username"].(string)
				password, _ := row["password"].(string)

				var port int
				switch v := row["port"].(type) {
				case float64:
					port = int(v)
				case int:
					port = v
				}

				var moduleNames []string
				if mods, ok := row["modules"].([]interface{}); ok {
					for _, mod := range mods {
						if mm, ok := mod.(map[string]interface{}); ok {
							if n, ok := mm["name"].(string); ok && n != "" {
								moduleNames = append(moduleNames, n)
							}
						}
					}
				}

				conn := map[string]interface{}{
					"name":           name,
					"host":           host,
					"port":           port,
					"connectionType": connType,
				}
				if username != "" {
					conn["username"] = username
				}
				if len(moduleNames) > 0 {
					conn["modules"] = moduleNames
				}
				connections = append(connections, conn)

				if password != "" {
					credEntry := map[string]interface{}{
						"name":     name,
						"host":     host,
						"port":     port,
						"username": username,
						"password": password,
					}
					leakedCreds = append(leakedCreds, credEntry)
					r.Findings = append(r.Findings, Finding{
						Category: "credentials",
						Title:    "RedisInsight /api/databases leaked Redis credential",
						Detail: fmt.Sprintf(
							"Connection %q (%s:%d) — password exposed in plaintext via unauthenticated /api/databases endpoint.",
							name, host, port,
						),
						Severity: "critical",
						Data:     credEntry,
					})
				}
			}

			if len(connections) > 0 {
				r.RawData["databases"] = connections
			}
			if len(leakedCreds) > 0 {
				r.RawData["leaked_credentials"] = leakedCreds
			}

			if len(arr) > 0 && len(leakedCreds) == 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    fmt.Sprintf("RedisInsight unauthenticated — %d connection record(s) readable", len(arr)),
					Detail:   "GET /api/databases accessible without authentication. No passwords in this response, but host/port/username metadata is exposed.",
					Severity: "high",
				})
			}

			// Chain B: use leaked credentials to probe the Redis keyspace directly.
			// For each connection record with a password, connect to the Redis port
			// and run key-pattern scans. "localhost" in the host field means the
			// RedisInsight host — substitute svc.Host.
			for _, item := range arr {
				row, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				password, _ := row["password"].(string)
				if password == "" {
					continue
				}
				redisHost, _ := row["host"].(string)
				if redisHost == "localhost" || redisHost == "127.0.0.1" || redisHost == "::1" {
					redisHost = svc.Host
				}
				var redisPort int
				switch v := row["port"].(type) {
				case float64:
					redisPort = int(v)
				case int:
					redisPort = v
				}
				if redisPort == 0 {
					redisPort = 6379
				}
				chainBFindings := redisChainBProbe(redisHost, redisPort, password, 8*time.Second)
				r.Findings = append(r.Findings, chainBFindings...)
				if len(chainBFindings) > 0 {
					r.RawData["chain_b_probe"] = map[string]interface{}{
						"redis_host": redisHost,
						"redis_port": redisPort,
						"findings":   len(chainBFindings),
					}
				}
			}
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	return r
}

// ── Argo Workflows ────────────────────────────────────────────────────────────

func enumArgoWorkflows(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// /api/v1/version — identity + version extraction. No auth check in source
	// (GetVersion has no GetClaims call). Fires on all instances.
	if st, _, body, err := httpGET(c, b+"/api/v1/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if v := jStr(m, "version"); v != "" {
				r.Version = v
				r.Details = append(r.Details, fmt.Sprintf("Version: %s", v))
				// Map version to CVE exposure window.
				r.Details = append(r.Details, argoWorkflowsCVEWindow(v))
			}
			if platform := jStr(m, "platform"); platform != "" {
				r.Details = append(r.Details, fmt.Sprintf("Platform: %s", platform))
			}
		}
	}

	// /api/v1/userinfo — auth mode classifier. serviceAccountName only present
	// when --auth-mode=server is active: all callers execute as argo-server SA,
	// no bearer token required. Empty {} = auth enforced.
	if st, _, body, err := httpGET(c, b+"/api/v1/userinfo"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			saName := jStr(m, "serviceAccountName")
			saNS := jStr(m, "serviceAccountNamespace")
			if saName != "" {
				r.AuthStatus = "none"
				r.Details = append(r.Details, fmt.Sprintf("Server mode: runs as SA %s/%s (no bearer token required)", saNS, saName))
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    "Argo Workflows: unauthenticated access (--auth-mode=server)",
					Detail:   fmt.Sprintf("All API endpoints accessible without credentials. Caller inherits argo-server ClusterRole: create/exec/delete workflows and pods cluster-wide. SA: %s/%s. Attack path: POST /api/v1/workflows/{namespace} → arbitrary container execution.", saNS, saName),
					Severity: "critical",
				})
			} else {
				r.AuthStatus = "auth required"
			}
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	// Namespace sweep — enumerate workflows across ML-common namespaces.
	// kubeflow/ml-pipeline carry KFP v1 pipelines with the highest credential density.
	mlNamespaces := []string{"argo", "kubeflow", "ml-pipeline", "training", "data-science", "mlflow", "default"}
	totalWorkflows := 0
	namespacesWithWorkflows := []string{}

	for _, ns := range mlNamespaces {
		url := fmt.Sprintf("%s/api/v1/workflows/%s", b, ns)
		if st, _, body, err := httpGET(c, url); err == nil && st == 200 {
			if m, err := parseJSON(body); err == nil {
				if items, ok := m["items"].([]interface{}); ok && len(items) > 0 {
					totalWorkflows += len(items)
					namespacesWithWorkflows = append(namespacesWithWorkflows, fmt.Sprintf("%s(%d)", ns, len(items)))
					// Scan first workflow spec for credential patterns in parameters.
					if len(items) > 0 {
						argoWorkflowsScanParams(items[0], &r, ns)
					}
				}
			}
		}
	}

	if totalWorkflows > 0 {
		r.RawData["workflow_count"] = totalWorkflows
		r.RawData["namespaces_with_workflows"] = namespacesWithWorkflows
		r.Details = append(r.Details, fmt.Sprintf("Workflows exposed: %d across %v", totalWorkflows, namespacesWithWorkflows))
		r.Findings = append(r.Findings, Finding{
			Category: "data",
			Title:    "Argo Workflows: workflow history and pipeline specs exposed",
			Detail:   fmt.Sprintf("%d workflows readable across namespaces %v. spec.arguments.parameters and status.nodes contain resolved parameter values — credentials passed as workflow parameters appear in plaintext.", totalWorkflows, namespacesWithWorkflows),
			Severity: "high",
		})
	}

	// CVE-2026-28229 probe: Authorization: Bearer nothing retrieves all
	// WorkflowTemplates including embedded K8s secrets on versions < 3.7.11 / < 4.0.2.
	// Probe the default 'argo' namespace; any namespace with templates works.
	for _, ns := range []string{"argo", "kubeflow", "default"} {
		url := fmt.Sprintf("%s/api/v1/workflow-templates/%s", b, ns)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer nothing")
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			if m, err := parseJSON(body); err == nil {
				if items, ok := m["items"].([]interface{}); ok && items != nil {
					r.RawData["cve_2026_28229_templates"] = len(items)
					r.Details = append(r.Details, fmt.Sprintf("CVE-2026-28229: %d WorkflowTemplates retrieved with 'Bearer nothing' in namespace %s", len(items), ns))
					r.Findings = append(r.Findings, Finding{
						Category: "access",
						Title:    "CVE-2026-28229: WorkflowTemplate exfil with fake bearer token",
						Detail:   fmt.Sprintf("GET /api/v1/workflow-templates/%s returned %d templates with 'Authorization: Bearer nothing'. Templates embed K8s secret references, artifact repo credentials (S3/GCS keys), and SA tokens. Affects versions < 3.7.11 / < 4.0.2.", ns, len(items)),
						Severity: "critical",
					})
					break
				}
			}
		}
	}

	// /api/v1/info — managedNamespace reveals scope; links may disclose internal tooling URLs.
	if st, _, body, err := httpGET(c, b+"/api/v1/info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if ns := jStr(m, "managedNamespace"); ns != "" {
				r.Details = append(r.Details, fmt.Sprintf("Managed namespace: %s", ns))
				r.RawData["managed_namespace"] = ns
			}
		}
	}

	// /metrics — version disclosure via argo_workflows_info label even when
	// ARGO_SERVER_METRICS_AUTH is not set. Also reveals workflow queue depth and
	// phase breakdown per namespace.
	if st, _, body, err := httpGET(c, b+"/metrics"); err == nil && st == 200 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "argo_workflows") {
			r.Details = append(r.Details, "Prometheus metrics exposed (/metrics): workflow counts and version labels readable")
			r.Findings = append(r.Findings, Finding{
				Category: "info",
				Title:    "Argo Workflows /metrics exposed",
				Detail:   "Prometheus metrics endpoint returns argo_workflows_info (version label) and per-namespace workflow phase counts without authentication. Reveals operational load and exact version string.",
				Severity: "low",
			})
		}
	}

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "auth required"
	}
	return r
}

// argoWorkflowsCVEWindow returns a CVE exposure summary for a given version string.
func argoWorkflowsCVEWindow(version string) string {
	// Strip leading 'v'.
	v := strings.TrimPrefix(version, "v")
	notes := []string{}

	// CVE-2026-28229: Bearer-nothing WorkflowTemplate exfil. Fixed 3.7.11 / 4.0.2.
	if argoVersionBefore(v, "3.7.11") || (strings.HasPrefix(v, "4.0.") && argoVersionBefore(v, "4.0.2")) {
		notes = append(notes, "CVE-2026-28229(CRIT:WorkflowTemplate exfil via Bearer nothing)")
	}
	// CVE-2025-66626: ZipSlip symlink RCE. Fixed 3.6.14 / 3.7.5.
	if argoVersionBefore(v, "3.6.14") || (strings.HasPrefix(v, "3.7.") && argoVersionBefore(v, "3.7.5")) {
		notes = append(notes, "CVE-2025-66626(HIGH:ZipSlip RCE)")
	}
	// CVE-2024-53862: Archived workflow fake-token bypass. Fixed 3.6.2 / 3.5.13.
	if argoVersionBefore(v, "3.6.2") {
		notes = append(notes, "CVE-2024-53862(HIGH:archived workflow auth bypass)")
	}

	if len(notes) == 0 {
		return "CVE window: no known critical/high CVEs for this version"
	}
	return "CVE window: " + strings.Join(notes, "; ")
}

// argoVersionBefore returns true if version a is strictly before version b.
// Compares major.minor.patch numerically; non-numeric parts are treated as 0.
func argoVersionBefore(a, b string) bool {
	pa := argoParseVer(a)
	pb := argoParseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return true
		}
		if pa[i] > pb[i] {
			return false
		}
	}
	return false
}

func argoParseVer(v string) [3]int {
	// Strip pre-release suffix (e.g. "3.7.11-rc1" → "3.7.11").
	v = strings.SplitN(v, "-", 2)[0]
	parts := strings.Split(v, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		fmt.Sscanf(parts[i], "%d", &out[i])
	}
	return out
}

// argoWorkflowsScanParams checks a workflow item for credential patterns in
// spec.arguments.parameters and flags any that look like secrets.
func argoWorkflowsScanParams(item interface{}, r *EnumResult, ns string) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return
	}
	spec, ok := m["spec"].(map[string]interface{})
	if !ok {
		return
	}
	args, ok := spec["arguments"].(map[string]interface{})
	if !ok {
		return
	}
	params, ok := args["parameters"].([]interface{})
	if !ok {
		return
	}

	credPatterns := []string{"key", "secret", "token", "password", "credential", "cred", "apikey", "api_key", "access", "auth"}
	for _, p := range params {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name := strings.ToLower(jStr(pm, "name"))
		value := jStr(pm, "value")
		for _, pat := range credPatterns {
			if strings.Contains(name, pat) && value != "" {
				r.Findings = append(r.Findings, Finding{
					Category: "credential",
					Title:    fmt.Sprintf("Argo Workflows: credential-pattern parameter in namespace %s", ns),
					Detail:   fmt.Sprintf("Workflow parameter '%s' matches credential naming pattern and has a non-empty resolved value. Credentials passed as workflow parameters are world-readable on unauth instances.", jStr(pm, "name")),
					Severity: "critical",
				})
				r.RawData["credential_param_"+ns] = jStr(pm, "name")
				return // one finding per workflow is sufficient
			}
		}
	}
}


// ── ML Governance / Data Catalog enumerators ─────────────────────────────────

// enumOpenMetadata enumerates OpenMetadata instances.
// CVE-2024-28255 (CVSS 9.8): path parameter injection auth bypass exploited in
// wild. Affects all versions < 1.3.1. /api/v1/system/version is unauthenticated
// and exposes exact version for targeted exploit selection.
func enumOpenMetadata(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Version disclosure — unauthenticated on all versions
	if st, _, body, err := httpGET(c, b+"/api/v1/system/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			version := jStr(m, "version")
			revision := jStr(m, "revision")
			r.Version = version
			r.RawData["version"] = version
			r.RawData["revision"] = revision
			r.Findings = append(r.Findings, Finding{
				Category: "version_disclosure",
				Title:    "OpenMetadata: unauthenticated version disclosure",
				Detail:   fmt.Sprintf("Version %s (revision %s) from /api/v1/system/version without auth. Versions < 1.3.1 are vulnerable to CVE-2024-28255 (CVSS 9.8) — auth bypass + SpEL RCE + datasource credential harvest.", version, revision),
				Severity: "medium",
			})
		}
	}

	// CVE-2024-28255 auth bypass: path parameter injection
	// GET /api/v1/tables;v1=x/ bypasses JWT validation on affected versions.
	if st, _, body, err := httpGET(c, b+"/api/v1/tables;v1=x/"); err == nil {
		if st == 200 && len(body) > 10 {
			r.AuthStatus = "bypass"
			r.Findings = append(r.Findings, Finding{
				Category: "auth_bypass",
				Title:    "OpenMetadata: CVE-2024-28255 auth bypass confirmed",
				Detail:   "GET /api/v1/tables;v1=x/ returned 200 — path parameter injection bypasses JWT auth. Chain: auth bypass → SpEL RCE → env var harvest of all connected datasource credentials. Actively exploited in wild against K8s clusters. CVSS 9.8.",
				Severity: "critical",
			})
			r.RawData["bypass_body_len"] = len(body)
		}
	}

	// Table inventory depth
	if st, _, body, err := httpGET(c, b+"/api/v1/tables?limit=1"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if paging, ok := m["paging"].(map[string]interface{}); ok {
				r.RawData["table_count"] = paging["total"]
			}
		}
	}

	// Database service connections
	if st, _, body, err := httpGET(c, b+"/api/v1/services/databaseServices?limit=25"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data, ok := m["data"].([]interface{}); ok && len(data) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data_exposure",
					Title:    fmt.Sprintf("OpenMetadata: %d database service connections enumerated", len(data)),
					Detail:   "Database service list accessible without auth — exposes connection metadata, service types, and lineage config.",
					Severity: "high",
				})
				r.RawData["db_service_count"] = len(data)
			}
		}
	}

	if r.AuthStatus == "" {
		r.AuthStatus = "on"
	}
	return r
}

// enumDataHub enumerates DataHub GMS (Generalized Metadata Service) instances.
// GMS is auth-off by default; even when METADATA_SERVICE_AUTH_ENABLED=true,
// JWT signatures are not cryptographically verified — forge any user token.
// Default credentials: datahub/datahub on the frontend (port 9002).
func enumDataHub(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Unauthenticated /config endpoint — unique to DataHub GMS
	if st, _, body, err := httpGET(c, b+"/config"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if jHas(m, "noCode") {
				r.AuthStatus = "none"
				r.RawData["config"] = m
				r.Findings = append(r.Findings, Finding{
					Category: "auth_off",
					Title:    "DataHub GMS: unauthenticated /config endpoint",
					Detail:   "GMS /config returned 200 without credentials. METADATA_SERVICE_AUTH_ENABLED is likely false (default). Full org data inventory, lineage graphs, PII classification, and ingestion source configs are readable without auth.",
					Severity: "high",
				})
			}
		}
	}

	// Entity read confirmation
	if st, _, body, err := httpGET(c, b+"/entities?urns[0]=urn:li:corpuser:datahub"); err == nil && st == 200 {
		if len(body) > 20 {
			r.Findings = append(r.Findings, Finding{
				Category: "data_exposure",
				Title:    "DataHub GMS: unauthenticated entity read confirmed",
				Detail:   "GET /entities?urns[0]=urn:li:corpuser:datahub returned 200 with body — full entity graph readable without auth.",
				Severity: "high",
			})
			r.RawData["entity_read_confirmed"] = true
		}
	}

	if r.AuthStatus == "" {
		r.AuthStatus = "on"
	}
	return r
}

// enumApacheAtlas enumerates Apache Atlas instances.
// Default credentials admin/admin are baked into users-credentials.properties
// and rarely rotated in enterprise deployments.
func enumApacheAtlas(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Version check with default admin:admin
	req, err := http.NewRequest("GET", b+"/api/atlas/admin/version", nil)
	if err == nil {
		req.SetBasicAuth("admin", "admin")
		req.Header.Set("User-Agent", "aimap/"+Version+" (security-research)")
		resp, err2 := c.Do(req)
		if err2 == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == 200 {
				r.AuthStatus = "default_credentials"
				if m, err3 := parseJSON(body); err3 == nil {
					r.Version = jStr(m, "Version")
					r.RawData["version"] = r.Version
				}
				r.Findings = append(r.Findings, Finding{
					Category: "default_credentials",
					Title:    "Apache Atlas: default credentials admin/admin accepted",
					Detail:   fmt.Sprintf("Version %s. admin/admin accepted at /api/atlas/admin/version. Full Hadoop/big-data inventory, PII classification rules, Hive tables, HDFS paths, Kafka topics, and entity lineage accessible.", r.Version),
					Severity: "critical",
				})
			} else if resp.StatusCode == 401 {
				r.AuthStatus = "on"
				r.RawData["default_creds_rejected"] = true
			}
		}
	}

	return r
}

// enumMarquez enumerates Marquez (OpenLineage API server) instances.
// No auth by default. Full pipeline lineage graph is readable and writable.
// Unauthenticated POST to /api/v1/lineage enables arbitrary lineage injection.
func enumMarquez(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Namespace list — unauthenticated, unique to Marquez
	if st, _, body, err := httpGET(c, b+"/api/v1/namespaces"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if namespaces, ok := m["namespaces"].([]interface{}); ok {
				r.AuthStatus = "none"
				r.RawData["namespace_count"] = len(namespaces)
				r.Findings = append(r.Findings, Finding{
					Category: "auth_off",
					Title:    fmt.Sprintf("Marquez: %d namespaces readable without authentication", len(namespaces)),
					Detail:   "GET /api/v1/namespaces returned namespace list without auth. Full pipeline lineage — job names, dataset schemas, run history, SQL query text in OpenLineage facets — readable and writable.",
					Severity: "medium",
				})
				// Sample first namespace for job enumeration
				if len(namespaces) > 0 {
					if ns, ok := namespaces[0].(map[string]interface{}); ok {
						nsName := jStr(ns, "name")
						r.RawData["first_namespace"] = nsName
						if st2, _, body2, err2 := httpGET(c, b+"/api/v1/jobs?namespace="+nsName+"&limit=5"); err2 == nil && st2 == 200 {
							r.RawData["first_ns_jobs_body_len"] = len(body2)
						}
					}
				}
			}
		}
	}

	if r.AuthStatus == "" {
		r.AuthStatus = "on"
	}
	return r
}

// ── LiteLLM ─────────────────────────────────────────────────────────
//
// LiteLLM is an OpenAI-compatible proxy gateway that routes requests to
// multiple upstream LLM providers (OpenAI, Azure, Anthropic, Gemini, etc.).
// Unauthenticated instances expose every upstream API key configured by the
// operator, the full model routing table, spend logs, and in some
// configurations the per-key credential list — a full LLMjacking surface.
//
// The master_key field controls auth. When absent or blank, the /v1/models
// endpoint is open to the internet and all probes below succeed without
// credentials. Even auth-on installs leak version and upstream topology
// via /health and /health/readiness.

func enumLiteLLM(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// 1. /health — version, health counters, unhealthy upstream names
	if st, _, body, err := httpGET(c, b+"/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if v := jStr(m, "litellm_version"); v != "" {
				r.Version = v
				r.Details = append(r.Details, "LiteLLM version: "+v)
			}
			healthyCount := int(jFloat(m, "healthy_count"))
			unhealthyCount := int(jFloat(m, "unhealthy_count"))
			r.Details = append(r.Details, fmt.Sprintf("Upstream endpoints: %d healthy, %d unhealthy", healthyCount, unhealthyCount))
			r.RawData["health"] = m

			// Unhealthy endpoint names reveal internal upstream routing config
			if unhealthyCount > 0 {
				if unhealthyArr := jArray(m, "unhealthy_endpoints"); unhealthyArr != nil {
					var names []string
					for _, ep := range unhealthyArr {
						if epMap, ok := ep.(map[string]interface{}); ok {
							if model := jStr(epMap, "model"); model != "" {
								names = append(names, model)
							}
						}
					}
					if len(names) > 0 {
						r.Details = append(r.Details, fmt.Sprintf("Unhealthy upstream models: %s", strings.Join(names, ", ")))
						r.Findings = append(r.Findings, Finding{
							Category: "config",
							Title:    fmt.Sprintf("Unhealthy upstream endpoint names disclosed (%d models)", len(names)),
							Detail:   fmt.Sprintf("models: %s", strings.Join(names, ", ")),
							Severity: "info",
						})
					}
				}
			}
		}
	}

	// 2. /model/info — upstream api_base URLs, model routing table
	// api_base values are internal upstream LLM endpoint URLs (Azure deployments,
	// private OpenAI-compat servers, etc.). Their presence confirms the operator
	// has not set LITELLM_MASK_API_BASE=true and reveals internal infrastructure.
	if st, _, body, err := httpGET(c, b+"/model/info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			dataArr := jArray(m, "data")
			if dataArr != nil {
				var modelNames []string
				var apiBases []string
				var providers []string

				for _, entry := range dataArr {
					entryMap, ok := entry.(map[string]interface{})
					if !ok {
						continue
					}
					if mn := jStr(entryMap, "model_name"); mn != "" {
						modelNames = append(modelNames, mn)
					}
					if params := jMap(entryMap, "litellm_params"); params != nil {
						if ab := jStr(params, "api_base"); ab != "" {
							apiBases = append(apiBases, ab)
						}
						if mdl := jStr(params, "model"); mdl != "" {
							// model field format is "provider/name" e.g. "openai/gpt-4o"
							if idx := strings.Index(mdl, "/"); idx > 0 {
								providers = append(providers, mdl[:idx])
							}
						}
					}
				}

				if len(modelNames) > 0 {
					r.Details = append(r.Details, fmt.Sprintf("Models configured: %d (%s)", len(modelNames), strings.Join(modelNames, ", ")))
					r.RawData["model_names"] = modelNames
				}

				if len(providers) > 0 {
					// Deduplicate providers
					seen := map[string]bool{}
					var uniq []string
					for _, p := range providers {
						if !seen[p] {
							seen[p] = true
							uniq = append(uniq, p)
						}
					}
					r.Details = append(r.Details, fmt.Sprintf("Upstream providers: %s", strings.Join(uniq, ", ")))
					r.RawData["upstream_providers"] = uniq
				}

				if len(apiBases) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "API_BASE_LEAK",
						Title:    fmt.Sprintf("Internal upstream API base URLs exposed (%d endpoints)", len(apiBases)),
						Detail:   fmt.Sprintf("api_base values: %s — these are the operator's upstream LLM endpoint URLs. May include Azure private deployments, self-hosted model servers, or internal routing infrastructure.", strings.Join(apiBases, "; ")),
						Severity: "high",
					})
					r.RawData["api_bases"] = apiBases
				}
			}
		}
	}

	// 3. /v1/models — model list; if accessible without auth → UNAUTH_ENUM
	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				modelArr := jArray(m, "data")
				var ids []string
				for _, entry := range modelArr {
					if em, ok := entry.(map[string]interface{}); ok {
						if id := jStr(em, "id"); id != "" {
							ids = append(ids, id)
						}
					}
				}
				r.Details = append(r.Details, fmt.Sprintf("Models enumerable: %d", len(ids)))
				r.RawData["v1_models"] = ids
				r.Findings = append(r.Findings, Finding{
					Category: "UNAUTH_ENUM",
					Title:    fmt.Sprintf("LiteLLM model list accessible without master_key (%d models)", len(ids)),
					Detail:   "GET /v1/models returned the full model routing table without authentication. Any caller can enumerate configured upstream providers and send requests that consume the operator's API quota.",
					Severity: "high",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// 4. /metrics — Prometheus endpoint; check for user/team/key labels (PII)
	if st, _, body, err := httpGET(c, b+"/metrics"); err == nil && st == 200 {
		bodyStr := string(body)
		var piiLabels []string
		for _, label := range []string{"litellm_team_alias", "litellm_api_key_hash", "litellm_user"} {
			if strings.Contains(bodyStr, label) {
				piiLabels = append(piiLabels, label)
			}
		}
		if len(piiLabels) > 0 {
			r.Findings = append(r.Findings, Finding{
				Category: "PII_METRICS_LEAK",
				Title:    fmt.Sprintf("Prometheus metrics expose user/team labels (%s)", strings.Join(piiLabels, ", ")),
				Detail:   "/metrics endpoint accessible and contains per-user or per-team telemetry labels. Labels may include hashed API keys, team names, and usernames associated with request traffic.",
				Severity: "medium",
			})
			r.RawData["pii_metrics_labels"] = piiLabels
		} else {
			r.Details = append(r.Details, "/metrics accessible (no user/team labels detected)")
		}
	}

	// 5. /health/readiness — DB connectivity; PostgreSQL backend = CVE-2026-42208 eligible
	if st, _, body, err := httpGET(c, b+"/health/readiness"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			dbStatus := jStr(m, "db")
			r.RawData["readiness"] = m
			if strings.EqualFold(dbStatus, "connected") {
				r.Findings = append(r.Findings, Finding{
					Category: "POSTGRES_BACKEND",
					Title:    "PostgreSQL backend confirmed via /health/readiness",
					Detail:   "db=connected in /health/readiness response. LiteLLM with a connected PostgreSQL backend is in the CVE-2026-42208 SQLi vulnerability class. Verify version against the patched release before treating as confirmed.",
					Severity: "info",
				})
				r.Details = append(r.Details, "PostgreSQL backend: connected")
			}
		}
	}

	// 6. /spend/logs — spend log access without auth
	if st, _, body, err := httpGET(c, b+"/spend/logs"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil && len(arr) > 0 {
			r.Findings = append(r.Findings, Finding{
				Category: "SPEND_LEAK",
				Title:    fmt.Sprintf("Spend log accessible without authentication (%d entries)", len(arr)),
				Detail:   "/spend/logs returned data without auth. Contains per-request cost attribution, model routing decisions, and API key identifiers for all traffic through the proxy.",
				Severity: "medium",
			})
			r.RawData["spend_log_count"] = len(arr)
		} else if m, err := parseJSON(body); err == nil {
			// Some versions return {"data":[...]} shape
			if dataArr := jArray(m, "data"); len(dataArr) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "SPEND_LEAK",
					Title:    fmt.Sprintf("Spend log accessible without authentication (%d entries)", len(dataArr)),
					Detail:   "/spend/logs returned data without auth. Contains per-request cost attribution, model routing decisions, and API key identifiers for all traffic through the proxy.",
					Severity: "medium",
				})
				r.RawData["spend_log_count"] = len(dataArr)
			}
		}
	}

	// 7. /key/list — API key enumeration; 200 = full credential leak
	if st, _, body, err := httpGET(c, b+"/key/list"); err == nil {
		if st == 200 {
			r.Findings = append(r.Findings, Finding{
				Category: "KEY_LIST_EXPOSED",
				Title:    "LiteLLM API key list accessible without authentication",
				Detail:   "GET /key/list returned HTTP 200. The key management endpoint is unauthenticated. All virtual keys issued through the proxy — including their upstream provider bindings — are enumerable without credentials.",
				Severity: "critical",
			})
			r.RawData["key_list_body_len"] = len(body)
			if r.AuthStatus != "none" {
				r.AuthStatus = "none"
			}
		}
	}

	if r.AuthStatus == "unknown" {
		r.AuthStatus = "on"
	}

	return r
}
