# Changelog

All notable changes to aimap are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [v1.9.28] - 2026-05-26

### Added: Evolution API (WhatsApp) fingerprint

**Evolution API** (default ports: 8080, 3000) — open-source WhatsApp automation
framework. Unauthenticated access exposes WhatsApp session management: create/destroy
sessions, send messages, read conversation history, extract QR codes for session
hijacking.

**Fingerprint (three-conjunct, Insight #6 discipline):**
- Primary: `GET /` → `status_code:200` + `json_field:version` + `body_contains:house`
  ("I'm in the house!" is the product-unique banner in every Evolution API response)
- Secondary: `GET /manager` → `status_code:200` — Evolution Manager SPA path

Severity: high. First confirmed live: 192.169.81.2:8080 (bmaconnect.com.br, Brazilian
WhatsApp SaaS) — 2026-05-26.

---

## [v1.9.27] - 2026-05-26

### Added: RedisInsight fingerprint + enumerator (Insight #61)

**RedisInsight** (default ports: 5540 for v2, 8001 for v1/Docker; also covers 80/443/8080):

RedisInsight ships with no authentication on a default install. `GET /api/databases`
returns connection records — including the `password` field in plaintext — with no
credentials required. Insight #61 (2026-05-26): 7 of 27 responsive instances in the
corpus leaked Redis credentials this way.

**Fingerprint (three-conjunct, Insight #6 discipline):**
- Primary: `GET /api/info` → `json_field:version` — RedisInsight-specific info endpoint
- Secondary: `GET /api/databases` → `status_code:200` + `json_array` — connection list (empty array on fresh install, still fires)
- Tertiary: `GET /` → `body_contains:RedisInsight` — SPA title fallback

**Enumerator (`enumRedisInsight`):**
- Extracts version + appType from `GET /api/info`
- Calls `GET /api/databases` and parses the JSON array
- For each connection: extracts `name`, `host`, `port`, `username`, `password`, `connectionType`, `modules[]`
- If `password != ""`: CRITICAL finding "RedisInsight /api/databases leaked Redis credential" with full credential struct in `Data`
- If connections present but no passwords: HIGH finding (metadata still exposed)
- All connection records stored in `raw_data.databases`; creds also in `raw_data.leaked_credentials`

Severity: critical. Verified live against 35.210.76.182:8001 — "CMS-Prod-Redis-DB"
credential leaked on first probe.

---

## [v1.9.26] - 2026-05-22

### Added: Rasa chatbot framework fingerprint + enumerator

**Rasa** (default port 5005; also covers 80/443/8080 for proxied deployments):

Rasa Open Source ships with no authentication on `/webhooks/rest/webhook` by default.
Operators must explicitly configure a token in `credentials.yml`; most do not.
Population survey 2026-05-22: 98/196 (50%) confirmed unauthenticated, 0 auth-gated.
Operator classes confirmed: government (ODPC Kenya / odpc.go.ke), electricity utilities
(LECO Sri Lanka, Uludağ Elektrik), insurance (HNBGI), payment validation, education.
Versions confirmed in corpus: 2.8.0, 3.5.10, 3.6.20, 3.9.6.

**Fingerprint (three-conjunct, Insight #6 discipline):**
- Primary: `GET /` → `body_contains:"Hello from Rasa:"` — product-unique version banner
- Secondary: `GET /status` → `json_field:model_file` — Rasa-specific status schema
- Tertiary: `GET /webhooks/rest/webhook` → `status_code:405` + `header_contains:Allow:GET` — confirms webhook endpoint exists without triggering a POST interaction

**Enumerator:**
- Extracts version string from GET / banner
- Extracts model file path from GET /status (LOW: internal naming disclosed)
- Auth check: POST /webhooks/rest/webhook with probe message → `auth_status: none` or `required`
- HIGH finding on unauthenticated webhook with remediation: "Set a token in credentials.yml"

Severity: high.

---

## [v1.9.25] - 2026-05-22

### Added: Opik LLM evaluation platform fingerprint

**Opik** (Comet ML, default ports: 5173, 80, 443, 8080):
- `GET /api/v1/private/projects` → `{"page":N,"total":N,"content":[...]}` — conjunctive on `status_code:200` + `json_field:total` + `json_field:content`. Path `/api/v1/private/` is Opik-specific (not shared with Langfuse or other observability platforms).
- `GET /` → `body_contains:Comet Opik` fallback for deployments behind a reverse proxy that gates the API but exposes the SPA.
- Fingerprinted live against 80.79.202.18:5173 (Opik v1.10.13) during 2026-05-22 ClimateGPT/vLLM session. Nginx SPA on :5173; VITE_BASE_API_URL="/api" confirmed via JS-bundle extraction.
- Auth: `OPIK_AUTHENTICATION_ENABLED=false` is the shipped default → fully unauthenticated API on fresh deploy.
- Severity: high. `/api/v1/private/projects`, `/api/v1/private/traces`, `/api/v1/private/spans` expose LLM evaluation run history, prompt/response pairs, token counts, scores, and dataset contents.
- Port 5173 was already in `port_classes.go`; this fingerprint makes Opik a named target at that port.

---

## [v1.9.24] - 2026-05-22

### Added: Evidently ML Monitoring fingerprint (LLM observability stragglers)

**Evidently ML Monitoring** (default ports: 8000, 3000, 80, 443, 8080):
- `GET /api/version` → `{"application":"Evidently UI","version":"...","commit":"..."}` — exact string `Evidently UI` in the `application` JSON field. Unambiguous; available unauthenticated on default deploy.
- Fingerprinted live against `evidently/evidently-service:latest` (v0.7.21) during the 2026-05-22 Evidently population survey.
- Auth posture: Tier-A (no auth concept). `/api/version` and `/api/projects` both 200 with no credentials on fresh install.
- Severity: high. `/api/projects/{id}/...` tree exposes ML experiment configurations, model evaluation scores, data drift reports, and dataset references.
- Shodan dorks catalogued in `shodan/queries/24-observability.md`.

---

## [v1.9.23] - 2026-05-21

### Added: LangGraph Server, SuperAGI, AgentGPT fingerprints (cat-06 agent framework stragglers)

Three new fingerprints for the agent-framework stragglers category (cat-06).
Source-researched and cross-validated against the 2026-05-16 survey case study
and a live LangGraph Server instance (jiaotong-2026-05-07).

**LangGraph Server** (default ports: 2024, 8123, 8000, 80, 443):
- `GET /` → `{"service":"LangGraph Pipelines Service","version":"1.0.0","pipeline_id":"..."}` — source-verified
- `GET /info` fallback — json_field:version + body_contains:langgraph
- Severity: high. No auth concept in dev mode; unauth = full thread history + graph definitions.
- `pipeline_id` field names the operator's agent graph (operator-attribution rich).

**SuperAGI** (default ports: 3000, 8001, 80, 443):
- `GET /` → HTML body_contains:SuperAGI
- `GET /health` → json_field:version + body_contains:superagi
- Severity: high. 40% of 2026-05-16 sample auth-gated; 60% open. `/api/v1/agents` discloses full agent roster + goals + tool assignments.

**AgentGPT** (default ports: 3000, 80, 443):
- `GET /` → body_contains:AgentGPT + body_contains:reworkd (conjunctive — two anchors required)
- Severity: high. SPA-only; no JSON identity endpoint. All 12 confirmed Shodan hits returned 200/no-auth in 2026-05-16 survey.

**Skipped (documented):**
- CrewAI Studio — library not server; no canonical HTTP surface to fingerprint.
- Goose (Block) — desktop-first local agent runner; no server deployment mode.

Cross-reference: Survey cat-06 2026-05-21, Insight #21 (port-first beats brand-dork for low-footprint platforms).

## [v1.9.22] - 2026-05-19

### Added: sub2api fingerprint + `-ports-class` profiles

Two gaps surfaced during the 2026-05-19 sub2api population survey.

**Sub2api fingerprint** (`fingerprints.go`):

Wei-Shaw/sub2api is the Go-rewrite successor to claude-relay-service.
7,720 hosts indexed on Shodan as of survey day. The survey forced a
custom 130-line `verify_probe.py` to be written because aimap had no
sub2api fingerprint. Now it does.

Three conjunctive anchors per Insight #6 discipline:

1. `/v1/models` 401 with verbatim `API_KEY_REQUIRED` envelope and the
   exact "API key is required in Authorization header (Bearer scheme)"
   message — the highest-precision single signature, sourced from the
   sub2api Go source at `backend/internal/gateway/*`.
2. `/setup/status` 200 with the sub2api `{code:0, data:{needs_setup,
   step}}` envelope — catches both pre-setup and post-setup states.
3. `/api/v1/admin/users` 401 with sub2api `{"code":"UNAUTHORIZED"}`
   envelope — confirms admin-surface auth-on-default.

Default ports: `8080, 443, 8090, 3000` (matches the population
distribution: 5,121 / 7,720 hosts on :8080, 1,073 on :443).

Severity: `high`. SETUP_OPEN substate (1.31% of the v2 population)
should be flagged per VisorScuba rule AI.H6 — see
github.com/Nicholas-Kloster/VisorScuba.

Cross-reference: Insight #40 (auth-on-default thesis shifts rightward
in successor OSS generations) at
github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/methodology/.
v2 sub2api hardened the v1 publicly-readable pool-stats surface;
**0 of 7,720 hosts had POOL_LEAK** in the survey.

**`-ports-class <name>` flag** (`port_classes.go`):

14 predefined port profiles for service-focused surveys, replacing the
51-port default catch-all when narrower coverage suffices:

- `llm-gateway`, `vector-db`, `observability`, `registry`,
  `network-mesh`, `workflow-orch`, `browser-control`, `sub2api`,
  `jetson`, `healthcare`, `finance`, `mcp`, `wide` (the existing
  51-port default kept as a named profile), `minimal` (80/443/8080/8443).

For a service-focused survey this is a 5-10× wall-time reduction.
The 2026-05-19 sub2api survey ran 22 minutes on the 51-port default;
the same survey with `-ports-class sub2api` (6 ports) would have
finished in ~3 minutes.

`ListPortClasses()` is exported so future tools (`visor versions`
sibling) can introspect the available profiles.

### Tests

Existing test suite passes clean (0.674s). Sub2api fingerprint was
not added to `fingerprints_systematic_ports_test.go` in this commit;
a follow-up will extend that to cover the new entry.

## [v1.9.21] - 2026-05-19

### Fixed: data race in watchdog tests (race detector under Go 1.25)

`watchdog_test.go` shared a `bytes.Buffer` between the watchdog goroutine and
the test, which `go test -race` (added to CI in v1.9.19) flags as unsafe
concurrent access. Wrapped the buffer in a `safeBuf` (mutex-protected
Write/String/Len) so the test reader and the goroutine writer are properly
synchronized.

The watchdog itself is unaffected — the race lives in the test harness.

CI is now race-clean.

## [v1.9.20] - 2026-05-19

### Fixed: IPv6 address formatting in `scanPorts` and `clawdbotWSProbe`

Latent bug surfaced by Go 1.25's `vet`: `fmt.Sprintf("%s:%d", host, port)` does
not produce a valid `net.Dial` address when `host` is an unbracketed IPv6
literal — `2001:db8::1:443` is ambiguous (host with embedded port? or host
ending in `:1` with port `:443`?). For IPv6, the address must be
`[host]:port`. Replaced both call sites with
`net.JoinHostPort(host, strconv.Itoa(port))`, which handles both IPv4 and
IPv6 correctly.

`parseTargets` in `utils.go` already strips brackets from IPv6 literals and
returns the bare address, so unbracketed IPv6 hosts can reach the dial
helpers. Before this fix, IPv6 scanning silently failed at the dial step.
After: IPv6 hosts work end-to-end.

The bug was inherited from the v1.0 implementation; local `go vet` (1.22)
did not flag it; the v1.9.19 CI run with Go 1.25 surfaced it and failed
the build.

No new tests (the existing test suite passes and the fix is mechanical),
but the fix is now CI-verified on every push via the workflow added in
v1.9.19.

## [v1.9.19] - 2026-05-19

### Fingerprint hardening: Insight #6 anchoring discipline applied to the 24
### remaining naked body_contains probes (close-out of the v1.9.17 audit gap)

The v1.9.17 internal audit identified 24 fingerprint probes in `fingerprints.go`
that used a single-condition `body_contains` against a short token, in direct
violation of the README's load-bearing rule ("naked single-word body_contains
is unsound at population scale"). v1.9.19 closes all 24.

**Fixed (16 high-FP-risk probes anchored to status + structured signal):**

- **vLLM `/v1/models`**: added `status_code=200` + `json_field=data` — rejects
  blog/marketing pages mentioning "vllm" that don't return the OpenAI-compat
  JSON shape.
- **LiteLLM `/health`**: added `status_code=200` + `json_field=healthy_count`.
- **LiteLLM `/model/info`**: now requires `body_contains "litellm_params"` (the
  LiteLLM-specific marker) rather than the bare brand.
- **Jupyter Notebook `/` fallback**: added `status_code=200` + `<title>` +
  `Jupyter` — rejects pages that merely mention the brand.
- **Milvus `/api/v1/health`**: converted `body_contains "is_healthy"` to
  `json_field=is_healthy` + `status_code=200`. The bare substring would have
  matched any K8s readiness-probe response.
- **Langfuse `/` fallback**: added `body_contains "__NEXT_DATA__"` to require
  the real Langfuse Next.js bundle marker.
- **Kubeflow `/` fallback**: added `status_code` + `<title>` anchor.
- **Whisper ASR `/inference`**: anchored to `status_code=400` (the spec-mandated
  error response when probed without multipart body).
- **dcm4chee `/dcm4chee-arc/` fallback**: added `status_code=200`.
- **Clawdbot, Coolify, Dify, OpenHands HTML-title probes**: added
  `status_code=200` to all four. The title tag was already a structured
  signal; status anchor closes the 500/404-page-with-title FP class.

**Fixed (11 Exposed API Credentials probes, Insight #38 cross-cutting):**

All 11 vendor-prefix probes (`sk-lf-`, `sk-helicone-`, `sk_live_`, `sk_test_`,
`sk-ant-api03-`, `lsv2_pt_`, `lsv2_sk_`, `sk-or-v1-`, `xoxp-`, plus two
`LANGFUSE_SECRET_KEY` env-var paths) now anchor on `status_code=200`.
Credential leaks in the wild come from 200-response surfaces (env-var dumps,
build logs, JS bundles, debug endpoints). The hard-proof validation still
happens at the enumerator stage via `scanCredentials` regex extraction +
format validation per `credentialClass`.

**Fixed (2 MCP Server permissive fallbacks):**

Probes 7 and 9 of the MCP Server fingerprint (the deliberately permissive
fallbacks at `/mcp` and `/` matching `Mcp-Session-Id`) now also require
`body_not_contains "<!DOCTYPE html"` — keeps the spec-unique-string recall
while excluding the HTML doc-page FP class (vendor docs / blog posts that
mention the spec header name).

**Regression tests.** Added `fingerprints_anchoring_test.go` with 20 named
test cases: every fix has a TP test (real-shape response still matches) and
a FP-reject test (the previously-FP-prone response is now rejected). Plus
`TestExposedCreds_AllPrefixesCovered` — an inventory test that fails if a
new `credentialClass` is added in `enum_credentials.go` without a matching
fingerprint probe.

### scanSecrets ported to validation discipline (Insight #38 generalized)

`scanSecrets` previously emitted every match at `Severity: "critical"` regardless
of evidence. A bare doc-page mention of `POSTGRES_PASSWORD` produced the same
finding as a real env-var dump with a 40-char value. Insight #38's validation
ladder is now generalized to `scanSecrets`:

- **secretPattern struct** gains `Value *regexp.Regexp` (extracts the value
  following the anchor) and `Format *regexp.Regexp` (validates extracted
  shape) and `BaseSev` (severity when only the anchor is present).
- **Severity ladder:**
  - anchor only → `BaseSev` (medium for env-var names, high for credential
    prefixes, low for very generic anchors like `HUGGING_FACE`)
  - anchor + value extracted, Format match → `critical`
  - anchor + value extracted, Format mismatch → `BaseSev` (no downgrade since
    the value is still suspicious)

`HUGGING_FACE` (a very generic anchor that previously fired critical on any
doc page) now emits at `low` unless a real `hf_xxx` value is extracted.
Twelve env-var patterns get format-validated against vendor-documented
shapes (sk-proj-/sk-ant-/AKIA/AIza/hf_/etc.).

Memory rule satisfied: `feedback_100_percent_verified_tier_labels.md` —
every tier label requires 100% verified evidence at that tier.

Regression tests added in `scan_secrets_test.go`: anchor-only emits at
BaseSev; format-validated values escalate to critical; format-mismatch stays
at BaseSev; the pre-v1.9.19 "false critical regression" case (bare doc-page
mention of POSTGRES_PASSWORD) now produces no critical finding.

### Registry-pattern dispatcher (replaces 50-arm switch)

`runEnumerators`'s 50-arm switch statement converted to a registry lookup:

```go
type enumeratorFn func(c *http.Client, svc ServiceMatch) EnumResult
var enumeratorRegistry = map[string]enumeratorFn{
    "Weaviate":          enumWeaviate,
    "Ollama":            enumOllama,
    "llama.cpp server":  enumLlamaCpp,
    // ... 50 entries grouped by category
}
```

Adding a new enumerator is one-line registration (next to its `enumXxx`
definition or in the central table); "did you wire it up?" becomes a
compile-time check rather than a silent "no enumerator ran" miss. No
behavior change — same 50 enumerators dispatch to the same functions.

### enum_credentials.go: credential-scanning code extracted from enumerators.go

The credential/secret-scanning code (363 lines) moved out of the 4,500-line
`enumerators.go` into a new `enum_credentials.go`:

- `secretPattern` type + `secretPatterns` table
- `credentialClass` type + `credentialClasses` table
- `redactKey`, `scanCredentials`, `scanSecrets`
- `enumExposedCredentials` (the cross-cutting enumerator that chains both
  scanners against `/`, `/env`, `/debug/vars`, `/.env`, `/config`, etc.)

This is a partial split of the v1.9.17 refactor item. The full
enumerators.go category split (per-category files: enum_vector.go,
enum_llm.go, enum_observability.go, enum_orchestration.go, enum_bi.go,
enum_safety.go) is queued for a separate refactor commit since each
remaining file move is mechanical but high-volume.

### GitHub Actions CI

New `.github/workflows/ci.yml`:

- `build-and-test` job: `go build`, `go vet`, `go test -race`, plus a
  `-version`/`const Version` consistency check that fails the build if the
  flag's output disagrees with `version.go`.
- `cross-platform-build` matrix job: builds linux+darwin × amd64+arm64 on
  every push/PR. Catches `GOOS`/`GOARCH` regressions before they ship.

### PKGBUILD sha256 backfill

`PKGBUILD` `sha256sums` was set to `SKIP` in v1.9.18 because the source
tarball had not yet been generated by GitHub. v1.9.19 backfills the
v1.9.18 hash (then sets the v1.9.19 hash to `SKIP` again pending the next
tag-push). Downstream packagers can verify the v1.9.18 tarball against
`46c6787bc13554f969a03727908715e58c2c4fc56fcda777d394b2245e5487cb`.

### Source

v1.9.17 internal review. The six follow-up items identified in that review
all closed in this release. No new fingerprints. No new enumerators. All
tests pass; 31 new regression tests added (20 anchoring + 9 scan-secrets +
2 dispatch inventory).

## [v1.9.18] - 2026-05-19

### Documentation refresh + version-string consolidation

The doc-and-release drift catch-up. Public-facing artifacts had fallen behind
the code by months; this release brings them current and removes the failure
mode that produced the gap.

**Version-string consolidation.** Single source of truth in `version.go` as
`const Version = "1.9.18"`. The banner in `reporter.go`, the JSON
`ToolVersion` field, the HTTP User-Agent, and the new `-version` flag all
read from there. No more three-place drift on every release (banner was
frozen at `v1.8`, ToolVersion at `1.9.16`, User-Agent at `1.0`).

**Added: `-version` flag.** `aimap -version` prints `aimap 1.9.18` and exits.
Operators can now determine the version without launching a scan.

**README refresh.** Service count corrected from 66 to 120 (50 dedicated deep
enumerators). The 11-row category table expanded to 24 rows covering every
fingerprint that ships, including the categories added across v1.4–v1.9:
image generation, embedding servers, code assistants, agent memory, data
labeling, MCP, observability/tracing, analytical datastores, medical AI/PACS,
and the cross-cutting credential scanner. About section reframed to honor
both audiences — defenders running it against their own networks and
researchers running it against authorized populations — and to credit the
population-FP discipline that every shipped fingerprint passes.

**Man page refresh.** `aimap.1` had been frozen at "aimap 1.3, April 2026,
36 services." Updated to 1.9.18, May 2026, 120 services across 24
categories. New flags (`-scan-all-fingerprints`, `-exclude-compromised`,
`-version`) documented. ML-adjacency rule and cross-cutting credential
scanner described in the pipeline section. Default port list updated to the
canonical 42-port set including 9200 (Elasticsearch).

**PKGBUILD bump.** `pkgver=1.9.18`. Description updated from "36 AI/ML
service types" to "120 fingerprints + 50 deep enumerators across LLM
runtimes, vector databases, model servers, agent platforms, observability
stacks, AI safety/guardrails, medical AI, and voice/audio AI." `sha256sums`
set to `SKIP` pending tarball generation; will be updated after the tag is
pushed.

**In-repo `CLAUDE.md` refresh.** Service count corrected from
"70 fingerprints + 37 enumerators" to "120 fingerprints + 50 enumerators."
Layout block now references `adjacency.go` (the Insight #20 rule) and the
`scanCredentials` / `scanSecrets` pair in `enumerators.go`.

**Default port list documentation drift.** README listed 41 ports without
9200; the binary's `main.go` has shipped 42 ports including 9200 since
v1.9.x. Documentation aligned to code.

### Source

The doc gap was the most-referenced item in the v1.9.17 internal review.
Operators reading the JSON `ToolVersion` field could not trust it; the
README undersold the tool's actual coverage by 54 services; the man page
was a release behind every release since v1.3.0. The fix is mechanical but
load-bearing: the public surface now matches the code, and the version
string is consolidated so future releases need to update exactly one line.

No behavior changes. No new fingerprints. No new enumerators. All existing
tests pass.

## [v1.9.17] - 2026-05-19

### Added: Exposed API Credentials fingerprint + scanCredentials (Insight #38)

New cross-cutting fingerprint `"Exposed API Credentials"` detects vendor API
keys in HTTP response bodies independent of what service is running. A Langfuse
key baked into a Dokploy build log, a Stripe secret in a React SPA bundle, a
Helicone key in an env-var dump page — all produce findings without the host
needing to match any other service fingerprint.

**Fingerprint:** 11 probes across `/`, `/env`, `/debug/vars` covering Langfuse
(`sk-lf-`), Helicone (`sk-helicone-`), Stripe live/test (`sk_live_`, `sk_test_`),
Anthropic (`sk-ant-api03-`), LangSmith (`lsv2_pt_`, `lsv2_sk_`), OpenRouter
(`sk-or-v1-`), Slack user token (`xoxp-`), and Langfuse env-var paths.

**`scanCredentials` function (alongside existing `scanSecrets`):** regex-based
extraction with format validation where a vendor key has a documented format
(UUID for Langfuse `sk-lf-`). Emits redacted key fragments (first 16 chars +
"..."). Severity is downgraded one step when format validation fails (likely
substring FP). Covers 15 credential classes across 10 vendors.

**Enumerator `enumExposedCredentials`:** probes the match path plus `/env`,
`/debug/vars`, `/api/settings`, `/.env`, `/config` to maximize surface coverage.
Deduplicates across paths.

Source: AI cost/billing/analytics survey 2026-05-19; methodology Insight #38
(hard-proof verification chain for exfiltrated-credential class findings).
Companion tooling: `~/AI-LLM-Infrastructure-OSINT/tools/exfil_cred_verify.py`.

13 new tests; all passing.

## [v1.9.16] - 2026-05-19

### Fixed: `dicom/` and `pacs/` substring FPs on `adicom/admin-mongo`

Population-pass third burn-in. `198.57.27.72:5000` (final pass3 of the
registry-population survey 2026-05-19) had `adicom/admin-mongo` in its
catalog. The healthcare classifier's `dicom/` signal matched the substring
`dicom/` inside `adicom/`. Classifier fired healthcare:high spuriously.

Same Insight #6 class as v1.9.14 (`tegra`/`mcintegration`) and v1.9.15
(`ray`/`krayzdrav`). The lesson: any classifier signal that ends in `/`
without a preceding-boundary character is vulnerable to the same FP.

**Fix.** Replaced `dicom/` and `pacs/` and their international cousins
(`klinik/`, `salud/`, `clinica/`, `sante/`, `clinique/`) with the
preceding-slash variant `/X/`, plus the `X-` and `X_` suffix variants.

Before:
  "/dicom", "dicom/", "dicomweb"

After:
  "/dicom", "dicom-", "/dicom/", "dicom_", "dicomweb"

Same pattern applied to `pacs`, `klinik`, `salud`, `clinica`, `sante`.

**Tests.** Added `TestHealthcareClassify_AdicomNoFP` (the literal FP),
`TestHealthcareClassify_RealDicomVariants_High` (5 anchored variants
still fire), `TestHealthcareClassify_VirtualKlinikStillFires_High`
(the legitimate Indonesian telehealth case `telekonsul/virtual-klinik-bakti`
from the same survey continues to fire).

**Live re-verify.** `198.57.27.72:5000` post-rebuild: healthcare=`-`
(correctly silent). `51.158.144.194:5000` (the legit telehealth case)
continues to fire healthcare=high.

### Pattern: the load-bearing rule across v1.9.14, v1.9.15, v1.9.16

Every population-pass version since v1.9.13 has caught one or more
single-token-substring FPs that the validation cohort missed. The class
of bug:

- **Bare 4-6 char tokens** in signal lists are vulnerable to substring
  collision on common English / international words.
- **Tokens ending in `/`** without a preceding-slash boundary collide
  with any word that ends with the same letters followed by `/`.
- The validation cohort (9 known hosts) doesn't surface these because
  the curated hosts are class-stereotypical.

The discipline that catches them: **every classifier signal added must
contain a path/word boundary (`/`, `-`, `_`) on BOTH sides of any token
under 8 characters**, OR be a long enough literal (8+ chars, e.g.
`dcm4chee`, `dicomweb`, `krayzdrav`) that substring collision is
implausible.

This is Insight #6 applied at the catalog-classifier layer.

## [v1.9.15] - 2026-05-19

### Fixed: `ray` substring FP'd on `krayzdrav` (Insight #6 extended again)

aiRegistryImages contained bare `ray` — matched as substring inside
`krayzdrav` (Russian/Ukrainian for "regional health"). This is the same
class of FP that v1.9.14 fixed for `tegra`. Replaced bare `ray` with
anchored variants: `/ray/`, `ray-`, `/ray-`, `rayproject/`, `anyscale/ray`.

Regression: `TestAIRegistryImages_NoBareRay` (catches any future
single-token additions) + `TestAIRegistryImages_AnchoredRayStillMatches`
(confirms `rayproject/ray`, `anyscale/ray`, `my/ray-cluster` still match).

### Added: International healthcare-system signals

The v1.9.13 healthcare signal set was western-DICOM-PACS-centric
(`dcm4chee`, `orthanc`, `ohif`, `weasis`, `/pacs`, `/dicom`). Registry
population survey 2026-05-19 found a Russian regional-healthcare operator
(`88.99.214.110:5000`, repos `external/krayzdrav/fss-*`) that v1.9.13
missed entirely.

v1.9.15 adds language-specific healthcare-system terms:

- **Russian / Ukrainian** (zdrav = health): `zdrav-`, `/zdrav`, `zdrav/`,
  `krayzdrav` (regional health), `minzdrav` (ministry of health).
- **German**: `/klinik`, `klinik-`, `klinik/` (clinic), `krankenhaus`
  (hospital), `/praxis`, `praxis-` (practice).
- **Spanish**: `/salud`, `salud-`, `salud/` (health), `/clinica`,
  `clinica-`, `clinica/` (clinic).
- **French**: `/sante`, `sante-`, `sante/` (health), `/clinique`,
  `clinique-` (clinic).
- **Italian**: `/sanita`, `sanita-` (health), `/ospedale`, `ospedale-`
  (hospital).
- **Mandarin** transliteration: `yiyuan` 医院 (hospital).
- **Japanese** transliteration: `byouin` 病院 (hospital).
- **Generic medical-system fragments** (path-anchored): `/medical-`,
  `medical/`, `/hospital-`, `hospital/`.

All multi-letter tokens that could plausibly collide with unrelated
English words are path/word-anchored per Insight #6 discipline.

Regression: `TestHealthcareClassify_RussianKrayzdrav_High` (the literal
case that surfaced this), `TestHealthcareClassify_InternationalTerms_High`
(6-language coverage check), `TestHealthcareClassify_NoCommonWordFP`
(commodity-stack negative check).

Live re-verify on `88.99.214.110:5000`: healthcare=`high`, 15 healthcare
repos surfaced.

### Source

Registry-population survey 2026-05-19. The validation cohort of 9 known
unauth registries gave 33% Jetson attribution; the Shodan-broad population
sample of 2,878 hosts gave 0.035% Jetson attribution. The very low yield
amplifies the cost of missed signals — every internationalization gap is
proportionally more impactful at population scale. Documented as
[Insight #35](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/methodology/insight-35-side-channel-attribution-high-precision-low-recall.md).

## [v1.9.14] - 2026-05-19

### Fixed: Jetson classifier `tegra` substring FP'd on `mcintegration`

Population-pass burn-in: 160.85.252.184:5000 has the single repo
`d-gree-mcintegration` in its `/v2/_catalog`. The Jetson high-signal list
included bare `tegra`; `mcintegration` contains the substring `tegra`
(inside `integration`); the classifier fired a high-confidence Jetson
attribution where none exists.

This is the load-bearing reason Insight #6 (conjunctive marker-anchored
matchers) is mandatory. The Insight already applied to body-text matchers;
v1.9.14 extends the discipline into the registry-catalog matcher.

**Fix.** Replaced bare `tegra` with path/word-anchored variants:
`/tegra`, `tegra/`, `tegra-`, `-tegra`, `tegra_`, `_tegra`. Single-token
`tegra` is no longer a high-confidence signal.

**Tests.** Added regression `TestJetsonClassify_McIntegration_NoFP` covering
the literal FP case, and `TestJetsonClassify_RealTegraVariants_High`
confirming the anchored variants still fire on legitimate paths
(`nvidia/l4t-tegra-cuda`, `vendor/tegra-base`, `my/tegra/builds`,
`build/tegra_pytorch`, `my_tegra_image`).

**Live re-verify.** 160.85.252.184:5000 after rebuild: jetson=`-`,
healthcare=`-`, finance=`-` (correctly silent).

**Source.** Registry-population survey 2026-05-19, first pass burned the FP
on host #160 of 1,905. Caught before the 10,388-host second pass.

## [v1.9.13] - 2026-05-18

### Added: Healthcare imaging (PACS / DICOM) and Finance / algotrading operator attribution

Extends the side-channel attribution pattern shipped in v1.9.12 to two
additional operator classes. The shared classifier engine (`classifyRepos`)
is now factored out; each operator class supplies its own high / medium /
arch signal lists. Multiple classifiers can fire on the same registry when
an operator runs a mixed stack.

**Healthcare imaging signals (high-confidence single match):**

- `dcm4chee` (the dcm4chee-arc DICOM archive reference platform)
- `orthancteam/orthanc`, `osimis/orthanc`, `/orthanc` (the other dominant PACS)
- `ohif/` (OHIF Viewer DICOM web client)
- `weasis` (DICOM web client)
- `/pacs`, `pacs-`, `pacs/`, `/dicom`, `dicom/`, `dicomweb`, `/wadors`, `/qido`

**Finance / algotrading signals (high-confidence single match):**

- `freqtrade` (dominant open-source crypto trading bot)
- `quantlib` (dominant quant finance library)
- `vector-bt`, `vectorbt` (vectorized backtesting library)
- `alpaca/`, `alpaca-` (Alpaca broker API)
- `ibapi`, `ib-gateway`, `/ibkr` (Interactive Brokers gateway / API)
- `oanda` (OANDA fx broker)
- `/mt4`, `/mt5`, `metatrader`
- `nautilus_trader`, `nautilus-trader`

Medium-confidence finance signals (need adjacent signal to promote):
`backtrader`, `zipline`, `lean-engine`, `binance-`, `kraken-`, `coinbase-`.

**Refactor: shared classifier engine.** `classifyRepos(repos, high, medium,
arch []string) (matched []string, confidence string)` is the new shared
implementation. `classifyJetsonRepos` / `classifyHealthcareRepos` /
`classifyFinanceRepos` are one-line wrappers over it. The tiering rule is
the same across all classes:
- any high-confidence match -> high
- medium match + any arch hint -> promoted to high
- medium match alone -> medium
- arch hint alone -> low (only when the class has arch signals)

**Cross-class isolation** is exercised in tests: a mixed-stack registry
(e.g., dcm4chee + freqtrade + dustynv in one catalog) produces independent
high-confidence findings on all three classifiers without false cross-fire.

**Tests:** 14 new fixture cases in `enumerators_healthcare_finance_test.go`
(6 healthcare, 6 finance, 1 cross-class isolation, plus negative
regressions confirming each classifier rejects the other classes' canonical
signals).

**Live regression check:** F4 (43.133.1.147:5000) re-verified after the
refactor. Jetson high-confidence attribution still fires via `dustynv/ollama`;
healthcare and finance correctly silent.

## [v1.9.12] - 2026-05-18

### Added: Jetson / NVIDIA edge operator attribution via Docker registry catalog

Jetson-tensorrt edge survey 2026-05-18 surfaced 5 unauthenticated Docker
registries whose `/v2/_catalog` content fingerprinted the operator as a
Jetson builder or deployer, even when the registry itself was not on
Jetson hardware. Direct Jetson dorks (body / title `Jetson`, `Tegra`,
`L4T`) returned mostly false positives (companies named Jetson, Minecraft
Bedrock MOTDs, ERP products). The registry-catalog side channel proved to
be the reliable attribution vector.

The `Docker Registry` deep enumerator now runs a Jetson-attribution pass
over the repository list and surfaces an `operator-attribution` finding
when a Jetson signal matches.

**Confidence tiers:**

- **High** (single match suffices): `dustynv/` (Jetson AI Lab containers,
  github.com/dusty-nv/jetson-containers), `l4t-*` / `*l4t-base` (NVIDIA
  Linux for Tegra), `jetson` substring, `tegra`, `jetpack`.
- **Medium** (Jetson when paired with an arch hint): `isaac-lab`,
  `isaac_ros`, `isaac-sim` (NVIDIA Isaac stack runs on x86 too; arch hint
  disambiguates).
- **Low** (architecture hint only): `aarch64`, `_arm`, `-arm-`, `/arm/`.

A medium signal plus an arch hint is promoted to high (the F5 Auriga
robotics case: `isaac-lab-*` plus `auriga/ros2_dev-aarch64-cpp`).

**Anchoring rule.** Generic `nvidia/*` images (`nvidia/cuda`,
`nvidia/driver`, `nvidia/deepstream`, `nvidia/gpu-operator`,
`nvidia/k8s/*`) are NOT Jetson signals on their own. The F3 (Volcano
Engine GPU Operator x86 K8s mirror) and F2 (HostPapa Harbor mirror with
`nvidia/deepstream`) cases verify the negative path: NVIDIA server-stack
operators do not get tagged as Jetson.

**Fixture-driven tests** (`enumerators_jetson_test.go`, 9 cases) cover
the 5 survey-real registries (F1 mfgbot Hetzner FI, F2 Harbor HostPapa
US, F3 GPU Operator Volcano Engine CN, F4 RAG-LLM APNIC JP, F5 Auriga
Aliyun CN) plus edge cases (isaac-sim alone, aarch64 alone, empty
catalog, commodity-AI without Jetson).

Live-verified against 43.133.1.147:5000 (F4) on release: `dustynv/ollama`
detection produces the expected `operator-attribution` finding at high
severity.

## [v1.9.11] - 2026-05-17

### Added: One API + NewAPI fingerprints (Survey #21)

LLM-gateway survey identified two heavily-populated open-source proxy
products that aimap did not previously fingerprint:

- **One API** (songquanpeng/one-api) — 202 unique instances. Discriminator:
  GET /api/status returns deployment config without authentication,
  including version, auth-provider flags, and email-verification state.
- **NewAPI** (Calcium-Ion/new-api) — 22 unique instances. Fork of One API
  with NewAPI-specific fields (HeaderNavModules, api_info array). Same
  /api/status discriminator pattern.

Severity: critical. These gateways hold the operator's upstream API
keys (OpenAI, Anthropic, DeepSeek), the user-account list with
quotas, and the full prompt-and-response log. Default admin
credentials in the upstream repository are `root` / `123456`.

## [v1.9.10] - 2026-05-17

### Added: actor attribution from the extortion marker doc

v1.9.9 detected the `read_me` marker but did not characterize the attacker.
v1.9.10 reads one document from the marker index (the attacker's planted
ransom note, not operator data) and parses it for actor identifiers.

**What gets extracted:**

- Bitcoin wallet address (`bc1q...` SegWit / `1...`/`3...` P2PKH-P2SH)
- Monero wallet address (95-char base58)
- Contact email addresses (deduplicated, order-preserved)
- Paste URL (tli.sh, paste.sh, pastebin.com, privatebin)
- Onion v3 / v2 service URL

**Actor classification:**

Three actors share the `read_me` marker schema but use distinct contact
channels (from the 2026-05-17 150-host campaign-scope analysis):

- **Actor A** (Meow / wendy.etabw): wallet `bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r`, email `wendy.etabw@gmx.com`, paste `tli.sh/73x1k`
- **Actor B** (sharebot): email `db-recovery@sharebot.net`
- **Actor C** (onionmail): email `scandal@onionmail.org`

The classifier matches on whichever identifier hits first.

**Where it lands in the output:**

- `raw_data.extortion_attribution` — full attribution map (`actor_class`, `btc_wallet`, `xmr_wallet`, `contact_emails[]`, `paste_url`, `onion_url`)
- `findings[].data` (category `compromised_by_extortion`) — same fields surfaced on the finding object for downstream pipeline consumption
- `findings[].detail` text — appended `Attributed actor: <class>` line

**Restraint:** single `GET /<marker>/_search?size=1` request, 64 KB response cap. The marker is the attacker's planted content; reading it characterizes the attacker, not the victim, and is consistent with the restraint ethic.

**Smoke test (tahakum.ai, 92.222.197.175 — fully wiped, Meow Actor A):**

```
pipeline_tag:        compromised-wiped
extortion_marker:    read_me
extortion_attribution:
  actor_class:       Meow-Actor-A (wendy.etabw / tli.sh)
  btc_wallet:        bc1q38rjul6gdamfflf6p4ukz0ymtvfgfv2j9saf6r
  contact_emails:    [wendy.etabw@gmx.com]
  paste_url:         tli.sh/73x1k
```

The attribution feeds downstream disclosure batching: per-actor language
("the wendy.etabw / Meow-A operator wipes after marker" vs "scandal@onionmail's
B-line clone schema"), per-wallet aggregate reporting to ransomwhe.re /
ID-Ransomware, and population-scale comparative campaign tracking.

### Fixed: wipe-state heuristic looks at doc counts, not cardinality

v1.9.9 declared `compromised-wiped` whenever the index count was ≤2. That
misclassified hosts where the operator's data sits in a single large index
alongside the marker — the Russian AI cloud at 81.94.155.178 carried only
`read_me` + `russian_news`, yet `russian_news` had 286,385 alive docs (6.6
GB). v1.9.10 collects `docs.count` per non-system index from `_cat/indices`
and declares wiped only when the sum of non-marker alive docs is zero.

`raw_data.non_marker_alive_docs` is now reported on every host with the
marker so the classification is auditable.

## [v1.9.9] - 2026-05-17

### Added: extortion classifier in `enumElasticsearch` + `--exclude-compromised` CLI flag

Yesterday's 2026-05-16 ES survey + today's 24-hour re-probe surfaced a
methodology gap: aimap classified `read_me`-only hosts as "auth_status=none,
index_count=1" rather than recognizing them as already-compromised by an
automated extortion campaign. That misclassification fed forward into the
disclosure pipeline as "your host is exposed" framing for hosts that were
already wiped. Insight #28's retraction + Insight #29 codify the meta-lesson;
this commit closes the loop in code so it doesn't recur.

**What got added to `enumElasticsearch`:**

After the `/_cat/indices` pass, walk the index name list for known
extortion-marker names (`read_me`, `read_me_first`, `recover_data`,
`readme`, `how_to_recover`). When a marker is found, classify the host into
one of two states:

- `compromised-wiped` — marker present + `index_count ≤ 2`: operator's
  data is gone (Meow's typical end state after its delete-all + plant-marker
  workflow completes).
- `compromised-marked` — marker present + other indices still alive: the
  attacker has established control but hasn't (or hasn't yet) wiped. These
  are the saveable cases — disclosure-urgent, data still recoverable if the
  operator hardens fast.

Both states get a `critical`-severity finding with category
`compromised_by_extortion`, a `pipeline_tag` written to `raw_data`, and
references to the Insight #28 retraction + the 2026-05-17 attribution
evidence pack.

**CLI:** `--exclude-compromised` drops both `compromised-*` states from
the final JSON report. Use this when feeding aimap output into a disclosure
pipeline that frames "your host is exposed" — those hosts need different
copy. Without the flag, all hosts including compromised ones are reported
(useful for the discovery/measurement side).

**Smoke test (Tahakum AI host, 92.222.197.175 — known fully-wiped):**

```
pipeline_tag:     compromised-wiped
extortion_marker: read_me
findings:
  [high]     unauth_data
  [critical] compromised_by_extortion
  [high]     rag_vector_store
```

With `--exclude-compromised`: report contains zero enum_results, matching
the intended downstream-disclosure-filter behavior.

### Why this matters

The 2026-05-17 disclosure batch caught the bad framing manually before
sending — but only because of the yesterday-vs-today re-probe. Future
surveys won't have that retroactive correction step; the classifier needs
to live in aimap, not in a survey-end checklist. 92.4% of yesterday's
surveyed-unauth ES hosts matched at least one of the two compromised
states; without this filter the disclosure pipeline would (silently)
produce ~4,400 wrongly-framed letters per survey at population scale.

## [v1.9.8] - 2026-05-17

### Added: Elasticsearch / OpenSearch fingerprint + deep enumerator

Closes the SESSION.md-flagged gap from the 2026-05-16 cross-platform
ten-survey day: the 5,037 unauth Elasticsearch hosts and 1,832 unauth
ClickHouse hosts confirmed yesterday were probed via bespoke
`fast_enum_es.py` / `fast_enum_clickhouse.py` scripts. The
manual-→-productize-→-re-run loop (per the methodology) is closed here.

**Elasticsearch fingerprint** (Tier-A* — `xpack.security.enabled=false` is
the default in the official Docker image):

- `GET /` conjunctive on (status 200, version object, cluster_name,
  cluster_uuid, body contains "lucene_version"). The 4-conjunct anchor
  also matches OpenSearch (Amazon ES fork) since the API surface is
  identical for our purposes — both report version objects + cluster
  identifiers, both expose `_cat/indices` + per-index `_mapping`.
- New port 9200 added to the default port scan set.

**`enumElasticsearch`** — pulls cluster identity, cluster health, index
list, and (capped at 30 per host) per-index `_mapping` to detect the
canonical AI-stack signal: `dense_vector` (ES) / `knn_vector` (OpenSearch)
/ `sparse_vector` field types. Walks one level of nested-object mappings
to catch the Spring AI / LangChain Java chunks pattern:
`chunks_<N>: {nested, properties: {vector_embedding_<N>: knn_vector}}`.
Captures both ES `dims` and OpenSearch `dimension` schema spellings.

Restraint enforced in code — GET-only, field-type metadata only. No
`_search`, no `_bulk`, no `_delete_by_query`. Validated on 84.247.189.64
(operator's DMS — `dms_documentvectors` indexed with knn_vector dim 768).

Ancient-version flag for ES 1.x / 2.x (multiple public unauth RCEs:
CVE-2014-3120, CVE-2015-1427, CVE-2015-5531).

**`enumClickHouse`** — extends the existing CH fingerprint (which only
detected presence via X-ClickHouse-* headers) with the SHOW DATABASES +
SHOW TABLES pass via the HTTP GET query interface (`/?query=...`). Caps
at 60 databases / 200 tables per host. AI-stack marker detection on DB +
table names (langfuse, signoz, vllm, ollama, prompt_*, chat_*,
embedding, vector, etc.).

Restraint — SHOW commands + `system.*` queries are pure metadata. No
SELECT * on user tables, no INSERT, no system.processes (query-text
leakage), no system.users (creds). Validated on 101.42.232.108:8123
(quantitative trading operator — DB `stock` with `backtest_*` tables).

### Why this matters

47 → 49 deep enumerators; ES / OpenSearch was the largest unauth-platform
class still relying on a bespoke probe. The two new enumerators feed
straight into the standard aimap pipeline and `visorlog ingest`,
eliminating the maintenance burden of survey-specific scripts.

## [v1.9.7] - 2026-05-16

### Fixed: ComfyUI-Manager presence detection (status≠404 not status==200)

The 2026-05-16 image-gen survey caught a fingerprint bug — `enumComfyUI`
checked `/customnode/getlist` for `status == 200 + body markers`, but real
Manager-loaded ComfyUI hosts frequently return 500/502/503 (Manager
endpoint exists but the catalog-fetch errored — no outbound internet,
slow connection, etc.). Field instance: `104.236.42.246:8188` had
`--enable-manager` in argv but the survey reported `has_manager=false`.

Fix: probe now treats `status != 404 && status != 0` (network error) as
Manager-present, with refined detail messaging:
- `200 + body markers` → "Confirmed: Manager catalog returned"
- `500/502/503` → "Manager loaded but catalog fetch errored"
- Other non-404 → "Endpoint present but unusual status"

`status == 404` remains the only "Manager not installed" signal.

### Added: agent-memory + data-labeling + vector-DB-stragglers fingerprint expansion (11 platforms)

Companion fingerprints for the 2026-05-16 4-survey batch — productizing
the manual probe knowledge from each survey.

**Agent-memory tier** (severity: medium — Tier-C confirmed at population scale):

- **Mem0** — `/openapi.json` returning mem0 paths
- **Argilla** — `/api/_info` returning version JSON
- **Zep** — `/api/v2/health` with zep marker (field-validation pending)
- **Letta** — `/v1/health` or `/openapi.json` with letta marker (field-validation pending)

**Data-labeling tier**:

- **Label Studio** — dual-path probe: `/api/version` (v1.x) OR `/version` (v0.7.x legacy)
- **CVAT** — `/api/server/about` with cvat marker
- **Doccano** — root HTML title check
- **Prodigy** — root HTML title (Tier-A* — auth-free by design)

**Vector-DB stragglers**:

- **Apache Solr** (severity: critical) — `/solr/admin/info/system` with `solr-spec-version` marker. 516 hosts on Solr 7.6.0 in the field survey vulnerable to CVE-2019-17558 Velocity RCE.
- **Meilisearch** — `/health` with `"status":"available"` JSON shape
- **Typesense** — `/health` with `"ok":true` JSON shape (Tier-C confirmed: 0/9837 unauth)
- **Vespa** — `/state/v1` with `config-server` marker

All field-validated 2026-05-16 in the corresponding 4 surveys. Tests
unchanged — existing fingerprint conjuncts validated against fixtures.

## [v1.9.6] - 2026-05-16

### Added: image-generation fingerprint pack (5 platforms)

Closes the image-generation gap (category 08) — previously no aimap coverage.
Field-validated 2026-05-16 across a 50,058-host ComfyUI corpus
(`product:"ComfyUI"` Shodan harvest). All five platforms ship with the
"no auth concept in framework default" posture — Tier-A in the auth-on-default
thesis.

**Fingerprints** (`fingerprints.go`):

- **ComfyUI** (`Severity: critical`) — `/system_stats` returns JSON with
  `system.comfyui_version` + `system.python_version` markers. Strict JSON-shape
  verification distinguishes real ComfyUI from the dominant FP class: SPA
  shells / reverse-proxy frontends that serve identical HTML for any path,
  unrelated services with `<title>ComfyUI</title>` (Synology ISX1104, Fireware
  XTM, Qlik Sense, PRTG, NVR301 all observed in the FP set). ~50% Shodan-tagged
  hosts are FPs — sharpens [[insight-15-dork-hits-vs-platform-instances]].
- **AUTOMATIC1111 / SD WebUI** (`Severity: high`) — `/sdapi/v1/options` with
  `sd_model_checkpoint` marker. Gradio-on-7860, brand string lives in JS bundle
  (Shodan-dark per [[insight-21-port-first-discovery-for-low-footprint-platforms]]).
- **InvokeAI** (`Severity: high`) — `/api/v1/app/version` JSON.
- **Fooocus** (`Severity: high`) — `/config` Gradio endpoint with `Fooocus` marker.
- **SwarmUI** (`Severity: high`) — root HTML with `SwarmUI` marker.

**Deep enumerators** (`enumerators.go`):

- `enumComfyUI` — reads `/system_stats` (version + GPU + operator argv),
  `/queue` (running + pending count), `/history` (run count), `/customnode/getlist`
  (ComfyUI-Manager presence — **unauth custom-node install = RCE by design**,
  the design intent is that auth gates this).
- `enumA1111` — reads `/sdapi/v1/options` (loaded checkpoint + lora_dir paths),
  `/sdapi/v1/sd-models` (model count). Operator-attribution-rich (model paths
  leak operator filesystem layout).
- `enumInvokeAI` — reads `/api/v1/app/version` (version disclosure).

**Restraint coded in:** no POST to `/prompt`, `/sdapi/v1/txt2img`,
`/sdapi/v1/img2img`, `/api/v1/queue/default/enqueue_batch`, or
`/customnode/install`. Read-only metadata enumeration only — per the
[METHODOLOGY restraint ethic](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/tree/main/methodology).

**Field validation:** `103.192.253.238:8575` (NVIDIA L40S, 1.08 TB RAM,
ComfyUI 0.3.60, Python 3.11.11, PyTorch 2.6.0+cu126, argv exposed). Plus
~127 confirmed unauth ComfyUI hosts in the first 7% of the survey
(extrapolating to ~1,700 across the 50K corpus).

## [v1.9.5] - 2026-05-15

### Added: container / k8s / MCP / medical-AI fingerprint expansion (13 new platforms)

**Container & orchestration tier** (extends category 12 coverage):

- **Docker daemon** — `/version` returning Docker version JSON, unauth port 2375 by framework spec
- **Kubernetes API** — `/api` + `/version` returning K8s API surface
- **etcd** — `/version` JSON + `/v2/keys` or `/v3/kv` reachable
- **Vault** — `/v1/sys/seal-status` + `/v1/sys/health` (sealed-state visibility regardless of auth)
- **Consul** — `/v1/agent/self` + `/v1/status/leader`
- **Portainer** — `/api/system/status` + UI title fingerprint
- **Kubelet** — `/healthz` on 10250 + `/pods` if anonymous-auth enabled

**MCP (Model Context Protocol) tier** (extends category 10):

- **MCP Server** (generic, 4 alternative probes) — covers FastMCP / Streamable-HTTP / `mcp-server` Server-header variants; empirical population coverage 26/88 (30%) on FastMCP 406-jsonrpc, ~18/88 (20%) on JSON-RPC -32600, ~6/88 (7%) on 405-method-not-allowed-with-POST, ~5/88 (6%) on Server-header. Built against the 2026-05-15 88-host MCP refresh corpus.

**Medical-AI tier** (extends category 28, ties to the medical-edge-ai survey):

- **MONAI Label Server** — `/info/` with `trainers` + `strategies` + `scoring` + `datastore` fields
- **Orthanc DICOM Server** — REST surface
- **dcm4che / dcm4chee-arc DICOM Archive** — `/dcm4chee-arc/aets` array
- **DICOMweb (QIDO-RS)** — `/studies` array + DICOM tag `0020000D`
- **NVIDIA NIM** — `/v1/metadata` with `modelInfo` array

### Added: `header_not_contains` match-condition type

Header-level anti-match for fingerprints. Probe FAILS if the specified header value contains the substring; PASSES if the header is absent OR doesn't contain it. Used to exclude services that self-identify via Server / X-Powered-By headers but otherwise share JSON shape with the target fingerprint.

### Tests

`fingerprints_container_test.go` (706 lines) + `fingerprints_mcp_test.go` (350 lines) — fixture-based coverage for the new fingerprint conjuncts. `go test ./...` clean.

## [v1.9.4] - 2026-05-15

### Added: `llama.cpp server` fingerprint + deep enumerator

aimap previously missed `llama.cpp`-served HTTP endpoints, including the
common deployment pattern where `llama-server` is colocated on port 11434
(Ollama's default). Field instance: `194.233.71.223:11434` on 2026-05-15
served Microsoft BitNet-b1.58-2B-4T unauth via llama.cpp and aimap PHASE-2
reported "No AI/ML services identified" despite the explicit `Server:
llama.cpp` HTTP header.

New fingerprint with three alternative probes (any one matches):

- `/v1/models` returning a body containing `"owned_by":"llamacpp"`
  (OpenAI-compatible models endpoint, the most reliable conjunct)
- `/props` returning JSON with `default_generation_settings` +
  `chat_template` (server-info endpoint, exposes operator's persona config)
- `/` with `Server: llama.cpp` header (banner fallback for stripped APIs)

New `enumLlamaCpp` deep enumerator surfaces:

- Loaded model IDs via `/v1/models`
- Server config (`n_ctx`, `total_slots`, `chat_template` excerpt) via `/props`
- `/completion` open-endpoint flag (POST is invocation; GET reachability
  confirms the unauth inference surface)
- Severity: critical when unauth (matching `enumOllama`'s posture)

### Fixed: PHASE 3 deep-enum is now parallel

The `runEnumerators` dispatcher iterated `services` **sequentially** even
when `-threads N` was specified. On a 10,000-host Ollama corpus this meant
~50 minutes of single-threaded HTTP probing while PHASE 1 (port discovery)
and PHASE 2 (fingerprinting) ran with 100 concurrent goroutines as
configured. The `-threads` flag now applies to PHASE 3 too via a worker-pool
semaphore — measured: 100 hosts at threads=50 finishes in ~19s where the
prior implementation took ~145s (and a 10K-host run that would have taken
hours completes in minutes).

The per-host enumerator logic is unchanged; only the dispatcher's scheduling
discipline. Output ordering preserved via pre-sized `results` slice indexed
by service index.

## [v1.9.3] - 2026-05-14

### Code-assistant fingerprints (category 09)

Eight new fingerprints for self-hosted code assistants, all source-verified
against live confirmed hosts during the 2026-05-14 code-assistant survey
(see `AI-LLM-Infrastructure-OSINT/shodan/queries/09-code-assistants.md`):

- **OpenHands** — `/api/options/config` (`APP_MODE` + `POSTHOG_CLIENT_KEY`)
  and `/api/options/models` (JSON array). Activates the pre-existing
  `enumOpenHands` enumerator, which was previously dead code (registered in
  the switch but unreachable with no OpenHands fingerprint to match first).
- **Sourcegraph** — `/.api/graphql` ("Private mode requires authentication")
  + `/sign-in` title.
- **Sourcebot** — `/api/repos` auth envelope (`errorCode` + `NOT_AUTHENTICATED`).
- **Sweep AI** — `/health` (Sweep-specific `autocomplete` field).
- **Tabnine Context Engine** — `/api/version` (Tabnine-specific `X-API-Key
  header` auth message).
- **Dyad** — `dyad-generated-app` title string.
- **bolt.diy** — `bolt.diy` body string, 200-anchored.
- **Refact** — `Refact Server Login` full title string (the bare token
  "Refact" is a false-positive trap — matches "refactor" in JS bundles).

Test count: 53 -> 65. Includes a false-positive guard test covering the
known FP traps from the survey (Tabby Terminal, "refactor" substring,
generic 401/health bodies).

## [v1.9.0] through [v1.9.2] - 2026-05-14

Agent-platform and browser-automation tier coverage. Fingerprint count:
74 -> 76. Test count: 47 -> 53.

### AutoGen Studio fingerprint + enumerator (v1.9.0)

New fingerprint for Microsoft's AutoGen Studio agent IDE. Source-verified
against `microsoft/autogen`: the FastAPI app carries unique messages at
`/api/version` ("Version retrieved successfully") and `/api/health`
("Service is healthy"). Dedicated enumerator probes `/api/teams`,
`/api/settings`, `/api/sessions` with `?user_id=guest@guest.com` — the
optional AuthMiddleware is off by default, so a 200 with a data array is
fully unauthenticated. Surfaced 9 confirmed unauth instances in the
agent-platform-tier survey.

### Flowise honeypot over-match fix (v1.9.1)

The Flowise fingerprint's single-word `body_contains: flowise` matched a
13-host AWS honeypot fleet serving Flowise SPA bait. Tightened to a
conjunctive `<title>flowise - build ai agents` match; moved the API probe
off the deprecated `/api/v1/flows` to `/api/v1/chatflows`.

### Anti-detect CDP server fingerprint + enumerator (v1.9.2)

New fingerprint for the aiohttp-fronted anti-detect Chrome DevTools
Protocol server, field-discovered in the browser-automation backend
survey (`159.195.70.69`, `23.19.231.93`). A Python aiohttp server fronts
CDP on :9222 and exposes a control-plane root —
`{"status","active","processes":{...,"seed","proxy","timezone","locale"}}`
— whose per-process anti-fingerprint seeds identify the platform class.
Both probes require the `Server: aiohttp` header, which keeps the
fingerprint off (a) the CDP honeypot fleet that fakes `/json/version`
with a bare-Chrome header, and (b) raw Chrome CDP whose HTTP server is
Chrome's own. The enumerator deep-reads `/json/version`, `/json`, and the
control-plane root — read-only, never opening the WebSocket — and reports
browser-level control, live hijackable sessions, and the managed
browser-process pool. Live-verified on both real hosts: matched,
NONE auth, critical risk. ToolVersion bumped 1.8.2 -> 1.9.2 (the
constant had lagged two releases).

## [v1.8.1] through [v1.8.8] - 2026-05-13

Bulletproofing arc. Twelve TDD + live-verification iterations against
Shodan-sourced candidates surfaced systemic gaps the catalog had carried
unnoticed. Fingerprint count: 74 -> 74 (no new platforms; existing FPs
hardened and modernized). Test count: **0 -> 47**. MLflow corpus
coverage on the Phase 5 120-host inventory: **0% -> 91%**.

### MLflow tracker invisibility (v1.8.1)

The MLflow fingerprint probed `/api/2.0/mlflow/experiments/list`, an
endpoint upstream removed years ago. **Every modern MLflow tracker on
the public Internet was silently invisible to aimap** for an unknown
duration. Field-validated against `78.135.66.61:5000` and 109 hosts
from the Phase 5 corpus. Replaced with a conjunctive GET / probe
(`<title>mlflow</title>` + `static-files/manifest.json` reference).

### Live-verified fingerprint refits (v1.8.1 through v1.8.8)

Each FP retested against at least one Shodan-sourced live candidate:

- **MLflow** - modern GET / probe (was deprecated endpoint)
- **Helicone Self-Hosted** - added `body_not_contains` guard against
  marketing-site reflections that served helicone.ai content on port
  3000 of unrelated hosts. Eliminated 4 known false-positive shapes.
- **Open WebUI** - tightened from single brand-word match to
  conjunctive `<title>Open WebUI</title>` + `/static/loader.js`
- **SillyTavern** - replaced the stale `WWW-Authenticate: SillyTavern`
  header probe (1.12+ doesn't ship that header) with the modern
  HTML login page shape.
- **Coqui XTTS** - added a third probe for the custom HTML UI fork
  with title pattern + tts-form class anchors.
- **Whisper ASR** - `/docs` probe relaxed (the `/asr` substring only
  appears in `/openapi.json`, not the Swagger HTML).
- **RVC WebUI** - added a probe for modern Gradio builds shipping
  `og:title="RVC WebUI"` instead of the upstream
  `Retrieval-based-Voice-Conversion` string.
- **Pipecat** - tightened from single brand-word match to title +
  `assets/index-` Vite-bundle path. Added direct `/client/` probe.
- **LiveKit Agents** - added a third probe for LiveKit Meet (the
  dominant deployment, ~1000 Shodan hits, previously invisible).
- **Promptfoo** - added GET / probe for SPA-only deployments where
  `/api/health` isn't mounted.
- **Ray Serve** - added probe for the custom REST root-JSON shape
  used in production Ray Serve deployments.

### Catalog-wide DefaultPorts widening (v1.8.4 / iter 8d)

Empirical Shodan counts of off-canonical-port deployments revealed
~150k host-port combinations the catalog couldn't reach:

```
n8n        89,770 off-port hits
Airflow    43,429
Superset    9,945
LiteLLM     4,617
Langfuse    2,231
Flowise     2,147
vLLM          195
BentoML        46
```

Added `{80, 443}` (and where relevant `8080`) to the DefaultPorts of
all 8 user-facing FPs. Also widened Grafana, Mem0, LangServe under
iter 8a / 8c.

### New aimap features

| Feature | Use |
|---|---|
| `parseTargetsVerbose()` | Tolerates and warns on common typos (`host:port` from another tool's output, comma-joined target lists, bracketed IPv6). Wired into `-target` and `-list` ingress in `main.go`. |
| `startWatchdog()` | Polls scan progress; emits a stderr warning if the counter doesn't advance for 12x the connection timeout. Surfaces silent-hang pathologies in 30s-60s instead of hours. |
| `MatchCond.Type = "body_not_contains"` | Anti-match condition. Lets fingerprints reject specific marketing-reflection or brand-mention shapes that contain the right strings but in the wrong context. |
| `AdjacencyMatch` type + `buildAdjacencies()` | Implements **Methodology Insight #20**. When a host has a confirmed AI/ML service (Phase 2 fingerprint match), data-tier ports on the SAME host (Postgres 5432, Redis 6379, MinIO 9000/9001, Kafka 9092, RabbitMQ 5672/15672, MailHog 1025/8025) are emitted as ML-adjacent findings with elevated severity. Reporter renders a new "ML-ADJACENT INFRASTRUCTURE" section; JSON report carries an `adjacencies` key. Severity counts include adjacency findings. |
| `-scan-all-fingerprints` flag | Bypasses the DefaultPorts filter; every FP probes every open port. Use when services live on operator-chosen non-canonical ports. Trades ~30x more HTTP requests for coverage. Also adds a stderr warning when an open port has zero FP candidates under the default filter. |
| Intra-port FP concurrency (v1.8.7 / iter 11) | DefaultPorts widening pushed port 80 from ~5 candidate FPs to 21. The serial inner loop made per-host wall time grow from ~10s to ~80s. Moved the semaphore from the outer port-goroutine to the inner FP-goroutine. **~6x speedup**: 80s -> 13s with `-threads 16`. |
| `matchProbe()` helper | Test-friendly offline matcher evaluation against a captured `PortResult`. Enables TDD-driven fingerprint development without a network round-trip. |
| `scripts/audit-fp.sh` | Codifies the audit pattern: given a FP name, pulls Shodan candidates, runs aimap against each, reports OK / MISS / TIMEOUT. Supports `--dork` override, `--limit N`, and `--scan-all` for non-canonical-port platforms. |

### Headline numbers

- **MLflow population coverage** (Phase 5 corpus, 120 hosts):
  - Before v1.8.1: 0% (deprecated endpoint, FP never matched)
  - After v1.8.8: ~91% (80 from canonical ports + 29 from miss-recovery pass with `-scan-all-fingerprints`)
- **Wall-time on dense port** (port 80, 21 candidate FPs after widening):
  - Before v1.8.7: ~80s/host (serial)
  - After v1.8.7: ~13s/host (`-threads 16`, intra-port parallelism)
- **False positives eliminated**: 4 Helicone marketing reflections + over-match guards added for Open WebUI / Coqui XTTS / Pipecat / LiveKit / Ray Serve / Promptfoo.

### Reusable methodology

The arc surfaced and codified five reusable lessons:

1. **Catalog audit means live verification.** Unit tests pass for FPs that probe dead endpoints; the bug surfaces only on a real host.
2. **DefaultPorts narrowness is the second-most-common cause of FP false-negatives** after deprecated endpoints.
3. **Single-word `body_contains` brand matches are the load-bearing pathology** - always anchor brand mentions to project-specific asset paths.
4. **`body_not_contains` is a class of FP fix**, not a one-off - marketing reflections share a hardcoded `canonical href` pattern.
5. **Per-port parallelism without intra-port parallelism is a partial optimization** - once a port claims many FPs, the inner loop becomes the bottleneck.

### Pending tail (no live-verification possible)

| FP | Why |
|---|---|
| TensorFlow Serving | 0 Shodan hits, no findable deployment |
| Triton Inference Server | 117 Shodan hits but all unreachable from scanning location |
| Inspect AI | 5 hits, all 000 |
| NeMo Guardrails | 0 hits |
| DeepEval Server | 0 hits |
| Lakera Guard Self-Hosted | 0 hits beyond brand-mention reflections |

These FPs may be correct but cannot be verified without a synthetic
deployment or upstream-project Docker spin-up. Tracked as future work.

---

## [v1.8.0] - 2026-05-12

AI observability tier completion. Backward-compatible. Fingerprint count: 69 -> 74. Enumerator count: 36 -> 41.

This release closes Phase 3 of the 2026-05 AI observability sweep (see `~/recon/2026-05-10-llm-sweep/PHASE-PLAN.md`). Phase 1 surveyed 7 platforms at population scale; Phase 2 ran per-platform deep-dives and cross-cuts; Phase 3 productizes the per-platform fingerprints into aimap so the same posture audit runs on demand against any new target.

### Added

- **Arize Phoenix fingerprint + enumerator.** Phoenix ships with `PHOENIX_ENABLE_AUTH=False` as the documented default, driving a 25% unauth rate at population scale (94 of 377 hosts on 2026-05-10). The enumerator probes `/graphql` with a minimal `__typename` query, escalates to project enumeration on success, and probes the schema for the `Secret` type (Phoenix 15.x+, enables stored API key extraction). Version extracted from the `X-Phoenix-Server-Version` response header. Severity: `critical`.
- **Helicone Self-Hosted fingerprint + enumerator.** Auth-on-by-default via BetterAuth or Supabase; zero unauth at population. Surfaces two latent primitives for operator self-audit: (1) the literal `BETTER_AUTH_SECRET="MKUcaeqyMD7UBkGeFYY5hwxKS1aB6Vsi"` value committed to three `.env.example` files upstream (session-cookie forgery if not rotated), and (2) the bundled `minioadmin:minioadmin` MinIO defaults on the `request-response-storage` bucket. Severity: `high`.
- **Lunary fingerprint + enumerator.** Auth-on-by-default via JWT; `/api/v1/health` returns `{status:OK}` unauth, protected routes return 401. Surfaces the `JWT_SECRET=changeme` placeholder pattern for operator audit. Severity: `high`.
- **OpenLIT fingerprint + enumerator.** Auth-on-by-default via NextAuth.js middleware; every API route redirects unauth requests through `/login?callbackUrl=...`. Detection probes follow the redirect chain and confirm middleware activity via body content. Severity: `high`.
- **Pezzo fingerprint + enumerator.** Auth-on-by-default via Nest.js JWT; `/graphql` requires POST and is JWT-gated. SPA frontend at port 4200 with the title-tag signature. Severity: `high`.
- Tool version bumped to `1.8.0` in reporter.go.

### Coverage

The five new enumerators complete the AI observability tier surveyed in the 2026-05-10 sweep. Combined with the existing Langfuse + LangSmith enumerators, aimap now fingerprints and deeply enumerates **7 of 7** AI observability platforms at population scale.

Reproducing Phase 1's full Phoenix population sweep is now a single command:

```bash
aimap -list phoenix-candidates.txt -ports 6006,80,443,8000 -threads 50 -o phoenix-posture.json
```

### Methodology notes for future enumerator authors

- aimap's HTTP client follows redirects up to 3 deep. Fingerprints that depend on status_code=307 will silently fail because the matcher sees the followed response, not the redirect. When fingerprinting a NextAuth-style middleware-protected service, probe for the post-redirect body content (e.g. `callbackUrl` query param, branded login page) instead of the 307 status code.
- The `X-Phoenix-Server-Version` response header is a clean version source. Prefer response headers over SPA-bootstrap-config regex extraction when the platform exposes one.

---

## [v1.7.2] - 2026-05-09

Port-filtered fingerprint matching in Phase 2. Backward-compatible performance fix.

### Fixed

- Phase 2 was trying all 69 fingerprints against every open port, regardless of whether the fingerprint's `DefaultPorts` included that port. Now builds a `candidateFPs` slice per port: only fingerprints whose `DefaultPorts` list the port (or have no restriction). On single-service ports (11434 = Ollama, 7997 = infinity-embedding, 6333 = Qdrant) reduces from 69 probes to 1. On common ports (8080, 8000) reduces to 20-30. Combined with the v1.7.1 concurrent goroutines and 2s timeout, Phase 2 on the 818-IP embedding survey completes in under 10 min.

---

## [v1.7.1] — 2026-05-09

Phase 2 fingerprinting made concurrent. Backward-compatible performance fix.

### Fixed

- `matchFingerprints` was sequential (single loop over all open ports, all fingerprints, all probes). On large port lists (4,484 open ports from 818-IP embedding survey) this produced estimated runtime of hours. Now uses a goroutine pool gated by the `-threads` flag (same semaphore pattern as Phase 1 port discovery). Phase 2 runtime on the embedding pool: 3–5 min instead of 4+ hours. `sync` added to `fingerprints.go` imports.

---

## [v1.7.0] — 2026-05-09

Embedding Services tier (3 platforms). Backward-compatible. Fingerprint count: 66 → 69. Enumerator count: 33 → 36.

### Added

**Fingerprints** — 3 new entries:

| Service | Ports | Probe (conjunctive) | Severity | Notes |
|---------|-------|---------------------|----------|-------|
| HuggingFace TEI | 80, 8080, 3000 | `GET /info` → status 200 + `json_field:model_pipeline_tag` + `body_contains:feature-extraction` | medium | `model_pipeline_tag:"feature-extraction"` is TEI-unique — not present in any LLM inference server; disambiguates from Ollama/llama.cpp |
| infinity-embedding | 7997, 8080, 8000 | `GET /openapi.json` → status 200 + `body_contains:Infinity Emb`; alt: `GET /v1/models` → `json_field:data` + `body_contains:infinity_emb` | medium | OpenAI-compat embedding server; OpenAPI title is the discriminating signal |
| Embedding API | 8000, 8001, 8080, 8002, 8100, 5000 | `GET /` → status 200 + `json_field:embedding_dimension`; OR `json_field:embed`; OR `GET /health` → `json_field:embedding_dimension` | medium | Custom FastAPI catch-all — `embedding_dimension` / `embed` JSON keys are embedding-specific; not present in LLM or general API roots |

**Enumerators** — 3 new deep enumerators:

| Enumerator | Probes | Extracted fields |
|-----------|--------|-----------------|
| `enumTEI` | `/info`, `/metrics` | model_id, version, max_input_length, max_batch_total_tokens, max_concurrent_requests; Prometheus te_request_count / te_embed_count |
| `enumInfinity` | `/v1/models`, `/openapi.json` | model list, OpenAPI title, version |
| `enumEmbeddingAPI` | `/`, `/health`, `/openapi.json` | embed model, embedding_dimension, reranker, llm backend, index_dir, docs_dir (filesystem path leak) |

### Methodology notes

Embedding services are **Shodan-dark** — TEI, infinity, and custom FastAPI embedding servers all return API JSON at `GET /`, which Shodan's crawler treats as non-HTML and indexes minimally. Shodan `http.html:"BAAI/bge"` (41 hits), `http.html:"nomic-embed"` (22 hits) and similar model-name queries are the only Shodan-viable approach; they work because model names appear in HTML dashboards, not because Shodan indexes the API roots.

**Docker Registry FP:** `"text-embeddings-inference"` in banner (6 hits) matches Docker Registry `/v2/_catalog` responses listing the TEI image. Not live TEI servers. The TEI fingerprint probes `/info` specifically to avoid this.

**Reposify contamination:** `http.html:"all-MiniLM"` at 404 hits is dominated by `Server: Reposify` honeypots at `Content-Length: 3151`. Filter: `server:"Reposify"` exclusion.

**Threat class:** Compute theft (GPU/CPU at operator's expense) + embedding oracle (attacker pre-computes query vectors to probe downstream vector DBs without the embedding key). Severity elevated to high when paired with exposed vector DB on same host.

Companion survey catalog: [`AI-LLM-Infrastructure-OSINT/shodan/queries/27-embedding-services.md`](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/shodan/queries/27-embedding-services.md)

## [v1.6.0] — 2026-05-08

BI/Dashboard tier (3 platforms) + Voice/Audio AI tier (10 platforms). Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes. Fingerprint count: 53 → 66.

### Added

**BI / Dashboard fingerprints** (already shipped in `b9136a9` — formalized in this release):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| Metabase | 3000, 80, 443, 8080, 8443 | `GET /api/session/properties` (status 200 + `json_field:has-user-setup`) | High — CVE-2023-38646 pre-auth RCE via setup wizard if `has-user-setup:false` |
| Apache Superset | 8088, 80, 443, 8080 | `GET /api/v1/` (status 200 + `json_field:message` + `body_contains:Superset`) | High — CVE-2023-27524 predictable SECRET_KEY auth bypass; default-creds `admin/general` and `admin/admin` checks |
| Redash | 5000, 80, 443, 8080 | `GET /api/status` (status 200 + `json_field:workers` + `json_field:version`) | High — `/api/data_sources` unauth = CRITICAL when present |

**Voice / Audio AI fingerprints** — 10 new entries:

| Service | Ports | Probe (conjunctive) | Severity | Why |
|---------|-------|---------------------|---------:|-----|
| Whisper ASR | 9000, 8080, 7860, 8000 | `body_contains:openai-whisper-asr-webservice` OR `/inference + body:whisper.cpp` OR `/docs + body:Whisper + body:/asr` | medium | Compute theft + PHI/PII risk in healthcare deployments |
| Coqui XTTS | 8020, 5002, 8000 | `/api/tts/speakers + body:speaker` OR `/ + body:XTTS + body:coqui` | medium | Voice-cloning compute theft |
| Piper TTS | 5000, 8080, 10200 | `body:piper + body:tts` | low | Edge / RPi deployments |
| RVC Voice Cloning WebUI | 7865, 7860, 7897 | `body:Retrieval-based-Voice-Conversion` / `body:GPT-SoVITS` / `body:Applio` | **high** | **Fraud-relevant — celebrity voice clones, deepfake-call enablement** |
| OpenVoice | 7860, 8000 | `body:OpenVoice + body:myshell` | **high** | Multi-language voice cloning |
| ChatTTS | 7860, 8000, 9966 | `body:ChatTTS + body:2noise` | medium | Conversational TTS |
| F5-TTS | 7860, 8000 | `body:F5-TTS` OR `body:swivid/f5-tts` | medium | Flow-matching voice clone |
| Pipecat Voice Agent | 7860, 8000, 8080 | `body:pipecat` (root or /health) | **high** | **Real-time outbound-call abuse — Twilio/Daily integration** |
| Vocode Voice Agent | 8000, 3000, 7860 | `body:vocode + body:transcriber` | **high** | Same — voice-agent framework abuse |
| LiveKit Agents | 7880, 8080, 3000 | `body:livekit-agents` OR `body:livekit-server` | medium | Real-time AV pipeline |

### Severity rationale (Voice / Audio)

Voice-cloning (RVC / OpenVoice) and real-time voice-agent (Pipecat / Vocode) fingerprints get `severity:high` because the abuse class differs qualitatively from typical compute-theft. RVC servers loaded with celebrity speaker embeddings are deepfake-fraud infrastructure; Pipecat / Vocode servers integrated with Twilio can make outbound scam calls. Other voice/audio fingerprints (transcription, simple TTS) stay at `medium` / `low`.

### Methodology context

Closes the Speech & Audio AI tier in [`FUTURE-SURVEYS.md`](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/FUTURE-SURVEYS.md). Companion query catalog at `shodan/queries/17-voice-audio-ai.md` and discovery runbook at `data/voice-audio-ai-discovery-runbook.sh` in the OSINT repo.

**Wake Forest "WHISPER" FP class** documented in the survey-17 catalog. `whisper.phs.wakehealth.edu` is a federally-funded clinical research portal (ColdFusion-on-IIS) that surfaces in `http.title:"Whisper"` Shodan dorks via keyword collision — pure FP for voice/audio AI. Same lesson class as the Garak / Garakuta-no-Kamisama collision Session 9 caught: single-keyword title/html match is unsound at population scale. The aimap fingerprints here all use conjunctive `body_contains` anchored to the actual project name (`openai-whisper-asr-webservice`, `whisper.cpp`, `Retrieval-based-Voice-Conversion`, `pipecat`, etc.) to avoid this class of FP.

### Notes for fingerprint authors

- Port 7860 (Gradio default) is heavily collision-prone across image generation, TTS, ASR, and voice cloning. Voice/audio fingerprints disambiguate via project-specific body strings; the catalog's `port:7860 http.html:"voice"` / `"speech"` / `"clone"` cross-cuts apply at Shodan-dork level, not at fingerprint level.
- Port 8000 / 8080 collisions (uvicorn, FastAPI generic) are handled by the same conjunctive pattern — voice-AI fingerprints require the project name appear in body.

## [v1.5.0] — 2026-05-05

Specialty data layers — analytic / OLAP / NoSQL tier. Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes.

### Added

**Fingerprints** — 3 new entries (50 → 53 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| ClickHouse | 8123, 8443, 9091 | `GET /ping` (status 200 + body `Ok.` + `X-Clickhouse-Server-Display-Name` header present) AND `GET /?query=SELECT+1` (status 200 + `X-Clickhouse-Format` header) | High — OLAP query access; sometimes including AI training datasets, model registries, or feature stores |
| Apache Pinot Controller | 9000 | `GET /cluster/info` (status 200 + json fields `clusterName` + `controllerHost`) AND `GET /tables` (status 200 + json field `tables`) | High — real-time analytics; tables/schema/segments/instance enumeration |
| ScyllaDB REST | 10000 | `GET /api-doc/` (status 200 + json field `apis` + body contains `storage_service`) | High — distributed NoSQL admin API; cluster topology, keyspaces, tables, sometimes AI feature stores |

### Methodology context

This release closes the Specialty data layers tier in [`FUTURE-SURVEYS.md`](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/FUTURE-SURVEYS.md). Cassandra CQL native protocol on port 9042 is **not** added to aimap — the CQL handshake is binary, not HTTP, and a proper protocol-strict OPTIONS-frame banner check belongs in the survey runbook (`data/specialty-data-layers-discovery-runbook.sh` in the OSINT repo). Adding tcp_send / binary_frame match types to aimap is a separate hardening pass, not blocking for this survey.

Port 9000 is collision-prone (ClickHouse native TCP, MinIO API, Pinot broker default, Whisper, etc.). The Apache Pinot Controller fingerprint discriminates via the conjunctive `clusterName` + `controllerHost` JSON field requirement — neither field appears on collision-class services.

Port 10000 collides with Webmin and miscellaneous management UIs; the ScyllaDB REST fingerprint discriminates via the `/api-doc/` Swagger-1.2 shape with `apis` array + the distinctive `storage_service` resource path.

### Notes for fingerprint authors

- Go's `net/http` canonicalizes `x-clickhouse-server-display-name` → `X-Clickhouse-Server-Display-Name`. Use canonical case for any new `header_contains` matchers.
- `header_contains` with `Value: ""` matches "header is present at all" (Go's `strings.Contains(s, "")` is always true). This is the idiomatic "header exists" check.

## [v1.4.0] — 2026-05-05

Specialty data layers — DuckDB-backed APIs. Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes.

### Added

**Fingerprints** — 2 new entries (48 → 50 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| Amulet Scan DuckDB API | 3001, 3000, 8000 | `GET /` JSON banner: `name`, `endpoints`, body contains `amulet scan` | High — Canton Network (Daml DLT) ledger-explorer backend; banner-declared admin endpoints (`POST /refresh-views`, `GET /health/config`, `/backfill/*`) |
| Definite.app DuckDB | 80, 443, 3000, 8000 | `GET /` operational headers: `X-Backend-Hostname` contains `duckdb-`, `X-Server-Version` contains `(git ` | High — YC-backed "DuckDB as a Service"; pod-name leak in header (`duckdb-deployment-*` prod / `duckdb-staging-deployment-*` staging) |

### Methodology context

Both fingerprints were derived during NuClide's `DuckDB-HTTP` Shodan-facet bucketing exercise (2026-05-05). The facet itself is substring-noisy at population scale — 38% of global facet hits are a single SaaS operator's K8s ingress fleet whose CSP `script-src` whitelists a `@duckdb/duckdb-wasm` CDN URL (browser-side WASM, not server-side DuckDB). Conjunctive matching anchors on **structured product banners** (JSON `name` field, operational headers in canonical case), not the keyword. Same lesson class as session-9's Garak/DeepEval substring-FP correction, with Shodan as the matcher.

### Notes for fingerprint authors

- Go's `net/http` canonicalizes header names (`x-backend-hostname` on the wire → `X-Backend-Hostname` in `resp.Header`). Existing fingerprints (`Server`, `Docker-Distribution-Api-Version`) already use canonical case; new `header_contains` matchers should follow the same convention. Case-insensitive header lookup is a separate hardening pass not done in this release.

## [v1.3.0] — 2026-04-23

Coverage release. Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes.

### Added

**Default port list (`-ports`)** — 7 new ports added to the default scan list:

- `80`, `443` — Dify and Coolify defaults; OpenHands installer; many AI services behind reverse proxies
- `2379` — etcd client port
- `5678` — n8n
- `9000` — MinIO API
- `30000` — SGLang, OpenHands NodePort default
- `18789` — Clawdbot

**Fingerprints** — 13 new entries (23 → 36 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| SGLang | 30000, 8889 | `/get_model_info` + body match | High severity — exposes model_path, runtime args |
| AI TTS Server | 10087, 8080 | `/v1/audio/voices` | Medium — voice/model enumeration |
| SillyTavern | 8000, 8001 | `Www-Authenticate: SillyTavern` header | Medium — character roleplay UI; often co-deployed with local LLMs |
| Grafana | 3000 | `/api/health` | Medium — DB status disclosure |
| Prometheus | 9090 | `/-/healthy` + `/api/v1/status/runtimeinfo` | Medium — metrics exposure |
| etcd | 2379 | `/health` + `/version` | Critical — Kubernetes/orchestration secret store |
| MinIO | 9000 | `/` AccessDenied XML + `/minio/health/live` | High — S3-compatible object store, often unauthenticated |
| n8n | 5678 | `/rest/active-workflows` | Critical — workflow orchestration with embedded credentials |
| OpenHands | 3000, 30000 | `<title>OpenHands</title>` + admin console body | Critical — autonomous agent platform |
| Mem0 | 8888 | `/docs` "Mem0 REST APIs" | High — agent memory store with PII |
| Coolify | 8000, 443 | `coolify_session` Set-Cookie | Low — self-hosted PaaS |
| Clawdbot | 18789, 443, 80 | `clawdbot-app` body | Medium |
| Open Directory | 9090, 8080, 8000, 4000 | "Directory listing for" / "Index of /" | High — Python http.server / nginx autoindex exposure |

**Deep enumerators** — 15 new dedicated enumerators (11 → 26 total):

- **`enumSGLang`** — model path, runtime args, served-model name, fingerprint extraction
- **`enumTTS`** — voice catalog and model enumeration via `/v1/audio/voices`
- **`enumVLLM`** — model list via `/v1/models` (previously fingerprint-only)
- **`enumOpenWebUI`** — auth posture, signup-open detection, environment leak via `/api/config`
- **`enumSillyTavern`** — basic-auth realm fingerprint, version probe
- **`enumGrafana`** — anonymous-access detection, version disclosure, snapshot enumeration
- **`enumPrometheus`** — anonymous query API, target enumeration, runtime info
- **`enumEtcd`** — anonymous v2/v3 access detection, member list, key enumeration without auth
- **`enumMinIO`** — bucket enumeration, anonymous access, server-info disclosure
- **`enumN8n`** — workflow enumeration, credential count, executions list
- **`enumOpenDirectory`** — directory walk + sensitive-filename heuristic (id_rsa, .env, *.pem, backup archives)
- **`enumOpenHands`** — admin console claim state, conversation history readability, agent runtime info
- **`enumMem0`** — memory enumeration, user/agent isolation check, PII detection in memory contents
- **`enumCoolify`** — installer claim state, server registration check
- **`enumClawdbot`** — version + auth fingerprint

**New category — AI agent platforms**: OpenHands, Mem0, Coolify, Clawdbot.

**New category — Observability / infra co-deployed with AI stacks**: Grafana, Prometheus, etcd, MinIO, n8n alongside Langfuse.

### Verified

- `go build -o aimap .` — clean
- `go vet ./...` — clean
- Banner reports `Fingerprints: 36 AI/ML services`

### Notes

The v1.3.0 commit message says "add Clawdbot fingerprint + enumerator, expand default ports" — that's the visible tip. The full delta also folds in a backlog of partially-staged fingerprints (SGLang, AI TTS, SillyTavern, the observability quintet, the agent-platform quartet, Open Directory) and their enumerators that had accumulated since v1.2.0.

---

## [v1.2.0] — 2026-04-17

Companion-tool release. No changes to the aimap Go binary, its fingerprint database, CLI flags, or JSON schema.

### Added

**`aimap-profile/` — target profiling + classification + disclosure-routing companion tool.**

Where aimap *fingerprints services* on a target (what's running?), `aimap-profile` *profiles the target itself* (what IS it? how should I approach it? where do I disclose?). The two tools are designed to be used together — profile first, then scan.

- Single-file Python (~500 LoC), read-only, passive-first.
- Reads Shodan historical data + live DNS/WHOIS/TLS cert + security.txt probes + RFC 9116 disclosure channels. Emits structured JSON designed for LLM/pipeline consumption.
- Eight analysis modules: identity, surface_passive (Shodan), surface_active (nmap, opt-in), discrepancy + honeypot scoring, classification + ethics flags, adjacency (PTR /29 + CT namespaces), web_surface (Nuxt/Next.js config extraction, token regex), disclosure (security.txt, MX, bounty hints).

Verified **100% primary-category accuracy across 17 real-world targets** spanning honeypot / clinical_hipaa / personal_device / commercial_staging / commercial_saas / research_lab / education classifications.

Honeypot detection example:

```json
"discrepancy": {
  "honeypot_score": 6,
  "verdict": "likely honeypot / deception asset",
  "signals": ["honeypot combo: [GlobalProtect, Ivanti] (+3)",
              "honeypot combo: [Asus, FortiGate] (+3)"]
}
```

HIPAA-boundary detection example:

```json
"classification": {
  "primary_category": "clinical_hipaa",
  "ethics_flags": [
    "HIPAA-adjacent network — no active probing of clinical systems",
    "Educational institution — CFAA exposure; prefer institutional CSIRT disclosure"
  ]
}
```

Run with `./aimap-profile/aimap_profile.py --target <ip|host> --mode fast`. See `aimap-profile/README.md` for heuristics reference and roadmap.

### Unchanged

- aimap Go binary (still v1.1.1)
- Fingerprint database (23 services)
- Default `-ports` list
- PKGBUILD / man page / CLI flags / JSON output schema

The aimap-profile companion is a separate script with its own versioning (v0.1.0); upgrading or skipping it does not affect `aimap` itself.

---

## [v1.1.0] — 2026-04-16

Additive release. No CLI, JSON schema, or existing fingerprint output changes.

### Added

**Default port list (`-ports`)** — 5 new ports added to the default scan list:

- `9091` — Milvus REST gateway
- `5001` — Dify (docker-compose's non-default web port)
- `8265` — Ray Dashboard
- `51000`, `55000` — Docker Registry (common non-default ports seen in the wild)

**Fingerprints** — 7 new entries (16 → 23 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| Milvus | 9091, 19530 | `/api/v1/health` | Closes gap where 19530 was scanned but unfingerprinted |
| Langfuse | 3000 | `/api/public/health` | High severity — stores full prompt/response traces |
| Dify | 80, 5001, 3000 | `/console/api/setup` | Catches critical "setup not completed → admin claimable" state |
| BentoML | 3000 | `/healthz` + `/docs.json` | |
| Ray Dashboard | 8265 | `/api/version` | Distinct from Ray Serve (already covered on 8000) |
| Kubeflow | 8080 | `/pipeline/apis/v1beta1/healthz` | |
| Docker Registry | 5000, 51000, 55000 | `/v2/` header | Severity: low — flagged for handoff to registry triage |

**Deep enumerators** — 4 new dedicated enumerators:

- **`enumMilvus`** — version, health, Prometheus metrics, collection enumeration via REST gateway, PII detection in collection names.
- **`enumLangfuse`** — auth status, open-signup detection, project count via `/api/public/projects`. Always emits an informational finding noting Langfuse contains LLM conversation data, so defenders know what they're dealing with even when auth is correctly configured.
- **`enumDify`** — primary signal is `/console/api/setup` returning a non-finished state, meaning anyone can claim the admin account. Critical-severity finding for fresh deployments.
- **`enumDockerRegistry`** — detects `/v2/_catalog` anonymous access, reports repo count, and flags adjacency. Does not perform full triage — points defender at dedicated registry tooling for that.

BentoML, Ray Dashboard, and Kubeflow are detected and risk-scored via the generic path; dedicated enumerators are queued for v1.2.

### Verified

- `go build -o aimap .` — clean
- `go vet ./...` — clean
- Banner reports `Fingerprints: 23 AI/ML services`

### Known limitations / queued for v1.2

- Autonomous agent frameworks (SuperAGI, AgentGPT, MetaGPT, OpenDevin) — intentionally skipped; category churns too fast for stable fingerprints.
- Dedicated deep enumerators for BentoML, Ray Dashboard, Kubeflow.
- Tier 2 adds from the Shodan AI/ML reference: Typesense, Label Studio, Argilla, ArangoDB.
- NVIDIA DCGM — GPU metrics exporter; useful for asset inventory but low severity standalone.

## [v1.0.0]

Initial release. 16 fingerprinted AI/ML services, ASCII banner UI, JSON report output, severity icons, progress bars.
