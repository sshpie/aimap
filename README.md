[![Claude Code Friendly](https://img.shields.io/badge/Claude_Code-Friendly-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)

# aimap

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/Nicholas-Kloster/aimap)](https://github.com/Nicholas-Kloster/aimap/releases)
[![Stars](https://img.shields.io/github/stars/Nicholas-Kloster/aimap)](https://github.com/Nicholas-Kloster/aimap/stargazers)

**nmap for AI infrastructure.** Purpose-built scanner for LLMs, vector databases, ML model servers, agent platforms, observability stacks, and 180+ other AI/ML services. Defenders run it against their own networks to find shadow AI before attackers do. NuClide research runs it against authorized populations to map exposure at scale.

Single Go binary. Zero external dependencies. Read-only HTTP probes. Safe for production.

## About the Engine

`aimap` is the core scanning engine of the NuClide Research AI-ASM (AI Attack Surface Management) platform. It is a purpose-built, high-concurrency Go toolchain designed to actively discover and fingerprint the shadow AI perimeter.

Traditional Cloud Security Posture Management (CSPM) and legacy vulnerability scanners are blind to the agentic era. They scan for known CVEs on legacy web ports, completely missing the unauthenticated ML orchestration frameworks, distributed vector databases, and LLM inference endpoints being rapidly deployed outside of centralized IT control.

By combining massive parallel scanning with ML-specific protocol "knocks" (REST, gRPC, and GraphQL), `aimap` accurately identifies exposed instances of Ollama, Weaviate, Ray, MLflow, and dozens of other AI infrastructure components. It translates raw perimeter exposures into structured JSON telemetry, designed to feed directly into visualization dashboards or downstream SIEMs.

## Why aimap exists

Security teams can't secure what they can't see, and AI adoption moves faster than inventory does. Every organization running modern ML has shadow deployments the security team doesn't know about:

- A data scientist stands up Ollama on a dev VM "just to test" — and never takes it down.
- An ML engineer deploys MLflow with `--host 0.0.0.0` because the docs said to — and it ends up on the internet when the security group gets relaxed.
- A team installs Jupyter for a workshop and forgets to set a token.
- A RAG prototype with a ChromaDB instance ships to production with no auth because "we'll add it later."
- Someone spins up Flowise to experiment with agent workflows and puts OpenAI keys in the credentials panel, which turns out to be world-readable.

Generic scanners (`nmap`, `nuclei`) don't identify these as AI services, so they don't show up in the security team's inventory. aimap does.

The 183 fingerprints in this release were forged from population-scale exposure surveys: 16,000+ unauthenticated Ollama deployments, 13,000+ Docker registries, 10,000+ NVIDIA Jetson edge devices, hundreds of extortion-wiped Elasticsearch clusters. Every fingerprint that ships passes the population-FP discipline: multi-condition matches anchored to status code + JSON shape + body, with a named regression test for every false-positive class the survey burned. Case studies are published at [nuclide-research.com](https://nuclide-research.com).

## What it detects (183 services, 62 deep enumerators)

| Category | Services |
|---|---|
| Vector databases & search | Weaviate, ChromaDB, Qdrant, Milvus, Apache Solr, Meilisearch, Typesense, Vespa |
| LLM runtimes | Ollama, llama.cpp server, vLLM, SGLang, LocalAI, text-generation-webui |
| Image generation | ComfyUI, AUTOMATIC1111 / SD WebUI, InvokeAI, Fooocus, SwarmUI |
| Embedding servers | HuggingFace TEI, infinity-embedding, Embedding API |
| Model serving | TensorFlow Serving, Triton Inference Server, NVIDIA NIM |
| ML platforms / experiment tracking | MLflow, Weights & Biases, WandB Service, ClearML, Aim |
| Orchestration / UI | LangServe, Flowise, Dify, Open WebUI, SillyTavern, LiteLLM, One API, NewAPI, BentoML, sub2api |
| AI agent platforms | OpenHands, AutoGen Studio, Anti-detect CDP server, Mem0, Coolify, OpenClaw |
| MCP | MCP Server |
| Code assistants | Sourcegraph, Sourcebot, Sweep AI, Tabnine Context Engine, Dyad, bolt.diy, Refact |
| Agent memory / data | Mem0, Argilla, Zep, Letta |
| Data labeling | Label Studio, CVAT, Doccano, Prodigy |
| Compute orchestration | Ray Serve, Ray Dashboard, Kubeflow, Apache Spark UI, Apache Airflow, Dask Dashboard, Prefect, Temporal Web |
| Container / Kubernetes / infra | etcd, Vault, Docker daemon, Kubernetes API, Consul, Portainer, Kubelet |
| BI / Dashboard | Metabase, Apache Superset, Redash, Grafana |
| Observability / tracing | Langfuse, Arize Phoenix, Helicone Self-Hosted, Lunary, OpenLIT, Pezzo, Prometheus |
| Workflow automation | n8n |
| Object storage | MinIO |
| Analytical datastores | ClickHouse, Elasticsearch, Apache Pinot, ScyllaDB REST, Amulet Scan DuckDB, Definite.app DuckDB |
| AI safety / eval / guardrails | Promptfoo, NeMo Guardrails, DeepEval, LangSmith Self-Hosted, Inspect AI, Garak REST, Lakera Guard Self-Hosted |
| Voice / Audio AI | Whisper ASR, Coqui XTTS, Piper TTS, RVC Voice Cloning, OpenVoice, ChatTTS, F5-TTS, Pipecat, Vocode, LiveKit Agents, AI TTS Server |
| Medical AI / PACS | MONAI Label Server, Orthanc DICOM Server, dcm4che / dcm4chee-arc, DICOMweb (QIDO-RS) |
| Notebooks / dev / adjacent | Jupyter Notebook, Open Directory, Docker Registry |
| Cross-cutting | Exposed API Credentials (Langfuse, Helicone, Stripe, Anthropic, LangSmith, OpenRouter, Slack — surfaces vendor keys in HTTP responses independent of the host's primary service) |

Each service has a dedicated fingerprint. 62 of the 183 services also have dedicated deep enumerators that surface PII fields, unauthenticated RCE, exposed credentials, claimable admin states, and other actionable findings.

## Port profiles (`-ports-class`)

The default 51-port scan is wide coverage for catch-all recon. For
service-focused surveys, `-ports-class <name>` narrows to a hand-curated
list — 5-10× wall-time reduction on typical populations (a 22-minute
sub2api survey on the default port set finishes in ~3 minutes with
`-ports-class sub2api`).

14 named profiles ship today:

| Profile | Ports | Best for |
|---|---|---|
| `llm-gateway` | 80, 443, 3000, 4000, 5000, 7860, 8000, 8001, 8080, 8443, 8888, 11434 | Ollama, vLLM, TGI, OpenWebUI, LiteLLM, sub2api, One API surveys |
| `vector-db` | 6333-6334, 7575-7576, 8000, 8123, 19121, 19530, 50051, 51000, 55000 | Qdrant, Weaviate, Chroma, Milvus, pgvector |
| `observability` | 3000, 4317, 5601, 6006, 8123, 9090-9094, 9100, 16686 | Phoenix, Langfuse, Helicone, Lunary, MLflow, OpenLLMetry |
| `registry` | 80, 443, 2376-2377, 5000-5001, 8080-8081, 8443, 9000, 9090 | Docker, Harbor, Quay |
| `network-mesh` | 4040, 4191, 8001, 9090-9092, 9901, 9999, 15010, 15012, 15014 | Envoy admin, Istio, Linkerd, Pomerium |
| `workflow-orch` | 2746, 3000, 4200, 7000, 7077, 8080, 8090, 8233, 8265, 8888 | Prefect, Dagster, Temporal, Argo |
| `browser-control` | 3000-3001, 3033, 4040, 4242, 4444, 8050, 9222, 9333 | CDP, Splash, Selenium Grid, Selenoid |
| `sub2api` | 80, 443, 3000, 8080, 8090, 8443 | sub2api-class pooled-account proxies |
| `jetson` | 80, 443, 5000, 5050, 8000-8002, 8554, 8765, 8888, 9090 | Jetson edge AI, Triton, CodeProject.AI, Frigate |
| `healthcare` | 80, 443, 4242, 8042-8043, 8080, 8200, 8443, 9090, 11112 | DICOM / PACS / dcm4chee / Orthanc |
| `finance` | 80, 443, 5000, 5555, 8000, 8080, 8443, 8501, 8888, 9090 | QuantConnect, OpenBB, JESSE |
| `mcp` | 3000-3001, 5173-5174, 8000-8001, 8080-8081, 11434 | Model Context Protocol servers |
| `wide` | 51 ports (the existing default catch-all) | Mixed-class recon |
| `minimal` | 80, 443, 8080, 8443 | Quick "is this host alive" probe |

Example:

```bash
aimap -list candidates.txt -ports-class sub2api -threads 30 -o out.json
```

Use `aimap -ports-class wide` to explicitly select the 51-port default.
Define new profiles in [`port_classes.go`](port_classes.go) — single
map, no other files touched.


## Companion tool: `aimap-profile`

Where aimap *fingerprints services* on a target, [`aimap-profile/`](./aimap-profile/) *profiles the target itself* — what is it, what category (personal device / institutional / commercial / research / honeypot), what's the ethics posture (HIPAA? CFAA? safe harbor?), who are its DNS neighbors, and where do you report a finding?

Single-file Python, emits structured JSON for LLM/pipeline consumption. Verified 100% primary-category accuracy across 17 real-world targets (campus infra, commercial staging, hospital research-compute, consumer devices, honeypots).

```bash
./aimap-profile/aimap_profile.py --target 129.49.255.85 --mode fast
# => {"classification": {"primary_category": "clinical_hipaa", ...}}
```

See [aimap-profile/README.md](./aimap-profile/README.md) for details.

## Install

### Go install (recommended for developers)

```bash
go install github.com/Nicholas-Kloster/aimap@latest
```

### Download a binary (recommended for security teams)

Pre-built Linux amd64 and arm64 binaries are on the [Releases page](https://github.com/Nicholas-Kloster/aimap/releases). Download, chmod, move to PATH:

```bash
curl -LO https://github.com/Nicholas-Kloster/aimap/releases/latest/download/aimap-linux-amd64
chmod +x aimap-linux-amd64
sudo mv aimap-linux-amd64 /usr/local/bin/aimap
```

### Build from source

```bash
git clone https://github.com/Nicholas-Kloster/aimap.git
cd aimap
go build -o aimap .
```

## Quick start

```bash
# Scan a single host
aimap -target 192.168.1.100

# Audit an internal subnet for shadow AI
aimap -target 10.0.0.0/24 -threads 50 -o audit.json

# Investigate one host with wide port coverage
aimap -target 10.5.5.5 -v -ports 8000,8080,8443,8888,9091,11434,6333,19530,5000,3000,7860,4000,51000,55000

# CI/CD deployment gate — fail build on critical findings
aimap -target $DEPLOY_URL -o check.json
jq '.enum_results[] | select(.risk_level == "critical")' check.json
```

### Common use cases

**Shadow-AI audit** — scan your internal CIDR ranges on a schedule, diff against last run, investigate new AI services appearing.

**External-exposure check** — scan your own public IPs to catch AI services that leaked onto the internet through misconfigured cloud security groups.

**CI/CD deployment gate** — run aimap against newly-deployed services as a smoke test, fail the build if critical findings surface.

**Incident response** — single-target deep dive when you have a tip that one specific host may be exposed.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | — | Single target (IP, hostname, or CIDR) |
| `-list` | — | File of targets, one per line (`#` comments supported) |
| `-ports` | 41-port default set | Comma-separated ports to scan |
| `-timeout` | `5s` | Connection timeout |
| `-threads` | `20` | Concurrent scan threads |
| `-o` | — | JSON report output file |
| `-v` | false | Verbose output |

Default port list (42 ports): `80,443,1984,2379,3000,3001,4000,4040,4200,5000,5001,5678,6333,7575,7576,7860,8000,8001,8080,8081,8088,8123,8233,8265,8443,8501,8787,8888,8889,9000,9090,9091,9200,10000,11434,15500,18080,18789,19530,30000,51000,55000`

See `man aimap` (if installed system-wide) for the full reference.

## Output

Terminal output is colorized, human-readable, and includes per-service risk scoring. JSON output (`-o file.json`) is machine-readable and stable across releases — suitable for pipeline integration, SIEM ingest, or diffing across scans.

### Risk levels

| Level | Criteria | Examples |
|-------|----------|----------|
| **critical** | Exploitable now, no auth | Unauthenticated Jupyter RCE, exposed Flowise credentials, Dify with unclaimed admin |
| **high** | Sensitive data accessible, no auth | Vector DB with PII, Langfuse traces readable, MLflow experiments accessible |
| **medium** | Information disclosure | Version leaks, CORS misconfig |
| **low** | Service detected, minor leak | Header disclosure |
| **info** | Service identified, auth in place | Nothing actionable |

**Escalation rule:** `auth == none` + `high` finding = `critical`. Data accessible without authentication is always critical regardless of other factors.

## Architecture

| File | Purpose |
|------|---------|
| `main.go` | CLI entry point, 3-phase orchestration, flag parsing |
| `scanner.go` | Parallel TCP connect + HTTP probe (Phase 1) |
| `fingerprints.go` | 183-entry fingerprint database + match engine (Phase 2) |
| `enumerators.go` | 62 service-specific deep enumerators + credential/secret scanners (Phase 3) |
| `adjacency.go` | ML-adjacency rule — data-tier ports on hosts with confirmed AI services (Insight #20) |
| `reporter.go` | Colored terminal output + JSON export |
| `utils.go` | HTTP client, JSON helpers, CIDR parsing, worker pool, target normalization |

Adding a new service is two steps:

1. Add a `Fingerprint` struct to `fingerprints.go` — multi-condition `Matches[]` only; naked single-word `body_contains` is unsound at population scale
2. (Optional) Add an `enum<Service>` function to `enumerators.go` and wire it in `runEnumerators`

PRs welcome.

## Safety and authorization

aimap is active — it performs TCP connections and HTTP GETs. **Only scan systems you own or have explicit written authorization to test.** Unauthorized scanning of third-party infrastructure may violate local computer-misuse laws.

For passive reconnaissance of external targets, use dedicated OSINT tools instead (Shodan, Censys, Certificate Transparency logs). aimap is designed to consume the IP lists those tools produce — Shodan dork exports, Censys API results, and CT-log cert-pivot outputs feed directly into `-list`.

aimap does not:

- Authenticate to services (even if credentials are provided)
- Submit forms or POST data
- Execute exploits or payloads
- Modify, delete, or create anything on target systems

All probes are HTTP GETs. All findings are derived from public-endpoint responses.

## Censys integration

Censys labels AI-infrastructure hosts at the service level (`host.services.labels.value = "AI"`), giving a pre-classified starting population of ~271K hosts (as of 2026-05). aimap is designed to fingerprint that population precisely: Censys identifies that a host *is* AI infrastructure; aimap identifies *which* AI service and *whether* it is authenticated.

```bash
# 1. Export AI-labeled hosts from Censys Search (free tier: first page; research tier: full dataset)
#    Query: host.services.labels.value = "AI" and host.services.port = 11434
#    Export IPs to censys-ai-ollama.txt

# 2. Run aimap against the Censys population
aimap -list censys-ai-ollama.txt -ports-class llm-gateway -threads 50 -o censys-aimap.json

# 3. Triage critical findings
jq '.enum_results[] | select(.risk_level == "critical") | {ip, service, findings}' censys-aimap.json
```

The `censys-sweep.py` script in [AI-LLM-Infrastructure-OSINT](https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT) handles the full workflow: Censys API query, cross-reference against existing Shodan populations, SAN extraction for cert-pivot, and delta-merge so the downstream aimap run sees the combined population.

Censys-specific query patterns for the AI survey program:

| Platform | Censys query |
|---|---|
| Ollama | `host.services.labels.value = "AI" and host.services.port = 11434` |
| n8n | `host.services.labels.value = "AI" and host.services.port = 5678` |
| Jupyter | `host.services.labels.value = "AI" and host.services.port = 8888` |
| Any AI service | `host.services.labels.value = "AI"` (~271K hosts) |
| Plus CT-log pivot | `services.certificate.leaf_data.subject_dn: "<platform name>"` |

## Integration examples

### GitHub Actions (CI gate)

```yaml
- name: AI exposure check
  run: |
    aimap -target ${{ env.DEPLOY_URL }} -o aimap.json
    CRITICAL=$(jq '[.enum_results[] | select(.risk_level == "critical")] | length' aimap.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::Deployment blocked: $CRITICAL critical AI exposures found"
      exit 1
    fi
```

### Cron-based continuous monitoring

```bash
# /etc/cron.monthly/aimap-audit
#!/bin/bash
OUT=/var/log/aimap/$(date +%Y-%m).json
aimap -target 10.0.0.0/16 -threads 50 -o "$OUT"

# Diff against last month
PREV=$(ls /var/log/aimap/*.json | tail -n 2 | head -n 1)
diff <(jq -S '.services' "$PREV") <(jq -S '.services' "$OUT") && \
  mail -s "aimap audit clean" security@example.com || \
  mail -s "aimap audit: NEW SERVICES DETECTED" security@example.com < "$OUT"
```

### Ingest into SIEM

The JSON schema is stable; findings have consistent `category`, `severity`, and `service` fields. Ingest `enum_results[].findings[]` into Splunk/Elastic/Loki as-is.

## Use with Claude Code

Claude Code can drive aimap scans, parse the JSON output, and chain findings into remediation or exploitation steps without leaving the terminal.

```
Run `aimap -target 10.0.0.0/24 -threads 50 -o aimap.json`, then parse aimap.json and give me a prioritized summary of every critical and high finding — service name, IP, port, and what's exposed.
```

```
I have aimap.json from a scan of my internal network. Cross-reference every AI service found against known CVEs for that service version, flag anything unauthenticated, and draft a one-paragraph executive summary I can paste into a security report.
```

---

## Contributing

Bug reports and fingerprint additions welcome via GitHub issues and PRs. When submitting a new fingerprint:

- Include the service's default port(s)
- Include a reliable distinguishing probe (path + body match)
- Note any known auth patterns
- Deep enumerators are nice-to-have, not required

## License

MIT. See [LICENSE](LICENSE).

## About

aimap is the fingerprint engine NuClide research surveys run on. The tool is open source under MIT. The methodology is published. The case studies are public.

Defenders run aimap against their own networks. Researchers run it against authorized populations. The 183 fingerprints come from real survey work: 30+ platform categories, hundreds of thousands of probes across exposed Ollama deployments, Weaviate vector databases, MLflow trackers, Langfuse instances, Docker registries, NVIDIA Jetson edge devices, Frigate camera fleets, Elasticsearch clusters, code-assistant servers, and the long tail of AI services that ship `--host 0.0.0.0` by default.

Survey scope (selected results, all published): 16,473 unauthenticated Ollama instances · 13,631 Weaviate PII exposures · 67 unauthenticated Kubecost cost APIs (Extreme Networks helmValues confirmed) · 52 unauthenticated OpenHands agent platforms · 6 unauthenticated voice/audio AI pipelines · 45+ survey categories completed. Findings reported to CISA, government CERTs, and enterprise vendors. Cross-platform auth-on-default thesis confirmed across 30+ platform classes.

Every fingerprint passes a population-FP discipline before it ships: multi-condition `Matches[]` anchored to status code + JSON shape + body, with a named regression test for every false-positive class the survey burned. The discipline is enforced because at population scale, a 0.1% FP rate against 10,000 hosts means 10 wrong findings, and the noise breaks the survey.

Maintained by **[Nicholas Michael Kloster](https://github.com/Nicholas-Kloster)** as part of [**NuClide**](https://nuclide-research.com).

CISA disclosures: [CVE-2025-4364](https://nvd.nist.gov/vuln/detail/CVE-2025-4364) · [ICSA-25-140-11](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-11)

Companion tools: [aimap-profile](./aimap-profile/), [BARE](https://github.com/Nicholas-Kloster/BARE), [recongraph](https://github.com/Nicholas-Kloster/recongraph), [cortex](https://github.com/Nicholas-Kloster/cortex-framework)

## See also

- [nmap](https://nmap.org) — general-purpose network scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) — template-based vulnerability scanner
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — risk framework for AI applications
