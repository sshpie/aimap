// port_classes.go — predefined port profiles for service-focused surveys.
//
// The default -ports flag scans 51 ports — wide coverage for catch-all
// recon, but wasteful when the survey targets a specific service class.
// At 5-8s timeout per port × 51 ports × N hosts ÷ thread pool, the bulk
// of wall time is spent waiting for irrelevant closed ports to time out.
//
// -ports-class <name> overrides -ports with a narrow, hand-curated list
// per service class. Empirical scale: a sub2api-class survey of 182 IPs
// finished in ~22 minutes with the default 51-port scan; the same survey
// with -ports-class sub2api (4 ports) would finish in ~2-3 minutes.
//
// Surfaced as a gap by the 2026-05-19 sub2api population survey. Custom
// per-survey -ports overrides duplicated the methodology's port-list
// knowledge across N invocations; this consolidates it.

package main

import (
	"fmt"
	"sort"
	"strings"
)

// PortClasses maps a profile name to its canonical port list. To add a
// new class: append here, document in the help text below, and (if it
// represents a recurring survey class) reference it in the relevant
// methodology / case-study docs.
var PortClasses = map[string][]int{
	// LLM inference gateways and brokers (Ollama, vLLM, TGI, OpenWebUI,
	// LiteLLM, sub2api, One API, NewAPI, etc.) — the most common survey
	// class. Default for the AI/LLM infra research program.
	"llm-gateway": {
		80, 443, 3000, 4000, 5000, 7860, 8000, 8001, 8080, 8443, 8888, 11434,
	},

	// Vector databases (Qdrant, Weaviate, Chroma, Milvus, pgvector,
	// Pinecone-self-hosted).
	"vector-db": {
		6333, 6334, 7575, 7576, 8000, 8123, 19530, 19121, 50051, 51000, 55000,
	},

	// Observability + tracing for LLM stacks (Phoenix, Langfuse, Helicone,
	// Lunary, MLflow, OpenLLMetry, Grafana, Prometheus).
	"observability": {
		3000, 4317, 5601, 6006, 8123, 9090, 9091, 9094, 9100, 16686,
	},

	// Container registries (Docker, Harbor, Quay) — the registry-pop and
	// Jetson registry surveys.
	"registry": {
		80, 443, 5000, 5001, 2376, 2377, 8080, 8081, 8443, 9000, 9090,
	},

	// Network/service mesh control + observability planes. Re-curated
	// 2026-05-31 from data/platform-intel/service-mesh-perimeter-osint to
	// the ports the introspection planes actually bind: Linkerd proxy-admin
	// 4191 + viz 8084/8085, Hubble Relay 4245 (gRPC) + UI 12000/30120,
	// k8s api 6443/8443, Cilium metrics 9962/9963/9965, Envoy admin 15000,
	// istiod xDS/debug 15010/15012/15014, Kiali 20001.
	"network-mesh": {
		80, 443, 4191, 4245, 6443, 8084, 8085, 8443, 9090, 9962, 9963,
		9965, 12000, 15000, 15010, 15012, 15014, 20001, 30120,
	},

	// Workflow orchestration (Prefect, Dagster, Temporal, Argo, Kubeflow,
	// KServe, Flyte, BentoML).
	"workflow-orch": {
		3000, 4200, 8080, 8090, 8233, 8265, 8888, 2746, 7000, 7077,
	},

	// Browser-automation backends (CDP, Splash, Selenium Grid, Selenoid,
	// Browserless, Playwright MCP) — the 2026-05-14 browser-automation
	// survey class.
	"browser-control": {
		3000, 3001, 4040, 4444, 8050, 9222, 9333, 3033, 4040, 4242,
	},

	// Sub2api-class pooled-account upstream proxies + downstream LLM
	// storefronts. Narrow port set, derived from the 2026-05-19 sub2api
	// population survey distribution (5,121 hosts on :8080, 1,073 on :443,
	// 441 on :80, 180 on :8090, 86 on :3000).
	"sub2api": {
		8080, 443, 80, 8090, 3000, 8443,
	},

	// Edge AI / Jetson — TensorRT, DeepStream, Triton, jetson-stats,
	// CodeProject.AI, DeepStack, Frigate, motionEye. Per the 2026-05-19
	// Jetson survey distribution.
	"jetson": {
		80, 443, 5000, 5050, 8000, 8001, 8002, 8554, 8765, 8888, 9090,
	},

	// Healthcare / DICOM / PACS — dcm4chee, Orthanc, OHIF, ClearCanvas.
	// Per the 2026-05-19 healthcare survey.
	"healthcare": {
		80, 443, 4242, 8042, 8043, 8080, 8200, 8443, 9090, 11112,
	},

	// Finance / algotrading platforms (QuantConnect, OpenBB, JESSE).
	"finance": {
		80, 443, 5000, 8000, 8080, 8443, 8501, 8888, 9090, 5555,
	},

	// MCP servers — the model context protocol exposure surface.
	"mcp": {
		3000, 3001, 5173, 5174, 8000, 8001, 8080, 8081, 11434,
	},

	// Voice / speech AI — STT (Whisper/Vosk/FunASR/WeNet), TTS synthesis
	// (Kokoro/Coqui/Piper/ChatTTS/F5/Orpheus/OpenTTS/MaryTTS/mimic3), voice
	// cloning/conversion (RVC/Applio/GPT-SoVITS/so-vits-svc/OpenVoice/XTTS/
	// VALL-E-X/Tortoise), and assistant stacks (Rhasspy/OVOS/Wyoming/Willow/
	// LiveKit). Curated 2026-08-06 from the tome voice-tts-conversational
	// corpus (56 platforms) by port frequency, not a raw union of all 61
	// observed ports. Two shared HTTP entrypoints dominate — 7860 (Gradio,
	// 17 platforms) and 8000 (FastAPI, 16) — so a port hit alone is weak;
	// the voice fingerprints anchor a marker (gradio_config blob / brand
	// string / /v1/audio/* path) on top. The long tail (2700 Vosk ws,
	// 10095 FunASR wss, 10086 WeNet, 10200-10700 Wyoming JSONL, 19000
	// Willow, 50051 Riva gRPC) is port-class-or-miss: one platform per port,
	// wire-protocol, invisible to any generic HTTP sweep.
	"voice": {
		80, 443, 2700, 4123, 5000, 5002, 5005, 5500, 6006, 6969, 7851,
		7860, 7865, 7880, 8000, 8001, 8020, 8080, 8181, 8501, 8880, 8888,
		8899, 8998, 9000, 9090, 9872, 9880, 10086, 10095, 10200, 10300,
		10400, 12101, 19000, 43001, 43007, 50051, 58003, 59125,
	},

	// Wide default — the existing 51-port catch-all kept here as a named
	// profile for explicit selection.
	"wide": {
		80, 443, 1984, 2379, 3000, 3001, 4000, 4040, 4200, 5000, 5001, 5678,
		6333, 7575, 7576, 7860, 8000, 8001, 8080, 8081, 8088, 8123, 8233,
		8265, 8443, 8501, 8787, 8888, 8889, 9000, 9090, 9091, 9200, 10000,
		11434, 15500, 18080, 18789, 19530, 30000, 51000, 55000,
	},

	// Minimal — quick "is this host serving HTTP at all" probe.
	"minimal": {
		80, 443, 8080, 8443,
	},
}

// ResolvePortsClass returns the comma-separated port list for the named
// profile. Returns "", error if the name is unknown.
func ResolvePortsClass(name string) (string, error) {
	ports, ok := PortClasses[name]
	if !ok {
		return "", fmt.Errorf("unknown port class %q (available: %s)", name, ListPortClasses())
	}
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(out, ","), nil
}

// ListPortClasses returns a sorted, comma-separated list of available
// profile names for error messages and --help output.
func ListPortClasses() string {
	names := make([]string, 0, len(PortClasses))
	for k := range PortClasses {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
