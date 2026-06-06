package main

import "testing"

// Cat-03 Model Serving survey (2026-06-05) verification pass exposed four
// false-positive fingerprints and one false-negative. These regression tests
// pin each fix: the FP shape must NOT match, and the genuine service must still
// match. See case-studies/commercial/cat03-model-serving-survey-2026-06-05.md
// in AI-LLM-Infrastructure-OSINT and memory reference-aimap-fp-framework-catchall-cat03.

// fpMatchesAny returns true if ANY probe of the named fingerprint matches pr.
// Mirrors the engine's OR-across-probes semantics.
func fpMatchesAny(name string, pr PortResult) bool {
	for _, fp := range Fingerprints {
		if fp.Name != name {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				return true
			}
		}
	}
	return false
}

// ── 1. GPT Researcher vs Gradio catch-all ──────────────────────────────
// The removed /api/report 405 probe matched every Gradio app. A Gradio
// "Whisper Playground" must no longer be tagged GPT Researcher.

func TestGPTResearcher_RejectsGradioCatchall(t *testing.T) {
	// Gradio FastAPI catch-all returns 405 on /api/report.
	gradio405 := PortResult{
		Host: "203.0.113.10", Port: 8000, Open: true, StatusCode: 405,
		Headers:     map[string]string{"Server": "uvicorn", "Content-Type": "application/json"},
		BodySnippet: `{"detail":"Method Not Allowed"}`,
	}
	if fpMatchesAny("GPT Researcher", gradio405) {
		t.Fatal("GPT Researcher matched a Gradio /api/report 405 — the FP probe was not removed")
	}
	// Gradio landing page (no gpt_researcher string) must also not match.
	gradioHome := PortResult{
		Host: "203.0.113.10", Port: 8000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Server": "uvicorn", "Content-Type": "text/html"},
		BodySnippet: `<meta property="og:title" content="Whisper Playground"/><script>window.gradio_config={}</script>`,
	}
	if fpMatchesAny("GPT Researcher", gradioHome) {
		t.Fatal("GPT Researcher matched a Gradio landing page lacking the gpt_researcher marker")
	}
}

func TestGPTResearcher_MatchesGenuine(t *testing.T) {
	real := PortResult{
		Host: "203.0.113.11", Port: 8000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<script src="/site/scripts/gpt_researcher/index.js"></script>`,
	}
	if !fpMatchesAny("GPT Researcher", real) {
		t.Fatal("GPT Researcher no longer matches a genuine instance (gpt_researcher in body)")
	}
}

// ── 2. Lunary vs CheckRef ──────────────────────────────────────────────
// CheckRef (scholarly reference validator) returns {"status":"ok",...} on
// /api/v1/health and matched the bare status:ok anchor.

func TestLunary_RejectsCheckRef(t *testing.T) {
	checkref := PortResult{
		Host: "203.0.113.20", Port: 3000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":"ok","services":{"database":"connected","redis":"connected"},"apis":{"doi_org":"up","crossref":"down","openalex":"up"}}`,
	}
	if fpMatchesAny("Lunary", checkref) {
		t.Fatal("Lunary matched CheckRef's /api/v1/health — crossref/openalex anti-match missing")
	}
}

func TestLunary_MatchesGenuine(t *testing.T) {
	real := PortResult{
		Host: "203.0.113.21", Port: 3000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":"ok"}`,
	}
	if !fpMatchesAny("Lunary", real) {
		t.Fatal("Lunary no longer matches its genuine {\"status\":\"ok\"} health body")
	}
}

// ── 3. h2oGPT vs KoboldCpp ─────────────────────────────────────────────
// KoboldCpp serves /openai_api/v1/models with a data array; it tags models
// owned_by:koboldcpp. h2oGPT must not claim it.

func TestH2OGPT_RejectsKoboldCpp(t *testing.T) {
	kobold := PortResult{
		Host: "203.0.113.30", Port: 5001, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Server": "KoboldCppServer 1", "Content-Type": "application/json"},
		BodySnippet: `{"object":"list","data":[{"id":"koboldcpp/gemma-4-31B-it-UD-Q8_K_XL","owned_by":"koboldcpp"}]}`,
	}
	if fpMatchesAny("h2oGPT", kobold) {
		t.Fatal("h2oGPT matched a KoboldCpp /openai_api/v1/models response — anti-koboldcpp match missing")
	}
}

func TestH2OGPT_MatchesGenuine(t *testing.T) {
	real := PortResult{
		Host: "203.0.113.31", Port: 5000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"object":"list","data":[{"id":"h2oai/h2ogpt-4096-llama2-7b","owned_by":"h2ogpt"}]}`,
	}
	if !fpMatchesAny("h2oGPT", real) {
		t.Fatal("h2oGPT no longer matches a genuine /openai_api/v1/models response")
	}
}

// ── 4. KoboldCpp false-negative ────────────────────────────────────────
// A live KoboldCpp serving a model (108.210.175.159:5001) was missed because
// /api/extra/version was unreachable. The Server header probe must catch it.

func TestKoboldCpp_MatchesViaServerHeader(t *testing.T) {
	lite := PortResult{
		Host: "203.0.113.40", Port: 5001, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Server": "KoboldCppServer 1", "Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><title>KoboldAI Lite</title>`,
	}
	if !fpMatchesAny("KoboldCpp", lite) {
		t.Fatal("KoboldCpp missed a live server identifiable by the Server: KoboldCppServer header")
	}
}

// ── 5 & 6. TTS fingerprints vs ZenTao path-echo ────────────────────────
// ZenTao's PHP router reflects the requested path in a 200 error body, so
// "speaker"/"voice" appear and matched Coqui XTTS / Chatterbox TTS.

func TestCoquiXTTS_RejectsZenTaoPathEcho(t *testing.T) {
	zentao := PortResult{
		Host: "203.0.113.50", Port: 8000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Set-Cookie": "zentaosid=abc123; path=/", "Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html>The method 'api/tts/speakers' illegal in /app/zentaopms/framework/base/router.class.php`,
	}
	if fpMatchesAny("Coqui XTTS", zentao) {
		t.Fatal("Coqui XTTS matched a ZenTao path-echo error — anti-ZenTao guards missing")
	}
}

func TestCoquiXTTS_MatchesGenuineSpeakerList(t *testing.T) {
	real := PortResult{
		Host: "203.0.113.51", Port: 8020, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"speakers":["female-en-5","male-pt-3"]}`,
	}
	if !fpMatchesAny("Coqui XTTS", real) {
		t.Fatal("Coqui XTTS no longer matches a genuine /api/tts/speakers JSON list")
	}
}

func TestChatterboxTTS_RejectsZenTaoPathEcho(t *testing.T) {
	zentao := PortResult{
		Host: "203.0.113.50", Port: 8000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Set-Cookie": "zentaosid=abc123; path=/", "Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html>The method 'get_predefined_voices' illegal in /app/zentaopms/framework/base/router.class.php`,
	}
	if fpMatchesAny("Chatterbox TTS", zentao) {
		t.Fatal("Chatterbox TTS matched a ZenTao path-echo error — anti-ZenTao guards missing")
	}
}

func TestChatterboxTTS_MatchesGenuineVoiceList(t *testing.T) {
	real := PortResult{
		Host: "203.0.113.52", Port: 8000, Open: true, StatusCode: 200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `[{"voice":"Emily","file":"emily.wav"}]`,
	}
	if !fpMatchesAny("Chatterbox TTS", real) {
		t.Fatal("Chatterbox TTS no longer matches a genuine /get_predefined_voices JSON list")
	}
}
