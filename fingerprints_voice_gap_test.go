package main

import (
	"testing"
)

// Voice gap-fill reconciliation (tome voice-tts-conversational, 2026-08-06).
// Focused positive-match + bare-brand-rejection guards for a few of the
// highest-value new voice FPs, mirroring fingerprints_voice_test.go. The
// load-bearing constraint is the conjunctive anchor: a structural build
// artifact (Gradio's gradio_config blob, a Swagger operationId) alongside
// the brand, so a README / article that merely mentions the project name
// does not trigger the fingerprint.

// matchFPByName runs every "/" (or empty) probe of the named FP against pr.
func matchFPRoot(name string, pr PortResult, paths ...string) bool {
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	for _, fp := range Fingerprints {
		if fp.Name != name {
			continue
		}
		for _, probe := range fp.Probes {
			if len(want) > 0 && !want[probe.Path] {
				continue
			}
			if matchProbe(probe, pr) {
				return true
			}
		}
	}
	return false
}

func TestGPTSoVITS_MatchesSwaggerRuntime(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.60", Port: 9880, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>GPT-SoVITS API - Swagger UI</title></head>` +
			`<body>...operationId set_gpt_weights ... operationId set_sovits_weights ...`,
	}
	if !matchFPRoot("GPT-SoVITS", pr, "/docs") {
		t.Fatal("GPT-SoVITS FP did not match its Swagger runtime with the set_*_weights operations")
	}
}

func TestGPTSoVITS_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.61", Port: 9880, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>Best TTS 2025</title></head>` +
			`<body><p>GPT-SoVITS is a great few-shot cloning model. See also RVC...</p>`,
	}
	if matchFPRoot("GPT-SoVITS", pr, "/docs", "/") {
		t.Fatal("GPT-SoVITS FP over-matched a bare brand-mention article")
	}
}

func TestSeedVC_MatchesGradioUI(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.62", Port: 7860, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><script>window.gradio_config = {` +
			`"title":"Seed-VC","components":[{"props":{"label":"Reference Audio"}}]};</script>`,
	}
	if !matchFPRoot("Seed-VC", pr, "/") {
		t.Fatal("Seed-VC FP did not match a real Gradio deployment (gradio_config + brand)")
	}
}

func TestSeedVC_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.63", Port: 7860, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>VC roundup</title></head>` +
			`<body><p>Seed-VC and so-vits-svc are popular voice conversion tools.</p>`,
	}
	if matchFPRoot("Seed-VC", pr, "/") {
		t.Fatal("Seed-VC FP over-matched a bare brand-mention article (no gradio_config)")
	}
}

func TestSherpaOnnx_MatchesDemoUI(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.64", Port: 6006, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><head><title>Next-gen Kaldi demo</title></head>` +
			`<body>Powered by k2-fsa/sherpa-onnx streaming_record.html</body>`,
	}
	if !matchFPRoot("sherpa-onnx", pr, "/") {
		t.Fatal("sherpa-onnx FP did not match its demo web UI")
	}
}

func TestSherpaOnnx_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.65", Port: 6006, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><head><title>ASR libraries</title></head>` +
			`<body><p>sherpa-onnx is a nice runtime for on-device ASR.</p>`,
	}
	if matchFPRoot("sherpa-onnx", pr, "/") {
		t.Fatal("sherpa-onnx FP over-matched a bare brand-mention (missing the demo title)")
	}
}

// Wire-protocol honesty guard: the pure-wire Vosk FP must NOT fire on an
// arbitrary HTTP 200 page — its placeholder probe requires the ws result
// JSON keys that never appear on a bare HTTP GET.
func TestVosk_DoesNotFireOnHTTP(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.66", Port: 2700, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body>It works! nginx default page</body></html>`,
	}
	if matchFPRoot("Vosk", pr, "/") {
		t.Fatal("Vosk wire-only FP false-positived on a generic HTTP page")
	}
}
