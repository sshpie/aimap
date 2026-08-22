# aimap-profile

**Target profiling + classification + disclosure-routing** for security research workflows. Complementary to [aimap](../aimap/) — where aimap fingerprints specific AI/ML services on a target, `aimap-profile` answers the questions **before** and **around** the scan:

- What is this target? (identity, WHOIS, ASN, TLS)
- What category? (personal / institutional / commercial / research / honeypot)
- What's the ethics posture? (HIPAA? education? personal device? safe harbor?)
- What's actually live? (active+passive surface fused, discrepancy flags)
- Who are its neighbors? (PTR /29, shared TLS SANs, CT namespace)
- What's in the web layer? (embedded config, framework, token leaks)
- Where do I disclose? (security.txt, MX, bounty program, SOC email)

Single command → structured JSON designed for LLM/pipeline consumption.

## Why it exists

Across every engagement in `~/recon/`, the same manual steps recurred:

| Friction | Manual time per target |
|---|---|
| Active/passive mode switching (nmap → Shodan fallback on rate-limit) | 5–10 min |
| Category classification (personal? institutional? clinical? commercial?) | 5–10 min |
| Disclosure channel discovery (security.txt → bounty platform → WHOIS → standard emails) | 20–30 min |
| PTR /29 neighborhood sweep | 2–5 min |
| CT enumeration for the apex | 2–5 min |
| Web config extraction (Nuxt/Next.js/embedded config) | 5–10 min |
| Honeypot recognition (impossible service combos) | missed on first pass |

`aimap-profile` encodes the decision framework once, so it doesn't have to be re-reasoned per target.

## Install

```bash
cd ~/ai-recon/aimap-profile
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# One-time Shodan API key (if not already configured):
shodan init <API_KEY>   # stores at ~/.config/shodan/api_key
```

Requires `nmap`, `dig`, `whois`, `openssl` in PATH.

## Usage

```bash
# Fast mode — passive only (Shodan + CT + DNS + web GET). No nmap.
./aimap_profile.py --target 129.49.255.85 --mode fast

# Full mode — adds nmap top-100 + CT apex enumeration. Use with written authorization.
./aimap_profile.py --target kumari.ai --mode full -v -o kumari.json
```

## Output

Single JSON blob with sections:

```
meta              — tool version, mode, elapsed time
identity          — rdns, forward_dns, resolved_ip, whois
surface_passive   — Shodan: ports, vulns, services
surface_active    — nmap (full mode only): ports + service/version
discrepancy       — honeypot_score, verdict, signals (active vs passive delta)
classification    — primary_category, all_hits, ethics_flags
adjacency         — ptr_sweep (/29), ct_namespaces (full mode)
web_surface       — probes with title/generator/embedded/secret_candidates
disclosure        — security_txt, mx_checks, whois_abuse_hint
```

## Example 1 — honeypot detection (54.183.84.204)

`aimap-profile` detects impossible service combinations (GlobalProtect + Ivanti + FortiGate cert issuer with `*.asusrouter.com` subject):

```json
"discrepancy": {
  "honeypot_score": 6,
  "verdict": "likely honeypot / deception asset",
  "signals": [
    "honeypot combo detected: ['GlobalProtect', 'Ivanti'] (+3)",
    "honeypot combo detected: ['Asus', 'FortiGate'] (+3)"
  ]
}
```

~10 seconds. Active nmap alone returns "all filtered" — the Shodan passive fingerprint is what reveals the deception.

## Example 2 — HIPAA-adjacent classification (129.49.255.85)

Auto-flags `clinical_hipaa` primary category, surfaces ethics constraints, and PTR-sweeps the /29 to reveal adjacent cluster members:

```json
"classification": {
  "primary_category": "clinical_hipaa",
  "all_hits": ["clinical_hipaa", "education", "research_lab"],
  "ethics_flags": [
    "HIPAA-adjacent network — no active probing of clinical systems",
    "Educational institution — CFAA exposure; prefer institutional CSIRT disclosure",
    "Research lab / HPC — likely shared multi-user; scope carefully"
  ]
},
"adjacency": {
  "ptr_sweep": [
    {"ip": "129.49.255.80", "rdns": "res-navy-onr.uhmc.sunysb.edu."},
    {"ip": "129.49.255.86", "rdns": "coe-cancer-data.uhmc.sunysb.edu."},
    {"ip": "129.49.255.87", "rdns": "som-cbase-2022.uhmc.sbuh.stonybrook.edu."}
  ]
}
```

The ethics flags surface before any active probe, so the researcher stops to reconsider scope before touching a clinical-adjacent host.

## Heuristics reference

### Category hints (substring match across rdns + forward_dns + hostnames + whois)

| Category | Sample keywords |
|---|---|
| `personal_device` | airport, timecapsule, printer, labview, synology, home-nas |
| `clinical_hipaa` | uhmc, sbuh, sbmed, epic, cerner, careconnect, apollo, ascom, medicine.edu |
| `education` | .edu, .ac., cs., student, grade, cse356, compas, course |
| `commercial_staging` | stg-, staging, -dev., preprod, qa. |
| `research_lab` | res-, lab-, labs., hpc, cluster, compute-, gpu- |
| `honeypot_signal` | canary, honey, opencanary, cowrie, tpot |

### Honeypot service-combo scoring

| Combo | Score |
|---|---|
| `{GlobalProtect, Ivanti}` | +3 |
| `{FortiGate, Asus}` | +3 |
| `{Cisco, Fortinet}` | +2 |
| `{Ivanti, Pulse}` | +1 |
| `{ASA, F5}` | +2 |

Score ≥ 3 → "likely honeypot". Score ≥ 1 → "mixed signals".

## Design notes

- **Passive-first by default.** `--mode fast` never issues traffic that could look like an attack.
- **No silent failures.** Each module's errors are captured in its own section, not swallowed.
- **Structured output, not prose.** Consumer is an LLM agent, a CI job, or a spreadsheet.
- **No state on target.** No POSTs, no auth, no form submissions.

## Roadmap

- CT reachability probing (pair CT hostnames with a safe-rate probe to distinguish exists-in-CT from actually-live)
- More framework extractors (Next.js `__NEXT_DATA__`, Angular, Remix)
- Public bounty program lookup (HackerOne / Bugcrowd / Intigriti program-list APIs)
- JS chunk walker (follow Next.js `/_next/static/chunks/*.js` and extract every HTTP call)
- Censys as a secondary passive source
- Go port as `aimap profile` subcommand

## License

MIT (same as aimap).

## Maintainer

`security@d5data.ai` — sshpie Michael sshpie / .
