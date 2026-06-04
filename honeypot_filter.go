package main

import "sort"

// Honeypot/tarpit pre-filter. aimap scans hosts directly (no Shodan dependency),
// so the natively-available deception signal is the port-scan result itself: a
// real AI service host opens one to a few of the AI-curated ports, while a
// honeypot answers on nearly all of them (chargen/daytime/telnet/ftp/smtp plus
// the AI ports). Skipping fingerprint + deep-enum on spray hosts reclaims scan
// time (Cat-04: a 49-min run, 4x clean, was honeypot tarpitting) and drops the
// false-critical bait findings at the source rather than downstream in VisorCAS.
const (
	// honeypotMinScanned: below this many scanned ports the open/scanned ratio is
	// unreliable (2 of 3 open is normal for a host running a couple of services),
	// so the filter stays off.
	honeypotMinScanned = 6
	// honeypotSprayRatio: a host opening at least this fraction of the scanned
	// ports is treated as a tarpit. Real AI hosts sit well under it (1-3 of a
	// 16-22 port curated scan); honeypots sit well over it.
	honeypotSprayRatio = 0.5
)

// honeypotHostsBySpray returns the set of hosts whose open-port count is an
// implausible fraction of the scanned ports - the tarpit signature.
func honeypotHostsBySpray(openPorts []PortResult, scannedCount int) map[string]bool {
	if scannedCount < honeypotMinScanned {
		return nil
	}
	byHost := map[string]int{}
	for _, p := range openPorts {
		if p.Open {
			byHost[p.Host]++
		}
	}
	hp := map[string]bool{}
	for h, n := range byHost {
		if float64(n)/float64(scannedCount) >= honeypotSprayRatio {
			hp[h] = true
		}
	}
	return hp
}

// filterHoneypotSpray partitions the scan result: kept ports (real hosts) flow on
// to fingerprint + deep-enum; honeypots is the sorted list of spray hosts skipped.
// Callers report the skipped hosts (honest negative space) rather than dropping
// them silently.
func filterHoneypotSpray(openPorts []PortResult, scannedCount int) (kept []PortResult, honeypots []string) {
	hp := honeypotHostsBySpray(openPorts, scannedCount)
	for _, p := range openPorts {
		if hp[p.Host] {
			continue
		}
		kept = append(kept, p)
	}
	for h := range hp {
		honeypots = append(honeypots, h)
	}
	sort.Strings(honeypots)
	return kept, honeypots
}
