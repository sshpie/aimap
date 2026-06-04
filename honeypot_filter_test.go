package main

import (
	"reflect"
	"testing"
)

// Honeypots/tarpits answer on nearly every scanned port (chargen, telnet, ftp,
// smtp, plus the AI ports). A real AI service host opens one to a few of the
// AI-curated ports. Flagging the spray lets us skip deep-enum on bait hosts -
// reclaiming scan time (Cat-04: 49min, 4x clean, was honeypot tarpitting) AND
// dropping the false-critical findings at the source. Sourced to the Cat-01/03/04
// dogfoods: the AWS bait fleet (51.44/51.94/43.208) opened most ports per host.
func ports(host string, n int) []PortResult {
	out := make([]PortResult, n)
	for i := 0; i < n; i++ {
		out[i] = PortResult{Host: host, Port: 1000 + i, Open: true}
	}
	return out
}

func TestHoneypotHostsBySprayFlagsTarpit(t *testing.T) {
	// 16 ports scanned. tarpit opens 14; real host opens 2.
	var ops []PortResult
	ops = append(ops, ports("9.9.9.9", 14)...) // tarpit
	ops = append(ops, ports("1.1.1.1", 2)...)  // real
	hp := honeypotHostsBySpray(ops, 16)
	if !hp["9.9.9.9"] {
		t.Error("tarpit host (14/16 open) must be flagged")
	}
	if hp["1.1.1.1"] {
		t.Error("real host (2/16 open) must NOT be flagged")
	}
}

// Below the scanned-port floor the ratio is unreliable (2/3 open is normal for a
// host running a couple of services) - never flag.
func TestHoneypotHostsBySprayHonorsFloor(t *testing.T) {
	ops := ports("8.8.8.8", 3) // 3 of 3 open, but only 3 scanned
	if hp := honeypotHostsBySpray(ops, 3); hp["8.8.8.8"] {
		t.Error("must not flag below the scanned-port floor (ratio unreliable)")
	}
}

// filterHoneypotSpray drops the tarpit's ports and returns its host; real hosts
// survive to fingerprint + deep-enum.
func TestFilterHoneypotSprayPartitions(t *testing.T) {
	var ops []PortResult
	ops = append(ops, ports("9.9.9.9", 14)...)
	ops = append(ops, ports("1.1.1.1", 2)...)
	kept, honeypots := filterHoneypotSpray(ops, 16)
	if !reflect.DeepEqual(honeypots, []string{"9.9.9.9"}) {
		t.Errorf("honeypots = %v, want [9.9.9.9]", honeypots)
	}
	for _, p := range kept {
		if p.Host == "9.9.9.9" {
			t.Error("tarpit ports must be removed from the kept set")
		}
	}
	if len(kept) != 2 {
		t.Errorf("kept = %d ports, want 2 (the real host)", len(kept))
	}
}
