package main

// Pipelined orchestration — the proven prototype model ported into the real aimap.
//
// The default engine runs three sequential phase barriers (scanPorts -> matchFingerprints ->
// runEnumerators), each at -threads concurrency, each waiting for the slowest host before the
// next begins. This path instead runs ONE flat worker pool over hosts: each worker takes a
// host and runs scan -> fingerprint -> enum end-to-end for that host, then grabs the next.
// No phase barrier; a slow host never stalls the others. The existing scanPorts/
// matchFingerprints/runEnumerators are reused verbatim (internal threads=1), so every real
// fingerprint and enumerator behaves identically — only the orchestration changes.
//
// Gated by AIMAP_PIPELINE=1 so the default phase path is byte-for-byte unchanged
// (separate-then-merge). Pair with -threads 200-300 for the speedup. The fetch cache
// (AIMAP_FETCH_CACHE=1) composes on top.

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var pipelineOn = os.Getenv("AIMAP_PIPELINE") == "1"

// runPipeline is the self-contained fast path: scan+fingerprint+enum per host in a flat pool,
// then the same reporting the default path uses. Returns nothing; writes output itself.
func runPipeline(target string, hosts []string, targets []Target, portList []int,
	timeout time.Duration, threads int, verbose bool, output string, startTime time.Time,
	scanHoneypots bool) {

	printPhase(1, "PIPELINED SCAN — identity+fingerprint+enum per host, no phase barriers")
	fmt.Printf("\n    Hosts: %s  Ports: %d  Workers: %d\n\n", fmtNum(len(hosts)), len(portList), threads)

	pool := newPool(threads)
	var (
		mu      sync.Mutex
		allOpen []PortResult
		allSvc  []ServiceMatch
		allEnum []EnumResult
		skipped []string // honeypot spray hosts
		done    atomic.Int64
		dummy   atomic.Int64
		wg      sync.WaitGroup
	)

	var stopCh chan struct{}
	if !verbose {
		stopCh = startProgress(&done, int64(len(targets)))
	}

	for _, t := range targets {
		wg.Add(1)
		pool.Acquire()
		go func(t Target) {
			defer wg.Done()
			defer pool.Release()
			defer done.Add(1)

			// stage 1: this host's port scan (internal threads=1; outer pool is the concurrency)
			ports := scanPorts([]Target{t}, timeout, 1, false, &dummy)
			var open []PortResult
			for _, p := range ports {
				if p.Open {
					open = append(open, p)
				}
			}
			if len(open) == 0 {
				return
			}

			// per-host honeypot pre-filter (parity with the default path's spray skip):
			// a spray host opens >= honeypotSprayRatio of the scanned ports.
			if !scanHoneypots && len(portList) >= honeypotMinScanned &&
				float64(len(open))/float64(len(portList)) >= honeypotSprayRatio {
				mu.Lock()
				skipped = append(skipped, t.Host)
				allOpen = append(allOpen, open...) // still reported as open, just not enumerated
				mu.Unlock()
				return
			}

			// stage 2 + 3, end-to-end for this host, no barrier
			svc := matchFingerprints(open, timeout, false, 1)
			enum := runEnumerators(svc, timeout, false, 1)

			mu.Lock()
			allOpen = append(allOpen, open...)
			allSvc = append(allSvc, svc...)
			allEnum = append(allEnum, enum...)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	if !verbose {
		close(stopCh)
		time.Sleep(20 * time.Millisecond)
		finalizeProgress(int64(len(targets)))
	}

	if len(skipped) > 0 {
		fmt.Printf("\n  %s honeypot/tarpit pre-filter: skipped %d spray host(s) (use -scan-honeypots to override)\n",
			yellow("[!]"), len(skipped))
	}

	printOpenPorts(allOpen)
	if len(allSvc) > 0 {
		printFingerprints(allSvc, len(allOpen))
	}
	for _, er := range allEnum {
		printServiceCard(er)
	}

	if fetchCacheOn && fetchCache != nil {
		f, h := fetchCache.Stats()
		fmt.Printf("\n  [fetch-cache] real fetches: %d | cache hits (deduped): %d | saved %.0f%%\n",
			f, h, 100*float64(h)/float64(f+h+1))
	}

	if output != "" {
		rpt := buildReport(hosts, len(portList), allOpen, allSvc, allEnum, time.Since(startTime))
		writeJSON(rpt, output)
		fmt.Printf("\n  Report written: %s\n", output)
	}
}

// enumItemConcurrency bounds the per-item (per-collection / per-index) fetches inside an
// enumerator. The serial version of these loops was the real enum bottleneck.
const enumItemConcurrency = 64

// fanout runs fn over indices [0,n) with bounded concurrency. Each fn call must write only
// its own index into caller-owned storage (no shared mutation), so no lock is needed; the
// caller aggregates after fanout returns. Used to parallelize per-item enumerator loops.
func fanout(n, conc int, fn func(i int)) {
	if n <= 0 {
		return
	}
	var wg sync.WaitGroup
	pool := newPool(conc)
	for i := 0; i < n; i++ {
		wg.Add(1)
		pool.Acquire()
		go func(idx int) {
			defer wg.Done()
			defer pool.Release()
			fn(idx)
		}(i)
	}
	wg.Wait()
}
