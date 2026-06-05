package main

// Fetch cache — ports the proven funnel result into aimap: every GET across all three
// phases (port scan, fingerprint, deep-enum) funnels through httpGET, so caching here makes
// each unique (GET url) fire exactly ONCE per run. Phase 2's "/" probe reuses Phase 1's grab;
// overlapping enumerator paths dedup; a dead port is dialed once, not re-timed-out per phase.
//
// Gated by env AIMAP_FETCH_CACHE=1 so the default path is byte-for-byte unchanged
// (separate-then-merge). Single-flight via sync.Map+Once (correctness); scanner's bloom/CAS
// ride along as the dedup-decision + instrumentation layer (the model we validated).
//
// Cacheable scope: GET only. httpPOST is left uncached (10 call sites; POSTs are not idempotent).
// Per-run lifetime: a fresh cache each invocation, so no stale cross-run data.

import (
	"net/http"
	"os"
	"sync"
	"sync/atomic"
)

type fetchResult struct {
	status int
	hdrs   map[string]string
	body   []byte
	err    error
}

type fcEntry struct {
	once sync.Once
	res  fetchResult
}

type FetchCache struct {
	bloom   *BloomFilter
	cas     *CASDedup
	store   sync.Map // url -> *fcEntry
	fetches int64    // real network requests
	hits    int64    // served from cache
}

var (
	fetchCacheOn = os.Getenv("AIMAP_FETCH_CACHE") == "1"
	fetchCache   *FetchCache
)

func initFetchCache() {
	if fetchCacheOn {
		fetchCache = &FetchCache{
			bloom: NewBloomFilter(4_000_000, 0.01),
			cas:   NewCASDedup(2_000_000),
		}
	}
}

// get fetches url at most once across all goroutines/phases this run.
func (fc *FetchCache) get(c *http.Client, url string) (int, map[string]string, []byte, error) {
	kb := []byte(url)
	seen := fc.bloom.Contains(kb)
	first := fc.cas.TryClaim(url)

	ai, loaded := fc.store.LoadOrStore(url, &fcEntry{})
	e := ai.(*fcEntry)
	if loaded || (seen && !first) {
		atomic.AddInt64(&fc.hits, 1)
	}
	e.once.Do(func() {
		fc.bloom.Add(kb)
		atomic.AddInt64(&fc.fetches, 1)
		s, h, b, err := httpGETRaw(c, url)
		e.res = fetchResult{s, h, b, err}
	})
	r := e.res
	return r.status, r.hdrs, r.body, r.err
}

// Stats returns (real fetches, cache hits) for end-of-run reporting.
func (fc *FetchCache) Stats() (int64, int64) {
	return atomic.LoadInt64(&fc.fetches), atomic.LoadInt64(&fc.hits)
}
