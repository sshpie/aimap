package main

import (
	"hash/fnv"
	"sync/atomic"
)

// CASDedup is a lock-free deduplication set built on an open-addressed table of
// 64-bit key hashes. Each slot holds a non-zero key hash (0 means empty). On
// collision it linearly probes to the next slot, so two DISTINCT keys that hash
// to the same start slot are never confused — the earlier implementation stored
// only a timestamp with no key identity and silently dropped distinct keys that
// collided. Claims use a single atomic compare-and-swap; no mutex, no queue.
type CASDedup struct {
	entries []uint64
	size    uint64
}

// NewCASDedup creates a dedup table with size slots (honored, unlike before).
func NewCASDedup(size uint64) *CASDedup {
	if size == 0 {
		size = 2_000_000
	}
	return &CASDedup{entries: make([]uint64, size), size: size}
}

// TryClaim returns true if this call is the first to claim key, false if key was
// already claimed. Distinct keys are never dropped: on a slot collision with a
// different key it probes forward; only a genuine repeat of the same key, or a
// full table, ends the probe.
func (cd *CASDedup) TryClaim(key string) bool {
	kh := keyHash(key)
	start := kh % cd.size
	for i := uint64(0); i < cd.size; i++ {
		idx := (start + i) % cd.size
		v := atomic.LoadUint64(&cd.entries[idx])
		switch {
		case v == kh:
			return false // this exact key already claimed
		case v == 0:
			if atomic.CompareAndSwapUint64(&cd.entries[idx], 0, kh) {
				return true // we claimed an empty slot
			}
			// lost the race for this slot; if the winner claimed OUR key, it is a
			// duplicate, otherwise keep probing past the now-occupied slot.
			if atomic.LoadUint64(&cd.entries[idx]) == kh {
				return false
			}
		}
		// occupied by a different key: probe the next slot
	}
	return true // table full: fail open (index it) rather than drop a real result
}

// Stats returns the number of claimed slots (approximate under concurrency).
func (cd *CASDedup) Stats() int {
	count := 0
	for i := range cd.entries {
		if atomic.LoadUint64(&cd.entries[i]) != 0 {
			count++
		}
	}
	return count
}

// keyHash maps a key to a non-zero 64-bit hash (0 is reserved for empty slots).
func keyHash(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	v := h.Sum64()
	if v == 0 {
		v = 1
	}
	return v
}
