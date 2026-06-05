package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
	"sync/atomic"
)

// BloomFilter is a thread-safe probabilistic set membership tester. The bit
// array is backed by []uint32 words mutated with atomic OR (compare-and-swap),
// so concurrent Add calls never lose a bit write — the property the worker pool
// depends on. Positions come from double hashing (h1 + i*h2), giving k distinct
// bits per element instead of collapsing to a handful.
type BloomFilter struct {
	words []uint32
	size  uint64 // number of bits
	k     uint32 // number of hash positions
}

// NewBloomFilter creates a Bloom filter sized for capacity elements at the given
// false-positive rate.
func NewBloomFilter(capacity uint64, fpRate float64) *BloomFilter {
	size := optimalSize(capacity, fpRate)
	if size == 0 {
		size = 1
	}
	k := optimalK(size, capacity)
	return &BloomFilter{
		words: make([]uint32, (size+31)/32),
		size:  size,
		k:     k,
	}
}

// Add sets the k bit positions for data. Each word is updated with an atomic
// OR via a CAS loop, so simultaneous Adds from many goroutines compose without
// losing writes.
func (bf *BloomFilter) Add(data []byte) {
	h1, h2 := baseHashes(data)
	for i := uint32(0); i < bf.k; i++ {
		idx := (h1 + uint64(i)*h2) % bf.size
		word, mask := idx/32, uint32(1)<<(idx%32)
		for {
			old := atomic.LoadUint32(&bf.words[word])
			if old&mask != 0 {
				break // already set
			}
			if atomic.CompareAndSwapUint32(&bf.words[word], old, old|mask) {
				break
			}
		}
	}
}

// Contains reports whether all k bits for data are set. False means definitely
// absent; true means probably present.
func (bf *BloomFilter) Contains(data []byte) bool {
	h1, h2 := baseHashes(data)
	for i := uint32(0); i < bf.k; i++ {
		idx := (h1 + uint64(i)*h2) % bf.size
		word, mask := idx/32, uint32(1)<<(idx%32)
		if atomic.LoadUint32(&bf.words[word])&mask == 0 {
			return false
		}
	}
	return true
}

// popcount returns the number of set bits (test/diagnostic helper).
func (bf *BloomFilter) popcount() int {
	total := 0
	for i := range bf.words {
		total += bits.OnesCount32(atomic.LoadUint32(&bf.words[i]))
	}
	return total
}

// baseHashes derives two independent 64-bit hashes from a single SHA-256 digest,
// used for Kirsch-Mitzenmacher double hashing (position_i = h1 + i*h2). h2 is
// forced non-zero so successive positions actually differ.
func baseHashes(data []byte) (uint64, uint64) {
	sum := sha256.Sum256(data)
	h1 := binary.BigEndian.Uint64(sum[0:8])
	h2 := binary.BigEndian.Uint64(sum[8:16])
	if h2 == 0 {
		h2 = 1
	}
	return h1, h2
}

// optimalSize calculates the optimal bit array size: m = -n*ln(p) / (ln(2)^2).
func optimalSize(n uint64, p float64) uint64 {
	return uint64(-float64(n) * math.Log(p) / (math.Log(2) * math.Log(2)))
}

// optimalK calculates the optimal number of hash positions: k = (m/n) * ln(2).
func optimalK(m, n uint64) uint32 {
	if n == 0 {
		return 1
	}
	k := float64(m) / float64(n) * math.Log(2)
	if k < 1 {
		return 1
	}
	if k > 64 {
		return 64
	}
	return uint32(k)
}
