//go:build timing

// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ctcurve

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"flag"
	"math"
	"math/big"
	"runtime"
	"testing"
	"time"
)

var (
	timingBatch       = flag.Int("timing-batch", 1, "multiplications per sample for duration-matched diagnostics")
	timingSamples     = flag.Int("timing-samples", 128, "samples per class for the diagnostic timing test")
	timingPointSink   point
	timingControlSink uint64
)

type observation struct {
	n        int
	mean, m2 float64
}

func (o *observation) add(v float64) {
	o.n++
	delta := v - o.mean
	o.mean += delta / float64(o.n)
	o.m2 += delta * (v - o.mean)
}

func welch(a, b observation) float64 {
	variance := a.m2/float64(a.n-1)/float64(a.n) + b.m2/float64(b.n-1)/float64(b.n)
	if variance == 0 {
		return math.Inf(1)
	}
	return (a.mean - b.mean) / math.Sqrt(variance)
}

// runTiming compares fixed and random scalars, excluding affine conversion.
// Passing this diagnostic does not prove constant-time execution.
func runTiming(t *testing.T, c *Curve, scalarSize int) {
	if *timingBatch < 1 || *timingBatch > 64 {
		t.Fatal("timing-batch must be between 1 and 64")
	}
	if *timingSamples < 32 || *timingSamples > 10000 {
		t.Fatal("timing-samples must be between 32 and 10000")
	}
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	params := c.Params()
	p := c.checkedPoint(params.Gx, params.Gy)
	type sample struct {
		class int
		k     [32]byte
	}
	sampleCount := *timingSamples
	samples := make([]sample, 2*sampleCount)
	for i := range samples {
		samples[i].class = i & 1
		if i&1 == 0 {
			samples[i].k[scalarSize-1] = 1
		} else {
			var input [8]byte
			binary.BigEndian.PutUint64(input[:], uint64(i))
			samples[i].k = sha256.Sum256(input[:])
		}
	}
	for i := len(samples) - 1; i > 0; i-- {
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(i))
		digest := sha256.Sum256(input[:])
		j := int(binary.BigEndian.Uint64(digest[:8]) % uint64(i+1))
		samples[i], samples[j] = samples[j], samples[i]
	}
	for i := 0; i < 8; i++ {
		subtle.WithDataIndependentTiming(func() {
			for range *timingBatch {
				timingPointSink = c.multiply(p, samples[i].k[:scalarSize])
			}
		})
	}
	var actual, control [2]observation
	for _, s := range samples {
		start := time.Now()
		subtle.WithDataIndependentTiming(func() {
			for range *timingBatch {
				timingPointSink = c.multiply(p, s.k[:scalarSize])
			}
		})
		actual[s.class].add(float64(time.Since(start).Nanoseconds()))
	}
	// Check that the test can detect an intentionally leaky loop.
	for _, s := range samples {
		start := time.Now()
		iterations := 32
		if s.class == 1 {
			iterations = 50000
		}
		for i := 0; i < iterations; i++ {
			timingControlSink = timingControlSink*33 + uint64(i)
		}
		control[s.class].add(float64(time.Since(start).Nanoseconds()))
	}
	actualT, controlT := welch(actual[0], actual[1]), welch(control[0], control[1])
	t.Logf("%s %s/%s samples/class=%d deterministic SHA-256 inputs; batch=%d; only one logical processor", runtime.Version(), runtime.GOOS, runtime.GOARCH, *timingSamples, *timingBatch)
	t.Logf("arithmetic means ns: %.0f / %.0f; Welch t=%.3f; leaky control t=%.3f", actual[0].mean, actual[1].mean, actualT, controlT)
	if math.Abs(controlT) < 5 {
		t.Fatal("positive control not detected; timing run is inconclusive")
	}
	if math.Abs(actualT) > 5 {
		t.Error("possible timing dependence; investigate before making a constant-time claim")
	}
}

func TestArithmeticTiming(t *testing.T) {
	t.Run("prime-P256-shaped", func(t *testing.T) {
		params := elliptic.P256().Params()
		runTiming(t, NewPrime(params), 32)
	})
	t.Run("binary-K163", func(t *testing.T) {
		// Public K-163 constants, also used in ecc/nist/params.go.
		polynomial := new(big.Int)
		for _, bit := range []int{163, 7, 6, 3, 0} {
			polynomial.SetBit(polynomial, bit, 1)
		}
		gx, ok := new(big.Int).SetString("02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8", 16)
		if !ok {
			t.Fatal("invalid generator X")
		}
		gy, ok := new(big.Int).SetString("0289070fb05d38ff58321f2e800536d538ccdaa3d9", 16)
		if !ok {
			t.Fatal("invalid generator Y")
		}
		params := &elliptic.CurveParams{P: polynomial, B: big.NewInt(1), Gx: gx, Gy: gy, BitSize: 163}
		runTiming(t, New(params, big.NewInt(1), true), 21)
	})
}
