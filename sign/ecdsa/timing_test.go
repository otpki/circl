//go:build timing

// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ecdsa

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"flag"
	"math"
	"runtime"
	"testing"
	"time"

	"github.com/cloudflare/circl/ecc/brainpool"
	"github.com/cloudflare/circl/ecc/nist"
	"github.com/cloudflare/circl/internal/ctfield"
)

var (
	signingTimingSamples = flag.Int("signing-timing-samples", 128, "samples per class for the diagnostic signing timing test")
	signingTimingSink    [2][]byte
	signingControlSink   uint64
)

type signingObservation struct {
	n        int
	mean, m2 float64
}

func (o *signingObservation) add(v float64) {
	o.n++
	delta := v - o.mean
	o.mean += delta / float64(o.n)
	o.m2 += delta * (v - o.mean)
}

func signingWelch(a, b signingObservation) float64 {
	variance := a.m2/float64(a.n-1)/float64(a.n) + b.m2/float64(b.n-1)/float64(b.n)
	if variance == 0 {
		return math.Inf(1)
	}
	return (a.mean - b.mean) / math.Sqrt(variance)
}

// measureSigning times nonce generation and signing, excluding DER encoding.
func measureSigning(t *testing.T, key *PrivateKey, entropy []byte, e ctfield.Element) float64 {
	t.Helper()
	var err error
	d := key.domain
	start := time.Now()
	subtle.WithDataIndependentTiming(func() {
		nonce := newNonceDRBG(d.hash, entropy, nil, [][]byte{d.scalar.Bytes(key.d), d.scalar.Bytes(e)})
		signingTimingSink[0], signingTimingSink[1], err = key.sign(nonce, e)
	})
	elapsed := float64(time.Since(start).Nanoseconds())
	if err != nil {
		t.Fatal(err)
	}
	return elapsed
}

// runSigningTiming compares fixed and random private keys, including nonce rejection.
// Passing this diagnostic does not prove constant-time execution.
func runSigningTiming(t *testing.T, c elliptic.Curve) {
	if *signingTimingSamples < 32 || *signingTimingSamples > 10000 {
		t.Fatal("signing-timing-samples must be between 32 and 10000")
	}
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	d, err := newDomain(c)
	if err != nil {
		t.Fatal(err)
	}
	type sample struct {
		class int
		key   PrivateKey
	}
	sampleCount := *signingTimingSamples
	samples := make([]sample, 2*sampleCount)
	for i := range samples {
		scalar := ctfield.Element{1}
		if i&1 != 0 {
			var input [8]byte
			binary.BigEndian.PutUint64(input[:], uint64(i))
			digest := sha256.Sum256(input[:])
			scalar = d.hashScalar(digest[:])
			if d.scalar.Equal(scalar, ctfield.Element{}) == 1 {
				scalar = ctfield.Element{1}
			}
		}
		samples[i] = sample{class: i & 1, key: PrivateKey{domain: d, d: scalar}}
	}
	for i := len(samples) - 1; i > 0; i-- {
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(i))
		digest := sha256.Sum256(input[:])
		j := int(binary.BigEndian.Uint64(digest[:8]) % uint64(i+1))
		samples[i], samples[j] = samples[j], samples[i]
	}
	digest := sha256.Sum256([]byte("CIRCL signing timing diagnostic"))
	e, entropy := d.hashScalar(digest[:]), make([]byte, d.size)
	for i := 0; i < 8; i++ {
		measureSigning(t, &samples[i].key, entropy, e)
	}
	var actual, control [2]signingObservation
	for i := range samples {
		s := &samples[i]
		actual[s.class].add(measureSigning(t, &s.key, entropy, e))
	}
	for _, s := range samples {
		start := time.Now()
		iterations := 32
		if s.class == 1 {
			iterations = 50000
		}
		for i := 0; i < iterations; i++ {
			signingControlSink = signingControlSink*33 + uint64(i)
		}
		control[s.class].add(float64(time.Since(start).Nanoseconds()))
	}
	actualT, controlT := signingWelch(actual[0], actual[1]), signingWelch(control[0], control[1])
	t.Logf("%s %s/%s samples/class=%d deterministic SHA-256 inputs; only one logical processor", runtime.Version(), runtime.GOOS, runtime.GOARCH, *signingTimingSamples)
	t.Logf("signing means ns: %.0f / %.0f; Welch t=%.3f; leaky control t=%.3f", actual[0].mean, actual[1].mean, actualT, controlT)
	if math.Abs(controlT) < 5 {
		t.Fatal("positive control not detected; timing run is inconclusive")
	}
	if math.Abs(actualT) > 5 {
		t.Error("possible timing dependence; investigate before making a constant-time claim")
	}
}

func TestSigningTiming(t *testing.T) {
	t.Run("Brainpool-P256r1", func(t *testing.T) { runSigningTiming(t, brainpool.P256r1()) })
	t.Run("binary-K163", func(t *testing.T) { runSigningTiming(t, nist.K163()) })
}
