// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ecdsa

import (
	"bytes"
	"crypto"
	std "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"sync"
	"testing"

	"github.com/cloudflare/circl/ecc/curves"
	"github.com/cloudflare/circl/ecc/nist"
	"github.com/cloudflare/circl/internal/ctcurve"
	"github.com/cloudflare/circl/internal/ctfield"
)

func TestRegisteredCurveSignatures(t *testing.T) {
	digest := sha512.Sum512([]byte("CIRCL custom ECDSA interoperability"))
	for _, c := range curves.All() {
		t.Run(c.Params().Name, func(t *testing.T) {
			key, err := GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := SignASN1(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			pub, ok := key.Public().(*std.PublicKey)
			if !ok {
				t.Fatal("unexpected public key type")
			}
			if !std.VerifyASN1(pub, digest[:], signature) {
				t.Fatal("signature failed standard verifier")
			}
			raw, err := key.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			imported, err := ParseRawPrivateKey(c, raw)
			if err != nil {
				t.Fatal(err)
			}
			if !pub.Equal(imported.Public()) {
				t.Fatal("private key round trip")
			}
			digest[0] ^= 1
			if std.VerifyASN1(pub, digest[:], signature) {
				t.Fatal("accepted modified digest")
			}
			digest[0] ^= 1
		})
	}
}

func TestKeyAndReaderBoundaries(t *testing.T) {
	c := elliptic.P256()
	for _, raw := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33), c.Params().N.Bytes()} {
		if _, err := ParseRawPrivateKey(c, raw); err == nil {
			t.Fatalf("accepted scalar %x", raw)
		}
	}
	if _, err := GenerateKey(nil, rand.Reader); err == nil {
		t.Fatal("nil curve")
	}
	if _, err := GenerateKey(c.Params(), rand.Reader); err == nil {
		t.Fatal("unsupported generic curve")
	}
	if _, err := GenerateKey(c, nil); err == nil {
		t.Fatal("nil random reader")
	}
	if _, err := GenerateKey(c, bytes.NewReader(nil)); err == nil {
		t.Fatal("reader error lost")
	}
	raw := make([]byte, 32)
	raw[31] = 1
	key, err := ParseRawPrivateKey(c, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[31] = 2
	exported, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if exported[31] != 1 {
		t.Fatal("retained caller's private slice")
	}
	exported[31] = 3
	again, err := key.Bytes()
	if err != nil || again[31] != 1 {
		t.Fatal("export aliases private state")
	}
	digest := sha256.Sum256([]byte("test"))
	if _, err := key.Sign(bytes.NewReader(nil), digest[:], crypto.SHA256); err == nil {
		t.Fatal("signing reader error lost")
	}
	if _, err := key.Sign(nil, digest[:], nil); err == nil {
		t.Fatal("nil reader")
	}
	if _, err := key.Sign(rand.Reader, nil, nil); err == nil {
		t.Fatal("empty digest")
	}
	var zero PrivateKey
	if _, err := zero.Bytes(); err == nil {
		t.Fatal("zero key export")
	}
	if _, err := zero.Sign(rand.Reader, digest[:], nil); err == nil {
		t.Fatal("zero key signing")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

var _ io.Reader = zeroReader{}

func TestHedgedAndConcurrentSigning(t *testing.T) {
	key, err := GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, b := sha256.Sum256([]byte("message A")), sha256.Sum256([]byte("message B"))
	sa, err := key.Sign(zeroReader{}, a[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := key.Sign(zeroReader{}, b[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var first, second struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sa, &first); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(sb, &second); err != nil {
		t.Fatal(err)
	}
	if first.R.Cmp(second.R) == 0 {
		t.Fatal("reused nonce across messages with a failed entropy source")
	}
	pub := key.Public().(*std.PublicKey)
	if !std.VerifyASN1(pub, a[:], sa) || !std.VerifyASN1(pub, b[:], sb) {
		t.Fatal("hedged signature invalid")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := key.Sign(rand.Reader, a[:], nil)
			if err != nil {
				t.Error(err)
				return
			}
			if !std.VerifyASN1(pub, a[:], sig) {
				t.Error("concurrent signature")
			}
		}()
	}
	wg.Wait()
}

// Check the full signatures from RFC 6979 A.2.5 and A.2.8 using their fixed nonces.
func TestRFC6979Signature(t *testing.T) {
	decode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range []struct {
		c         elliptic.Curve
		key, r, s string
	}{
		{elliptic.P256(), "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"},
		{nist.K163(), "009A4D6792295A7F730FC3F2B49CBC0F62E862272F", "0113A63990598A3828C407C0F4D2438D990DF99A7F", "01313A2E03F5412DDB296A22E2C455335545672D9F"},
	} {
		t.Run(tc.c.Params().Name, func(t *testing.T) {
			key, err := ParseRawPrivateKey(tc.c, decode(tc.key))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("sample"))
			e := key.domain.hashScalar(digest[:])
			nonce := newNonceDRBG(sha256.New, key.domain.scalar.Bytes(key.d), key.domain.scalar.Bytes(e), nil)
			r, s, err := key.sign(nonce, e)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(r, decode(tc.r)) || !bytes.Equal(s, decode(tc.s)) {
				t.Fatalf("signature r=%x s=%x", r, s)
			}
		})
	}
}

func TestPublicCopy(t *testing.T) {
	key, err := GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := key.Public().(*std.PublicKey)
	mutated := key.Public().(*std.PublicKey)
	mutated.X.SetInt64(0)
	mutated.Y.SetInt64(0)
	if !original.Equal(key.Public()) {
		t.Fatal("Public aliases key coordinates")
	}
}

func TestRejectedCandidatesAndZeroComponents(t *testing.T) {
	c := elliptic.P256()
	one := make([]byte, 32)
	one[31] = 1
	input := append(make([]byte, 32), c.Params().N.Bytes()...)
	input = append(input, one...)
	key, err := GenerateKey(c, bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.Bytes()
	if err != nil || !bytes.Equal(raw, one) {
		t.Fatal("did not reject zero and out-of-range candidates")
	}
	// In this toy group, 7G has x=0, and G has x=5.
	params := &elliptic.CurveParams{P: big.NewInt(17), N: big.NewInt(19), B: big.NewInt(2), Gx: big.NewInt(5), Gy: big.NewInt(1), BitSize: 5}
	scalar, err := ctfield.New([]byte{19}, false)
	if err != nil {
		t.Fatal(err)
	}
	d := &domain{point: ctcurve.New(params, big.NewInt(2), false), scalar: scalar, size: 1, bits: 5}
	toy := &PrivateKey{domain: d, d: ctfield.Element{1}}
	for _, tc := range []struct {
		nonce  byte
		digest ctfield.Element
	}{{7 << 3, ctfield.Element{1}}, {1 << 3, ctfield.Element{14}}} {
		if _, _, err := toy.sign(bytes.NewReader([]byte{tc.nonce}), tc.digest); err == nil {
			t.Fatal("accepted zero signature component")
		}
	}
}
