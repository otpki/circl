// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package ecdsa provides fixed-width ECDSA private-key operations for CIRCL's
// registered curves. Signatures and public keys interoperate with crypto/ecdsa.
// Use this package's signer for custom curves; crypto/ecdsa.Sign uses its own path.
package ecdsa

import (
	"crypto"
	std "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/internal/ctfield"
)

// PrivateKey stores a fixed-width private scalar and supports concurrent signing.
// Use Bytes to export it, and treat the curve parameters as read-only.
type PrivateKey struct {
	domain *domain
	d      ctfield.Element
	public std.PublicKey
}

var _ crypto.Signer = (*PrivateKey)(nil)

// GenerateKey generates a private key for a registered curve using random.
// A nil randomness source is an error.
func GenerateKey(c elliptic.Curve, random io.Reader) (*PrivateKey, error) {
	domain, err := newDomain(c)
	if err != nil {
		return nil, err
	}
	if random == nil {
		return nil, errors.New("ecdsa: nil randomness source")
	}
	scalar, err := domain.randomScalar(random, false)
	if err != nil {
		return nil, err
	}
	return domain.privateKey(scalar), nil
}

// ParseRawPrivateKey imports a big-endian scalar in [1, N).
// Its length must be ceil(N.BitLen()/8).
func ParseRawPrivateKey(c elliptic.Curve, data []byte) (*PrivateKey, error) {
	domain, err := newDomain(c)
	if err != nil {
		return nil, err
	}
	scalar, err := domain.scalar.SetBytes(data)
	if err != nil || domain.scalar.Equal(scalar, ctfield.Element{}) == 1 {
		return nil, errors.New("ecdsa: invalid private scalar")
	}
	return domain.privateKey(scalar), nil
}

func (d *domain) privateKey(scalar ctfield.Element) *PrivateKey {
	x, y := d.point.ScalarBaseMultBytes(d.scalar.Bytes(scalar))
	// The public coordinates can now be converted to big.Int.
	return &PrivateKey{domain: d, d: scalar, public: std.PublicKey{Curve: d.curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}}
}

// Bytes returns a new fixed-width big-endian copy of the private scalar.
func (k *PrivateKey) Bytes() ([]byte, error) {
	if k == nil || k.domain == nil {
		return nil, errors.New("ecdsa: invalid private key")
	}
	return k.domain.scalar.Bytes(k.d), nil
}

// Public returns a *crypto/ecdsa.PublicKey with a copy of the coordinates.
func (k *PrivateKey) Public() crypto.PublicKey {
	if k == nil || k.domain == nil {
		return nil
	}
	return &std.PublicKey{Curve: k.public.Curve, X: new(big.Int).Set(k.public.X), Y: new(big.Int).Set(k.public.Y)}
}

// Sign signs digest and returns a DER ECDSA signature. It mixes fresh randomness
// with the private key and digest to generate the nonce, as Go's signer does.
// opts is ignored. Nil randomness, an empty digest, or a reader failure returns
// an error; deterministic signing is not supported.
func (k *PrivateKey) Sign(random io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k == nil || k.domain == nil {
		return nil, errors.New("ecdsa: invalid private key")
	}
	if random == nil {
		return nil, errors.New("ecdsa: nil randomness source")
	}
	if len(digest) == 0 {
		return nil, errors.New("ecdsa: empty digest")
	}
	d := k.domain
	entropy := make([]byte, d.size)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return nil, err
	}
	e := d.hashScalar(digest)
	var r, s []byte
	var err error
	subtle.WithDataIndependentTiming(func() {
		nonce := newNonceDRBG(d.hash, entropy, nil, [][]byte{d.scalar.Bytes(k.d), d.scalar.Bytes(e)})
		r, s, err = k.sign(nonce, e)
	})
	if err != nil {
		return nil, err
	}
	// r and s are public, so variable-time DER encoding is safe here.
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
}

func (k *PrivateKey) sign(nonce io.Reader, e ctfield.Element) ([]byte, []byte, error) {
	d := k.domain
	ephemeral, err := d.randomScalar(nonce, true)
	if err != nil {
		return nil, nil, err
	}
	x, _ := d.point.ScalarBaseMultBytes(d.scalar.Bytes(ephemeral))
	r := d.scalar.Reduce(x)
	// Match Go's behavior for the negligible chance of a zero signature component.
	if d.scalar.Equal(r, ctfield.Element{}) == 1 {
		return nil, nil, errors.New("ecdsa: signature r is zero")
	}
	s := d.scalar.Mul(d.scalar.Inv(ephemeral), d.scalar.Add(e, d.scalar.Mul(r, k.d)))
	if d.scalar.Equal(s, ctfield.Element{}) == 1 {
		return nil, nil, errors.New("ecdsa: signature s is zero")
	}
	return d.scalar.Bytes(r), d.scalar.Bytes(s), nil
}

// SignASN1 signs digest using k, returning a standard DER ECDSA signature.
func SignASN1(random io.Reader, k *PrivateKey, digest []byte) ([]byte, error) {
	return k.Sign(random, digest, nil)
}
