// Copyright (c) 2026 OmniTrust Security LLC.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ecdsa

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/curves"
	"github.com/cloudflare/circl/internal/ctcurve"
	"github.com/cloudflare/circl/internal/ctfield"
)

type domain struct {
	curve      elliptic.Curve
	point      *ctcurve.Curve
	scalar     *ctfield.Field
	size, bits int
	hash       func() hash.Hash
}

func newDomain(c elliptic.Curve) (*domain, error) {
	if !registered(c) {
		return nil, errors.New("ecdsa: unsupported curve")
	}
	source := c.Params()
	params := *source
	params.P = new(big.Int).Set(source.P)
	params.N = new(big.Int).Set(source.N)
	params.Gx = new(big.Int).Set(source.Gx)
	params.Gy = new(big.Int).Set(source.Gy)
	var a *big.Int
	binary := false
	if b, ok := c.(ecc.BinaryCurve); ok {
		binary = true
		a = new(big.Int).Set(b.BinaryParams().A)
		params.B = new(big.Int).Set(b.BinaryParams().B)
	} else if source.B != nil {
		params.B = new(big.Int).Set(source.B)
		a = new(big.Int).Sub(params.P, big.NewInt(3))
	} else {
		// Brainpool r omits B from Params, so recover the coefficients from G and 2G.
		x, y := c.Double(source.Gx, source.Gy)
		v := new(big.Int).Mul(source.Gy, source.Gy)
		v.Sub(v, new(big.Int).Exp(source.Gx, big.NewInt(3), source.P))
		v.Sub(v, new(big.Int).Mul(y, y)).Add(v, new(big.Int).Exp(x, big.NewInt(3), source.P))
		inverse := new(big.Int).ModInverse(new(big.Int).Sub(source.Gx, x), source.P)
		if inverse == nil {
			return nil, errors.New("ecdsa: invalid public curve parameters")
		}
		a = new(big.Int).Mul(v, inverse)
		a.Mod(a, source.P)
		params.B = new(big.Int).Mul(source.Gy, source.Gy)
		params.B.Sub(params.B, new(big.Int).Exp(source.Gx, big.NewInt(3), source.P))
		params.B.Sub(params.B, new(big.Int).Mul(a, source.Gx)).Mod(params.B, source.P)
	}
	scalar, err := ctfield.New(params.N.Bytes(), false)
	if err != nil {
		return nil, err
	}
	bits := params.N.BitLen()
	var h func() hash.Hash = sha512.New
	if bits <= 256 {
		h = sha256.New
	} else if bits <= 384 {
		h = sha512.New384
	}
	return &domain{curve: c, point: ctcurve.New(&params, a, binary), scalar: scalar, size: (bits + 7) / 8, bits: bits, hash: h}, nil
}

func registered(c elliptic.Curve) bool {
	// Registered curves are pointers; unknown implementations have different types.
	for _, known := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		if c == known {
			return true
		}
	}
	for _, known := range curves.All() {
		if c == known {
			return true
		}
	}
	return false
}

func (d *domain) hashScalar(digest []byte) ctfield.Element {
	length := min(len(digest), d.size)
	encoded := append([]byte(nil), digest[:length]...)
	if excess := length*8 - d.bits; excess > 0 {
		shiftRight(encoded, excess)
	}
	return d.scalar.Reduce(encoded)
}

func shiftRight(b []byte, count int) {
	var carry byte
	for i, value := range b {
		b[i] = value>>uint(count) | carry
		carry = value << uint(8-count)
	}
}

func (d *domain) randomScalar(random io.Reader, truncate bool) (ctfield.Element, error) {
	b := make([]byte, d.size)
	for {
		if _, err := io.ReadFull(random, b); err != nil {
			return ctfield.Element{}, err
		}
		if excess := d.size*8 - d.bits; excess > 0 {
			if truncate {
				shiftRight(b, excess)
			} else {
				b[0] &= 0xff >> uint(excess)
			}
		}
		scalar, err := d.scalar.SetBytes(b)
		if err == nil && d.scalar.Equal(scalar, ctfield.Element{}) == 0 {
			return scalar, nil
		}
	}
}
