// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ecc

import (
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"

	"github.com/cloudflare/circl/internal/ctcurve"
)

// initial binary curve implementation reference:
// https://github.com/RyuaNerin/elliptic2
// https://neuromancer.sk/std/

type Curve interface {
	elliptic.Curve
	Oid() asn1.ObjectIdentifier
}

type BinaryCurve interface {
	Curve
	BinaryParams() *BinaryCurveParams
}

// ensure curve implements the elliptic.Curve interface
var (
	_ elliptic.Curve = (*CurveParams)(nil)
	_ elliptic.Curve = (*BinaryCurveParams)(nil)
)

// CurveParams adds an OID to a curve and keeps its timing properties.
type CurveParams struct {
	elliptic.Curve
	OidVal asn1.ObjectIdentifier
}

// BinaryCurveParams describes a curve over an irreducible binary field of degree
// 2 through 571. Treat the parameters as read-only during curve operations.
type BinaryCurveParams struct {
	Name    string
	BitSize int
	F       *big.Int // field
	A, B    *big.Int // params
	Gx, Gy  *big.Int // generator
	N       *big.Int // order
	H       int      // cofactor
	OidVal  asn1.ObjectIdentifier
}

func (c *CurveParams) Oid() asn1.ObjectIdentifier {
	return c.OidVal
}

func (b *BinaryCurveParams) Oid() asn1.ObjectIdentifier {
	return b.OidVal
}

func (b *BinaryCurveParams) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       b.F,
		N:       b.N,
		B:       b.B,
		Gx:      b.Gx,
		Gy:      b.Gy,
		BitSize: b.BitSize,
		Name:    b.Name,
	}
}

func (b *BinaryCurveParams) BinaryParams() *BinaryCurveParams {
	return b
}

func (b *BinaryCurveParams) backend() *ctcurve.Curve {
	return ctcurve.New(b.Params(), b.A, true)
}

func (b *BinaryCurveParams) IsOnCurve(x, y *big.Int) bool {
	return b.backend().IsOnCurve(x, y)
}

func (b *BinaryCurveParams) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	return b.backend().Add(x1, y1, x2, y2)
}

func (b *BinaryCurveParams) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return b.backend().Double(x1, y1)
}

// ScalarMult returns kP. Use a fixed-length k and public input coordinates;
// conversion of the result to big.Int is variable time.
func (b *BinaryCurveParams) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	return b.backend().ScalarMult(x1, y1, k)
}

func (b *BinaryCurveParams) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return b.backend().ScalarBaseMult(k)
}
