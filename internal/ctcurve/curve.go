// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package ctcurve implements fixed-width elliptic.Curve arithmetic.
// Parameters, affine inputs, and scalar lengths must be public.
// Conversion to big.Int is variable time.
package ctcurve

import (
	"crypto/elliptic"
	"crypto/subtle"
	"math/big"

	"github.com/cloudflare/circl/internal/ctfield"
)

type element = ctfield.Element

type point struct{ x, y, z element }

// Curve implements elliptic.Curve over trusted built-in prime or binary fields.
// Treat its parameters as read-only.
type Curve struct {
	params *elliptic.CurveParams
	field  *ctfield.Field
	a, b   element
	size   int
	binary bool
}

// New copies the field coefficients. P must be prime or an irreducible binary
// polynomial; New does not check either property.
func New(params *elliptic.CurveParams, a *big.Int, binary bool) *Curve {
	f, err := ctfield.New(params.P.Bytes(), binary)
	if err != nil {
		panic(err)
	}
	size := (params.BitSize + 7) / 8
	aa, err := f.SetBytes(a.FillBytes(make([]byte, size)))
	if err != nil {
		panic(err)
	}
	bb, err := f.SetBytes(params.B.FillBytes(make([]byte, size)))
	if err != nil {
		panic(err)
	}
	return &Curve{params: params, field: f, a: aa, b: bb, size: size, binary: binary}
}

// Params returns the curve parameters.
func (c *Curve) Params() *elliptic.CurveParams { return c.params }

func (c *Curve) affine(x, y *big.Int) (point, bool) {
	if x == nil || y == nil || x.Sign() < 0 || y.Sign() < 0 || x.BitLen() > c.params.BitSize || y.BitLen() > c.params.BitSize {
		return point{}, false
	}
	xx, err := c.field.SetBytes(x.FillBytes(make([]byte, c.size)))
	if err != nil {
		return point{}, false
	}
	yy, err := c.field.SetBytes(y.FillBytes(make([]byte, c.size)))
	if err != nil {
		return point{}, false
	}
	p := point{xx, yy, element{1}}
	identity := c.field.Equal(xx, element{}) & c.field.Equal(yy, element{})
	p = c.selectPoint(p, point{}, identity)
	return p, c.onCurve(xx, yy)|identity == 1
}

func (c *Curve) onCurve(x, y element) int {
	f := c.field
	xx := f.Square(x)
	rhs := f.Add(f.Mul(xx, x), c.b)
	lhs := f.Square(y)
	if c.binary {
		lhs = f.Add(lhs, f.Mul(x, y))
		rhs = f.Add(rhs, f.Mul(c.a, xx))
	} else {
		rhs = f.Add(rhs, f.Mul(c.a, x))
	}
	return f.Equal(lhs, rhs)
}

// IsOnCurve checks canonical public coordinates. Infinity is not on the curve.
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	p, valid := c.affine(x, y)
	return valid && c.field.Equal(p.z, element{}) == 0
}

func (c *Curve) checkedPoint(x, y *big.Int) point {
	p, valid := c.affine(x, y)
	if !valid {
		panic("crypto/elliptic: attempted operation on invalid point")
	}
	return p
}

// big.Int conversion stays outside the timing scope.
func (c *Curve) coordinates(operation func() point) (*big.Int, *big.Int) {
	bx, by := c.pointBytes(operation)
	return new(big.Int).SetBytes(bx), new(big.Int).SetBytes(by)
}

func (c *Curve) pointBytes(operation func() point) ([]byte, []byte) {
	var bx, by []byte
	subtle.WithDataIndependentTiming(func() {
		p := operation()
		f := c.field
		z := f.Inv(p.z)
		x, y := f.Mul(p.x, z), f.Mul(p.y, z)
		if !c.binary {
			x = f.Mul(x, z)
			y = f.Mul(f.Mul(y, z), z)
		}
		bx, by = f.Bytes(x), f.Bytes(y)
	})
	return bx, by
}

// Add returns P+Q, accepting (0,0) as infinity as in crypto/elliptic.
func (c *Curve) Add(x, y, u, v *big.Int) (*big.Int, *big.Int) {
	p, q := c.checkedPoint(x, y), c.checkedPoint(u, v)
	return c.coordinates(func() point { return c.add(p, q) })
}

// Double returns 2P.
func (c *Curve) Double(x, y *big.Int) (*big.Int, *big.Int) {
	p := c.checkedPoint(x, y)
	return c.coordinates(func() point { return c.double(p) })
}

// ScalarMult returns kP. Use a fixed-length k and public input coordinates;
// conversion of the result to big.Int is variable time.
func (c *Curve) ScalarMult(x, y *big.Int, k []byte) (*big.Int, *big.Int) {
	p := c.checkedPoint(x, y)
	return c.coordinates(func() point { return c.multiply(p, k) })
}

func (c *Curve) multiply(p point, k []byte) point {
	var out point
	for _, b := range k {
		for i := 7; i >= 0; i-- {
			out = c.double(out)
			sum := c.add(out, p)
			out = c.selectPoint(out, sum, int((b>>uint(i))&1))
		}
	}
	return out
}

// ScalarBaseMult returns kG, with the same timing contract as ScalarMult.
func (c *Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(c.params.Gx, c.params.Gy, k)
}

func (c *Curve) selectPoint(x, y point, choice int) point {
	f := c.field
	return point{f.Select(x.x, y.x, choice), f.Select(x.y, y.y, choice), f.Select(x.z, y.z, choice)}
}

func (c *Curve) add(p, q point) point {
	var out point
	if c.binary {
		out = c.addBinary(p, q)
	} else {
		out = c.addPrime(p, q)
	}
	out = c.selectPoint(out, q, c.field.Equal(p.z, element{}))
	return c.selectPoint(out, p, c.field.Equal(q.z, element{}))
}

func (c *Curve) double(p point) point {
	if c.binary {
		return c.doubleBinary(p)
	}
	return c.doublePrime(p)
}

// NewPrime constructs a trusted short Weierstrass curve with A=-3.
func NewPrime(params *elliptic.CurveParams) *Curve {
	return New(params, new(big.Int).Sub(params.P, big.NewInt(3)), false)
}

// ScalarBaseMultBytes returns kG as fixed-width coordinates within the timing scope.
func (c *Curve) ScalarBaseMultBytes(k []byte) ([]byte, []byte) {
	p := c.checkedPoint(c.params.Gx, c.params.Gy)
	return c.pointBytes(func() point { return c.multiply(p, k) })
}
