// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ctcurve

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestPrimePoints(t *testing.T) {
	params := &elliptic.CurveParams{P: big.NewInt(17), N: big.NewInt(19), B: big.NewInt(2), Gx: big.NewInt(5), Gy: big.NewInt(1), BitSize: 5, Name: "test"}
	c := New(params, big.NewInt(2), false)
	points := [][2]int64{{0, 0}}
	for x := int64(0); x < 17; x++ {
		for y := int64(0); y < 17; y++ {
			if (y*y-x*x*x-2*x-2)%17 == 0 {
				points = append(points, [2]int64{x, y})
			}
		}
	}
	for _, p := range points {
		x, y := big.NewInt(p[0]), big.NewInt(p[1])
		for _, q := range points {
			u, v := big.NewInt(q[0]), big.NewInt(q[1])
			gotX, gotY := c.Add(x, y, u, v)
			wantX, wantY := primeAdd(x, y, u, v, params.P, big.NewInt(2))
			if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
				t.Fatalf("%v+%v got (%v,%v) want (%v,%v)", p, q, gotX, gotY, wantX, wantY)
			}
		}
		wantX, wantY := new(big.Int), new(big.Int)
		for k := 0; k < 40; k++ {
			gotX, gotY := c.ScalarMult(x, y, []byte{0, byte(k)})
			if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
				t.Fatalf("%d*%v got (%v,%v) want (%v,%v)", k, p, gotX, gotY, wantX, wantY)
			}
			wantX, wantY = primeAdd(wantX, wantY, x, y, params.P, big.NewInt(2))
		}
	}
	for _, p := range [][2]int64{{-1, 1}, {17, 1}, {1, 1}, {0, 0}} {
		if c.IsOnCurve(big.NewInt(p[0]), big.NewInt(p[1])) {
			t.Fatalf("accepted %v", p)
		}
	}
}

// primeAdd uses affine big.Int arithmetic as an independent test reference.
func primeAdd(x, y, u, v, p, a *big.Int) (*big.Int, *big.Int) {
	if x.Sign() == 0 && y.Sign() == 0 {
		return new(big.Int).Set(u), new(big.Int).Set(v)
	}
	if u.Sign() == 0 && v.Sign() == 0 {
		return new(big.Int).Set(x), new(big.Int).Set(y)
	}
	numerator, denominator := new(big.Int), new(big.Int)
	if x.Cmp(u) == 0 {
		if y.Cmp(v) != 0 || y.Sign() == 0 {
			return new(big.Int), new(big.Int)
		}
		numerator.Mul(x, x).Mul(numerator, big.NewInt(3)).Add(numerator, a)
		denominator.Lsh(y, 1)
	} else {
		numerator.Sub(v, y)
		denominator.Sub(u, x)
	}
	slope := new(big.Int).ModInverse(denominator, p)
	slope.Mul(slope, numerator).Mod(slope, p)
	rx := new(big.Int).Mul(slope, slope)
	rx.Sub(rx, x).Sub(rx, u).Mod(rx, p)
	ry := new(big.Int).Sub(x, rx)
	ry.Mul(ry, slope).Sub(ry, y).Mod(ry, p)
	return rx, ry
}

func polynomialMul(x, y int64) int64 {
	var z int64
	for y != 0 {
		if y&1 != 0 {
			z ^= x
		}
		y >>= 1
		x <<= 1
	}
	for i := 7; i >= 4; i-- {
		if z&(1<<uint(i)) != 0 {
			z ^= 0x13 << uint(i-4)
		}
	}
	return z
}

func polynomialInv(x int64) int64 {
	for y := int64(1); y < 16; y++ {
		if polynomialMul(x, y) == 1 {
			return y
		}
	}
	panic("no inverse")
}

func binaryAdd(p, q [2]int64) [2]int64 {
	if p == [2]int64{} {
		return q
	}
	if q == [2]int64{} {
		return p
	}
	x, y, u, v := p[0], p[1], q[0], q[1]
	var slope int64
	if x == u {
		if y != v || x == 0 {
			return [2]int64{}
		}
		slope = x ^ polynomialMul(y, polynomialInv(x))
	} else {
		slope = polynomialMul(y^v, polynomialInv(x^u))
	}
	rx := polynomialMul(slope, slope) ^ slope ^ x ^ u ^ 1
	ry := polynomialMul(slope, x^rx) ^ rx ^ y
	return [2]int64{rx, ry}
}

func TestBinaryPoints(t *testing.T) {
	params := &elliptic.CurveParams{P: big.NewInt(0x13), N: big.NewInt(16), B: big.NewInt(1), Gx: big.NewInt(1), Gy: big.NewInt(6), BitSize: 4, Name: "binary test"}
	c := New(params, big.NewInt(1), true)
	points := [][2]int64{{0, 0}}
	for x := int64(0); x < 16; x++ {
		for y := int64(0); y < 16; y++ {
			xx := polynomialMul(x, x)
			if polynomialMul(y, y)^polynomialMul(x, y) == polynomialMul(xx, x)^xx^1 {
				points = append(points, [2]int64{x, y})
			}
		}
	}
	for _, p := range points {
		x, y := big.NewInt(p[0]), big.NewInt(p[1])
		for _, q := range points {
			gx, gy := c.Add(x, y, big.NewInt(q[0]), big.NewInt(q[1]))
			want := binaryAdd(p, q)
			if gx.Int64() != want[0] || gy.Int64() != want[1] {
				t.Fatalf("%v+%v got (%v,%v) want %v", p, q, gx, gy, want)
			}
		}
		want := [2]int64{}
		for k := 0; k < 24; k++ {
			gx, gy := c.ScalarMult(x, y, []byte{0, byte(k)})
			if gx.Int64() != want[0] || gy.Int64() != want[1] {
				t.Fatalf("%d*%v got (%v,%v) want %v", k, p, gx, gy, want)
			}
			want = binaryAdd(want, p)
		}
	}
}

func TestInvalidPointBoundaries(t *testing.T) {
	params := &elliptic.CurveParams{P: big.NewInt(17), N: big.NewInt(19), B: big.NewInt(2), Gx: big.NewInt(5), Gy: big.NewInt(1), BitSize: 5}
	c := New(params, big.NewInt(2), false)
	for _, bad := range [][2]*big.Int{{nil, big.NewInt(1)}, {big.NewInt(-1), big.NewInt(1)}, {big.NewInt(17), big.NewInt(1)}, {big.NewInt(1), big.NewInt(1)}} {
		if c.IsOnCurve(bad[0], bad[1]) {
			t.Fatal("invalid point accepted")
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid scalar-multiplication input did not panic")
				}
			}()
			c.ScalarMult(bad[0], bad[1], []byte{1})
		}()
	}
}

func TestPrimeOrderTwo(t *testing.T) {
	params := &elliptic.CurveParams{P: big.NewInt(17), N: big.NewInt(2), B: big.NewInt(1), Gx: big.NewInt(16), Gy: new(big.Int), BitSize: 5}
	c := New(params, new(big.Int), false)
	if !c.IsOnCurve(params.Gx, params.Gy) {
		t.Fatal("order-two point rejected")
	}
	x, y := c.Double(params.Gx, params.Gy)
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Fatal("doubling order-two point")
	}
	for _, k := range []byte{0, 1, 2, 3, 255} {
		x, y = c.ScalarBaseMult([]byte{k})
		want := int64(0)
		if k&1 != 0 {
			want = 16
		}
		if x.Int64() != want || y.Sign() != 0 {
			t.Fatalf("scalar %d: (%v,%v)", k, x, y)
		}
	}
}

func TestMultipleScalarBytes(t *testing.T) {
	params := &elliptic.CurveParams{P: big.NewInt(17), N: big.NewInt(19), B: big.NewInt(2), Gx: big.NewInt(5), Gy: big.NewInt(1), BitSize: 5}
	c := New(params, big.NewInt(2), false)
	for _, k := range [][]byte{{1, 0}, {1, 1}, {128, 1}, {0, 1, 0}, {255, 255}} {
		count := new(big.Int).SetBytes(k)
		count.Mod(count, params.N)
		wantX, wantY := new(big.Int), new(big.Int)
		for i := int64(0); i < count.Int64(); i++ {
			wantX, wantY = primeAdd(wantX, wantY, params.Gx, params.Gy, params.P, big.NewInt(2))
		}
		x, y := c.ScalarBaseMult(k)
		if x.Cmp(wantX) != 0 || y.Cmp(wantY) != 0 {
			t.Fatalf("scalar %x: got (%v,%v) want (%v,%v)", k, x, y, wantX, wantY)
		}
	}
}

func TestFixedWidthScalarOutput(t *testing.T) {
	params := &elliptic.CurveParams{P: big.NewInt(17), N: big.NewInt(19), B: big.NewInt(2), Gx: big.NewInt(5), Gy: big.NewInt(1), BitSize: 5}
	c := New(params, big.NewInt(2), false)
	x, y := c.ScalarBaseMultBytes([]byte{0, 3})
	if len(x) != 1 || len(y) != 1 || x[0] != 10 || y[0] != 6 {
		t.Fatalf("3G=(%x,%x)", x, y)
	}
	x, y = c.ScalarBaseMultBytes([]byte{0, 0})
	if len(x) != 1 || len(y) != 1 || x[0] != 0 || y[0] != 0 {
		t.Fatal("identity encoding")
	}
}
