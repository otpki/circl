// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ctfield

import (
	"math/big"
	"testing"
)

func TestPrimeArithmetic(t *testing.T) {
	f, err := New([]byte{17}, false)
	if err != nil {
		t.Fatal(err)
	}
	for x := byte(0); x < 17; x++ {
		a, err := f.SetBytes([]byte{x})
		if err != nil {
			t.Fatal(err)
		}
		for y := byte(0); y < 17; y++ {
			b, err := f.SetBytes([]byte{y})
			if err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				got  Element
				want byte
			}{
				{f.Add(a, b), (x + y) % 17},
				{f.Sub(a, b), (x + 17 - y) % 17},
				{f.Mul(a, b), byte(uint16(x) * uint16(y) % 17)},
			}
			for _, tc := range cases {
				got := f.Bytes(tc.got)
				if len(got) != 1 || got[0] != tc.want {
					t.Fatalf("x=%d y=%d: got %x want %x", x, y, got, tc.want)
				}
			}
		}
		if x != 0 && f.Equal(f.Mul(a, f.Inv(a)), Element{1}) != 1 {
			t.Fatalf("inverse of %d", x)
		}
	}
}

// polynomialProduct uses big.Int as an independent test reference.
func polynomialProduct(x, y, p *big.Int) *big.Int {
	z := new(big.Int)
	for i := 0; i < y.BitLen(); i++ {
		if y.Bit(i) != 0 {
			z.Xor(z, new(big.Int).Lsh(x, uint(i)))
		}
	}
	for z.BitLen() >= p.BitLen() {
		z.Xor(z, new(big.Int).Lsh(p, uint(z.BitLen()-p.BitLen())))
	}
	return z
}

func TestBinaryArithmetic(t *testing.T) {
	p := big.NewInt(0x13) // x^4+x+1, irreducible over GF(2).
	f, err := New(p.Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	for x := int64(0); x < 16; x++ {
		a, err := f.SetBytes([]byte{byte(x)})
		if err != nil {
			t.Fatal(err)
		}
		for y := int64(0); y < 16; y++ {
			b, err := f.SetBytes([]byte{byte(y)})
			if err != nil {
				t.Fatal(err)
			}
			want := polynomialProduct(big.NewInt(x), big.NewInt(y), p)
			if got := new(big.Int).SetBytes(f.Bytes(f.Mul(a, b))); got.Cmp(want) != 0 {
				t.Fatalf("%d*%d: got %x want %x", x, y, got, want)
			}
			if got := f.Bytes(f.Add(a, b))[0]; got != byte(x^y) {
				t.Fatalf("%d+%d", x, y)
			}
			if f.Equal(f.Add(a, b), f.Sub(a, b)) != 1 {
				t.Fatal("binary subtraction")
			}
		}
		if x != 0 && f.Equal(f.Mul(a, f.Inv(a)), Element{1}) != 1 {
			t.Fatalf("inverse of %d", x)
		}
	}
}

func TestEncodingAndSelection(t *testing.T) {
	for _, binary := range []bool{false, true} {
		f, err := New([]byte{17}, binary)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range [][]byte{nil, {0, 1}, {17}, {255}} {
			if _, err := f.SetBytes(b); err == nil {
				t.Fatalf("accepted %x (binary=%v)", b, binary)
			}
		}
		x, y := Element{3}, Element{9}
		if f.Equal(f.Select(x, y, 0), x) != 1 || f.Equal(f.Select(x, y, 1), y) != 1 || f.Equal(x, y) != 0 {
			t.Fatal("selection")
		}
		if f.Equal(f.Inv(Element{}), Element{}) != 1 {
			t.Fatal("inverse zero must be zero")
		}
	}
	for _, p := range [][]byte{nil, {0}, {1}, {2}, make([]byte, 73)} {
		if _, err := New(p, false); err == nil {
			t.Fatalf("accepted modulus %x", p)
		}
	}
}

func polynomialInverse(x, p *big.Int) *big.Int {
	u, v := new(big.Int).Set(x), new(big.Int).Set(p)
	a, b := big.NewInt(1), new(big.Int)
	for u.Cmp(big.NewInt(1)) != 0 {
		if u.Sign() == 0 {
			return nil
		}
		shift := u.BitLen() - v.BitLen()
		if shift < 0 {
			u, v = v, u
			a, b = b, a
			shift = -shift
		}
		u.Xor(u, new(big.Int).Lsh(v, uint(shift)))
		a.Xor(a, new(big.Int).Lsh(b, uint(shift)))
	}
	return polynomialProduct(a, big.NewInt(1), p)
}

func TestLargeFieldReferences(t *testing.T) {
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(1))
	polynomial := new(big.Int)
	for _, bit := range []int{571, 10, 5, 2, 0} {
		polynomial.SetBit(polynomial, bit, 1)
	}
	for _, tc := range []struct {
		name    string
		modulus *big.Int
		binary  bool
	}{
		{"P521", prime, false},
		{"B571", polynomial, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := New(tc.modulus.Bytes(), tc.binary)
			if err != nil {
				t.Fatal(err)
			}
			bound := new(big.Int).Set(tc.modulus)
			if tc.binary {
				bound.Lsh(big.NewInt(1), 571)
			}
			values := []*big.Int{new(big.Int), big.NewInt(1), new(big.Int).Sub(bound, big.NewInt(1)), new(big.Int).Rsh(bound, 1)}
			for i := int64(0); i < 8; i++ {
				// Exercise high limbs as well as low ones.
				v := new(big.Int).Exp(big.NewInt(0x123456789abcdef+i), big.NewInt(13+i), bound)
				values = append(values, v)
			}
			for i, x := range values {
				y := values[len(values)-1-i]
				a, err := f.SetBytes(x.FillBytes(make([]byte, f.size)))
				if err != nil {
					t.Fatal(err)
				}
				b, err := f.SetBytes(y.FillBytes(make([]byte, f.size)))
				if err != nil {
					t.Fatal(err)
				}
				if got := new(big.Int).SetBytes(f.Bytes(a)); got.Cmp(x) != 0 {
					t.Fatal("encoding round trip")
				}
				add, sub, mul := new(big.Int), new(big.Int), new(big.Int)
				var inverse *big.Int
				if tc.binary {
					add.Xor(x, y)
					sub.Set(add)
					mul = polynomialProduct(x, y, tc.modulus)
					inverse = polynomialInverse(x, tc.modulus)
				} else {
					add.Add(x, y).Mod(add, tc.modulus)
					sub.Sub(x, y).Mod(sub, tc.modulus)
					mul.Mul(x, y).Mod(mul, tc.modulus)
					inverse = new(big.Int).ModInverse(x, tc.modulus)
				}
				square := new(big.Int).Mul(x, x)
				if tc.binary {
					square = polynomialProduct(x, x, tc.modulus)
				} else {
					square.Mod(square, tc.modulus)
				}
				checks := []struct {
					name string
					got  Element
					want *big.Int
				}{
					{"add", f.Add(a, b), add}, {"sub", f.Sub(a, b), sub}, {"mul", f.Mul(a, b), mul}, {"square", f.Square(a), square},
				}
				if inverse != nil {
					checks = append(checks, struct {
						name string
						got  Element
						want *big.Int
					}{"inv", f.Inv(a), inverse})
				}
				for _, check := range checks {
					got := elementBig(check.got)
					if got.Cmp(check.want) != 0 {
						t.Fatalf("case %d %s: got %x want %x", i, check.name, got, check.want)
					}
				}
			}
		})
	}
}

func TestFieldWidths(t *testing.T) {
	for _, width := range []uint{2, 7, 8, 9, 63, 64, 65, 127, 128, 129, 511, 512, 513, 570, 571} {
		for _, binary := range []bool{false, true} {
			// Encoding and addition also work with composite moduli.
			modulus := new(big.Int).Lsh(big.NewInt(1), width)
			if binary {
				modulus.Add(modulus, big.NewInt(3))
			} else {
				modulus.Sub(modulus, big.NewInt(1))
			}
			f, err := New(modulus.Bytes(), binary)
			if err != nil {
				t.Fatal(err)
			}
			max := new(big.Int).Sub(modulus, big.NewInt(1))
			if binary {
				max.Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
			}
			encoded := max.FillBytes(make([]byte, f.size))
			x, err := f.SetBytes(encoded)
			if err != nil {
				t.Fatal(err)
			}
			sum := new(big.Int).SetBytes(f.Bytes(f.Add(x, x)))
			if binary {
				if sum.Sign() != 0 {
					t.Fatal("binary doubling")
				}
			} else {
				want := new(big.Int).Lsh(max, 1)
				want.Mod(want, modulus)
				if sum.Cmp(want) != 0 {
					t.Fatalf("width %d modular addition", width)
				}
			}
			if _, err := f.SetBytes(append([]byte{0}, encoded...)); err == nil {
				t.Fatal("accepted wrong width")
			}
		}
	}
}

func elementBig(x Element) *big.Int {
	z := new(big.Int)
	for i := len(x) - 1; i >= 0; i-- {
		z.Lsh(z, 64)
		z.Or(z, new(big.Int).SetUint64(x[i]))
	}
	return z
}

func TestEveryLimb(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(1))
	f, err := New(p.Bytes(), false)
	if err != nil {
		t.Fatal(err)
	}
	for i := range (Element{}) {
		x := Element{}
		x[i] = 1
		if f.Equal(x, Element{}) != 0 || f.Equal(x, x) != 1 {
			t.Fatalf("equality in limb %d", i)
		}
		if f.Select(x, Element{}, 0) != x || f.Select(Element{}, x, 1) != x {
			t.Fatalf("selection in limb %d", i)
		}
	}
}

func FuzzPrimeMultiplication(f *testing.F) {
	f.Add([]byte{1}, []byte{2})
	f.Add([]byte{255, 255}, []byte{0, 1})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a) > 16 || len(b) > 16 {
			t.Skip()
		}
		p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
		field, err := New(p.Bytes(), false)
		if err != nil {
			t.Fatal(err)
		}
		x, y := new(big.Int).SetBytes(a), new(big.Int).SetBytes(b)
		x.Mod(x, p)
		y.Mod(y, p)
		xx, err := field.SetBytes(x.FillBytes(make([]byte, 16)))
		if err != nil {
			t.Fatal(err)
		}
		yy, err := field.SetBytes(y.FillBytes(make([]byte, 16)))
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Mul(x, y)
		want.Mod(want, p)
		if got := elementBig(field.Mul(xx, yy)); got.Cmp(want) != 0 {
			t.Fatalf("got %x want %x", got, want)
		}
	})
}

func FuzzBinaryMultiplication(f *testing.F) {
	f.Add([]byte{1}, []byte{2})
	f.Add([]byte{255, 255}, []byte{9, 7})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a) > 72 || len(b) > 72 {
			t.Skip()
		}
		p := new(big.Int)
		for _, bit := range []int{571, 10, 5, 2, 0} {
			p.SetBit(p, bit, 1)
		}
		field, err := New(p.Bytes(), true)
		if err != nil {
			t.Fatal(err)
		}
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 571), big.NewInt(1))
		x, y := new(big.Int).SetBytes(a), new(big.Int).SetBytes(b)
		x.And(x, mask)
		y.And(y, mask)
		xx, err := field.SetBytes(x.FillBytes(make([]byte, 72)))
		if err != nil {
			t.Fatal(err)
		}
		yy, err := field.SetBytes(y.FillBytes(make([]byte, 72)))
		if err != nil {
			t.Fatal(err)
		}
		want := polynomialProduct(x, y, p)
		if got := elementBig(field.Mul(xx, yy)); got.Cmp(want) != 0 {
			t.Fatalf("got %x want %x", got, want)
		}
	})
}

func TestWordProductsAndSquares(t *testing.T) {
	for _, width := range []uint{3, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 570, 571} {
		p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
		field, err := New(p.Bytes(), false)
		if err != nil {
			t.Fatal(err)
		}
		values := []*big.Int{new(big.Int), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(p, big.NewInt(2)), new(big.Int).Rsh(p, 1)}
		for _, x := range values {
			for _, y := range values {
				a, err := field.SetBytes(x.FillBytes(make([]byte, field.size)))
				if err != nil {
					t.Fatal(err)
				}
				b, err := field.SetBytes(y.FillBytes(make([]byte, field.size)))
				if err != nil {
					t.Fatal(err)
				}
				want := new(big.Int).Mul(x, y)
				want.Mod(want, p)
				if got := elementBig(field.Mul(a, b)); got.Cmp(want) != 0 {
					t.Fatalf("width=%d x=%x y=%x got %x want %x", width, x, y, got, want)
				}
				square := new(big.Int).Mul(x, x)
				square.Mod(square, p)
				if got := elementBig(field.Square(a)); got.Cmp(square) != 0 {
					t.Fatalf("square width %d", width)
				}
			}
		}
	}
}

func TestReduction(t *testing.T) {
	for _, binary := range []bool{false, true} {
		modulus := big.NewInt(17)
		if binary {
			modulus = big.NewInt(0x13)
		}
		field, err := New(modulus.Bytes(), binary)
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range [][]byte{nil, {0}, {17}, {255}, {1, 0}, {255, 255, 255}} {
			want := new(big.Int).SetBytes(input)
			if binary {
				want = polynomialProduct(want, big.NewInt(1), modulus)
			} else {
				want.Mod(want, modulus)
			}
			if got := elementBig(field.Reduce(input)); got.Cmp(want) != 0 {
				t.Fatalf("reduce %x: got %x want %x", input, got, want)
			}
		}
	}
}

func TestBinaryWordBoundaries(t *testing.T) {
	for _, width := range []uint{63, 64, 65, 127, 128, 129, 163, 176, 571} {
		for _, second := range []uint{1, width / 2, width - 1} {
			modulus := new(big.Int).Lsh(big.NewInt(1), width)
			modulus.SetBit(modulus, int(second), 1).SetBit(modulus, 0, 1)
			f, err := New(modulus.Bytes(), true)
			if err != nil {
				t.Fatal(err)
			}
			bound := new(big.Int).Lsh(big.NewInt(1), width)
			values := []*big.Int{new(big.Int), big.NewInt(1), new(big.Int).Sub(bound, big.NewInt(1)), new(big.Int).Rsh(bound, 1)}
			for _, x := range values {
				for _, y := range values {
					a, err := f.SetBytes(x.FillBytes(make([]byte, f.size)))
					if err != nil {
						t.Fatal(err)
					}
					b, err := f.SetBytes(y.FillBytes(make([]byte, f.size)))
					if err != nil {
						t.Fatal(err)
					}
					if got, want := elementBig(f.Mul(a, b)), polynomialProduct(x, y, modulus); got.Cmp(want) != 0 {
						t.Fatalf("width %d: product got %x want %x", width, got, want)
					}
					if got, want := elementBig(f.Square(a)), polynomialProduct(x, x, modulus); got.Cmp(want) != 0 {
						t.Fatalf("width %d: square got %x want %x", width, got, want)
					}
					wide := new(big.Int).Lsh(x, width+65)
					wide.Or(wide, y)
					if got, want := elementBig(f.Reduce(wide.Bytes())), polynomialProduct(wide, big.NewInt(1), modulus); got.Cmp(want) != 0 {
						t.Fatalf("width %d: reduction got %x want %x", width, got, want)
					}
				}
			}
		}
	}
}
