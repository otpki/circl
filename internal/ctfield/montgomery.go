// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ctfield

import "math/bits"

// montgomery returns x*y/R mod p for R=2^(64*words). All inputs are canonical.
// Always propagate carries through every limb, even when the carry is zero.
func (f *Field) montgomery(x, y Element) Element {
	var product [20]uint64
	n := f.words
	for i := 0; i < n; i++ {
		var carry uint64
		for j := 0; j < n; j++ {
			hi, lo := bits.Mul64(x[j], y[i])
			var c uint64
			lo, c = bits.Add64(lo, product[i+j], 0)
			hi += c
			lo, c = bits.Add64(lo, carry, 0)
			hi += c
			product[i+j] = lo
			carry = hi
		}
		product[i+n] = carry
	}
	for i := 0; i < n; i++ {
		multiplier := product[i] * f.inverse
		var carry uint64
		for j := 0; j < n; j++ {
			hi, lo := bits.Mul64(multiplier, f.modulus[j])
			var c uint64
			lo, c = bits.Add64(lo, product[i+j], 0)
			hi += c
			lo, c = bits.Add64(lo, carry, 0)
			hi += c
			product[i+j] = lo
			carry = hi
		}
		var c uint64
		product[i+n], c = bits.Add64(product[i+n], carry, 0)
		for j := i + n + 1; j <= 2*n; j++ {
			product[j], c = bits.Add64(product[j], 0, c)
		}
	}
	var out, reduced Element
	copy(out[:n], product[n:2*n])
	// At nine limbs p has at least five spare bits, so the extra limb is zero.
	if n < len(out) {
		out[n] = product[2*n]
	}
	var borrow uint64
	for i := range out {
		reduced[i], borrow = bits.Sub64(out[i], f.modulus[i], borrow)
	}
	return f.Select(reduced, out, int(borrow))
}
