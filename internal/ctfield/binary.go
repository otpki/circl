// Copyright 2024 The Go Authors. All rights reserved.
// Use of the original carryless32 routine is governed by the BSD-style license
// in LICENSE. Adapted from Go's crypto/internal/fips140/aes/gcm/ghash.go.
// Modifications copyright (c) 2026 OmniTrust Security LLC, licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).

package ctfield

// carryless32 uses the Go GHASH bit-hole technique: eight coefficient products
// fit within each four-bit lane without carries crossing into the next lane.
func carryless32(x, y uint32) uint64 {
	var xm, ym [4]uint32
	var z [4]uint64
	for i := range 4 {
		xm[i] = x & (0x11111111 << i)
		ym[i] = y & (0x11111111 << i)
	}
	for i := range 4 {
		z[i] = uint64(xm[0])*uint64(ym[i]) ^ uint64(xm[1])*uint64(ym[(i+3)%4]) ^ uint64(xm[2])*uint64(ym[(i+2)%4]) ^ uint64(xm[3])*uint64(ym[(i+1)%4])
		z[i] &= 0x1111111111111111 << i
	}
	return z[0] | z[1] | z[2] | z[3]
}

func carryless64(x, y uint64) (low, high uint64) {
	a := carryless32(uint32(x), uint32(y))
	b := carryless32(uint32(x>>32), uint32(y>>32))
	middle := carryless32(uint32(x)^uint32(x>>32), uint32(y)^uint32(y>>32)) ^ a ^ b
	return a ^ (middle << 32), b ^ (middle >> 32)
}

func (f *Field) multiplyBinary(x, y Element) Element {
	var product [18]uint64
	for i := 0; i < f.words; i++ {
		for j := 0; j < f.words; j++ {
			low, high := carryless64(x[i], y[j])
			product[i+j] ^= low
			product[i+j+1] ^= high
		}
	}
	return f.reduceBinary(product, 2*f.bitSize-2)
}

func interleave(x uint32) uint64 {
	z := uint64(x)
	z = (z | z<<16) & 0x0000ffff0000ffff
	z = (z | z<<8) & 0x00ff00ff00ff00ff
	z = (z | z<<4) & 0x0f0f0f0f0f0f0f0f
	z = (z | z<<2) & 0x3333333333333333
	return (z | z<<1) & 0x5555555555555555
}

func (f *Field) squareBinary(x Element) Element {
	var product [18]uint64
	for i := 0; i < f.words; i++ {
		product[2*i] = interleave(uint32(x[i]))
		product[2*i+1] = interleave(uint32(x[i] >> 32))
	}
	return f.reduceBinary(product, 2*f.bitSize-2)
}

func (f *Field) reduceBinary(product [18]uint64, highest int) (out Element) {
	// A chunk's lower-term contributions must land below the chunk being cleared.
	step := min(64, f.bitSize-int(f.terms[len(f.terms)-2]))
	for top := highest; top >= f.bitSize; {
		count := min(step, top-f.bitSize+1)
		shift := top - f.bitSize + 1 - count
		position := f.bitSize + shift
		word, offset := position/64, uint(position%64)
		chunk := product[word] >> offset
		if int(offset)+count > 64 {
			chunk |= product[word+1] << (64 - offset)
		}
		chunk &= ^uint64(0) >> uint(64-count)
		for _, term := range f.terms {
			position := uint(shift) + term
			word, offset := position/64, position%64
			product[word] ^= chunk << offset
			if int(offset)+count > 64 {
				product[word+1] ^= chunk >> (64 - offset)
			}
		}
		top -= count
	}
	copy(out[:f.words], product[:f.words])
	return out
}
