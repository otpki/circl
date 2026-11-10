// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package ctfield implements fixed-width arithmetic for trusted public ECC fields.
package ctfield

import (
	"crypto/subtle"
	"errors"
	"math/bits"
)

// Element stores a field element in little-endian limbs. The extra headroom
// above the largest supported field prevents overflow during modular addition.
type Element [9]uint64

// Field holds read-only public parameters. Elements must be reduced and belong
// to this field. Operations return new values.
type Field struct {
	modulus  Element
	exponent Element
	bitSize  int
	size     int
	binary   bool
	words    int
	inverse  uint64
	rr       Element
	terms    []uint
}

// New accepts an odd prime of 2–571 bits or an irreducible binary polynomial of
// degree 2–571. It checks the encoding and size, not primality or irreducibility.
func New(modulus []byte, binary bool) (*Field, error) {
	if len(modulus) == 0 || len(modulus) > 72 || modulus[0] == 0 {
		return nil, errors.New("ctfield: invalid public modulus")
	}
	bitSize := 8*(len(modulus)-1) + bits.Len8(modulus[0])
	if binary {
		bitSize--
	}
	if bitSize < 2 || bitSize > 571 || modulus[len(modulus)-1]&1 == 0 {
		return nil, errors.New("ctfield: unsupported public modulus")
	}
	f := &Field{modulus: decode(modulus), bitSize: bitSize, size: (bitSize + 7) / 8, binary: binary}
	if binary {
		for i := 1; i < bitSize; i++ {
			f.exponent[i/64] |= uint64(1) << uint(i%64)
		}
	} else {
		var borrow uint64
		f.exponent[0], borrow = bits.Sub64(f.modulus[0], 2, 0)
		for i := 1; i < len(f.exponent); i++ {
			f.exponent[i], borrow = bits.Sub64(f.modulus[i], 0, borrow)
		}
	}
	f.words = (bitSize + 63) / 64
	if binary {
		for i := 0; i <= bitSize; i++ {
			if (f.modulus[i/64]>>uint(i%64))&1 != 0 {
				f.terms = append(f.terms, uint(i))
			}
		}
	} else {
		inverse := uint64(1)
		for range 6 {
			inverse *= 2 - f.modulus[0]*inverse
		}
		f.inverse = 0 - inverse
		f.rr = Element{1}
		for range 128 * f.words {
			f.rr = f.Add(f.rr, f.rr)
		}
	}
	return f, nil
}

func decode(b []byte) (x Element) {
	for i := range b {
		j := len(b) - 1 - i
		x[j/8] |= uint64(b[i]) << uint(8*(j%8))
	}
	return x
}

// SetBytes parses a fixed-width, big-endian element and rejects unreduced values.
func (f *Field) SetBytes(b []byte) (Element, error) {
	if len(b) != f.size {
		return Element{}, errors.New("ctfield: invalid element length")
	}
	x := decode(b)
	var valid uint64
	if f.binary {
		valid = 1 ^ nonzero(x[f.bitSize/64]>>uint(f.bitSize%64))
	} else {
		var borrow uint64
		for i := range x {
			_, borrow = bits.Sub64(x[i], f.modulus[i], borrow)
		}
		valid = borrow
	}
	if valid == 0 {
		return Element{}, errors.New("ctfield: noncanonical element")
	}
	return x, nil
}

// Bytes encodes a canonical element at the field's public fixed width.
func (f *Field) Bytes(x Element) []byte {
	b := make([]byte, f.size)
	for i := range b {
		j := len(b) - 1 - i
		b[i] = byte(x[j/8] >> uint(8*(j%8)))
	}
	return b
}

func nonzero(x uint64) uint64 {
	return uint64(1 - (subtle.ConstantTimeEq(int32(x), 0) & subtle.ConstantTimeEq(int32(x>>32), 0)))
}

// Equal returns one if x and y are equal and zero otherwise.
func (*Field) Equal(x, y Element) int {
	var diff uint64
	for i := range x {
		diff |= x[i] ^ y[i]
	}
	return int(1 ^ nonzero(diff))
}

// Select returns x when choice is zero and y when choice is one.
// The caller must ensure choice is either zero or one.
func (*Field) Select(x, y Element, choice int) (z Element) {
	for i := range z {
		low := uint32(subtle.ConstantTimeSelect(choice, int(uint32(y[i])), int(uint32(x[i]))))
		high := uint32(subtle.ConstantTimeSelect(choice, int(uint32(y[i]>>32)), int(uint32(x[i]>>32))))
		z[i] = uint64(low) | uint64(high)<<32
	}
	return z
}

// Add returns x+y in the field.
func (f *Field) Add(x, y Element) (z Element) {
	if f.binary {
		for i := range z {
			z[i] = x[i] ^ y[i]
		}
		return z
	}
	var carry uint64
	for i := range z {
		z[i], carry = bits.Add64(x[i], y[i], carry)
	}
	var reduced Element
	var borrow uint64
	for i := range z {
		reduced[i], borrow = bits.Sub64(z[i], f.modulus[i], borrow)
	}
	return f.Select(reduced, z, int(borrow))
}

// Sub returns x-y in the field.
func (f *Field) Sub(x, y Element) (z Element) {
	if f.binary {
		return f.Add(x, y)
	}
	var borrow uint64
	for i := range z {
		z[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}
	addend := f.Select(Element{}, f.modulus, int(borrow))
	var carry uint64
	for i := range z {
		z[i], carry = bits.Add64(z[i], addend[i], carry)
	}
	return z
}

// Mul returns x*y using a schedule determined only by the public field.
func (f *Field) Mul(x, y Element) Element {
	if f.binary {
		return f.multiplyBinary(x, y)
	}
	return f.montgomery(f.montgomery(x, y), f.rr)
}

// Square returns x*x in the field.
func (f *Field) Square(x Element) Element {
	if f.binary {
		return f.squareBinary(x)
	}
	return f.Mul(x, x)
}

// Reduce reduces a big-endian integer (or polynomial in a binary field).
// Its schedule depends on the public input length, not its contents.
func (f *Field) Reduce(input []byte) (out Element) {
	for _, b := range input {
		for bit := 7; bit >= 0; bit-- {
			value := uint64((b >> uint(bit)) & 1)
			if f.binary {
				var shifted [18]uint64
				var carry uint64
				for i := range out {
					shifted[i] = out[i]<<1 | carry
					carry = out[i] >> 63
				}
				shifted[0] ^= value
				out = f.reduceBinary(shifted, f.bitSize)
			} else {
				out = f.Add(f.Add(out, out), Element{value})
			}
		}
	}
	return out
}

// Inv returns 1/x, or zero when x is zero, using the field's fixed public exponent.
func (f *Field) Inv(x Element) Element {
	z := Element{1}
	for i := f.bitSize - 1; i >= 0; i-- {
		z = f.Square(z)
		if (f.exponent[i/64]>>uint(i%64))&1 != 0 {
			z = f.Mul(z, x)
		}
	}
	return z
}
