// Copyright (c) 2026 OmniTrust Security LLC.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package curves_test

import (
	"math/big"
	"testing"

	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/curves"
)

func TestGroupOrderBoundaries(t *testing.T) {
	seen := make(map[string]bool)
	for _, c := range curves.All() {
		oid := c.Oid().String()
		if seen[oid] {
			continue
		}
		seen[oid] = true
		t.Run(c.Params().Name, func(t *testing.T) {
			p := c.Params()
			x, y := c.ScalarBaseMult(p.N.Bytes())
			if x.Sign() != 0 || y.Sign() != 0 {
				t.Fatal("N*G is not infinity")
			}
			n1 := new(big.Int).Add(p.N, big.NewInt(1))
			x, y = c.ScalarBaseMult(n1.Bytes())
			if x.Cmp(p.Gx) != 0 || y.Cmp(p.Gy) != 0 {
				t.Fatal("(N+1)*G is not G")
			}
		})
	}
}

func TestGroupEdges(t *testing.T) {
	zero := new(big.Int)
	for _, c := range curves.All() {
		t.Run(c.Params().Name, func(t *testing.T) {
			p := c.Params()
			x, y := c.Add(zero, zero, p.Gx, p.Gy)
			if x.Cmp(p.Gx) != 0 || y.Cmp(p.Gy) != 0 {
				t.Fatal("infinity+G")
			}
			x, y = c.Double(zero, zero)
			if x.Sign() != 0 || y.Sign() != 0 {
				t.Fatal("double infinity")
			}
			inverseY := new(big.Int)
			if _, binary := c.(ecc.BinaryCurve); binary {
				inverseY.Xor(p.Gx, p.Gy)
			} else {
				inverseY.Sub(p.P, p.Gy).Mod(inverseY, p.P)
			}
			x, y = c.Add(p.Gx, p.Gy, p.Gx, inverseY)
			if x.Sign() != 0 || y.Sign() != 0 {
				t.Fatal("G+(-G)")
			}
			x, y = c.ScalarBaseMult(nil)
			if x.Sign() != 0 || y.Sign() != 0 {
				t.Fatal("zero scalar")
			}
		})
	}
}
