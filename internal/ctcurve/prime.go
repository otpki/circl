// Copyright (c) 2026 OmniTrust Security LLC.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ctcurve

// Prime points use Jacobian coordinates x=X/Z², y=Y/Z³, including low-order points.
// Addition computes both cases and selects the result without branching.
func (c *Curve) addPrime(p, q point) point {
	f := c.field
	z1z1, z2z2 := f.Square(p.z), f.Square(q.z)
	u1, u2 := f.Mul(p.x, z2z2), f.Mul(q.x, z1z1)
	s1, s2 := f.Mul(p.y, f.Mul(q.z, z2z2)), f.Mul(q.y, f.Mul(p.z, z1z1))
	h, r := f.Sub(u2, u1), f.Sub(s2, s1)
	hh := f.Square(h)
	hhh := f.Mul(h, hh)
	v := f.Mul(u1, hh)
	x := f.Sub(f.Sub(f.Square(r), hhh), f.Add(v, v))
	y := f.Sub(f.Mul(r, f.Sub(v, x)), f.Mul(s1, hhh))
	z := f.Mul(h, f.Mul(p.z, q.z))
	same := f.Equal(h, element{}) & f.Equal(r, element{})
	return c.selectPoint(point{x, y, z}, c.doublePrime(p), same)
}

func (c *Curve) doublePrime(p point) point {
	f := c.field
	xx, yy, zz := f.Square(p.x), f.Square(p.y), f.Square(p.z)
	yyyy := f.Square(yy)
	s := f.Sub(f.Sub(f.Square(f.Add(p.x, yy)), xx), yyyy)
	s = f.Add(s, s)
	m := f.Add(f.Add(xx, xx), xx)
	m = f.Add(m, f.Mul(c.a, f.Square(zz)))
	x := f.Sub(f.Square(m), f.Add(s, s))
	eight := f.Add(yyyy, yyyy)
	eight = f.Add(eight, eight)
	eight = f.Add(eight, eight)
	y := f.Sub(f.Mul(m, f.Sub(s, x)), eight)
	z := f.Sub(f.Sub(f.Square(f.Add(p.y, p.z)), yy), zz)
	return point{x, y, z}
}
