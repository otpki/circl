// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ctcurve

// Binary points use homogeneous coordinates x=X/Z, y=Y/Z on y²+xy=x³+ax²+b.
// Addition computes both cases and selects the result without branching.
func (c *Curve) addBinary(p, q point) point {
	f := c.field
	z12 := f.Mul(p.z, q.z)
	u := f.Add(f.Mul(p.y, q.z), f.Mul(q.y, p.z))
	v := f.Add(f.Mul(p.x, q.z), f.Mul(q.x, p.z))
	vv := f.Square(v)
	d := f.Mul(vv, z12)
	nx := f.Add(f.Mul(f.Square(u), z12), f.Mul(f.Mul(u, v), z12))
	nx = f.Add(nx, f.Mul(vv, v))
	nx = f.Add(nx, f.Mul(c.a, d))
	vz1 := f.Mul(v, p.z)
	x := f.Mul(nx, vz1)
	y := f.Mul(u, f.Add(f.Mul(p.x, d), f.Mul(nx, p.z)))
	y = f.Add(y, f.Mul(nx, vz1))
	y = f.Add(y, f.Mul(p.y, f.Mul(v, d)))
	z := f.Mul(d, vz1)
	same := f.Equal(v, element{}) & f.Equal(u, element{})
	return c.selectPoint(point{x, y, z}, c.doubleBinary(p), same)
}

func (c *Curve) doubleBinary(p point) point {
	f := c.field
	xx, zz := f.Square(p.x), f.Square(p.z)
	u := f.Add(xx, f.Mul(p.y, p.z))
	v := f.Mul(p.x, p.z)
	d := f.Square(v)
	nx := f.Add(f.Add(f.Square(u), f.Mul(u, v)), f.Mul(c.a, d))
	vz2 := f.Mul(v, zz)
	x := f.Mul(nx, vz2)
	y := f.Add(f.Mul(xx, f.Mul(v, d)), f.Mul(f.Mul(f.Add(u, v), nx), zz))
	z := f.Mul(d, vz2)
	return point{x, y, z}
}
