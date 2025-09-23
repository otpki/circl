package x962

import (
	"github.com/cloudflare/circl/ecc"
)

func Prime192v1() ecc.Curve {
	initonce.Do(initAll)
	return prime192v1
}

func Prime192v2() ecc.Curve {
	initonce.Do(initAll)
	return prime192v2
}

func Prime192v3() ecc.Curve {
	initonce.Do(initAll)
	return prime192v3
}

func Prime239v1() ecc.Curve {
	initonce.Do(initAll)
	return prime239v1
}

func Prime239v2() ecc.Curve {
	initonce.Do(initAll)
	return prime239v2
}

func Prime239v3() ecc.Curve {
	initonce.Do(initAll)
	return prime239v3
}

func Prime256v1() ecc.Curve {
	initonce.Do(initAll)
	return prime256v1
}

// binary fields

func C2pnb176w1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb176w1
}

func C2pnb163v1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb163v1
}

func C2pnb163v2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb163v2
}

func C2pnb163v3() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb163v3
}

func C2pnb208w1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb208w1
}

func C2tnb191v3() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb191v3
}

func C2tnb191v2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb191v2
}

func C2tnb191v1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb191v1
}

func C2tnb239v3() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb239v3
}

func C2tnb239v2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb239v2
}

func C2tnb239v1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb239v1
}

func C2pnb272w1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb272w1
}

func C2pnb304w1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb304w1
}

func C2pnb368w1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2pnb368w1
}

func C2tnb359v1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb359v1
}

func C2tnb431r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return c2tnb431r1
}

//func C2onb191v4() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb191v4
//}
//
//func C2onb191v5() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb191v5
//}
//
//func C2onb239v4() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb239v4
//}
//
//func C2onb239v5() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb239v5
//}
