package brainpool

import (
	"github.com/otpki/circl/ecc"
)

// https://github.com/ebfe/brainpool/blob/master/curves.go
// https://github.com/keybase/go-crypto/blob/master/brainpool/brainpool.go

func P160t1() ecc.Curve {
	initonce.Do(initAll)
	return p160t1
}

func P192t1() ecc.Curve {
	initonce.Do(initAll)
	return p192t1
}

func P224t1() ecc.Curve {
	initonce.Do(initAll)
	return p224t1
}

func P256t1() ecc.Curve {
	initonce.Do(initAll)
	return p256t1
}

func P320t1() ecc.Curve {
	initonce.Do(initAll)
	return p320t1
}

func P384t1() ecc.Curve {
	initonce.Do(initAll)
	return p384t1
}

func P512t1() ecc.Curve {
	initonce.Do(initAll)
	return p512t1
}

// rcurves

func P160r1() ecc.Curve {
	initonce.Do(initAll)
	return p160r1
}

func P192r1() ecc.Curve {
	initonce.Do(initAll)
	return p192r1
}

func P224r1() ecc.Curve {
	initonce.Do(initAll)
	return p224r1
}

func P256r1() ecc.Curve {
	initonce.Do(initAll)
	return p256r1
}

func P320r1() ecc.Curve {
	initonce.Do(initAll)
	return p320r1
}

func P384r1() ecc.Curve {
	initonce.Do(initAll)
	return p384r1
}

func P512r1() ecc.Curve {
	initonce.Do(initAll)
	return p512r1
}
