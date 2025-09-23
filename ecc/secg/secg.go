package secg

import "crypto/elliptic"

func Secp192r1() elliptic.Curve {
	initonce.Do(initAll)
	return secp192r1
}

func Secp224r1() elliptic.Curve {
	initonce.Do(initAll)
	return secp224r1
}

func Secp256r1() elliptic.Curve {
	initonce.Do(initAll)
	return secp256r1
}

func Secp384r1() elliptic.Curve {
	initonce.Do(initAll)
	return secp384r1
}

func Secp521r1() elliptic.Curve {
	initonce.Do(initAll)
	return secp521r1
}

// binary parameters

func Sect113r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect113r1
}

func Sect113r2() elliptic.Curve {
	initonce.Do(initAll)
	return sect113r2
}

func Sect131r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect131r1
}

func Sect131r2() elliptic.Curve {
	initonce.Do(initAll)
	return sect131r2
}

func Sect163k1() elliptic.Curve {
	initonce.Do(initAll)
	return sect163k1
}

func Sect163r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect163r1
}

func Sect163r2() elliptic.Curve {
	initonce.Do(initAll)
	return sect163r2
}

func Sect193r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect193r1
}

func Sect193r2() elliptic.Curve {
	initonce.Do(initAll)
	return sect193r2
}

func Sect233k1() elliptic.Curve {
	initonce.Do(initAll)
	return sect233k1
}

func Sect233r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect233r1
}

func Sect239k1() elliptic.Curve {
	initonce.Do(initAll)
	return sect239k1
}

func Sect283k1() elliptic.Curve {
	initonce.Do(initAll)
	return sect283k1
}

func Sect283r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect283r1
}

func Sect409k1() elliptic.Curve {
	initonce.Do(initAll)
	return sect409k1
}

func Sect409r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect409r1
}

func Sect571k1() elliptic.Curve {
	initonce.Do(initAll)
	return sect571k1
}

func Sect571r1() elliptic.Curve {
	initonce.Do(initAll)
	return sect571r1
}
