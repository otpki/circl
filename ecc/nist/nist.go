package nist

import "crypto/elliptic"

func P192() elliptic.Curve {
	initonce.Do(initAll)
	return p192
}

func P224() elliptic.Curve {
	initonce.Do(initAll)
	return p224
}

func P256() elliptic.Curve {
	initonce.Do(initAll)
	return p256
}

func P384() elliptic.Curve {
	initonce.Do(initAll)
	return p384
}

func P521() elliptic.Curve {
	initonce.Do(initAll)
	return p521
}

// binary parameters

func K163() elliptic.Curve {
	initonce.Do(initAll)
	return k163
}

func B163() elliptic.Curve {
	initonce.Do(initAll)
	return b163
}

func K233() elliptic.Curve {
	initonce.Do(initAll)
	return k233
}

func B233() elliptic.Curve {
	initonce.Do(initAll)
	return b233
}

func K283() elliptic.Curve {
	initonce.Do(initAll)
	return k283
}

func B283() elliptic.Curve {
	initonce.Do(initAll)
	return b283
}

func K409() elliptic.Curve {
	initonce.Do(initAll)
	return k409
}

func B409() elliptic.Curve {
	initonce.Do(initAll)
	return b409
}

func K571() elliptic.Curve {
	initonce.Do(initAll)
	return k571
}

func B571() elliptic.Curve {
	initonce.Do(initAll)
	return b571
}
