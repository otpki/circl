package main_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/brainpool"
	"github.com/cloudflare/circl/ecc/nist"
)

// 3*Basepoint for each curve
var testvec3G = []struct {
	curve elliptic.Curve
	x, y  string
}{
	// -------- Brainpool --------
	{
		curve: brainpool.P160t1(),
		x:     "0xc7fb4e367ed789413fc9648ce0e921156f37642b",
		y:     "0x554bba4e002e3f5c7cef7f0bd169cc5979d8ff3d",
	},
	{
		curve: brainpool.P160r1(),
		x:     "0x8a7c28a550682cda519ce7bc73778ea9ac7812b5",
		y:     "0x868562a3f2101faf2fb5ee7a0f366dcbac9147fe",
	},
	{
		curve: brainpool.P192t1(),
		x:     "0x1092182a330dcdbbab7bd585e1611b05d197df5745273fdc",
		y:     "0x65e8622349aa118d9e46dab8eddde2bcf7765f768c05e708",
	},
	{
		curve: brainpool.P192r1(),
		x:     "0x15372d94937774620bdbff366d5677d8464866c7b0b20626",
		y:     "0x240f7e24234c9ecc309f54b7d88002eaf78341ab1d1e4919",
	},
	{
		curve: brainpool.P224t1(),
		x:     "0x347945949fc2a5a3c21d6c34f880545b85f9283ffc900fa0be1efc11",
		y:     "0x545ec6fcdf28122f82bfc658dce53035eca6267d49199a0cc00cee8e",
	},
	{
		curve: brainpool.P224r1(),
		x:     "0x9051dae686fa68103a478db398818d048c2042f01f0ecab577e4598e",
		y:     "0xbaa97f6f99cabf4a626c056b63f21f793589d36cd5981a3579782900",
	},
	{
		curve: brainpool.P256t1(),
		x:     "0x46b2a45fdd881abea0cb4e5fea19c5a72d399245643b06e0fbe24a5e4058d806",
		y:     "0x4f88cd8d4bc69acc7b7032d98460b2c23160441f40562c00bee2aa7860c19aa8",
	},
	{
		curve: brainpool.P256r1(),
		x:     "0xa8f217b77338f1d4d6624c3ab4f6cc16d2aa843d0c0fca016b91e2ad25cae39d",
		y:     "0x4b49cafc7dac26bb0aa2a6850a1b40f5fac10e4589348fb77e65cc5602b74f9d",
	},
	{
		curve: brainpool.P320t1(),
		x:     "0x847758c1c7338efab1b79a22b4446f56c87fab0070b7858e8abdbbd94d454e0c340ebb42dcf91633",
		y:     "0x3d944522b6c1b7d42038e281d4d77ac75c2e0a37e33381c3f0d845cf32d54c39406ee208f7f322c1",
	},
	{
		curve: brainpool.P320r1(),
		x:     "0xc1e31fd7f03708ce169cfd15be47890edb83acdef8aef8ba0957fc7ac717c6efbce18f0bcf5e73c9",
		y:     "0xcdb9aece49778b79f7a6ef2ffa840297f67e4d269ad8a58e8a5f27ce8c5ada7d9303a9404c589400",
	},
	{
		curve: brainpool.P384t1(),
		x:     "0x3e7e83b88ba8d99a004f1c92ee361648a922f773f96d64b2bb66d1f3c0eeac30485cfef216f68b596b8861fbc005ea9",
		y:     "0x298585e0c24722037f09dd015c2fefeec87058d76a07fe43ed52e8641b7248d2c8baba631d9d68adc2bd7e748c753c0d",
	},
	{
		curve: brainpool.P384r1(),
		x:     "0x7b63205bf00ddae73b17452b6a27ebf53df581348c6949f83ee1b6fcc7463bbe3c11ef6596a3b8897d7cc85b3035f11f",
		y:     "0x761d3a4a5f8093775521a326bc02baaf7b2eb481ead16a5c7b2bd39462363e0373c0edaea3b8f59381d7129d48772eb3",
	},
	{
		curve: brainpool.P512t1(),
		x:     "0x6ebd6e634974f138300e1d9024e1132bf53bfdcb1d0142501efcbbd2a295f70fac1b86449310ab68d8c7e6aaafa22a0a4398aedacdcfadd2cbdd03a56ee4ff0d",
		y:     "0x2fbe930ec94f50e8031161d73095549c2d39e1085dedb61db91f1c931c1a0c1022effddc3f91bde114e87f77f544ee1ac6ddb5db1f55fe8406fb7f856ff951b0",
	},
	{
		curve: brainpool.P512r1(),
		x:     "0x8dd87e12b0a4cc436cdd42543f20afe907c80ef3bc2459309c09cefd830151bc1f6fb975ceecade4780ae53e1853d62f56e34abfa9ac7205d4abf882ccb8d94",
		y:     "0x26ef5c6e1dab71d756ff0067376fa7543d903b4a6334c4bba0b382e1716d843acdab8eb772327b3febfcb69c0f37c5f8cce5bc75d8de6495cdeafba05b02c37",
	},
	// -------- NIST --------
	{
		curve: nist.P192(),
		x:     "0x76e32a2557599e6edcd283201fb2b9aadfd0d359cbb263da",
		y:     "0x782c37e372ba4520aa62e0fed121d49ef3b543660cfd05fd",
	},
	{
		curve: nist.P224(),
		x:     "0xdf1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04",
		y:     "0xa3f7f03cadd0be444c0aa56830130ddf77d317344e1af3591981a925",
	},
	{
		curve: nist.P256(),
		x:     "0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
		y:     "0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
	},
	{
		curve: nist.P384(),
		x:     "0x77a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831",
		y:     "0xc995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1",
	},
	{
		curve: nist.P521(),
		x:     "0x1a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede37ad7d",
		y:     "0x13e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588ca1ee86c0e5",
	},
	{
		curve: nist.K163(),
		x:     "0x2acfcfcc9a2af8e3f2828024f820033db20f69520",
		y:     "0x5729c47f915badc7b4c17df14e5804109ffecdfe4",
	},
	{
		curve: nist.B163(),
		x:     "0x634000577f86aa315009d6f9b906691f6edd691fe",
		y:     "0x401a3de0d6c2ec014e6fba5653587bd45dc2230be",
	},
	{
		curve: nist.K233(),
		x:     "0x4656e0aabbe341407715ca4a7fac287b41baa1f789c29bfa27e53a7a46",
		y:     "0xf79a7245fba513df787a64c618e97ebcc078638ebaaa562e9862bc00ce",
	},
	{
		curve: nist.B233(),
		x:     "0x80f50a330911bd753a76364595b9f0158c4d02a85cc0e3fb6ea0aef9ff",
		y:     "0x17a49033f12eb52675e98e6432cc27104bd5c42bcbe3daf76901c9b8743",
	},
	{
		curve: nist.K283(),
		x:     "0x15dccc30a8b1f5146412d51fec337741090321408aac521391ad36c5912e280124fe3b5",
		y:     "0x53fc9bed137312952ad97f6a98c4c7ac1b421635fbafe28898e9213d979d5b4d279f192",
	},
	{
		curve: nist.B283(),
		x:     "0xd257a925ba8bbf1a490a06a80d8338453a9a00eed2c51a90467a4283b3a4df9de2bc0b",
		y:     "0x22a7592959069fbbc245bee792106e995513d5f6837b90f291feb732b1cbe3427c8e585",
	},
	{
		curve: nist.K409(),
		x:     "0x15cdee83fc75049adc9ac4b259a4973fc82fe6c27ad22796b0992521eebfbae63aacd6cc7decd27453215a5c92a2eca614f2fa2",
		y:     "0x973314e9c9e2eb4cf9d70cfc9127619d5d190131a8c8638f96e859976d3b34db7ed3651bde3779a5d833a9d05952a7d4d06d16",
	},
	{
		curve: nist.B409(),
		x:     "0xd5f0e8b27d12d7a9dcea13a5cfb9dee62d63376e31f7666ba2ac2bf314b91420749ef549a17e5dc6815a7b044ff458c40c415",
		y:     "0x1db5b78d491e45cc58e9e44bd7e42537597b9aba85e2e3589f02d466ed31b816235f6d22679690002fcef2b5390f0de885e90be",
	},
	{
		curve: nist.K571(),
		x:     "0x287b0ccbb649860ccb56f10afea9090c8a05a351d2b70671084c563d37c6536b8be7b6130bfcd60e2111cd8a1283edf48970333c3906a61809d10bbfd4e016650ad4a749a68199a",
		y:     "0x2264fc0cb1b83968ff3f8f5689aeacd2b3cc9ce59ef83f0007e2da3045ac8ab2c0b43f4a2c9d2f29710cccee24286c3e4224614eba64f2f1629fd79168094130f31d6ce787cbd41",
	},
	{
		curve: nist.B571(),
		x:     "0x72d033e612ca6dd14c28f1f6689af9a97bba7fd88a25bae969dd1c91e75a9f680442dea747eab06e73b746911780505dab0e03149de396b1020fbaf55580cf4d6eb9738ce0d26f8",
		y:     "0x494ba50070ca0fc97e89f3ea55de5aed4d5bd139b3725618dfeb90152230aa53fa37b6e39baad54a77771f0df01bffee82fbb0bad45f2d5c89f704c6eba6722b1e4433638d87dda",
	},
}

func testDoubleAndAdd(curve elliptic.Curve, x1, y1, ex, ey *big.Int) bool {
	x, y := curve.Double(x1, y1)
	x, y = curve.Add(x, y, x1, y1)
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestDoubleAndAdd(t *testing.T) {
	for i, tc := range testvec3G {
		params := tc.curve.Params()
		Gx, Gy := params.Gx, params.Gy

		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)

		if !testDoubleAndAdd(tc.curve, Gx, Gy, Ex, Ey) {
			t.Errorf("%d Add(Double(G), G) != 3G", i)
		}
	}
}

func testScalarBaseMult(curve elliptic.Curve, k, ex, ey *big.Int) bool {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestScalarBaseMult(t *testing.T) {
	three := big.NewInt(3)
	for i, tc := range testvec3G {
		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)

		if !testScalarBaseMult(tc.curve, three, Ex, Ey) {
			t.Errorf("%d ScalarBaseMult(3) != 3G", i)
		}
	}
}

func testScalarMult(curve elliptic.Curve, x1, y1, k, ex, ey *big.Int) bool {
	x, y := curve.ScalarMult(x1, y1, k.Bytes())
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestScalarMult(t *testing.T) {
	three := big.NewInt(3)
	for i, tc := range testvec3G {
		params := tc.curve.Params()
		Gx, Gy := params.Gx, params.Gy
		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)

		if !testScalarMult(tc.curve, Gx, Gy, three, Ex, Ey) {
			t.Errorf("%d ScalarMult(G, 3) != 3G", i)
		}
	}
}

func TestIsOnCurve(t *testing.T) {
	for _, tc := range testvec3G {
		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)
		ok := tc.curve.IsOnCurve(Ex, Ey)
		if ok != true {
			t.Errorf("IsOnCurve(%s, %s) = false", tc.x, tc.y)
		}
	}
}

func TestSign(t *testing.T) {
	for _, curve := range testvec3G {
		priv, err := ecdsa.GenerateKey(curve.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello world")
		r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
			t.Fatal("failed to verify signature")
		}
	}
}
