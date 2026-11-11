// Copyright (c) 2026 OmniTrust Security LLC.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).

package ecdsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

func TestNonceDRBGRFC6979(t *testing.T) {
	// RFC 6979 Appendix A.2.5, P-256, message "sample". These digest prefixes
	// are already below the order, so bits2octets only truncates them.
	key, err := hex.DecodeString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		h    func() hash.Hash
		want string
	}{
		{"SHA256", sha256.New, "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"},
		{"SHA384", sha512.New384, "09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4"},
		{"SHA512", sha512.New, "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.h()
			_, _ = h.Write([]byte("sample"))
			d := newNonceDRBG(tt.h, key, h.Sum(nil)[:32], nil)
			out := make([]byte, 32)
			if n, err := d.Read(out); n != len(out) || err != nil {
				t.Fatalf("Read = %d, %v", n, err)
			}
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, want) {
				t.Fatalf("nonce = %X, want %X", out, want)
			}
		})
	}
}

func TestNonceDRBGBlockAlignment(t *testing.T) {
	for _, h := range []func() hash.Hash{sha256.New, sha512.New384, sha512.New} {
		block := h().BlockSize()
		for _, prefixLen := range []int{0, block - h().Size() - 1, block - h().Size(), block + 1} {
			for _, parts := range [][][]byte{nil, {{}}, {{1}, {}, bytes.Repeat([]byte{2}, block), {3, 4}}} {
				entropy := bytes.Repeat([]byte{5}, prefixLen)
				nonce := []byte{6, 7}
				seed := append(append([]byte{}, entropy...), nonce...)
				// Build V || separator || seed with each part aligned to a hash block.
				for _, part := range parts {
					for (h().Size()+1+len(seed))%block != 0 {
						seed = append(seed, 0)
					}
					seed = append(seed, part...)
				}
				aligned := newNonceDRBG(h, entropy, nonce, parts)
				plain := newNonceDRBG(h, seed, nil, nil)
				// Cover state updates, empty reads, and output spanning hash blocks.
				for _, size := range []int{block + 1, 0, 17} {
					got, want := make([]byte, size), make([]byte, size)
					if _, err := aligned.Read(got); err != nil {
						t.Fatal(err)
					}
					if _, err := plain.Read(want); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("block %d, prefix %d, parts %v, size %d: alignment differs", block, prefixLen, parts, size)
					}
				}
			}
		}
	}
}

func TestNonceDRBGGenerateSequence(t *testing.T) {
	// Independently calculated with Python's hmac/hashlib from SP 800-90A
	// Sections 10.1.2.2–10.1.2.5, entropy 01 and no nonce/personalization.
	d := newNonceDRBG(sha256.New, []byte{1}, nil, nil)
	for _, wantHex := range []string{
		"143f9aeedc80fd2590cc4269c8754d0e91e7f162bf7fe7174a52ea4f5d28c0e88633933f9099b1254bcb764f2cef75b7b03946c710bf06ce658e5e8d7c34f9d19b",
		"",
		"cdcec52715e76072288720a4bb1844df13",
	} {
		want, err := hex.DecodeString(wantHex)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if n, err := d.Read(got); n != len(got) || err != nil {
			t.Fatalf("Read = %d, %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Generate(%d) = %X, want %X", len(got), got, want)
		}
	}
}

func TestNonceDRBGReadLimits(t *testing.T) {
	d := newNonceDRBG(sha256.New, []byte{1}, nil, nil)
	control := newNonceDRBG(sha256.New, []byte{1}, nil, nil)
	tooBig := bytes.Repeat([]byte{0xAA}, (1<<16)+1)
	if n, err := d.Read(tooBig); n != 0 || err == nil {
		t.Fatalf("oversized Read = %d, %v", n, err)
	}
	if !bytes.Equal(tooBig, bytes.Repeat([]byte{0xAA}, len(tooBig))) {
		t.Fatal("failed Read modified output")
	}
	got, want := make([]byte, 1<<16), make([]byte, 1<<16)
	if _, err := d.Read(got); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Read(want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("failed Read changed state or maximum request failed")
	}
	d.reseedCounter = 1 << 48
	if n, err := d.Read(got[:1]); n != 1 || err != nil {
		t.Fatalf("last allowed Read = %d, %v", n, err)
	}
	last := got[0]
	if n, err := d.Read(got[:1]); n != 0 || err == nil {
		t.Fatalf("exhausted Read = %d, %v", n, err)
	}
	if got[0] != last {
		t.Fatal("exhausted Read modified output")
	}
}
