// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Modifications copyright (c) 2026 OmniTrust Security LLC, licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).

package ecdsa

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"hash"
)

// nonceDRBG is Go's SP 800-90A Rev. 1 HMAC_DRBG, adapted from
// crypto/internal/fips140/ecdsa/hmacdrbg.go for per-signature nonce generation.
// Each signature gets its own instance. Each Read, even an empty one, advances it.
type nonceDRBG struct {
	newHMAC       func(key []byte) hash.Hash
	hK            hash.Hash
	v             []byte
	reseedCounter uint64
}

func newNonceDRBG(h func() hash.Hash, entropy, nonce []byte, personalization [][]byte) *nonceDRBG {
	d := &nonceDRBG{
		newHMAC:       func(key []byte) hash.Hash { return hmac.New(h, key) },
		v:             bytes.Repeat([]byte{1}, h().Size()),
		reseedCounter: 1,
	}
	key := make([]byte, len(d.v))
	mac := d.newHMAC(key)
	// HMAC_DRBG_Instantiate and Update, Sections 10.1.2.3 and 10.1.2.2.
	for _, separator := range []byte{0, 1} {
		_, _ = mac.Write(d.v)
		_, _ = mac.Write([]byte{separator})
		_, _ = mac.Write(entropy)
		_, _ = mac.Write(nonce)
		written := len(d.v) + 1 + len(entropy) + len(nonce)
		// Align each part to a hash block, matching Go's nonce construction
		// (draft-irtf-cfrg-det-sigs-with-noise-04 §4).
		for _, part := range personalization {
			if rem := written % mac.BlockSize(); rem != 0 {
				_, _ = mac.Write(make([]byte, mac.BlockSize()-rem))
			}
			_, _ = mac.Write(part)
			written = len(part)
		}
		key = mac.Sum(key[:0])
		mac = d.newHMAC(key)
		_, _ = mac.Write(d.v)
		d.v = mac.Sum(d.v[:0])
		mac.Reset()
	}
	d.hK = mac
	return d
}

func (d *nonceDRBG) Read(out []byte) (int, error) {
	// HMAC_DRBG_Generate, Section 10.1.2.5, with no additional input.
	if len(out) > 1<<16 {
		return 0, errors.New("ecdsa: nonce DRBG request exceeds 64 KiB")
	}
	if d.reseedCounter > 1<<48 {
		return 0, errors.New("ecdsa: nonce DRBG reseed interval exceeded")
	}
	for written := 0; written < len(out); {
		d.hK.Reset()
		_, _ = d.hK.Write(d.v)
		d.v = d.hK.Sum(d.v[:0])
		written += copy(out[written:], d.v)
	}
	// HMAC_DRBG_Update without provided_data.
	d.hK.Reset()
	_, _ = d.hK.Write(d.v)
	_, _ = d.hK.Write([]byte{0})
	key := d.hK.Sum(nil)
	d.hK = d.newHMAC(key)
	_, _ = d.hK.Write(d.v)
	d.v = d.hK.Sum(d.v[:0])
	d.reseedCounter++
	return len(out), nil
}
