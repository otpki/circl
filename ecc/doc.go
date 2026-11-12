// Copyright (c) 2026 OmniTrust Security LLC.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package ecc provides curve interfaces, object identifiers, and binary-curve arithmetic.
//
// # Security
//
// Scalar arithmetic is constant time for fixed-length scalars. Curve parameters
// and affine inputs must be public; big.Int coordinate conversions are variable time.
// Use sign/ecdsa for custom-curve signing; Go's generic signer remains variable time.
// These curves are experimental and unaudited, and registration does not imply
// modern security strength. The curvegen tools are variable-time reference tools.
package ecc
