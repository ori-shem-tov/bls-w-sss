package curvebls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	// ciphersuiteID https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature section 4.2.1. Basic
	ciphersuiteID = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
)

var (
	// g2aff is the generator of the subgroup G2
	g2aff bls12381.G2Affine
)

func init() {
	_, _, _, g2aff = bls12381.Generators()
}
