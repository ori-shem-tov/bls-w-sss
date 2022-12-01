package curvebls12381

import (
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type (
	Message []byte
)

// String returns a base64 string representation of msg
func (msg Message) String() string {
	return base64.StdEncoding.EncodeToString(msg)
}

// hashToPoint converts msg to a point in G1.
func (msg Message) hashToPoint() (bls12381.G1Affine, error) {
	// domain separation tag based on the ciphersuite we use
	// see https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature section 4.1. Ciphersuite format
	dst := []byte(ciphersuiteID)
	// we use HashToG1 instead of EncodeToG1. it's slower than EncodeToG1, but outputs are uniformly distributed
	// which is required by the security analysis.
	// see: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature,
	// section 5.6. Implementing hash_to_point and hash_pubkey_to_point
	msgPoint, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	return msgPoint, nil
}
