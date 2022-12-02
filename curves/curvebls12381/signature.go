package curvebls12381

import (
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	SignatureSize = 48 // size in bytes
)

type Signature [SignatureSize]byte

// String returns a base64 string representation of sig
func (sig Signature) String() string {
	return base64.StdEncoding.EncodeToString(sig[:])
}

// sigToPoint converts sig to a point in G1.
// We're using the minimal-signature-size variant so signatures are points in G1.
// Fails if the point is not in the correct subgroup.
func (sig Signature) sigToPoint() (bls12381.G1Affine, error) {
	var sigPoint bls12381.G1Affine
	err := sigPoint.Unmarshal(sig[:])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	return sigPoint, nil
}
