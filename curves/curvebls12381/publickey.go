package curvebls12381

import (
	"encoding/base64"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const PublicKeySize = 96 // size in bytes

type PublicKey [PublicKeySize]byte

// String returns a base64 string representation of pk
func (pk PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(pk[:])
}

// pubkeyToPoint converts pk to public key point in G2.
// We're using the minimal-signature-size variant so public keys are points in G2.
// Fails if the point is not in the correct subgroup.
func (pk PublicKey) pubkeyToPoint() (bls12381.G2Affine, error) {

	var pkPoint bls12381.G2Affine
	err := pkPoint.Unmarshal(pk[:])
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	return pkPoint, nil
}

// Validate ensures that a public key is valid.
// In particular, it ensures that a public key represents a valid, non-identity point that is in the correct subgroup.
// Following https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ section 2.5. KeyValidate
func (pk PublicKey) Validate() error {
	_, err := pk.pubkeyToPointWithValidate()
	return err
}

// pubkeyToPointWithValidate ensures that a public key is valid and converts it to a point in G2.
// In particular, it ensures that a public key represents a valid, non-identity point that is in the correct subgroup.
func (pk PublicKey) pubkeyToPointWithValidate() (bls12381.G2Affine, error) {

	// convert pk to public key point in G2
	// we're using the minimal-signature-size variant so public keys are points in G2
	// fails if the point is not in the correct subgroup
	pkPoint, err := pk.pubkeyToPoint()
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	// check if the public key point is the identity element
	if pkPoint.IsInfinity() {
		return bls12381.G2Affine{}, fmt.Errorf("pk cannot be the identitiy element")
	}
	return pkPoint, nil
}

// coreVerify checks that a signature (sig) is valid for the byte slice (msg) under the public key (pk).
// Following https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ section 2.7. CoreVerify
func (pk PublicKey) coreVerify(msg Message, sig Signature) error {

	// get the signature point in G1
	// we're using the minimal-signature-size variant so signatures are points in G1
	sigPoint, err := sig.sigToPoint()
	if err != nil {
		return err
	}

	// get the public key point in G2
	// we're using the minimal-signature-size variant so public keys are points in G2
	pkPoint, err := pk.pubkeyToPointWithValidate()
	if err != nil {
		return err
	}

	// get the message point in G1
	msgPoint, err := msg.hashToPoint()
	if err != nil {
		return err
	}

	// compute the bilinear pairing
	c1, err := bls12381.Pair([]bls12381.G1Affine{msgPoint}, []bls12381.G2Affine{pkPoint})
	if err != nil {
		return err
	}
	c2, err := bls12381.Pair([]bls12381.G1Affine{sigPoint}, []bls12381.G2Affine{g2aff})
	if err != nil {
		return err
	}

	// compare the outputs of the bilinear pairing
	if !c1.Equal(&c2) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// Verify checks that a signature (sig) is valid for the byte slice (msg) under the public key (pk).
// Following https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ section 3.1. Basic scheme
func (pk PublicKey) Verify(msg Message, sig Signature) error {
	return pk.coreVerify(msg, sig)
}
