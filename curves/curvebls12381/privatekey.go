package curvebls12381

import (
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"math/big"
)

const PrivateKeySize = 32 // size in bytes

type PrivateKey [PrivateKeySize]byte

// String returns a base64 string representation of sk
func (sk PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(sk[:])
}

// toBigInt converts sk bytes to a big integer
func (sk PrivateKey) toBigInt() big.Int {

	var skBigInt big.Int
	skBigInt.SetBytes(sk[:])

	return skBigInt
}

// PublicKey returns the public key corresponding with sk
// Following https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ section 2.4. SkToPk
func (sk PrivateKey) PublicKey() PublicKey {

	// convert sk bytes to a big integer
	skBigInt := sk.toBigInt()

	// compute the public key point in G2 by multiplying the sk scalar with the G2 generator
	// we're using the minimal-signature-size variant so public keys are points in G2
	var pkPoint bls12381.G2Affine
	pkPoint.ScalarMultiplication(&g2aff, &skBigInt)

	// serialize the public key point
	// TODO: can we use pkPoint.Bytes() instead to get a compressed representation? 96 bytes instead of 192
	var pk PublicKey
	copy(pk[:], pkPoint.Marshal())

	return pk
}

// coreSign computes a signature from sk, a secret key, and msg, a byte slice.
// Following https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ section 2.6. CoreSign
func (sk PrivateKey) coreSign(msg Message) (Signature, error) {
	// get the message point in G1
	msgPoint, err := msg.hashToPoint()
	if err != nil {
		return Signature{}, err
	}

	// convert sk bytes to a big integer
	skBigInt := sk.toBigInt()

	// compute the signature point in G1 by multiplying the sk scalar with the message point
	// we're using the minimal-signature-size variant so signatures are points in G1
	var sigPoint bls12381.G1Affine
	sigPoint.ScalarMultiplication(&msgPoint, &skBigInt)

	// serialize the signature point
	// TODO: can we use sig.Bytes() instead to get a compressed representation? 48 bytes instead of 96
	var sig Signature
	copy(sig[:], sigPoint.Marshal())

	return sig, nil
}

// Sign computes a signature from sk, a secret key, and msg, a byte slice.
// Following https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ section 3.1. Basic scheme
func (sk PrivateKey) Sign(msg Message) (Signature, error) {
	return sk.coreSign(msg)
}

// KeyGen returns a secret key sk, a uniformly random integer such that 1 <= sk < r where r is the order of G1 and G2.
func KeyGen() (PrivateKey, error) {

	var sk fr.Element

	for {
		// get a uniformly random integer such that 0 <= sk < r
		_, err := sk.SetRandom()
		if err != nil {
			return PrivateKey{}, err
		}

		// if sk == 0, we go for another iteration
		if !sk.IsZero() {
			break
		}
	}

	return sk.Bytes(), nil
}
