package curvebls12381

//import (
//	"fmt"
//	"github.com/consensys/gnark-crypto/ecc/bls12-381"
//)
//
//// TODO: verify with tests that    Precondition: n >= 1, otherwise return INVALID.
//func coreAggregateVerify(pks []PublicKey, msgs []Message, sig Signature) error {
//	if len(pks) != len(msgs) {
//		return fmt.Errorf("pks and msgs are not the same size")
//	}
//	// this also checks that R is in subgroup
//	R, err := sig.sigToPoint()
//	if err != nil {
//		return err
//	}
//
//	var c1 bls12381.GT
//	c1.SetOne()
//
//	for i, pk := range pks {
//		xP, err := pk.pubkeyToPoint()
//		if err != nil {
//			return fmt.Errorf("invalid pk %d", i)
//		}
//		msgPoint, err := msgs[i].hashToPoint()
//		if err != nil {
//			return fmt.Errorf("cannot convert msg %d to point", i)
//		}
//		paired, err := bls12381.Pair([]bls12381.G1Affine{msgPoint}, []bls12381.G2Affine{xP})
//		c1 = *c1.Mul(&c1, &paired)
//	}
//	c2, err := bls12381.Pair([]bls12381.G1Affine{R}, []bls12381.G2Affine{g2aff})
//	if err != nil {
//		return err
//	}
//
//	if !c1.Equal(&c2) {
//		return fmt.Errorf("invalid signature")
//	}
//	return nil
//
//}
//
//func AggregateVerify(pks []PublicKey, msgs []Message, sig Signature) error {
//	msgsSet := make(map[string]byte)
//	for _, msg := range msgs {
//		msgStr := msg.String()
//		if _, ok := msgsSet[msgStr]; ok {
//			return fmt.Errorf("messages are not disticnt")
//		}
//		msgsSet[msgStr] = 1
//	}
//	return coreAggregateVerify(pks, msgs, sig)
//}
//
//func Aggregate(sigs []Signature) (Signature, error) {
//	if len(sigs) == 0 {
//		return Signature{}, fmt.Errorf("empty sigs")
//	}
//	var aggregate bls12381.G1Affine
//	err := aggregate.Unmarshal(sigs[0][:])
//	if err != nil {
//		return Signature{}, err
//	}
//	for _, sig := range sigs[1:] {
//		var next bls12381.G1Affine
//		err = next.Unmarshal(sig[:])
//		if err != nil {
//			return Signature{}, err
//		}
//		aggregate.Add(&aggregate, &next)
//	}
//
//	var result Signature
//	copy(result[:], aggregate.Marshal())
//
//	return result, nil
//}
