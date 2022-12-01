package main

import (
	"bls-w-sss/curves/curvebls12381"
	"crypto/rand"
	"fmt"
)

func main() {
	var sigs []curvebls12381.Signature
	var pks []curvebls12381.PublicKey
	var msgs []curvebls12381.Message
	for i := 0; i < 100; i++ {
		sk, err := curvebls12381.KeyGen()
		if err != nil {
			panic(err)
		}

		fmt.Printf("sk is %s\n", sk)

		pk := sk.PublicKey()
		pks = append(pks, pk)
		fmt.Printf("pk is %s\n", pk)

		err = pk.Validate()
		if err != nil {
			panic(err)
		}

		msg := make(curvebls12381.Message, 32)
		_, err = rand.Read(msg)
		if err != nil {
			panic(err)
		}
		msgs = append(msgs, msg)
		fmt.Printf("msg is %s\n", msg)

		sig, err := sk.Sign(msg)
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, sig)
		fmt.Printf("sig is %s\n", sig)

		err = pk.Verify(msg, sig)
		if err != nil {
			panic(err)
		}

		fmt.Println("Signature valid!")
	}

	//aggSig, err := curvebls12381.Aggregate(sigs)
	//if err != nil {
	//	panic(err)
	//}
	//
	//err = curvebls12381.AggregateVerify(pks, msgs, aggSig)
	//if err != nil {
	//	panic(err)
	//}
	//
	//fmt.Printf("aggSig is %s\n", aggSig)
}
